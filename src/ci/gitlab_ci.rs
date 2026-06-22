//! GitLab CI parsing.
//!
//! Extracts shell commands from `script:`, `before_script:`, and `after_script:`
//! keys in `.gitlab-ci.yml` (preserving file/line locations) and `variables:`
//! env assignments. Like the GitHub Actions provider the command scan is
//! line-oriented; env is read structurally with `serde_yaml`.

use std::path::Path;

use crate::ci::yaml::{
    is_block_scalar_indicator, join_continuations, leading_spaces, mapping_key, strip_comment,
    unquote,
};
use crate::ci::{redact_env_value, CiCommand, CiProvider, EnvAssignment, ParsedCi};

/// The GitLab CI provider (`.gitlab-ci.yml`).
pub struct GitlabCi;

impl CiProvider for GitlabCi {
    fn name(&self) -> &'static str {
        "GitLab CI"
    }
    fn matches(&self, relative: &Path) -> bool {
        // GitLab CI's canonical configuration file is **only** the
        // repository-root `.gitlab-ci.yml`.  A file with the same name under a
        // subdirectory (e.g. `vendor/example/.gitlab-ci.yml`) is not executed
        // by GitLab — treating it as real CI would produce phantom findings.
        // Anchoring to a single-component path mirrors how GitHub Actions
        // anchors to `.github/workflows/` and CircleCI anchors to
        // `.circleci/config.yml`.
        // Exactly one normal path component equal to `.gitlab-ci.yml`. Iterate
        // and short-circuit rather than collecting into a Vec — this runs once
        // per scanned file.
        let mut normals = relative.components().filter_map(|c| match c {
            std::path::Component::Normal(n) => Some(n),
            _ => None,
        });
        match (normals.next(), normals.next()) {
            (Some(name), None) => name
                .to_str()
                .is_some_and(|n| n.eq_ignore_ascii_case(".gitlab-ci.yml")),
            _ => false,
        }
    }
    fn parse(&self, relative: &Path, text: &str) -> ParsedCi {
        ParsedCi {
            commands: extract_script_commands(relative, text),
            env: extract_variables(text),
        }
    }
}

const SCRIPT_KEYS: &[&str] = &["script", "before_script", "after_script"];

/// Extracts commands from the `*script` keys. Each non-empty array item or block
/// scalar content line becomes one command, anchored at its source line.
fn extract_script_commands(relative: &Path, text: &str) -> Vec<CiCommand> {
    let lines: Vec<&str> = text.lines().collect();
    let mut commands = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let Some((key_indent, key, value)) = mapping_key(lines[i]) else {
            i += 1;
            continue;
        };
        let is_script = SCRIPT_KEYS.contains(&key);

        // Consume the whole block scalar for ANY key, but only emit commands for
        // a script key — so a `script:`-looking line inside a non-script block
        // (e.g. a multi-line `variables:` value) is not parsed as a command.
        if is_block_scalar_indicator(value) {
            let mut j = i + 1;
            let mut content_lines: Vec<(usize, &str)> = Vec::new();
            while j < lines.len() {
                let line = lines[j];
                if line.trim().is_empty() {
                    j += 1;
                    continue;
                }
                if leading_spaces(line) <= key_indent {
                    break;
                }
                if is_script {
                    content_lines.push((j, unquote(strip_comment(line).trim())));
                }
                j += 1;
            }
            if is_script {
                for (line_no, command) in join_continuations(&content_lines) {
                    if !command.is_empty() {
                        commands.push(CiCommand {
                            file: relative.to_path_buf(),
                            line: line_no,
                            command,
                        });
                    }
                }
            }
            i = j;
            continue;
        }

        if !is_script {
            i += 1;
            continue;
        }
        // Inline single command: `script: npm ci`.
        if !value.is_empty() {
            push(
                &mut commands,
                relative,
                i,
                unquote(strip_comment(value).trim()),
            );
            i += 1;
            continue;
        }
        // Array form: consume `- item` lines (incl. per-item `- |` block text).
        // YAML allows an "indentless block sequence" where `- item` aligns with
        // the parent mapping key (e.g. `script:\n- npm ci`).  We therefore break
        // only when the indent is *strictly less* than `key_indent`, or when the
        // indent equals `key_indent` and the line is not a sequence item.
        // We also collect content lines per logical array item and apply
        // continuation joining so a command split with `\` across multiple lines
        // is reunited.
        let mut j = i + 1;
        let mut item_lines: Vec<(usize, &str)> = Vec::new();
        let mut in_item_block = false;
        while j < lines.len() {
            let line = lines[j];
            if line.trim().is_empty() {
                j += 1;
                continue;
            }
            let indent = leading_spaces(line);
            let content = strip_comment(line).trim();
            // A bare `-` (exactly `-`, or `-` followed by whitespace/comment
            // that strips away) is also a valid YAML empty sequence item.
            let is_seq_item = content.starts_with("- ") || content == "-";
            if indent < key_indent || (indent == key_indent && !is_seq_item) {
                break;
            }
            if let Some(item) = content.strip_prefix("- ") {
                // Flush any accumulated item lines before starting a new item.
                for (line_no, command) in join_continuations(&item_lines) {
                    if !command.is_empty() {
                        commands.push(CiCommand {
                            file: relative.to_path_buf(),
                            line: line_no,
                            command,
                        });
                    }
                }
                item_lines.clear();
                in_item_block = false;
                if is_block_scalar_indicator(item.trim()) {
                    // `- |` array item: subsequent indented lines are content.
                    in_item_block = true;
                } else {
                    item_lines.push((j, unquote(item.trim())));
                }
            } else if content == "-" {
                // Empty list item.
                for (line_no, command) in join_continuations(&item_lines) {
                    if !command.is_empty() {
                        commands.push(CiCommand {
                            file: relative.to_path_buf(),
                            line: line_no,
                            command,
                        });
                    }
                }
                item_lines.clear();
                in_item_block = false;
            } else if in_item_block || !is_block_scalar_indicator(content) {
                // Block-scalar content line under a `- |` array item, or a
                // continuation line of a plain array item.
                item_lines.push((j, unquote(content)));
            }
            j += 1;
        }
        // Flush remaining item lines.
        for (line_no, command) in join_continuations(&item_lines) {
            if !command.is_empty() {
                commands.push(CiCommand {
                    file: relative.to_path_buf(),
                    line: line_no,
                    command,
                });
            }
        }
        i = j;
    }
    commands
}

fn push(commands: &mut Vec<CiCommand>, relative: &Path, line_idx: usize, command: &str) {
    if command.is_empty() {
        return;
    }
    commands.push(CiCommand {
        file: relative.to_path_buf(),
        line: (line_idx as u32) + 1,
        command: command.to_string(),
    });
}

/// Extracts `variables:` mappings (top-level and per-job) structurally; secret
/// values are redacted.
fn extract_variables(text: &str) -> Vec<EnvAssignment> {
    let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_variables(&doc, &mut out);
    out
}

fn collect_variables(node: &serde_yaml::Value, out: &mut Vec<EnvAssignment>) {
    if let serde_yaml::Value::Mapping(map) = node {
        for (k, v) in map {
            if k.as_str() == Some("variables") {
                if let serde_yaml::Value::Mapping(vars) = v {
                    for (name, value) in vars {
                        if let Some(name) = name.as_str() {
                            let raw = scalar_to_string(value);
                            out.push(EnvAssignment {
                                name: name.to_string(),
                                value: redact_env_value(name, &raw),
                            });
                        }
                    }
                }
            } else {
                collect_variables(v, out);
            }
        }
    }
}

fn scalar_to_string(v: &serde_yaml::Value) -> String {
    match v {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Number(n) => n.to_string(),
        // GitLab also allows `VAR: { value: "...", description: "..." }`.
        serde_yaml::Value::Mapping(m) => m
            .get(serde_yaml::Value::String("value".into()))
            .map(scalar_to_string)
            .unwrap_or_default(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cmds(text: &str) -> Vec<String> {
        extract_script_commands(&PathBuf::from(".gitlab-ci.yml"), text)
            .into_iter()
            .map(|c| c.command)
            .collect()
    }

    #[test]
    fn matches_only_root_gitlab_ci_file() {
        // Root-level canonical file must match.
        assert!(GitlabCi.matches(Path::new(".gitlab-ci.yml")));
        // Case-insensitive match still anchored to root.
        assert!(GitlabCi.matches(Path::new(".GITLAB-CI.YML")));

        // A file with the same name under any subdirectory must NOT match —
        // GitLab only reads the repository-root `.gitlab-ci.yml`.
        assert!(!GitlabCi.matches(Path::new("vendor/example/.gitlab-ci.yml")));
        assert!(!GitlabCi.matches(Path::new("sub/.gitlab-ci.yml")));
        assert!(!GitlabCi.matches(Path::new("a/b/c/.gitlab-ci.yml")));

        // Unrelated files must not match.
        assert!(!GitlabCi.matches(Path::new(".github/workflows/ci.yml")));
        assert!(!GitlabCi.matches(Path::new(".circleci/config.yml")));
        assert!(!GitlabCi.matches(Path::new("gitlab-ci.yml")));
    }

    #[test]
    fn extracts_array_and_inline_scripts() {
        let text = "\
build:
  before_script:
    - npm ci
  script:
    - npm test
    - npm run build
test:
  script: pytest -q
";
        assert_eq!(
            cmds(text),
            vec!["npm ci", "npm test", "npm run build", "pytest -q"]
        );
    }

    #[test]
    fn extracts_block_scalar_script() {
        let text = "\
job:
  script:
    - |
      pip install -r requirements.txt
      pytest
";
        assert_eq!(
            cmds(text),
            vec!["pip install -r requirements.txt", "pytest"]
        );
    }

    #[test]
    fn strips_comments_and_quotes() {
        let text = "job:\n  script:\n    - \"npm ci\" # frozen\n";
        assert_eq!(cmds(text), vec!["npm ci"]);
    }

    #[test]
    fn script_like_line_in_a_non_script_block_is_not_a_command() {
        let text = "\
variables:
  NOTE: |
    script: echo leaked
    before_script: echo also
job:
  script:
    - npm test
";
        assert_eq!(cmds(text), vec!["npm test"]);
    }

    #[test]
    fn extracts_variables_with_redaction() {
        let text = "variables:\n  NODE_ENV: production\n  NPM_TOKEN: abcd\n";
        let env = extract_variables(text);
        let get = |n: &str| env.iter().find(|e| e.name == n).map(|e| e.value.as_str());
        assert_eq!(get("NODE_ENV"), Some("production"));
        assert_eq!(get("NPM_TOKEN"), Some("<redacted>"));
    }

    // Indentless block sequence: `- item` at the *same* indent level as the
    // parent `script:` key — valid YAML per the spec.
    #[test]
    fn extracts_indentless_script_sequence() {
        let text = "\
job:
  script:
  - npm install
  - npm audit
";
        assert_eq!(cmds(text), vec!["npm install", "npm audit"]);
    }

    #[test]
    fn extracts_indentless_before_and_after_script() {
        let text = "\
job:
  before_script:
  - npm ci
  script:
  - npm test
  after_script:
  - npm run clean
";
        assert_eq!(cmds(text), vec!["npm ci", "npm test", "npm run clean"]);
    }

    #[test]
    fn indentless_sequence_stops_at_next_mapping_key() {
        let text = "\
build:
  script:
  - npm ci
  - npm run build
deploy:
  script:
  - npm run deploy
";
        assert_eq!(
            cmds(text),
            vec!["npm ci", "npm run build", "npm run deploy"]
        );
    }

    // A bare `-` (empty YAML sequence item, optionally followed by a comment)
    // must be treated as a sequence item so the parser does not exit the block
    // early and drop subsequent commands.
    #[test]
    fn indentless_sequence_bare_dash_skipped_collection_continues() {
        let text = "\
job:
  script:
  - npm ci
  -
  - # this is just a comment
  - npm test
";
        assert_eq!(cmds(text), vec!["npm ci", "npm test"]);
    }

    #[test]
    fn backslash_continuation_in_array_script_is_joined() {
        // A command split across continuation lines must be reassembled so that
        // dangerous flags are not separated from the installer invocation.
        let text = "\
job:
  script:
    - pip install \\
      --break-system-packages \\
      -r requirements.txt
";
        assert_eq!(
            cmds(text),
            vec!["pip install --break-system-packages -r requirements.txt"]
        );
    }

    #[test]
    fn backslash_continuation_in_block_scalar_script_is_joined() {
        let text = "\
job:
  script:
    - |
      pip install \\
        --break-system-packages \\
        -r requirements.txt
      pytest
";
        assert_eq!(
            cmds(text),
            vec![
                "pip install --break-system-packages -r requirements.txt",
                "pytest"
            ]
        );
    }

    #[test]
    fn multiple_array_items_with_continuation_are_independent() {
        let text = "\
job:
  script:
    - npm ci
    - pip install \\
      --break-system-packages \\
      -r requirements.txt
    - pytest
";
        assert_eq!(
            cmds(text),
            vec![
                "npm ci",
                "pip install --break-system-packages -r requirements.txt",
                "pytest"
            ]
        );
    }
}
