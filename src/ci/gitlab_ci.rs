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
        relative
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case(".gitlab-ci.yml"))
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
        // We collect content lines per logical array item and apply continuation
        // joining so a command split with `\` across multiple lines is reunited.
        let mut j = i + 1;
        let mut item_lines: Vec<(usize, &str)> = Vec::new();
        let mut in_item_block = false;
        let mut item_block_indent: usize = 0;
        while j < lines.len() {
            let line = lines[j];
            if line.trim().is_empty() {
                j += 1;
                continue;
            }
            if leading_spaces(line) <= key_indent {
                break;
            }
            let content = strip_comment(line).trim();
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
                    item_block_indent = leading_spaces(line) + 2; // content deeper than `- `
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
                let _ = item_block_indent; // used for block detection only
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
    fn matches_gitlab_ci_file() {
        assert!(GitlabCi.matches(Path::new(".gitlab-ci.yml")));
        assert!(!GitlabCi.matches(Path::new(".github/workflows/ci.yml")));
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
