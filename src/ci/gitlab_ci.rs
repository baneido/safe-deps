//! GitLab CI parsing.
//!
//! Extracts shell commands from `script:`, `before_script:`, and `after_script:`
//! keys in `.gitlab-ci.yml` (preserving file/line locations) and `variables:`
//! env assignments. Like the GitHub Actions provider the command scan is
//! line-oriented; env is read structurally with `serde_yaml`.

use std::path::Path;

use crate::ci::yaml::{
    is_block_scalar_indicator, leading_spaces, mapping_key, strip_comment, unquote,
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
        if !SCRIPT_KEYS.contains(&key) {
            i += 1;
            continue;
        }
        // Inline single command: `script: npm ci`.
        if !value.is_empty() && !is_block_scalar_indicator(value) {
            push(
                &mut commands,
                relative,
                i,
                unquote(strip_comment(value).trim()),
            );
            i += 1;
            continue;
        }
        // Block: consume more-indented lines as array items / block-scalar text.
        let mut j = i + 1;
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
                // An array item; `- |` introduces a per-item block scalar whose
                // content lines are handled by the plain-content branch below.
                if !is_block_scalar_indicator(item.trim()) {
                    push(&mut commands, relative, j, unquote(item.trim()));
                }
            } else if content != "-" && !is_block_scalar_indicator(content) {
                // Block-scalar content line (`script: |` form, or under `- |`).
                push(&mut commands, relative, j, unquote(content));
            }
            j += 1;
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
    fn extracts_variables_with_redaction() {
        let text = "variables:\n  NODE_ENV: production\n  NPM_TOKEN: abcd\n";
        let env = extract_variables(text);
        let get = |n: &str| env.iter().find(|e| e.name == n).map(|e| e.value.as_str());
        assert_eq!(get("NODE_ENV"), Some("production"));
        assert_eq!(get("NPM_TOKEN"), Some("<redacted>"));
    }
}
