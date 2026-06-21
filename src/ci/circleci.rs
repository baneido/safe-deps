//! CircleCI parsing.
//!
//! Extracts shell commands from `run` steps in `.circleci/config.yml`. A step is
//! either the short form `- run: <cmd>` (inline or block scalar) or the map form
//! `- run:\n    command: <cmd>`. Env is read from `environment:` mappings.
//! Command extraction is line-oriented to preserve file/line locations.

use std::path::Path;

use crate::ci::yaml::{
    is_block_scalar_indicator, leading_spaces, mapping_key, strip_comment, unquote,
};
use crate::ci::{redact_env_value, CiCommand, CiProvider, EnvAssignment, ParsedCi};

/// The CircleCI provider (`.circleci/config.yml`).
pub struct CircleCi;

impl CiProvider for CircleCi {
    fn name(&self) -> &'static str {
        "CircleCI"
    }
    fn matches(&self, relative: &Path) -> bool {
        let comps: Vec<String> = relative
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(n) => Some(n.to_string_lossy().to_string()),
                _ => None,
            })
            .collect();
        comps.len() >= 2
            && comps[0] == ".circleci"
            && (comps[1].eq_ignore_ascii_case("config.yml")
                || comps[1].eq_ignore_ascii_case("config.yaml"))
    }
    fn parse(&self, relative: &Path, text: &str) -> ParsedCi {
        ParsedCi {
            commands: extract_run_commands(relative, text),
            env: extract_environment(text),
        }
    }
}

/// Extracts commands from `run:`/`command:` keys. The short form's value and the
/// map form's `command:` value are both shell; `name:`/other keys are ignored.
fn extract_run_commands(relative: &Path, text: &str) -> Vec<CiCommand> {
    let lines: Vec<&str> = text.lines().collect();
    let mut commands = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let Some((key_indent, key, value)) = mapping_key(lines[i]) else {
            i += 1;
            continue;
        };
        // `run:` short form carries the command inline or as a block scalar; its
        // empty/map form defers to the nested `command:` key (handled on its own
        // iteration). `command:` always carries shell.
        let carries_command = key == "command" || key == "run";
        if !carries_command {
            i += 1;
            continue;
        }
        if !value.is_empty() && !is_block_scalar_indicator(value) {
            push(
                &mut commands,
                relative,
                i,
                unquote(strip_comment(value).trim()),
            );
            i += 1;
        } else if is_block_scalar_indicator(value) {
            i = consume_block(&lines, i, key_indent, relative, &mut commands);
        } else {
            i += 1;
        }
    }
    commands
}

/// Emits each non-blank content line of a block scalar starting after `key_idx`
/// as a command; returns the index of the first line at/under `key_indent`.
fn consume_block(
    lines: &[&str],
    key_idx: usize,
    key_indent: usize,
    relative: &Path,
    commands: &mut Vec<CiCommand>,
) -> usize {
    let mut j = key_idx + 1;
    while j < lines.len() {
        let line = lines[j];
        if line.trim().is_empty() {
            j += 1;
            continue;
        }
        if leading_spaces(line) <= key_indent {
            break;
        }
        push(commands, relative, j, strip_comment(line).trim());
        j += 1;
    }
    j
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

/// Extracts `environment:` mappings structurally; secret values are redacted.
fn extract_environment(text: &str) -> Vec<EnvAssignment> {
    let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_environment(&doc, &mut out);
    out
}

fn collect_environment(node: &serde_yaml::Value, out: &mut Vec<EnvAssignment>) {
    match node {
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                if k.as_str() == Some("environment") {
                    if let serde_yaml::Value::Mapping(vars) = v {
                        for (name, value) in vars {
                            if let (Some(name), Some(value)) = (name.as_str(), value.as_str()) {
                                out.push(EnvAssignment {
                                    name: name.to_string(),
                                    value: redact_env_value(name, value),
                                });
                            }
                        }
                    }
                } else {
                    collect_environment(v, out);
                }
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for item in seq {
                collect_environment(item, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cmds(text: &str) -> Vec<String> {
        extract_run_commands(&PathBuf::from(".circleci/config.yml"), text)
            .into_iter()
            .map(|c| c.command)
            .collect()
    }

    #[test]
    fn matches_circleci_config() {
        assert!(CircleCi.matches(Path::new(".circleci/config.yml")));
        assert!(!CircleCi.matches(Path::new(".gitlab-ci.yml")));
    }

    #[test]
    fn extracts_short_and_map_run_steps() {
        let text = "\
jobs:
  build:
    steps:
      - checkout
      - run: npm ci
      - run:
          name: Test
          command: npm test
";
        assert_eq!(cmds(text), vec!["npm ci", "npm test"]);
    }

    #[test]
    fn extracts_block_command() {
        let text = "\
jobs:
  build:
    steps:
      - run:
          command: |
            pip install -r requirements.txt
            pytest
";
        assert_eq!(
            cmds(text),
            vec!["pip install -r requirements.txt", "pytest"]
        );
    }

    #[test]
    fn extracts_environment_with_redaction() {
        let text = "\
jobs:
  build:
    environment:
      NODE_ENV: production
      API_TOKEN: secret
    steps:
      - run: echo hi
";
        let env = extract_environment(text);
        let get = |n: &str| env.iter().find(|e| e.name == n).map(|e| e.value.as_str());
        assert_eq!(get("NODE_ENV"), Some("production"));
        assert_eq!(get("API_TOKEN"), Some("<redacted>"));
    }
}
