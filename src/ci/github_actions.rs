//! GitHub Actions workflow parsing.
//!
//! Extracts `run` commands with file/line locations and `env` assignments from
//! `.github/workflows/*.yml` and `*.yaml`. The `run` extraction is line-oriented
//! so findings can point at the exact command line; `env` is read structurally
//! with `serde_yaml`. Matrix expansion is out of scope (the design marks
//! matrix-expanded content as not required for the MVP).

use std::path::Path;

use crate::ci::{redact_env_value, CiCommand, EnvAssignment};

/// Whether a workspace-relative path is a GitHub Actions workflow file
/// (`.github/workflows/*.yml` or `*.yaml`).
pub fn is_workflow_file(relative: &Path) -> bool {
    let comps: Vec<String> = relative
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(n) => Some(n.to_string_lossy().to_string()),
            _ => None,
        })
        .collect();
    let in_workflows = comps
        .windows(2)
        .any(|w| w[0] == ".github" && w[1] == "workflows");
    let ext_ok = relative
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("yml") || e.eq_ignore_ascii_case("yaml"))
        .unwrap_or(false);
    in_workflows && ext_ok
}

/// The result of parsing one workflow file.
#[derive(Debug, Default)]
pub struct WorkflowParse {
    pub commands: Vec<CiCommand>,
    pub env: Vec<EnvAssignment>,
}

/// Parses a workflow file's text into CI facts.
pub fn parse(relative: &Path, text: &str) -> WorkflowParse {
    WorkflowParse {
        commands: extract_run_commands(relative, text),
        env: extract_env(text),
    }
}

/// Extracts shell command lines from `run:` keys, preserving 1-based file lines.
///
/// Block scalars (`run: |`, `run: >`) contribute one command per non-blank
/// content line; inline scalars (`run: npm ci`) contribute a single command.
fn extract_run_commands(relative: &Path, text: &str) -> Vec<CiCommand> {
    let lines: Vec<&str> = text.lines().collect();
    let mut commands = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let raw = lines[i];
        let Some((key_indent, value)) = run_key_value(raw) else {
            i += 1;
            continue;
        };
        if is_block_scalar_indicator(value) {
            // Consume the block: following lines indented deeper than the key.
            let mut block_indent: Option<usize> = None;
            let mut j = i + 1;
            while j < lines.len() {
                let line = lines[j];
                if line.trim().is_empty() {
                    j += 1;
                    continue;
                }
                let indent = leading_spaces(line);
                if indent <= key_indent {
                    break;
                }
                let bi = *block_indent.get_or_insert(indent);
                let content = dedent(line, bi);
                let trimmed = content.trim_end();
                if !trimmed.trim().is_empty() {
                    commands.push(CiCommand {
                        file: relative.to_path_buf(),
                        line: (j as u32) + 1,
                        command: trimmed.to_string(),
                    });
                }
                j += 1;
            }
            i = j;
        } else {
            // Inline scalar on the same line as `run:`.
            let command = clean_inline_scalar(value);
            if !command.is_empty() {
                commands.push(CiCommand {
                    file: relative.to_path_buf(),
                    line: (i as u32) + 1,
                    command,
                });
            }
            i += 1;
        }
    }
    commands
}

/// If `line` is a `run:` mapping key, returns `(key_column, value_after_colon)`,
/// where `key_column` is the column at which the `run` key begins. Handles an
/// optional `- ` sequence marker (`- run: …`); for that form the key column is
/// the column of `run`, not of the `-`, so sibling step keys (which align with
/// `run`) are correctly treated as outside the block scalar.
fn run_key_value(line: &str) -> Option<(usize, &str)> {
    let indent = leading_spaces(line);
    let after_indent = &line[indent..];
    let mut key_column = indent;
    let mut rest = after_indent;
    // Allow a sequence marker introducing the mapping (`- run: …`). The key
    // column advances past `- ` and any extra spaces before the key.
    if let Some(stripped) = rest.strip_prefix("- ") {
        let trimmed = stripped.trim_start();
        key_column += rest.len() - trimmed.len();
        rest = trimmed;
    }
    let value = rest.strip_prefix("run:")?;
    // The next char after `run` must be `:` (handled) and then space or EOL,
    // so we don't match keys like `runs:` or `running:`.
    if !(value.is_empty() || value.starts_with([' ', '\t'])) {
        return None;
    }
    Some((key_column, value.trim_start()))
}

/// Whether a scalar value introduces a YAML block scalar (`|` or `>` with
/// optional chomping/indentation indicators such as `|-`, `>2`). A trailing
/// comment (`| # note`) is permitted and ignored.
fn is_block_scalar_indicator(value: &str) -> bool {
    let v = value.trim();
    // A YAML comment requires whitespace before `#`; strip it before checking.
    let v = match v.find(" #") {
        Some(idx) => v[..idx].trim_end(),
        None => v,
    };
    let mut chars = v.chars();
    match chars.next() {
        Some('|') | Some('>') => {
            // Remaining chars may only be chomping/indent indicators.
            chars.all(|c| c == '+' || c == '-' || c.is_ascii_digit())
        }
        _ => false,
    }
}

/// Strips a YAML comment and surrounding quotes from an inline scalar value.
fn clean_inline_scalar(value: &str) -> String {
    let v = value.trim();
    // A quoted scalar runs to its matching closing quote; anything after it
    // (e.g. ` # comment`) is not part of the value. Handle this before comment
    // stripping so `run: "npm ci" # note` yields `npm ci`, not `"npm ci"`.
    if let Some(quote) = v.chars().next().filter(|c| *c == '"' || *c == '\'') {
        if let Some(end) = v[1..].find(quote) {
            return v[1..=end].to_string();
        }
    }
    // For unquoted scalars, ` #` begins a comment.
    if let Some(idx) = v.find(" #") {
        return v[..idx].trim_end().to_string();
    }
    v.to_string()
}

fn leading_spaces(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ').count()
}

fn dedent(line: &str, n: usize) -> &str {
    let mut idx = 0;
    for (count, (byte_idx, c)) in line.char_indices().enumerate() {
        if count >= n || c != ' ' {
            idx = byte_idx;
            return &line[idx..];
        }
        idx = byte_idx + c.len_utf8();
    }
    &line[idx..]
}

/// Extracts workflow-, job-, and step-level `env` assignments structurally.
/// Secret-looking values are redacted. Returns an empty list if the YAML cannot
/// be parsed (best effort; the line-based run scan still runs).
fn extract_env(text: &str) -> Vec<EnvAssignment> {
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_env(&value, &mut out); // workflow-level
    if let Some(jobs) = value.get("jobs").and_then(|j| j.as_mapping()) {
        for (_id, job) in jobs {
            collect_env(job, &mut out); // job-level
            if let Some(steps) = job.get("steps").and_then(|s| s.as_sequence()) {
                for step in steps {
                    collect_env(step, &mut out); // step-level
                }
            }
        }
    }
    out
}

/// Appends the `env` mapping of `node` (if any) to `out`, in document order.
fn collect_env(node: &serde_yaml::Value, out: &mut Vec<EnvAssignment>) {
    let Some(env) = node.get("env").and_then(|e| e.as_mapping()) else {
        return;
    };
    for (k, v) in env {
        let Some(name) = k.as_str() else { continue };
        let value = scalar_to_string(v);
        out.push(EnvAssignment {
            name: name.to_string(),
            value: redact_env_value(name, &value),
        });
    }
}

fn scalar_to_string(v: &serde_yaml::Value) -> String {
    match v {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Null => String::new(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn detects_workflow_files() {
        assert!(is_workflow_file(Path::new(".github/workflows/ci.yml")));
        assert!(is_workflow_file(Path::new(
            ".github/workflows/release.yaml"
        )));
        assert!(!is_workflow_file(Path::new(".github/dependabot.yml")));
        assert!(!is_workflow_file(Path::new("docs/ci.yml")));
        assert!(!is_workflow_file(Path::new(".github/workflows/notes.md")));
    }

    #[test]
    fn extracts_block_scalar_run_lines_with_locations() {
        let text = "jobs:\n  build:\n    steps:\n      - run: |\n          npm install\n          npm test\n";
        let cmds = extract_run_commands(&PathBuf::from(".github/workflows/ci.yml"), text);
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].command, "npm install");
        assert_eq!(cmds[0].line, 5);
        assert_eq!(cmds[1].command, "npm test");
        assert_eq!(cmds[1].line, 6);
    }

    #[test]
    fn extracts_inline_run_and_strips_comment() {
        let text = "steps:\n  - run: npm ci # frozen install\n";
        let cmds = extract_run_commands(&PathBuf::from("w.yml"), text);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "npm ci");
        assert_eq!(cmds[0].line, 2);
    }

    #[test]
    fn quoted_inline_run_with_trailing_comment() {
        // The quotes and the trailing comment must both be removed.
        for q in ['"', '\''] {
            let text = format!("steps:\n  - run: {q}npm ci{q} # frozen\n");
            let cmds = extract_run_commands(&PathBuf::from("w.yml"), &text);
            assert_eq!(cmds.len(), 1);
            assert_eq!(cmds[0].command, "npm ci", "quote {q}");
        }
    }

    #[test]
    fn does_not_match_runs_on_key() {
        let text = "jobs:\n  build:\n    runs-on: ubuntu-latest\n";
        let cmds = extract_run_commands(&PathBuf::from("w.yml"), text);
        assert!(cmds.is_empty());
    }

    #[test]
    fn extracts_env_at_all_levels_and_redacts_secrets() {
        let text = "\
env:\n  NODE_ENV: production\njobs:\n  build:\n    env:\n      NPM_TOKEN: abcdef\n    steps:\n      - run: npm ci\n        env:\n          FOO: bar\n";
        let env = extract_env(text);
        let names: Vec<&str> = env.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["NODE_ENV", "NPM_TOKEN", "FOO"]);
        let token = env.iter().find(|e| e.name == "NPM_TOKEN").unwrap();
        assert_eq!(token.value, "<redacted>");
        let node_env = env.iter().find(|e| e.name == "NODE_ENV").unwrap();
        assert_eq!(node_env.value, "production");
    }

    #[test]
    fn sibling_keys_after_run_block_are_not_slurped() {
        // The `run` block is the step's first key (`- run: |`); the following
        // `env:` sibling and its entries must not be parsed as commands.
        let text = "steps:\n  - run: |\n      npm install\n    env:\n      FOO: bar\n";
        let cmds = extract_run_commands(&PathBuf::from("w.yml"), text);
        assert_eq!(cmds.len(), 1, "got: {cmds:?}");
        assert_eq!(cmds[0].command, "npm install");
    }

    #[test]
    fn block_scalar_with_trailing_comment_is_a_block() {
        let text = "steps:\n  - run: | # install deps\n      npm install\n";
        let cmds = extract_run_commands(&PathBuf::from("w.yml"), text);
        assert_eq!(cmds.len(), 1, "got: {cmds:?}");
        assert_eq!(cmds[0].command, "npm install");
    }

    #[test]
    fn nested_run_inside_block_is_not_double_counted() {
        // A `run:` substring inside a block scalar must not be parsed as a key.
        let text = "steps:\n  - run: |\n      echo \"run: not a key\"\n      npm install\n";
        let cmds = extract_run_commands(&PathBuf::from("w.yml"), text);
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].command, "echo \"run: not a key\"");
        assert_eq!(cmds[1].command, "npm install");
    }
}
