//! GitHub Actions workflow parsing.
//!
//! Extracts `run` commands with file/line locations and `env` assignments from
//! `.github/workflows/*.yml` and `*.yaml`. The `run` extraction is line-oriented
//! so findings can point at the exact command line; `env` is read structurally
//! with `serde_yaml`. Matrix expansion is out of scope (the design marks
//! matrix-expanded content as not required for the MVP).

use std::path::Path;

use crate::ci::yaml::{dedent, is_block_scalar_indicator, leading_spaces, mapping_key};
use crate::ci::{redact_env_value, CiCommand, CiProvider, EnvAssignment, ParsedCi};

/// The GitHub Actions provider (`.github/workflows/*.yml|yaml`).
pub struct GithubActions;

impl CiProvider for GithubActions {
    fn name(&self) -> &'static str {
        "GitHub Actions"
    }
    fn matches(&self, relative: &Path) -> bool {
        is_workflow_file(relative)
    }
    fn parse(&self, relative: &Path, text: &str) -> ParsedCi {
        parse(relative, text)
    }
}

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
    // GitHub Actions only runs workflows under the repository-root
    // `.github/workflows/`. Anchoring to the path prefix avoids treating a
    // nested `docs/.github/workflows/ci.yml` (or any vendored copy) as a real
    // workflow and extracting phantom CI commands from it.
    let in_workflows = comps.len() >= 2 && comps[0] == ".github" && comps[1] == "workflows";
    let ext_ok = relative
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("yml") || e.eq_ignore_ascii_case("yaml"))
        .unwrap_or(false);
    in_workflows && ext_ok
}

/// Parses a workflow file's text into CI facts.
pub fn parse(relative: &Path, text: &str) -> ParsedCi {
    ParsedCi {
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
        let Some((key_indent, key, value)) = mapping_key(raw) else {
            i += 1;
            continue;
        };
        if is_block_scalar_indicator(value) {
            // Consume the whole block scalar for ANY key, but only emit commands
            // for `run:`. This prevents an inner `run:`-looking line inside a
            // non-run block (e.g. a github-script `with.script: |`) from being
            // mis-parsed as a CI command.
            let is_run = key == "run";
            let mut block_indent: Option<usize> = None;
            // Buffer for joining backslash-continued lines into one command.
            let mut pending: Option<(u32, String)> = None;
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
                if is_run {
                    let bi = *block_indent.get_or_insert(indent);
                    let content = dedent(line, bi).trim_end();
                    if !content.trim().is_empty() {
                        push_run_line(&mut commands, &mut pending, relative, j, content);
                    }
                }
                j += 1;
            }
            if let Some((line_no, command)) = pending.take() {
                commands.push(CiCommand {
                    file: relative.to_path_buf(),
                    line: line_no,
                    command,
                });
            }
            i = j;
        } else {
            if key == "run" {
                // Inline scalar on the same line as `run:`.
                let command = clean_inline_scalar(value);
                if !command.is_empty() {
                    commands.push(CiCommand {
                        file: relative.to_path_buf(),
                        line: (i as u32) + 1,
                        command,
                    });
                }
            }
            i += 1;
        }
    }
    commands
}

/// Appends a block-scalar content line to `commands`, joining shell line
/// continuations (`\` at end of line) so a command and its flags stay together.
fn push_run_line(
    commands: &mut Vec<CiCommand>,
    pending: &mut Option<(u32, String)>,
    relative: &Path,
    line_idx: usize,
    content: &str,
) {
    let line_no = (line_idx as u32) + 1;
    if let Some(rest) = content.strip_suffix('\\') {
        let piece = rest.trim();
        match pending {
            Some((_, acc)) => {
                acc.push(' ');
                acc.push_str(piece);
            }
            None => *pending = Some((line_no, piece.to_string())),
        }
        return;
    }
    let piece = content.trim();
    match pending.take() {
        Some((start, mut acc)) => {
            acc.push(' ');
            acc.push_str(piece);
            commands.push(CiCommand {
                file: relative.to_path_buf(),
                line: start,
                command: acc,
            });
        }
        None => commands.push(CiCommand {
            file: relative.to_path_buf(),
            line: line_no,
            command: piece.to_string(),
        }),
    }
}

/// Strips a YAML comment and surrounding quotes from an inline scalar value.
fn clean_inline_scalar(value: &str) -> String {
    let v = value.trim();
    // A quoted scalar runs to its matching closing quote; anything after it
    // (e.g. ` # comment`) is not part of the value. Handle this before comment
    // stripping so `run: "npm ci" # note` yields `npm ci`, not `"npm ci"`.
    if let Some(unquoted) = unquote_scalar(v) {
        return unquoted;
    }
    // For unquoted scalars, ` #` begins a comment.
    if let Some(idx) = v.find(" #") {
        return v[..idx].trim_end().to_string();
    }
    v.to_string()
}

/// Unquotes a YAML flow scalar, honoring escapes so an embedded quote does not
/// truncate the command: `\"` inside a double-quoted scalar and `''` inside a
/// single-quoted one. Returns `None` if `v` is not quoted or has no closing
/// quote (an unterminated scalar falls back to the raw text).
fn unquote_scalar(v: &str) -> Option<String> {
    let chars: Vec<char> = v.chars().collect();
    let quote = *chars.first().filter(|c| **c == '"' || **c == '\'')?;
    let mut out = String::new();
    let mut i = 1;
    while i < chars.len() {
        let c = chars[i];
        if quote == '"' {
            // Double-quoted: a backslash escapes the next char (keep it literal).
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == quote {
                return Some(out);
            }
        } else {
            // Single-quoted: a doubled quote `''` is one literal quote.
            if c == quote {
                if chars.get(i + 1) == Some(&quote) {
                    out.push(quote);
                    i += 2;
                    continue;
                }
                return Some(out);
            }
        }
        out.push(c);
        i += 1;
    }
    None
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
        // Only the repository-root .github/workflows is a real workflow dir; a
        // nested or vendored copy is not.
        assert!(!is_workflow_file(Path::new(
            "docs/.github/workflows/ci.yml"
        )));
        assert!(!is_workflow_file(Path::new(
            "vendor/x/.github/workflows/ci.yaml"
        )));
    }

    #[test]
    fn inline_run_with_escaped_quotes_is_not_truncated() {
        // Double-quoted scalar with escaped inner quotes.
        let text = "steps:\n  - run: \"echo \\\"hi\\\" && npm ci\"\n";
        let cmds = extract_run_commands(&PathBuf::from("w.yml"), text);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "echo \"hi\" && npm ci");
        // Single-quoted scalar with a doubled inner quote.
        let text = "steps:\n  - run: 'echo ''hi'' && npm ci'\n";
        let cmds = extract_run_commands(&PathBuf::from("w.yml"), text);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "echo 'hi' && npm ci");
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
    fn run_inside_a_non_run_block_scalar_is_not_a_command() {
        // A github-script `script: |` block containing a `run:`-looking line
        // must be consumed, not parsed as a CI command.
        let text = "steps:\n  - uses: actions/github-script@v7\n    with:\n      script: |\n        run: npm install --force\n        core.info('hi')\n  - run: npm ci\n";
        let cmds = extract_run_commands(&PathBuf::from("w.yml"), text);
        assert_eq!(cmds.len(), 1, "got: {cmds:?}");
        assert_eq!(cmds[0].command, "npm ci");
    }

    #[test]
    fn backslash_continuation_lines_are_joined() {
        let text =
            "steps:\n  - run: |\n      pip install \\\n        --break-system-packages requests\n";
        let cmds = extract_run_commands(&PathBuf::from("w.yml"), text);
        assert_eq!(cmds.len(), 1, "got: {cmds:?}");
        assert_eq!(
            cmds[0].command,
            "pip install --break-system-packages requests"
        );
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
