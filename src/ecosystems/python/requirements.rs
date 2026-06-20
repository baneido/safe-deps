//! `requirements*.txt` parsing for pip workflows.
//!
//! pip accepts options inline in requirements files. This parser captures the
//! security-relevant flags: `--require-hashes`, `--trusted-host`,
//! `--index-url`, `--extra-index-url`, and the presence of `--hash=` pins.

use std::path::Path;

use crate::ecosystems::EcoError;

#[derive(Debug, Clone, Default)]
pub struct RequirementsSettings {
    pub require_hashes: bool,
    pub trusted_hosts: Vec<String>,
    pub index_urls: Vec<String>,
    pub extra_index_urls: Vec<String>,
    /// True only when every requirement is hash-pinned, mirroring pip's
    /// `--require-hashes` rule that rejects any unpinned requirement.
    pub has_hash_pins: bool,
    /// Count of requirement lines (excluding options, comments, blanks).
    pub requirement_count: usize,
    /// Count of requirement lines that carry at least one `--hash=` pin.
    pub hashed_requirement_count: usize,
    /// Raw requirement specs (and `-e`/`--editable` targets) for SD006 source
    /// classification.
    pub specs: Vec<String>,
}

pub fn load(
    ctx: &crate::filesystem::WorkspaceContext,
    relative: &Path,
) -> Result<RequirementsSettings, EcoError> {
    let text = crate::filesystem::read_text(ctx, relative).map_err(|source| EcoError::Read {
        path: relative.to_path_buf(),
        source,
    })?;
    Ok(parse(&text))
}

pub fn parse(text: &str) -> RequirementsSettings {
    let mut settings = RequirementsSettings::default();
    // pip joins lines ending in `\` into one logical requirement, so hashes on
    // continuation lines belong to the requirement above them.
    for logical in logical_lines(text) {
        let line = logical.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('-') {
            parse_option_line(line, &mut settings);
            continue;
        }
        settings.requirement_count += 1;
        // Capture the requirement up to the first `--hash`/option for SD006.
        settings.specs.push(requirement_spec(line));
        if line_has_hash(line) {
            settings.hashed_requirement_count += 1;
        }
    }
    // Integrity is only enforced when the explicit flag is present or every
    // requirement is hash-pinned. A single hashed requirement is not enough.
    if settings.requirement_count > 0
        && settings.hashed_requirement_count == settings.requirement_count
    {
        settings.has_hash_pins = true;
        settings.require_hashes = true;
    }
    settings
}

/// Joins physical lines into logical lines, honoring trailing `\` continuations
/// and stripping inline comments first.
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for raw in text.lines() {
        let stripped = strip_inline_comment(raw);
        if let Some(prefix) = stripped.trim_end().strip_suffix('\\') {
            current.push_str(prefix);
            current.push(' ');
        } else {
            current.push_str(stripped);
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

/// The requirement portion of a line, excluding any trailing options such as
/// `--hash=…`. Tokens are re-joined with single spaces.
fn requirement_spec(line: &str) -> String {
    line.split_whitespace()
        .take_while(|tok| !tok.starts_with("--"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether a requirement's logical line carries a `--hash` pin in any form.
fn line_has_hash(line: &str) -> bool {
    line.split_whitespace()
        .any(|t| t == "--hash" || t.starts_with("--hash="))
}

fn strip_inline_comment(line: &str) -> &str {
    // Requirements may carry inline comments preceded by `  # `. A leading `#`
    // is handled by the caller. We avoid splitting on `#` inside URLs.
    if let Some(idx) = find_inline_comment(line) {
        &line[..idx]
    } else {
        line
    }
}

fn find_inline_comment(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut in_url = false;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b':' && i + 2 < bytes.len() && bytes[i + 1] == b'/' && bytes[i + 2] == b'/' {
            in_url = true;
        }
        if !in_url && c == b'#' && i > 0 && bytes[i - 1] == b' ' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn parse_option_line(line: &str, settings: &mut RequirementsSettings) {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let mut i = 0;
    while i < tokens.len() {
        // Options accept both `--flag value` and `--flag=value`.
        let (flag, inline) = match tokens[i].split_once('=') {
            Some((f, v)) => (f, Some(v)),
            None => (tokens[i], None),
        };
        match flag {
            "--require-hashes" => settings.require_hashes = true,
            "--trusted-host" => {
                if let Some(host) = take_value(inline, &tokens, &mut i) {
                    settings.trusted_hosts.push(host);
                }
            }
            "--index-url" | "-i" => {
                if let Some(url) = take_value(inline, &tokens, &mut i) {
                    settings.index_urls.push(url);
                }
            }
            "--extra-index-url" => {
                if let Some(url) = take_value(inline, &tokens, &mut i) {
                    settings.extra_index_urls.push(url);
                }
            }
            "-e" | "--editable" => {
                // Editable installs are typically local paths or VCS refs;
                // record them for SD006 (they cannot be hash-pinned).
                if let Some(target) = take_value(inline, &tokens, &mut i) {
                    settings.specs.push(format!("-e {target}"));
                }
            }
            _ => {}
        }
        i += 1;
    }
}

/// Resolves an option value from either the inline `=value` or the next token,
/// advancing the cursor when the next token is consumed.
fn take_value(inline: Option<&str>, tokens: &[&str], i: &mut usize) -> Option<String> {
    if let Some(value) = inline {
        return Some(value.to_string());
    }
    if let Some(value) = tokens.get(*i + 1) {
        *i += 1;
        return Some(value.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_requirements_and_ignores_options() {
        let s = parse("--index-url https://pypi.org/simple\nrequests==2.31.0\nflask==3.0.0\n");
        assert_eq!(s.requirement_count, 2);
        assert_eq!(s.index_urls, vec!["https://pypi.org/simple"]);
    }

    #[test]
    fn captures_require_hashes() {
        let s = parse("--require-hashes\nrequests==2.31.0\n");
        assert!(s.require_hashes);
    }

    #[test]
    fn captures_trusted_host_and_extra_index() {
        let s = parse("--trusted-host pypi.internal\n--extra-index-url http://pypi.internal/simple\nrequests==2.31.0\n");
        assert_eq!(s.trusted_hosts, vec!["pypi.internal"]);
        assert_eq!(s.extra_index_urls, vec!["http://pypi.internal/simple"]);
    }

    #[test]
    fn hash_pins_imply_require_hashes() {
        let s = parse("requests==2.31.0 --hash=sha256:abc123\n");
        assert!(s.has_hash_pins);
        assert!(s.require_hashes);
    }

    #[test]
    fn strips_inline_comment_but_keeps_url() {
        let s = parse("requests==2.31.0  # pinned\n--index-url https://pypi.org/simple\n");
        assert_eq!(s.requirement_count, 1);
        assert_eq!(s.index_urls, vec!["https://pypi.org/simple"]);
    }

    #[test]
    fn skips_blank_and_comment_lines() {
        let s = parse("\n# a comment\nrequests==2.31.0\n");
        assert_eq!(s.requirement_count, 1);
    }

    #[test]
    fn parses_equals_joined_options() {
        // Regression: `--flag=value` was dropped because parsing assumed the
        // value was the next whitespace-separated token.
        let s = parse(
            "--index-url=http://pypi.internal/simple\n--trusted-host=pypi.internal\n--extra-index-url=https://extra/simple\nrequests==2.31.0\n",
        );
        assert_eq!(s.index_urls, vec!["http://pypi.internal/simple"]);
        assert_eq!(s.trusted_hosts, vec!["pypi.internal"]);
        assert_eq!(s.extra_index_urls, vec!["https://extra/simple"]);
    }

    #[test]
    fn partial_hash_pinning_is_not_treated_as_enforced() {
        // Regression: a single `--hash` used to mark the whole file as pinned.
        let s = parse("requests==2.31.0 --hash=sha256:aaa\nflask==3.0.0\n");
        assert_eq!(s.requirement_count, 2);
        assert_eq!(s.hashed_requirement_count, 1);
        assert!(!s.has_hash_pins);
        assert!(!s.require_hashes);
    }

    #[test]
    fn all_requirements_hashed_is_enforced() {
        let s = parse("requests==2.31.0 --hash=sha256:aaa\nflask==3.0.0 --hash=sha256:bbb\n");
        assert!(s.has_hash_pins);
        assert!(s.require_hashes);
    }

    #[test]
    fn hash_on_continuation_line_counts_for_requirement() {
        let s = parse("requests==2.31.0 \\\n    --hash=sha256:aaa\n");
        assert_eq!(s.requirement_count, 1);
        assert_eq!(s.hashed_requirement_count, 1);
        assert!(s.require_hashes);
    }
}
