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
    /// Whether any requirement line carried `--hash=` metadata.
    pub has_hash_pins: bool,
    /// Count of requirement lines (excluding options, comments, blanks).
    pub requirement_count: usize,
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
    for raw in text.lines() {
        let line = strip_inline_comment(raw).trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('-') {
            parse_option_line(line, &mut settings);
            continue;
        }
        settings.requirement_count += 1;
        if line.contains("--hash=") {
            settings.has_hash_pins = true;
        }
    }
    if settings.has_hash_pins {
        settings.require_hashes = true;
    }
    settings
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
        let token = tokens[i];
        match token {
            "--require-hashes" => settings.require_hashes = true,
            "--trusted-host" => {
                if let Some(host) = tokens.get(i + 1) {
                    settings.trusted_hosts.push(host.to_string());
                    i += 1;
                }
            }
            "--index-url" | "-i" => {
                if let Some(url) = tokens.get(i + 1) {
                    settings.index_urls.push(url.to_string());
                    i += 1;
                }
            }
            "--extra-index-url" => {
                if let Some(url) = tokens.get(i + 1) {
                    settings.extra_index_urls.push(url.to_string());
                    i += 1;
                }
            }
            "--hash" => {
                settings.has_hash_pins = true;
            }
            _ => {
                if let Some(rest) = token.strip_prefix("--hash=") {
                    let _ = rest;
                    settings.has_hash_pins = true;
                }
            }
        }
        i += 1;
    }
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
}
