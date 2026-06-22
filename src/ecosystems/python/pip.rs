//! `pip.conf` / `pip.ini` parsing (minimal INI).
//!
//! pip config uses INI sections such as `[global]` and `[install]`. We capture
//! the security-relevant keys regardless of section.
//!
//! ## Multi-line values
//!
//! INI continuation lines begin with leading whitespace on the lines following
//! a `key = value` assignment. This is how pip encodes list-like settings:
//!
//! ```ini
//! [global]
//! trusted-host =
//!     pypi.org
//!     files.pythonhosted.org
//! extra-index-url =
//!     http://private.example/simple
//!     https://pypi.org/simple
//! ```
//!
//! The parser joins continuation lines into the key's value, then splits on
//! whitespace to produce one entry per token. Single-line values are unchanged.

use std::path::Path;

use crate::ecosystems::EcoError;

#[derive(Debug, Clone, Default)]
pub struct PipConfSettings {
    pub trusted_hosts: Vec<String>,
    pub index_urls: Vec<String>,
    pub extra_index_urls: Vec<String>,
    pub require_hashes: bool,
}

pub fn load(
    ctx: &crate::filesystem::WorkspaceContext,
    relative: &Path,
) -> Result<PipConfSettings, EcoError> {
    let text = crate::filesystem::read_text(ctx, relative).map_err(|source| EcoError::Read {
        path: relative.to_path_buf(),
        source,
    })?;
    Ok(parse(&text))
}

/// A parsed key-value pair from the INI file, where the value may span
/// multiple continuation lines that have already been joined.
struct KeyValue {
    key: String,
    /// All whitespace-separated tokens from the (possibly multi-line) value.
    tokens: Vec<String>,
}

/// Collect logical `key = value` entries from an INI-formatted string.
///
/// Continuation lines (lines whose first character is a space or tab) are
/// appended to the most-recent key's value before tokenising, matching pip's
/// own parsing behaviour.
fn collect_entries(text: &str) -> Vec<KeyValue> {
    // We store (key, accumulated_raw_value) while scanning, then emit a
    // `KeyValue` when the key changes.
    let mut entries: Vec<KeyValue> = Vec::new();

    // Flush the pending key/value into `entries`.
    let flush = |entries: &mut Vec<KeyValue>, key: String, raw: String| {
        // Split on any whitespace (spaces, tabs, newlines introduced by
        // continuation) to get individual tokens; ignore empty segments.
        let tokens: Vec<String> = raw
            .split_whitespace()
            .filter(|t| !t.is_empty())
            .map(|t| t.trim_matches('"').to_string())
            .collect();
        if !key.is_empty() {
            entries.push(KeyValue { key, tokens });
        }
    };

    let mut pending_key = String::new();
    let mut pending_raw = String::new();

    for raw_line in text.lines() {
        // Continuation line: starts with a space or tab (after the key line).
        if !pending_key.is_empty()
            && raw_line
                .chars()
                .next()
                .map(|c| c == ' ' || c == '\t')
                .unwrap_or(false)
        {
            pending_raw.push(' ');
            pending_raw.push_str(raw_line.trim());
            continue;
        }

        // Any other line means the previous key (if any) is complete.
        if !pending_key.is_empty() {
            let key = std::mem::take(&mut pending_key);
            let raw = std::mem::take(&mut pending_raw);
            flush(&mut entries, key, raw);
        }

        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            continue;
        }

        if let Some((k, v)) = line.split_once('=') {
            pending_key = k.trim().to_string();
            pending_raw = v.trim().trim_matches('"').to_string();
        }
    }

    // Flush any trailing key.
    if !pending_key.is_empty() {
        flush(&mut entries, pending_key, pending_raw);
    }

    entries
}

pub fn parse(text: &str) -> PipConfSettings {
    let mut settings = PipConfSettings::default();
    for entry in collect_entries(text) {
        match entry.key.as_str() {
            "trusted-host" => {
                settings.trusted_hosts.extend(entry.tokens);
            }
            "index-url" => {
                settings.index_urls.extend(entry.tokens);
            }
            "extra-index-url" => {
                settings.extra_index_urls.extend(entry.tokens);
            }
            "require-hashes" => {
                settings.require_hashes = entry.tokens.first().is_some_and(|v| {
                    matches!(v.to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on")
                });
            }
            _ => {}
        }
    }
    settings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_global_section_keys() {
        let s = parse(
            "[global]\ntrusted-host = pypi.internal\nindex-url = http://pypi.internal/simple\n",
        );
        assert_eq!(s.trusted_hosts, vec!["pypi.internal"]);
        assert_eq!(s.index_urls, vec!["http://pypi.internal/simple"]);
    }

    #[test]
    fn parses_extra_index_and_require_hashes() {
        let s = parse("[install]\nextra-index-url = https://extra/simple\nrequire-hashes = true\n");
        assert_eq!(s.extra_index_urls, vec!["https://extra/simple"]);
        assert!(s.require_hashes);
    }

    #[test]
    fn ignores_comments_and_section_headers() {
        let s = parse("; comment\n[global]\n# another\ntrusted-host = host.example\n");
        assert_eq!(s.trusted_hosts, vec!["host.example"]);
    }

    // --- multi-line / continuation tests -------------------------------------

    #[test]
    fn multiline_trusted_host_continuation() {
        let text = "[global]\ntrusted-host =\n    pypi.org\n    files.pythonhosted.org\n";
        let s = parse(text);
        assert_eq!(
            s.trusted_hosts,
            vec!["pypi.org", "files.pythonhosted.org"],
            "both hosts should be captured from continuation lines"
        );
    }

    #[test]
    fn multiline_extra_index_url_continuation() {
        let text = "[global]\nextra-index-url =\n    http://private.example/simple\n    https://pypi.org/simple\n";
        let s = parse(text);
        assert_eq!(
            s.extra_index_urls,
            vec!["http://private.example/simple", "https://pypi.org/simple"],
            "both extra index URLs should be captured"
        );
    }

    #[test]
    fn multiline_index_url_continuation() {
        let text = "[global]\nindex-url =\n    https://primary.example/simple\n";
        let s = parse(text);
        assert_eq!(
            s.index_urls,
            vec!["https://primary.example/simple"],
            "primary index URL from continuation should be captured"
        );
    }

    #[test]
    fn mixed_single_and_multiline_values() {
        // A realistic pip.conf: multi-line trusted-host AND single-line keys.
        let text = "[global]\ntrusted-host =\n    pypi.org\n    files.pythonhosted.org\nextra-index-url = http://private.example/simple\nrequire-hashes = true\n";
        let s = parse(text);
        assert_eq!(s.trusted_hosts, vec!["pypi.org", "files.pythonhosted.org"]);
        assert_eq!(s.extra_index_urls, vec!["http://private.example/simple"]);
        assert!(s.require_hashes);
    }

    #[test]
    fn tab_indented_continuation_lines() {
        let text = "[global]\ntrusted-host =\n\tpypi.org\n\tfiles.pythonhosted.org\n";
        let s = parse(text);
        assert_eq!(
            s.trusted_hosts,
            vec!["pypi.org", "files.pythonhosted.org"],
            "tab-indented continuation lines should be joined"
        );
    }

    #[test]
    fn inline_value_followed_by_continuation() {
        // First value on the same line as the key, then continuation for more.
        let text = "[global]\ntrusted-host = pypi.org\n    files.pythonhosted.org\n";
        let s = parse(text);
        assert_eq!(
            s.trusted_hosts,
            vec!["pypi.org", "files.pythonhosted.org"],
            "inline value plus continuation should all be captured"
        );
    }
}
