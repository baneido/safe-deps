//! `pip.conf` / `pip.ini` parsing (minimal INI).
//!
//! pip config uses INI sections such as `[global]` and `[install]`. We capture
//! the security-relevant keys regardless of section.

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

pub fn parse(text: &str) -> PipConfSettings {
    let mut settings = PipConfSettings::default();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            continue;
        }
        let (key, value) = match line.split_once('=') {
            Some(pair) => pair,
            None => continue,
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        match key {
            "trusted-host" => settings.trusted_hosts.push(value.to_string()),
            "index-url" => settings.index_urls.push(value.to_string()),
            "extra-index-url" => settings.extra_index_urls.push(value.to_string()),
            "require-hashes" => {
                settings.require_hashes = matches!(
                    value.to_ascii_lowercase().as_str(),
                    "true" | "1" | "yes" | "on"
                );
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
}
