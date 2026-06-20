//! `.npmrc` parsing for npm and pnpm.
//!
//! `.npmrc` is line-oriented `key=value` with `;`/`#` comments and optional
//! scope prefixes such as `@scope:registry=https://...`.

use std::path::Path;

use crate::ecosystems::EcoError;

/// Security-relevant settings extracted from an `.npmrc`.
#[derive(Debug, Clone, Default)]
pub struct NpmrcSettings {
    pub strict_ssl: Option<bool>,
    pub registry: Option<String>,
    pub package_lock_enabled: Option<bool>,
    /// Any registry URLs (scoped or default) that use plaintext HTTP.
    pub http_registries: Vec<String>,
}

pub fn load(
    ctx: &crate::filesystem::WorkspaceContext,
    relative: &Path,
) -> Result<NpmrcSettings, EcoError> {
    let text = crate::filesystem::read_text(ctx, relative).map_err(|source| EcoError::Read {
        path: relative.to_path_buf(),
        source,
    })?;
    Ok(parse(&text))
}

pub fn parse(text: &str) -> NpmrcSettings {
    let mut settings = NpmrcSettings::default();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        let (key, value) = match line.split_once('=') {
            Some(pair) => pair,
            None => continue,
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        match key {
            "strict-ssl" => settings.strict_ssl = parse_bool(value),
            "package-lock" => settings.package_lock_enabled = parse_bool(value),
            "registry" => {
                settings.registry = Some(value.to_string());
                if value.starts_with("http://") {
                    settings.http_registries.push(value.to_string());
                }
            }
            _ if key.ends_with(":registry") && value.starts_with("http://") => {
                settings.http_registries.push(value.to_string());
            }
            _ => {}
        }
    }
    settings
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_strict_ssl_false() {
        let s = parse("strict-ssl=false\n");
        assert_eq!(s.strict_ssl, Some(false));
    }

    #[test]
    fn parses_http_default_registry() {
        let s = parse("registry=http://registry.example.com/\n");
        assert_eq!(s.registry.as_deref(), Some("http://registry.example.com/"));
        assert_eq!(s.http_registries, vec!["http://registry.example.com/"]);
    }

    #[test]
    fn https_registry_is_not_flagged() {
        let s = parse("registry=https://registry.npmjs.org/\n");
        assert!(s.http_registries.is_empty());
    }

    #[test]
    fn flags_http_scoped_registry() {
        let s = parse("@acme:registry=http://npm.acme.internal/\n");
        assert_eq!(s.http_registries, vec!["http://npm.acme.internal/"]);
    }

    #[test]
    fn parses_package_lock_false() {
        let s = parse("package-lock=false\n");
        assert_eq!(s.package_lock_enabled, Some(false));
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let s = parse("; a comment\n\n# another\nstrict-ssl=false\n");
        assert_eq!(s.strict_ssl, Some(false));
    }

    #[test]
    fn strips_surrounding_quotes() {
        let s = parse("registry=\"http://q.example.com/\"\n");
        assert_eq!(s.registry.as_deref(), Some("http://q.example.com/"));
    }
}
