//! `uv.toml` parsing. uv accepts the same keys as `[tool.uv]` at the top level
//! and under `[pip]`.

use std::path::Path;

use crate::ecosystems::python::pyproject::UvSettings;
use crate::ecosystems::EcoError;

pub fn load(
    ctx: &crate::filesystem::WorkspaceContext,
    relative: &Path,
) -> Result<UvSettings, EcoError> {
    let text = crate::filesystem::read_text(ctx, relative).map_err(|source| EcoError::Read {
        path: relative.to_path_buf(),
        source,
    })?;
    Ok(parse(&text))
}

pub fn parse(text: &str) -> UvSettings {
    let value: toml::Value = match toml::from_str(text) {
        Ok(v) => v,
        Err(_) => return UvSettings::default(),
    };
    // Top-level uv keys behave like [tool.uv].
    let mut settings = extract(&value);
    // Merge `[pip]` section keys that overlap.
    if let Some(pip) = value.get("pip") {
        let pip_settings = extract(pip);
        settings.trusted_hosts.extend(pip_settings.trusted_hosts);
        settings.index_urls.extend(pip_settings.index_urls);
        settings
            .extra_index_urls
            .extend(pip_settings.extra_index_urls);
        settings
            .allow_insecure_hosts
            .extend(pip_settings.allow_insecure_hosts);
    }
    settings
}

fn extract(value: &toml::Value) -> UvSettings {
    let mut settings = UvSettings::default();
    if let Some(arr) = value.get("allow-insecure-host").and_then(|v| v.as_array()) {
        settings.allow_insecure_hosts = arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
    }
    if let Some(s) = value.get("index-strategy").and_then(|v| v.as_str()) {
        settings.index_strategy = Some(s.to_string());
    }
    if let Some(arr) = value.get("index").and_then(|v| v.as_array()) {
        for entry in arr {
            if let Some(url) = entry.as_str() {
                settings.index_urls.push(url.to_string());
            } else if let Some(url) = entry.get("url").and_then(|v| v.as_str()) {
                settings.index_urls.push(url.to_string());
            }
        }
    }
    if let Some(arr) = value.get("extra-index-url").and_then(|v| v.as_array()) {
        settings.extra_index_urls = arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
    }
    if let Some(arr) = value.get("trusted-host").and_then(|v| v.as_array()) {
        settings.trusted_hosts = arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
    }
    settings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_top_level_keys() {
        let s =
            parse("allow-insecure-host = [\"internal\"]\nindex-strategy = \"unsafe-best-match\"\n");
        assert_eq!(s.allow_insecure_hosts, vec!["internal"]);
        assert_eq!(s.index_strategy.as_deref(), Some("unsafe-best-match"));
    }

    #[test]
    fn merges_pip_section() {
        let s = parse("[pip]\nextra-index-url = [\"http://pypi.internal/simple\"]\n");
        assert_eq!(s.extra_index_urls, vec!["http://pypi.internal/simple"]);
    }

    #[test]
    fn parses_index_table_array() {
        let s = parse("[[index]]\nurl = \"https://example/simple\"\n");
        assert_eq!(s.index_urls, vec!["https://example/simple"]);
    }

    #[test]
    fn malformed_toml_yields_default() {
        // A broken uv.toml must degrade to "nothing declared", not panic.
        let s = parse("this is not = valid toml {{{");
        assert!(s.allow_insecure_hosts.is_empty());
        assert!(s.index_urls.is_empty());
        assert!(s.extra_index_urls.is_empty());
        assert!(s.trusted_hosts.is_empty());
        assert!(s.index_strategy.is_none());
    }

    #[test]
    fn index_string_array_form() {
        // `index` may be a plain array of URL strings, not only `[[index]]`.
        let s = parse("index = [\"https://a/simple\", \"https://b/simple\"]\n");
        assert_eq!(s.index_urls, vec!["https://a/simple", "https://b/simple"]);
    }

    #[test]
    fn index_mixed_string_and_table_forms() {
        // A single `index` array may mix bare URL strings and `{ url = ... }`.
        let s = parse("index = [\"https://a/simple\", { url = \"https://b/simple\" }]\n");
        assert_eq!(s.index_urls, vec!["https://a/simple", "https://b/simple"]);
    }

    #[test]
    fn wrong_value_types_are_tolerated() {
        // Valid TOML but with unexpected scalar types must be ignored, not panic,
        // and non-string array entries are filtered out.
        let s = parse(
            "index-strategy = 123\nallow-insecure-host = \"notanarray\"\ntrusted-host = [\"ok\", 7]\n",
        );
        assert!(s.index_strategy.is_none());
        assert!(s.allow_insecure_hosts.is_empty());
        assert_eq!(s.trusted_hosts, vec!["ok"]);
    }

    #[test]
    fn merges_top_level_and_pip_sections() {
        // Keys set both at the top level and under `[pip]` are concatenated.
        let s = parse("allow-insecure-host = [\"top\"]\n[pip]\nallow-insecure-host = [\"pip\"]\n");
        assert_eq!(s.allow_insecure_hosts, vec!["top", "pip"]);
    }
}
