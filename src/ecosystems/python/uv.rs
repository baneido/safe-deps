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
}
