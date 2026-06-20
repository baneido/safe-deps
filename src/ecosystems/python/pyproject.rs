//! `pyproject.toml` parsing: `[tool.uv]` detection and settings extraction.

use std::path::Path;

use crate::ecosystems::EcoError;

/// Whether `[tool.uv]` is declared, plus uv-relevant settings.
#[derive(Debug, Clone, Default)]
pub struct Pyproject {
    pub has_tool_uv: bool,
    pub project_name: Option<String>,
    pub has_dependencies: bool,
    pub uv: UvSettings,
}

#[derive(Debug, Clone, Default)]
pub struct UvSettings {
    pub allow_insecure_hosts: Vec<String>,
    pub index_strategy: Option<String>,
    pub index_urls: Vec<String>,
    pub extra_index_urls: Vec<String>,
    pub trusted_hosts: Vec<String>,
}

pub fn load(
    ctx: &crate::filesystem::WorkspaceContext,
    relative: &Path,
) -> Result<Pyproject, EcoError> {
    let text = crate::filesystem::read_text(ctx, relative).map_err(|source| EcoError::Read {
        path: relative.to_path_buf(),
        source,
    })?;
    Ok(parse(&text))
}

pub fn parse(text: &str) -> Pyproject {
    let value: toml::Value = match toml::from_str(text) {
        Ok(v) => v,
        Err(_) => return Pyproject::default(),
    };
    let project_name = value
        .get("project")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .map(|s| s.to_string());

    let project_deps = value
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_array())
        .is_some_and(|a| !a.is_empty());
    let uv_dev = value
        .get("tool")
        .and_then(|t| t.get("uv"))
        .and_then(|u| u.get("dev-dependencies"))
        .and_then(|d| d.as_table())
        .is_some_and(|t| !t.is_empty());
    let has_dependencies = project_deps || uv_dev;

    let tool_uv = value.get("tool").and_then(|t| t.get("uv"));
    let has_tool_uv = tool_uv.is_some();
    let uv = tool_uv.map(extract_uv_settings).unwrap_or_default();

    Pyproject {
        has_tool_uv,
        project_name,
        has_dependencies,
        uv,
    }
}

fn extract_uv_settings(tool_uv: &toml::Value) -> UvSettings {
    let mut settings = UvSettings::default();
    if let Some(arr) = tool_uv
        .get("allow-insecure-host")
        .and_then(|v| v.as_array())
    {
        settings.allow_insecure_hosts = arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
    }
    if let Some(s) = tool_uv.get("index-strategy").and_then(|v| v.as_str()) {
        settings.index_strategy = Some(s.to_string());
    }
    if let Some(arr) = tool_uv.get("index").and_then(|v| v.as_array()) {
        for entry in arr {
            if let Some(url) = entry.as_str() {
                settings.index_urls.push(url.to_string());
            } else if let Some(url) = entry.get("url").and_then(|v| v.as_str()) {
                settings.index_urls.push(url.to_string());
            }
        }
    }
    if let Some(arr) = tool_uv.get("extra-index-url").and_then(|v| v.as_array()) {
        settings.extra_index_urls = arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
    }
    if let Some(arr) = tool_uv.get("trusted-host").and_then(|v| v.as_array()) {
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
    fn detects_tool_uv_and_dependencies() {
        let p = parse(
            "[project]\nname = \"demo\"\ndependencies = [\"requests\"]\n[tool.uv]\nindex-strategy = \"unsafe-best-match\"\n",
        );
        assert!(p.has_tool_uv);
        assert!(p.has_dependencies);
        assert_eq!(p.project_name.as_deref(), Some("demo"));
        assert_eq!(p.uv.index_strategy.as_deref(), Some("unsafe-best-match"));
    }

    #[test]
    fn no_tool_uv_section() {
        let p = parse("[project]\nname = \"demo\"\n");
        assert!(!p.has_tool_uv);
        assert!(!p.has_dependencies);
    }

    #[test]
    fn extracts_allow_insecure_host() {
        let p = parse("[tool.uv]\nallow-insecure-host = [\"internal.example\"]\n");
        assert_eq!(p.uv.allow_insecure_hosts, vec!["internal.example"]);
    }

    #[test]
    fn dev_dependencies_count_as_dependencies() {
        let p = parse("[tool.uv.dev-dependencies]\npytest = \"*\"\n");
        assert!(p.has_dependencies);
    }

    #[test]
    fn invalid_toml_yields_default() {
        let p = parse("= = =");
        assert!(!p.has_tool_uv);
    }
}
