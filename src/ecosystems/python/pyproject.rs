//! `pyproject.toml` parsing: `[tool.uv]` detection and settings extraction.

use std::path::Path;

use crate::ecosystems::EcoError;

/// Whether `[tool.uv]` is declared, plus uv-relevant settings.
#[derive(Debug, Clone, Default)]
pub struct Pyproject {
    pub has_tool_uv: bool,
    pub project_name: Option<String>,
    pub has_dependencies: bool,
    /// `[project] dependencies` (PEP 508 strings), for SD006 source analysis.
    pub dependencies: Vec<String>,
    /// Flattened `[project.optional-dependencies]` values.
    pub optional_dependencies: Vec<String>,
    /// `[tool.uv] dev-dependencies` (array or legacy table form, normalized to
    /// PEP 508 strings), for SD006 source analysis.
    pub dev_dependencies: Vec<String>,
    pub uv: UvSettings,
}

impl Pyproject {
    /// All dependencies classified by source for SD006, anchored to `file`.
    /// PEP 508 names are stripped to the bare distribution name for display.
    pub fn classified_dependencies(&self, file: &Path) -> Vec<crate::ecosystems::Dependency> {
        use crate::ecosystems::source::classify_python_source;
        use crate::ecosystems::{Dependency, DependencyGroup};
        let groups = [
            (&self.dependencies, DependencyGroup::Production),
            (&self.optional_dependencies, DependencyGroup::Optional),
            (&self.dev_dependencies, DependencyGroup::Development),
        ];
        let mut out = Vec::new();
        for (specs, group) in groups {
            for spec in specs {
                out.push(Dependency {
                    name: pep508_name(spec),
                    source: classify_python_source(spec),
                    spec: spec.clone(),
                    group,
                    file: file.to_path_buf(),
                });
            }
        }
        out
    }
}

/// Normalizes a legacy `name = "spec"` dev-dependency table entry into a PEP 508
/// string: a URL/VCS value becomes a `name @ url` direct reference, a version
/// constraint is appended (`name>=1`).
fn pep508_from_table_entry(name: &str, spec: &str) -> String {
    let s = spec.trim();
    let is_url = ["git+", "git://", "ssh://", "http://", "https://", "file:"]
        .iter()
        .any(|p| s.starts_with(p));
    if is_url {
        format!("{name} @ {s}")
    } else {
        format!("{name}{s}")
    }
}

/// Extracts the distribution name from a PEP 508 requirement string.
pub fn pep508_name(spec: &str) -> String {
    let s = spec.trim();
    let end = s
        .find(|c: char| {
            c.is_whitespace() || matches!(c, '=' | '<' | '>' | '~' | '!' | '@' | '[' | '(')
        })
        .unwrap_or(s.len());
    s[..end].to_string()
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

    let dependencies =
        collect_string_array(value.get("project").and_then(|p| p.get("dependencies")));
    let mut optional_dependencies = Vec::new();
    if let Some(table) = value
        .get("project")
        .and_then(|p| p.get("optional-dependencies"))
        .and_then(|d| d.as_table())
    {
        for group in table.values() {
            optional_dependencies.extend(collect_string_array(Some(group)));
        }
    }
    let uv_dev_dependencies = value
        .get("tool")
        .and_then(|t| t.get("uv"))
        .and_then(|u| u.get("dev-dependencies"));
    // uv accepts either an array of PEP 508 strings or a legacy name=spec table;
    // normalize both into PEP 508 strings so SD006 analyzes either form.
    let mut dev_dependencies = collect_string_array(uv_dev_dependencies);
    if let Some(table) = uv_dev_dependencies.and_then(|d| d.as_table()) {
        for (name, val) in table {
            if let Some(spec) = val.as_str() {
                dev_dependencies.push(pep508_from_table_entry(name, spec));
            }
        }
    }
    // PEP 735 `[dependency-groups]`: each group is an array of PEP 508 strings
    // (and `{ include-group = … }` directives, which carry no source and are
    // skipped). Treat them as development dependencies for SD006.
    if let Some(groups) = value.get("dependency-groups").and_then(|g| g.as_table()) {
        for group in groups.values() {
            dev_dependencies.extend(collect_string_array(Some(group)));
        }
    }
    let has_dependencies = !dependencies.is_empty()
        || !optional_dependencies.is_empty()
        || !dev_dependencies.is_empty();

    let tool_uv = value.get("tool").and_then(|t| t.get("uv"));
    let has_tool_uv = tool_uv.is_some();
    let uv = tool_uv.map(extract_uv_settings).unwrap_or_default();

    Pyproject {
        has_tool_uv,
        project_name,
        has_dependencies,
        dependencies,
        optional_dependencies,
        dev_dependencies,
        uv,
    }
}

/// Collects a TOML array of strings, ignoring non-string entries.
fn collect_string_array(value: Option<&toml::Value>) -> Vec<String> {
    value
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
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
    fn dev_dependencies_table_form_is_classified() {
        let p = parse(
            "[tool.uv.dev-dependencies]\ninternal = \"git+https://h/r.git\"\npytest = \">=7\"\n",
        );
        let deps = p.classified_dependencies(std::path::Path::new("pyproject.toml"));
        let internal = deps
            .iter()
            .find(|d| d.name == "internal")
            .expect("internal dep");
        assert!(matches!(
            internal.source,
            crate::ecosystems::DependencySource::Git { .. }
        ));
        assert!(deps.iter().any(|d| d.name == "pytest"));
    }

    #[test]
    fn invalid_toml_yields_default() {
        let p = parse("= = =");
        assert!(!p.has_tool_uv);
    }
}
