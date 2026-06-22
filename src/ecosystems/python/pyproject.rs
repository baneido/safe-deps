//! `pyproject.toml` parsing: `[tool.uv]` and `[tool.poetry]` detection and
//! settings extraction.

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
    /// `[tool.poetry.dependencies]` entries (name → TOML value), excluding the
    /// `python` key which is a version constraint on the interpreter, not a
    /// dependency to be installed.
    pub poetry_dependencies: Vec<PoetryDep>,
    /// `[tool.poetry.group.*.dependencies]` entries, flattened across groups.
    pub poetry_dev_dependencies: Vec<PoetryDep>,
    pub uv: UvSettings,
}

/// A single dependency declared in a Poetry table (`name = value`).
#[derive(Debug, Clone)]
pub struct PoetryDep {
    pub name: String,
    pub value: toml::Value,
}

impl Pyproject {
    /// All dependencies classified by source for SD006, anchored to `file`.
    /// PEP 508 names are stripped to the bare distribution name for display.
    pub fn classified_dependencies(&self, file: &Path) -> Vec<crate::ecosystems::Dependency> {
        use crate::ecosystems::source::{classify_poetry_dependency, classify_python_source};
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
        // Poetry production dependencies (`[tool.poetry.dependencies]`).
        for dep in &self.poetry_dependencies {
            out.push(Dependency {
                name: dep.name.clone(),
                source: classify_poetry_dependency(&dep.value),
                spec: poetry_dep_spec(&dep.value),
                group: DependencyGroup::Production,
                file: file.to_path_buf(),
            });
        }
        // Poetry group/dev dependencies (`[tool.poetry.group.*.dependencies]`).
        for dep in &self.poetry_dev_dependencies {
            out.push(Dependency {
                name: dep.name.clone(),
                source: classify_poetry_dependency(&dep.value),
                spec: poetry_dep_spec(&dep.value),
                group: DependencyGroup::Development,
                file: file.to_path_buf(),
            });
        }
        out
    }
}

/// Builds a concise, single-line spec summary for a Poetry dependency, used in
/// SD006 messages and de-duplication. The dependency name is omitted (SD006
/// messages already include it). A plain string is the version constraint; an
/// inline table is summarized to the source-relevant keys (`git` + ref, `path`,
/// or `url`), mirroring Cargo's `spec_string()`.
fn poetry_dep_spec(value: &toml::Value) -> String {
    if let Some(v) = value.as_str() {
        return v.to_string();
    }
    if let Some(t) = value.as_table() {
        if let Some(p) = t.get("path").and_then(|v| v.as_str()) {
            return format!("path = \"{p}\"");
        }
        if let Some(g) = t.get("git").and_then(|v| v.as_str()) {
            let git_ref = ["rev", "tag", "branch"]
                .iter()
                .find_map(|k| {
                    t.get(*k)
                        .and_then(|v| v.as_str())
                        .map(|v| format!(", {k} = \"{v}\""))
                })
                .unwrap_or_default();
            return format!("git = \"{g}\"{git_ref}");
        }
        if let Some(u) = t.get("url").and_then(|v| v.as_str()) {
            return format!("url = \"{u}\"");
        }
        if let Some(v) = t.get("version").and_then(|v| v.as_str()) {
            return v.to_string();
        }
    }
    "<complex>".to_string()
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

    // `[tool.poetry.dependencies]`: each entry is `name = version_string` or
    // `name = { git = "…", … }`. The `python` key is an interpreter constraint,
    // not an installable package, and must be skipped.
    let mut poetry_dependencies = Vec::new();
    if let Some(table) = value
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_table())
    {
        for (name, val) in table {
            if name == "python" {
                continue;
            }
            poetry_dependencies.push(PoetryDep {
                name: name.clone(),
                value: val.clone(),
            });
        }
    }

    // `[tool.poetry.group.*.dependencies]`: flatten all named groups into a
    // single collection treated as development / non-production dependencies.
    let mut poetry_dev_dependencies = Vec::new();
    if let Some(groups) = value
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("group"))
        .and_then(|g| g.as_table())
    {
        for group_table in groups.values() {
            if let Some(deps) = group_table.get("dependencies").and_then(|d| d.as_table()) {
                for (name, val) in deps {
                    if name == "python" {
                        continue;
                    }
                    poetry_dev_dependencies.push(PoetryDep {
                        name: name.clone(),
                        value: val.clone(),
                    });
                }
            }
        }
    }

    let has_dependencies = !dependencies.is_empty()
        || !optional_dependencies.is_empty()
        || !dev_dependencies.is_empty()
        || !poetry_dependencies.is_empty()
        || !poetry_dev_dependencies.is_empty();

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
        poetry_dependencies,
        poetry_dev_dependencies,
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

    #[test]
    fn poetry_git_dependency_is_classified() {
        let toml = r#"
[tool.poetry.dependencies]
python = "^3.12"
foo = { git = "https://github.com/example/foo.git", branch = "main" }
bar = { path = "../bar" }
requests = "^2.31"
"#;
        let p = parse(toml);
        // `python` key must be skipped; only foo, bar, requests are collected.
        assert_eq!(p.poetry_dependencies.len(), 3);
        assert!(!p.poetry_dependencies.iter().any(|d| d.name == "python"));
        assert!(p.has_dependencies);

        let deps = p.classified_dependencies(std::path::Path::new("pyproject.toml"));
        let foo = deps.iter().find(|d| d.name == "foo").expect("foo dep");
        assert!(
            matches!(
                foo.source,
                crate::ecosystems::DependencySource::Git { floating: true, .. }
            ),
            "foo: {:?}",
            foo.source
        );
        assert!(matches!(
            foo.group,
            crate::ecosystems::DependencyGroup::Production
        ));

        let bar = deps.iter().find(|d| d.name == "bar").expect("bar dep");
        assert!(
            matches!(bar.source, crate::ecosystems::DependencySource::Path),
            "bar: {:?}",
            bar.source
        );

        let req = deps
            .iter()
            .find(|d| d.name == "requests")
            .expect("requests dep");
        assert!(
            matches!(req.source, crate::ecosystems::DependencySource::Registry),
            "requests: {:?}",
            req.source
        );
    }

    #[test]
    fn poetry_git_pinned_by_rev_is_not_floating() {
        let toml = r#"
[tool.poetry.dependencies]
foo = { git = "https://github.com/example/foo.git", rev = "abc1234def5678901234567890123456789abcde" }
"#;
        let p = parse(toml);
        let deps = p.classified_dependencies(std::path::Path::new("pyproject.toml"));
        let foo = deps.iter().find(|d| d.name == "foo").expect("foo dep");
        assert!(
            matches!(
                foo.source,
                crate::ecosystems::DependencySource::Git {
                    floating: false,
                    ssh: false
                }
            ),
            "foo: {:?}",
            foo.source
        );
    }

    #[test]
    fn poetry_group_dev_dependencies_are_classified() {
        let toml = r#"
[tool.poetry.group.dev.dependencies]
pytest = "^7.0"
internal = { git = "https://github.com/example/internal.git", branch = "main" }

[tool.poetry.group.test.dependencies]
mypy = "^1.0"
"#;
        let p = parse(toml);
        assert_eq!(p.poetry_dev_dependencies.len(), 3);
        let deps = p.classified_dependencies(std::path::Path::new("pyproject.toml"));

        let internal = deps
            .iter()
            .find(|d| d.name == "internal")
            .expect("internal dep");
        assert!(
            matches!(
                internal.source,
                crate::ecosystems::DependencySource::Git { floating: true, .. }
            ),
            "internal: {:?}",
            internal.source
        );
        assert!(matches!(
            internal.group,
            crate::ecosystems::DependencyGroup::Development
        ));
    }

    #[test]
    fn poetry_python_key_is_skipped() {
        let toml = r#"
[tool.poetry.dependencies]
python = "^3.12"

[tool.poetry.group.dev.dependencies]
python = "^3.12"
"#;
        let p = parse(toml);
        assert!(p.poetry_dependencies.is_empty());
        assert!(p.poetry_dev_dependencies.is_empty());
        assert!(!p.has_dependencies);
    }

    /// Parses `x = <value>` and returns the value of `x` for spec-string tests.
    fn dep_value(line: &str) -> toml::Value {
        let parsed: toml::Value = toml::from_str(line).unwrap();
        parsed["x"].clone()
    }

    #[test]
    fn poetry_dep_spec_omits_name_and_is_concise() {
        // Plain version string: the spec is just the constraint, no name.
        let version = toml::Value::String("^2.31".to_string());
        assert_eq!(poetry_dep_spec(&version), "^2.31");

        // Inline table: a single-line `git = "…", branch = "…"` summary that
        // does not lead with the dependency name.
        let git =
            dep_value("x = { git = \"https://github.com/example/foo.git\", branch = \"main\" }");
        let spec = poetry_dep_spec(&git);
        assert_eq!(
            spec,
            "git = \"https://github.com/example/foo.git\", branch = \"main\""
        );
        assert!(
            !spec.contains("foo ="),
            "spec must not duplicate name: {spec}"
        );
        assert!(!spec.contains('\n'), "spec must be single-line: {spec}");

        // Path table summary.
        let path = dep_value("x = { path = \"../bar\" }");
        assert_eq!(poetry_dep_spec(&path), "path = \"../bar\"");
    }

    #[test]
    fn poetry_classified_spec_does_not_duplicate_name() {
        let toml = r#"
[tool.poetry.dependencies]
foo = { git = "https://github.com/example/foo.git", branch = "main" }
bar = { path = "../bar" }
requests = "^2.31"
"#;
        let p = parse(toml);
        let deps = p.classified_dependencies(std::path::Path::new("pyproject.toml"));
        for dep in &deps {
            // The spec must not begin with `name ` (the old `"name spec"` form).
            assert!(
                !dep.spec.starts_with(&format!("{} ", dep.name)),
                "{}: spec duplicates name: {:?}",
                dep.name,
                dep.spec
            );
            assert!(!dep.spec.contains('\n'), "{}: spec is multiline", dep.name);
        }
        let foo = deps.iter().find(|d| d.name == "foo").expect("foo dep");
        assert_eq!(
            foo.spec,
            "git = \"https://github.com/example/foo.git\", branch = \"main\""
        );
    }

    #[test]
    fn poetry_scp_like_ssh_git_is_ssh_classified() {
        let toml = r#"
[tool.poetry.dependencies]
internal = { git = "git@github.com:org/internal.git" }
"#;
        let p = parse(toml);
        let deps = p.classified_dependencies(std::path::Path::new("pyproject.toml"));
        let internal = deps
            .iter()
            .find(|d| d.name == "internal")
            .expect("internal dep");
        assert!(
            matches!(
                internal.source,
                crate::ecosystems::DependencySource::Git { ssh: true, .. }
            ),
            "internal: {:?}",
            internal.source
        );
    }

    #[test]
    fn poetry_url_dependency_is_tarball() {
        let toml = r#"
[tool.poetry.dependencies]
mylib = { url = "https://example.com/mylib-1.0.tar.gz" }
"#;
        let p = parse(toml);
        let deps = p.classified_dependencies(std::path::Path::new("pyproject.toml"));
        let mylib = deps.iter().find(|d| d.name == "mylib").expect("mylib dep");
        assert!(
            matches!(mylib.source, crate::ecosystems::DependencySource::Tarball),
            "mylib: {:?}",
            mylib.source
        );
    }
}
