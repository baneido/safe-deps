//! Cargo dependency-source extraction for SD006.

use std::path::Path;

use crate::ecosystems::{classify_cargo_dependency, Dependency, DependencyGroup, DependencySource};

/// Extracts non-registry dependencies (git/path) plus `[patch]`/`[replace]`
/// redirects from a parsed `Cargo.toml`, deduplicated by (name, spec). Plain
/// registry/workspace dependencies are safe and omitted.
pub(super) fn dependencies(value: &toml::Value, file: &Path) -> Vec<Dependency> {
    let mut out = Vec::new();
    let mut push = |table: Option<&toml::value::Table>, group: DependencyGroup| {
        let Some(table) = table else { return };
        for (name, spec) in table {
            let source = classify_cargo_dependency(spec);
            if matches!(
                source,
                DependencySource::Registry | DependencySource::Workspace
            ) {
                continue;
            }
            out.push(Dependency {
                name: name.clone(),
                spec: spec_string(spec),
                group,
                source,
                file: file.to_path_buf(),
            });
        }
    };

    let as_table = |k: &str| value.get(k).and_then(|d| d.as_table());
    push(as_table("dependencies"), DependencyGroup::Production);
    push(as_table("build-dependencies"), DependencyGroup::Production);
    push(as_table("dev-dependencies"), DependencyGroup::Development);
    // `[target.<cfg>.dependencies]` etc.
    if let Some(targets) = value.get("target").and_then(|t| t.as_table()) {
        for cfg in targets.values() {
            push(
                cfg.get("dependencies").and_then(|d| d.as_table()),
                DependencyGroup::Production,
            );
            push(
                cfg.get("build-dependencies").and_then(|d| d.as_table()),
                DependencyGroup::Production,
            );
            push(
                cfg.get("dev-dependencies").and_then(|d| d.as_table()),
                DependencyGroup::Development,
            );
        }
    }
    // `[patch.<registry>]` redirects and legacy `[replace]` reroute crates to a
    // git/path source for the whole graph — a strong supply-chain signal.
    if let Some(patch) = value.get("patch").and_then(|p| p.as_table()) {
        for registry in patch.values() {
            push(registry.as_table(), DependencyGroup::Production);
        }
    }
    push(
        value.get("replace").and_then(|r| r.as_table()),
        DependencyGroup::Production,
    );
    // `[workspace.dependencies]` defines the source for `dep = { workspace = true }`
    // members. It lives only in the workspace root (often a virtual manifest), so
    // a git/path source here is the single declaration point for the whole graph.
    push(
        value
            .get("workspace")
            .and_then(|w| w.get("dependencies"))
            .and_then(|d| d.as_table()),
        DependencyGroup::Production,
    );

    let mut seen = std::collections::HashSet::new();
    out.retain(|d| seen.insert((d.name.clone(), d.spec.clone())));
    out
}

/// A compact, readable spec string for a Cargo dependency value.
fn spec_string(value: &toml::Value) -> String {
    if let Some(s) = value.as_str() {
        return s.to_string();
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
        if let Some(v) = t.get("version").and_then(|v| v.as_str()) {
            return v.to_string();
        }
    }
    "<complex>".to_string()
}
