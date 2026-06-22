//! Cargo dependency-source extraction for SD006.

use std::collections::HashMap;
use std::path::Path;

use crate::ecosystems::{
    classify_cargo_dependency, is_proper_ancestor, manifest_dir, Dependency, DependencyGroup,
    DependencySource,
};
use crate::filesystem::{files_named, read_text, WorkspaceContext};

/// Extracts non-registry dependencies (git/path) plus `[patch]`/`[replace]`
/// redirects from a parsed `Cargo.toml`, deduplicated by (name, spec). Plain
/// registry/workspace dependencies are safe and omitted.
///
/// `dir` is the manifest's directory (normalized; `.` at the workspace root) and
/// `ctx` is needed to resolve which `[workspace.dependencies]` entries member
/// crates actually inherit via `<dep> = { workspace = true }`.
pub(super) fn dependencies(
    ctx: &WorkspaceContext,
    value: &toml::Value,
    dir: &Path,
    file: &Path,
) -> Vec<Dependency> {
    let mut out = Vec::new();
    let push = |out: &mut Vec<Dependency>, table: Option<&toml::value::Table>, group| {
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
    push(
        &mut out,
        as_table("dependencies"),
        DependencyGroup::Production,
    );
    push(
        &mut out,
        as_table("build-dependencies"),
        DependencyGroup::Production,
    );
    push(
        &mut out,
        as_table("dev-dependencies"),
        DependencyGroup::Development,
    );
    // `[target.<cfg>.dependencies]` etc.
    if let Some(targets) = value.get("target").and_then(|t| t.as_table()) {
        for cfg in targets.values() {
            push(
                &mut out,
                cfg.get("dependencies").and_then(|d| d.as_table()),
                DependencyGroup::Production,
            );
            push(
                &mut out,
                cfg.get("build-dependencies").and_then(|d| d.as_table()),
                DependencyGroup::Production,
            );
            push(
                &mut out,
                cfg.get("dev-dependencies").and_then(|d| d.as_table()),
                DependencyGroup::Development,
            );
        }
    }
    // `[workspace.dependencies]` declares a *pool* of shared specs; an entry only
    // becomes an active dependency edge when some member inherits it via
    // `<dep> = { workspace = true }`. Emit only the inherited entries, and
    // classify each by the kind of member table that inherits it (a dep used
    // only through `[dev-dependencies]` must not be reported as production).
    if let Some(ws_deps) = value
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(|d| d.as_table())
    {
        let inherited = inherited_groups(ctx, dir);
        for (name, spec) in ws_deps {
            let Some(&group) = inherited.get(name.as_str()) else {
                continue;
            };
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
    }
    // `[patch.<registry>]` redirects and legacy `[replace]` reroute crates to a
    // git/path source for the whole graph — a strong supply-chain signal.
    if let Some(patch) = value.get("patch").and_then(|p| p.as_table()) {
        for registry in patch.values() {
            push(&mut out, registry.as_table(), DependencyGroup::Production);
        }
    }
    push(
        &mut out,
        value.get("replace").and_then(|r| r.as_table()),
        DependencyGroup::Production,
    );

    let mut seen = std::collections::HashSet::new();
    out.retain(|d| seen.insert((d.name.clone(), d.spec.clone())));
    out
}

/// Builds the set of `[workspace.dependencies]` names that members of the
/// workspace rooted at `root` actually inherit (`<dep> = { workspace = true }`),
/// mapped to the dependency group of the inheriting member table. When a name is
/// inherited through more than one kind of table, the strongest (production) wins
/// so SD006 severity is not understated.
fn inherited_groups(ctx: &WorkspaceContext, root: &Path) -> HashMap<String, DependencyGroup> {
    let mut groups: HashMap<String, DependencyGroup> = HashMap::new();
    for manifest in files_named(ctx, "Cargo.toml") {
        let member_dir = manifest_dir(&manifest);
        // Only proper descendants are members; the root manifest itself does not
        // inherit from its own `[workspace.dependencies]`.
        if !is_proper_ancestor(root, &member_dir) {
            continue;
        }
        let Some(value) = read_text(ctx, &manifest)
            .ok()
            .and_then(|text| toml::from_str::<toml::Value>(&text).ok())
        else {
            continue;
        };
        record_inherited(&value, &mut groups);
    }
    groups
}

/// Scans one member manifest's dependency tables for `workspace = true`
/// inheritance, recording each inherited name's strongest group.
fn record_inherited(value: &toml::Value, groups: &mut HashMap<String, DependencyGroup>) {
    let mut note = |table: Option<&toml::value::Table>, group: DependencyGroup| {
        let Some(table) = table else { return };
        for (name, spec) in table {
            if !inherits_workspace(spec) {
                continue;
            }
            groups
                .entry(name.clone())
                .and_modify(|existing| {
                    // Production beats Development so a dep inherited in both
                    // dev and normal tables is reported at the higher severity.
                    if group == DependencyGroup::Production {
                        *existing = DependencyGroup::Production;
                    }
                })
                .or_insert(group);
        }
    };
    // `[dependencies]` and `[build-dependencies]` ship in the build/production
    // closure; `[dev-dependencies]` does not. This mirrors the per-kind grouping
    // the package-manifest extraction above uses.
    note(
        value.get("dependencies").and_then(|d| d.as_table()),
        DependencyGroup::Production,
    );
    note(
        value.get("build-dependencies").and_then(|d| d.as_table()),
        DependencyGroup::Production,
    );
    note(
        value.get("dev-dependencies").and_then(|d| d.as_table()),
        DependencyGroup::Development,
    );
    if let Some(targets) = value.get("target").and_then(|t| t.as_table()) {
        for cfg in targets.values() {
            note(
                cfg.get("dependencies").and_then(|d| d.as_table()),
                DependencyGroup::Production,
            );
            note(
                cfg.get("build-dependencies").and_then(|d| d.as_table()),
                DependencyGroup::Production,
            );
            note(
                cfg.get("dev-dependencies").and_then(|d| d.as_table()),
                DependencyGroup::Development,
            );
        }
    }
}

/// Whether a member dependency value inherits from `[workspace.dependencies]`,
/// i.e. it is a table with `workspace = true` (`dep = { workspace = true }` or
/// the `dep.workspace = true` dotted form, which TOML parses identically).
fn inherits_workspace(spec: &toml::Value) -> bool {
    spec.as_table()
        .and_then(|t| t.get("workspace"))
        .and_then(|v| v.as_bool())
        == Some(true)
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
