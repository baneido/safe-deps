//! Cargo workspace membership: whether a crate is covered by an ancestor
//! `[workspace]`'s `Cargo.lock`.

use std::path::Path;

use crate::ecosystems::{contains_file, is_proper_ancestor, manifest_dir};
use crate::filesystem::{files_named, project_join, read_text, WorkspaceContext};

/// A crate is covered when it is an actual member of a proper-ancestor
/// `[workspace]` that holds a `Cargo.lock`. A crate matched by the workspace's
/// `exclude`, or absent from an explicit `members` list, is NOT covered (it has
/// no lockfile of its own).
pub(super) fn covered_by_workspace(ctx: &WorkspaceContext, dir: &Path) -> bool {
    if dir == Path::new(".") {
        return false;
    }
    for manifest in files_named(ctx, "Cargo.toml") {
        let root = manifest_dir(&manifest);
        if !is_proper_ancestor(&root, dir) {
            continue;
        }
        let Some(ws) = workspace_spec(ctx, &manifest) else {
            continue;
        };
        if !contains_file(ctx, &project_join(&root, "Cargo.lock")) {
            continue;
        }
        // Path of the crate relative to the workspace root.
        let rel = if root == Path::new(".") {
            dir
        } else {
            dir.strip_prefix(&root).unwrap_or(dir)
        };
        if matches_any(&ws.exclude, rel) {
            continue;
        }
        // With an explicit `members` list only matching crates are covered;
        // without one the workspace auto-includes nested path crates.
        if ws.members.is_empty() || matches_any(&ws.members, rel) {
            return true;
        }
    }
    false
}

struct WorkspaceSpec {
    members: Vec<String>,
    exclude: Vec<String>,
}

/// Returns the `[workspace]` membership/exclude globs if `manifest` declares a
/// workspace, else `None`.
fn workspace_spec(ctx: &WorkspaceContext, manifest: &Path) -> Option<WorkspaceSpec> {
    let value: toml::Value = read_text(ctx, manifest)
        .ok()
        .and_then(|text| toml::from_str(&text).ok())?;
    let ws = value.get("workspace")?;
    let globs = |key: &str| {
        ws.get(key)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    };
    Some(WorkspaceSpec {
        members: globs("members"),
        exclude: globs("exclude"),
    })
}

/// Whether a relative crate path matches any workspace glob (Cargo globs are
/// relative to the workspace root and `/`-separated).
fn matches_any(globs: &[String], rel: &Path) -> bool {
    let rel_str = rel.to_string_lossy().replace('\\', "/");
    globs.iter().any(|g| {
        globset::Glob::new(g)
            .map(|glob| glob.compile_matcher().is_match(&rel_str))
            .unwrap_or(false)
    })
}
