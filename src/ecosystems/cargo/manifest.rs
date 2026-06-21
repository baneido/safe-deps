//! `Cargo.toml` parsing: dependency presence, project-kind inference, and the
//! normalized dependency-source list (delegated to `depsource`).

use std::path::Path;

use crate::ecosystems::{contains_file, Dependency, ProjectKind};
use crate::filesystem::{files_in_dir, project_join, read_text, WorkspaceContext};

use super::depsource;

/// The subset of `Cargo.toml` the analyzer reads.
#[derive(Debug)]
pub(super) struct CargoManifest {
    pub(super) has_package: bool,
    pub(super) is_workspace: bool,
    pub(super) has_dependencies: bool,
    pub(super) kind: ProjectKind,
    /// Non-registry dependencies (git/path) and `[patch]`/`[replace]`
    /// redirects, for SD006. Computed on every manifest parse but only consumed
    /// via `facts`; the value produced during `detect` is discarded.
    pub(super) dependencies: Vec<Dependency>,
}

impl Default for CargoManifest {
    fn default() -> Self {
        Self {
            has_package: false,
            is_workspace: false,
            has_dependencies: false,
            kind: ProjectKind::Unknown,
            dependencies: Vec::new(),
        }
    }
}

pub(super) fn read_manifest(ctx: &WorkspaceContext, relative: &Path) -> CargoManifest {
    try_read_manifest(ctx, relative).unwrap_or_default()
}

pub(super) fn try_read_manifest(
    ctx: &WorkspaceContext,
    relative: &Path,
) -> Result<CargoManifest, ()> {
    let dir = relative.parent().unwrap_or(Path::new("."));
    let text = read_text(ctx, relative).map_err(|_| ())?;
    let value: toml::Value = toml::from_str(&text).map_err(|_| ())?;

    let has_package = value.get("package").is_some();
    let is_workspace = value.get("workspace").is_some();

    Ok(CargoManifest {
        has_package,
        is_workspace,
        has_dependencies: declares_dependencies(&value),
        kind: infer_kind(ctx, dir, &value),
        dependencies: depsource::dependencies(&value, relative),
    })
}

/// Whether the manifest declares any dependencies, including target-specific
/// ones (`[target.'cfg(...)'.dependencies]`), which cross-platform crates use.
fn declares_dependencies(value: &toml::Value) -> bool {
    const KEYS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];
    let non_empty = |v: &toml::Value, k: &str| {
        v.get(k)
            .and_then(|d| d.as_table())
            .is_some_and(|t| !t.is_empty())
    };
    if KEYS.iter().any(|k| non_empty(value, k)) {
        return true;
    }
    // `[target.<triple-or-cfg>.dependencies]` lives under the `target` table.
    value
        .get("target")
        .and_then(|t| t.as_table())
        .is_some_and(|targets| {
            targets
                .values()
                .any(|t| KEYS.iter().any(|k| non_empty(t, k)))
        })
}

/// Infers application vs library conservatively. A crate with a library target
/// is treated as a library even if it also ships a binary, so SD001 does not
/// escalate a lib-with-a-CLI to an application error.
fn infer_kind(ctx: &WorkspaceContext, dir: &Path, value: &toml::Value) -> ProjectKind {
    let has_lib =
        value.get("lib").is_some() || contains_file(ctx, &project_join(dir, "src/lib.rs"));
    // A binary is declared via `[[bin]]`, `src/main.rs`, or the `src/bin/*.rs`
    // autobin convention.
    let has_bin = value.get("bin").is_some()
        || contains_file(ctx, &project_join(dir, "src/main.rs"))
        || has_autobin(ctx, dir);
    if has_lib {
        ProjectKind::Library
    } else if has_bin {
        ProjectKind::Application
    } else {
        ProjectKind::Unknown
    }
}

/// Whether the crate has any `src/bin/*.rs` autobin target.
fn has_autobin(ctx: &WorkspaceContext, dir: &Path) -> bool {
    let bin_dir = project_join(dir, "src/bin");
    files_in_dir(ctx, &bin_dir).any(|p| p.extension().and_then(|e| e.to_str()) == Some("rs"))
}
