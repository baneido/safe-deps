//! Cargo (Rust) ecosystem analyzer.
//!
//! Detects crates by `Cargo.toml` and extracts the facts the shared rules need:
//! the manifest, whether it declares dependencies, the `Cargo.lock` lockfile,
//! and whether a workspace root covers the crate. Project kind is inferred
//! conservatively from `[[bin]]`/`[lib]` so SD001 severity matches the existing
//! application/library model without any new user-facing concepts.

use std::path::Path;

use crate::ecosystems::{
    contains_file, is_proper_ancestor, manifest_dir, Analyzer, EcoError, Ecosystem, FileFact,
    InstallSettings, PackageManager, Project, ProjectFacts, ProjectKind,
};
use crate::filesystem::{files_named, project_join, read_text, WorkspaceContext};

pub struct CargoAnalyzer;

impl Analyzer for CargoAnalyzer {
    fn name(&self) -> &'static str {
        "rust"
    }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Project> {
        files_named(ctx, "Cargo.toml")
            .iter()
            .filter_map(|manifest| {
                let dir = manifest_dir(manifest);
                let parsed = read_manifest(ctx, manifest);
                // A pure `[workspace]` root with no `[package]` is not itself a
                // crate; its members are detected on their own.
                if !parsed.has_package && parsed.is_workspace {
                    return None;
                }
                Some(Project {
                    root: dir,
                    ecosystem: Ecosystem::Rust,
                    package_manager: PackageManager::Cargo,
                    kind: parsed.kind,
                })
            })
            .collect()
    }

    fn facts(&self, project: &Project, ctx: &WorkspaceContext) -> Result<ProjectFacts, EcoError> {
        let dir = &project.root;
        let manifest_path = project_join(dir, "Cargo.toml");
        let manifest = contains_file(ctx, &manifest_path).then(|| FileFact {
            relative: manifest_path.clone(),
        });

        let mut parse_diagnostics = Vec::new();
        let parsed = match try_read_manifest(ctx, &manifest_path) {
            Ok(p) => p,
            Err(()) => {
                parse_diagnostics.push(crate::diagnostics::Diagnostic::warn_at(
                    format!("could not parse {}", manifest_path.display()),
                    manifest_path.clone(),
                ));
                CargoManifest::default()
            }
        };

        let lock_path = project_join(dir, "Cargo.lock");
        let lockfiles = if contains_file(ctx, &lock_path) {
            vec![FileFact {
                relative: lock_path,
            }]
        } else {
            Vec::new()
        };

        Ok(ProjectFacts {
            project: project.clone(),
            manifest,
            lockfiles,
            configs: Vec::new(),
            has_manifest_dependencies: parsed.has_dependencies,
            install_settings: InstallSettings::default(),
            covered_by_workspace_lockfile: covered_by_workspace(ctx, dir),
            has_legacy_bun_lockfile: false,
            parse_diagnostics,
        })
    }
}

/// The subset of `Cargo.toml` the analyzer reads.
#[derive(Debug)]
struct CargoManifest {
    has_package: bool,
    is_workspace: bool,
    has_dependencies: bool,
    kind: ProjectKind,
}

impl Default for CargoManifest {
    fn default() -> Self {
        Self {
            has_package: false,
            is_workspace: false,
            has_dependencies: false,
            kind: ProjectKind::Unknown,
        }
    }
}

fn read_manifest(ctx: &WorkspaceContext, relative: &Path) -> CargoManifest {
    try_read_manifest(ctx, relative).unwrap_or_default()
}

fn try_read_manifest(ctx: &WorkspaceContext, relative: &Path) -> Result<CargoManifest, ()> {
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
    let has_bin =
        value.get("bin").is_some() || contains_file(ctx, &project_join(dir, "src/main.rs"));
    if has_lib {
        ProjectKind::Library
    } else if has_bin {
        ProjectKind::Application
    } else {
        ProjectKind::Unknown
    }
}

/// A crate is covered when a proper-ancestor `[workspace]` root holds a
/// `Cargo.lock`, mirroring the JS/Python monorepo coverage rule. The ancestor
/// check is a cheap `workspace`-key probe to avoid re-parsing every manifest
/// fully for each member.
fn covered_by_workspace(ctx: &WorkspaceContext, dir: &Path) -> bool {
    if dir == Path::new(".") {
        return false;
    }
    for manifest in files_named(ctx, "Cargo.toml") {
        let root = manifest_dir(&manifest);
        if !is_proper_ancestor(&root, dir) {
            continue;
        }
        if is_workspace_manifest(ctx, &manifest)
            && contains_file(ctx, &project_join(&root, "Cargo.lock"))
        {
            return true;
        }
    }
    false
}

/// Cheap check for a `[workspace]` table without inferring kind or scanning the
/// filesystem.
fn is_workspace_manifest(ctx: &WorkspaceContext, manifest: &Path) -> bool {
    read_text(ctx, manifest)
        .ok()
        .and_then(|text| toml::from_str::<toml::Value>(&text).ok())
        .is_some_and(|v| v.get("workspace").is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::filesystem::{scan, ScanOptions};
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn ws(files: &[(&str, &str)]) -> TempDir {
        let dir = TempDir::new().unwrap();
        for (rel, contents) in files {
            let p = dir.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, contents).unwrap();
        }
        dir
    }

    fn facts_for(dir: &TempDir) -> Vec<ProjectFacts> {
        let ctx = scan(dir.path(), Config::default(), &ScanOptions::default()).unwrap();
        let analyzer = CargoAnalyzer;
        analyzer
            .detect(&ctx)
            .iter()
            .map(|p| analyzer.facts(p, &ctx).unwrap())
            .collect()
    }

    #[test]
    fn detects_binary_crate_with_deps_and_no_lock() {
        let dir = ws(&[
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\n\n[dependencies]\nserde = \"1\"\n",
            ),
            ("src/main.rs", "fn main() {}\n"),
        ]);
        let facts = facts_for(&dir);
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].project.package_manager, PackageManager::Cargo);
        assert_eq!(facts[0].project.kind, ProjectKind::Application);
        assert!(facts[0].has_manifest_dependencies);
        assert!(facts[0].lockfiles.is_empty());
    }

    #[test]
    fn lib_with_a_bin_stays_library() {
        // A library that also ships a CLI must not escalate to Application.
        let dir = ws(&[
            (
                "Cargo.toml",
                "[package]\nname = \"l\"\n[dependencies]\nx = \"1\"\n",
            ),
            ("src/lib.rs", "\n"),
            ("src/main.rs", "fn main() {}\n"),
        ]);
        assert_eq!(facts_for(&dir)[0].project.kind, ProjectKind::Library);
    }

    #[test]
    fn target_specific_dependencies_count() {
        let dir = ws(&[
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\n[target.'cfg(windows)'.dependencies]\nwinapi = \"0.3\"\n",
            ),
            ("src/main.rs", "fn main() {}\n"),
        ]);
        assert!(facts_for(&dir)[0].has_manifest_dependencies);
    }

    #[test]
    fn library_crate_is_classified_as_library() {
        let dir = ws(&[
            (
                "Cargo.toml",
                "[package]\nname = \"lib\"\n\n[dependencies]\nserde = \"1\"\n",
            ),
            ("src/lib.rs", "\n"),
            ("Cargo.lock", "version = 3\n"),
        ]);
        let facts = facts_for(&dir);
        assert_eq!(facts[0].project.kind, ProjectKind::Library);
        assert!(!facts[0].lockfiles.is_empty());
    }

    #[test]
    fn pure_workspace_root_is_not_a_crate() {
        let dir = ws(&[
            ("Cargo.toml", "[workspace]\nmembers = [\"crates/a\"]\n"),
            (
                "crates/a/Cargo.toml",
                "[package]\nname = \"a\"\n[dependencies]\nx = \"1\"\n",
            ),
            ("crates/a/src/lib.rs", "\n"),
            ("Cargo.lock", "version = 3\n"),
        ]);
        let facts = facts_for(&dir);
        // Only the member crate is detected, and the root lock covers it.
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].project.root, PathBuf::from("crates/a"));
        assert!(facts[0].covered_by_workspace_lockfile);
    }
}
