//! Cargo (Rust) ecosystem analyzer.
//!
//! Detects crates by `Cargo.toml` and extracts the facts the shared rules need:
//! the manifest, whether it declares dependencies, the `Cargo.lock` lockfile,
//! and whether a workspace root covers the crate. Project kind is inferred
//! conservatively from `[[bin]]`/`[lib]` so SD001 severity matches the existing
//! application/library model without any new user-facing concepts.
//!
//! The implementation is split into focused submodules: [`manifest`] (parsing,
//! kind inference), [`depsource`] (SD006 dependency sources), [`workspace`]
//! (workspace-lockfile coverage), and [`lockfile`] (`Cargo.lock` presence).

mod depsource;
mod lockfile;
mod manifest;
mod workspace;

use crate::ecosystems::{
    contains_file, manifest_dir, Analyzer, EcoError, Ecosystem, FileFact, InstallSettings,
    PackageManager, Project, ProjectFacts, ProjectKind,
};
use crate::filesystem::{files_named, project_join, WorkspaceContext};

use manifest::CargoManifest;

pub struct CargoAnalyzer;

impl Analyzer for CargoAnalyzer {
    fn name(&self) -> &'static str {
        "rust"
    }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Project> {
        files_named(ctx, "Cargo.toml")
            .iter()
            .filter_map(|man| {
                let dir = manifest_dir(man);
                let parsed = manifest::read_manifest(ctx, man);
                // A pure `[workspace]` root with no `[package]` is not itself a
                // crate, so its members are detected on their own. However, the
                // virtual root may still declare workspace-level dependency sources
                // (`[patch]`, `[replace]`, `[workspace.dependencies]`) that SD006
                // must evaluate. Emit a project for it when such entries exist so
                // `facts` can extract and report them.
                if !parsed.has_package && parsed.is_workspace {
                    if parsed.dependencies.is_empty() {
                        return None;
                    }
                    return Some(Project {
                        root: dir,
                        ecosystem: Ecosystem::Rust,
                        package_manager: PackageManager::Cargo,
                        kind: ProjectKind::Unknown,
                    });
                }
                Some(Project {
                    root: dir,
                    ecosystem: Ecosystem::Rust,
                    package_manager: PackageManager::Cargo,
                    // Emit Unknown so `refine_kinds` can apply user-configured
                    // application_roots/library_roots; `facts` infers from the
                    // crate's targets only when the kind is still Unknown.
                    kind: ProjectKind::Unknown,
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
        let parsed = match manifest::try_read_manifest(ctx, &manifest_path) {
            Ok(p) => p,
            Err(()) => {
                parse_diagnostics.push(crate::diagnostics::Diagnostic::warn_at(
                    format!("could not parse {}", manifest_path.display()),
                    manifest_path.clone(),
                ));
                CargoManifest::default()
            }
        };

        // Infer kind only when the user's roots (applied by refine_kinds) left
        // it Unknown, so configured application/library roots win.
        let mut project = project.clone();
        if project.kind == ProjectKind::Unknown {
            project.kind = parsed.kind;
        }

        Ok(ProjectFacts {
            project,
            manifest,
            lockfiles: lockfile::lockfiles(ctx, dir),
            configs: Vec::new(),
            has_manifest_dependencies: parsed.has_dependencies,
            install_settings: InstallSettings::default(),
            dependencies: parsed.dependencies,
            covered_by_workspace_lockfile: workspace::covered_by_workspace(ctx, dir),
            has_legacy_bun_lockfile: false,
            parse_diagnostics,
        })
    }
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

    #[test]
    fn excluded_crate_is_not_covered_by_workspace() {
        let dir = ws(&[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"crates/*\"]\nexclude = [\"vendored/sub\"]\n",
            ),
            ("Cargo.lock", "version = 3\n"),
            (
                "vendored/sub/Cargo.toml",
                "[package]\nname = \"sub\"\n[dependencies]\nx = \"1\"\n",
            ),
            ("vendored/sub/src/lib.rs", "\n"),
        ]);
        let facts = facts_for(&dir);
        let sub = facts
            .iter()
            .find(|f| f.project.root == std::path::Path::new("vendored/sub"))
            .unwrap();
        assert!(
            !sub.covered_by_workspace_lockfile,
            "an excluded crate is not covered by the workspace lock"
        );
    }

    #[test]
    fn src_bin_autobin_is_an_application() {
        let dir = ws(&[
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\n[dependencies]\nx = \"1\"\n",
            ),
            ("src/bin/tool.rs", "fn main() {}\n"),
        ]);
        assert_eq!(facts_for(&dir)[0].project.kind, ProjectKind::Application);
    }

    #[test]
    fn virtual_workspace_root_without_unsafe_sources_is_not_a_project() {
        // A bare [workspace] with only registry deps in members should not produce
        // an extra project for the root; only members are detected.
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
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].project.root, PathBuf::from("crates/a"));
    }

    #[test]
    fn virtual_workspace_root_with_patch_is_detected_as_project() {
        // A [workspace] root with a [patch.crates-io] git redirect must be
        // detected so SD006 can evaluate the unsafe source.
        let dir = ws(&[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"crates/a\"]\n\n[patch.crates-io]\nfoo = { git = \"https://github.com/example/foo\", branch = \"main\" }\n",
            ),
            (
                "crates/a/Cargo.toml",
                "[package]\nname = \"a\"\n[dependencies]\nfoo = \"1\"\n",
            ),
            ("crates/a/src/lib.rs", "\n"),
            ("Cargo.lock", "version = 3\n"),
        ]);
        let facts = facts_for(&dir);
        // Both the virtual root (for [patch]) and the member crate are detected.
        assert_eq!(facts.len(), 2);
        let root_facts = facts
            .iter()
            .find(|f| f.project.root == std::path::Path::new("."))
            .expect("virtual workspace root should be detected");
        assert_eq!(root_facts.project.package_manager, PackageManager::Cargo);
        assert!(
            !root_facts.dependencies.is_empty(),
            "patch dep should be extracted"
        );
        let dep = &root_facts.dependencies[0];
        assert_eq!(dep.name, "foo");
    }

    #[test]
    fn virtual_workspace_root_with_workspace_dependencies_is_detected() {
        // [workspace.dependencies] with a path or git entry must be detected.
        let dir = ws(&[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"crates/a\"]\n\n[workspace.dependencies]\nbar = { path = \"../bar\" }\n",
            ),
            (
                "crates/a/Cargo.toml",
                "[package]\nname = \"a\"\n[dependencies]\nbar.workspace = true\n",
            ),
            ("crates/a/src/lib.rs", "\n"),
            ("Cargo.lock", "version = 3\n"),
        ]);
        let facts = facts_for(&dir);
        let root_facts = facts
            .iter()
            .find(|f| f.project.root == std::path::Path::new("."))
            .expect("virtual workspace root should be detected");
        let dep_names: Vec<&str> = root_facts
            .dependencies
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert!(
            dep_names.contains(&"bar"),
            "workspace path dep should be extracted: {dep_names:?}"
        );
    }

    #[test]
    fn inherited_workspace_dependency_is_production() {
        // A [workspace.dependencies] git entry inherited by a member's normal
        // [dependencies] is an active production dependency edge.
        let dir = ws(&[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"crates/a\"]\n\n[workspace.dependencies]\nfoo = { git = \"https://github.com/example/foo\", branch = \"main\" }\n",
            ),
            (
                "crates/a/Cargo.toml",
                "[package]\nname = \"a\"\n[dependencies]\nfoo = { workspace = true }\n",
            ),
            ("crates/a/src/lib.rs", "\n"),
            ("Cargo.lock", "version = 3\n"),
        ]);
        let facts = facts_for(&dir);
        let root = facts
            .iter()
            .find(|f| f.project.root == std::path::Path::new("."))
            .expect("virtual workspace root should be detected");
        let foo = root
            .dependencies
            .iter()
            .find(|d| d.name == "foo")
            .expect("inherited workspace dep should be extracted");
        assert_eq!(foo.group, crate::ecosystems::DependencyGroup::Production);
    }

    #[test]
    fn unused_workspace_dependency_is_not_extracted() {
        // A [workspace.dependencies] entry no member inherits is just a pool
        // entry, not an active edge, so it must not be surfaced to SD006.
        let dir = ws(&[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"crates/a\"]\n\n[workspace.dependencies]\nfoo = { git = \"https://github.com/example/foo\", branch = \"main\" }\n",
            ),
            (
                "crates/a/Cargo.toml",
                "[package]\nname = \"a\"\n[dependencies]\nserde = \"1\"\n",
            ),
            ("crates/a/src/lib.rs", "\n"),
            ("Cargo.lock", "version = 3\n"),
        ]);
        let facts = facts_for(&dir);
        // No member inherits `foo`, so the virtual root has no unsafe sources
        // and is not even emitted as a project.
        assert!(
            facts
                .iter()
                .all(|f| f.project.root != std::path::Path::new(".")),
            "unused workspace dep must not produce a virtual-root project"
        );
        assert!(
            facts
                .iter()
                .all(|f| f.dependencies.iter().all(|d| d.name != "foo")),
            "unused workspace dep must not be extracted"
        );
    }

    #[test]
    fn workspace_dependency_inherited_only_via_dev_is_not_production() {
        // A [workspace.dependencies] entry inherited solely through a member's
        // [dev-dependencies] is a development edge, so it must not be classified
        // as Production (a path dev dep must not become an SD006 prod finding).
        let dir = ws(&[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"crates/a\"]\n\n[workspace.dependencies]\nfoo = { path = \"../foo\" }\n",
            ),
            (
                "crates/a/Cargo.toml",
                "[package]\nname = \"a\"\n[dev-dependencies]\nfoo = { workspace = true }\n",
            ),
            ("crates/a/src/lib.rs", "\n"),
            ("Cargo.lock", "version = 3\n"),
        ]);
        let facts = facts_for(&dir);
        let root = facts
            .iter()
            .find(|f| f.project.root == std::path::Path::new("."))
            .expect("virtual workspace root should be detected");
        let foo = root
            .dependencies
            .iter()
            .find(|d| d.name == "foo")
            .expect("dev-inherited workspace dep should be extracted");
        assert_eq!(foo.group, crate::ecosystems::DependencyGroup::Development);
        assert!(
            !foo.group.is_production(),
            "dev-only inherited dep must not be production"
        );
    }
}
