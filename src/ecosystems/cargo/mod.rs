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
            .map(|man| Project {
                root: manifest_dir(man),
                ecosystem: Ecosystem::Rust,
                package_manager: PackageManager::Cargo,
                // Emit Unknown so `refine_kinds` can apply user-configured
                // application_roots/library_roots; `facts` infers from the
                // crate's targets only when the kind is still Unknown.
                //
                // A pure `[workspace]` root (virtual manifest, no `[package]`) is
                // not a crate — its members are detected separately — but it is
                // still emitted so its root-only `[patch]`/`[replace]`/
                // `[workspace.dependencies]` unsafe sources are checked by SD006.
                // It declares no `[dependencies]`, so SD001 does not fire for it.
                kind: ProjectKind::Unknown,
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
    use std::path::Path;
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
    fn pure_workspace_root_is_collected_without_being_a_crate() {
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
        // The virtual root and the member crate are both collected.
        assert_eq!(facts.len(), 2);

        let root = facts
            .iter()
            .find(|f| f.project.root.as_path() == Path::new("."))
            .expect("virtual workspace root is collected");
        // It is not a crate: no declared `[dependencies]`, so SD001 stays quiet.
        assert!(!root.has_manifest_dependencies);
        assert!(root.dependencies.is_empty());

        let member = facts
            .iter()
            .find(|f| f.project.root.as_path() == Path::new("crates/a"))
            .expect("member crate is detected");
        assert!(member.has_manifest_dependencies);
        assert!(member.covered_by_workspace_lockfile);
    }

    #[test]
    fn virtual_workspace_root_unsafe_sources_are_collected() {
        // `[patch]`, `[replace]`, and `[workspace.dependencies]` live only in the
        // root (virtual) manifest; their unsafe sources must reach SD006.
        let dir = ws(&[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"crates/a\"]\n\n\
                 [patch.crates-io]\nfoo = { git = \"https://example.com/foo\" }\n\n\
                 [replace]\n\"bar:1.0.0\" = { path = \"../bar\" }\n\n\
                 [workspace.dependencies]\nbaz = { path = \"../baz\" }\n",
            ),
            (
                "crates/a/Cargo.toml",
                "[package]\nname = \"a\"\n[dependencies]\nbaz = { workspace = true }\n",
            ),
            ("crates/a/src/lib.rs", "\n"),
        ]);
        let facts = facts_for(&dir);
        let root = facts
            .iter()
            .find(|f| f.project.root.as_path() == Path::new("."))
            .expect("virtual root collected");
        let names: Vec<&str> = root.dependencies.iter().map(|d| d.name.as_str()).collect();
        assert!(
            names.contains(&"foo"),
            "patch git source missing: {names:?}"
        );
        // `[replace]` keys are package-id specs (`name:version`).
        assert!(
            names.contains(&"bar:1.0.0"),
            "replace path source missing: {names:?}"
        );
        assert!(
            names.contains(&"baz"),
            "workspace.dependencies path source missing: {names:?}"
        );
        // The member's `baz = {{ workspace = true }}` is a safe workspace ref, so
        // it is not double-counted as an unsafe source.
        let member = facts
            .iter()
            .find(|f| f.project.root.as_path() == Path::new("crates/a"))
            .unwrap();
        assert!(
            member.dependencies.is_empty(),
            "member should add no sources"
        );
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
}
