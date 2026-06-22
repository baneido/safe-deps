//! Go modules ecosystem analyzer.
//!
//! Detects modules by `go.mod` and reports whether the module requires any
//! dependencies and whether the `go.sum` integrity file is committed. `go.sum`
//! is Go's reproducibility/integrity record, so SD001 treats a `go.mod` with
//! requirements but no `go.sum` like any other missing lockfile. Application vs
//! library is not inferable from `go.mod` alone, so modules stay `Unknown`
//! (warning) unless the user configures roots.
//!
//! The implementation is split into focused submodules: [`manifest`] (`go.mod`
//! require parsing), [`depsource`] (SD006 `replace` targets), and [`lockfile`]
//! (`go.sum` presence). There is no workspace submodule: a `go.work.sum`
//! supplements rather than replaces a module's own `go.sum`, so module coverage
//! is always self-contained (`covered_by_workspace_lockfile` is always false).

mod depsource;
mod lockfile;
mod manifest;

use crate::ecosystems::{
    contains_file, manifest_dir, Analyzer, EcoError, Ecosystem, FileFact, InstallSettings,
    PackageManager, Project, ProjectFacts, ProjectKind,
};
use crate::filesystem::{files_named, project_join, read_text, WorkspaceContext};

pub struct GoAnalyzer;

impl Analyzer for GoAnalyzer {
    fn name(&self) -> &'static str {
        "go"
    }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Project> {
        files_named(ctx, "go.mod")
            .iter()
            .map(|manifest| Project {
                root: manifest_dir(manifest),
                ecosystem: Ecosystem::Go,
                package_manager: PackageManager::Go,
                kind: ProjectKind::Unknown,
            })
            .collect()
    }

    fn facts(&self, project: &Project, ctx: &WorkspaceContext) -> Result<ProjectFacts, EcoError> {
        let dir = &project.root;
        let mod_path = project_join(dir, "go.mod");
        let manifest = contains_file(ctx, &mod_path).then(|| FileFact {
            relative: mod_path.clone(),
        });

        // An unreadable go.mod is surfaced as a parse diagnostic (so it is not
        // silently treated as dependency-free and can escalate under
        // --strict-parser-errors), mirroring the other analyzers.
        let mut parse_diagnostics = Vec::new();
        let mut dependencies = Vec::new();
        let has_manifest_dependencies = if manifest.is_some() {
            match read_text(ctx, &mod_path) {
                Ok(text) => {
                    dependencies = depsource::dependencies(&text, &mod_path);
                    manifest::parse_requires(&text) > 0
                }
                Err(err) => {
                    parse_diagnostics.push(crate::diagnostics::Diagnostic::warn_at(
                        format!("could not read {}: {err}", mod_path.display()),
                        mod_path.clone(),
                    ));
                    false
                }
            }
        } else {
            false
        };

        Ok(ProjectFacts {
            project: project.clone(),
            manifest,
            lockfiles: lockfile::lockfiles(ctx, dir),
            configs: Vec::new(),
            has_manifest_dependencies,
            install_settings: InstallSettings::default(),
            dependencies,
            // Each module keeps its own go.sum. A workspace `go.work.sum`
            // supplements (does not replace) a module's checksums, so a module
            // missing its own go.sum is still flagged.
            covered_by_workspace_lockfile: false,
            has_legacy_bun_lockfile: false,
            parse_diagnostics,
            pip_requirements: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::filesystem::{scan, ScanOptions};
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
        let analyzer = GoAnalyzer;
        analyzer
            .detect(&ctx)
            .iter()
            .map(|p| analyzer.facts(p, &ctx).unwrap())
            .collect()
    }

    #[test]
    fn module_with_requires_and_no_sum_is_flaggable() {
        let dir = ws(&[(
            "go.mod",
            "module example.com/m\n\ngo 1.21\n\nrequire github.com/x/y v1.0.0\n",
        )]);
        let facts = facts_for(&dir);
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].project.package_manager, PackageManager::Go);
        assert!(facts[0].has_manifest_dependencies);
        assert!(facts[0].lockfiles.is_empty());
    }

    #[test]
    fn module_with_go_sum_has_lockfile() {
        let dir = ws(&[
            (
                "go.mod",
                "module example.com/m\n\ngo 1.21\n\nrequire github.com/x/y v1.0.0\n",
            ),
            ("go.sum", "github.com/x/y v1.0.0 h1:abc=\n"),
        ]);
        let facts = facts_for(&dir);
        assert!(!facts[0].lockfiles.is_empty());
    }
}
