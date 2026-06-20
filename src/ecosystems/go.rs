//! Go modules ecosystem analyzer.
//!
//! Detects modules by `go.mod` and reports whether the module requires any
//! dependencies and whether the `go.sum` integrity file is committed. `go.sum`
//! is Go's reproducibility/integrity record, so SD001 treats a `go.mod` with
//! requirements but no `go.sum` like any other missing lockfile. Application vs
//! library is not inferable from `go.mod` alone, so modules stay `Unknown`
//! (warning) unless the user configures roots.

use std::path::Path;

use crate::ecosystems::{
    contains_file, is_proper_ancestor, manifest_dir, Analyzer, EcoError, Ecosystem, FileFact,
    InstallSettings, PackageManager, Project, ProjectFacts, ProjectKind,
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

        let has_manifest_dependencies = read_text(ctx, &mod_path)
            .map(|text| parse_requires(&text) > 0)
            .unwrap_or(false);

        let sum_path = project_join(dir, "go.sum");
        let lockfiles = if contains_file(ctx, &sum_path) {
            vec![FileFact { relative: sum_path }]
        } else {
            Vec::new()
        };

        Ok(ProjectFacts {
            project: project.clone(),
            manifest,
            lockfiles,
            configs: Vec::new(),
            has_manifest_dependencies,
            install_settings: InstallSettings::default(),
            // A module usually keeps its own go.sum, but a Go workspace
            // (`go.work` + `go.work.sum`) provides a shared integrity file.
            covered_by_workspace_lockfile: covered_by_go_work(ctx, dir),
            has_legacy_bun_lockfile: false,
            parse_diagnostics: Vec::new(),
        })
    }
}

/// Whether a proper-ancestor `go.work` workspace holds a `go.work.sum` covering
/// this module's checksums.
fn covered_by_go_work(ctx: &WorkspaceContext, dir: &Path) -> bool {
    if dir == Path::new(".") {
        return false;
    }
    for work in files_named(ctx, "go.work") {
        let root = manifest_dir(&work);
        if is_proper_ancestor(&root, dir) && contains_file(ctx, &project_join(&root, "go.work.sum"))
        {
            return true;
        }
    }
    false
}

/// Counts required modules in a `go.mod`, across both the block form
/// (`require ( … )`) and single-line `require path version` directives.
fn parse_requires(text: &str) -> usize {
    let mut count = 0;
    let mut in_block = false;
    for raw in text.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if in_block {
            if line == ")" {
                in_block = false;
            } else {
                count += 1;
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("require") {
            // Require a keyword boundary so a module path like `require-utils…`
            // is not mistaken for the `require` directive.
            let boundary = match rest.chars().next() {
                Some(c) => c.is_whitespace() || c == '(',
                None => true,
            };
            if !boundary {
                continue;
            }
            let rest = rest.trim_start();
            if rest.starts_with('(') {
                in_block = true;
            } else if !rest.is_empty() {
                count += 1;
            }
        }
    }
    count
}

/// Strips a `//` line comment, ignoring `//` inside nothing in particular
/// (go.mod has no strings, so a simple scan is correct).
fn strip_comment(line: &str) -> &str {
    match line.find("//") {
        Some(idx) => &line[..idx],
        None => line,
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
    fn counts_block_and_single_requires() {
        let block = "module m\n\ngo 1.21\n\nrequire (\n\tgithub.com/x/y v1.2.3\n\tgithub.com/a/b v0.1.0 // indirect\n)\n";
        assert_eq!(parse_requires(block), 2);
        let single = "module m\n\ngo 1.21\n\nrequire github.com/x/y v1.0.0\n";
        assert_eq!(parse_requires(single), 1);
        let none = "module m\n\ngo 1.21\n";
        assert_eq!(parse_requires(none), 0);
        // A module path beginning with "require" is not the require directive.
        let tricky = "module m\nrequire-utils.example/x v1.0.0 is not a directive\n";
        assert_eq!(parse_requires(tricky), 0);
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
