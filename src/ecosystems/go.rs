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
    classify_go_replace_target, contains_file, manifest_dir, Analyzer, Dependency, DependencyGroup,
    DependencySource, EcoError, Ecosystem, FileFact, InstallSettings, PackageManager, Project,
    ProjectFacts, ProjectKind,
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
                    dependencies = go_dependencies(&text, &mod_path);
                    parse_requires(&text) > 0
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
            dependencies,
            // Each module keeps its own go.sum. A workspace `go.work.sum`
            // supplements (does not replace) a module's checksums, so a module
            // missing its own go.sum is still flagged.
            covered_by_workspace_lockfile: false,
            has_legacy_bun_lockfile: false,
            parse_diagnostics,
        })
    }
}

/// Counts required modules in a `go.mod`, across both the block form
/// (`require ( … )`) and single-line `require path version` directives.
/// Extracts SD006-relevant dependencies from `replace` directives. A `replace`
/// to a local filesystem path is unsafe (it is ignored outside the main module,
/// so consumers cannot resolve it); module-to-module replacements and ordinary
/// `require`d modules are proxy-resolved and checksummed (safe), so they are not
/// emitted.
fn go_dependencies(text: &str, file: &Path) -> Vec<Dependency> {
    let mut out = Vec::new();
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
                push_replace(line, file, &mut out);
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("replace") {
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
            } else {
                push_replace(rest, file, &mut out);
            }
        }
    }
    out
}

/// Parses one `old[ ver] => new[ ver]` replacement; pushes a dependency only for
/// an unsafe (local-path) target.
fn push_replace(spec: &str, file: &Path, out: &mut Vec<Dependency>) {
    let Some((lhs, rhs)) = spec.split_once("=>") else {
        return;
    };
    let name = lhs.split_whitespace().next().unwrap_or("");
    let target = rhs.trim();
    if name.is_empty() || target.is_empty() {
        return;
    }
    let source = classify_go_replace_target(target);
    if matches!(source, DependencySource::Registry) {
        return;
    }
    // Drop any version suffix from the target for a readable spec.
    let spec = target.split_whitespace().next().unwrap_or(target);
    out.push(Dependency {
        name: name.to_string(),
        spec: spec.to_string(),
        group: DependencyGroup::Production,
        source,
        file: file.to_path_buf(),
    });
}

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
