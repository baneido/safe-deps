//! Cargo (Rust) ecosystem analyzer.
//!
//! Detects crates by `Cargo.toml` and extracts the facts the shared rules need:
//! the manifest, whether it declares dependencies, the `Cargo.lock` lockfile,
//! and whether a workspace root covers the crate. Project kind is inferred
//! conservatively from `[[bin]]`/`[lib]` so SD001 severity matches the existing
//! application/library model without any new user-facing concepts.

use std::path::Path;

use crate::ecosystems::{
    classify_cargo_dependency, contains_file, is_proper_ancestor, manifest_dir, Analyzer,
    Dependency, DependencyGroup, DependencySource, EcoError, Ecosystem, FileFact, InstallSettings,
    PackageManager, Project, ProjectFacts, ProjectKind,
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

        // Infer kind only when the user's roots (applied by refine_kinds) left
        // it Unknown, so configured application/library roots win.
        let mut project = project.clone();
        if project.kind == ProjectKind::Unknown {
            project.kind = parsed.kind;
        }

        Ok(ProjectFacts {
            project,
            manifest,
            lockfiles,
            configs: Vec::new(),
            has_manifest_dependencies: parsed.has_dependencies,
            install_settings: InstallSettings::default(),
            dependencies: parsed.dependencies,
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
    /// Non-registry dependencies (git/path) and `[patch]`/`[replace]`
    /// redirects, for SD006. Computed on every manifest parse but only consumed
    /// via `facts`; the value produced during `detect` is discarded.
    dependencies: Vec<Dependency>,
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
        dependencies: cargo_dependencies(&value, relative),
    })
}

/// Extracts non-registry dependencies (git/path) plus `[patch]`/`[replace]`
/// redirects from a parsed `Cargo.toml`, deduplicated by (name, spec). Plain
/// registry/workspace dependencies are safe and omitted.
fn cargo_dependencies(value: &toml::Value, file: &Path) -> Vec<Dependency> {
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
                spec: cargo_spec_string(spec),
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

    let mut seen = std::collections::HashSet::new();
    out.retain(|d| seen.insert((d.name.clone(), d.spec.clone())));
    out
}

/// A compact, readable spec string for a Cargo dependency value.
fn cargo_spec_string(value: &toml::Value) -> String {
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
    crate::filesystem::files_in_dir(ctx, &bin_dir)
        .any(|p| p.extension().and_then(|e| e.to_str()) == Some("rs"))
}

/// A crate is covered when it is an actual member of a proper-ancestor
/// `[workspace]` that holds a `Cargo.lock`. A crate matched by the workspace's
/// `exclude`, or absent from an explicit `members` list, is NOT covered (it has
/// no lockfile of its own).
fn covered_by_workspace(ctx: &WorkspaceContext, dir: &Path) -> bool {
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
}
