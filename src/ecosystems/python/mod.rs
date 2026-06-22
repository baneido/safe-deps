//! Python ecosystem analyzer: detects pip and uv projects and extracts
//! normalized facts from `pyproject.toml`, `requirements*.txt`, `pip.conf`, and
//! `uv.toml`.

use std::path::{Path, PathBuf};

use crate::ecosystems::source::classify_python_source;
use crate::ecosystems::{
    Dependency, DependencyGroup, EcoError, Ecosystem, FileFact, InstallSettings, PackageManager,
    Project, ProjectFacts, ProjectKind,
};
use crate::filesystem::{files_named, project_join, WorkspaceContext};

pub mod pip;
pub mod pyproject;
pub mod requirements;
pub mod uv;

pub struct PythonAnalyzer;

impl crate::ecosystems::Analyzer for PythonAnalyzer {
    fn name(&self) -> &'static str {
        "python"
    }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Project> {
        let pyproject_files = files_named(ctx, "pyproject.toml");
        let mut projects = Vec::new();
        let mut covered_dirs: Vec<PathBuf> = Vec::new();

        for py in &pyproject_files {
            let dir = project_dir(py);
            let manager = detect_python_manager(ctx, &dir, py);
            projects.push(Project {
                root: dir.clone(),
                ecosystem: Ecosystem::Python,
                package_manager: manager,
                kind: ProjectKind::Unknown,
            });
            covered_dirs.push(dir);
        }

        for req in requirements_files(ctx) {
            let dir = requirements_project_dir(&req);
            if covered_dirs.contains(&dir) {
                continue;
            }
            covered_dirs.push(dir.clone());
            projects.push(Project {
                root: dir,
                ecosystem: Ecosystem::Python,
                package_manager: PackageManager::Pip,
                kind: ProjectKind::Unknown,
            });
        }

        projects
    }

    fn facts(&self, project: &Project, ctx: &WorkspaceContext) -> Result<ProjectFacts, EcoError> {
        match project.package_manager {
            PackageManager::Uv => build_uv_facts(ctx, project),
            PackageManager::Pip => build_pip_facts(ctx, project),
            _ => Err(EcoError::UnknownEcosystem("non-python".to_string())),
        }
    }
}

fn project_dir(path: &Path) -> PathBuf {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn detect_python_manager(
    ctx: &WorkspaceContext,
    dir: &Path,
    pyproject_path: &Path,
) -> PackageManager {
    if has_file_in(ctx, dir, "uv.lock") {
        return PackageManager::Uv;
    }
    if has_file_in(ctx, dir, "uv.toml") {
        return PackageManager::Uv;
    }
    if let Ok(py) = pyproject::load(ctx, pyproject_path) {
        if py.has_tool_uv {
            return PackageManager::Uv;
        }
    }
    PackageManager::Pip
}

fn has_file_in(ctx: &WorkspaceContext, dir: &Path, name: &str) -> bool {
    let target = project_join(dir, name);
    ctx.contains(&target)
}

fn is_proper_ancestor(ancestor: &Path, descendant: &Path) -> bool {
    if ancestor == Path::new(".") {
        return descendant != Path::new(".");
    }
    descendant.starts_with(ancestor) && descendant != ancestor
}

/// A uv member project is covered when a proper-ancestor uv project declares a
/// `[tool.uv.workspace]` and holds the shared `uv.lock`. This mirrors the JS
/// monorepo behavior so members do not get a false SD001.
fn covered_by_uv_workspace(ctx: &WorkspaceContext, dir: &Path) -> bool {
    if dir == Path::new(".") {
        return false;
    }
    for py in files_named(ctx, "pyproject.toml") {
        let root_dir = project_dir(&py);
        if !is_proper_ancestor(&root_dir, dir) {
            continue;
        }
        if has_file_in(ctx, &root_dir, "uv.lock") && declares_uv_workspace(ctx, &py) {
            return true;
        }
    }
    false
}

fn declares_uv_workspace(ctx: &WorkspaceContext, pyproject_path: &Path) -> bool {
    let Ok(text) = crate::filesystem::read_text(ctx, pyproject_path) else {
        return false;
    };
    let Ok(value) = toml::from_str::<toml::Value>(&text) else {
        return false;
    };
    value
        .get("tool")
        .and_then(|t| t.get("uv"))
        .and_then(|u| u.get("workspace"))
        .is_some()
}

/// Returns a warning diagnostic when a `pyproject.toml` exists in `dir` but is
/// not valid TOML. Detection treats a malformed `pyproject.toml` as pip, so the
/// check must run regardless of the resolved package manager.
fn pyproject_parse_diagnostic(
    ctx: &WorkspaceContext,
    dir: &Path,
) -> Option<crate::diagnostics::Diagnostic> {
    if !has_file_in(ctx, dir, "pyproject.toml") {
        return None;
    }
    let py_path = project_join(dir, "pyproject.toml");
    let text = crate::filesystem::read_text(ctx, &py_path).ok()?;
    if toml::from_str::<toml::Value>(&text).is_err() {
        Some(crate::diagnostics::Diagnostic::warn_at(
            format!("could not parse {}", py_path.display()),
            py_path,
        ))
    } else {
        None
    }
}

/// Returns the logical project root directory for a requirements file path.
///
/// For a standard `requirements*.txt` (name starts with `requirements`) the
/// project root is the file's parent directory, same as `project_dir`.
///
/// For a file inside a directory named `requirements` (e.g.
/// `requirements/base.txt` or `myapp/requirements/dev.txt`) the project root
/// is the parent of the `requirements/` directory, so that `myapp/` rather
/// than `myapp/requirements/` is treated as the project root.
fn requirements_project_dir(path: &Path) -> PathBuf {
    // Walk the components to find the `requirements` directory component.
    // Build two paths simultaneously: one accumulating up to and including
    // the component before `requirements`, and one for the whole parent.
    let components: Vec<_> = path.components().collect();
    // The file name is the last component; skip it.
    for i in (0..components.len().saturating_sub(1)).rev() {
        if components[i].as_os_str() == "requirements" {
            // The `requirements` directory is at index i.
            // Project root = components[0..i] joined, defaulting to ".".
            let root: PathBuf = components[..i].iter().collect();
            return if root.as_os_str().is_empty() {
                PathBuf::from(".")
            } else {
                root
            };
        }
    }
    // No `requirements` dir in path — fall back to the file's parent.
    project_dir(path)
}

/// Returns relative paths of requirements `.txt` entry-point files.
///
/// A file qualifies when:
/// - its name starts with `requirements` and ends with `.txt` (e.g.
///   `requirements.txt`, `requirements-dev.txt`), **or**
/// - it lives inside a directory named `requirements` and ends with `.txt`
///   (e.g. `requirements/base.txt`, `requirements/ci/test.txt`).
///
/// Files under a `requirements/` directory are included as entry-point
/// candidates so that common layouts like:
/// ```text
/// requirements/
///   base.txt
///   dev.txt
/// requirements.txt   # -r requirements/base.txt
/// ```
/// are covered even when the top-level file is absent.
fn requirements_files(ctx: &WorkspaceContext) -> Vec<PathBuf> {
    ctx.files
        .iter()
        .filter(|f| {
            let name = f
                .relative
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            // Classic top-level: requirements*.txt
            if name.starts_with("requirements") && name.ends_with(".txt") {
                return true;
            }
            // requirements/**/*.txt — any .txt inside a `requirements` directory
            if name.ends_with(".txt") {
                return f
                    .relative
                    .components()
                    .any(|c| c.as_os_str() == "requirements");
            }
            false
        })
        .map(|f| f.relative.clone())
        .collect()
}

/// Collects classified dependencies from a Python project directory, drawing on
/// both `pyproject.toml` (`[project]`/`[tool.uv]` dependencies) and any
/// `requirements*.txt` in the same directory, so SD006 covers pip and uv
/// projects alike. A pre-parsed `pyproject` is reused to avoid a second parse.
/// Each dependency is anchored to the file it came from. Exact `(name, spec)`
/// duplicates (the same package and spec declared in both pyproject and an
/// exported `requirements.txt`) are collapsed, but a package declared with
/// *different* specs/sources in each is kept so an unsafe source is never
/// dropped just because a same-named safe one was seen first.
/// A `requirements*.txt` whose name marks it as dev/test holds development
/// dependencies; everything else is treated as production.
fn requirements_group(path: &Path) -> DependencyGroup {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.contains("dev") || name.contains("test") {
        DependencyGroup::Development
    } else {
        DependencyGroup::Production
    }
}

/// Collects classified dependencies from a Python project directory.
///
/// Returns the dependencies and any diagnostics emitted while following
/// `-r`/`-c` includes (cyclic or missing includes become warning diagnostics).
/// A shared `visited` set is passed through `load_recursive` calls to prevent
/// double-processing a file that appears both as an entry-point and as an
/// include target.
fn python_dependencies(
    ctx: &WorkspaceContext,
    dir: &Path,
    pyproject: Option<&pyproject::Pyproject>,
) -> (Vec<Dependency>, Vec<crate::diagnostics::Diagnostic>) {
    let py_path = project_join(dir, "pyproject.toml");
    let owned = if pyproject.is_none() && has_file_in(ctx, dir, "pyproject.toml") {
        pyproject::load(ctx, &py_path).ok()
    } else {
        None
    };
    let mut out: Vec<Dependency> = Vec::new();
    let mut diagnostics: Vec<crate::diagnostics::Diagnostic> = Vec::new();

    if let Some(py) = pyproject.or(owned.as_ref()) {
        out.extend(py.classified_dependencies(&py_path));
    }

    // Shared visited set so a file that is both an entry-point and an include
    // target is not processed twice (which would double-count specs/settings).
    let mut visited = std::collections::HashSet::new();

    for req in requirements_files(ctx)
        .into_iter()
        .filter(|p| requirements_project_dir(p) == *dir)
    {
        // A `requirements-dev.txt` / `requirements/test.txt` holds dev deps, so
        // a local editable path there is not a production-source finding.
        let group = requirements_group(&req);
        let r = requirements::load_recursive(ctx, &req, &mut visited, &mut diagnostics);
        for spec in r.specs {
            let bare = spec.strip_prefix("-e ").unwrap_or(&spec).trim();
            out.push(Dependency {
                name: pyproject::pep508_name(bare),
                source: classify_python_source(&spec),
                spec,
                group,
                file: req.clone(),
            });
        }
    }
    // Collapse exact (name, spec) duplicates only, so distinct sources for the
    // same package both survive (SD006 still flags the unsafe one).
    let mut seen = std::collections::HashSet::new();
    out.retain(|d| seen.insert((d.name.clone(), d.spec.clone())));
    (out, diagnostics)
}

fn build_uv_facts(ctx: &WorkspaceContext, project: &Project) -> Result<ProjectFacts, EcoError> {
    let dir = &project.root;
    let py_path = project_join(dir, "pyproject.toml");

    let manifest = if has_file_in(ctx, dir, "pyproject.toml") {
        Some(FileFact {
            relative: py_path.clone(),
        })
    } else {
        None
    };

    let lockfiles = if has_file_in(ctx, dir, "uv.lock") {
        vec![FileFact {
            relative: project_join(dir, "uv.lock"),
        }]
    } else {
        Vec::new()
    };

    let mut configs = Vec::new();
    if has_file_in(ctx, dir, "uv.toml") {
        configs.push(FileFact {
            relative: project_join(dir, "uv.toml"),
        });
    }

    let mut parse_diagnostics: Vec<_> = pyproject_parse_diagnostic(ctx, dir).into_iter().collect();
    for config in &configs {
        if let Some(diag) = crate::ecosystems::syntax_diagnostic(ctx, &config.relative) {
            parse_diagnostics.push(diag);
        }
    }

    let py = pyproject::load(ctx, &py_path).ok();
    let has_manifest_dependencies = py.as_ref().is_some_and(|p| p.has_dependencies);

    let mut settings = InstallSettings::default();
    if let Some(p) = &py {
        settings.allow_insecure_hosts = p.uv.allow_insecure_hosts.clone();
        settings.index_strategy = p.uv.index_strategy.clone();
        settings.index_urls = p.uv.index_urls.clone();
        settings.extra_index_urls = p.uv.extra_index_urls.clone();
        settings.trusted_hosts = p.uv.trusted_hosts.clone();
    }
    let uv_toml = project_join(dir, "uv.toml");
    if has_file_in(ctx, dir, "uv.toml") {
        if let Ok(uv_settings) = uv::load(ctx, &uv_toml) {
            settings
                .allow_insecure_hosts
                .extend(uv_settings.allow_insecure_hosts);
            settings.index_urls.extend(uv_settings.index_urls);
            settings
                .extra_index_urls
                .extend(uv_settings.extra_index_urls);
            settings.trusted_hosts.extend(uv_settings.trusted_hosts);
            if settings.index_strategy.is_none() {
                settings.index_strategy = uv_settings.index_strategy;
            }
        }
    }

    let (deps, dep_diagnostics) = python_dependencies(ctx, dir, py.as_ref());
    parse_diagnostics.extend(dep_diagnostics);

    Ok(ProjectFacts {
        project: project.clone(),
        manifest,
        lockfiles,
        configs,
        has_manifest_dependencies,
        dependencies: deps,
        install_settings: settings,
        covered_by_workspace_lockfile: covered_by_uv_workspace(ctx, dir),
        has_legacy_bun_lockfile: false,
        parse_diagnostics,
    })
}

fn build_pip_facts(ctx: &WorkspaceContext, project: &Project) -> Result<ProjectFacts, EcoError> {
    let dir = &project.root;

    let reqs: Vec<PathBuf> = requirements_files(ctx)
        .into_iter()
        .filter(|p| requirements_project_dir(p) == *dir)
        .collect();

    let manifest = reqs.first().map(|p| FileFact {
        relative: p.clone(),
    });

    let mut configs = Vec::new();
    if has_file_in(ctx, dir, "pip.conf") {
        configs.push(FileFact {
            relative: project_join(dir, "pip.conf"),
        });
    }
    if has_file_in(ctx, dir, "pip.ini") {
        configs.push(FileFact {
            relative: project_join(dir, "pip.ini"),
        });
    }

    let mut settings = InstallSettings::default();
    let mut requirement_count = 0;
    let mut any_hashes = false;

    // Use a shared visited set so a file that is both an entry-point and an
    // include target is not double-counted for settings.
    let mut visited = std::collections::HashSet::new();
    let mut parse_diagnostics: Vec<crate::diagnostics::Diagnostic> =
        pyproject_parse_diagnostic(ctx, dir).into_iter().collect();

    for req in &reqs {
        let r = requirements::load_recursive(ctx, req, &mut visited, &mut parse_diagnostics);
        if r.require_hashes {
            settings.require_hashes = Some(true);
        }
        settings.trusted_hosts.extend(r.trusted_hosts);
        settings.index_urls.extend(r.index_urls);
        settings.extra_index_urls.extend(r.extra_index_urls);
        requirement_count += r.requirement_count;
        any_hashes |= r.has_hash_pins;
    }
    if any_hashes {
        settings.require_hashes = Some(true);
    }

    if let Some(pip_conf) = configs
        .iter()
        .find(|c| c.relative.file_name().and_then(|n| n.to_str()) == Some("pip.conf"))
    {
        if let Ok(pc) = pip::load(ctx, &pip_conf.relative) {
            settings.trusted_hosts.extend(pc.trusted_hosts);
            settings.index_urls.extend(pc.index_urls);
            settings.extra_index_urls.extend(pc.extra_index_urls);
            if pc.require_hashes {
                settings.require_hashes = Some(true);
            }
        }
    }

    let has_manifest_dependencies = requirement_count > 0;

    // Collect dependencies (with include-following), merging their diagnostics.
    let (deps, dep_diagnostics) = python_dependencies(ctx, dir, None);
    parse_diagnostics.extend(dep_diagnostics);

    Ok(ProjectFacts {
        project: project.clone(),
        manifest,
        lockfiles: Vec::new(),
        configs,
        has_manifest_dependencies,
        dependencies: deps,
        install_settings: settings,
        covered_by_workspace_lockfile: false,
        has_legacy_bun_lockfile: false,
        parse_diagnostics,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::ecosystems::{Analyzer, Ecosystem};
    use crate::filesystem::{scan, ScanOptions};
    use tempfile::TempDir;

    fn make_ctx(files: &[(&str, &str)]) -> (WorkspaceContext, TempDir) {
        let dir = TempDir::new().unwrap();
        for (rel, contents) in files {
            let p = dir.path().join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(p, contents).unwrap();
        }
        let ctx = scan(dir.path(), Config::default(), &ScanOptions::default()).unwrap();
        (ctx, dir)
    }

    // --- requirements_project_dir -------------------------------------------

    #[test]
    fn project_dir_for_top_level_requirements_is_dot() {
        assert_eq!(
            requirements_project_dir(Path::new("requirements.txt")),
            PathBuf::from(".")
        );
    }

    #[test]
    fn project_dir_for_requirements_subdir_is_parent_of_requirements() {
        // requirements/base.txt → project root is "."
        assert_eq!(
            requirements_project_dir(Path::new("requirements/base.txt")),
            PathBuf::from(".")
        );
    }

    #[test]
    fn project_dir_for_nested_requirements_subdir_is_app_root() {
        // myapp/requirements/dev.txt → project root is "myapp"
        assert_eq!(
            requirements_project_dir(Path::new("myapp/requirements/dev.txt")),
            PathBuf::from("myapp")
        );
    }

    #[test]
    fn project_dir_for_non_requirements_subdir_is_parent() {
        // configs/prod.txt → no `requirements` dir, project root is "configs"
        assert_eq!(
            requirements_project_dir(Path::new("configs/prod.txt")),
            PathBuf::from("configs")
        );
    }

    // --- requirements_files detection ----------------------------------------

    #[test]
    fn requirements_subdir_txt_files_are_detected() {
        let (ctx, _d) = make_ctx(&[
            ("requirements/base.txt", "requests==2.31.0\n"),
            ("requirements/dev.txt", "pytest==7.0\n"),
        ]);
        let files = requirements_files(&ctx);
        assert!(
            files.contains(&PathBuf::from("requirements/base.txt")),
            "base.txt missing from: {files:?}"
        );
        assert!(
            files.contains(&PathBuf::from("requirements/dev.txt")),
            "dev.txt missing from: {files:?}"
        );
    }

    #[test]
    fn classic_requirements_txt_still_detected() {
        let (ctx, _d) = make_ctx(&[("requirements.txt", "requests==2.31.0\n")]);
        let files = requirements_files(&ctx);
        assert!(files.contains(&PathBuf::from("requirements.txt")));
    }

    // --- detect: project rooted at the right directory -----------------------

    #[test]
    fn requirements_subdir_detects_project_at_workspace_root() {
        let (ctx, _d) = make_ctx(&[("requirements/base.txt", "requests==2.31.0\n")]);
        let projects = PythonAnalyzer.detect(&ctx);
        assert_eq!(projects.len(), 1, "expected one project: {projects:?}");
        assert_eq!(
            projects[0].root,
            PathBuf::from("."),
            "project root should be workspace root, not requirements/"
        );
        assert_eq!(projects[0].ecosystem, Ecosystem::Python);
    }

    #[test]
    fn requirements_subdir_does_not_duplicate_project_with_requirements_txt() {
        // requirements.txt and requirements/base.txt both map to root "." —
        // detect should yield exactly one project.
        let (ctx, _d) = make_ctx(&[
            ("requirements.txt", "-r requirements/base.txt\n"),
            ("requirements/base.txt", "requests==2.31.0\n"),
        ]);
        let projects = PythonAnalyzer.detect(&ctx);
        assert_eq!(projects.len(), 1, "expected one project, got: {projects:?}");
    }

    // --- facts: includes are followed for dependencies -----------------------

    #[test]
    fn dependencies_from_included_requirements_file_are_collected() {
        let (ctx, _d) = make_ctx(&[
            ("requirements.txt", "-r requirements/base.txt\n"),
            ("requirements/base.txt", "requests==2.31.0\nflask==3.0.0\n"),
        ]);
        let projects = PythonAnalyzer.detect(&ctx);
        assert_eq!(projects.len(), 1);
        let facts = PythonAnalyzer.facts(&projects[0], &ctx).unwrap();
        let names: Vec<&str> = facts.dependencies.iter().map(|d| d.name.as_str()).collect();
        assert!(
            names.contains(&"requests"),
            "requests missing from deps: {names:?}"
        );
        assert!(
            names.contains(&"flask"),
            "flask missing from deps: {names:?}"
        );
    }

    #[test]
    fn requirements_subdir_deps_are_collected_as_entry_points() {
        // requirements/base.txt is an entry-point (no top-level requirements.txt).
        let (ctx, _d) = make_ctx(&[
            ("requirements/base.txt", "requests==2.31.0\n"),
            ("requirements/dev.txt", "pytest==7.0\n"),
        ]);
        let projects = PythonAnalyzer.detect(&ctx);
        assert_eq!(projects.len(), 1);
        let facts = PythonAnalyzer.facts(&projects[0], &ctx).unwrap();
        let names: Vec<&str> = facts.dependencies.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"requests"), "{names:?}");
        assert!(names.contains(&"pytest"), "{names:?}");
    }

    #[test]
    fn cyclic_include_does_not_panic_and_emits_diagnostic() {
        let (ctx, _d) = make_ctx(&[
            (
                "requirements.txt",
                "-r requirements/a.txt\nrequests==2.31.0\n",
            ),
            (
                "requirements/a.txt",
                "-r ../requirements/a.txt\nflask==3.0.0\n",
            ),
        ]);
        let projects = PythonAnalyzer.detect(&ctx);
        assert_eq!(projects.len(), 1);
        let facts = PythonAnalyzer.facts(&projects[0], &ctx).unwrap();
        // Must not panic; a cyclic-include diagnostic must be present.
        assert!(
            facts
                .parse_diagnostics
                .iter()
                .any(|d| d.message.contains("cyclic")),
            "expected cyclic diagnostic, got: {:?}",
            facts.parse_diagnostics
        );
    }

    // --- build_pip_facts: settings propagate through includes ----------------

    #[test]
    fn require_hashes_propagates_from_included_file() {
        let (ctx, _d) = make_ctx(&[
            ("requirements.txt", "-r requirements/base.txt\n"),
            (
                "requirements/base.txt",
                "--require-hashes\nrequests==2.31.0 --hash=sha256:aaa\n",
            ),
        ]);
        let projects = PythonAnalyzer.detect(&ctx);
        assert_eq!(projects.len(), 1);
        let facts = PythonAnalyzer.facts(&projects[0], &ctx).unwrap();
        assert_eq!(
            facts.install_settings.require_hashes,
            Some(true),
            "require_hashes should propagate through -r include"
        );
    }
}
