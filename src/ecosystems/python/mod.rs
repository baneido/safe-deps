//! Python ecosystem analyzer: detects pip and uv projects and extracts
//! normalized facts from `pyproject.toml`, `requirements*.txt`, `pip.conf`, and
//! `uv.toml`.

use std::path::{Path, PathBuf};

use crate::ecosystems::source::classify_python_source;
use crate::ecosystems::{
    Dependency, DependencyGroup, EcoError, Ecosystem, FileFact, InstallSettings, PackageManager,
    Project, ProjectFacts, ProjectKind, Sourced,
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
            let dir = project_dir(&req);
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

        // Detect uv projects. Two cases:
        //
        // 1. The directory was already registered (e.g. via `requirements*.txt`
        //    as `pip`) but ALSO contains `uv.toml` or `uv.lock` — this is the
        //    common "uv manages a requirements-based project" layout. Upgrade the
        //    existing project to `PackageManager::Uv` so that `build_uv_facts`
        //    runs and uv settings reach SD003/SD007.
        //
        // 2. The directory has only `uv.toml` / `uv.lock` with no
        //    `pyproject.toml` or `requirements*.txt`. These directories are
        //    otherwise invisible to the analyzer; add a new project entry.
        for uv_file in files_named(ctx, "uv.toml")
            .into_iter()
            .chain(files_named(ctx, "uv.lock"))
        {
            let dir = project_dir(&uv_file);
            if let Some(existing) = projects.iter_mut().find(|p| p.root == dir) {
                // Upgrade a previously-detected pip project to uv so that uv
                // config (allow-insecure-host, index-strategy, …) is parsed.
                if existing.package_manager == PackageManager::Pip {
                    existing.package_manager = PackageManager::Uv;
                }
                // If it was already Uv (e.g. detected via pyproject.toml with
                // [tool.uv]), leave it as-is — no duplicate entry needed.
            } else {
                covered_dirs.push(dir.clone());
                projects.push(Project {
                    root: dir,
                    ecosystem: Ecosystem::Python,
                    package_manager: PackageManager::Uv,
                    kind: ProjectKind::Unknown,
                });
            }
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

/// Appends each parsed value to `target`, tagging it with the file it came from
/// so rules can locate a finding on the exact source config when several config
/// files (e.g. both `pip.conf` and `pip.ini`) declare overlapping settings.
fn extend_sourced(
    target: &mut Vec<Sourced<String>>,
    values: impl IntoIterator<Item = String>,
    source: &Path,
) {
    target.extend(
        values
            .into_iter()
            .map(|v| Sourced::from(v, source.to_path_buf())),
    );
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

/// Returns relative paths of `requirements*.txt` files.
fn requirements_files(ctx: &WorkspaceContext) -> Vec<PathBuf> {
    ctx.files
        .iter()
        .filter(|f| {
            let name = f
                .relative
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            name.starts_with("requirements") && name.ends_with(".txt")
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

fn python_dependencies(
    ctx: &WorkspaceContext,
    dir: &Path,
    pyproject: Option<&pyproject::Pyproject>,
) -> Vec<Dependency> {
    let py_path = project_join(dir, "pyproject.toml");
    let owned = if pyproject.is_none() && has_file_in(ctx, dir, "pyproject.toml") {
        pyproject::load(ctx, &py_path).ok()
    } else {
        None
    };
    let mut out = Vec::new();
    if let Some(py) = pyproject.or(owned.as_ref()) {
        out.extend(py.classified_dependencies(&py_path));
    }
    for req in requirements_files(ctx)
        .into_iter()
        .filter(|p| project_dir(p) == *dir)
    {
        // A `requirements-dev.txt` / `requirements/test.txt` holds dev deps, so
        // a local editable path there is not a production-source finding.
        let group = requirements_group(&req);
        if let Ok(r) = requirements::load(ctx, &req) {
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
    }
    // Collapse exact (name, spec) duplicates only, so distinct sources for the
    // same package both survive (SD006 still flags the unsafe one).
    let mut seen = std::collections::HashSet::new();
    out.retain(|d| seen.insert((d.name.clone(), d.spec.clone())));
    out
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
        extend_sourced(&mut settings.index_urls, p.uv.index_urls.clone(), &py_path);
        extend_sourced(
            &mut settings.extra_index_urls,
            p.uv.extra_index_urls.clone(),
            &py_path,
        );
        extend_sourced(
            &mut settings.trusted_hosts,
            p.uv.trusted_hosts.clone(),
            &py_path,
        );
    }
    let uv_toml = project_join(dir, "uv.toml");
    if has_file_in(ctx, dir, "uv.toml") {
        if let Ok(uv_settings) = uv::load(ctx, &uv_toml) {
            settings
                .allow_insecure_hosts
                .extend(uv_settings.allow_insecure_hosts);
            extend_sourced(&mut settings.index_urls, uv_settings.index_urls, &uv_toml);
            extend_sourced(
                &mut settings.extra_index_urls,
                uv_settings.extra_index_urls,
                &uv_toml,
            );
            extend_sourced(
                &mut settings.trusted_hosts,
                uv_settings.trusted_hosts,
                &uv_toml,
            );
            if settings.index_strategy.is_none() {
                settings.index_strategy = uv_settings.index_strategy;
            }
        }
    }

    Ok(ProjectFacts {
        project: project.clone(),
        manifest,
        lockfiles,
        configs,
        has_manifest_dependencies,
        dependencies: python_dependencies(ctx, dir, py.as_ref()),
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
        .filter(|p| project_dir(p) == *dir)
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
    for req in &reqs {
        if let Ok(r) = requirements::load(ctx, req) {
            if r.require_hashes {
                settings.require_hashes = Some(true);
            }
            extend_sourced(&mut settings.trusted_hosts, r.trusted_hosts, req);
            extend_sourced(&mut settings.index_urls, r.index_urls, req);
            extend_sourced(&mut settings.extra_index_urls, r.extra_index_urls, req);
            requirement_count += r.requirement_count;
            any_hashes |= r.has_hash_pins;
        }
    }
    if any_hashes {
        settings.require_hashes = Some(true);
    }

    for pip_config in configs.iter().filter(|c| {
        matches!(
            c.relative.file_name().and_then(|n| n.to_str()),
            Some("pip.conf") | Some("pip.ini")
        )
    }) {
        let source = &pip_config.relative;
        if let Ok(pc) = pip::load(ctx, source) {
            extend_sourced(&mut settings.trusted_hosts, pc.trusted_hosts, source);
            extend_sourced(&mut settings.index_urls, pc.index_urls, source);
            extend_sourced(&mut settings.extra_index_urls, pc.extra_index_urls, source);
            if pc.require_hashes {
                settings.require_hashes = Some(true);
            }
        }
    }

    let has_manifest_dependencies = requirement_count > 0;

    Ok(ProjectFacts {
        project: project.clone(),
        manifest,
        lockfiles: Vec::new(),
        configs,
        has_manifest_dependencies,
        dependencies: python_dependencies(ctx, dir, None),
        install_settings: settings,
        covered_by_workspace_lockfile: false,
        has_legacy_bun_lockfile: false,
        parse_diagnostics: pyproject_parse_diagnostic(ctx, dir).into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::ecosystems::{Analyzer, Ecosystem, PackageManager, ProjectKind};
    use crate::filesystem::{scan, ScanOptions};
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Builds a temporary workspace with the given `(relative_path, contents)`
    /// pairs and returns a scanned `WorkspaceContext` rooted at it. The
    /// `TempDir` is returned alongside so it stays alive for the duration of
    /// the test.
    fn make_ctx(files: &[(&str, &str)]) -> (TempDir, WorkspaceContext) {
        let dir = TempDir::new().unwrap();
        for (rel, contents) in files {
            let p = dir.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, contents).unwrap();
        }
        let ctx = scan(dir.path(), Config::default(), &ScanOptions::default()).unwrap();
        (dir, ctx)
    }

    fn pip_project() -> Project {
        Project {
            root: PathBuf::from("."),
            ecosystem: Ecosystem::Python,
            package_manager: PackageManager::Pip,
            kind: ProjectKind::Unknown,
        }
    }

    /// Whether any sourced value matches `needle`.
    fn has_value(values: &[Sourced<String>], needle: &str) -> bool {
        values.iter().any(|s| s.value == needle)
    }

    /// The source file recorded for the sourced value equal to `needle`.
    fn source_of<'a>(values: &'a [Sourced<String>], needle: &str) -> Option<&'a Path> {
        values
            .iter()
            .find(|s| s.value == needle)
            .and_then(|s| s.source.as_deref())
    }

    #[test]
    fn pip_ini_trusted_host_is_collected() {
        let (_dir, ctx) = make_ctx(&[
            ("requirements.txt", "requests==2.31.0\n"),
            ("pip.ini", "[global]\ntrusted-host = pypi.internal\n"),
        ]);
        let facts = build_pip_facts(&ctx, &pip_project()).unwrap();
        assert!(
            has_value(&facts.install_settings.trusted_hosts, "pypi.internal"),
            "trusted_hosts: {:?}",
            facts.install_settings.trusted_hosts
        );
    }

    #[test]
    fn pip_ini_index_url_is_collected() {
        let (_dir, ctx) = make_ctx(&[
            ("requirements.txt", "requests==2.31.0\n"),
            ("pip.ini", "[global]\nindex-url = http://internal/simple\n"),
        ]);
        let facts = build_pip_facts(&ctx, &pip_project()).unwrap();
        assert!(
            has_value(&facts.install_settings.index_urls, "http://internal/simple"),
            "index_urls: {:?}",
            facts.install_settings.index_urls
        );
    }

    #[test]
    fn pip_ini_require_hashes_is_collected() {
        let (_dir, ctx) = make_ctx(&[
            ("requirements.txt", "requests==2.31.0\n"),
            ("pip.ini", "[global]\nrequire-hashes = true\n"),
        ]);
        let facts = build_pip_facts(&ctx, &pip_project()).unwrap();
        assert_eq!(
            facts.install_settings.require_hashes,
            Some(true),
            "require_hashes must be Some(true) from pip.ini"
        );
    }

    /// Builds a temporary workspace and returns just the `TempDir`.
    fn ws(files: &[(&str, &str)]) -> TempDir {
        let dir = TempDir::new().unwrap();
        for (rel, contents) in files {
            let p = dir.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, contents).unwrap();
        }
        dir
    }

    fn detect_projects(dir: &TempDir) -> Vec<Project> {
        let ctx = scan(dir.path(), Config::default(), &ScanOptions::default()).unwrap();
        PythonAnalyzer.detect(&ctx)
    }

    fn all_facts(dir: &TempDir) -> Vec<ProjectFacts> {
        let ctx = scan(dir.path(), Config::default(), &ScanOptions::default()).unwrap();
        PythonAnalyzer
            .detect(&ctx)
            .iter()
            .filter_map(|p| PythonAnalyzer.facts(p, &ctx).ok())
            .collect()
    }

    // --- uv.toml-only detection -----------------------------------------------

    #[test]
    fn uv_toml_only_detects_uv_project() {
        // A directory with only uv.toml (no pyproject.toml, no requirements.txt)
        // must be detected as a uv/Python project so SD003/SD007 can fire.
        let dir = ws(&[("uv.toml", "allow-insecure-host = [\"internal.example\"]\n")]);
        let projects = detect_projects(&dir);
        assert_eq!(projects.len(), 1, "expected one project: {projects:?}");
        assert_eq!(projects[0].package_manager, PackageManager::Uv);
        assert_eq!(projects[0].ecosystem, Ecosystem::Python);
    }

    #[test]
    fn uv_lock_only_detects_uv_project() {
        // A directory with only uv.lock (no pyproject.toml) must also be detected.
        let dir = ws(&[("uv.lock", "version = 1\n")]);
        let projects = detect_projects(&dir);
        assert_eq!(projects.len(), 1, "expected one project: {projects:?}");
        assert_eq!(projects[0].package_manager, PackageManager::Uv);
    }

    #[test]
    fn uv_toml_insecure_host_populates_settings() {
        // The insecure-host in uv.toml must be collected so SD003 can fire.
        let dir = ws(&[("uv.toml", "allow-insecure-host = [\"internal.example\"]\n")]);
        let facts = all_facts(&dir);
        assert_eq!(facts.len(), 1);
        assert_eq!(
            facts[0].install_settings.allow_insecure_hosts,
            vec!["internal.example"]
        );
    }

    #[test]
    fn pip_ini_extra_index_url_is_collected() {
        let (_dir, ctx) = make_ctx(&[
            ("requirements.txt", "requests==2.31.0\n"),
            (
                "pip.ini",
                "[global]\nextra-index-url = https://internal/simple\n",
            ),
        ]);
        let facts = build_pip_facts(&ctx, &pip_project()).unwrap();
        assert!(
            has_value(
                &facts.install_settings.extra_index_urls,
                "https://internal/simple"
            ),
            "extra_index_urls: {:?}",
            facts.install_settings.extra_index_urls
        );
    }

    #[test]
    fn pip_ini_appears_in_configs() {
        let (_dir, ctx) = make_ctx(&[
            ("requirements.txt", "requests==2.31.0\n"),
            ("pip.ini", "[global]\nindex-url = https://pypi.org/simple\n"),
        ]);
        let facts = build_pip_facts(&ctx, &pip_project()).unwrap();
        let has_pip_ini = facts
            .configs
            .iter()
            .any(|c| c.relative.file_name().and_then(|n| n.to_str()) == Some("pip.ini"));
        assert!(
            has_pip_ini,
            "pip.ini must appear in configs: {:?}",
            facts.configs
        );
    }

    #[test]
    fn pip_ini_and_pip_conf_both_collected() {
        // Both files may coexist; settings from each must be merged.
        let (_dir, ctx) = make_ctx(&[
            ("requirements.txt", "requests==2.31.0\n"),
            ("pip.conf", "[global]\ntrusted-host = host1.internal\n"),
            ("pip.ini", "[global]\ntrusted-host = host2.internal\n"),
        ]);
        let facts = build_pip_facts(&ctx, &pip_project()).unwrap();
        let hosts = &facts.install_settings.trusted_hosts;
        assert!(
            has_value(hosts, "host1.internal"),
            "host from pip.conf missing: {hosts:?}"
        );
        assert!(
            has_value(hosts, "host2.internal"),
            "host from pip.ini missing: {hosts:?}"
        );
    }

    #[test]
    fn pip_settings_carry_their_originating_file() {
        // With both files present, each host must record the file it came from
        // so a rule does not attribute a pip.ini setting to pip.conf.
        let (_dir, ctx) = make_ctx(&[
            ("requirements.txt", "requests==2.31.0\n"),
            ("pip.conf", "[global]\ntrusted-host = host1.internal\n"),
            ("pip.ini", "[global]\ntrusted-host = host2.internal\n"),
        ]);
        let facts = build_pip_facts(&ctx, &pip_project()).unwrap();
        let hosts = &facts.install_settings.trusted_hosts;
        assert_eq!(
            source_of(hosts, "host1.internal"),
            Some(Path::new("pip.conf")),
            "host1 must be attributed to pip.conf: {hosts:?}"
        );
        assert_eq!(
            source_of(hosts, "host2.internal"),
            Some(Path::new("pip.ini")),
            "host2 must be attributed to pip.ini: {hosts:?}"
        );
    }

    #[test]
    fn index_url_only_in_pip_ini_is_sourced_to_pip_ini() {
        // pip.conf has a safe index; pip.ini has the insecure one. The insecure
        // index must be attributed to pip.ini, not the first-existing pip.conf.
        let (_dir, ctx) = make_ctx(&[
            ("requirements.txt", "requests==2.31.0\n"),
            (
                "pip.conf",
                "[global]\nindex-url = https://pypi.org/simple\n",
            ),
            ("pip.ini", "[global]\nindex-url = http://internal/simple\n"),
        ]);
        let facts = build_pip_facts(&ctx, &pip_project()).unwrap();
        assert_eq!(
            source_of(&facts.install_settings.index_urls, "http://internal/simple"),
            Some(Path::new("pip.ini")),
            "insecure index from pip.ini must be sourced to pip.ini: {:?}",
            facts.install_settings.index_urls
        );
    }

    #[test]
    fn uv_toml_and_lock_lockfile_is_present() {
        // With both uv.toml and uv.lock the lockfile vec must be non-empty
        // so SD001 does not fire (no manifest means has_manifest_dependencies=false
        // anyway, but the lockfile should still be recorded correctly).
        let dir = ws(&[
            ("uv.toml", "index-strategy = \"first-match\"\n"),
            ("uv.lock", "version = 1\n"),
        ]);
        let facts = all_facts(&dir);
        assert_eq!(facts.len(), 1);
        assert_eq!(
            facts[0].lockfiles.len(),
            1,
            "uv.lock must appear in lockfiles"
        );
        assert!(!facts[0].has_manifest_dependencies);
    }

    #[test]
    fn uv_toml_with_pyproject_not_double_detected() {
        // When both pyproject.toml and uv.toml are present, only one project
        // should be detected (pyproject.toml wins because it appears first).
        let dir = ws(&[
            (
                "pyproject.toml",
                "[project]\nname = \"x\"\ndependencies = [\"requests\"]\n",
            ),
            ("uv.toml", "index-strategy = \"first-match\"\n"),
            ("uv.lock", "version = 1\n"),
        ]);
        let projects = detect_projects(&dir);
        assert_eq!(projects.len(), 1, "duplicate detection: {projects:?}");
        assert_eq!(projects[0].package_manager, PackageManager::Uv);
    }

    #[test]
    fn existing_pyproject_detection_unaffected() {
        // A plain pyproject.toml project without uv.* files must still be pip.
        let dir = ws(&[(
            "pyproject.toml",
            "[project]\nname = \"x\"\ndependencies = [\"requests\"]\n",
        )]);
        let projects = detect_projects(&dir);
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].package_manager, PackageManager::Pip);
    }

    #[test]
    fn existing_requirements_detection_unaffected() {
        // A plain requirements.txt project without uv.* files must still be pip.
        let dir = ws(&[("requirements.txt", "requests==2.31.0\n")]);
        let projects = detect_projects(&dir);
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].package_manager, PackageManager::Pip);
    }

    // --- requirements.txt + uv.toml upgrade ------------------------------------

    #[test]
    fn requirements_plus_uv_toml_upgrades_to_uv() {
        // A directory with both requirements.txt AND uv.toml must be classified
        // as Uv (not Pip) so that uv settings reach SD003/SD007.
        let dir = ws(&[
            ("requirements.txt", "requests==2.31.0\n"),
            ("uv.toml", "allow-insecure-host = [\"internal.example\"]\n"),
        ]);
        let projects = detect_projects(&dir);
        assert_eq!(projects.len(), 1, "expected one project, got: {projects:?}");
        assert_eq!(projects[0].package_manager, PackageManager::Uv);
    }

    #[test]
    fn requirements_plus_uv_lock_upgrades_to_uv() {
        // A directory with requirements.txt AND uv.lock must also be upgraded.
        let dir = ws(&[
            ("requirements.txt", "requests==2.31.0\n"),
            ("uv.lock", "version = 1\n"),
        ]);
        let projects = detect_projects(&dir);
        assert_eq!(projects.len(), 1, "expected one project, got: {projects:?}");
        assert_eq!(projects[0].package_manager, PackageManager::Uv);
    }

    #[test]
    fn requirements_plus_uv_toml_no_duplicate_projects() {
        // The upgrade must not create a second project entry for the same dir.
        let dir = ws(&[
            ("requirements.txt", "requests==2.31.0\n"),
            ("uv.toml", "index-strategy = \"unsafe-best-match\"\n"),
        ]);
        let projects = detect_projects(&dir);
        assert_eq!(projects.len(), 1, "duplicate projects: {projects:?}");
    }

    #[test]
    fn requirements_plus_uv_toml_allow_insecure_host_in_settings() {
        // After upgrading to Uv, build_uv_facts must parse uv.toml so that
        // allow-insecure-host populates install_settings (SD003 can fire).
        let dir = ws(&[
            ("requirements.txt", "requests==2.31.0\n"),
            ("uv.toml", "allow-insecure-host = [\"internal.example\"]\n"),
        ]);
        let facts = all_facts(&dir);
        assert_eq!(facts.len(), 1);
        assert_eq!(
            facts[0].install_settings.allow_insecure_hosts,
            vec!["internal.example"],
            "allow-insecure-host from uv.toml must be present in settings"
        );
    }

    #[test]
    fn requirements_plus_uv_toml_index_strategy_in_settings() {
        // After upgrading to Uv, index-strategy from uv.toml must be visible
        // in install_settings so SD007 can fire.
        let dir = ws(&[
            ("requirements.txt", "requests==2.31.0\n"),
            (
                "uv.toml",
                "index-strategy = \"unsafe-best-match\"\nextra-index-url = [\"https://pypi.internal/simple\"]\n",
            ),
        ]);
        let facts = all_facts(&dir);
        assert_eq!(facts.len(), 1);
        assert_eq!(
            facts[0].install_settings.index_strategy.as_deref(),
            Some("unsafe-best-match"),
            "index-strategy from uv.toml must be present in settings"
        );
    }
}
