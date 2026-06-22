//! Python ecosystem analyzer: detects pip and uv projects and extracts
//! normalized facts from `pyproject.toml`, `requirements*.txt`, `pip.conf`, and
//! `uv.toml`.

use std::path::{Path, PathBuf};

use crate::ecosystems::source::classify_python_source;
use crate::ecosystems::{
    Dependency, DependencyGroup, EcoError, Ecosystem, FileFact, InstallSettings, PackageManager,
    PipRequirementFile, Project, ProjectFacts, ProjectKind,
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
        pip_requirements: Vec::new(),
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
    let mut pip_requirements: Vec<PipRequirementFile> = Vec::new();
    for req in &reqs {
        if let Ok(r) = requirements::load(ctx, req) {
            // `r.require_hashes` is true when the file uses `--require-hashes`
            // explicitly or when every requirement carries `--hash=` inline.
            // Both signal integrity enforcement for that individual file.
            // Do NOT propagate to `settings.require_hashes` here — that field
            // is reserved for pip.conf-level global enforcement. Per-file state
            // lives in `pip_requirements` so SD004 can evaluate each file
            // independently without a hash-pinned dev file masking an unhashed
            // production file.
            settings.trusted_hosts.extend(r.trusted_hosts);
            settings.index_urls.extend(r.index_urls);
            settings.extra_index_urls.extend(r.extra_index_urls);
            requirement_count += r.requirement_count;
            pip_requirements.push(PipRequirementFile {
                relative: req.clone(),
                has_hashes: r.require_hashes,
                has_requirements: r.requirement_count > 0,
            });
        }
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
        pip_requirements,
    })
}
