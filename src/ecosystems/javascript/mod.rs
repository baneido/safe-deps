//! JavaScript ecosystem analyzer: detects npm/Yarn/pnpm/Bun projects and
//! extracts normalized facts from manifests, lockfiles, and config files.

use std::path::{Path, PathBuf};

use crate::ecosystems::{
    is_proper_ancestor, EcoError, Ecosystem, FileFact, InstallSettings, PackageManager, Project,
    ProjectFacts, ProjectKind,
};
use crate::filesystem::{files_named, project_join, WorkspaceContext};

pub mod bun;
pub mod npm;
pub mod package_json;
pub mod pnpm;
pub mod yarn;

pub struct JavaScriptAnalyzer;

impl crate::ecosystems::Analyzer for JavaScriptAnalyzer {
    fn name(&self) -> &'static str {
        "javascript"
    }

    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Project> {
        let package_jsons = files_named(ctx, "package.json");
        let mut projects = Vec::new();
        for pj in &package_jsons {
            let dir = project_dir(pj);
            let manager = detect_package_manager(ctx, &dir, pj);
            projects.push(Project {
                root: dir,
                ecosystem: Ecosystem::JavaScript,
                package_manager: manager,
                kind: ProjectKind::Unknown,
            });
        }
        projects
    }

    fn facts(&self, project: &Project, ctx: &WorkspaceContext) -> Result<ProjectFacts, EcoError> {
        build_facts(ctx, project)
    }
}

fn project_dir(package_json_path: &Path) -> PathBuf {
    package_json_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Determines the package manager for a directory containing `package.json`,
/// falling back to the nearest ancestor workspace root before defaulting to npm.
fn detect_package_manager(
    ctx: &WorkspaceContext,
    dir: &Path,
    package_json_path: &Path,
) -> PackageManager {
    detect_local_package_manager(ctx, dir, package_json_path)
        // Inherit from the nearest ancestor workspace root, if any.
        .or_else(|| inherit_from_workspace_root(ctx, dir))
        .unwrap_or(PackageManager::Npm)
}

/// Like [`detect_package_manager`] but without the workspace-root inheritance
/// fallback. Used when resolving a workspace root's own manager, to avoid
/// recursing back into inheritance.
fn detect_package_manager_skip_inherit(
    ctx: &WorkspaceContext,
    dir: &Path,
    package_json_path: &Path,
) -> PackageManager {
    detect_local_package_manager(ctx, dir, package_json_path).unwrap_or(PackageManager::Npm)
}

/// Resolves the package manager from signals local to `dir` (the `packageManager`
/// hint, then lockfiles, then config files). Returns `None` when no local signal
/// is present, leaving the fallback (inheritance and/or npm default) to callers.
fn detect_local_package_manager(
    ctx: &WorkspaceContext,
    dir: &Path,
    package_json_path: &Path,
) -> Option<PackageManager> {
    if let Ok(pj) = package_json::load(ctx, package_json_path) {
        if let Some(hint) = pj.package_manager_hint() {
            return Some(hint.manager);
        }
    }

    if has_file_in(ctx, dir, "pnpm-lock.yaml") {
        return Some(PackageManager::Pnpm);
    }
    if has_file_in(ctx, dir, "yarn.lock") {
        return Some(PackageManager::Yarn);
    }
    if has_file_in(ctx, dir, "package-lock.json") || has_file_in(ctx, dir, "npm-shrinkwrap.json") {
        return Some(PackageManager::Npm);
    }
    if has_file_in(ctx, dir, "bun.lock") || has_file_in(ctx, dir, "bun.lockb") {
        return Some(PackageManager::Bun);
    }

    if has_file_in(ctx, dir, ".yarnrc.yml") || has_file_in(ctx, dir, ".yarnrc") {
        return Some(PackageManager::Yarn);
    }
    if has_file_in(ctx, dir, "pnpm-workspace.yaml") {
        return Some(PackageManager::Pnpm);
    }
    if has_file_in(ctx, dir, "bunfig.toml") {
        return Some(PackageManager::Bun);
    }

    None
}

fn has_file_in(ctx: &WorkspaceContext, dir: &Path, name: &str) -> bool {
    let target = project_join(dir, name);
    ctx.contains(&target)
}

/// Finds the nearest ancestor workspace root and returns its package manager.
fn inherit_from_workspace_root(ctx: &WorkspaceContext, dir: &Path) -> Option<PackageManager> {
    let package_jsons = files_named(ctx, "package.json");
    let mut best: Option<(usize, PackageManager)> = None;
    for pj in &package_jsons {
        let root_dir = project_dir(pj);
        if !is_proper_ancestor(&root_dir, dir) {
            continue;
        }
        if !is_workspace_root(ctx, &root_dir, pj) {
            continue;
        }
        let pm = detect_package_manager_skip_inherit(ctx, &root_dir, pj);
        let depth = root_dir.components().count();
        match &best {
            None => best = Some((depth, pm)),
            Some((best_depth, _)) if depth > *best_depth => best = Some((depth, pm)),
            _ => {}
        }
    }
    best.map(|(_, pm)| pm)
}

fn is_workspace_root(ctx: &WorkspaceContext, dir: &Path, package_json_path: &Path) -> bool {
    if has_file_in(ctx, dir, "pnpm-workspace.yaml") {
        return true;
    }
    if let Ok(pj) = package_json::load(ctx, package_json_path) {
        if !pj.workspaces.is_empty() {
            return true;
        }
    }
    false
}

/// Returns whether a lockfile for `manager` exists in `dir`.
fn lockfile_in_dir(ctx: &WorkspaceContext, dir: &Path, manager: PackageManager) -> Vec<PathBuf> {
    let names: &[&str] = match manager {
        PackageManager::Npm => &["package-lock.json", "npm-shrinkwrap.json"],
        PackageManager::Yarn => &["yarn.lock"],
        PackageManager::Pnpm => &["pnpm-lock.yaml"],
        PackageManager::Bun => &["bun.lock"],
        PackageManager::Pip | PackageManager::Uv | PackageManager::Cargo | PackageManager::Go => {
            &[]
        }
    };
    names
        .iter()
        .filter_map(|name| {
            let path = project_join(dir, name);
            if ctx.contains(&path) {
                Some(path)
            } else {
                None
            }
        })
        .collect()
}

/// Builds `ProjectFacts` for a JavaScript project.
fn build_facts(ctx: &WorkspaceContext, project: &Project) -> Result<ProjectFacts, EcoError> {
    let dir = &project.root;
    let pj_path = project_join(dir, "package.json");

    let manifest = if ctx.contains(&pj_path) {
        Some(FileFact {
            relative: pj_path.clone(),
        })
    } else {
        None
    };

    let lockfiles: Vec<FileFact> = lockfile_in_dir(ctx, dir, project.package_manager)
        .into_iter()
        .map(|p| FileFact { relative: p })
        .collect();

    let configs = collect_configs(ctx, dir, project.package_manager);

    let mut parse_diagnostics = Vec::new();
    let package_json = if manifest.is_some() {
        match package_json::load(ctx, &pj_path) {
            Ok(pj) => Some(pj),
            Err(err) => {
                parse_diagnostics.push(crate::diagnostics::Diagnostic::warn_at(
                    err.to_string(),
                    pj_path.clone(),
                ));
                None
            }
        }
    } else {
        None
    };
    let has_manifest_dependencies = package_json
        .as_ref()
        .is_some_and(|pj| pj.has_dependencies());
    let dependencies = package_json
        .as_ref()
        .map(|pj| pj.dependencies(&pj_path))
        .unwrap_or_default();

    // Surface malformed structured config files (bunfig.toml, .yarnrc.yml,
    // pnpm-workspace.yaml) so they are not silently ignored.
    for config in &configs {
        if let Some(diag) = crate::ecosystems::syntax_diagnostic(ctx, &config.relative) {
            parse_diagnostics.push(diag);
        }
    }

    let install_settings =
        build_install_settings(ctx, dir, project.package_manager, package_json.as_ref());

    let covered_by_workspace_lockfile = covered_by_workspace(ctx, dir, project.package_manager);

    let has_legacy_bun_lockfile = project.package_manager == PackageManager::Bun
        && bun::has_bun_lockb(ctx, dir)
        && !bun::has_bun_lock(ctx, dir);

    Ok(ProjectFacts {
        project: project.clone(),
        manifest,
        lockfiles,
        configs,
        has_manifest_dependencies,
        dependencies,
        install_settings,
        covered_by_workspace_lockfile,
        has_legacy_bun_lockfile,
        parse_diagnostics,
    })
}

fn collect_configs(ctx: &WorkspaceContext, dir: &Path, manager: PackageManager) -> Vec<FileFact> {
    let candidates: &[&str] = match manager {
        PackageManager::Npm => &[".npmrc"],
        PackageManager::Pnpm => &[".npmrc", "pnpm-workspace.yaml"],
        PackageManager::Yarn => &[".yarnrc.yml", ".yarnrc"],
        PackageManager::Bun => &["bunfig.toml", ".npmrc"],
        PackageManager::Pip | PackageManager::Uv | PackageManager::Cargo | PackageManager::Go => {
            &[]
        }
    };
    candidates
        .iter()
        .filter_map(|name| {
            let path = project_join(dir, name);
            if ctx.contains(&path) {
                Some(FileFact { relative: path })
            } else {
                None
            }
        })
        .collect()
}

fn build_install_settings(
    ctx: &WorkspaceContext,
    dir: &Path,
    manager: PackageManager,
    package_json: Option<&package_json::PackageJson>,
) -> InstallSettings {
    let mut settings = InstallSettings::default();

    match manager {
        PackageManager::Npm | PackageManager::Pnpm => {
            let npmrc_path = project_join(dir, ".npmrc");
            if let Ok(npmrc) = npm::load(ctx, &npmrc_path) {
                settings.strict_ssl = npmrc.strict_ssl;
                settings.strict_ssl_line = npmrc.strict_ssl_line;
                settings.registry = npmrc.registry;
                settings.package_lock_enabled = npmrc.package_lock_enabled;
                settings.package_lock_line = npmrc.package_lock_line;
                settings.http_registries = npmrc.http_registries;
            }
            if manager == PackageManager::Pnpm {
                settings.pnpm_allow_all_builds = pnpm_allow_all_builds(ctx, dir, package_json);
            }
        }
        PackageManager::Yarn => {
            let yarnrc_yml = project_join(dir, ".yarnrc.yml");
            let has_yml = has_file_in(ctx, dir, ".yarnrc.yml");
            let has_v1 = has_file_in(ctx, dir, ".yarnrc");
            if has_yml {
                if let Ok(yarnrc) = yarn::load_yarnrc_yml(ctx, &yarnrc_yml) {
                    settings.checksum_behavior = yarnrc.checksum_behavior;
                    settings.unsafe_http_whitelist = yarnrc.unsafe_http_whitelist;
                }
            }
            settings.yarn_generation = Some(yarn::detect_generation(ctx, dir, has_yml, has_v1));
        }
        PackageManager::Bun => {
            // Bun reads `trustedDependencies` from package.json; an older bunfig
            // form is also accepted. Merge both sources.
            if let Some(pj) = package_json {
                settings
                    .trusted_dependencies
                    .extend(pj.trusted_dependencies.iter().cloned());
            }
            let bunfig = project_join(dir, "bunfig.toml");
            if has_file_in(ctx, dir, "bunfig.toml") {
                if let Ok(bunfig_settings) = bun::load_bunfig(ctx, &bunfig) {
                    settings
                        .trusted_dependencies
                        .extend(bunfig_settings.trusted_dependencies);
                }
            }
        }
        PackageManager::Pip | PackageManager::Uv | PackageManager::Cargo | PackageManager::Go => {}
    }

    settings
}

/// Resolves pnpm's `dangerouslyAllowAllBuilds` from `pnpm-workspace.yaml` first
/// (where pnpm itself reads it), then the `package.json` `pnpm` field.
fn pnpm_allow_all_builds(
    ctx: &WorkspaceContext,
    dir: &Path,
    package_json: Option<&package_json::PackageJson>,
) -> Option<bool> {
    let ws_path = project_join(dir, "pnpm-workspace.yaml");
    if has_file_in(ctx, dir, "pnpm-workspace.yaml") {
        if let Ok(ws) = pnpm::load_workspace(ctx, &ws_path) {
            if ws.dangerously_allow_all_builds.is_some() {
                return ws.dangerously_allow_all_builds;
            }
        }
    }
    package_json
        .and_then(|pj| pj.pnpm.as_ref())
        .and_then(|c| c.dangerously_allow_all_builds)
}

/// A project is covered when a proper-ancestor workspace root declares
/// workspaces and holds a lockfile for the same package manager.
fn covered_by_workspace(ctx: &WorkspaceContext, dir: &Path, manager: PackageManager) -> bool {
    if dir == Path::new(".") {
        return false;
    }
    let package_jsons = files_named(ctx, "package.json");
    for pj in &package_jsons {
        let root_dir = project_dir(pj);
        if !is_proper_ancestor(&root_dir, dir) {
            continue;
        }
        if !is_workspace_root(ctx, &root_dir, pj) {
            continue;
        }
        if !lockfile_in_dir(ctx, &root_dir, manager).is_empty() {
            return true;
        }
    }
    false
}
