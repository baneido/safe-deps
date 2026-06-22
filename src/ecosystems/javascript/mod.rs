//! JavaScript ecosystem analyzer: detects npm/Yarn/pnpm/Bun projects and
//! extracts normalized facts from manifests, lockfiles, and config files.

use std::path::{Path, PathBuf};

use crate::ecosystems::{
    EcoError, Ecosystem, FileFact, InstallSettings, PackageManager, Project, ProjectFacts,
    ProjectKind,
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

/// Determines the package manager for a directory containing `package.json`.
fn detect_package_manager(
    ctx: &WorkspaceContext,
    dir: &Path,
    package_json_path: &Path,
) -> PackageManager {
    if let Ok(pj) = package_json::load(ctx, package_json_path) {
        if let Some(hint) = pj.package_manager_hint() {
            return hint.manager;
        }
    }

    if has_file_in(ctx, dir, "pnpm-lock.yaml") {
        return PackageManager::Pnpm;
    }
    if has_file_in(ctx, dir, "yarn.lock") {
        return PackageManager::Yarn;
    }
    if has_file_in(ctx, dir, "package-lock.json") || has_file_in(ctx, dir, "npm-shrinkwrap.json") {
        return PackageManager::Npm;
    }
    if has_file_in(ctx, dir, "bun.lock") || has_file_in(ctx, dir, "bun.lockb") {
        return PackageManager::Bun;
    }

    if has_file_in(ctx, dir, ".yarnrc.yml") || has_file_in(ctx, dir, ".yarnrc") {
        return PackageManager::Yarn;
    }
    if has_file_in(ctx, dir, "pnpm-workspace.yaml") {
        return PackageManager::Pnpm;
    }
    if has_file_in(ctx, dir, "bunfig.toml") {
        return PackageManager::Bun;
    }

    // Inherit from the nearest ancestor workspace root, if any.
    if let Some(inherited) = inherit_from_workspace_root(ctx, dir) {
        return inherited;
    }

    PackageManager::Npm
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

fn detect_package_manager_skip_inherit(
    ctx: &WorkspaceContext,
    dir: &Path,
    package_json_path: &Path,
) -> PackageManager {
    if let Ok(pj) = package_json::load(ctx, package_json_path) {
        if let Some(hint) = pj.package_manager_hint() {
            return hint.manager;
        }
    }
    if has_file_in(ctx, dir, "pnpm-lock.yaml") {
        return PackageManager::Pnpm;
    }
    if has_file_in(ctx, dir, "yarn.lock") {
        return PackageManager::Yarn;
    }
    if has_file_in(ctx, dir, "package-lock.json") || has_file_in(ctx, dir, "npm-shrinkwrap.json") {
        return PackageManager::Npm;
    }
    if has_file_in(ctx, dir, "bun.lock") || has_file_in(ctx, dir, "bun.lockb") {
        return PackageManager::Bun;
    }
    if has_file_in(ctx, dir, ".yarnrc.yml") || has_file_in(ctx, dir, ".yarnrc") {
        return PackageManager::Yarn;
    }
    if has_file_in(ctx, dir, "pnpm-workspace.yaml") {
        return PackageManager::Pnpm;
    }
    if has_file_in(ctx, dir, "bunfig.toml") {
        return PackageManager::Bun;
    }
    PackageManager::Npm
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

fn is_proper_ancestor(ancestor: &Path, descendant: &Path) -> bool {
    if ancestor == Path::new(".") {
        return descendant != Path::new(".");
    }
    descendant.starts_with(ancestor) && descendant != ancestor
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
/// workspaces, holds a lockfile for the same package manager, AND the target
/// directory is matched by the workspace's member globs.
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
        if lockfile_in_dir(ctx, &root_dir, manager).is_empty() {
            continue;
        }
        // The root has a lockfile: only consider `dir` covered if it is
        // actually matched by the workspace member globs.
        if is_workspace_member(ctx, &root_dir, pj, dir) {
            return true;
        }
    }
    false
}

/// Returns the workspace package globs declared by a workspace root, in
/// declaration order (so include/exclude `!`-negation can be applied in order
/// by [`is_workspace_member`]).
///
/// For pnpm the authoritative source is `pnpm-workspace.yaml` `packages:`; for
/// all managers the `package.json` `workspaces` field (array or object form) is
/// also consulted. Globs from `pnpm-workspace.yaml` are listed before those
/// from `package.json`. An empty result means no member globs were declared.
fn workspace_globs(
    ctx: &WorkspaceContext,
    root_dir: &Path,
    package_json_path: &Path,
) -> Vec<String> {
    let mut globs: Vec<String> = Vec::new();

    // pnpm-workspace.yaml is the authoritative config for pnpm workspaces.
    let ws_yaml_path = project_join(root_dir, "pnpm-workspace.yaml");
    if ctx.contains(&ws_yaml_path) {
        if let Ok(ws) = pnpm::load_workspace(ctx, &ws_yaml_path) {
            globs.extend(ws.packages);
        }
    }

    // package.json `workspaces` (array or object { packages: [...] }).
    if let Ok(pj) = package_json::load(ctx, package_json_path) {
        globs.extend(pj.workspaces.packages().iter().cloned());
    }

    globs
}

/// Returns `true` when `dir` is a workspace member declared at `root_dir`.
///
/// Globs are relative to the workspace root and use `/`-separated paths, and
/// are evaluated with ordered include/exclude semantics: patterns apply in
/// declaration order, and a `!`-prefixed pattern excludes a path that an
/// earlier pattern included (matching the behaviour of npm/Yarn `workspaces`
/// and pnpm's `pnpm-workspace.yaml` `packages`). A path is a member only if,
/// after applying every pattern in order, it ends up included.
///
/// When no (positive) globs are declared, child packages are NOT members:
/// pnpm with an empty/omitted `packages` includes only the root, and an
/// empty/missing npm/Yarn `workspaces` array likewise declares no members.
fn is_workspace_member(
    ctx: &WorkspaceContext,
    root_dir: &Path,
    package_json_path: &Path,
    dir: &Path,
) -> bool {
    let globs = workspace_globs(ctx, root_dir, package_json_path);
    if globs.is_empty() {
        // No globs declared: only the root is a member, never its children.
        return false;
    }

    // Compute the path of `dir` relative to `root_dir`, normalised to `/`.
    let rel = if root_dir == Path::new(".") {
        dir.to_owned()
    } else {
        dir.strip_prefix(root_dir).unwrap_or(dir).to_owned()
    };
    let rel_str = rel.to_string_lossy().replace('\\', "/");

    // Apply include/exclude patterns in order: a positive glob marks the path
    // included, a `!`-prefixed glob un-includes a previously-included path.
    let mut included = false;
    for g in &globs {
        let (pattern, negated) = match g.strip_prefix('!') {
            Some(rest) => (rest, true),
            None => (g.as_str(), false),
        };
        let matches = globset::Glob::new(pattern)
            .map(|glob| glob.compile_matcher().is_match(&rel_str))
            .unwrap_or(false);
        if matches {
            included = !negated;
        }
    }
    included
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::ecosystems::Analyzer;
    use crate::filesystem::{scan, ScanOptions};
    use tempfile::TempDir;

    const PKG_DEPS: &str = r#"{ "name": "pkg", "dependencies": { "left-pad": "^1" } }"#;

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
        let analyzer = JavaScriptAnalyzer;
        analyzer
            .detect(&ctx)
            .iter()
            .map(|p| analyzer.facts(p, &ctx).unwrap())
            .collect()
    }

    fn facts_for_dir<'a>(facts: &'a [ProjectFacts], rel: &str) -> Option<&'a ProjectFacts> {
        facts
            .iter()
            .find(|f| f.project.root == std::path::Path::new(rel))
    }

    // --- workspace glob membership -------------------------------------------

    /// npm workspace: member matched by glob is covered; non-member is not.
    #[test]
    fn npm_workspace_member_is_covered_non_member_is_not() {
        let dir = ws(&[
            (
                "package.json",
                r#"{ "name": "root", "private": true, "workspaces": ["packages/*"] }"#,
            ),
            ("package-lock.json", r#"{ "lockfileVersion": 3 }"#),
            ("packages/app/package.json", PKG_DEPS),
            ("examples/standalone/package.json", PKG_DEPS),
        ]);
        let facts = facts_for(&dir);

        let member = facts_for_dir(&facts, "packages/app").expect("packages/app not detected");
        assert!(
            member.covered_by_workspace_lockfile,
            "packages/app should be covered by root lockfile"
        );

        let non_member =
            facts_for_dir(&facts, "examples/standalone").expect("examples/standalone not detected");
        assert!(
            !non_member.covered_by_workspace_lockfile,
            "examples/standalone is not in workspaces glob and must not be covered"
        );
    }

    /// Yarn workspace (object form `{ packages: [...] }`): member covered, non-member flagged.
    #[test]
    fn yarn_workspace_object_form_member_covered_non_member_not() {
        let dir = ws(&[
            (
                "package.json",
                r#"{ "name": "root", "private": true, "workspaces": { "packages": ["apps/*"] } }"#,
            ),
            ("yarn.lock", ""),
            ("apps/web/package.json", PKG_DEPS),
            ("tools/cli/package.json", PKG_DEPS),
        ]);
        let facts = facts_for(&dir);

        let member = facts_for_dir(&facts, "apps/web").expect("apps/web not detected");
        assert!(
            member.covered_by_workspace_lockfile,
            "apps/web should be covered by yarn root lockfile"
        );

        let non_member = facts_for_dir(&facts, "tools/cli").expect("tools/cli not detected");
        assert!(
            !non_member.covered_by_workspace_lockfile,
            "tools/cli is not in apps/* glob and must not be covered"
        );
    }

    /// pnpm workspace: globs from `pnpm-workspace.yaml` are used for membership.
    #[test]
    fn pnpm_workspace_yaml_member_covered_non_member_not() {
        let dir = ws(&[
            (
                "package.json",
                r#"{ "name": "root", "private": true, "packageManager": "pnpm@9" }"#,
            ),
            ("pnpm-workspace.yaml", "packages:\n  - \"packages/*\"\n"),
            ("pnpm-lock.yaml", "lockfileVersion: 9\n"),
            ("packages/lib/package.json", PKG_DEPS),
            ("examples/demo/package.json", PKG_DEPS),
        ]);
        let facts = facts_for(&dir);

        let member = facts_for_dir(&facts, "packages/lib").expect("packages/lib not detected");
        assert!(
            member.covered_by_workspace_lockfile,
            "packages/lib should be covered by pnpm root lockfile"
        );

        let non_member =
            facts_for_dir(&facts, "examples/demo").expect("examples/demo not detected");
        assert!(
            !non_member.covered_by_workspace_lockfile,
            "examples/demo is not in packages/* glob and must not be covered"
        );
    }

    /// pnpm workspace with a `!`-negated glob: an excluded package is NOT
    /// covered (SD001 fires) even though an earlier include matched it.
    #[test]
    fn pnpm_workspace_negated_glob_excludes_package() {
        let dir = ws(&[
            (
                "package.json",
                r#"{ "name": "root", "private": true, "packageManager": "pnpm@9" }"#,
            ),
            (
                "pnpm-workspace.yaml",
                "packages:\n  - \"packages/*\"\n  - \"!packages/excluded\"\n",
            ),
            ("pnpm-lock.yaml", "lockfileVersion: 9\n"),
            ("packages/included/package.json", PKG_DEPS),
            ("packages/excluded/package.json", PKG_DEPS),
        ]);
        let facts = facts_for(&dir);

        let included =
            facts_for_dir(&facts, "packages/included").expect("packages/included not detected");
        assert!(
            included.covered_by_workspace_lockfile,
            "packages/included matches packages/* and should be covered"
        );

        let excluded =
            facts_for_dir(&facts, "packages/excluded").expect("packages/excluded not detected");
        assert!(
            !excluded.covered_by_workspace_lockfile,
            "packages/excluded is negated by !packages/excluded and must not be covered"
        );
    }

    /// pnpm workspace whose `pnpm-workspace.yaml` omits `packages`: only the
    /// root is a member, so a child package is NOT covered (SD001 fires).
    #[test]
    fn pnpm_workspace_empty_packages_excludes_children() {
        let dir = ws(&[
            (
                "package.json",
                r#"{ "name": "root", "private": true, "packageManager": "pnpm@9" }"#,
            ),
            // No `packages:` key at all (only an unrelated setting present).
            ("pnpm-workspace.yaml", "dangerouslyAllowAllBuilds: false\n"),
            ("pnpm-lock.yaml", "lockfileVersion: 9\n"),
            ("packages/lib/package.json", PKG_DEPS),
        ]);
        let facts = facts_for(&dir);

        let child = facts_for_dir(&facts, "packages/lib").expect("packages/lib not detected");
        assert!(
            !child.covered_by_workspace_lockfile,
            "with no `packages` globs only the root is a member; the child must not be covered"
        );
    }

    /// Bun workspace: member matched by glob is covered; non-member is not.
    #[test]
    fn bun_workspace_member_covered_non_member_not() {
        let dir = ws(&[
            (
                "package.json",
                r#"{ "name": "root", "private": true, "workspaces": ["pkgs/*"], "packageManager": "bun@1.2.0" }"#,
            ),
            ("bun.lock", ""),
            ("pkgs/server/package.json", PKG_DEPS),
            ("extras/standalone/package.json", PKG_DEPS),
        ]);
        let facts = facts_for(&dir);

        let member = facts_for_dir(&facts, "pkgs/server").expect("pkgs/server not detected");
        assert!(
            member.covered_by_workspace_lockfile,
            "pkgs/server should be covered by bun root lockfile"
        );

        let non_member =
            facts_for_dir(&facts, "extras/standalone").expect("extras/standalone not detected");
        assert!(
            !non_member.covered_by_workspace_lockfile,
            "extras/standalone is not in pkgs/* glob and must not be covered"
        );
    }
}
