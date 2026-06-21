//! Project kind inference and monorepo relationship helpers.
//!
//! `ProjectKind` is inferred conservatively. Without strong evidence or
//! configured roots, projects stay `Unknown` and avoid high-severity findings
//! for rules where library/application policy differs.

use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::ecosystems::{Project, ProjectKind};
use crate::filesystem::WorkspaceContext;

/// Refines the `ProjectKind` of each project using configured roots. Projects
/// already classified by an analyzer are left unchanged.
pub fn refine_kinds(projects: &mut [Project], ctx: &WorkspaceContext) {
    let app_set = build_root_set(&ctx.config.policy.application_roots);
    let lib_set = build_root_set(&ctx.config.policy.library_roots);
    for project in projects.iter_mut() {
        if project.kind != ProjectKind::Unknown {
            continue;
        }
        let relative = project
            .root
            .strip_prefix(&ctx.root)
            .unwrap_or(&project.root);
        let rel_str = relative.to_string_lossy();
        if app_set.as_ref().is_some_and(|s| s.is_match(&*rel_str)) {
            project.kind = ProjectKind::Application;
        } else if lib_set.as_ref().is_some_and(|s| s.is_match(&*rel_str)) {
            project.kind = ProjectKind::Library;
        }
    }
}

/// Builds a glob set from configured root patterns, or `None` when none are
/// configured. Invalid globs are rejected earlier by `config::validate`, so
/// reaching `Glob::new(...).ok()?` with a bad pattern is not expected.
fn build_root_set(patterns: &[String]) -> Option<GlobSet> {
    if patterns.is_empty() {
        return None;
    }
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        let glob = Glob::new(p).ok()?;
        builder.add(glob);
    }
    builder.build().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::ecosystems::{Ecosystem, PackageManager, Project};
    use crate::filesystem::{scan, ScanOptions};
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Builds a real `WorkspaceContext` (so `ctx.root` is set) carrying the given
    /// configured roots. The TempDir is returned to keep it alive for the test.
    fn ctx_with_roots(app: &[&str], lib: &[&str]) -> (TempDir, WorkspaceContext) {
        let dir = TempDir::new().unwrap();
        let mut config = Config::default();
        config.policy.application_roots = app.iter().map(|s| s.to_string()).collect();
        config.policy.library_roots = lib.iter().map(|s| s.to_string()).collect();
        let ctx = scan(dir.path(), config, &ScanOptions::default()).unwrap();
        (dir, ctx)
    }

    fn project(root: PathBuf, kind: ProjectKind) -> Project {
        Project {
            root,
            ecosystem: Ecosystem::JavaScript,
            package_manager: PackageManager::Npm,
            kind,
        }
    }

    #[test]
    fn classifies_unknown_project_by_application_root() {
        let (_d, ctx) = ctx_with_roots(&["apps/*"], &[]);
        let mut projects = vec![project(ctx.root.join("apps/web"), ProjectKind::Unknown)];
        refine_kinds(&mut projects, &ctx);
        assert_eq!(projects[0].kind, ProjectKind::Application);
    }

    #[test]
    fn classifies_unknown_project_by_library_root() {
        let (_d, ctx) = ctx_with_roots(&[], &["libs/*"]);
        let mut projects = vec![project(ctx.root.join("libs/core"), ProjectKind::Unknown)];
        refine_kinds(&mut projects, &ctx);
        assert_eq!(projects[0].kind, ProjectKind::Library);
    }

    #[test]
    fn unmatched_project_stays_unknown() {
        let (_d, ctx) = ctx_with_roots(&["apps/*"], &["libs/*"]);
        let mut projects = vec![project(ctx.root.join("services/api"), ProjectKind::Unknown)];
        refine_kinds(&mut projects, &ctx);
        assert_eq!(projects[0].kind, ProjectKind::Unknown);
    }

    #[test]
    fn no_configured_roots_keeps_unknown() {
        let (_d, ctx) = ctx_with_roots(&[], &[]);
        let mut projects = vec![project(ctx.root.join("anything"), ProjectKind::Unknown)];
        refine_kinds(&mut projects, &ctx);
        assert_eq!(projects[0].kind, ProjectKind::Unknown);
    }

    #[test]
    fn already_classified_project_is_left_unchanged() {
        // A project an analyzer already classified must not be re-typed even when
        // its path matches a configured root.
        let (_d, ctx) = ctx_with_roots(&["apps/*"], &[]);
        let mut projects = vec![
            project(ctx.root.join("apps/web"), ProjectKind::Library),
            project(ctx.root.join("apps/cli"), ProjectKind::ToolingOnly),
        ];
        refine_kinds(&mut projects, &ctx);
        assert_eq!(projects[0].kind, ProjectKind::Library);
        assert_eq!(projects[1].kind, ProjectKind::ToolingOnly);
    }

    #[test]
    fn application_root_takes_precedence_when_both_match() {
        // The same path is in both root sets; application is checked first.
        let (_d, ctx) = ctx_with_roots(&["pkg/*"], &["pkg/*"]);
        let mut projects = vec![project(ctx.root.join("pkg/thing"), ProjectKind::Unknown)];
        refine_kinds(&mut projects, &ctx);
        assert_eq!(projects[0].kind, ProjectKind::Application);
    }
}
