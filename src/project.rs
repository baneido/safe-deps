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
