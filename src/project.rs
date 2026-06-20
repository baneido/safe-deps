//! Project kind inference and monorepo relationship helpers.
//!
//! `ProjectKind` is inferred conservatively. Without strong evidence or
//! configured roots, projects stay `Unknown` and avoid high-severity findings
//! for rules where library/application policy differs.

use std::path::Path;

use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::ecosystems::{Project, ProjectKind};
use crate::filesystem::WorkspaceContext;
use crate::rule::Policy;

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

/// Infers a kind from a single project root and policy.
pub fn infer_kind(project_root: &Path, workspace_root: &Path, policy: &Policy) -> ProjectKind {
    let relative = project_root
        .strip_prefix(workspace_root)
        .unwrap_or(project_root);
    let rel_str = relative.to_string_lossy();
    if let Some(set) = build_root_set(&policy.application_roots) {
        if set.is_match(&*rel_str) {
            return ProjectKind::Application;
        }
    }
    if let Some(set) = build_root_set(&policy.library_roots) {
        if set.is_match(&*rel_str) {
            return ProjectKind::Library;
        }
    }
    ProjectKind::Unknown
}

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
