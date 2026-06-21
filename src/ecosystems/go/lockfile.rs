//! `go.sum` presence — Go's integrity/reproducibility record. Not parsed; only
//! its presence matters to SD001.

use std::path::Path;

use crate::ecosystems::{contains_file, FileFact};
use crate::filesystem::{project_join, WorkspaceContext};

/// The committed `go.sum` for a module directory, if any.
pub(super) fn lockfiles(ctx: &WorkspaceContext, dir: &Path) -> Vec<FileFact> {
    let sum_path = project_join(dir, "go.sum");
    if contains_file(ctx, &sum_path) {
        vec![FileFact { relative: sum_path }]
    } else {
        Vec::new()
    }
}
