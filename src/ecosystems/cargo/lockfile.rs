//! Cargo lockfile (`Cargo.lock`) presence. Cargo locks are not parsed; only
//! their presence matters to SD001.

use std::path::Path;

use crate::ecosystems::{contains_file, FileFact};
use crate::filesystem::{project_join, WorkspaceContext};

/// The committed `Cargo.lock` for a crate directory, if any.
pub(super) fn lockfiles(ctx: &WorkspaceContext, dir: &Path) -> Vec<FileFact> {
    let lock_path = project_join(dir, "Cargo.lock");
    if contains_file(ctx, &lock_path) {
        vec![FileFact {
            relative: lock_path,
        }]
    } else {
        Vec::new()
    }
}
