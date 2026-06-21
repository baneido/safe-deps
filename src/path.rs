//! Shared path rendering helpers.

use std::path::Path;

/// Renders a path with `/` separators so output is stable across platforms.
pub(crate) fn normalize_separators(path: &Path) -> String {
    path.to_string_lossy()
        .replace([std::path::MAIN_SEPARATOR, '\\'], "/")
}
