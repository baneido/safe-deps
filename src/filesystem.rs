//! Workspace scanning with the `ignore` crate.
//!
//! Respects `.gitignore` by default and excludes heavy generated directories.
//! Dotfiles such as `.npmrc` and `.github/workflows` are included because they
//! carry security-relevant configuration.

use std::path::{Path, PathBuf};

use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;

use crate::config::Config;

/// Directories always excluded to avoid walking generated/dependency trees.
const DEFAULT_EXCLUDE_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "target",
    "vendor",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
];

/// Options controlling workspace traversal.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    pub no_gitignore: bool,
    pub includes: Vec<String>,
    pub excludes: Vec<String>,
}

/// A file discovered in the workspace.
#[derive(Debug, Clone)]
pub struct WorkspaceFile {
    pub relative: PathBuf,
    pub absolute: PathBuf,
}

/// The scanned workspace context handed to analyzers and rules.
#[derive(Debug, Clone)]
pub struct WorkspaceContext {
    pub root: PathBuf,
    pub files: Vec<FileEntry>,
    pub config: Config,
}

/// A file entry in the workspace, with content loaded lazily.
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub relative: PathBuf,
    pub absolute: PathBuf,
}

impl FileEntry {
    pub fn name(&self) -> std::ffi::OsString {
        self.relative.file_name().unwrap_or_default().to_os_string()
    }
}

/// Reads a file's contents as UTF-8, returning a friendly error on failure.
pub fn read_text(ctx: &WorkspaceContext, relative: &Path) -> Result<String, std::io::Error> {
    let abs = ctx.root.join(relative);
    std::fs::read_to_string(&abs)
}

/// Joins a project-root directory with a child file name, yielding a path in the
/// same normalized form as the entries in [`WorkspaceContext::files`].
///
/// A project located at the workspace root has `dir == "."`. Plain
/// `Path::join` would then produce `./name`, which never compares equal to the
/// normalized `name` stored in `files`. This helper drops the leading `.` so
/// root-level lookups and constructed file paths match correctly.
pub fn project_join(dir: &Path, name: &str) -> PathBuf {
    if dir.as_os_str().is_empty() || dir == Path::new(".") {
        PathBuf::from(name)
    } else {
        dir.join(name)
    }
}

/// Whether the workspace contains a file at the given relative path.
pub fn has_file(ctx: &WorkspaceContext, relative: &str) -> bool {
    ctx.files.iter().any(|f| f.relative == Path::new(relative))
}

/// Whether the workspace contains any file whose relative path ends with the
/// given trailing components (e.g. `["src", "package.json"]`).
pub fn has_file_suffix(ctx: &WorkspaceContext, suffix: &[&str]) -> bool {
    ctx.files
        .iter()
        .any(|f| ends_with_components(&f.relative, suffix))
}

/// Finds all files whose final path component equals `name` and whose parent
/// dir is `dir_relative`. Used to locate manifests at a project root.
pub fn files_named_in_dir(ctx: &WorkspaceContext, dir_relative: &Path, name: &str) -> Vec<PathBuf> {
    ctx.files
        .iter()
        .filter(|f| f.relative.parent() == Some(dir_relative))
        .filter(|f| f.relative.file_name().and_then(|n| n.to_str()) == Some(name))
        .map(|f| f.relative.clone())
        .collect()
}

/// Returns the relative paths of all files with the given basename anywhere in
/// the workspace.
pub fn files_named(ctx: &WorkspaceContext, name: &str) -> Vec<PathBuf> {
    ctx.files
        .iter()
        .filter(|f| f.relative.file_name().and_then(|n| n.to_str()) == Some(name))
        .map(|f| f.relative.clone())
        .collect()
}

/// Scans the workspace root and builds a `WorkspaceContext`.
pub fn scan(
    root: &Path,
    config: Config,
    options: &ScanOptions,
) -> Result<WorkspaceContext, FsError> {
    if !root.is_dir() {
        return Err(FsError::NotADirectory(root.to_path_buf()));
    }

    let exclude_set = build_globset(
        DEFAULT_EXCLUDE_DIRS
            .iter()
            .map(|d| format!("/{d}/**"))
            .chain(options.excludes.iter().cloned())
            .chain(config.workspace.exclude.iter().cloned()),
    )?;
    let include_set = build_globset(
        options
            .includes
            .iter()
            .cloned()
            .chain(config.workspace.include.iter().cloned()),
    )?;

    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false)
        .ignore(true)
        .git_ignore(!options.no_gitignore)
        .git_global(false)
        .git_exclude(!options.no_gitignore)
        .parents(true);

    let mut files = Vec::new();

    for result in builder.build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| FsError::Internal("could not strip root prefix".into()))?
            .to_path_buf();
        let normalized = normalize(&relative);

        if is_under_default_exclude(&normalized) {
            continue;
        }
        let path_str = normalized.to_string_lossy();
        let excluded = exclude_set.is_match(&*path_str);
        let included = !include_set.is_empty() && include_set.is_match(&*path_str);
        if excluded && !included {
            continue;
        }

        files.push(FileEntry {
            relative: normalized,
            absolute: entry.path().to_path_buf(),
        });
    }

    files.sort_by(|a, b| a.relative.cmp(&b.relative));
    files.dedup_by(|a, b| a.relative == b.relative);

    Ok(WorkspaceContext {
        root: root.to_path_buf(),
        files,
        config,
    })
}

fn is_under_default_exclude(relative: &Path) -> bool {
    for component in relative.components() {
        if let std::path::Component::Normal(name) = component {
            if DEFAULT_EXCLUDE_DIRS.contains(&name.to_string_lossy().as_ref()) {
                return true;
            }
        }
    }
    false
}

fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        if let std::path::Component::Normal(name) = component {
            out.push(name);
        }
    }
    out
}

fn ends_with_components(path: &Path, suffix: &[&str]) -> bool {
    let components: Vec<String> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(n) => Some(n.to_string_lossy().to_string()),
            _ => None,
        })
        .collect();
    if components.len() < suffix.len() {
        return false;
    }
    let tail = &components[components.len() - suffix.len()..];
    tail.iter().zip(suffix.iter()).all(|(a, b)| a == b)
}

fn build_globset(patterns: impl Iterator<Item = String>) -> Result<GlobSet, FsError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = Glob::new(&pattern).map_err(|err| FsError::Glob {
            pattern,
            message: err.to_string(),
        })?;
        builder.add(glob);
    }
    builder.build().map_err(|err| FsError::Glob {
        pattern: "<set>".to_string(),
        message: err.to_string(),
    })
}

/// Errors produced while scanning.
#[derive(Debug, thiserror::Error)]
pub enum FsError {
    #[error("workspace root is not a directory: {0}")]
    NotADirectory(PathBuf),
    #[error("invalid glob pattern {pattern:?}: {message}")]
    Glob { pattern: String, message: String },
    #[error("internal filesystem error: {0}")]
    Internal(String),
}
