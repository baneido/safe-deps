//! Workspace scanning with the `ignore` crate.
//!
//! Respects `.gitignore` by default and excludes heavy generated directories.
//! Dotfiles such as `.npmrc` and `.github/workflows` are included because they
//! carry security-relevant configuration.

use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;

use crate::config::Config;
use crate::diagnostics::Diagnostic;

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
    /// Warning diagnostics for paths the directory walk could not traverse
    /// (permission denied, broken symlink, …). Surfaced so a coverage gap is
    /// not a silent miss; the analysis engine counts these as parse failures so
    /// `--strict-parser-errors` can escalate the run.
    pub scan_diagnostics: Vec<Diagnostic>,

    // Indices built once from `files` so the per-analyzer lookups below are not
    // O(files). The values are indices into `files`, in sorted (file) order, so
    // lookup results keep the same deterministic ordering as a linear scan.
    path_set: HashSet<PathBuf>,
    by_name: HashMap<OsString, Vec<u32>>,
    by_dir: HashMap<PathBuf, Vec<u32>>,
}

impl WorkspaceContext {
    /// Builds the context and its lookup indices from the sorted `files` list.
    fn new(
        root: PathBuf,
        files: Vec<FileEntry>,
        config: Config,
        scan_diagnostics: Vec<Diagnostic>,
    ) -> Self {
        let mut path_set = HashSet::with_capacity(files.len());
        let mut by_name: HashMap<OsString, Vec<u32>> = HashMap::new();
        let mut by_dir: HashMap<PathBuf, Vec<u32>> = HashMap::new();
        for (i, f) in files.iter().enumerate() {
            path_set.insert(f.relative.clone());
            if let Some(name) = f.relative.file_name() {
                by_name
                    .entry(name.to_os_string())
                    .or_default()
                    .push(i as u32);
            }
            if let Some(parent) = f.relative.parent() {
                by_dir
                    .entry(parent.to_path_buf())
                    .or_default()
                    .push(i as u32);
            }
        }
        Self {
            root,
            files,
            config,
            scan_diagnostics,
            path_set,
            by_name,
            by_dir,
        }
    }

    /// Whether the workspace contains a file at the given relative path. O(1).
    pub fn contains(&self, relative: &Path) -> bool {
        self.path_set.contains(relative)
    }

    /// The files (in sorted order) whose basename equals `name`.
    fn entries_named(&self, name: &str) -> impl Iterator<Item = &FileEntry> {
        self.by_name
            .get(OsStr::new(name))
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .map(move |&i| &self.files[i as usize])
    }

    /// The files (in sorted order) whose parent directory is `dir`.
    fn entries_in_dir(&self, dir: &Path) -> impl Iterator<Item = &FileEntry> {
        self.by_dir
            .get(dir)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .map(move |&i| &self.files[i as usize])
    }
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

/// Whether the workspace contains a file at the given relative path. O(1).
pub fn has_file(ctx: &WorkspaceContext, relative: &str) -> bool {
    ctx.contains(Path::new(relative))
}

/// Whether the workspace contains any file whose relative path ends with the
/// given trailing components (e.g. `["src", "package.json"]`). Indexed on the
/// final component, so only same-basename files are checked. An empty `suffix`
/// returns `false` (there is no component to anchor on).
pub fn has_file_suffix(ctx: &WorkspaceContext, suffix: &[&str]) -> bool {
    let Some(last) = suffix.last() else {
        return false;
    };
    ctx.entries_named(last)
        .any(|f| ends_with_components(&f.relative, suffix))
}

/// Finds all files whose final path component equals `name` and whose parent
/// dir is `dir_relative`. Used to locate manifests at a project root.
pub fn files_named_in_dir(ctx: &WorkspaceContext, dir_relative: &Path, name: &str) -> Vec<PathBuf> {
    ctx.entries_in_dir(dir_relative)
        .filter(|f| f.relative.file_name() == Some(OsStr::new(name)))
        .map(|f| f.relative.clone())
        .collect()
}

/// Returns the relative paths of all files with the given basename anywhere in
/// the workspace.
pub fn files_named(ctx: &WorkspaceContext, name: &str) -> Vec<PathBuf> {
    ctx.entries_named(name)
        .map(|f| f.relative.clone())
        .collect()
}

/// Iterates the relative paths of files whose parent directory is `dir`
/// (in sorted order). O(matches) via the workspace dir index.
pub fn files_in_dir<'a>(
    ctx: &'a WorkspaceContext,
    dir: &Path,
) -> impl Iterator<Item = &'a Path> + 'a {
    ctx.entries_in_dir(dir).map(|f| f.relative.as_path())
}

/// Scans the workspace root and builds a `WorkspaceContext`.
pub fn scan(
    root: &Path,
    config: Config,
    options: &ScanOptions,
) -> Result<WorkspaceContext, FsError> {
    // Use an explicit stat so we can distinguish three cases:
    //   1. path exists and is a directory          → proceed
    //   2. path exists but is not a directory, or
    //      path does not exist (NotFound)          → user input error (exit 2)
    //   3. metadata call fails for any other reason
    //      (e.g. PermissionDenied on a non-searchable parent) → internal/operational
    //      error (exit 3); not the user's fault.
    match std::fs::metadata(root) {
        Ok(meta) if meta.is_dir() => {
            // Valid directory — fall through to the walk below.
        }
        Ok(_) => {
            // Path exists but is a file, symlink to a file, etc.
            return Err(FsError::NotADirectory(root.to_path_buf()));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Path does not exist at all — also a user input error but
            // semantically distinct from "exists but is not a directory".
            return Err(FsError::PathNotFound(root.to_path_buf()));
        }
        Err(e) => {
            // Permission denied, I/O error, or any other OS-level failure
            // while stat-ing the root itself. This is an operational problem,
            // not a bad argument — surface it as an internal error (exit 3).
            return Err(FsError::Internal(format!(
                "could not stat workspace root {}: {}",
                root.display(),
                e
            )));
        }
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
    let mut scan_diagnostics = Vec::new();

    for result in builder.build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(err) => {
                // A path the walk could not traverse (permission denied, broken
                // symlink, …). Record it instead of skipping silently so the
                // coverage gap is visible. `ignore::Error`'s Display carries the
                // offending path for IO errors; anchor the location at the root.
                scan_diagnostics.push(Diagnostic::warn_at(
                    format!("could not scan a path under the workspace: {err}"),
                    root.to_path_buf(),
                ));
                continue;
            }
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

    // Walk order is filesystem-dependent; sort so the surfaced diagnostics are
    // deterministic across runs and platforms (the failing path is carried in
    // the message). Matches how every other diagnostic source is ordered.
    scan_diagnostics.sort_by(|a, b| a.message.cmp(&b.message));

    Ok(WorkspaceContext::new(
        root.to_path_buf(),
        files,
        config,
        scan_diagnostics,
    ))
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
    #[error("workspace root does not exist: {0}")]
    PathNotFound(PathBuf),
    #[error("invalid glob pattern {pattern:?}: {message}")]
    Glob { pattern: String, message: String },
    #[error("internal filesystem error: {0}")]
    Internal(String),
}

impl FsError {
    /// Returns `true` for errors that originate from user-supplied input
    /// (a path that does not exist or is not a directory), so callers can
    /// map them to a usage error (exit 2) rather than an internal error
    /// (exit 3).
    pub fn is_user_input_error(&self) -> bool {
        matches!(self, FsError::NotADirectory(_) | FsError::PathNotFound(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    #[cfg(unix)]
    fn walk_errors_are_recorded_as_diagnostics() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("inner.txt"), "x").unwrap();
        // Remove read/execute so the walk cannot enumerate the directory.
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

        let ctx = scan(dir.path(), Config::default(), &ScanOptions::default()).unwrap();

        // Restore permissions so the TempDir can be cleaned up.
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Running as root bypasses permission checks; only assert when the OS
        // actually denied us (the realistic CI/developer case).
        if ctx.scan_diagnostics.is_empty() {
            eprintln!("skipping: directory permissions were not enforced (running as root?)");
            return;
        }
        assert!(ctx
            .scan_diagnostics
            .iter()
            .any(|d| d.message.contains("could not scan")));
        // The reachable file is still scanned despite the locked sibling.
        assert!(ctx
            .files
            .iter()
            .any(|f| f.relative == Path::new("package.json")));
    }

    #[test]
    fn clean_workspace_has_no_scan_diagnostics() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();
        let ctx = scan(dir.path(), Config::default(), &ScanOptions::default()).unwrap();
        assert!(ctx.scan_diagnostics.is_empty());
    }

    fn ctx_with(files: &[&str]) -> WorkspaceContext {
        let dir = TempDir::new().unwrap();
        for rel in files {
            let p = dir.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "{}").unwrap();
        }
        // Keep the TempDir alive for the scan, then leak it (test process exits).
        let ctx = scan(dir.path(), Config::default(), &ScanOptions::default()).unwrap();
        std::mem::forget(dir);
        ctx
    }

    #[test]
    fn index_lookups_match_a_linear_scan() {
        let ctx = ctx_with(&[
            "package.json",
            "packages/a/package.json",
            "packages/b/package.json",
            "src/bin/tool.rs",
            "src/main.rs",
        ]);

        // contains / has_file
        assert!(ctx.contains(Path::new("packages/a/package.json")));
        assert!(!ctx.contains(Path::new("nope.json")));
        assert!(has_file(&ctx, "src/main.rs"));

        // files_named — all basenames, in sorted order.
        assert_eq!(
            files_named(&ctx, "package.json"),
            vec![
                PathBuf::from("package.json"),
                PathBuf::from("packages/a/package.json"),
                PathBuf::from("packages/b/package.json"),
            ]
        );

        // files_named_in_dir — basename within one directory.
        assert_eq!(
            files_named_in_dir(&ctx, Path::new("packages/a"), "package.json"),
            vec![PathBuf::from("packages/a/package.json")]
        );
        assert!(files_named_in_dir(&ctx, Path::new("packages/a"), "Cargo.toml").is_empty());

        // files_in_dir — any file in a directory.
        let bins: Vec<&Path> = files_in_dir(&ctx, Path::new("src/bin")).collect();
        assert_eq!(bins, vec![Path::new("src/bin/tool.rs")]);

        // has_file_suffix — trailing components.
        assert!(has_file_suffix(&ctx, &["packages", "a", "package.json"]));
        assert!(has_file_suffix(&ctx, &["bin", "tool.rs"]));
        assert!(!has_file_suffix(&ctx, &["a", "main.rs"]));
        assert!(!has_file_suffix(&ctx, &[]));
    }

    #[test]
    fn scan_nonexistent_path_is_user_input_error() {
        // Use a TempDir to produce a guaranteed-missing child path: we create
        // the parent, reference a child that is never created, then drop the
        // parent.  This avoids hardcoding a /tmp/... path that could
        // coincidentally exist on some machines.
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("this-child-is-never-created");
        drop(dir); // parent is now gone, so `missing` definitely does not exist

        let err = scan(&missing, Config::default(), &ScanOptions::default()).unwrap_err();
        assert!(
            err.is_user_input_error(),
            "expected user input error for non-existent path, got: {err}"
        );
        assert!(
            matches!(err, FsError::PathNotFound(_)),
            "expected PathNotFound variant, got: {err}"
        );
    }

    #[test]
    fn scan_file_path_is_user_input_error() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("not-a-dir.txt");
        std::fs::write(&file, "contents").unwrap();
        let err = scan(&file, Config::default(), &ScanOptions::default()).unwrap_err();
        assert!(
            err.is_user_input_error(),
            "expected user input error when path is a file, got: {err}"
        );
    }

    #[test]
    fn fserror_internal_is_not_user_input_error() {
        let err = FsError::Internal("something went wrong".into());
        assert!(!err.is_user_input_error());
    }

    #[test]
    fn fserror_glob_is_not_user_input_error() {
        let err = FsError::Glob {
            pattern: "[bad".into(),
            message: "invalid syntax".into(),
        };
        assert!(!err.is_user_input_error());
    }

    /// When the *parent* directory is non-searchable (mode 0o000), `metadata(root)`
    /// fails with `PermissionDenied`. That is an operational failure — not a bad
    /// argument — so `scan()` must return `FsError::Internal`, and
    /// `is_user_input_error()` must be `false` (→ exit 3, not exit 2).
    #[test]
    #[cfg(unix)]
    fn scan_non_searchable_parent_is_internal_error() {
        use std::os::unix::fs::PermissionsExt;

        let parent = TempDir::new().unwrap();
        // Create the child directory *before* locking the parent.
        let child = parent.path().join("workspace");
        std::fs::create_dir(&child).unwrap();

        // Remove all permissions on the parent so stat-ing `child` through it
        // requires search permission we no longer have.
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o000)).unwrap();

        let result = scan(&child, Config::default(), &ScanOptions::default());

        // Restore permissions before any assertion so TempDir can clean up even
        // if the test fails.
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

        // Running as root bypasses permission checks; skip the assertion in that case.
        let err = match result {
            Err(e) => e,
            Ok(_) => {
                eprintln!("skipping: permission check was not enforced (running as root?)");
                return;
            }
        };

        assert!(
            !err.is_user_input_error(),
            "PermissionDenied on parent should be an internal error (exit 3), not a \
             usage error (exit 2); got: {err}"
        );
        assert!(
            matches!(err, FsError::Internal(_)),
            "expected FsError::Internal for stat failure, got: {err}"
        );
    }
}
