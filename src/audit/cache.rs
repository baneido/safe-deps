//! On-disk cache for audit results.
//!
//! Caching makes re-runs cheap and keeps request volume (and rate-limit
//! pressure) down: each package's advisories are stored under the cache
//! directory keyed by coordinate, with the fetch time so freshness can be
//! checked against a TTL. `audit --offline` reads the cache without any network.
//!
//! ## Cache-directory fallback
//!
//! When neither `$XDG_CACHE_HOME` nor `$HOME` is set (e.g. inside a minimal
//! container or a `sudo`-stripped environment), the cache falls back to
//! `std::env::temp_dir()/safe-deps/osv`.  Be aware of the caveats:
//!
//! - **Ownership**: the temp directory is typically world-writable; a different
//!   user or process could replace or delete cache files between runs.
//! - **Visibility**: on Linux `$TMPDIR` (or `/tmp`) is not namespaced per user,
//!   so cache entries might be visible to other local users.
//! - **Lifetime**: many systems clear `/tmp` on reboot or via a tmpwatch timer,
//!   so the cache may be shorter-lived than the configured TTL.
//!
//! For production use, ensure `$HOME` (or `$XDG_CACHE_HOME`) is set so the
//! cache lands in a user-private, persistent location.

use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::audit::{Advisory, PackageCoordinate};

/// A filesystem cache of per-coordinate advisory lists.
pub struct Cache {
    dir: PathBuf,
    ttl_secs: u64,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    fetched: u64,
    advisories: Vec<Advisory>,
}

impl Cache {
    pub fn new(dir: PathBuf, ttl_secs: u64) -> Self {
        Self { dir, ttl_secs }
    }

    /// The default cache directory: `$XDG_CACHE_HOME/safe-deps/osv` (or
    /// `$HOME/.cache/safe-deps/osv`), falling back to a temp dir.
    ///
    /// See the module-level documentation for caveats that apply when the
    /// temp-dir fallback is used (`$HOME` and `$XDG_CACHE_HOME` are both absent).
    pub fn default_dir() -> PathBuf {
        if let Some(base) = std::env::var_os("XDG_CACHE_HOME") {
            return PathBuf::from(base).join("safe-deps/osv");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".cache/safe-deps/osv");
        }
        std::env::temp_dir().join("safe-deps/osv")
    }

    fn path(&self, coord: &PackageCoordinate) -> PathBuf {
        self.dir.join(format!("{}.json", coord.cache_key()))
    }

    fn load(&self, coord: &PackageCoordinate) -> Option<Entry> {
        let text = std::fs::read_to_string(self.path(coord)).ok()?;
        // Corrupt or invalid JSON is treated as a cache miss — degrade safely
        // rather than propagating an error.
        serde_json::from_str(&text).ok()
    }

    /// Whether a usable cache entry exists for `coord` (regardless of
    /// freshness). Loads it rather than testing existence so a truncated or
    /// corrupt file counts as a miss, consistent with `get_any`/`get_fresh`.
    pub fn contains(&self, coord: &PackageCoordinate) -> bool {
        self.load(coord).is_some()
    }

    /// Returns cached advisories only if they are within the TTL. An entry
    /// stamped in the future (clock skew or a hand-edited cache) is treated as
    /// stale rather than perpetually fresh.
    pub fn get_fresh(&self, coord: &PackageCoordinate) -> Option<Vec<Advisory>> {
        let entry = self.load(coord)?;
        let now = now();
        if entry.fetched > now {
            return None;
        }
        ((now - entry.fetched) <= self.ttl_secs).then_some(entry.advisories)
    }

    /// Returns cached advisories regardless of age (used in offline mode).
    pub fn get_any(&self, coord: &PackageCoordinate) -> Option<Vec<Advisory>> {
        self.load(coord).map(|e| e.advisories)
    }

    /// Stores advisories for a coordinate atomically: write a freshly created,
    /// randomly named temp file in the same directory (via `tempfile`, which
    /// opens with `O_EXCL`), then atomically replace the target so concurrent
    /// readers never see a partial file and a re-`put` overwrites cleanly on
    /// every platform.
    ///
    /// Returns `Some(message)` if the directory could not be created or the
    /// write/persist failed; the caller should surface this as a diagnostic.
    /// The cache is best-effort — callers must not treat a `Some` return as
    /// fatal.
    pub fn put(&self, coord: &PackageCoordinate, advisories: &[Advisory]) -> Option<String> {
        if let Err(e) = std::fs::create_dir_all(&self.dir) {
            return Some(format!(
                "cache: could not create directory {}: {e}",
                self.dir.display()
            ));
        }
        let entry = Entry {
            fetched: now(),
            advisories: advisories.to_vec(),
        };
        let text = match serde_json::to_string(&entry) {
            Ok(t) => t,
            Err(e) => return Some(format!("cache: could not serialize entry: {e}")),
        };

        let target = self.path(coord);
        // Create the temp file with `tempfile`: it opens with `O_EXCL` (so it
        // always refers to a freshly created file, never a pre-existing symlink)
        // and uses an unguessable random name, closing the symlink/TOCTOU and
        // name-collision windows a predictable pid+timestamp name would leave
        // open. It lives in the SAME directory as the target so the final move
        // stays a same-filesystem atomic rename.
        let mut tmp = match tempfile::NamedTempFile::new_in(&self.dir) {
            Ok(f) => f,
            Err(e) => {
                return Some(format!(
                    "cache: could not create temp file in {}: {e}",
                    self.dir.display()
                ));
            }
        };

        if let Err(e) = tmp.write_all(text.as_bytes()) {
            return Some(format!(
                "cache: could not write temp file {}: {e}",
                tmp.path().display()
            ));
        }

        // `persist` atomically renames over `target` on Unix. On Windows a plain
        // rename will not replace an existing file, so fall back to `tempfile`'s
        // `persist_noclobber`-free replace path: drop into a manual replace via
        // `NamedTempFile::persist` and, if it reports the target already exists,
        // remove the target and retry. (`tempfile::persist` is documented to
        // overwrite on Unix; on Windows it surfaces the replace error so we can
        // handle it.)
        if let Err(e) = persist_replace(tmp, &target) {
            return Some(format!(
                "cache: could not persist temp file to {}: {e}",
                target.display()
            ));
        }

        None
    }
}

/// Atomically place `tmp` at `target`, replacing any existing file
/// cross-platform.
///
/// On Unix, `NamedTempFile::persist` performs a `rename(2)` that atomically
/// replaces an existing target. On Windows, `rename` refuses to overwrite an
/// existing file, so a second `put` for the same coordinate would otherwise
/// start failing once an entry exists; we detect that case and replace the
/// target explicitly. The temp file is dropped (and cleaned up) on any error so
/// no orphan lingers in the cache directory.
fn persist_replace(tmp: tempfile::NamedTempFile, target: &std::path::Path) -> std::io::Result<()> {
    match tmp.persist(target) {
        Ok(_) => Ok(()),
        Err(persist_err) => {
            // `persist` only fails to overwrite on platforms (Windows) where a
            // rename onto an existing file is rejected. Recover the temp file,
            // remove the stale target, and retry the rename so an overwrite of an
            // existing entry succeeds everywhere.
            if target.exists() {
                let tmp = persist_err.file;
                std::fs::remove_file(target)?;
                tmp.persist(target).map(|_| ()).map_err(|e| e.error)
            } else {
                Err(persist_err.error)
            }
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn coord() -> PackageCoordinate {
        PackageCoordinate {
            ecosystem: "crates.io".into(),
            name: "left-pad".into(),
            version: "1.0.0".into(),
        }
    }

    fn advisory() -> Advisory {
        Advisory {
            id: "RUSTSEC-1".into(),
            aliases: vec![],
            summary: "x".into(),
            severity: None,
            package: coord(),
        }
    }

    #[test]
    fn round_trips_within_ttl() {
        let dir = TempDir::new().unwrap();
        let cache = Cache::new(dir.path().to_path_buf(), 3600);
        assert!(cache.get_fresh(&coord()).is_none());
        assert!(
            cache.put(&coord(), &[advisory()]).is_none(),
            "put must succeed"
        );
        let got = cache.get_fresh(&coord()).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "RUSTSEC-1");
    }

    #[test]
    fn expired_entry_is_not_fresh_but_is_available_offline() {
        let dir = TempDir::new().unwrap();
        let cache = Cache::new(dir.path().to_path_buf(), 3600);
        // Hand-write an entry stamped well in the past so it is deterministically
        // stale (a `put` + same-second read could still look fresh).
        std::fs::create_dir_all(&cache.dir).unwrap();
        let entry = Entry {
            fetched: now() - 10_000,
            advisories: vec![advisory()],
        };
        std::fs::write(cache.path(&coord()), serde_json::to_string(&entry).unwrap()).unwrap();

        assert!(
            cache.get_fresh(&coord()).is_none(),
            "an expired entry must not be considered fresh"
        );
        // ...but it is still available for offline (cache-any) reads.
        assert!(cache.get_any(&coord()).is_some());
    }

    #[test]
    fn corrupt_json_is_a_cache_miss() {
        let dir = TempDir::new().unwrap();
        let cache = Cache::new(dir.path().to_path_buf(), 3600);
        std::fs::create_dir_all(&cache.dir).unwrap();
        // Write deliberately invalid JSON to the cache file.
        std::fs::write(cache.path(&coord()), b"not valid json {{{{").unwrap();

        // All access paths must treat corrupt content as a cache miss, not a
        // crash or an error propagated to the caller.
        assert!(
            !cache.contains(&coord()),
            "corrupt entry must not be 'contained'"
        );
        assert!(
            cache.get_fresh(&coord()).is_none(),
            "corrupt entry must not be fresh"
        );
        assert!(
            cache.get_any(&coord()).is_none(),
            "corrupt entry must not be available offline"
        );
    }

    #[test]
    fn atomic_write_leaves_no_temp_file() {
        let dir = TempDir::new().unwrap();
        let cache = Cache::new(dir.path().to_path_buf(), 3600);

        let diag = cache.put(&coord(), &[advisory()]);
        assert!(diag.is_none(), "put must succeed: {diag:?}");

        // The final entry must exist and be readable.
        assert!(cache.get_fresh(&coord()).is_some());

        // No leftover temp files should remain under the cache directory.
        let leftover_temps: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            leftover_temps.is_empty(),
            "temp files must not linger after a successful put: {leftover_temps:?}"
        );
    }

    #[test]
    fn put_twice_overwrites_existing_entry() {
        // Re-`put`ting the same coordinate must replace the existing entry
        // cleanly on every platform (Windows `rename` refusing to overwrite an
        // existing file was the regression this guards against). The second read
        // must reflect the latest content, with no lingering temp file and no
        // spurious diagnostic.
        let dir = TempDir::new().unwrap();
        let cache = Cache::new(dir.path().to_path_buf(), 3600);

        let first = Advisory {
            id: "RUSTSEC-FIRST".into(),
            ..advisory()
        };
        let second = Advisory {
            id: "RUSTSEC-SECOND".into(),
            ..advisory()
        };

        assert!(
            cache.put(&coord(), &[first]).is_none(),
            "first put must succeed"
        );
        assert!(
            cache.put(&coord(), &[second]).is_none(),
            "second put (overwrite) must succeed"
        );

        // The latest content wins.
        let got = cache
            .get_any(&coord())
            .expect("entry must exist after overwrite");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "RUSTSEC-SECOND");

        // No leftover temp files from either write.
        let leftover_temps: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                // The cache entry itself ends in `.json`; anything else under the
                // dir would be an orphaned temp file.
                !name.ends_with(".json")
            })
            .collect();
        assert!(
            leftover_temps.is_empty(),
            "temp files must not linger after overwrite: {leftover_temps:?}"
        );
    }

    #[test]
    fn put_in_unwritable_dir_returns_diagnostic() {
        // Only meaningful on Unix where mode bits can be enforced. Root (uid 0)
        // bypasses permission checks, so we probe whether the lock actually held
        // rather than hard-failing when it didn't.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            // Create a dir and then make it unwritable.
            let outer = TempDir::new().unwrap();
            let locked = outer.path().join("locked");
            std::fs::create_dir_all(&locked).unwrap();
            let locked_cache = locked.join("cache");
            // Point the cache at a sub-directory of the locked dir so
            // create_dir_all must traverse the locked parent.
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();

            let cache = Cache::new(locked_cache.clone(), 3600);
            let result = cache.put(&coord(), &[advisory()]);

            // Restore permissions so TempDir cleanup can delete the directory.
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();

            // Root bypasses mode bits; if the write succeeded despite the locked
            // parent (result.is_none()), the directory must now exist — that is
            // the only valid "root ignores permissions" outcome.  For a non-root
            // caller the write must have returned a diagnostic.
            match result {
                None => assert!(
                    locked_cache.exists(),
                    "put succeeded but cache directory was not created"
                ),
                Some(ref msg) => assert!(
                    msg.contains("cache:"),
                    "diagnostic message must start with 'cache:': {msg}"
                ),
            }
        }
        #[cfg(not(unix))]
        {
            // Non-Unix: just verify put compiles and returns None for a writable dir.
            let dir = TempDir::new().unwrap();
            let cache = Cache::new(dir.path().to_path_buf(), 3600);
            assert!(cache.put(&coord(), &[advisory()]).is_none());
        }
    }
}
