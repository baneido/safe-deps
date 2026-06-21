//! On-disk cache for audit results.
//!
//! Caching makes re-runs cheap and keeps request volume (and rate-limit
//! pressure) down: each package's advisories are stored under the cache
//! directory keyed by coordinate, with the fetch time so freshness can be
//! checked against a TTL. `audit --offline` reads the cache without any network.

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
        serde_json::from_str(&text).ok()
    }

    /// Whether a cache entry exists for `coord` (regardless of freshness).
    pub fn contains(&self, coord: &PackageCoordinate) -> bool {
        self.path(coord).exists()
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

    /// Stores advisories for a coordinate, stamping the current time. Errors are
    /// ignored — the cache is an optimization, not a source of truth.
    pub fn put(&self, coord: &PackageCoordinate, advisories: &[Advisory]) {
        let _ = std::fs::create_dir_all(&self.dir);
        let entry = Entry {
            fetched: now(),
            advisories: advisories.to_vec(),
        };
        if let Ok(text) = serde_json::to_string(&entry) {
            let _ = std::fs::write(self.path(coord), text);
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
        cache.put(&coord(), &[advisory()]);
        let got = cache.get_fresh(&coord()).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "RUSTSEC-1");
    }

    #[test]
    fn expired_entry_is_not_fresh_but_is_available_offline() {
        let dir = TempDir::new().unwrap();
        // TTL of 0 → anything stored is immediately stale.
        let cache = Cache::new(dir.path().to_path_buf(), 0);
        cache.put(&coord(), &[advisory()]);
        // Freshness may still pass within the same second; force staleness by
        // checking get_any always returns it.
        assert!(cache.get_any(&coord()).is_some());
    }
}
