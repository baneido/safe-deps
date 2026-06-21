//! Collecting pinned package coordinates from lockfiles for audit queries.
//!
//! Only exactly-pinned, registry-sourced packages are collected — those are the
//! ones a vulnerability database can answer for. Git/path/workspace members are
//! skipped. Currently `Cargo.lock` (crates.io) and `package-lock.json` (npm) are
//! supported; other lockfiles are a follow-up.

use std::collections::BTreeSet;

use crate::audit::PackageCoordinate;
use crate::filesystem::{files_named, read_text, WorkspaceContext};

/// Collects deduplicated, deterministically-ordered coordinates from every
/// supported lockfile in the workspace, plus diagnostics for any lockfile that
/// could not be read or parsed (so an audit never silently reports "clean" for
/// a file it never analyzed).
#[derive(Debug, Default)]
pub struct Collected {
    pub coordinates: Vec<PackageCoordinate>,
    pub diagnostics: Vec<String>,
}

pub fn collect(ctx: &WorkspaceContext) -> Collected {
    let mut set: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut diagnostics = Vec::new();

    for lock in files_named(ctx, "Cargo.lock") {
        match read_text(ctx, &lock) {
            Ok(text) if toml::from_str::<toml::Value>(&text).is_ok() => {
                for c in cargo_lock_coordinates(&text) {
                    set.insert((c.ecosystem, c.name, c.version));
                }
            }
            Ok(_) => diagnostics.push(format!("could not parse {}", lock.display())),
            Err(e) => diagnostics.push(format!("could not read {}: {e}", lock.display())),
        }
    }
    for lock in files_named(ctx, "package-lock.json") {
        match read_text(ctx, &lock) {
            Ok(text) if serde_json::from_str::<serde_json::Value>(&text).is_ok() => {
                for c in npm_lock_coordinates(&text) {
                    set.insert((c.ecosystem, c.name, c.version));
                }
            }
            Ok(_) => diagnostics.push(format!("could not parse {}", lock.display())),
            Err(e) => diagnostics.push(format!("could not read {}: {e}", lock.display())),
        }
    }

    Collected {
        coordinates: set
            .into_iter()
            .map(|(ecosystem, name, version)| PackageCoordinate {
                ecosystem,
                name,
                version,
            })
            .collect(),
        diagnostics,
    }
}

/// Parses `[[package]]` entries from a `Cargo.lock`, keeping only crates.io
/// packages (those with a registry source). The local crate(s) under audit have
/// no `source` and are skipped, as are git/path dependencies.
pub fn cargo_lock_coordinates(text: &str) -> Vec<PackageCoordinate> {
    let Ok(value) = toml::from_str::<toml::Value>(text) else {
        return Vec::new();
    };
    let Some(packages) = value.get("package").and_then(|p| p.as_array()) else {
        return Vec::new();
    };
    packages
        .iter()
        .filter_map(|pkg| {
            let source = pkg.get("source").and_then(|s| s.as_str())?;
            if !is_crates_io_source(source) {
                return None;
            }
            Some(PackageCoordinate {
                ecosystem: "crates.io".to_string(),
                name: pkg.get("name").and_then(|n| n.as_str())?.to_string(),
                version: pkg.get("version").and_then(|v| v.as_str())?.to_string(),
            })
        })
        .collect()
}

/// Whether a Cargo.lock `source` is the public crates.io index (registry or
/// sparse), not an alternate registry whose URL merely mentions crates.io.
fn is_crates_io_source(source: &str) -> bool {
    source == "registry+https://github.com/rust-lang/crates.io-index"
        || source.starts_with("sparse+https://index.crates.io/")
}

/// Whether an npm version string is a plain registry version rather than a git
/// ref, alias (`npm:real@1`), or URL.
fn is_registry_version(version: &str) -> bool {
    !version.contains(':') && !version.contains('/')
}

/// Parses an npm `package-lock.json` (v1 `dependencies` or v2/v3 `packages`).
pub fn npm_lock_coordinates(text: &str) -> Vec<PackageCoordinate> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let has_packages = value.get("packages").is_some();

    // v2/v3: a flat `packages` map keyed by install path.
    if let Some(packages) = value.get("packages").and_then(|p| p.as_object()) {
        for (key, entry) in packages {
            // The root project has an empty-string key; skip it and any
            // non-registry (link/git) entries that lack a plain version.
            let Some(name) = npm_name_from_path(key) else {
                continue;
            };
            if entry.get("link").and_then(|l| l.as_bool()) == Some(true) {
                continue;
            }
            // Skip git/file-resolved entries: their `version` is the upstream's
            // own version, which OSV cannot match to a registry release.
            if let Some(resolved) = entry.get("resolved").and_then(|r| r.as_str()) {
                if resolved.starts_with("git+")
                    || resolved.starts_with("git:")
                    || resolved.starts_with("file:")
                {
                    continue;
                }
            }
            if let Some(version) = entry.get("version").and_then(|v| v.as_str()) {
                if is_registry_version(version) {
                    out.push(npm_coord(name, version));
                }
            }
        }
    }

    // v1: a nested `dependencies` tree keyed by package name. A v2 lockfile
    // carries this for backward-compat *alongside* `packages`; only read it when
    // `packages` is absent so packages are not collected twice.
    if !has_packages {
        if let Some(deps) = value.get("dependencies").and_then(|d| d.as_object()) {
            collect_npm_v1(deps, &mut out);
        }
    }

    out
}

fn collect_npm_v1(
    deps: &serde_json::Map<String, serde_json::Value>,
    out: &mut Vec<PackageCoordinate>,
) {
    for (name, entry) in deps {
        // Skip git/file-resolved entries (the v2/v3 path applies the same guard).
        let non_registry_resolved =
            entry
                .get("resolved")
                .and_then(|r| r.as_str())
                .is_some_and(|r| {
                    r.starts_with("git+") || r.starts_with("git:") || r.starts_with("file:")
                });
        if let Some(version) = entry.get("version").and_then(|v| v.as_str()) {
            // Skip non-registry refs: git/file URLs and `npm:` aliases all carry
            // `:` or `/`, which a plain registry version never does.
            if !non_registry_resolved && is_registry_version(version) {
                out.push(npm_coord(name, version));
            }
        }
        if let Some(nested) = entry.get("dependencies").and_then(|d| d.as_object()) {
            collect_npm_v1(nested, out);
        }
    }
}

/// Extracts the package name from a `packages` key like
/// `node_modules/@scope/pkg`. Returns `None` for the root (empty key) or any
/// path not under `node_modules`.
fn npm_name_from_path(key: &str) -> Option<&str> {
    let idx = key.rfind("node_modules/")?;
    let name = &key[idx + "node_modules/".len()..];
    (!name.is_empty()).then_some(name)
}

fn npm_coord(name: &str, version: &str) -> PackageCoordinate {
    PackageCoordinate {
        ecosystem: "npm".to_string(),
        name: name.to_string(),
        version: version.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_lock_keeps_only_registry_crates() {
        let text = r#"
[[package]]
name = "left-pad"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "my-app"
version = "0.1.0"

[[package]]
name = "from-git"
version = "0.2.0"
source = "git+https://github.com/x/y"
"#;
        let coords = cargo_lock_coordinates(text);
        assert_eq!(coords.len(), 1);
        assert_eq!(coords[0].name, "left-pad");
        assert_eq!(coords[0].ecosystem, "crates.io");
        assert_eq!(coords[0].version, "1.0.0");
    }

    #[test]
    fn npm_lock_v3_packages() {
        let text = r#"{
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "root", "version": "1.0.0" },
            "node_modules/left-pad": { "version": "1.3.0" },
            "node_modules/@scope/util": { "version": "2.0.0" },
            "node_modules/linked": { "version": "0.0.0", "link": true }
          }
        }"#;
        let coords = npm_lock_coordinates(text);
        let names: Vec<&str> = coords.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"left-pad"));
        assert!(names.contains(&"@scope/util"));
        assert!(!names.contains(&"linked"));
        assert!(!names.contains(&"root"));
    }

    #[test]
    fn npm_v2_does_not_double_count_packages_and_dependencies() {
        // A v2 lockfile carries both `packages` and a legacy `dependencies`
        // tree; the same package must be returned once, not twice.
        let text = r#"{
          "lockfileVersion": 2,
          "packages": { "node_modules/left-pad": { "version": "1.3.0" } },
          "dependencies": { "left-pad": { "version": "1.3.0" } }
        }"#;
        let coords = npm_lock_coordinates(text);
        assert_eq!(coords.len(), 1, "{coords:?}");
        assert_eq!(coords[0].name, "left-pad");
    }

    #[test]
    fn npm_lock_v1_dependencies() {
        let text = r#"{
          "lockfileVersion": 1,
          "dependencies": {
            "a": { "version": "1.0.0", "dependencies": { "b": { "version": "2.0.0" } } },
            "fromgit": { "version": "github:x/y#abc" }
          }
        }"#;
        let coords = npm_lock_coordinates(text);
        let names: Vec<&str> = coords.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
        assert!(!names.contains(&"fromgit"));
    }
}
