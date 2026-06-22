//! Cargo `[source]` replacement extraction for SD006.
//!
//! A `.cargo/config.toml` (or legacy `.cargo/config`) can globally redirect a
//! registry to another source via `[source.<name>]` `replace-with`. When the
//! replacement target is a REMOTE source (`registry`/`git`) this silently
//! reroutes the whole crate graph for everyone who builds the project, an
//! integrity-relevant source change.
//!
//! A redirect to a LOCAL target (`directory`/`local-registry`) is the standard
//! deterministic/offline vendoring setup that `cargo vendor` produces, so it is
//! NOT flagged. The replacement target's definition is inspected to tell the two
//! apart.
//!
//! Cargo config lookup is hierarchical: a `.cargo/config.toml` at a workspace
//! root applies to member crates. Member facts therefore also scan ancestor
//! config locations up to the scanned workspace root, deduplicating redirects
//! that resolve identically so a member and its root do not double-report.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::diagnostics::Diagnostic;
use crate::ecosystems::{Dependency, DependencyGroup, DependencySource};
use crate::filesystem::{project_join, read_text, WorkspaceContext};

/// Cargo source config filenames, in precedence order (`.cargo/config.toml`
/// supersedes the legacy `.cargo/config`).
const CONFIG_NAMES: [&str; 2] = [".cargo/config.toml", ".cargo/config"];

/// The kind of a `[source.<name>]` definition, used to decide whether a
/// `replace-with` redirect targeting it is a remote (unsafe) or local (safe,
/// vendoring) source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceKind {
    /// `registry = <url>` or `git = <url>`: a remote source. Redirecting to it
    /// reroutes resolution off the registry over the network.
    Remote,
    /// `directory` or `local-registry`: an on-disk vendored source. Redirecting
    /// to it is the standard deterministic/offline setup `cargo vendor` builds.
    Local,
}

/// Result of scanning the Cargo source config(s) applicable to a crate.
#[derive(Debug, Default)]
pub(super) struct SourceConfig {
    /// Remote `replace-with` redirects to flag (SD006), deduplicated.
    pub(super) dependencies: Vec<Dependency>,
    /// Warning diagnostics for config files that could not be parsed.
    pub(super) diagnostics: Vec<Diagnostic>,
}

/// Extracts remote `[source]` `replace-with` redirects that apply to the crate
/// at `dir`, honoring Cargo's hierarchical config lookup: the crate's own
/// `.cargo/config.toml` plus those in ancestor directories up to the scanned
/// workspace root. Redirects to a local (`directory`/`local-registry`) target
/// are vendoring and are not emitted. Identical redirects discovered at multiple
/// levels are reported once.
pub(super) fn source_replacements(ctx: &WorkspaceContext, dir: &Path) -> SourceConfig {
    let mut out = SourceConfig::default();
    // (source name, replacement) already emitted, so a redirect declared at both
    // the crate and an ancestor level is not double-reported.
    let mut seen = std::collections::HashSet::new();
    for config_dir in ancestor_config_dirs(dir) {
        for name in CONFIG_NAMES {
            let rel = project_join(&config_dir, name);
            let Ok(text) = read_text(ctx, &rel) else {
                continue;
            };
            let value: toml::Value = match toml::from_str(&text) {
                Ok(v) => v,
                Err(_) => {
                    // Surface the parse failure so `--strict-parser-errors` can
                    // escalate, consistent with the other parsers.
                    out.diagnostics.push(Diagnostic::warn_at(
                        format!("could not parse {}", rel.display()),
                        rel.clone(),
                    ));
                    // A malformed config at this level supersedes the legacy
                    // filename; stop scanning other names for this directory.
                    break;
                }
            };
            for dep in replacements(&value, &rel) {
                if let DependencySource::RegistryReplaced { replacement } = &dep.source {
                    if seen.insert((dep.name.clone(), replacement.clone())) {
                        out.dependencies.push(dep);
                    }
                }
            }
            // `.cargo/config.toml` supersedes the legacy `.cargo/config` in the
            // same directory; stop after the first that parsed.
            break;
        }
    }
    out.dependencies.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// The directories whose `.cargo/config.toml` apply to a crate at `dir`: the
/// crate dir itself and every ancestor up to (and including) the scanned
/// workspace root `.`. Ordered nearest-first.
fn ancestor_config_dirs(dir: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut current = if dir.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        dir.to_path_buf()
    };
    loop {
        dirs.push(current.clone());
        if current == Path::new(".") || current.as_os_str().is_empty() {
            break;
        }
        match current.parent() {
            // An empty parent means the next level up is the workspace root.
            Some(p) if p.as_os_str().is_empty() => current = PathBuf::from("."),
            Some(p) => current = p.to_path_buf(),
            None => break,
        }
    }
    // Ensure the root `.` is always considered even for crates whose normalized
    // path has no `.` ancestor component.
    if !dirs.iter().any(|d| d == Path::new(".")) {
        dirs.push(PathBuf::from("."));
    }
    dirs
}

/// Parses the `[source.<name>]` tables of a `.cargo/config.toml` value, emitting
/// a [`Dependency`] only for `replace-with` redirects whose target is a remote
/// source. A redirect to a local (`directory`/`local-registry`) target, or to an
/// undefined source, is treated as vendoring/unknown and not emitted.
fn replacements(value: &toml::Value, file: &Path) -> Vec<Dependency> {
    let Some(sources) = value.get("source").and_then(|s| s.as_table()) else {
        return Vec::new();
    };
    // First pass: classify every declared source by kind so a redirect can
    // resolve its target.
    let kinds: BTreeMap<&str, SourceKind> = sources
        .iter()
        .filter_map(|(name, body)| source_kind(body).map(|k| (name.as_str(), k)))
        .collect();

    let mut out = Vec::new();
    for (name, body) in sources {
        let Some(table) = body.as_table() else {
            continue;
        };
        let Some(replacement) = table.get("replace-with").and_then(|v| v.as_str()) else {
            continue;
        };
        // Only flag redirects to a known remote source. A target that is local
        // (vendoring) or not defined in this file is not a remote reroute.
        if kinds.get(replacement) != Some(&SourceKind::Remote) {
            continue;
        }
        out.push(Dependency {
            name: name.clone(),
            spec: format!("replace-with = \"{replacement}\""),
            group: DependencyGroup::Production,
            source: DependencySource::RegistryReplaced {
                replacement: replacement.to_string(),
            },
            file: file.to_path_buf(),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Classifies a `[source.<name>]` table by its target kind. `directory` and
/// `local-registry` are on-disk (local); `registry` and `git` are remote. A
/// table that only declares `replace-with` (a pure redirect, no target of its
/// own) has no inherent kind.
fn source_kind(body: &toml::Value) -> Option<SourceKind> {
    let table = body.as_table()?;
    if table.contains_key("directory") || table.contains_key("local-registry") {
        return Some(SourceKind::Local);
    }
    if table.contains_key("registry") || table.contains_key("git") {
        return Some(SourceKind::Remote);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml_text: &str) -> Vec<Dependency> {
        let value: toml::Value = toml::from_str(toml_text).unwrap();
        replacements(&value, Path::new(".cargo/config.toml"))
    }

    #[test]
    fn replace_with_remote_registry_is_flagged() {
        let cfg = "\
[source.crates-io]
replace-with = \"mirror\"

[source.mirror]
registry = \"https://internal.example/index\"
";
        let deps = parse(cfg);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "crates-io");
        assert_eq!(
            deps[0].source,
            DependencySource::RegistryReplaced {
                replacement: "mirror".to_string()
            }
        );
    }

    #[test]
    fn replace_with_remote_git_is_flagged() {
        let cfg = "\
[source.crates-io]
replace-with = \"forked\"

[source.forked]
git = \"https://internal.example/crates.git\"
";
        let deps = parse(cfg);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "crates-io");
    }

    #[test]
    fn replace_with_vendored_directory_is_not_flagged() {
        // `cargo vendor` emits exactly this; it is deterministic/offline, safe.
        let cfg = "\
[source.crates-io]
replace-with = \"vendored-sources\"

[source.vendored-sources]
directory = \"vendor\"
";
        assert!(parse(cfg).is_empty());
    }

    #[test]
    fn replace_with_local_registry_is_not_flagged() {
        let cfg = "\
[source.crates-io]
replace-with = \"local\"

[source.local]
local-registry = \"registry\"
";
        assert!(parse(cfg).is_empty());
    }

    #[test]
    fn replace_with_undefined_target_is_not_flagged() {
        // The target source is not defined in this file, so its kind is unknown;
        // we do not assume it is remote.
        let cfg = "[source.crates-io]\nreplace-with = \"mirror\"\n";
        assert!(parse(cfg).is_empty());
    }

    #[test]
    fn source_definition_without_replace_with_is_not_emitted() {
        // Declaring a custom registry source is not, by itself, a redirect.
        let cfg = "[source.mirror]\nregistry = \"https://internal.example/index\"\n";
        assert!(parse(cfg).is_empty());
    }

    #[test]
    fn no_source_table_is_empty() {
        assert!(parse("[net]\nretry = 2\n").is_empty());
    }

    #[test]
    fn multiple_remote_replacements_are_sorted_by_name() {
        let cfg = "\
[source.crates-io]
replace-with = \"a\"

[source.another]
replace-with = \"b\"

[source.a]
registry = \"https://a.example/index\"

[source.b]
registry = \"https://b.example/index\"
";
        let deps = parse(cfg);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "another");
        assert_eq!(deps[1].name, "crates-io");
    }

    #[test]
    fn ancestor_config_dirs_walks_up_to_root() {
        let dirs = ancestor_config_dirs(Path::new("crates/a"));
        assert_eq!(
            dirs,
            vec![
                PathBuf::from("crates/a"),
                PathBuf::from("crates"),
                PathBuf::from("."),
            ]
        );
        // A root crate yields just the root.
        assert_eq!(
            ancestor_config_dirs(Path::new(".")),
            vec![PathBuf::from(".")]
        );
    }
}
