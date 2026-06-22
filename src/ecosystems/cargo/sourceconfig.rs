//! Cargo `[source]` replacement extraction for SD006.
//!
//! A `.cargo/config.toml` (or legacy `.cargo/config`) can globally redirect a
//! registry to another source via `[source.<name>]` `replace-with`. This silently
//! reroutes the whole crate graph for everyone who builds the project, so it is an
//! integrity-relevant source change. The replacement target's definition is also
//! inspected so the finding can name where crates actually resolve from.

use std::path::Path;

use crate::ecosystems::{Dependency, DependencyGroup, DependencySource};
use crate::filesystem::{project_join, read_text, WorkspaceContext};

/// Cargo source config filenames, in precedence order (`.cargo/config.toml`
/// supersedes the legacy `.cargo/config`).
const CONFIG_NAMES: [&str; 2] = [".cargo/config.toml", ".cargo/config"];

/// Extracts `[source]` `replace-with` redirects declared in the crate's
/// `.cargo/config.toml`. Each redirected source becomes a [`Dependency`] with a
/// [`DependencySource::RegistryReplaced`] so SD006 can flag the rerouting. A
/// source without `replace-with` (e.g. a plain definition of a custom registry)
/// is not itself a redirect and is not emitted.
pub(super) fn source_replacements(ctx: &WorkspaceContext, dir: &Path) -> Vec<Dependency> {
    for name in CONFIG_NAMES {
        let rel = project_join(dir, name);
        let Ok(text) = read_text(ctx, &rel) else {
            continue;
        };
        let Ok(value) = toml::from_str::<toml::Value>(&text) else {
            // A malformed config is surfaced elsewhere (syntax_diagnostic); here
            // we just skip rather than guess.
            return Vec::new();
        };
        return replacements(&value, &rel);
    }
    Vec::new()
}

/// Parses the `[source.<name>]` tables of a `.cargo/config.toml` value.
fn replacements(value: &toml::Value, file: &Path) -> Vec<Dependency> {
    let Some(sources) = value.get("source").and_then(|s| s.as_table()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, body) in sources {
        let Some(table) = body.as_table() else {
            continue;
        };
        let Some(replacement) = table.get("replace-with").and_then(|v| v.as_str()) else {
            continue;
        };
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
    // Deterministic order regardless of TOML map iteration order.
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml_text: &str) -> Vec<Dependency> {
        let value: toml::Value = toml::from_str(toml_text).unwrap();
        replacements(&value, Path::new(".cargo/config.toml"))
    }

    #[test]
    fn replace_with_is_flagged_as_registry_replacement() {
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
    fn multiple_replacements_are_sorted_by_name() {
        let cfg = "\
[source.crates-io]
replace-with = \"a\"

[source.another]
replace-with = \"b\"
";
        let deps = parse(cfg);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "another");
        assert_eq!(deps[1].name, "crates-io");
    }
}
