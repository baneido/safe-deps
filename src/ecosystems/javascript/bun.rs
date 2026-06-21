//! Bun helpers: `bunfig.toml` parsing and lockfile detection.
//!
//! Bun 1.2+ uses `bun.lock` (text). Legacy `bun.lockb` (binary) is accepted as
//! legacy lockfile evidence and reported as a migration note, not a missing
//! lockfile error.

use std::path::Path;

use crate::ecosystems::EcoError;

/// Security-relevant settings extracted from `bunfig.toml`.
#[derive(Debug, Clone, Default)]
pub struct BunfigSettings {
    /// Entries under `[install]` trusted dependencies. Empty when unset.
    pub trusted_dependencies: Vec<String>,
}

pub fn load_bunfig(
    ctx: &crate::filesystem::WorkspaceContext,
    relative: &Path,
) -> Result<BunfigSettings, EcoError> {
    let text = crate::filesystem::read_text(ctx, relative).map_err(|source| EcoError::Read {
        path: relative.to_path_buf(),
        source,
    })?;
    Ok(parse(&text))
}

pub fn parse(text: &str) -> BunfigSettings {
    let value: toml::Value = match toml::from_str(text) {
        Ok(v) => v,
        Err(_) => return BunfigSettings::default(),
    };
    let trusted_dependencies = value
        .get("install")
        .and_then(|install| install.get("trustedDependencies"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    BunfigSettings {
        trusted_dependencies,
    }
}

/// Returns whether `bun.lock` (Bun 1.2+) exists at the project dir.
pub fn has_bun_lock(ctx: &crate::filesystem::WorkspaceContext, project_dir: &Path) -> bool {
    let target = crate::filesystem::project_join(project_dir, "bun.lock");
    ctx.contains(&target)
}

/// Returns whether the legacy `bun.lockb` exists at the project dir.
pub fn has_bun_lockb(ctx: &crate::filesystem::WorkspaceContext, project_dir: &Path) -> bool {
    let target = crate::filesystem::project_join(project_dir, "bun.lockb");
    ctx.contains(&target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_trusted_dependencies() {
        let s = parse("[install]\ntrustedDependencies = [\"esbuild\", \"sharp\"]\n");
        assert_eq!(s.trusted_dependencies, vec!["esbuild", "sharp"]);
    }

    #[test]
    fn no_install_section_yields_empty() {
        let s = parse("[run]\nbun = true\n");
        assert!(s.trusted_dependencies.is_empty());
    }

    #[test]
    fn invalid_toml_yields_default() {
        let s = parse("this is = not = valid toml");
        assert!(s.trusted_dependencies.is_empty());
    }
}
