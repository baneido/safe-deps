//! pnpm helpers: `pnpm-workspace.yaml` parsing and lockfile detection.

use std::path::Path;

use crate::ecosystems::EcoError;

/// Workspace package globs declared in `pnpm-workspace.yaml`.
#[derive(Debug, Clone, Default)]
pub struct PnpmWorkspace {
    pub packages: Vec<String>,
    /// `dangerouslyAllowAllBuilds: true` runs every dependency build script.
    pub dangerously_allow_all_builds: Option<bool>,
}

pub fn load_workspace(
    ctx: &crate::filesystem::WorkspaceContext,
    relative: &Path,
) -> Result<PnpmWorkspace, EcoError> {
    let text = crate::filesystem::read_text(ctx, relative).map_err(|source| EcoError::Read {
        path: relative.to_path_buf(),
        source,
    })?;
    Ok(parse(&text))
}

pub fn parse(text: &str) -> PnpmWorkspace {
    let value: serde_yaml::Value = match serde_yaml::from_str(text) {
        Ok(v) => v,
        Err(_) => return PnpmWorkspace::default(),
    };
    let packages = value
        .get(serde_yaml::Value::String("packages".to_string()))
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let dangerously_allow_all_builds = value
        .get(serde_yaml::Value::String(
            "dangerouslyAllowAllBuilds".to_string(),
        ))
        .and_then(|v| v.as_bool());
    PnpmWorkspace {
        packages,
        dangerously_allow_all_builds,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dangerously_allow_all_builds() {
        let w = parse("packages:\n  - 'pkgs/*'\ndangerouslyAllowAllBuilds: true\n");
        assert_eq!(w.dangerously_allow_all_builds, Some(true));
        assert_eq!(w.packages, vec!["pkgs/*"]);
    }

    #[test]
    fn absent_flag_is_none() {
        let w = parse("packages:\n  - 'pkgs/*'\n");
        assert_eq!(w.dangerously_allow_all_builds, None);
    }
}
