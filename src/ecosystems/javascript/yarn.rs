//! Yarn config (`.yarnrc.yml`) and lockfile generation detection.
//!
//! Yarn v1 uses `.yarnrc`; Yarn Berry (v2+) uses `.yarnrc.yml`. The lockfile
//! format also differs: Berry lockfiles contain a `__metadata` entry.

use std::path::Path;

use crate::ecosystems::{EcoError, YarnGeneration};

/// Security-relevant settings extracted from `.yarnrc.yml`.
#[derive(Debug, Clone, Default)]
pub struct YarnrcSettings {
    pub checksum_behavior: Option<String>,
    /// Hosts listed in `unsafeHttpWhitelist`. Any non-empty list is flagged.
    pub unsafe_http_whitelist: Vec<String>,
}

pub fn load_yarnrc_yml(
    ctx: &crate::filesystem::WorkspaceContext,
    relative: &Path,
) -> Result<YarnrcSettings, EcoError> {
    let text = crate::filesystem::read_text(ctx, relative).map_err(|source| EcoError::Read {
        path: relative.to_path_buf(),
        source,
    })?;
    Ok(parse(&text))
}

pub fn parse(text: &str) -> YarnrcSettings {
    let value: serde_yaml::Value = match serde_yaml::from_str(text) {
        Ok(v) => v,
        Err(_) => return YarnrcSettings::default(),
    };
    let mapping = match value {
        serde_yaml::Value::Mapping(m) => m,
        _ => return YarnrcSettings::default(),
    };

    let checksum_behavior = mapping
        .get(serde_yaml::Value::String("checksumBehavior".to_string()))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let unsafe_http_whitelist = mapping
        .get(serde_yaml::Value::String("unsafeHttpWhitelist".to_string()))
        .and_then(|v| match v {
            serde_yaml::Value::Mapping(m) => Some(
                m.keys()
                    .filter_map(|k| k.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>(),
            ),
            serde_yaml::Value::Sequence(seq) => Some(
                seq.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .unwrap_or_default();

    YarnrcSettings {
        checksum_behavior,
        unsafe_http_whitelist,
    }
}

/// Determines the Yarn generation from available evidence.
///
/// `.yarnrc.yml` implies Berry. A plain `.yarnrc` implies v1. Otherwise inspect
/// `yarn.lock`: Berry lockfiles contain a `__metadata` entry.
pub fn detect_generation(
    ctx: &crate::filesystem::WorkspaceContext,
    project_dir: &Path,
    has_yarnrc_yml: bool,
    has_yarnrc: bool,
) -> YarnGeneration {
    if has_yarnrc_yml {
        return YarnGeneration::Berry;
    }
    if has_yarnrc {
        return YarnGeneration::V1;
    }
    let lockfile = crate::filesystem::project_join(project_dir, "yarn.lock");
    if let Ok(text) = crate::filesystem::read_text(ctx, &lockfile) {
        if text.contains("__metadata") {
            return YarnGeneration::Berry;
        }
        return YarnGeneration::V1;
    }
    YarnGeneration::Berry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_checksum_behavior_ignore() {
        let s = parse("checksumBehavior: ignore\n");
        assert_eq!(s.checksum_behavior.as_deref(), Some("ignore"));
    }

    #[test]
    fn parses_unsafe_http_whitelist_sequence() {
        let s = parse("unsafeHttpWhitelist:\n  - example.com\n  - npm.internal\n");
        assert_eq!(s.unsafe_http_whitelist, vec!["example.com", "npm.internal"]);
    }

    #[test]
    fn empty_config_has_no_settings() {
        let s = parse("nodeLinker: node-modules\n");
        assert!(s.checksum_behavior.is_none());
        assert!(s.unsafe_http_whitelist.is_empty());
    }

    #[test]
    fn invalid_yaml_yields_default() {
        let s = parse(":::not yaml:::\n  - [");
        assert!(s.checksum_behavior.is_none());
    }
}
