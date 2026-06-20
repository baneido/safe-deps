//! `package.json` parsing into a minimal typed representation.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::ecosystems::EcoError;

/// The subset of `package.json` fields that `safe-deps` needs.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PackageJson {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, alias = "packageManager")]
    pub package_manager: Option<String>,
    /// `private` is conventionally a boolean, but real manifests sometimes write
    /// `"true"`/`"false"` as strings (npm tolerates this). Parse leniently so a
    /// quirky `private` value never aborts the whole manifest and hides findings.
    #[serde(default, deserialize_with = "de_bool_lenient")]
    pub private: Option<bool>,
    #[serde(default)]
    pub dependencies: BTreeMap<String, String>,
    #[serde(default, alias = "devDependencies")]
    pub dev_dependencies: BTreeMap<String, String>,
    #[serde(default, alias = "peerDependencies")]
    pub peer_dependencies: BTreeMap<String, String>,
    #[serde(default, alias = "optionalDependencies")]
    pub optional_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub workspaces: Workspaces,
}

/// `workspaces` may be an array of globs or an object with `packages`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(untagged)]
pub enum Workspaces {
    #[default]
    None,
    List(Vec<String>),
    Object {
        #[serde(default)]
        packages: Vec<String>,
        #[serde(default)]
        nohoist: Vec<String>,
    },
}

impl Workspaces {
    pub fn packages(&self) -> &[String] {
        match self {
            Workspaces::None => &[],
            Workspaces::List(list) => list,
            Workspaces::Object { packages, .. } => packages,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.packages().is_empty()
    }
}

impl PackageJson {
    pub fn has_dependencies(&self) -> bool {
        !self.dependencies.is_empty()
            || !self.dev_dependencies.is_empty()
            || !self.peer_dependencies.is_empty()
            || !self.optional_dependencies.is_empty()
    }

    pub fn package_manager_hint(&self) -> Option<PackageManagerHint> {
        let raw = self.package_manager.as_ref()?;
        PackageManagerHint::parse(raw)
    }
}

/// Deserializes a boolean that may be written as a real bool or as the strings
/// `"true"`/`"false"`. Any other shape is treated as "not declared" rather than
/// failing, so a single odd field cannot abort the whole manifest parse.
fn de_bool_lenient<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    Ok(
        match Option::<serde_json::Value>::deserialize(deserializer)? {
            Some(serde_json::Value::Bool(b)) => Some(b),
            Some(serde_json::Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            },
            _ => None,
        },
    )
}

/// Parsed `packageManager` field, e.g. `yarn@4.1.0`.
#[derive(Debug, Clone)]
pub struct PackageManagerHint {
    pub manager: crate::ecosystems::PackageManager,
    pub version: Option<String>,
}

impl PackageManagerHint {
    pub fn parse(raw: &str) -> Option<Self> {
        let (name, version) = raw.split_once('@').unwrap_or((raw, ""));
        let manager = match name {
            "npm" => crate::ecosystems::PackageManager::Npm,
            "yarn" => crate::ecosystems::PackageManager::Yarn,
            "pnpm" => crate::ecosystems::PackageManager::Pnpm,
            "bun" => crate::ecosystems::PackageManager::Bun,
            _ => return None,
        };
        let version = if version.is_empty() {
            None
        } else {
            Some(version.to_string())
        };
        Some(Self { manager, version })
    }
}

/// Reads and parses a `package.json` from the workspace.
pub fn load(
    ctx: &crate::filesystem::WorkspaceContext,
    relative: &Path,
) -> Result<PackageJson, EcoError> {
    let text = crate::filesystem::read_text(ctx, relative).map_err(|source| EcoError::Read {
        path: relative.to_path_buf(),
        source,
    })?;
    serde_json::from_str::<PackageJson>(&text).map_err(|err| EcoError::Parse {
        path: relative.to_path_buf(),
        message: err.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> PackageJson {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn parses_package_manager_hint() {
        let hint = PackageManagerHint::parse("yarn@4.1.0").unwrap();
        assert_eq!(hint.manager, crate::ecosystems::PackageManager::Yarn);
        assert_eq!(hint.version.as_deref(), Some("4.1.0"));
    }

    #[test]
    fn package_manager_hint_without_version() {
        let hint = PackageManagerHint::parse("pnpm").unwrap();
        assert_eq!(hint.manager, crate::ecosystems::PackageManager::Pnpm);
        assert!(hint.version.is_none());
    }

    #[test]
    fn unknown_package_manager_hint_is_none() {
        assert!(PackageManagerHint::parse("rush@1.0.0").is_none());
    }

    #[test]
    fn detects_dependencies_across_groups() {
        let pj = parse(r#"{"devDependencies":{"typescript":"^5"}}"#);
        assert!(pj.has_dependencies());
        let empty = parse(r#"{"name":"x"}"#);
        assert!(!empty.has_dependencies());
    }

    #[test]
    fn workspaces_array_form() {
        let pj = parse(r#"{"workspaces":["packages/*"]}"#);
        assert_eq!(pj.workspaces.packages(), &["packages/*".to_string()]);
        assert!(!pj.workspaces.is_empty());
    }

    #[test]
    fn workspaces_object_form() {
        let pj = parse(r#"{"workspaces":{"packages":["apps/*"]}}"#);
        assert_eq!(pj.workspaces.packages(), &["apps/*".to_string()]);
    }

    #[test]
    fn missing_workspaces_is_empty() {
        let pj = parse(r#"{"name":"x"}"#);
        assert!(pj.workspaces.is_empty());
    }

    #[test]
    fn reads_camel_case_package_manager_field() {
        // Regression: the real key is camelCase `packageManager`; without the
        // alias it was always None and detection fell back to npm.
        let pj = parse(r#"{"name":"x","packageManager":"yarn@4.1.0"}"#);
        let hint = pj.package_manager_hint().unwrap();
        assert_eq!(hint.manager, crate::ecosystems::PackageManager::Yarn);
    }

    #[test]
    fn private_as_string_does_not_abort_parse() {
        // Regression: `"private": "true"` (a string) used to fail the whole
        // manifest parse, hiding every dependency and finding.
        let pj = parse(r#"{"name":"app","private":"true","dependencies":{"left-pad":"^1"}}"#);
        assert_eq!(pj.private, Some(true));
        assert!(pj.has_dependencies());

        assert_eq!(parse(r#"{"private":false}"#).private, Some(false));
        assert_eq!(parse(r#"{"private":"false"}"#).private, Some(false));
        assert_eq!(parse(r#"{"name":"x"}"#).private, None);
    }
}
