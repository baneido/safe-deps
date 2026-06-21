//! Configuration loading for `safe-deps.toml`.
//!
//! CLI arguments override config values. Environment variables provide CI
//! convenience for profile and format. Invalid config fails with exit code 2.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::rule::{Profile, Severity};

/// Threshold for failing the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailLevel {
    Error,
    Warning,
    Info,
    None,
}

impl FailLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            FailLevel::Error => "error",
            FailLevel::Warning => "warning",
            FailLevel::Info => "info",
            FailLevel::None => "none",
        }
    }

    /// Returns true if a finding at `severity` meets the fail threshold.
    pub fn triggers(&self, severity: Severity) -> bool {
        match self {
            FailLevel::None => false,
            FailLevel::Info => true,
            FailLevel::Warning => matches!(severity, Severity::Warning | Severity::Error),
            FailLevel::Error => matches!(severity, Severity::Error),
        }
    }
}

/// Report output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
    Junit,
}

impl OutputFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            OutputFormat::Text => "text",
            OutputFormat::Json => "json",
            OutputFormat::Sarif => "sarif",
            OutputFormat::Junit => "junit",
        }
    }
}

/// Per-rule configuration override.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleConfig {
    #[serde(default)]
    pub level: Option<Severity>,
}

/// Workspace scanning configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkspaceConfig {
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub include: Vec<String>,
}

/// A centralized suppression entry. `reason` is required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suppression {
    pub rule: String,
    pub path: String,
    pub reason: String,
    #[serde(default)]
    pub expires: Option<String>,
    #[serde(default)]
    pub line: Option<u32>,
    #[serde(default)]
    pub package_manager: Option<String>,
    #[serde(default)]
    pub ecosystem: Option<String>,
}

/// The full configuration model.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub profile: Option<Profile>,
    #[serde(default)]
    pub fail_on: Option<FailLevel>,
    #[serde(default)]
    pub format: Option<OutputFormat>,
    #[serde(default)]
    pub workspace: WorkspaceConfig,
    #[serde(default)]
    pub policy: crate::rule::Policy,
    #[serde(default)]
    pub rules: std::collections::HashMap<String, RuleConfig>,
    #[serde(default)]
    pub suppressions: Vec<Suppression>,
    /// Advisory IDs to ignore in `safe-deps audit`, each with a required reason
    /// and an optional expiry.
    #[serde(default)]
    pub advisory_ignores: Vec<AdvisoryIgnore>,
}

/// An ignore entry for a specific vulnerability advisory in `audit`. `id`
/// matches an advisory ID or any of its aliases (e.g. `RUSTSEC-2024-0001`,
/// `GHSA-…`, `CVE-…`). `reason` is required; an expired ignore stops applying
/// and surfaces a diagnostic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisoryIgnore {
    pub id: String,
    pub reason: String,
    #[serde(default)]
    pub expires: Option<String>,
}

/// Errors produced while loading or validating configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("invalid config: {0}")]
    Invalid(String),
}

/// Validates a loaded config. Missing suppression reasons are config errors.
pub fn validate(config: &Config) -> Result<(), ConfigError> {
    for supp in &config.suppressions {
        if supp.reason.trim().is_empty() {
            return Err(ConfigError::Invalid(format!(
                "suppression for rule {} at path {} is missing a reason",
                supp.rule, supp.path
            )));
        }
        if supp.rule.trim().is_empty() || supp.path.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "suppression requires both `rule` and `path`".to_string(),
            ));
        }
        if let Some(expires) = &supp.expires {
            if parse_iso_date(expires).is_none() {
                return Err(ConfigError::Invalid(format!(
                    "suppression for rule {} has invalid expires '{}' (expected YYYY-MM-DD)",
                    supp.rule, expires
                )));
            }
        }
    }
    for ignore in &config.advisory_ignores {
        if ignore.id.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "an [[advisory_ignores]] entry requires an `id`".to_string(),
            ));
        }
        if ignore.reason.trim().is_empty() {
            return Err(ConfigError::Invalid(format!(
                "[[advisory_ignores]] entry for {} is missing a reason",
                ignore.id
            )));
        }
        if let Some(expires) = &ignore.expires {
            if parse_iso_date(expires).is_none() {
                return Err(ConfigError::Invalid(format!(
                    "[[advisory_ignores]] entry for {} has invalid expires '{}' (expected YYYY-MM-DD)",
                    ignore.id, expires
                )));
            }
        }
    }
    Ok(())
}

/// Today's date as `(year, month, day)` in UTC, for expiry comparisons.
pub fn today_ymd() -> (i64, u32, u32) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    civil_from_days(secs.div_euclid(86400))
}

/// Converts days since the Unix epoch to a proleptic Gregorian `(year, month,
/// day)`. Based on Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Parses a `YYYY-MM-DD` date into a `(year, month, day)` tuple suitable for
/// ordered comparison. Components may be non-zero-padded (`2026-6-1`). Returns
/// `None` for malformed input so callers can reject it rather than silently
/// treating a typo as "never expires".
pub fn parse_iso_date(s: &str) -> Option<(i64, u32, u32)> {
    let mut parts = s.trim().split('-');
    let year = parts.next()?.parse::<i64>().ok()?;
    let month = parts.next()?.parse::<u32>().ok()?;
    let day = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some((year, month, day))
}

/// Loads config from a file path.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let config: Config = toml::from_str(&contents).map_err(|err| ConfigError::Parse {
        path: path.to_path_buf(),
        message: err.to_string(),
    })?;
    validate(&config)?;
    Ok(config)
}

/// Resolved, effective configuration after merging file config, CLI flags, and
/// environment variables. CLI overrides config; config overrides env defaults.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub profile: Profile,
    pub fail_on: FailLevel,
    pub format: OutputFormat,
    pub config: Config,
}

impl Default for ResolvedConfig {
    fn default() -> Self {
        Self {
            profile: Profile::Balanced,
            fail_on: FailLevel::Error,
            format: OutputFormat::Text,
            config: Config::default(),
        }
    }
}

/// Environment variable names used for CI convenience.
pub mod env {
    pub const PROFILE: &str = "SAFE_DEPS_PROFILE";
    pub const FORMAT: &str = "SAFE_DEPS_FORMAT";
}

/// Parses a profile from a string.
pub fn parse_profile(s: &str) -> Result<Profile, ConfigError> {
    match s.to_ascii_lowercase().as_str() {
        "balanced" => Ok(Profile::Balanced),
        "strict" => Ok(Profile::Strict),
        "permissive" => Ok(Profile::Permissive),
        other => Err(ConfigError::Invalid(format!("unknown profile '{other}'"))),
    }
}

/// Parses an output format from a string.
pub fn parse_format(s: &str) -> Result<OutputFormat, ConfigError> {
    match s.to_ascii_lowercase().as_str() {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        "sarif" => Ok(OutputFormat::Sarif),
        "junit" => Ok(OutputFormat::Junit),
        other => Err(ConfigError::Invalid(format!("unknown format '{other}'"))),
    }
}

/// Parses a fail threshold from a string.
pub fn parse_fail_on(s: &str) -> Result<FailLevel, ConfigError> {
    match s.to_ascii_lowercase().as_str() {
        "error" => Ok(FailLevel::Error),
        "warning" => Ok(FailLevel::Warning),
        "info" => Ok(FailLevel::Info),
        "none" => Ok(FailLevel::None),
        other => Err(ConfigError::Invalid(format!(
            "unknown fail-on level '{other}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_level_triggers_respect_threshold() {
        assert!(FailLevel::Error.triggers(Severity::Error));
        assert!(!FailLevel::Error.triggers(Severity::Warning));
        assert!(FailLevel::Warning.triggers(Severity::Warning));
        assert!(FailLevel::Warning.triggers(Severity::Error));
        assert!(!FailLevel::Warning.triggers(Severity::Info));
        assert!(FailLevel::Info.triggers(Severity::Info));
        assert!(!FailLevel::None.triggers(Severity::Error));
    }

    #[test]
    fn parses_known_profiles_case_insensitively() {
        assert_eq!(parse_profile("Strict").unwrap(), Profile::Strict);
        assert_eq!(parse_profile("balanced").unwrap(), Profile::Balanced);
        assert!(parse_profile("nope").is_err());
    }

    #[test]
    fn parses_formats_and_fail_levels() {
        assert_eq!(parse_format("json").unwrap(), OutputFormat::Json);
        assert_eq!(parse_fail_on("none").unwrap(), FailLevel::None);
        assert!(parse_format("yaml").is_err());
        assert!(parse_fail_on("fatal").is_err());
    }

    #[test]
    fn validate_rejects_missing_reason() {
        let mut config = Config::default();
        config.suppressions.push(Suppression {
            rule: "SD001".to_string(),
            path: "pkg/package.json".to_string(),
            reason: "  ".to_string(),
            expires: None,
            line: None,
            package_manager: None,
            ecosystem: None,
        });
        assert!(validate(&config).is_err());
    }

    #[test]
    fn validate_accepts_complete_suppression() {
        let mut config = Config::default();
        config.suppressions.push(Suppression {
            rule: "SD001".to_string(),
            path: "pkg/package.json".to_string(),
            reason: "tracked elsewhere".to_string(),
            expires: None,
            line: None,
            package_manager: None,
            ecosystem: None,
        });
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn loads_full_config_from_toml() {
        let toml = r#"
profile = "strict"
fail_on = "warning"
format = "json"

[policy]
allow_git_dependencies = false
external_audit = true

[rules.SD001]
level = "warning"

[[suppressions]]
rule = "SD003"
path = "fixtures/package.json"
reason = "intentional fixture"
expires = "2030-01-01"
"#;
        let config: Config = ::toml::from_str(toml).unwrap();
        assert_eq!(config.profile, Some(Profile::Strict));
        assert_eq!(config.fail_on, Some(FailLevel::Warning));
        assert_eq!(config.format, Some(OutputFormat::Json));
        assert!(config.policy.external_audit);
        assert_eq!(config.rules["SD001"].level, Some(Severity::Warning));
        assert_eq!(config.suppressions.len(), 1);
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn parses_iso_dates_including_non_padded() {
        assert_eq!(parse_iso_date("2026-06-21"), Some((2026, 6, 21)));
        assert_eq!(parse_iso_date("2026-6-1"), Some((2026, 6, 1)));
        assert!(parse_iso_date("soon").is_none());
        assert!(parse_iso_date("2026-13-01").is_none());
        assert!(parse_iso_date("2026-06").is_none());
        assert!(parse_iso_date("2026-06-21-01").is_none());
    }

    #[test]
    fn iso_dates_order_chronologically_not_lexically() {
        // "2026-6-21" must sort after "2026-06-01", which a string compare
        // (where '6' > '0') would get wrong.
        assert!(parse_iso_date("2026-6-21") > parse_iso_date("2026-06-01"));
    }

    #[test]
    fn validate_rejects_malformed_expires() {
        let mut config = Config::default();
        config.suppressions.push(Suppression {
            rule: "SD001".to_string(),
            path: "package.json".to_string(),
            reason: "r".to_string(),
            expires: Some("soon".to_string()),
            line: None,
            package_manager: None,
            ecosystem: None,
        });
        assert!(validate(&config).is_err());
    }
}
