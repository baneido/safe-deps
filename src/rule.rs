//! Rule engine primitives: findings, severity, and the `Rule` trait.
//!
//! `Profile` and `Policy` live here (rather than in `config`) so that
//! `config` can depend on these types without creating a module cycle:
//! `rule` depends on `ecosystems` and `ci`, while `config` depends on `rule`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::ci::CiFacts;
use crate::ecosystems::{Ecosystem, PackageManager, ProjectFacts};

/// A rule identifier such as `SD001`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleId(pub String);

impl RuleId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<&str> for RuleId {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// Finding severity. CI exit decisions are severity-based.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
        }
    }

    pub fn rank(&self) -> u8 {
        match self {
            Severity::Error => 3,
            Severity::Warning => 2,
            Severity::Info => 1,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How certain the rule is about the finding. Display ordering considers both
/// severity and confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A source location for a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub file: PathBuf,
    pub line: Option<u32>,
    pub column: Option<u32>,
}

impl Location {
    pub fn file(file: impl Into<PathBuf>) -> Self {
        Self {
            file: file.into(),
            line: None,
            column: None,
        }
    }

    pub fn line(file: impl Into<PathBuf>, line: u32) -> Self {
        Self {
            file: file.into(),
            line: Some(line),
            column: None,
        }
    }
}

/// A policy violation emitted by a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: RuleId,
    pub severity: Severity,
    pub confidence: Confidence,
    pub message: String,
    pub location: Option<Location>,
    pub project_root: PathBuf,
    pub ecosystem: Ecosystem,
    pub package_manager: Option<PackageManager>,
    pub remediation: Option<String>,
}

impl Finding {
    /// A normalized path key used for deterministic sorting and suppression
    /// matching, relative to the workspace root. Path separators are normalized
    /// to `/` so suppression globs (always written with `/`) match on Windows,
    /// where `to_string_lossy` would otherwise yield backslashes.
    pub fn location_path_string(&self) -> String {
        let raw = match &self.location {
            Some(loc) => loc.file.to_string_lossy(),
            None => self.project_root.to_string_lossy(),
        };
        raw.replace(std::path::MAIN_SEPARATOR, "/")
    }
}

/// Analysis profile. Controls default severity for heuristic rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    #[default]
    Balanced,
    Strict,
    Permissive,
}

impl Profile {
    pub fn as_str(&self) -> &'static str {
        match self {
            Profile::Balanced => "balanced",
            Profile::Strict => "strict",
            Profile::Permissive => "permissive",
        }
    }
}

/// Project-level policy declarations. Teams can declare equivalent external
/// controls so the linter does not force one workflow.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub application_roots: Vec<String>,
    #[serde(default)]
    pub library_roots: Vec<String>,
    #[serde(default)]
    pub allow_local_path_dependencies: bool,
    #[serde(default)]
    pub allow_git_dependencies: bool,
    #[serde(default)]
    pub require_audit_in_ci: bool,
    #[serde(default)]
    pub external_audit: bool,
    #[serde(default)]
    pub external_audit_reason: Option<String>,
}

/// Input handed to a project-scoped rule, once per detected project.
pub struct RuleInput<'a> {
    pub facts: &'a ProjectFacts,
    pub ci: &'a CiFacts,
    pub profile: Profile,
    pub policy: &'a Policy,
}

/// Input handed to a workspace-scoped rule exactly once per run. CI-derived
/// rules (e.g. SD002, SD009) use this so a single unsafe CI command produces one
/// finding regardless of how many projects the workspace contains.
pub struct WorkspaceInput<'a> {
    pub projects: &'a [ProjectFacts],
    pub ci: &'a CiFacts,
    pub profile: Profile,
    pub policy: &'a Policy,
}

/// A rule evaluates normalized facts and emits findings.
///
/// Most rules are project-scoped and implement [`Rule::evaluate`], which runs
/// once per detected project. Rules whose facts are workspace-global (CI
/// commands that are not tied to a single project) instead set
/// [`Rule::is_workspace_rule`] and implement [`Rule::evaluate_workspace`], which
/// the engine calls exactly once.
pub trait Rule: Send + Sync {
    fn id(&self) -> RuleId;
    /// One-line summary used by `explain` and `list-rules`.
    fn summary(&self) -> &'static str;
    /// Longer explanation used by `explain`.
    fn explanation(&self) -> &'static str;
    /// Project-scoped evaluation, called once per detected project.
    fn evaluate(&self, _input: &RuleInput) -> Vec<Finding> {
        Vec::new()
    }
    /// Workspace-scoped evaluation, called once when [`Rule::is_workspace_rule`]
    /// returns true.
    fn evaluate_workspace(&self, _input: &WorkspaceInput) -> Vec<Finding> {
        Vec::new()
    }
    /// Whether this rule is workspace-scoped (evaluated once via
    /// [`Rule::evaluate_workspace`]) rather than per project.
    fn is_workspace_rule(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_rank_orders_error_highest() {
        assert!(Severity::Error.rank() > Severity::Warning.rank());
        assert!(Severity::Warning.rank() > Severity::Info.rank());
    }

    #[test]
    fn confidence_orders_high_above_low() {
        assert!(Confidence::High > Confidence::Medium);
        assert!(Confidence::Medium > Confidence::Low);
    }

    #[test]
    fn rule_id_equality_and_normalization_helpers() {
        let id = RuleId::new("SD001");
        assert_eq!(id, "SD001");
        assert_eq!(id.as_str(), "SD001");
        assert_eq!(id.to_string(), "SD001");
    }

    #[test]
    fn location_constructors() {
        let file_only = Location::file("a/b.toml");
        assert!(file_only.line.is_none());
        let with_line = Location::line("a/b.toml", 7);
        assert_eq!(with_line.line, Some(7));
    }

    #[test]
    fn package_manager_maps_to_ecosystem() {
        assert_eq!(PackageManager::Npm.ecosystem(), Ecosystem::JavaScript);
        assert_eq!(PackageManager::Uv.ecosystem(), Ecosystem::Python);
    }

    #[test]
    fn location_path_string_normalizes_separators() {
        // Built component-by-component so the path uses the OS separator; the
        // key must still use `/` so suppression globs match on Windows.
        let mut file = PathBuf::new();
        file.push("pkg");
        file.push("package.json");
        let finding = Finding {
            rule_id: RuleId::new("SD001"),
            severity: Severity::Warning,
            confidence: Confidence::High,
            message: String::new(),
            location: Some(Location::file(file)),
            project_root: PathBuf::from("pkg"),
            ecosystem: Ecosystem::JavaScript,
            package_manager: Some(PackageManager::Npm),
            remediation: None,
        };
        let key = finding.location_path_string();
        assert!(!key.contains('\\'));
        assert_eq!(key, "pkg/package.json");
    }
}
