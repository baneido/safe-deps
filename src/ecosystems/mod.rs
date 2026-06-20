//! Ecosystem detection and fact extraction.
//!
//! Parsers produce normalized `ProjectFacts`. Rules turn facts into findings.
//! Parser code avoids policy decisions.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::filesystem::WorkspaceContext;

pub mod javascript;
pub mod python;

/// Supported ecosystems for the MVP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    JavaScript,
    Python,
}

impl Ecosystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            Ecosystem::JavaScript => "javascript",
            Ecosystem::Python => "python",
        }
    }
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Package managers supported in the MVP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageManager {
    Npm,
    Yarn,
    Pnpm,
    Bun,
    Pip,
    Uv,
}

impl PackageManager {
    pub fn as_str(&self) -> &'static str {
        match self {
            PackageManager::Npm => "npm",
            PackageManager::Yarn => "yarn",
            PackageManager::Pnpm => "pnpm",
            PackageManager::Bun => "bun",
            PackageManager::Pip => "pip",
            PackageManager::Uv => "uv",
        }
    }

    pub fn ecosystem(&self) -> Ecosystem {
        match self {
            PackageManager::Npm
            | PackageManager::Yarn
            | PackageManager::Pnpm
            | PackageManager::Bun => Ecosystem::JavaScript,
            PackageManager::Pip | PackageManager::Uv => Ecosystem::Python,
        }
    }
}

impl std::fmt::Display for PackageManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Conservative classification of a project's primary role.
///
/// `Unknown` stays unknown unless the tool has strong evidence or the user
/// configures application/library roots. Unknown projects receive lower
/// severity for rules where library/application policy differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProjectKind {
    Application,
    Library,
    ToolingOnly,
    Unknown,
}

/// A detected project root.
#[derive(Debug, Clone)]
pub struct Project {
    pub root: PathBuf,
    pub ecosystem: Ecosystem,
    pub package_manager: PackageManager,
    pub kind: ProjectKind,
}

/// A file attached to a project, with its path relative to the workspace root.
#[derive(Debug, Clone)]
pub struct FileFact {
    pub relative: PathBuf,
}

/// Yarn major generation. SD002 and SD004 apply different settings by version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YarnGeneration {
    /// Yarn v1 (classic).
    V1,
    /// Yarn Berry (v2+).
    Berry,
}

/// Normalized security-relevant install settings extracted from config files.
///
/// Only the fields relevant to the project's package manager are populated.
/// `None`/empty means "not declared in config", which rules treat distinctly
/// from an explicit unsafe value.
#[derive(Debug, Clone, Default)]
pub struct InstallSettings {
    // npm and pnpm (.npmrc)
    pub strict_ssl: Option<bool>,
    pub registry: Option<String>,
    pub package_lock_enabled: Option<bool>,
    /// Any registry URLs (default or scoped) using plaintext HTTP.
    pub http_registries: Vec<String>,

    // yarn (.yarnrc.yml)
    pub yarn_generation: Option<YarnGeneration>,
    pub checksum_behavior: Option<String>,
    pub unsafe_http_whitelist: Vec<String>,

    // pip (pip.conf, requirements flags) and uv (uv.toml, pyproject [tool.uv])
    pub trusted_hosts: Vec<String>,
    pub index_urls: Vec<String>,
    pub extra_index_urls: Vec<String>,
    pub allow_insecure_hosts: Vec<String>,
    pub index_strategy: Option<String>,
    pub require_hashes: Option<bool>,

    // bun (bunfig.toml)
    pub trusted_dependencies: Vec<String>,
}

/// Normalized facts about a detected project, consumed by rules.
#[derive(Debug, Clone)]
pub struct ProjectFacts {
    pub project: Project,
    pub manifest: Option<FileFact>,
    pub lockfiles: Vec<FileFact>,
    pub configs: Vec<FileFact>,
    /// Whether the manifest declares any runtime or dev dependencies. Used by
    /// SD001 to avoid flagging empty manifests.
    pub has_manifest_dependencies: bool,
    pub install_settings: InstallSettings,
    /// Whether a parent workspace root provides a covering lockfile for this
    /// project. Avoids false positives in monorepos.
    pub covered_by_workspace_lockfile: bool,
    /// True when a legacy `bun.lockb` is present instead of `bun.lock`.
    pub has_legacy_bun_lockfile: bool,
    /// Warning-level diagnostics for files the analyzer tried to parse but could
    /// not (malformed JSON/TOML). Analysis continues with partial facts; under
    /// `--strict-parser-errors` these escalate the run to exit code 4.
    pub parse_diagnostics: Vec<crate::diagnostics::Diagnostic>,
}

/// Analyzes a workspace for projects of a given ecosystem family.
pub trait Analyzer {
    fn name(&self) -> &'static str;
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Project>;
    fn facts(&self, project: &Project, ctx: &WorkspaceContext) -> Result<ProjectFacts, EcoError>;
}

/// Returns all built-in analyzers.
pub fn analyzers() -> Vec<Box<dyn Analyzer>> {
    vec![
        Box::new(javascript::JavaScriptAnalyzer),
        Box::new(python::PythonAnalyzer),
    ]
}

/// Detect all projects across all ecosystems.
pub fn detect_all(ctx: &WorkspaceContext) -> Vec<Project> {
    let mut projects = Vec::new();
    for analyzer in analyzers() {
        projects.extend(analyzer.detect(ctx));
    }
    projects
}

/// Extract facts for a project using the matching analyzer.
pub fn facts_for(project: &Project, ctx: &WorkspaceContext) -> Result<ProjectFacts, EcoError> {
    for analyzer in analyzers() {
        if analyzer.name() == ecosystem_analyzer_name(project.ecosystem) {
            return analyzer.facts(project, ctx);
        }
    }
    Err(EcoError::UnknownEcosystem(project.ecosystem.to_string()))
}

fn ecosystem_analyzer_name(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::JavaScript => "javascript",
        Ecosystem::Python => "python",
    }
}

/// Errors produced by ecosystem fact extraction.
#[derive(Debug, thiserror::Error)]
pub enum EcoError {
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("no analyzer registered for ecosystem {0}")]
    UnknownEcosystem(String),
}
