//! Ecosystem detection and fact extraction.
//!
//! Parsers produce normalized `ProjectFacts`. Rules turn facts into findings.
//! Parser code avoids policy decisions.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::filesystem::WorkspaceContext;

pub mod cargo;
pub mod go;
pub mod javascript;
pub mod python;
pub mod source;

pub use source::{
    classify_cargo_dependency, classify_go_replace_target, Dependency, DependencyGroup,
    DependencySource,
};

/// Whether a URL uses the plaintext `http` scheme. URL schemes are
/// case-insensitive (RFC 3986), so `HTTP://` is treated the same as `http://`.
/// `https` is never matched.
pub fn is_http_url(url: &str) -> bool {
    let trimmed = url.trim_start();
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("http://")
}

/// The directory containing a manifest, normalized so a manifest at the
/// workspace root yields `.` (matching the normalized entries in
/// [`WorkspaceContext::files`]). Shared by the ecosystem analyzers.
pub(crate) fn manifest_dir(manifest: &std::path::Path) -> PathBuf {
    manifest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Whether `ancestor` is a strict ancestor directory of `descendant`. A `.`
/// (workspace root) is an ancestor of everything except itself.
pub(crate) fn is_proper_ancestor(ancestor: &std::path::Path, descendant: &std::path::Path) -> bool {
    if ancestor == std::path::Path::new(".") {
        return descendant != std::path::Path::new(".");
    }
    descendant.starts_with(ancestor) && descendant != ancestor
}

/// Whether the workspace contains a file at the given relative path. O(1) via
/// the workspace path index.
pub(crate) fn contains_file(ctx: &WorkspaceContext, relative: &std::path::Path) -> bool {
    ctx.contains(relative)
}

/// Validates the syntax of a structured manifest/config file and returns a
/// warning diagnostic when it cannot be parsed. The format is chosen by
/// extension (TOML/JSON/YAML); line-based files such as `.npmrc` and `pip.conf`
/// have no recognized extension and are skipped. Analysis continues either way;
/// under `--strict-parser-errors` these diagnostics escalate the run to exit 4.
pub fn syntax_diagnostic(
    ctx: &WorkspaceContext,
    relative: &std::path::Path,
) -> Option<crate::diagnostics::Diagnostic> {
    let text = crate::filesystem::read_text(ctx, relative).ok()?;
    let ext = relative
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let parses = match ext.as_str() {
        "toml" => toml::from_str::<toml::Value>(&text).is_ok(),
        "json" => serde_json::from_str::<serde_json::Value>(&text).is_ok(),
        "yml" | "yaml" => serde_yaml::from_str::<serde_yaml::Value>(&text).is_ok(),
        _ => return None,
    };
    if parses {
        None
    } else {
        Some(crate::diagnostics::Diagnostic::warn_at(
            format!("could not parse {}", relative.display()),
            relative.to_path_buf(),
        ))
    }
}

/// Supported ecosystems for the MVP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    JavaScript,
    Python,
    Rust,
    Go,
}

impl Ecosystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            Ecosystem::JavaScript => "javascript",
            Ecosystem::Python => "python",
            Ecosystem::Rust => "rust",
            Ecosystem::Go => "go",
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
    Cargo,
    Go,
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
            PackageManager::Cargo => "cargo",
            PackageManager::Go => "go",
        }
    }

    pub fn ecosystem(&self) -> Ecosystem {
        match self {
            PackageManager::Npm
            | PackageManager::Yarn
            | PackageManager::Pnpm
            | PackageManager::Bun => Ecosystem::JavaScript,
            PackageManager::Pip | PackageManager::Uv => Ecosystem::Python,
            PackageManager::Cargo => Ecosystem::Rust,
            PackageManager::Go => Ecosystem::Go,
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

/// A setting value paired with the config/manifest file it was declared in.
///
/// `source` lets rules point a finding at the file that *actually* supplied the
/// offending value rather than guessing the first config file that happens to
/// exist. `None` means the originating file is unknown (the rule then falls back
/// to its usual location heuristic).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sourced<T> {
    pub value: T,
    pub source: Option<PathBuf>,
}

impl<T> Sourced<T> {
    /// A value whose originating file is known.
    pub fn from(value: T, source: PathBuf) -> Self {
        Self {
            value,
            source: Some(source),
        }
    }

    /// A value whose originating file is unknown.
    pub fn anonymous(value: T) -> Self {
        Self {
            value,
            source: None,
        }
    }
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
    /// 1-based line of `strict-ssl` in `.npmrc`, when known.
    pub strict_ssl_line: Option<u32>,
    pub registry: Option<String>,
    pub package_lock_enabled: Option<bool>,
    /// 1-based line of `package-lock` in `.npmrc`, when known.
    pub package_lock_line: Option<u32>,
    /// Any registry URLs (default or scoped) using plaintext HTTP.
    pub http_registries: Vec<String>,

    // yarn (.yarnrc.yml)
    pub yarn_generation: Option<YarnGeneration>,
    pub checksum_behavior: Option<String>,
    pub unsafe_http_whitelist: Vec<String>,

    // pip (pip.conf, requirements flags) and uv (uv.toml, pyproject [tool.uv]).
    // Index/host settings carry the file that declared each one so a finding
    // points at the real source when several config files coexist (e.g. both
    // `pip.conf` and `pip.ini`).
    pub trusted_hosts: Vec<Sourced<String>>,
    pub index_urls: Vec<Sourced<String>>,
    pub extra_index_urls: Vec<Sourced<String>>,
    pub allow_insecure_hosts: Vec<String>,
    pub index_strategy: Option<String>,
    pub require_hashes: Option<bool>,
    /// File that supplied an enabling `require-hashes`/hash-pin signal, when one
    /// did. Used by SD004 only as informational provenance.
    pub require_hashes_source: Option<PathBuf>,

    // bun (bunfig.toml)
    pub trusted_dependencies: Vec<String>,

    // pnpm (pnpm-workspace.yaml or package.json `pnpm` field)
    /// `dangerouslyAllowAllBuilds`: runs every dependency's build/postinstall
    /// script, bypassing the build allowlist (pnpm 10.9+). `None` when not set.
    pub pnpm_allow_all_builds: Option<bool>,
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
    /// Declared dependencies with their source classification, for SD006. Empty
    /// when the manifest declares none or could not be parsed.
    pub dependencies: Vec<Dependency>,
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
        Box::new(cargo::CargoAnalyzer),
        Box::new(go::GoAnalyzer),
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
        Ecosystem::Rust => "rust",
        Ecosystem::Go => "go",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_scheme_detection_is_case_insensitive() {
        assert!(is_http_url("http://example.com"));
        assert!(is_http_url("HTTP://example.com"));
        assert!(is_http_url("  Http://example.com"));
        assert!(!is_http_url("https://example.com"));
        assert!(!is_http_url("HTTPS://example.com"));
    }
}
