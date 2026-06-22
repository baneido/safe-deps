//! SD004: Integrity/checksum validation disabled.
//!
//! Flags disabled lockfile or checksum behavior: npm `package-lock=false`,
//! Yarn Berry `checksumBehavior: ignore` (with `update` as a warning), and
//! pip deployment requirements without `--require-hashes` in strict profiles.

use crate::ecosystems::{PackageManager, YarnGeneration};
use crate::rule::{Confidence, Finding, Location, Profile, Rule, RuleId, RuleInput, Severity};

pub struct Sd004;

impl Rule for Sd004 {
    fn id(&self) -> RuleId {
        RuleId::new("SD004")
    }

    fn summary(&self) -> &'static str {
        "Integrity or checksum validation is disabled."
    }

    fn explanation(&self) -> &'static str {
        "Lockfile hashes and checksums should not be disabled or silently \
regenerated. Flagged signals include npm package-lock=false, Yarn Berry \
checksumBehavior: ignore (with update treated as suspicious), and pip \
deployment requirements that lack --require-hashes."
    }

    fn evaluate(&self, input: &RuleInput) -> Vec<Finding> {
        let facts = input.facts;
        let settings = &facts.install_settings;
        let pm = facts.project.package_manager;
        let mut findings = Vec::new();

        match pm {
            PackageManager::Npm => {
                if settings.package_lock_enabled == Some(false) {
                    findings.push(finding(
                        input,
                        "package-lock=false disables npm lockfile generation.",
                        Some("remove package-lock=false so npm records integrity metadata."),
                        config_loc_at(facts, ".npmrc", settings.package_lock_line),
                        Severity::Error,
                        Confidence::High,
                    ));
                }
            }
            PackageManager::Yarn => {
                let is_berry = settings.yarn_generation == Some(YarnGeneration::Berry);
                if !is_berry {
                    return findings;
                }
                match settings.checksum_behavior.as_deref() {
                    Some("ignore") => findings.push(finding(
                        input,
                        "checksumBehavior: ignore discards Yarn lockfile integrity checks.",
                        Some("set checksumBehavior to throw (default) or remove the override."),
                        config_loc(facts, ".yarnrc.yml"),
                        Severity::Error,
                        Confidence::High,
                    )),
                    Some("update") => findings.push(finding(
                        input,
                        "checksumBehavior: update silently regenerates checksums; review before accepting in CI.",
                        Some("prefer throw and update checksums through an explicit review process."),
                        config_loc(facts, ".yarnrc.yml"),
                        Severity::Warning,
                        Confidence::Medium,
                    )),
                    _ => {}
                }
            }
            PackageManager::Pip => {
                if !facts.has_manifest_dependencies {
                    return findings;
                }
                let require_hashes = settings.require_hashes.unwrap_or(false);
                if require_hashes {
                    return findings;
                }
                let severity = match input.profile {
                    Profile::Strict => Severity::Warning,
                    Profile::Balanced => Severity::Info,
                    Profile::Permissive => return findings,
                };
                findings.push(finding(
                    input,
                    "pip requirements lack --require-hashes; integrity is not enforced.",
                    Some("add --require-hashes and pin all requirements with hashes."),
                    pip_config_loc(facts).or_else(|| config_loc(facts, "requirements.txt")),
                    severity,
                    Confidence::Medium,
                ));
            }
            PackageManager::Pnpm
            | PackageManager::Bun
            | PackageManager::Uv
            | PackageManager::Cargo
            | PackageManager::Go => {
                // No static integrity-disable signal for Phase 1. CI command
                // flags such as pnpm --update-checksums and Bun lockfile-skip
                // env vars are handled in Phase 2.
            }
        }

        findings
    }
}

fn finding(
    input: &RuleInput,
    message: impl Into<String>,
    remediation: Option<&str>,
    location: Option<Location>,
    severity: Severity,
    confidence: Confidence,
) -> Finding {
    let facts = input.facts;
    Finding {
        rule_id: RuleId::new("SD004"),
        severity,
        confidence,
        message: message.into(),
        location,
        project_root: facts.project.root.clone(),
        ecosystem: facts.project.ecosystem,
        package_manager: Some(facts.project.package_manager),
        remediation: remediation.map(|s| s.to_string()),
    }
}

fn config_loc(facts: &crate::ecosystems::ProjectFacts, basename: &str) -> Option<Location> {
    facts
        .configs
        .iter()
        .find(|c| c.relative.file_name().and_then(|n| n.to_str()) == Some(basename))
        .map(|c| Location::file(&c.relative))
        .or_else(|| facts.manifest.as_ref().map(|m| Location::file(&m.relative)))
}

/// Searches only the `configs` list (no manifest fallback) for a file with
/// the given basename, returning its location when found.
fn config_only_loc(facts: &crate::ecosystems::ProjectFacts, basename: &str) -> Option<Location> {
    facts
        .configs
        .iter()
        .find(|c| c.relative.file_name().and_then(|n| n.to_str()) == Some(basename))
        .map(|c| Location::file(&c.relative))
}

/// Returns the location of whichever pip config file (`pip.conf` or `pip.ini`)
/// is present, or falls back to the manifest.
fn pip_config_loc(facts: &crate::ecosystems::ProjectFacts) -> Option<Location> {
    for basename in ["pip.conf", "pip.ini"] {
        if let Some(loc) = config_only_loc(facts, basename) {
            return Some(loc);
        }
    }
    facts.manifest.as_ref().map(|m| Location::file(&m.relative))
}

/// Like [`config_loc`] but attaches a 1-based line when one is known.
fn config_loc_at(
    facts: &crate::ecosystems::ProjectFacts,
    basename: &str,
    line: Option<u32>,
) -> Option<Location> {
    let mut loc = config_loc(facts, basename)?;
    if let Some(line) = line {
        loc.line = Some(line);
    }
    Some(loc)
}
