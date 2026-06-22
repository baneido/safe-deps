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
                // A project-wide require_hashes set via pip.conf covers all files.
                let global_require_hashes = settings.require_hashes.unwrap_or(false);
                if global_require_hashes {
                    return findings;
                }
                let severity = match input.profile {
                    Profile::Strict => Severity::Warning,
                    Profile::Balanced => Severity::Info,
                    Profile::Permissive => return findings,
                };
                if facts.pip_requirements.is_empty() {
                    // No per-file data (e.g. older analysis path): emit a single
                    // project-level finding as before.
                    findings.push(finding(
                        input,
                        "pip requirements lack --require-hashes; integrity is not enforced.",
                        Some("add --require-hashes and pin all requirements with hashes."),
                        pip_config_loc(facts).or_else(|| config_loc(facts, "requirements.txt")),
                        severity,
                        Confidence::Medium,
                    ));
                } else {
                    // Emit one finding per requirements file that lacks require-hashes
                    // enforcement, so a file with enforcement does not mask one without.
                    for req_file in &facts.pip_requirements {
                        if !req_file.has_requirements || req_file.has_hashes {
                            continue;
                        }
                        findings.push(finding(
                            input,
                            "pip requirements lack --require-hashes; integrity is not enforced.",
                            Some("add --require-hashes and pin all requirements with hashes."),
                            Some(Location::file(&req_file.relative)),
                            severity,
                            Confidence::Medium,
                        ));
                    }
                }
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

/// Returns the location of whichever pip config file (`pip.conf` or `pip.ini`)
/// is present, or falls back to the manifest. Delegates to the shared helper in
/// `rules::pip_config_loc` to keep the SD003/SD004 heuristics in sync.
fn pip_config_loc(facts: &crate::ecosystems::ProjectFacts) -> Option<Location> {
    crate::rules::pip_config_loc(facts)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ci::CiFacts;
    use crate::ecosystems::{
        Ecosystem, FileFact, InstallSettings, PipRequirementFile, Project, ProjectFacts,
        ProjectKind,
    };
    use crate::rule::Policy;
    use std::path::PathBuf;

    fn pip_facts(pip_files: Vec<PipRequirementFile>, global_require_hashes: bool) -> ProjectFacts {
        let has_requirements = pip_files.iter().any(|f| f.has_requirements);
        let manifest = pip_files.first().map(|f| FileFact {
            relative: f.relative.clone(),
        });
        let mut install_settings = InstallSettings::default();
        if global_require_hashes {
            install_settings.require_hashes = Some(true);
        }
        ProjectFacts {
            project: Project {
                root: PathBuf::from("."),
                ecosystem: Ecosystem::Python,
                package_manager: PackageManager::Pip,
                kind: ProjectKind::Unknown,
            },
            manifest,
            lockfiles: Vec::new(),
            configs: Vec::new(),
            has_manifest_dependencies: has_requirements,
            dependencies: Vec::new(),
            install_settings,
            covered_by_workspace_lockfile: false,
            has_legacy_bun_lockfile: false,
            parse_diagnostics: Vec::new(),
            pip_requirements: pip_files,
        }
    }

    fn eval(facts: &ProjectFacts, profile: Profile) -> Vec<Finding> {
        let ci = CiFacts::empty();
        let policy = Policy::default();
        let input = RuleInput {
            facts,
            ci: &ci,
            profile,
            policy: &policy,
        };
        Sd004.evaluate(&input)
    }

    fn req_file(path: &str, has_hashes: bool) -> PipRequirementFile {
        PipRequirementFile {
            relative: PathBuf::from(path),
            has_hashes,
            has_requirements: true,
        }
    }

    #[test]
    fn single_unhashed_file_emits_finding_at_that_file() {
        let facts = pip_facts(vec![req_file("requirements.txt", false)], false);
        let findings = eval(&facts, Profile::Strict);
        assert_eq!(findings.len(), 1);
        let loc = findings[0].location.as_ref().unwrap();
        assert_eq!(loc.file, PathBuf::from("requirements.txt"));
    }

    #[test]
    fn single_hashed_file_emits_no_finding() {
        let facts = pip_facts(vec![req_file("requirements.txt", true)], false);
        let findings = eval(&facts, Profile::Strict);
        assert!(findings.is_empty());
    }

    #[test]
    fn hashed_dev_file_does_not_mask_unhashed_prod_file() {
        // The core bug: requirements.txt (prod, no hashes) + requirements-dev.txt
        // (dev, with hashes) must produce a finding for requirements.txt only.
        let facts = pip_facts(
            vec![
                req_file("requirements.txt", false),
                req_file("requirements-dev.txt", true),
            ],
            false,
        );
        let findings = eval(&facts, Profile::Strict);
        assert_eq!(findings.len(), 1, "expected exactly one finding");
        let loc = findings[0].location.as_ref().unwrap();
        assert_eq!(loc.file, PathBuf::from("requirements.txt"));
    }

    #[test]
    fn both_files_unhashed_emit_two_findings() {
        let facts = pip_facts(
            vec![
                req_file("requirements.txt", false),
                req_file("requirements-dev.txt", false),
            ],
            false,
        );
        let findings = eval(&facts, Profile::Strict);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn both_files_hashed_emit_no_finding() {
        let facts = pip_facts(
            vec![
                req_file("requirements.txt", true),
                req_file("requirements-dev.txt", true),
            ],
            false,
        );
        let findings = eval(&facts, Profile::Strict);
        assert!(findings.is_empty());
    }

    #[test]
    fn global_require_hashes_suppresses_all_findings() {
        // pip.conf --require-hashes covers all files even if none have hash pins.
        let facts = pip_facts(
            vec![
                req_file("requirements.txt", false),
                req_file("requirements-dev.txt", false),
            ],
            true,
        );
        let findings = eval(&facts, Profile::Strict);
        assert!(findings.is_empty());
    }

    #[test]
    fn permissive_profile_suppresses_pip_findings() {
        let facts = pip_facts(vec![req_file("requirements.txt", false)], false);
        let findings = eval(&facts, Profile::Permissive);
        assert!(findings.is_empty());
    }

    #[test]
    fn balanced_profile_emits_info_severity() {
        let facts = pip_facts(vec![req_file("requirements.txt", false)], false);
        let findings = eval(&facts, Profile::Balanced);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn strict_profile_emits_warning_severity() {
        let facts = pip_facts(vec![req_file("requirements.txt", false)], false);
        let findings = eval(&facts, Profile::Strict);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
    }
}
