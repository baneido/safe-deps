//! SD001: Lockfile missing.
//!
//! A manifest with dependencies but no expected lockfile. Severity depends on
//! the project kind: applications error, libraries and unknown projects warn,
//! tooling-only projects are informational. pip has no conventional lockfile
//! and is not flagged.

use crate::ecosystems::{PackageManager, ProjectKind};
use crate::rule::{Confidence, Finding, Location, Profile, Rule, RuleId, RuleInput, Severity};

pub struct Sd001;

impl Rule for Sd001 {
    fn id(&self) -> RuleId {
        RuleId::new("SD001")
    }

    fn summary(&self) -> &'static str {
        "Lockfile missing for a manifest that declares dependencies."
    }

    fn explanation(&self) -> &'static str {
        "Committing a lockfile makes dependency resolution reproducible and \
reviewable. npm expects package-lock.json (or npm-shrinkwrap.json), Yarn \
expects yarn.lock, pnpm expects pnpm-lock.yaml, Bun 1.2+ expects bun.lock, \
and uv expects uv.lock. pip has no conventional lockfile and is assessed via \
--require-hashes (SD004) instead. In workspaces, a root-level lockfile \
covers member packages."
    }

    fn evaluate(&self, input: &RuleInput) -> Vec<Finding> {
        let facts = input.facts;
        let pm = facts.project.package_manager;

        if !facts.has_manifest_dependencies {
            return Vec::new();
        }
        if facts.covered_by_workspace_lockfile {
            return Vec::new();
        }

        match pm {
            PackageManager::Npm
            | PackageManager::Yarn
            | PackageManager::Pnpm
            | PackageManager::Uv
            | PackageManager::Cargo
            | PackageManager::Go => {
                if !facts.lockfiles.is_empty() {
                    return Vec::new();
                }
                vec![missing_finding(input, pm)]
            }
            PackageManager::Bun => {
                if !facts.lockfiles.is_empty() {
                    return Vec::new();
                }
                if facts.has_legacy_bun_lockfile {
                    vec![legacy_bun_finding(input)]
                } else {
                    vec![missing_finding(input, pm)]
                }
            }
            PackageManager::Pip => Vec::new(),
        }
    }
}

fn missing_finding(input: &RuleInput, pm: PackageManager) -> Finding {
    let facts = input.facts;
    let severity = sd001_severity(input, facts.project.kind);
    let lockfile_name = expected_lockfile_name(pm);
    Finding {
        rule_id: RuleId::new("SD001"),
        severity,
        confidence: Confidence::High,
        message: format!("manifest declares dependencies but no {lockfile_name} is committed."),
        location: facts.manifest.as_ref().map(|m| Location::file(&m.relative)),
        project_root: facts.project.root.clone(),
        ecosystem: facts.project.ecosystem,
        package_manager: Some(pm),
        remediation: Some(format!(
            "commit {lockfile_name} and install from it in CI with a frozen/locked command."
        )),
    }
}

fn legacy_bun_finding(input: &RuleInput) -> Finding {
    let facts = input.facts;
    Finding {
        rule_id: RuleId::new("SD001"),
        severity: Severity::Info,
        confidence: Confidence::High,
        message: "legacy bun.lockb detected; migrate to bun.lock (Bun 1.2+).".to_string(),
        location: facts.manifest.as_ref().map(|m| Location::file(&m.relative)),
        project_root: facts.project.root.clone(),
        ecosystem: facts.project.ecosystem,
        package_manager: Some(PackageManager::Bun),
        remediation: Some("run `bun install` with Bun 1.2+ to generate bun.lock.".to_string()),
    }
}

fn sd001_severity(input: &RuleInput, kind: ProjectKind) -> Severity {
    match (kind, input.profile) {
        (ProjectKind::Application, _) => Severity::Error,
        (ProjectKind::ToolingOnly, _) => Severity::Info,
        (ProjectKind::Library, Profile::Permissive) => Severity::Info,
        (ProjectKind::Library, _) => Severity::Warning,
        (ProjectKind::Unknown, Profile::Permissive) => Severity::Info,
        (ProjectKind::Unknown, _) => Severity::Warning,
    }
}

fn expected_lockfile_name(pm: PackageManager) -> &'static str {
    match pm {
        PackageManager::Npm => "package-lock.json (or npm-shrinkwrap.json)",
        PackageManager::Yarn => "yarn.lock",
        PackageManager::Pnpm => "pnpm-lock.yaml",
        PackageManager::Bun => "bun.lock",
        PackageManager::Uv => "uv.lock",
        PackageManager::Cargo => "Cargo.lock",
        PackageManager::Go => "go.sum",
        PackageManager::Pip => "lockfile",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ci::CiFacts;
    use crate::ecosystems::{FileFact, InstallSettings, Project, ProjectFacts};
    use crate::rule::Policy;
    use std::path::PathBuf;

    fn facts(pm: PackageManager, kind: ProjectKind, with_lockfile: bool) -> ProjectFacts {
        ProjectFacts {
            project: Project {
                root: PathBuf::from("pkg"),
                ecosystem: pm.ecosystem(),
                package_manager: pm,
                kind,
            },
            manifest: Some(FileFact {
                relative: PathBuf::from("pkg/package.json"),
            }),
            lockfiles: if with_lockfile {
                vec![FileFact {
                    relative: PathBuf::from("pkg/package-lock.json"),
                }]
            } else {
                Vec::new()
            },
            configs: Vec::new(),
            has_manifest_dependencies: true,
            install_settings: InstallSettings::default(),
            covered_by_workspace_lockfile: false,
            has_legacy_bun_lockfile: false,
            parse_diagnostics: Vec::new(),
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
        Sd001.evaluate(&input)
    }

    #[test]
    fn application_missing_lockfile_is_error() {
        let f = facts(PackageManager::Npm, ProjectKind::Application, false);
        let findings = eval(&f, Profile::Balanced);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn unknown_missing_lockfile_is_warning_in_balanced() {
        let f = facts(PackageManager::Npm, ProjectKind::Unknown, false);
        let findings = eval(&f, Profile::Balanced);
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn unknown_missing_lockfile_is_info_in_permissive() {
        let f = facts(PackageManager::Npm, ProjectKind::Unknown, false);
        let findings = eval(&f, Profile::Permissive);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn present_lockfile_yields_no_finding() {
        let f = facts(PackageManager::Npm, ProjectKind::Application, true);
        assert!(eval(&f, Profile::Balanced).is_empty());
    }

    #[test]
    fn no_dependencies_yields_no_finding() {
        let mut f = facts(PackageManager::Npm, ProjectKind::Application, false);
        f.has_manifest_dependencies = false;
        assert!(eval(&f, Profile::Balanced).is_empty());
    }

    #[test]
    fn workspace_coverage_suppresses_finding() {
        let mut f = facts(PackageManager::Npm, ProjectKind::Application, false);
        f.covered_by_workspace_lockfile = true;
        assert!(eval(&f, Profile::Balanced).is_empty());
    }

    #[test]
    fn pip_has_no_conventional_lockfile_finding() {
        let f = facts(PackageManager::Pip, ProjectKind::Application, false);
        assert!(eval(&f, Profile::Balanced).is_empty());
    }

    #[test]
    fn legacy_bun_lockb_is_info_migration() {
        let mut f = facts(PackageManager::Bun, ProjectKind::Application, false);
        f.has_legacy_bun_lockfile = true;
        let findings = eval(&f, Profile::Balanced);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].message.contains("bun.lockb"));
    }
}
