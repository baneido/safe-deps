//! SD005: Install-time script/build bypass.
//!
//! Flags configuration that broadly enables dependency build/lifecycle scripts,
//! turning a normally-gated install into one that runs arbitrary code from every
//! dependency: pnpm's `dangerouslyAllowAllBuilds` and a Bun `trustedDependencies`
//! wildcard. Specific, named allowlist entries are the safe pattern and are not
//! flagged. The finding is only raised when the unsafe setting is actually
//! present, which inherently respects the version gate (older managers cannot
//! set it).

use crate::ecosystems::{PackageManager, ProjectFacts};
use crate::rule::{Confidence, Finding, Location, Rule, RuleId, RuleInput, Severity};
use crate::rules::config_loc;

pub struct Sd005;

impl Rule for Sd005 {
    fn id(&self) -> RuleId {
        RuleId::new("SD005")
    }

    fn summary(&self) -> &'static str {
        "Dependency build/lifecycle scripts are broadly enabled."
    }

    fn explanation(&self) -> &'static str {
        "Running build or postinstall scripts for every dependency lets any \
package in the tree execute code at install time. pnpm's \
dangerouslyAllowAllBuilds and a Bun trustedDependencies wildcard remove the \
build allowlist that normally contains this. Prefer an explicit allowlist \
(pnpm onlyBuiltDependencies, named Bun trustedDependencies) scoped to the few \
packages that genuinely need a build step."
    }

    fn evaluate(&self, input: &RuleInput) -> Vec<Finding> {
        let facts = input.facts;
        let settings = &facts.install_settings;
        let mut findings = Vec::new();

        if settings.pnpm_allow_all_builds == Some(true) {
            findings.push(finding(
                facts,
                "pnpm `dangerouslyAllowAllBuilds` runs build scripts for every dependency",
                "remove dangerouslyAllowAllBuilds and allowlist builds via onlyBuiltDependencies.",
                config_loc(facts, "pnpm-workspace.yaml"),
            ));
        }

        if facts.project.package_manager == PackageManager::Bun
            && settings.trusted_dependencies.iter().any(|d| d == "*")
        {
            findings.push(finding(
                facts,
                "Bun `trustedDependencies` contains a `*` wildcard, trusting every dependency's scripts",
                "list only the specific packages that need install scripts instead of `*`.",
                config_loc(facts, "bunfig.toml"),
            ));
        }

        findings
    }
}

fn finding(
    facts: &ProjectFacts,
    message: &str,
    remediation: &str,
    location: Option<Location>,
) -> Finding {
    Finding {
        rule_id: RuleId::new("SD005"),
        severity: Severity::Error,
        confidence: Confidence::High,
        message: message.to_string(),
        location,
        project_root: facts.project.root.clone(),
        ecosystem: facts.project.ecosystem,
        package_manager: Some(facts.project.package_manager),
        remediation: Some(remediation.to_string()),
    }
}
