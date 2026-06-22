//! SD008: Audit missing or disabled.
//!
//! Warns when a project has dependencies and its CI installs them but never runs
//! a dependency audit (`npm audit`, `yarn audit`, `pnpm audit`, `pip-audit`,
//! `safety`). The check never runs audits itself. Teams that audit elsewhere
//! (a separate workflow, SaaS scanner, or scheduled job) declare
//! `[policy] external_audit = true` to opt out.

use crate::ci::command::{self};
use crate::ci::CiFacts;
use crate::ecosystems::Ecosystem;
use crate::rule::{Confidence, Finding, Location, Rule, RuleId, RuleInput, Severity};

pub struct Sd008;

impl Rule for Sd008 {
    fn id(&self) -> RuleId {
        RuleId::new("SD008")
    }

    // `summary`/`explanation` are derived from the declarative metadata in
    // `rules::meta` (the single source, #66); only `evaluate` lives here.

    fn evaluate(&self, input: &RuleInput) -> Vec<Finding> {
        let facts = input.facts;
        // Nothing to audit without declared dependencies.
        if !facts.has_manifest_dependencies {
            return Vec::new();
        }
        // The team audits through an external control.
        if input.policy.external_audit {
            return Vec::new();
        }
        let ecosystem = facts.project.ecosystem;
        // Only flag when CI actually installs this ecosystem's dependencies but
        // never audits them; this avoids noise for projects without CI.
        if !ci_installs_ecosystem(input.ci, ecosystem) || ci_audits_ecosystem(input.ci, ecosystem) {
            return Vec::new();
        }

        let location = facts.manifest.as_ref().map(|m| Location::file(&m.relative));
        vec![Finding {
            rule_id: RuleId::new("SD008"),
            severity: Severity::Warning,
            confidence: Confidence::Medium,
            message: format!(
                "CI installs {ecosystem} dependencies but no audit command is visible"
            ),
            location,
            project_root: facts.project.root.clone(),
            ecosystem,
            package_manager: Some(facts.project.package_manager),
            remediation: Some(audit_remediation(ecosystem).to_string()),
        }]
    }
}

/// Whether any CI command installs dependencies for `ecosystem`.
fn ci_installs_ecosystem(ci: &CiFacts, ecosystem: Ecosystem) -> bool {
    ci_any_segment(ci, |tokens| {
        matches!(command::invocation(tokens), Some(inv)
            if inv.pm.ecosystem() == ecosystem && command::is_install(&inv))
    })
}

/// Whether any CI command runs a dependency audit for `ecosystem`.
fn ci_audits_ecosystem(ci: &CiFacts, ecosystem: Ecosystem) -> bool {
    ci_any_segment(ci, |tokens| is_audit(tokens, ecosystem))
}

fn ci_any_segment(ci: &CiFacts, mut predicate: impl FnMut(&[String]) -> bool) -> bool {
    ci.commands
        .iter()
        .flat_map(|c| command::segments(&c.command))
        .any(|segment| predicate(&segment))
}

fn is_audit(tokens: &[String], ecosystem: Ecosystem) -> bool {
    let Some(program) = command::program(tokens) else {
        return false;
    };
    match ecosystem {
        Ecosystem::JavaScript => {
            matches!(program, "npm" | "yarn" | "pnpm" | "bun")
                && command::subcommand(tokens) == Some("audit")
        }
        Ecosystem::Python => matches!(program, "pip-audit" | "safety"),
        // Rust/Go are not driven by SD008 yet (their CI installs aren't
        // recognized as install invocations, so this rule never fires for them).
        Ecosystem::Rust | Ecosystem::Go => false,
    }
}

fn audit_remediation(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::JavaScript => {
            "add an audit step (e.g. `npm audit`/`pnpm audit`) or set [policy] external_audit."
        }
        Ecosystem::Python => "add an audit step (e.g. `pip-audit`) or set [policy] external_audit.",
        Ecosystem::Rust => "add an audit step (e.g. `cargo audit`) or set [policy] external_audit.",
        Ecosystem::Go => "add an audit step (e.g. `govulncheck`) or set [policy] external_audit.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ci::CiCommand;

    fn ci(commands: &[&str]) -> CiFacts {
        CiFacts {
            commands: commands
                .iter()
                .enumerate()
                .map(|(i, c)| CiCommand {
                    file: std::path::PathBuf::from(".github/workflows/ci.yml"),
                    line: (i as u32) + 1,
                    command: (*c).to_string(),
                })
                .collect(),
            env: Vec::new(),
        }
    }

    #[test]
    fn install_without_audit_is_detected() {
        let facts = ci(&["npm ci"]);
        assert!(ci_installs_ecosystem(&facts, Ecosystem::JavaScript));
        assert!(!ci_audits_ecosystem(&facts, Ecosystem::JavaScript));
    }

    #[test]
    fn install_with_audit_clears() {
        let facts = ci(&["npm ci && npm audit"]);
        assert!(ci_installs_ecosystem(&facts, Ecosystem::JavaScript));
        assert!(ci_audits_ecosystem(&facts, Ecosystem::JavaScript));
    }

    #[test]
    fn bun_audit_clears() {
        let facts = ci(&["bun install --frozen-lockfile && bun audit"]);
        assert!(ci_installs_ecosystem(&facts, Ecosystem::JavaScript));
        assert!(ci_audits_ecosystem(&facts, Ecosystem::JavaScript));
    }

    #[test]
    fn python_audit_tools_recognized() {
        let facts = ci(&["pip install -r requirements.txt", "pip-audit"]);
        assert!(ci_installs_ecosystem(&facts, Ecosystem::Python));
        assert!(ci_audits_ecosystem(&facts, Ecosystem::Python));
    }

    #[test]
    fn ecosystems_do_not_cross_satisfy() {
        let facts = ci(&["pip install -r requirements.txt", "npm audit"]);
        // Python install present, but only a JS audit exists.
        assert!(ci_installs_ecosystem(&facts, Ecosystem::Python));
        assert!(!ci_audits_ecosystem(&facts, Ecosystem::Python));
    }
}
