//! SD008: Audit missing or disabled.
//!
//! Warns when CI installs an ecosystem's dependencies but never runs a
//! dependency audit (`npm audit`, `yarn audit`, `pnpm audit`, `pip-audit`,
//! `safety`). The check never runs audits itself. Teams that audit elsewhere
//! (a separate workflow, SaaS scanner, or scheduled job) declare
//! `[policy] external_audit = true` to opt out.
//!
//! This is a **workspace-scoped** rule. CI commands are not reliably tied to a
//! single project (a monorepo's workflow installs and audits several packages
//! from the repository root), so SD008 reasons over the whole workspace's CI
//! facts and emits at most one finding per ecosystem. Evaluating it per project
//! would both duplicate the same finding once per package and let one package's
//! audit command count as coverage for an unrelated sibling.

use crate::ci::command::{self};
use crate::ci::{CiCommand, CiFacts};
use crate::ecosystems::{Ecosystem, PackageManager};
use crate::rule::{Confidence, Finding, Location, Rule, RuleId, Severity, WorkspaceInput};

pub struct Sd008;

/// Ecosystems whose CI installs SD008 recognizes. Rust/Go installs are not
/// modeled as install invocations, so they never reach this rule.
const AUDITED_ECOSYSTEMS: &[Ecosystem] = &[Ecosystem::JavaScript, Ecosystem::Python];

impl Rule for Sd008 {
    fn id(&self) -> RuleId {
        RuleId::new("SD008")
    }

    fn summary(&self) -> &'static str {
        "CI installs dependencies but no audit command is visible."
    }

    fn explanation(&self) -> &'static str {
        "When CI installs dependencies, a dependency audit step gives a path to \
catch known-vulnerable packages. Use npm/yarn/pnpm audit or pip-audit/safety. \
If audits run in a separate workflow, a SaaS scanner, or an organization-wide \
schedule, declare [policy] external_audit = true to acknowledge that control. \
This rule reads CI command facts extracted from GitHub Actions, GitLab CI, and \
CircleCI configurations."
    }

    fn is_workspace_rule(&self) -> bool {
        true
    }

    fn evaluate_workspace(&self, input: &WorkspaceInput) -> Vec<Finding> {
        // The team audits through an external control.
        if input.policy.external_audit {
            return Vec::new();
        }
        let mut findings = Vec::new();
        for &ecosystem in AUDITED_ECOSYSTEMS {
            // Anchor the finding to the first install command for this ecosystem;
            // its absence is also the install gate (no install -> nothing to
            // audit). An audit anywhere in the workspace's CI clears it.
            let Some((cmd, pm)) = first_install(input.ci, ecosystem) else {
                continue;
            };
            if ci_audits_ecosystem(input.ci, ecosystem) {
                continue;
            }
            findings.push(Finding {
                rule_id: RuleId::new("SD008"),
                severity: Severity::Warning,
                confidence: Confidence::Medium,
                message: format!(
                    "CI installs {ecosystem} dependencies but no audit command is visible"
                ),
                location: Some(Location::line(&cmd.file, cmd.line)),
                // CI findings are not tied to one project; anchor the
                // sort/suppression key on the workflow file that holds the
                // install command.
                project_root: cmd.file.clone(),
                ecosystem,
                package_manager: Some(pm),
                remediation: Some(audit_remediation(ecosystem).to_string()),
            });
        }
        findings
    }
}

/// The first CI command (in `(file, line)` order) that installs `ecosystem`'s
/// dependencies, along with the package manager it uses. `None` if CI never
/// installs that ecosystem.
fn first_install(ci: &CiFacts, ecosystem: Ecosystem) -> Option<(&CiCommand, PackageManager)> {
    ci.commands.iter().find_map(|cmd| {
        command::segments(&cmd.command).iter().find_map(|segment| {
            let inv = command::invocation(segment)?;
            (inv.pm.ecosystem() == ecosystem && command::is_install(&inv)).then_some((cmd, inv.pm))
        })
    })
}

/// Whether any CI command runs a dependency audit for `ecosystem`.
fn ci_audits_ecosystem(ci: &CiFacts, ecosystem: Ecosystem) -> bool {
    ci.commands
        .iter()
        .flat_map(|c| command::segments(&c.command))
        .any(|segment| is_audit(&segment, ecosystem))
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
    use crate::rule::{Policy, Profile};

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

    fn findings(ci: &CiFacts) -> Vec<Finding> {
        let policy = Policy::default();
        let input = WorkspaceInput {
            ci,
            profile: Profile::Balanced,
            policy: &policy,
        };
        Sd008.evaluate_workspace(&input)
    }

    fn install_present(ci: &CiFacts, eco: Ecosystem) -> bool {
        first_install(ci, eco).is_some()
    }

    #[test]
    fn install_without_audit_is_detected() {
        let facts = ci(&["npm ci"]);
        assert!(install_present(&facts, Ecosystem::JavaScript));
        assert!(!ci_audits_ecosystem(&facts, Ecosystem::JavaScript));
        let f = findings(&facts);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].ecosystem, Ecosystem::JavaScript);
        assert_eq!(f[0].package_manager, Some(PackageManager::Npm));
    }

    #[test]
    fn install_with_audit_clears() {
        let facts = ci(&["npm ci && npm audit"]);
        assert!(install_present(&facts, Ecosystem::JavaScript));
        assert!(ci_audits_ecosystem(&facts, Ecosystem::JavaScript));
        assert!(findings(&facts).is_empty());
    }

    #[test]
    fn bun_audit_clears() {
        let facts = ci(&["bun install --frozen-lockfile && bun audit"]);
        assert!(install_present(&facts, Ecosystem::JavaScript));
        assert!(ci_audits_ecosystem(&facts, Ecosystem::JavaScript));
        assert!(findings(&facts).is_empty());
    }

    #[test]
    fn python_audit_tools_recognized() {
        let facts = ci(&["pip install -r requirements.txt", "pip-audit"]);
        assert!(install_present(&facts, Ecosystem::Python));
        assert!(ci_audits_ecosystem(&facts, Ecosystem::Python));
        assert!(findings(&facts).is_empty());
    }

    #[test]
    fn ecosystems_do_not_cross_satisfy() {
        let facts = ci(&["pip install -r requirements.txt", "npm audit"]);
        // Python install present, but only a JS audit exists.
        assert!(install_present(&facts, Ecosystem::Python));
        assert!(!ci_audits_ecosystem(&facts, Ecosystem::Python));
        let f = findings(&facts);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].ecosystem, Ecosystem::Python);
    }

    #[test]
    fn no_install_no_finding() {
        // Nothing to audit if CI never installs anything for the ecosystem.
        let facts = ci(&["npm run build"]);
        assert!(!install_present(&facts, Ecosystem::JavaScript));
        assert!(findings(&facts).is_empty());
    }

    #[test]
    fn fires_once_for_one_ecosystem_regardless_of_install_count() {
        // Two separate JS install commands (e.g. one per package in a monorepo
        // workflow) must still yield a single SD008 finding, not one per command.
        let facts = ci(&["cd packages/app && npm ci", "cd packages/lib && npm ci"]);
        let f = findings(&facts);
        assert_eq!(f.len(), 1, "expected a single JS finding: {f:?}");
        assert_eq!(f[0].ecosystem, Ecosystem::JavaScript);
    }

    #[test]
    fn one_package_audit_clears_the_workspace_ecosystem() {
        // An audit anywhere in the workspace's CI clears SD008 for that
        // ecosystem; the rule does not attempt per-package attribution.
        let facts = ci(&[
            "cd packages/app && npm ci && npm audit",
            "cd packages/lib && npm ci",
        ]);
        assert!(findings(&facts).is_empty());
    }

    #[test]
    fn external_audit_policy_opts_out() {
        let facts = ci(&["npm ci"]);
        let policy = Policy {
            external_audit: true,
            ..Policy::default()
        };
        let input = WorkspaceInput {
            ci: &facts,
            profile: Profile::Balanced,
            policy: &policy,
        };
        assert!(Sd008.evaluate_workspace(&input).is_empty());
    }
}
