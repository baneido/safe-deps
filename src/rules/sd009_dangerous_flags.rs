//! SD009: Dangerous install flags.
//!
//! Flags CI `run` commands that bypass safety checks during dependency
//! installation: `--force`, `--legacy-peer-deps`, `--no-lockfile`,
//! `--ignore-platform-reqs`, `--break-system-packages`, and
//! `--no-build-isolation`. Each flag is only reported for the package managers
//! where it is a real install bypass, so unrelated uses (e.g. `git --force`)
//! are not flagged.

use crate::ci::command::{self};
use crate::ci::CiCommand;
use crate::ecosystems::PackageManager;
use crate::rule::{Confidence, Finding, Location, Rule, RuleId, Severity, WorkspaceInput};

pub struct Sd009;

impl Rule for Sd009 {
    fn id(&self) -> RuleId {
        RuleId::new("SD009")
    }

    fn summary(&self) -> &'static str {
        "CI install commands use a flag that bypasses dependency safety checks."
    }

    fn explanation(&self) -> &'static str {
        "Flags such as --force, --legacy-peer-deps, --no-lockfile, \
--ignore-platform-reqs, --break-system-packages, and --no-build-isolation \
suppress resolution, lockfile, or environment checks. They turn an enforced \
install into a best-effort one and can mask supply-chain or compatibility \
problems. Remove them or scope them to a documented exception."
    }

    fn is_workspace_rule(&self) -> bool {
        true
    }

    fn evaluate_workspace(&self, input: &WorkspaceInput) -> Vec<Finding> {
        let mut findings = Vec::new();
        for cmd in &input.ci.commands {
            for segment in command::segments(&cmd.command) {
                let Some(inv) = command::invocation(&segment) else {
                    continue;
                };
                // These flags are install bypasses; only gate-relevant install
                // commands count (so `npm cache clean --force` is not flagged).
                if !command::is_install(&inv) {
                    continue;
                }
                for spec in DANGEROUS_FLAGS {
                    if spec.applies_to(inv.pm) && command::has_flag(&segment, spec.flag) {
                        findings.push(make_finding(cmd, inv.pm, spec));
                    }
                }
            }
        }
        findings
    }
}

/// A dangerous flag and the package managers for which it is an install bypass.
struct FlagSpec {
    flag: &'static str,
    managers: &'static [PackageManager],
    severity: Severity,
    remediation: &'static str,
}

impl FlagSpec {
    fn applies_to(&self, pm: PackageManager) -> bool {
        self.managers.contains(&pm)
    }
}

use PackageManager::{Bun, Npm, Pip, Pnpm, Uv, Yarn};

const DANGEROUS_FLAGS: &[FlagSpec] = &[
    FlagSpec {
        flag: "--force",
        managers: &[Npm, Yarn, Pnpm, Bun],
        severity: Severity::Error,
        remediation: "remove --force; let the resolver enforce the lockfile.",
    },
    FlagSpec {
        flag: "--legacy-peer-deps",
        managers: &[Npm],
        severity: Severity::Warning,
        remediation: "fix peer dependency conflicts instead of using --legacy-peer-deps.",
    },
    FlagSpec {
        flag: "--no-lockfile",
        managers: &[Yarn, Bun],
        severity: Severity::Warning,
        remediation: "remove --no-lockfile so installs are reproducible from the lockfile.",
    },
    FlagSpec {
        flag: "--ignore-platform-reqs",
        managers: &[Yarn],
        severity: Severity::Warning,
        remediation: "remove --ignore-platform-reqs; platform mismatches should fail the install.",
    },
    FlagSpec {
        flag: "--break-system-packages",
        managers: &[Pip, Uv],
        severity: Severity::Error,
        remediation: "install into a virtual environment instead of --break-system-packages.",
    },
    FlagSpec {
        flag: "--no-build-isolation",
        managers: &[Pip, Uv],
        severity: Severity::Warning,
        remediation: "remove --no-build-isolation unless a build backend genuinely requires it.",
    },
];

fn make_finding(cmd: &CiCommand, pm: PackageManager, spec: &FlagSpec) -> Finding {
    Finding {
        rule_id: RuleId::new("SD009"),
        severity: spec.severity,
        confidence: Confidence::High,
        message: format!(
            "dangerous install flag `{}` in CI {} command",
            spec.flag, pm
        ),
        location: Some(Location::line(&cmd.file, cmd.line)),
        project_root: cmd.file.clone(),
        ecosystem: pm.ecosystem(),
        package_manager: Some(pm),
        remediation: Some(spec.remediation.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(cmd: &str) -> Vec<(&'static str, PackageManager)> {
        let mut out = Vec::new();
        for segment in command::segments(cmd) {
            let Some(inv) = command::invocation(&segment) else {
                continue;
            };
            if !command::is_install(&inv) {
                continue;
            }
            for spec in DANGEROUS_FLAGS {
                if spec.applies_to(inv.pm) && command::has_flag(&segment, spec.flag) {
                    out.push((spec.flag, inv.pm));
                }
            }
        }
        out
    }

    #[test]
    fn flags_force_for_package_managers() {
        assert_eq!(flags("npm install --force"), vec![("--force", Npm)]);
        assert_eq!(flags("pnpm install --force"), vec![("--force", Pnpm)]);
        // `npm ci --force` is still an install bypass.
        assert_eq!(flags("npm ci --force"), vec![("--force", Npm)]);
    }

    #[test]
    fn does_not_flag_force_for_unrelated_programs() {
        assert!(flags("git push --force").is_empty());
        assert!(flags("rm --force node_modules").is_empty());
        // Non-install package-manager commands are not install bypasses.
        assert!(flags("npm cache clean --force").is_empty());
        assert!(flags("pnpm dlx create-app --force").is_empty());
    }

    #[test]
    fn pip_break_system_packages_is_flagged() {
        assert_eq!(
            flags("pip install --break-system-packages requests"),
            vec![("--break-system-packages", Pip)]
        );
        assert_eq!(
            flags("python -m pip install --break-system-packages requests"),
            vec![("--break-system-packages", Pip)]
        );
    }

    #[test]
    fn legacy_peer_deps_is_npm_only() {
        assert_eq!(
            flags("npm install --legacy-peer-deps"),
            vec![("--legacy-peer-deps", Npm)]
        );
        assert!(flags("pnpm install --legacy-peer-deps").is_empty());
    }
}
