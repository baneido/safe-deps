//! SD002: Non-frozen CI install.
//!
//! Flags resolving install commands in CI `run` blocks: `npm install`/`npm i`,
//! `yarn install` without `--immutable`, `pnpm install` without
//! `--frozen-lockfile`, `bun install` without `--frozen-lockfile`, `uv sync`
//! without `--locked`, and (in the strict profile) `pip install -r` without
//! `--require-hashes`. Each finding points at the exact workflow line.

use crate::ci::command::{self};
use crate::ci::CiCommand;
use crate::ecosystems::PackageManager;
use crate::rule::{Confidence, Finding, Location, Profile, Rule, RuleId, Severity, WorkspaceInput};

pub struct Sd002;

impl Rule for Sd002 {
    fn id(&self) -> RuleId {
        RuleId::new("SD002")
    }

    fn summary(&self) -> &'static str {
        "CI installs should use a frozen/locked command, not a resolving one."
    }

    fn explanation(&self) -> &'static str {
        "CI should fail when the manifest and lockfile disagree. Use npm ci, \
yarn install --immutable, pnpm install --frozen-lockfile, \
bun install --frozen-lockfile (or bun ci), uv sync --locked, and \
pip install --require-hashes for deployment requirements. This rule reads \
CI command facts extracted from GitHub Actions workflows."
    }

    fn is_workspace_rule(&self) -> bool {
        true
    }

    fn evaluate_workspace(&self, input: &WorkspaceInput) -> Vec<Finding> {
        let mut findings = Vec::new();
        for cmd in &input.ci.commands {
            for segment in command::segments(&cmd.command) {
                if let Some(hit) = classify(&segment, input.profile) {
                    findings.push(make_finding(cmd, hit));
                }
            }
        }
        findings
    }
}

/// A detected non-frozen install, ready to turn into a finding.
struct Hit {
    pm: PackageManager,
    severity: Severity,
    confidence: Confidence,
    message: String,
    remediation: &'static str,
}

fn classify(tokens: &[String], profile: Profile) -> Option<Hit> {
    let program = command::program(tokens)?;
    let sub = command::subcommand(tokens);
    match program {
        "npm" => match sub {
            Some("install") | Some("i") | Some("add") if !is_global(tokens) => Some(Hit {
                pm: PackageManager::Npm,
                severity: Severity::Error,
                confidence: Confidence::High,
                message: format!("`npm {}` resolves dependencies in CI", sub.unwrap()),
                remediation: "use `npm ci`, which installs strictly from package-lock.json.",
            }),
            _ => None,
        },
        "yarn" => match sub {
            // Bare `yarn` is equivalent to `yarn install`.
            None | Some("install") => {
                if command::has_any_flag(
                    tokens,
                    &["--immutable", "--frozen-lockfile", "--immutable-cache"],
                ) {
                    None
                } else {
                    Some(Hit {
                        pm: PackageManager::Yarn,
                        severity: Severity::Warning,
                        confidence: Confidence::Medium,
                        message: "`yarn install` may resolve dependencies in CI".to_string(),
                        remediation:
                            "use `yarn install --immutable` (Berry) or `--frozen-lockfile` (v1).",
                    })
                }
            }
            _ => None,
        },
        "pnpm" => match sub {
            Some("install") | Some("i") => {
                if command::has_flag(tokens, "--frozen-lockfile") {
                    None
                } else {
                    Some(Hit {
                        pm: PackageManager::Pnpm,
                        severity: Severity::Warning,
                        confidence: Confidence::Medium,
                        message: "`pnpm install` is not pinned with --frozen-lockfile".to_string(),
                        remediation:
                            "use `pnpm install --frozen-lockfile` so CI fails on lockfile drift.",
                    })
                }
            }
            _ => None,
        },
        "bun" => match sub {
            Some("install") | Some("i") => {
                if command::has_flag(tokens, "--frozen-lockfile") {
                    None
                } else {
                    Some(Hit {
                        pm: PackageManager::Bun,
                        severity: Severity::Error,
                        confidence: Confidence::High,
                        message: "`bun install` resolves dependencies in CI".to_string(),
                        remediation: "use `bun install --frozen-lockfile` (or `bun ci`).",
                    })
                }
            }
            _ => None,
        },
        "uv" => match sub {
            Some("sync") => {
                if command::has_any_flag(tokens, &["--locked", "--frozen"]) {
                    None
                } else {
                    Some(Hit {
                        pm: PackageManager::Uv,
                        severity: Severity::Error,
                        confidence: Confidence::High,
                        message: "`uv sync` is not pinned with --locked".to_string(),
                        remediation: "use `uv sync --locked` to enforce the lockfile in CI.",
                    })
                }
            }
            _ => None,
        },
        "pip" | "pip3" => classify_pip(tokens, profile),
        // `python -m pip install ...`
        "python" | "python3" if is_python_pip(tokens) => classify_pip(tokens, profile),
        _ => None,
    }
}

fn classify_pip(tokens: &[String], profile: Profile) -> Option<Hit> {
    // Only flag hash-less requirement installs, and only in the strict profile,
    // matching the design's "strict deploy profiles" scope.
    if profile != Profile::Strict {
        return None;
    }
    let installs_requirements = tokens.windows(2).any(|w| w[0] == "install")
        && command::has_any_flag(tokens, &["-r", "--requirement"]);
    if !installs_requirements {
        return None;
    }
    if command::has_flag(tokens, "--require-hashes") {
        return None;
    }
    Some(Hit {
        pm: PackageManager::Pip,
        severity: Severity::Warning,
        confidence: Confidence::Medium,
        message: "`pip install -r` does not enforce hashes in a strict CI install".to_string(),
        remediation: "add `--require-hashes` and pin hashed requirements for deploys.",
    })
}

fn is_global(tokens: &[String]) -> bool {
    command::has_any_flag(tokens, &["-g", "--global", "--location=global"])
}

fn is_python_pip(tokens: &[String]) -> bool {
    let mut iter = tokens.iter();
    while let Some(t) = iter.next() {
        if t == "-m" {
            return iter.next().map(|m| m == "pip").unwrap_or(false);
        }
    }
    false
}

fn make_finding(cmd: &CiCommand, hit: Hit) -> Finding {
    let ecosystem = hit.pm.ecosystem();
    Finding {
        rule_id: RuleId::new("SD002"),
        severity: hit.severity,
        confidence: hit.confidence,
        message: hit.message,
        location: Some(Location::line(&cmd.file, cmd.line)),
        // CI findings are not tied to one project; anchor the sort/suppression
        // key on the workflow file that holds the command.
        project_root: cmd.file.clone(),
        ecosystem,
        package_manager: Some(hit.pm),
        remediation: Some(hit.remediation.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(cmd: &str, profile: Profile) -> Option<Hit> {
        let segs = command::segments(cmd);
        segs.iter().find_map(|s| classify(s, profile))
    }

    #[test]
    fn flags_npm_install_but_not_npm_ci() {
        assert!(one("npm install", Profile::Balanced).is_some());
        assert!(one("npm i", Profile::Balanced).is_some());
        assert!(one("npm ci", Profile::Balanced).is_none());
    }

    #[test]
    fn ignores_global_tool_installs() {
        assert!(one("npm install -g pnpm", Profile::Balanced).is_none());
        assert!(one("npm i --global typescript", Profile::Balanced).is_none());
    }

    #[test]
    fn yarn_immutable_is_safe() {
        assert!(one("yarn install", Profile::Balanced).is_some());
        assert!(one("yarn", Profile::Balanced).is_some());
        assert!(one("yarn install --immutable", Profile::Balanced).is_none());
        assert!(one("yarn install --frozen-lockfile", Profile::Balanced).is_none());
    }

    #[test]
    fn pnpm_and_bun_and_uv_frozen_flags() {
        assert!(one("pnpm install", Profile::Balanced).is_some());
        assert!(one("pnpm install --frozen-lockfile", Profile::Balanced).is_none());
        assert!(one("bun install", Profile::Balanced).is_some());
        assert!(one("bun install --frozen-lockfile", Profile::Balanced).is_none());
        assert!(one("uv sync", Profile::Balanced).is_some());
        assert!(one("uv sync --locked", Profile::Balanced).is_none());
    }

    #[test]
    fn pip_requires_hashes_only_in_strict() {
        assert!(one("pip install -r requirements.txt", Profile::Balanced).is_none());
        assert!(one("pip install -r requirements.txt", Profile::Strict).is_some());
        assert!(one(
            "pip install -r requirements.txt --require-hashes",
            Profile::Strict
        )
        .is_none());
        assert!(one("python -m pip install -r requirements.txt", Profile::Strict).is_some());
    }
}
