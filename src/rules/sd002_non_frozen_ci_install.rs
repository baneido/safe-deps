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

    // `summary`/`explanation` are derived from the declarative metadata in
    // `rules::meta` (the single source, #66); only `evaluate` lives here.

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
    let inv = command::invocation(tokens)?;
    let sub = inv.sub.as_deref();
    match inv.pm {
        PackageManager::Npm => match sub {
            // Only a *full* resolving install is flagged. `npm install <pkg>`
            // (a positional arg beyond the subcommand) adds a specific package
            // and rewrites the manifest/lockfile like `npm add`, for which
            // `npm ci` is not a substitute — so it is exempt, same as global
            // installs.
            Some("install") | Some("i") if !is_global(tokens) && !adds_specific_package(tokens) => {
                Some(Hit {
                    pm: PackageManager::Npm,
                    severity: Severity::Error,
                    confidence: Confidence::High,
                    message: format!("`npm {}` resolves dependencies in CI", sub.unwrap()),
                    remediation: "use `npm ci`, which installs strictly from package-lock.json.",
                })
            }
            _ => None,
        },
        // Bare `yarn` is equivalent to `yarn install`.
        PackageManager::Yarn => match sub {
            None | Some("install") => {
                // `--immutable-cache` only forbids cache mutations; it does NOT
                // freeze the lockfile and is NOT a substitute for `--immutable`.
                if command::has_any_flag(tokens, &["--immutable", "--frozen-lockfile"]) {
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
        PackageManager::Pnpm => match sub {
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
        PackageManager::Bun => match sub {
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
        PackageManager::Uv => match sub {
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
        // pip, pip3, `python -m pip`, and `uv pip` all normalize to pip here.
        PackageManager::Pip => classify_pip(tokens, profile, sub),
        PackageManager::Cargo => classify_cargo(tokens, sub),
        PackageManager::Go => classify_go(tokens, sub),
    }
}

/// Cargo subcommands that resolve and compile the dependency graph. Without
/// `--locked`/`--frozen` they may update `Cargo.lock`, so CI is not reproducible.
const CARGO_BUILD_SUBCOMMANDS: &[&str] =
    &["build", "test", "check", "run", "bench", "clippy", "doc"];

fn classify_cargo(tokens: &[String], sub: Option<&str>) -> Option<Hit> {
    let sub = sub?;
    if !CARGO_BUILD_SUBCOMMANDS.contains(&sub) {
        return None;
    }
    // `--frozen` implies `--locked` (plus `--offline`); either pins the lockfile.
    if command::has_any_flag(tokens, &["--locked", "--frozen"]) {
        return None;
    }
    Some(Hit {
        pm: PackageManager::Cargo,
        severity: Severity::Warning,
        confidence: Confidence::Medium,
        message: format!("`cargo {sub}` may update Cargo.lock in CI"),
        remediation: "use `--locked` (or `--frozen`) so CI fails on lockfile drift.",
    })
}

/// Go build-like subcommands that resolve the module graph.
const GO_BUILD_SUBCOMMANDS: &[&str] = &["build", "test", "run", "vet", "install"];

fn classify_go(tokens: &[String], sub: Option<&str>) -> Option<Hit> {
    let sub = sub?;
    if !GO_BUILD_SUBCOMMANDS.contains(&sub) {
        return None;
    }
    // `-mod=readonly` is the default since Go 1.16; the unsafe signal is an
    // explicit `-mod=mod`, which lets the build rewrite go.mod/go.sum.
    if !uses_mod_mod(tokens) {
        return None;
    }
    Some(Hit {
        pm: PackageManager::Go,
        severity: Severity::Warning,
        confidence: Confidence::Medium,
        message: format!("`go {sub} -mod=mod` lets CI rewrite go.mod/go.sum"),
        remediation: "drop `-mod=mod` to keep the default `-mod=readonly`, which fails on drift.",
    })
}

/// Whether the command passes `-mod=mod` (attached or space-separated).
fn uses_mod_mod(tokens: &[String]) -> bool {
    tokens.iter().enumerate().any(|(i, t)| {
        t == "-mod=mod" || (t == "-mod" && tokens.get(i + 1).map(String::as_str) == Some("mod"))
    })
}

fn classify_pip(tokens: &[String], profile: Profile, sub: Option<&str>) -> Option<Hit> {
    // Only flag hash-less requirement installs, and only in the strict profile,
    // matching the design's "strict deploy profiles" scope.
    if profile != Profile::Strict || sub != Some("install") || !installs_requirements(tokens) {
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

/// Whether a pip install references a requirements file, handling both the
/// separated (`-r req.txt`, `--requirement req.txt`) and attached (`-rreq.txt`)
/// forms.
fn installs_requirements(tokens: &[String]) -> bool {
    command::has_any_flag(tokens, &["-r", "--requirement"])
        || tokens.iter().any(|t| t.starts_with("-r") && t.len() > 2)
}

fn is_global(tokens: &[String]) -> bool {
    command::has_any_flag(tokens, &["-g", "--global", "--location=global"])
}

/// Whether the install names a specific package (a positional beyond the
/// subcommand), e.g. `npm install left-pad` — which adds a dependency rather
/// than resolving the whole tree.
fn adds_specific_package(tokens: &[String]) -> bool {
    command::positionals(tokens).len() > 1
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
    fn flags_npm_install_but_not_npm_ci_or_add() {
        assert!(one("npm install", Profile::Balanced).is_some());
        assert!(one("npm i", Profile::Balanced).is_some());
        assert!(one("npm ci", Profile::Balanced).is_none());
        // `npm add` is not a non-frozen reinstall; `npm ci` is no substitute.
        assert!(one("npm add left-pad", Profile::Balanced).is_none());
        // `npm install <pkg>` adds a specific package (like `npm add`); exempt.
        assert!(one("npm install --no-save eslint", Profile::Balanced).is_none());
        assert!(one("npm i left-pad", Profile::Balanced).is_none());
    }

    #[test]
    fn flags_cargo_build_without_locked() {
        assert!(one("cargo build", Profile::Balanced).is_some());
        assert!(one("cargo test", Profile::Balanced).is_some());
        assert!(one("cargo build --locked", Profile::Balanced).is_none());
        assert!(one("cargo test --frozen", Profile::Balanced).is_none());
        // Non-build subcommands are not gated.
        assert!(one("cargo fmt", Profile::Balanced).is_none());
    }

    #[test]
    fn flags_go_build_only_with_mod_mod() {
        // The default (-mod=readonly) is safe; only explicit -mod=mod is flagged.
        assert!(one("go build ./...", Profile::Balanced).is_none());
        assert!(one("go build -mod=mod ./...", Profile::Balanced).is_some());
        assert!(one("go test -mod mod ./...", Profile::Balanced).is_some());
        assert!(one("go build -mod=readonly ./...", Profile::Balanced).is_none());
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
        // `--immutable-cache` only prevents cache mutations; it does NOT freeze
        // the lockfile, so it must still be flagged as a finding.
        assert!(one("yarn install --immutable-cache", Profile::Balanced).is_some());
        // `--immutable --immutable-cache` together is safe because `--immutable` is present.
        assert!(one(
            "yarn install --immutable --immutable-cache",
            Profile::Balanced
        )
        .is_none());
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
        // `uv pip install` is uv's pip interface and is checked like pip.
        assert!(one("uv pip install -r requirements.txt", Profile::Strict).is_some());
        // Attached `-rFILE` form is also recognized.
        assert!(one("pip install -rrequirements.txt", Profile::Strict).is_some());
        // A non-install pip subcommand is not flagged.
        assert!(one("pip download -r requirements.txt", Profile::Strict).is_none());
    }

    // Tests for value-taking option handling (issue #87).

    #[test]
    fn monorepo_prefix_flag_is_transparent() {
        // `npm --prefix web ci` must be recognized as `npm ci` (a frozen install).
        assert!(one("npm --prefix web ci", Profile::Balanced).is_none());
        // `pnpm --filter app install` without --frozen-lockfile should still fire.
        assert!(one("pnpm --filter app install", Profile::Balanced).is_some());
        // `yarn --cwd web install` without --immutable should still fire.
        assert!(one("yarn --cwd web install", Profile::Balanced).is_some());
        // `uv --project . sync` without --locked should still fire.
        assert!(one("uv --project . sync", Profile::Balanced).is_some());
    }

    #[test]
    fn workspace_flag_value_not_counted_as_added_package() {
        // `npm install --workspace packages/app` is a full workspace install, not
        // adding a specific package — SD002 must fire.
        assert!(one("npm install --workspace packages/app", Profile::Balanced).is_some());
        // `npm install lodash` adds a specific package — SD002 must NOT fire.
        assert!(one("npm install lodash", Profile::Balanced).is_none());
        // `-w` short form of --workspace should also work.
        assert!(one("npm install -w packages/app", Profile::Balanced).is_some());
        // `npm ci` is the frozen form, so a workspace-scoped `npm ci` must NOT
        // fire even though the workspace value is a positional.
        assert!(one("npm --prefix packages/app ci", Profile::Balanced).is_none());
    }

    #[test]
    fn pnpm_filter_frozen_is_safe() {
        // `pnpm --filter app install --frozen-lockfile` is safe (flag present).
        assert!(one(
            "pnpm --filter app install --frozen-lockfile",
            Profile::Balanced
        )
        .is_none());
    }

    #[test]
    fn yarn_cwd_immutable_is_safe() {
        // `yarn --cwd web install --immutable` is safe (flag present).
        assert!(one("yarn --cwd web install --immutable", Profile::Balanced).is_none());
    }

    #[test]
    fn uv_project_locked_is_safe() {
        // `uv --project . sync --locked` is safe (flag present).
        assert!(one("uv --project . sync --locked", Profile::Balanced).is_none());
    }
}
