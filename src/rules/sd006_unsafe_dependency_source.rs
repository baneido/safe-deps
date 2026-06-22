//! SD006: Unsafe dependency source.
//!
//! Flags dependencies that resolve from something other than a registry version
//! in a way that weakens reproducibility or integrity: floating Git refs,
//! SSH-based VCS dependencies, direct tarball URLs, local path dependencies in
//! production groups, and Cargo `[source]` `replace-with` redirects to a remote
//! registry/git source. Registry and internal workspace references are safe. For
//! Go, CI environment that globally disables checksum-database verification
//! (`GOSUMDB=off`, or `GONOSUMCHECK`/`GONOSUMDB` set to the wildcard `*`) is also
//! flagged, since it lets modules resolve without integrity checks.
//! `[policy] allow_git_dependencies` and `allow_local_path_dependencies` opt out
//! of the respective findings.

use crate::ci::CiFacts;
use crate::ecosystems::{Dependency, DependencySource, Ecosystem, ProjectFacts};
use crate::rule::{Confidence, Finding, Location, Policy, Rule, RuleId, RuleInput, Severity};

pub struct Sd006;

impl Rule for Sd006 {
    fn id(&self) -> RuleId {
        RuleId::new("SD006")
    }

    fn summary(&self) -> &'static str {
        "Dependency resolves from an unsafe source (floating git, tarball, path)."
    }

    fn explanation(&self) -> &'static str {
        "Dependencies pulled from a moving Git ref, an SSH VCS URL, a direct \
tarball, or a local filesystem path are not reproducible or integrity-checked \
the way registry releases are. A Cargo [source] replace-with redirect to a remote \
registry/git source reroutes the whole crate graph; Go CI that globally disables \
the checksum database (GOSUMDB=off, or GONOSUMCHECK/GONOSUMDB set to the wildcard \
'*') installs modules without integrity checks. Pin Git dependencies to a commit, \
publish internal packages to a registry, keep local path dependencies out of \
production groups, review remote source redirects, and leave Go's checksum \
database enabled. Declare [policy] allow_git_dependencies or \
allow_local_path_dependencies to accept a deliberate choice."
    }

    fn evaluate(&self, input: &RuleInput) -> Vec<Finding> {
        let facts = input.facts;
        let policy = input.policy;
        let mut findings: Vec<Finding> = facts
            .dependencies
            .iter()
            .filter_map(|dep| {
                classify(dep, policy)
                    .map(|(message, remediation)| finding(facts, dep, message, remediation))
            })
            .collect();
        findings.extend(go_sumdb_findings(facts, input.ci));
        findings
    }
}

/// Declarative CI `env:` assignments that GLOBALLY disable Go's checksum-database
/// verification, weakening module integrity. Returns at most one finding per Go
/// project, anchored on its `go.mod`, so a multi-module workspace surfaces the
/// concern per module without duplicating one CI env across unrelated managers.
///
/// Note: `go env -w` command invocations in CI scripts are not yet inspected;
/// only declarative `env:` blocks parsed from GitHub Actions workflows are checked.
///
/// `GOPRIVATE`/`GONOSUMDB`/`GONOSUMCHECK` scoped to specific module path patterns
/// is intentional, recommended configuration and is deliberately NOT flagged;
/// only blanket (wildcard `*` or `GOSUMDB=off`) integrity-disabling values are.
fn go_sumdb_findings(facts: &ProjectFacts, ci: &CiFacts) -> Vec<Finding> {
    if facts.project.ecosystem != Ecosystem::Go {
        return Vec::new();
    }
    let Some(manifest) = facts.manifest.as_ref() else {
        return Vec::new();
    };
    let Some((var, value)) = ci
        .env
        .iter()
        .find_map(|e| go_disabling_env(&e.name, &e.value))
    else {
        return Vec::new();
    };
    vec![Finding {
        rule_id: RuleId::new("SD006"),
        severity: Severity::Warning,
        confidence: Confidence::Medium,
        message: format!(
            "CI sets `{var}={value}`, globally disabling Go's module checksum database; modules resolve without integrity checks"
        ),
        location: Some(Location::file(&manifest.relative)),
        project_root: facts.project.root.clone(),
        ecosystem: facts.project.ecosystem,
        package_manager: Some(facts.project.package_manager),
        remediation: Some(
            "leave the Go checksum database (GOSUMDB) enabled; scope GOPRIVATE/GONOSUMDB to specific private module path patterns instead of disabling verification globally."
                .to_string(),
        ),
    }]
}

/// Whether a CI env assignment GLOBALLY disables Go checksum-database
/// verification. Returns the normalized `(name, value)` to surface in the
/// finding.
///
/// Only true global bypasses match:
/// - `GOSUMDB=off` turns the checksum database off entirely.
/// - `GONOSUMCHECK`/`GONOSUMDB` are module-path *pattern lists*; only the
///   wildcard `*` (every module) is a blanket bypass. Literal patterns (a module
///   prefix) or non-pattern values like `1`/`on` are NOT a global disable.
///
/// `GOINSECURE` and `GOFLAGS=-insecure` are deliberately NOT matched here: they
/// allow insecure (HTTP) transport for matching modules, which is a distinct
/// concern from disabling checksum-database validation.
fn go_disabling_env(name: &str, value: &str) -> Option<(String, String)> {
    let upper = name.to_ascii_uppercase();
    let v = value.trim();
    match upper.as_str() {
        // Pattern lists: only the wildcard disables verification for everything.
        "GONOSUMCHECK" | "GONOSUMDB" if v == "*" => Some((upper, "*".to_string())),
        // Turning the checksum database off entirely.
        "GOSUMDB" if v.eq_ignore_ascii_case("off") => Some((upper, "off".to_string())),
        _ => None,
    }
}

/// Returns a `(message, remediation)` for an unsafe dependency, or `None` when
/// the source is safe or explicitly allowed by policy.
fn classify(dep: &Dependency, policy: &Policy) -> Option<(String, &'static str)> {
    match &dep.source {
        DependencySource::Registry | DependencySource::Workspace => None,
        DependencySource::Git { floating, ssh } => {
            if policy.allow_git_dependencies {
                return None;
            }
            if *floating {
                // A dependency can be both floating and SSH; the remediation
                // must address both, otherwise pinning the SHA leaves the SSH
                // source flagged on the next run.
                let remediation = if *ssh {
                    "pin the Git dependency to a specific commit SHA and prefer an https URL (or a registry release)."
                } else {
                    "pin the Git dependency to a specific commit SHA, or publish a registry release."
                };
                Some((
                    format!(
                        "dependency `{}` uses a floating Git ref (`{}`); it can change without notice",
                        dep.name, dep.spec
                    ),
                    remediation,
                ))
            } else if *ssh {
                Some((
                    format!(
                        "dependency `{}` uses an SSH Git source (`{}`)",
                        dep.name, dep.spec
                    ),
                    "prefer an https Git URL or a registry release so CI and consumers can resolve it.",
                ))
            } else {
                None
            }
        }
        DependencySource::Tarball => Some((
            format!(
                "dependency `{}` is a direct tarball URL (`{}`); integrity is not verifiable from the manifest",
                dep.name, dep.spec
            ),
            "install from a registry, or pin and verify the artifact via the lockfile.",
        )),
        DependencySource::Path => {
            if dep.group.is_production() && !policy.allow_local_path_dependencies {
                Some((
                    format!(
                        "{} dependency `{}` is a local path (`{}`); consumers cannot resolve it",
                        dep.group.as_str(),
                        dep.name,
                        dep.spec
                    ),
                    "publish the package to a registry, or move it to a dev dependency.",
                ))
            } else {
                None
            }
        }
        DependencySource::RegistryReplaced { replacement } => Some((
            format!(
                "source `{}` is redirected to `{}` via `[source]` `replace-with`; this reroutes the whole crate graph",
                dep.name, replacement
            ),
            "remove the [source] replace-with redirect, or document and pin the mirror so resolution is reviewed.",
        )),
    }
}

fn finding(
    facts: &ProjectFacts,
    dep: &Dependency,
    message: String,
    remediation: &'static str,
) -> Finding {
    Finding {
        rule_id: RuleId::new("SD006"),
        severity: Severity::Warning,
        confidence: Confidence::Medium,
        message,
        // Anchor on the exact manifest the dependency was declared in (e.g. a
        // specific requirements file), not just the project's primary manifest.
        location: Some(Location::file(&dep.file)),
        project_root: facts.project.root.clone(),
        ecosystem: facts.project.ecosystem,
        package_manager: Some(facts.project.package_manager),
        remediation: Some(remediation.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_replacement_is_classified_unsafe() {
        let dep = Dependency {
            name: "crates-io".to_string(),
            spec: "replace-with = \"mirror\"".to_string(),
            group: crate::ecosystems::DependencyGroup::Production,
            source: DependencySource::RegistryReplaced {
                replacement: "mirror".to_string(),
            },
            file: std::path::PathBuf::from(".cargo/config.toml"),
        };
        let (message, _) = classify(&dep, &Policy::default()).expect("flagged");
        assert!(message.contains("crates-io"), "{message}");
        assert!(message.contains("mirror"), "{message}");
    }

    #[test]
    fn go_disabling_env_matches_only_global_integrity_bypasses() {
        // GOSUMDB=off is a true global disable.
        assert!(go_disabling_env("GOSUMDB", "off").is_some());
        assert!(go_disabling_env("GOSUMDB", "OFF").is_some());
        // GONOSUMCHECK/GONOSUMDB are pattern lists; only the wildcard `*` is a
        // blanket bypass.
        assert!(go_disabling_env("GONOSUMCHECK", "*").is_some());
        assert!(go_disabling_env("GONOSUMDB", "*").is_some());
        // Case-insensitive matching: lowercase variants must also be detected.
        assert!(go_disabling_env("gonosumdb", "*").is_some());

        // Pattern-list values like `1`/`on` are literal patterns, not "off".
        assert!(go_disabling_env("GONOSUMCHECK", "1").is_none());
        assert!(go_disabling_env("gonosumcheck", "on").is_none());
        assert!(go_disabling_env("GONOSUMCHECK", "0").is_none());
        // GOINSECURE controls insecure transport, not the checksum database, so
        // it never matches this checksum-disable path (even with a wildcard).
        assert!(go_disabling_env("GOINSECURE", "*").is_none());
        assert!(go_disabling_env("GOINSECURE", "internal.example/*").is_none());
        // GOFLAGS=-insecure is insecure transport too, not a sumdb bypass.
        assert!(go_disabling_env("GOFLAGS", "-mod=mod -insecure").is_none());
        assert!(go_disabling_env("GOFLAGS", "-mod=readonly").is_none());

        // Recommended/benign configurations are not flagged.
        assert!(go_disabling_env("GOSUMDB", "sum.golang.org").is_none());
        assert!(go_disabling_env("GOPRIVATE", "github.com/me/*").is_none());
        assert!(go_disabling_env("GONOSUMDB", "github.com/me/*").is_none());
        assert!(go_disabling_env("GOOS", "linux").is_none());
    }
}
