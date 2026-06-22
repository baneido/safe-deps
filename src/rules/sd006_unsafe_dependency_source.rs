//! SD006: Unsafe dependency source.
//!
//! Flags dependencies that resolve from something other than a registry version
//! in a way that weakens reproducibility or integrity: floating Git refs,
//! SSH-based VCS dependencies, direct tarball URLs, and local path dependencies
//! in production groups. Registry and internal workspace references are safe.
//! `[policy] allow_git_dependencies` and `allow_local_path_dependencies` opt out
//! of the respective findings.

use crate::ecosystems::{Dependency, DependencySource, ProjectFacts};
use crate::rule::{Confidence, Finding, Location, Policy, Rule, RuleId, RuleInput, Severity};

pub struct Sd006;

impl Rule for Sd006 {
    fn id(&self) -> RuleId {
        RuleId::new("SD006")
    }

    // `summary`/`explanation` are derived from the declarative metadata in
    // `rules::meta` (the single source, #66); only `evaluate` lives here.

    fn evaluate(&self, input: &RuleInput) -> Vec<Finding> {
        let facts = input.facts;
        let policy = input.policy;
        facts
            .dependencies
            .iter()
            .filter_map(|dep| {
                classify(dep, policy)
                    .map(|(message, remediation)| finding(facts, dep, message, remediation))
            })
            .collect()
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
