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

    fn summary(&self) -> &'static str {
        "Dependency resolves from an unsafe source (floating git, tarball, path)."
    }

    fn explanation(&self) -> &'static str {
        "Dependencies pulled from a moving Git ref, an SSH VCS URL, a direct \
tarball, or a local filesystem path are not reproducible or integrity-checked \
the way registry releases are. Pin Git dependencies to a commit, publish \
internal packages to a registry, and keep local path dependencies out of \
production groups. Declare [policy] allow_git_dependencies or \
allow_local_path_dependencies to accept a deliberate choice."
    }

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
                Some((
                    format!(
                        "dependency `{}` uses a floating Git ref (`{}`); it can change without notice",
                        dep.name, dep.spec
                    ),
                    "pin the Git dependency to a specific commit SHA, or publish a registry release.",
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
