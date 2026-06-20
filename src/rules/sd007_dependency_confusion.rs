//! SD007: Dependency confusion via index/source config.
//!
//! Flags index configuration that lets a public index shadow or substitute an
//! internal package: pip/uv `--extra-index-url` (a second index searched with no
//! ownership guarantee) and uv `index-strategy = "unsafe-best-match"` (which
//! picks the best version across all indexes). Severity follows the profile —
//! an error under `strict`, a warning otherwise — since a mitigated setup can be
//! legitimate.

use crate::ecosystems::{PackageManager, ProjectFacts};
use crate::rule::{Confidence, Finding, Location, Profile, Rule, RuleId, RuleInput, Severity};

pub struct Sd007;

impl Rule for Sd007 {
    fn id(&self) -> RuleId {
        RuleId::new("SD007")
    }

    fn summary(&self) -> &'static str {
        "Index/source config exposes the project to dependency confusion."
    }

    fn explanation(&self) -> &'static str {
        "An extra package index or a cross-index resolution strategy lets a \
public package shadow an internal one of the same name (dependency confusion). \
Prefer a single trusted index, or pin internal packages to a dedicated index \
with explicit ownership. uv's index-strategy = unsafe-best-match resolves the \
best version across all configured indexes and should be avoided. This rule is \
an error under the strict profile and a warning otherwise."
    }

    fn evaluate(&self, input: &RuleInput) -> Vec<Finding> {
        let facts = input.facts;
        let pm = facts.project.package_manager;
        if pm != PackageManager::Pip && pm != PackageManager::Uv {
            return Vec::new();
        }
        let settings = &facts.install_settings;
        let severity = profile_severity(input.profile);
        let mut findings = Vec::new();

        // The same extra index can be declared in more than one source
        // (pyproject + uv.toml, or requirements + pip.conf); report each once.
        let mut seen = std::collections::HashSet::new();
        for url in settings
            .extra_index_urls
            .iter()
            .filter(|u| seen.insert(u.as_str()))
        {
            findings.push(finding(
                facts,
                severity,
                format!("extra index URL `{url}` is searched alongside the primary index"),
                "drop --extra-index-url, or pin internal packages to a dedicated, owned index.",
                python_config_loc(facts),
            ));
        }

        if pm == PackageManager::Uv
            && settings.index_strategy.as_deref() == Some("unsafe-best-match")
        {
            findings.push(finding(
                facts,
                severity,
                "uv `index-strategy = \"unsafe-best-match\"` resolves versions across all indexes"
                    .to_string(),
                "use the default first-match strategy so an internal index is not shadowed.",
                python_config_loc(facts),
            ));
        }

        findings
    }
}

/// SD007 is an error under the strict profile and a warning otherwise.
fn profile_severity(profile: Profile) -> Severity {
    match profile {
        Profile::Strict => Severity::Error,
        Profile::Balanced | Profile::Permissive => Severity::Warning,
    }
}

fn finding(
    facts: &ProjectFacts,
    severity: Severity,
    message: String,
    remediation: &'static str,
    location: Option<Location>,
) -> Finding {
    Finding {
        rule_id: RuleId::new("SD007"),
        severity,
        confidence: Confidence::High,
        message,
        location,
        project_root: facts.project.root.clone(),
        ecosystem: facts.project.ecosystem,
        package_manager: Some(facts.project.package_manager),
        remediation: Some(remediation.to_string()),
    }
}

/// Locates the most relevant Python config/manifest for an index finding.
fn python_config_loc(facts: &ProjectFacts) -> Option<Location> {
    for basename in ["uv.toml", "pip.conf", "pip.ini", "pyproject.toml"] {
        if let Some(c) = facts
            .configs
            .iter()
            .chain(facts.manifest.iter())
            .find(|f| f.relative.file_name().and_then(|n| n.to_str()) == Some(basename))
        {
            return Some(Location::file(&c.relative));
        }
    }
    facts.manifest.as_ref().map(|m| Location::file(&m.relative))
}
