//! Report rendering. Output formatting is independent from rule execution.

use std::path::PathBuf;

use crate::config::OutputFormat;
use crate::diagnostics::Diagnostic;
use crate::rule::{Finding, Profile};

pub mod json;
pub mod sarif;
pub mod text;

/// A stable report handed to reporters.
#[derive(Debug, Clone)]
pub struct Report {
    pub tool_version: String,
    pub profile: Profile,
    pub path: PathBuf,
    pub findings: Vec<Finding>,
    pub diagnostics: Vec<Diagnostic>,
}

impl Report {
    pub fn new(path: PathBuf, profile: Profile, tool_version: &str) -> Self {
        Self {
            tool_version: tool_version.to_string(),
            profile,
            path,
            findings: Vec::new(),
            diagnostics: Vec::new(),
        }
    }
}

/// Reporters render a `Report` without re-running rule logic.
pub trait Reporter {
    fn format(&self, report: &Report) -> Result<Vec<u8>, ReportError>;
}

/// Returns the reporter for the requested format.
pub fn reporter_for(format: OutputFormat) -> Box<dyn Reporter> {
    match format {
        OutputFormat::Text => Box::new(text::TextReporter),
        OutputFormat::Json => Box::new(json::JsonReporter),
        OutputFormat::Sarif => Box::new(sarif::SarifReporter),
        OutputFormat::Junit => Box::new(text::TextReporter),
    }
}

/// Sorts findings deterministically: severity desc, confidence desc, project
/// path, rule id, file path, line.
pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| b.confidence.cmp(&a.confidence))
            .then_with(|| a.project_root.cmp(&b.project_root))
            .then_with(|| a.rule_id.as_str().cmp(b.rule_id.as_str()))
            .then_with(|| a.location_path_string().cmp(&b.location_path_string()))
            .then_with(|| {
                a.location
                    .as_ref()
                    .and_then(|l| l.line)
                    .cmp(&b.location.as_ref().and_then(|l| l.line))
            })
    });
}

/// Errors produced while rendering a report.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("failed to render report: {0}")]
    Render(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystems::{Ecosystem, PackageManager};
    use crate::rule::{Confidence, Finding, Location, RuleId, Severity};

    fn finding(rule: &str, severity: Severity, confidence: Confidence, root: &str) -> Finding {
        Finding {
            rule_id: RuleId::new(rule),
            severity,
            confidence,
            message: "msg".to_string(),
            location: Some(Location::file(format!("{root}/file"))),
            project_root: PathBuf::from(root),
            ecosystem: Ecosystem::JavaScript,
            package_manager: Some(PackageManager::Npm),
            remediation: None,
        }
    }

    #[test]
    fn sorts_by_severity_then_confidence_then_path() {
        let mut findings = vec![
            finding("SD001", Severity::Warning, Confidence::High, "b"),
            finding("SD003", Severity::Error, Confidence::Low, "a"),
            finding("SD004", Severity::Error, Confidence::High, "a"),
        ];
        sort_findings(&mut findings);
        // Errors first; within errors, higher confidence first.
        assert_eq!(findings[0].rule_id, "SD004");
        assert_eq!(findings[1].rule_id, "SD003");
        assert_eq!(findings[2].rule_id, "SD001");
    }

    #[test]
    fn sort_is_stable_and_deterministic() {
        let build = || {
            vec![
                finding("SD003", Severity::Error, Confidence::High, "z"),
                finding("SD003", Severity::Error, Confidence::High, "a"),
            ]
        };
        let mut first = build();
        let mut second = build();
        sort_findings(&mut first);
        sort_findings(&mut second);
        assert_eq!(first[0].project_root, PathBuf::from("a"));
        assert_eq!(
            first
                .iter()
                .map(|f| f.project_root.clone())
                .collect::<Vec<_>>(),
            second
                .iter()
                .map(|f| f.project_root.clone())
                .collect::<Vec<_>>(),
        );
    }
}
