//! Stable JSON reporter.

use crate::diagnostics::{Diagnostic, DiagnosticLevel};
use crate::report::{Report, ReportError, Reporter};
use crate::rule::{Confidence, Finding, Severity};
use serde::Serialize;

pub struct JsonReporter;

impl Reporter for JsonReporter {
    fn format(&self, report: &Report) -> Result<Vec<u8>, ReportError> {
        let schema = JsonReport::from_report(report);
        serde_json::to_vec_pretty(&schema).map_err(|err| ReportError::Render(err.to_string()))
    }
}

#[derive(Debug, Serialize)]
struct JsonReport {
    schema_version: &'static str,
    tool: JsonTool,
    profile: String,
    path: String,
    findings: Vec<JsonFinding>,
    diagnostics: Vec<JsonDiagnostic>,
    summary: JsonSummary,
}

#[derive(Debug, Serialize)]
struct JsonTool {
    name: &'static str,
    version: String,
}

#[derive(Debug, Serialize)]
struct JsonFinding {
    rule_id: String,
    severity: String,
    confidence: String,
    message: String,
    location: Option<JsonLocation>,
    project_root: String,
    ecosystem: String,
    package_manager: Option<String>,
    remediation: Option<String>,
}

#[derive(Debug, Serialize)]
struct JsonLocation {
    file: String,
    line: Option<u32>,
    column: Option<u32>,
}

#[derive(Debug, Serialize)]
struct JsonDiagnostic {
    level: String,
    message: String,
    location: Option<String>,
}

#[derive(Debug, Serialize)]
struct JsonSummary {
    total: usize,
    errors: usize,
    warnings: usize,
    info: usize,
}

impl JsonReport {
    fn from_report(report: &Report) -> Self {
        // Use the canonical ordering so JSON and text agree on a stable order.
        // Sorting JsonFinding by its severity *string* would put "warning"
        // ahead of "error"; sort the typed findings instead.
        let mut sorted = report.findings.clone();
        crate::report::sort_findings(&mut sorted);
        let findings: Vec<JsonFinding> = sorted.iter().map(json_finding).collect();
        let diagnostics: Vec<JsonDiagnostic> =
            report.diagnostics.iter().map(json_diagnostic).collect();
        let (errors, warnings, info) = count_severities(&report.findings);
        Self {
            schema_version: "1",
            tool: JsonTool {
                name: "safe-deps",
                version: report.tool_version.clone(),
            },
            profile: report.profile.as_str().to_string(),
            path: report.path.display().to_string(),
            findings,
            diagnostics,
            summary: JsonSummary {
                total: report.findings.len(),
                errors,
                warnings,
                info,
            },
        }
    }
}

fn json_finding(f: &Finding) -> JsonFinding {
    JsonFinding {
        rule_id: f.rule_id.as_str().to_string(),
        severity: f.severity.as_str().to_string(),
        confidence: f.confidence.as_str().to_string(),
        message: f.message.clone(),
        location: f.location.as_ref().map(|l| JsonLocation {
            file: l.file.display().to_string(),
            line: l.line,
            column: l.column,
        }),
        project_root: f.project_root.display().to_string(),
        ecosystem: f.ecosystem.as_str().to_string(),
        package_manager: f.package_manager.map(|p| p.as_str().to_string()),
        remediation: f.remediation.clone(),
    }
}

fn json_diagnostic(d: &Diagnostic) -> JsonDiagnostic {
    JsonDiagnostic {
        level: match d.level {
            DiagnosticLevel::Error => "error",
            DiagnosticLevel::Warning => "warning",
            DiagnosticLevel::Info => "info",
        }
        .to_string(),
        message: d.message.clone(),
        location: d.location.as_ref().map(|p| p.display().to_string()),
    }
}

fn count_severities(findings: &[Finding]) -> (usize, usize, usize) {
    let mut errors = 0;
    let mut warnings = 0;
    let mut info = 0;
    for f in findings {
        match f.severity {
            Severity::Error => errors += 1,
            Severity::Warning => warnings += 1,
            Severity::Info => info += 1,
        }
        let _ = Confidence::High;
    }
    (errors, warnings, info)
}
