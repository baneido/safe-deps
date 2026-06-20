//! Human-readable text reporter.

use std::io::Write;

use crate::diagnostics::DiagnosticLevel;
use crate::report::{sort_findings, Report, ReportError, Reporter};
use crate::rule::{Confidence, Severity};

pub struct TextReporter;

impl Reporter for TextReporter {
    fn format(&self, report: &Report) -> Result<Vec<u8>, ReportError> {
        let mut out = Vec::new();
        render(&mut out, report)?;
        Ok(out)
    }
}

fn render(out: &mut Vec<u8>, report: &Report) -> Result<(), ReportError> {
    let mut findings = report.findings.clone();
    sort_findings(&mut findings);

    writeln!(out, "safe-deps {}", report.tool_version).map_err(write_err)?;
    writeln!(
        out,
        "profile: {}  path: {}",
        report.profile.as_str(),
        report.path.display()
    )
    .map_err(write_err)?;
    writeln!(out, "findings: {}", findings.len()).map_err(write_err)?;
    writeln!(out).map_err(write_err)?;

    if findings.is_empty() {
        writeln!(out, "No findings.").map_err(write_err)?;
    } else {
        render_by_severity(out, &findings)?;
    }

    if !report.diagnostics.is_empty() {
        writeln!(out).map_err(write_err)?;
        writeln!(out, "diagnostics:").map_err(write_err)?;
        for diag in &report.diagnostics {
            let level = match diag.level {
                DiagnosticLevel::Error => "error",
                DiagnosticLevel::Warning => "warning",
                DiagnosticLevel::Info => "info",
            };
            let loc = diag
                .location
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "-".to_string());
            writeln!(out, "  [{level}] {loc}: {}", diag.message).map_err(write_err)?;
        }
    }

    Ok(())
}

fn render_by_severity(
    out: &mut Vec<u8>,
    findings: &[crate::rule::Finding],
) -> Result<(), ReportError> {
    for severity in [Severity::Error, Severity::Warning, Severity::Info] {
        let bucket: Vec<_> = findings.iter().filter(|f| f.severity == severity).collect();
        if bucket.is_empty() {
            continue;
        }
        let label = match severity {
            Severity::Error => "Errors",
            Severity::Warning => "Warnings",
            Severity::Info => "Info",
        };
        writeln!(out, "{label} ({}):", bucket.len()).map_err(write_err)?;
        for finding in bucket {
            let pm = finding.package_manager.map(|p| p.as_str()).unwrap_or("-");
            let conf = match finding.confidence {
                Confidence::High => "high",
                Confidence::Medium => "medium",
                Confidence::Low => "low",
            };
            let loc = finding
                .location
                .as_ref()
                .map(|l| {
                    let base = l.file.display().to_string();
                    match l.line {
                        Some(line) => format!("{base}:{line}"),
                        None => base,
                    }
                })
                .unwrap_or_else(|| finding.project_root.display().to_string());
            writeln!(
                out,
                "  {id} [{pm}] {loc} (confidence: {conf})",
                id = finding.rule_id
            )
            .map_err(write_err)?;
            writeln!(out, "    {}", finding.message).map_err(write_err)?;
            if let Some(remediation) = &finding.remediation {
                writeln!(out, "    remediation: {remediation}").map_err(write_err)?;
            }
        }
        writeln!(out).map_err(write_err)?;
    }
    Ok(())
}

fn write_err(err: std::io::Error) -> ReportError {
    ReportError::Render(err.to_string())
}
