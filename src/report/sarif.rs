//! SARIF 2.1.0 reporter for GitHub code scanning and compatible platforms.
//!
//! Each built-in rule is emitted as a SARIF reporting descriptor; each finding
//! becomes a result that references its rule by index and points at the file
//! region when a location is known. Messages are kept concise and never carry
//! secret values (CI env values are redacted upstream).

use serde::Serialize;

use crate::report::{Report, ReportError, Reporter};
use crate::rule::{Finding, Severity};

const SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const INFORMATION_URI: &str = "https://github.com/baneido/safe-deps";
const HELP_URI: &str =
    "https://github.com/baneido/safe-deps/blob/main/docs/design/safe-deps-cli-design.md";

pub struct SarifReporter;

impl Reporter for SarifReporter {
    fn format(&self, report: &Report) -> Result<Vec<u8>, ReportError> {
        let doc = SarifLog::from_report(report);
        serde_json::to_vec_pretty(&doc).map_err(|err| ReportError::Render(err.to_string()))
    }
}

#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
    /// The tool invocation. Always present so a consumer can read the run's
    /// `executionSuccessful` state; linter-run notes (parse failures, expired
    /// suppressions) ride along as notifications, separate from findings.
    invocations: Vec<SarifInvocation>,
}

#[derive(Serialize)]
struct SarifInvocation {
    /// `false` when any error-level diagnostic was raised: an errored run must
    /// not be reported as successful.
    #[serde(rename = "executionSuccessful")]
    execution_successful: bool,
    #[serde(
        rename = "toolExecutionNotifications",
        skip_serializing_if = "Vec::is_empty"
    )]
    tool_execution_notifications: Vec<SarifNotification>,
}

#[derive(Serialize)]
struct SarifNotification {
    level: &'static str,
    message: SarifText,
    #[serde(rename = "locations", skip_serializing_if = "Vec::is_empty")]
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: &'static str,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<SarifRuleDescriptor>,
}

#[derive(Serialize)]
struct SarifRuleDescriptor {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifText,
    #[serde(rename = "fullDescription")]
    full_description: SarifText,
    #[serde(rename = "helpUri")]
    help_uri: &'static str,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    #[serde(rename = "ruleIndex", skip_serializing_if = "Option::is_none")]
    rule_index: Option<usize>,
    level: &'static str,
    message: SarifText,
    locations: Vec<SarifLocation>,
    properties: SarifResultProperties,
}

#[derive(Serialize)]
struct SarifResultProperties {
    confidence: String,
    ecosystem: String,
    #[serde(rename = "packageManager", skip_serializing_if = "Option::is_none")]
    package_manager: Option<String>,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<SarifRegion>,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: u32,
}

#[derive(Serialize)]
struct SarifText {
    text: String,
}

impl SarifLog {
    fn from_report(report: &Report) -> Self {
        // Stable rule index built from the canonical rule registry, so result
        // `ruleIndex` values match the emitted `rules` array exactly.
        let rules = crate::rules::all_rules();
        let descriptors: Vec<SarifRuleDescriptor> = rules
            .iter()
            .map(|r| SarifRuleDescriptor {
                id: r.id().as_str().to_string(),
                name: r.id().as_str().to_string(),
                short_description: SarifText {
                    text: r.summary().to_string(),
                },
                full_description: SarifText {
                    text: r.explanation().to_string(),
                },
                help_uri: HELP_URI,
            })
            .collect();
        let index_of = |id: &str| rules.iter().position(|r| r.id() == id);

        let mut sorted = report.findings.clone();
        crate::report::sort_findings(&mut sorted);
        // `ruleIndex` is optional in SARIF; omit it rather than guess when a
        // finding's rule is somehow absent from the registry, so a result is
        // never silently attributed to the wrong descriptor.
        let results = sorted
            .iter()
            .map(|f| sarif_result(f, index_of(f.rule_id.as_str())))
            .collect();

        // Surface linter-run diagnostics on the invocation, matching the text
        // and JSON reporters which both include them. An error-level diagnostic
        // means the run could not fully analyze the workspace, so the invocation
        // must report `executionSuccessful = false` — a consumer must never read
        // an errored run as a successful one.
        let notifications: Vec<SarifNotification> =
            report.diagnostics.iter().map(sarif_notification).collect();
        let execution_successful = !report
            .diagnostics
            .iter()
            .any(|d| d.level == crate::diagnostics::DiagnosticLevel::Error);
        // Always emit exactly one invocation so a consumer can read the run's
        // execution state even on a clean run; only the notifications list is
        // conditional on there being diagnostics.
        let invocations = vec![SarifInvocation {
            execution_successful,
            tool_execution_notifications: notifications,
        }];

        SarifLog {
            schema: SCHEMA,
            version: "2.1.0",
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "safe-deps",
                        version: report.tool_version.clone(),
                        information_uri: INFORMATION_URI,
                        rules: descriptors,
                    },
                },
                results,
                invocations,
            }],
        }
    }
}

fn sarif_notification(d: &crate::diagnostics::Diagnostic) -> SarifNotification {
    use crate::diagnostics::DiagnosticLevel;
    let level = match d.level {
        DiagnosticLevel::Error => "error",
        DiagnosticLevel::Warning => "warning",
        DiagnosticLevel::Info => "note",
    };
    let locations = d
        .location
        .as_ref()
        .map(|p| {
            vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: crate::path::normalize_separators(p),
                    },
                    region: None,
                },
            }]
        })
        .unwrap_or_default();
    SarifNotification {
        level,
        message: SarifText {
            text: d.message.clone(),
        },
        locations,
    }
}

fn sarif_result(f: &Finding, rule_index: Option<usize>) -> SarifResult {
    let uri = f.location_path_string();
    let region = f
        .location
        .as_ref()
        .and_then(|l| l.line)
        .map(|start_line| SarifRegion { start_line });
    SarifResult {
        rule_id: f.rule_id.as_str().to_string(),
        rule_index,
        level: sarif_level(f.severity),
        message: SarifText {
            text: f.message.clone(),
        },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation { uri },
                region,
            },
        }],
        properties: SarifResultProperties {
            confidence: f.confidence.as_str().to_string(),
            ecosystem: f.ecosystem.as_str().to_string(),
            package_manager: f.package_manager.map(|p| p.as_str().to_string()),
        },
    }
}

/// Maps a finding severity to a SARIF result level. SARIF has no `info`; the
/// closest standard level is `note`.
fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystems::{Ecosystem, PackageManager};
    use crate::report::Report;
    use crate::rule::{Confidence, Location, Profile, RuleId};
    use std::path::PathBuf;

    fn report_with(finding: Finding) -> Report {
        let mut r = Report::new(PathBuf::from("."), Profile::Balanced, "0.1.0");
        r.findings.push(finding);
        r
    }

    #[test]
    fn diagnostics_are_emitted_as_invocation_notifications() {
        let mut r = Report::new(PathBuf::from("."), Profile::Balanced, "0.1.0");
        r.diagnostics.push(crate::diagnostics::Diagnostic::warn_at(
            "could not parse pkg/package.json",
            PathBuf::from("pkg/package.json"),
        ));
        let bytes = SarifReporter.format(&r).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let note = &v["runs"][0]["invocations"][0]["toolExecutionNotifications"][0];
        assert_eq!(note["level"], "warning");
        assert!(note["message"]["text"]
            .as_str()
            .unwrap()
            .contains("could not parse"));
        assert_eq!(
            note["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "pkg/package.json"
        );
    }

    #[test]
    fn error_diagnostic_marks_execution_unsuccessful() {
        let mut r = Report::new(PathBuf::from("."), Profile::Balanced, "0.1.0");
        r.diagnostics
            .push(crate::diagnostics::Diagnostic::error("internal failure"));
        let bytes = SarifReporter.format(&r).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let inv = &v["runs"][0]["invocations"][0];
        assert_eq!(
            inv["executionSuccessful"], false,
            "an error diagnostic must not report a successful execution"
        );
        assert_eq!(inv["toolExecutionNotifications"][0]["level"], "error");
    }

    #[test]
    fn clean_run_reports_successful_invocation() {
        // No findings, no diagnostics: the invocation is still present (so a
        // consumer can read execution state) and reports success.
        let r = Report::new(PathBuf::from("."), Profile::Balanced, "0.1.0");
        let bytes = SarifReporter.format(&r).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let inv = &v["runs"][0]["invocations"][0];
        assert_eq!(inv["executionSuccessful"], true);
        // No notifications array when there are no diagnostics.
        assert!(inv["toolExecutionNotifications"].is_null());
    }

    #[test]
    fn warning_diagnostic_keeps_execution_successful() {
        let mut r = Report::new(PathBuf::from("."), Profile::Balanced, "0.1.0");
        r.diagnostics
            .push(crate::diagnostics::Diagnostic::warn("could not parse"));
        let bytes = SarifReporter.format(&r).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["runs"][0]["invocations"][0]["executionSuccessful"], true,
            "a warning diagnostic is non-fatal and keeps the run successful"
        );
    }

    #[test]
    fn emits_valid_sarif_skeleton_with_region() {
        let finding = Finding {
            rule_id: RuleId::new("SD002"),
            severity: Severity::Error,
            confidence: Confidence::High,
            message: "`npm install` resolves dependencies in CI".to_string(),
            location: Some(Location::line(".github/workflows/ci.yml", 7)),
            project_root: PathBuf::from(".github/workflows/ci.yml"),
            ecosystem: Ecosystem::JavaScript,
            package_manager: Some(PackageManager::Npm),
            remediation: None,
        };
        let bytes = SarifReporter.format(&report_with(finding)).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert!(v["$schema"].is_string());
        let run = &v["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "safe-deps");
        // SD002 is the second registered rule (index 1).
        let result = &run["results"][0];
        assert_eq!(result["ruleId"], "SD002");
        assert_eq!(result["ruleIndex"], 1);
        assert_eq!(result["level"], "error");
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            ".github/workflows/ci.yml"
        );
        assert_eq!(
            result["locations"][0]["physicalLocation"]["region"]["startLine"],
            7
        );
        // ruleIndex must point at the matching descriptor.
        let idx = result["ruleIndex"].as_u64().unwrap() as usize;
        assert_eq!(run["tool"]["driver"]["rules"][idx]["id"], "SD002");
    }

    #[test]
    fn omits_region_when_line_unknown() {
        let finding = Finding {
            rule_id: RuleId::new("SD001"),
            severity: Severity::Warning,
            confidence: Confidence::High,
            message: "lockfile missing".to_string(),
            location: Some(Location::file("package.json")),
            project_root: PathBuf::from("."),
            ecosystem: Ecosystem::JavaScript,
            package_manager: Some(PackageManager::Npm),
            remediation: None,
        };
        let bytes = SarifReporter.format(&report_with(finding)).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let phys = &v["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert_eq!(phys["artifactLocation"]["uri"], "package.json");
        assert!(phys["region"].is_null());
    }
}
