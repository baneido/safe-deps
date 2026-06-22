//! JUnit XML reporter for generic CI test-report dashboards.
//!
//! Each finding becomes a `<testcase>`; severity maps to the JUnit outcome a
//! dashboard understands: errors to `<error>`, warnings to `<failure>`, and
//! informational findings to `<skipped>` (surfaced but non-failing).
//!
//! Linter-run diagnostics (parse failures, expired suppressions) are *not*
//! findings, but a dashboard must still be able to see that the run was
//! incomplete. They are emitted in a second `<testsuite name="diagnostics">`
//! using the same level→outcome mapping (error→`<error>`, warning→`<failure>`,
//! info→`<skipped>`), so their existence is discoverable from JUnit output
//! without being conflated with policy findings. The top-level `<testsuites>`
//! aggregate counts include both suites. Both suites are deterministically
//! ordered like the other reporters.

use crate::diagnostics::{Diagnostic, DiagnosticLevel};
use crate::report::{Report, ReportError, Reporter};
use crate::rule::{Finding, Severity};

pub struct JunitReporter;

impl Reporter for JunitReporter {
    fn format(&self, report: &Report) -> Result<Vec<u8>, ReportError> {
        let mut sorted = report.findings.clone();
        crate::report::sort_findings(&mut sorted);

        let f_errors = count(&sorted, Severity::Error);
        let f_failures = count(&sorted, Severity::Warning);
        let f_skipped = count(&sorted, Severity::Info);
        let f_total = sorted.len();

        let diagnostics = &report.diagnostics;
        let d_errors = count_diag(diagnostics, DiagnosticLevel::Error);
        let d_failures = count_diag(diagnostics, DiagnosticLevel::Warning);
        let d_skipped = count_diag(diagnostics, DiagnosticLevel::Info);
        let d_total = diagnostics.len();

        // The top-level aggregate spans both the findings and the diagnostics
        // suites, so a dashboard's headline counts reflect run incompleteness too.
        let total = f_total + d_total;
        let errors = f_errors + d_errors;
        let failures = f_failures + d_failures;
        let skipped = f_skipped + d_skipped;

        let mut out = String::new();
        out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.push_str(&format!(
            "<testsuites name=\"safe-deps\" tests=\"{total}\" failures=\"{failures}\" errors=\"{errors}\" skipped=\"{skipped}\">\n"
        ));
        out.push_str(&format!(
            "  <testsuite name=\"safe-deps\" tests=\"{f_total}\" failures=\"{f_failures}\" errors=\"{f_errors}\" skipped=\"{f_skipped}\">\n"
        ));
        for finding in &sorted {
            out.push_str(&testcase(finding));
        }
        out.push_str("  </testsuite>\n");
        // Only emit the diagnostics suite when there is something to report, so
        // a clean run keeps the original single-suite shape.
        if d_total > 0 {
            out.push_str(&format!(
                "  <testsuite name=\"diagnostics\" tests=\"{d_total}\" failures=\"{d_failures}\" errors=\"{d_errors}\" skipped=\"{d_skipped}\">\n"
            ));
            for diag in diagnostics {
                out.push_str(&diagnostic_case(diag));
            }
            out.push_str("  </testsuite>\n");
        }
        out.push_str("</testsuites>\n");
        Ok(out.into_bytes())
    }
}

fn testcase(f: &Finding) -> String {
    // A stable name (rule + message) so a dashboard keeps pass/fail history
    // across runs; the location goes in classname. Two findings that are
    // genuinely identical (same rule, message and location) are the same case.
    let name = escape(&format!("{}: {}", f.rule_id, f.message));
    let classname = escape(&classname(f));
    let detail = escape(&detail(f));
    let rule_id = escape(f.rule_id.as_str());
    let message = escape(&f.message);
    let body = match f.severity {
        Severity::Error => {
            format!("      <error message=\"{message}\" type=\"{rule_id}\">{detail}</error>\n")
        }
        Severity::Warning => {
            format!("      <failure message=\"{message}\" type=\"{rule_id}\">{detail}</failure>\n")
        }
        // Carry the same detail (file:line, remediation) as the other outcomes
        // so an informational finding is not bare in the dashboard.
        Severity::Info => {
            format!("      <skipped message=\"{message}\">{detail}</skipped>\n")
        }
    };
    format!("    <testcase name=\"{name}\" classname=\"{classname}\">\n{body}    </testcase>\n")
}

/// A stable classname grouping testcases by ecosystem and project location.
fn classname(f: &Finding) -> String {
    let loc = f.location_path_string();
    format!("{}.{}", f.ecosystem.as_str(), loc)
}

fn detail(f: &Finding) -> String {
    let mut text = String::new();
    if let Some(loc) = &f.location {
        text.push_str(&crate::path::normalize_separators(&loc.file));
        if let Some(line) = loc.line {
            text.push_str(&format!(":{line}"));
        }
        text.push('\n');
    }
    text.push_str(&f.message);
    if let Some(r) = &f.remediation {
        text.push_str(&format!("\nremediation: {r}"));
    }
    text
}

fn count(findings: &[Finding], severity: Severity) -> usize {
    findings.iter().filter(|f| f.severity == severity).count()
}

fn count_diag(diagnostics: &[Diagnostic], level: DiagnosticLevel) -> usize {
    diagnostics.iter().filter(|d| d.level == level).count()
}

/// Renders one diagnostic as a `<testcase>` in the diagnostics suite, mapping
/// its level to the same JUnit outcome the findings use. The optional file
/// location is carried in the classname and the body detail so an operator can
/// trace the diagnostic back to its source.
fn diagnostic_case(d: &Diagnostic) -> String {
    let loc = d
        .location
        .as_ref()
        .map(|p| crate::path::normalize_separators(p));
    let name = escape(&match &loc {
        Some(path) => format!("diagnostic: {path}: {}", d.message),
        None => format!("diagnostic: {}", d.message),
    });
    let classname = escape(&format!("diagnostics.{}", loc.as_deref().unwrap_or("-")));
    let message = escape(&d.message);
    let detail = escape(&match &loc {
        Some(path) => format!("{path}\n{}", d.message),
        None => d.message.clone(),
    });
    let body = match d.level {
        DiagnosticLevel::Error => {
            format!("      <error message=\"{message}\" type=\"diagnostic\">{detail}</error>\n")
        }
        DiagnosticLevel::Warning => {
            format!("      <failure message=\"{message}\" type=\"diagnostic\">{detail}</failure>\n")
        }
        DiagnosticLevel::Info => {
            format!("      <skipped message=\"{message}\">{detail}</skipped>\n")
        }
    };
    format!("    <testcase name=\"{name}\" classname=\"{classname}\">\n{body}    </testcase>\n")
}

/// Escapes the five XML predefined entities so messages and paths are safe in
/// both attribute and text positions. Control characters that are invalid in
/// XML 1.0 (everything below 0x20 except tab/newline/carriage-return) are
/// dropped, since a stray byte parsed from a manifest would otherwise produce a
/// report no dashboard can ingest.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if (c as u32) < 0x20 => {}
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecosystems::{Ecosystem, PackageManager};
    use crate::report::Report;
    use crate::rule::{Confidence, Location, Profile, RuleId};
    use std::path::PathBuf;

    fn report_with(findings: Vec<Finding>) -> Report {
        let mut r = Report::new(PathBuf::from("."), Profile::Balanced, "0.1.0");
        r.findings = findings;
        r
    }

    fn finding(rule: &str, severity: Severity, message: &str) -> Finding {
        Finding {
            rule_id: RuleId::new(rule),
            severity,
            confidence: Confidence::High,
            message: message.to_string(),
            location: Some(Location::line("Cargo.toml", 3)),
            project_root: PathBuf::from("."),
            ecosystem: Ecosystem::Rust,
            package_manager: Some(PackageManager::Cargo),
            remediation: Some("do the thing".to_string()),
        }
    }

    #[test]
    fn maps_severities_and_counts() {
        let report = report_with(vec![
            finding("SD001", Severity::Error, "missing Cargo.lock"),
            finding("SD006", Severity::Warning, "git dep"),
            finding("SD001", Severity::Info, "note"),
        ]);
        let xml = String::from_utf8(JunitReporter.format(&report).unwrap()).unwrap();
        assert!(xml.contains("tests=\"3\""));
        assert!(xml.contains("failures=\"1\""));
        assert!(xml.contains("errors=\"1\""));
        assert!(xml.contains("skipped=\"1\""));
        assert!(xml.contains("<error message=\"missing Cargo.lock\" type=\"SD001\">"));
        assert!(xml.contains("<failure message=\"git dep\" type=\"SD006\">"));
        // `<skipped>` now carries the detail (file:line, remediation) like the
        // other outcomes, and names omit a position index so they stay stable.
        assert!(xml.contains("<skipped message=\"note\">"));
        assert!(xml.contains("do the thing"));
        assert!(!xml.contains("[0]"));
    }

    #[test]
    fn escapes_rule_id_in_type_attribute() {
        let mut f = finding("S<&>D", Severity::Error, "boom");
        f.rule_id = RuleId::new("S<&>D");
        let xml = String::from_utf8(JunitReporter.format(&report_with(vec![f]).clone()).unwrap())
            .unwrap();
        assert!(xml.contains("type=\"S&lt;&amp;&gt;D\""), "{xml}");
        assert!(!xml.contains("type=\"S<&>D\""));
    }

    #[test]
    fn escapes_xml_metacharacters() {
        let report = report_with(vec![finding(
            "SD003",
            Severity::Error,
            "registry <a> & \"b\" uses http",
        )]);
        let xml = String::from_utf8(JunitReporter.format(&report).unwrap()).unwrap();
        assert!(xml.contains("&lt;a&gt; &amp; &quot;b&quot;"));
        assert!(!xml.contains("<a>"));
    }

    #[test]
    fn drops_invalid_xml_control_characters() {
        let report = report_with(vec![finding(
            "SD003",
            Severity::Error,
            "host\u{0001}name uses http",
        )]);
        let xml = String::from_utf8(JunitReporter.format(&report).unwrap()).unwrap();
        assert!(!xml.contains('\u{0001}'));
        assert!(xml.contains("hostname uses http"));
    }

    #[test]
    fn empty_report_is_valid_empty_suite() {
        let xml =
            String::from_utf8(JunitReporter.format(&report_with(vec![]).clone()).unwrap()).unwrap();
        assert!(xml.contains("tests=\"0\""));
        assert!(xml.starts_with("<?xml"));
        // No diagnostics → keep the original single-suite shape.
        assert!(!xml.contains("name=\"diagnostics\""));
    }

    #[test]
    fn diagnostics_are_emitted_in_their_own_suite() {
        let mut report = report_with(vec![]);
        report
            .diagnostics
            .push(crate::diagnostics::Diagnostic::warn_at(
                "could not parse pkg/package.json",
                PathBuf::from("pkg/package.json"),
            ));
        let xml = String::from_utf8(JunitReporter.format(&report).unwrap()).unwrap();
        // A separate suite makes diagnostics discoverable without conflating
        // them with policy findings; a warning maps to <failure>.
        assert!(xml.contains("<testsuite name=\"diagnostics\""), "{xml}");
        assert!(
            xml.contains(
                "<failure message=\"could not parse pkg/package.json\" type=\"diagnostic\">"
            ),
            "{xml}"
        );
        assert!(xml.contains("pkg/package.json"), "{xml}");
        // The top-level aggregate counts the diagnostic too.
        assert!(
            xml.contains("<testsuites name=\"safe-deps\" tests=\"1\""),
            "{xml}"
        );
    }

    #[test]
    fn error_diagnostic_maps_to_error_outcome() {
        let mut report = report_with(vec![]);
        report
            .diagnostics
            .push(crate::diagnostics::Diagnostic::error("internal failure"));
        let xml = String::from_utf8(JunitReporter.format(&report).unwrap()).unwrap();
        assert!(
            xml.contains("<error message=\"internal failure\" type=\"diagnostic\">"),
            "{xml}"
        );
        assert!(
            xml.contains("<testsuite name=\"diagnostics\" tests=\"1\" failures=\"0\" errors=\"1\""),
            "{xml}"
        );
    }

    #[test]
    fn findings_and_diagnostics_aggregate_together() {
        let mut report = report_with(vec![finding("SD001", Severity::Error, "missing lock")]);
        report
            .diagnostics
            .push(crate::diagnostics::Diagnostic::warn("parse trouble"));
        let xml = String::from_utf8(JunitReporter.format(&report).unwrap()).unwrap();
        // 1 finding (error) + 1 diagnostic (warning => failure) across two suites.
        assert!(
            xml.contains("<testsuites name=\"safe-deps\" tests=\"2\" failures=\"1\" errors=\"1\""),
            "{xml}"
        );
        // The findings suite keeps its own scoped counts.
        assert!(
            xml.contains("<testsuite name=\"safe-deps\" tests=\"1\" failures=\"0\" errors=\"1\""),
            "{xml}"
        );
    }
}
