//! JUnit XML reporter for generic CI test-report dashboards.
//!
//! Each finding becomes a `<testcase>`; severity maps to the JUnit outcome a
//! dashboard understands: errors to `<error>`, warnings to `<failure>`, and
//! informational findings to `<skipped>` (surfaced but non-failing). The output
//! is a single `<testsuite>` wrapped in `<testsuites>`, deterministically
//! ordered like the other reporters.

use crate::report::{Report, ReportError, Reporter};
use crate::rule::{Finding, Severity};

pub struct JunitReporter;

impl Reporter for JunitReporter {
    fn format(&self, report: &Report) -> Result<Vec<u8>, ReportError> {
        let mut sorted = report.findings.clone();
        crate::report::sort_findings(&mut sorted);

        let errors = count(&sorted, Severity::Error);
        let failures = count(&sorted, Severity::Warning);
        let skipped = count(&sorted, Severity::Info);
        let total = sorted.len();

        let mut out = String::new();
        out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.push_str(&format!(
            "<testsuites name=\"safe-deps\" tests=\"{total}\" failures=\"{failures}\" errors=\"{errors}\" skipped=\"{skipped}\">\n"
        ));
        out.push_str(&format!(
            "  <testsuite name=\"safe-deps\" tests=\"{total}\" failures=\"{failures}\" errors=\"{errors}\" skipped=\"{skipped}\">\n"
        ));
        for (index, finding) in sorted.iter().enumerate() {
            out.push_str(&testcase(finding, index));
        }
        out.push_str("  </testsuite>\n");
        out.push_str("</testsuites>\n");
        Ok(out.into_bytes())
    }
}

fn testcase(f: &Finding, index: usize) -> String {
    // Include a stable index so two findings with an identical rule+message+path
    // remain distinct testcases (dashboards key on classname+name).
    let name = escape(&format!("[{index}] {}: {}", f.rule_id, f.message));
    let classname = escape(&classname(f));
    let detail = escape(&detail(f));
    let body = match f.severity {
        Severity::Error => format!(
            "      <error message=\"{}\" type=\"{}\">{}</error>\n",
            escape(&f.message),
            f.rule_id,
            detail
        ),
        Severity::Warning => format!(
            "      <failure message=\"{}\" type=\"{}\">{}</failure>\n",
            escape(&f.message),
            f.rule_id,
            detail
        ),
        Severity::Info => format!("      <skipped message=\"{}\"/>\n", escape(&f.message)),
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
        text.push_str(&loc.file.display().to_string());
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
        assert!(xml.contains("<skipped message=\"note\"/>"));
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
    }
}
