//! Rule registry and analysis engine.
//!
//! The engine detects projects, extracts facts, runs all rules, then applies
//! config rule-level overrides and suppressions. Findings and diagnostics are
//! kept separate.

use std::collections::HashSet;

use globset::Glob;

use crate::ci::{self, CiFacts};
use crate::config::{Config, Suppression};
use crate::diagnostics::{Diagnostic, DiagnosticLevel};
use crate::ecosystems::{detect_all, facts_for};
use crate::filesystem::WorkspaceContext;
use crate::project::refine_kinds;
use crate::report::sort_findings;
use crate::rule::{Finding, Profile, Rule, RuleInput, WorkspaceInput};

pub mod sd001_lockfile_missing;
pub mod sd002_non_frozen_ci_install;
pub mod sd003_insecure_registry;
pub mod sd004_integrity_disabled;
pub mod sd005_install_script_bypass;
pub mod sd006_unsafe_dependency_source;
pub mod sd007_dependency_confusion;
pub mod sd008_audit_missing;
pub mod sd009_dangerous_flags;

/// Returns all built-in rules.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(sd001_lockfile_missing::Sd001),
        Box::new(sd002_non_frozen_ci_install::Sd002),
        Box::new(sd003_insecure_registry::Sd003),
        Box::new(sd004_integrity_disabled::Sd004),
        Box::new(sd005_install_script_bypass::Sd005),
        Box::new(sd006_unsafe_dependency_source::Sd006),
        Box::new(sd007_dependency_confusion::Sd007),
        Box::new(sd008_audit_missing::Sd008),
        Box::new(sd009_dangerous_flags::Sd009),
    ]
}

/// Result of running the analysis engine.
#[derive(Debug, Default)]
pub struct AnalysisResult {
    pub findings: Vec<Finding>,
    pub diagnostics: Vec<Diagnostic>,
    pub unused_suppressions: Vec<String>,
    /// Number of files the analyzers could not parse. Used by
    /// `--strict-parser-errors` to escalate the run to exit code 4.
    pub parse_failures: usize,
    /// Whether any [`DiagnosticLevel::Error`] diagnostic was produced. An
    /// error-level diagnostic indicates a linter-side configuration or
    /// suppression problem that must not pass silently, so the exit-code
    /// decision in `check_runner` treats this as a failure condition
    /// independent of the finding threshold.
    pub has_error_diagnostic: bool,
}

/// Runs all rules over all detected projects.
pub fn analyze(ctx: &WorkspaceContext, profile: Profile, ci_facts: &CiFacts) -> AnalysisResult {
    // Surface directory-walk failures recorded during scanning; they are
    // coverage gaps, counted like parse failures so `--strict-parser-errors`
    // can escalate.
    let mut diagnostics = ctx.scan_diagnostics.clone();
    let mut parse_failures = ctx.scan_diagnostics.len();

    let mut projects = detect_all(ctx);
    refine_kinds(&mut projects, ctx);

    let mut facts_list = Vec::with_capacity(projects.len());
    for project in &projects {
        match facts_for(project, ctx) {
            Ok(facts) => {
                for diag in &facts.parse_diagnostics {
                    parse_failures += 1;
                    diagnostics.push(diag.clone());
                }
                facts_list.push(facts);
            }
            Err(err) => {
                parse_failures += 1;
                diagnostics.push(Diagnostic::warn_at(
                    format!("skipping {}: {err}", project.root.display()),
                    project.root.clone(),
                ));
            }
        }
    }

    let rules = all_rules();

    // Project-scoped rules run once per detected project.
    let mut findings: Vec<Finding> = facts_list
        .iter()
        .flat_map(|facts| {
            let input = RuleInput {
                facts,
                ci: ci_facts,
                profile,
                policy: &ctx.config.policy,
            };
            rules
                .iter()
                .filter(|rule| !rule.is_workspace_rule())
                .flat_map(|rule| rule.evaluate(&input))
                .collect::<Vec<_>>()
        })
        .collect();

    // Workspace-scoped rules (CI-derived) run exactly once so a single unsafe
    // command is not duplicated across every project in a monorepo.
    let ws_input = WorkspaceInput {
        ci: ci_facts,
        profile,
        policy: &ctx.config.policy,
    };
    for rule in rules.iter().filter(|rule| rule.is_workspace_rule()) {
        findings.extend(rule.evaluate_workspace(&ws_input));
    }

    apply_rule_overrides(&mut findings, &ctx.config);
    let (suppressed_count, supp_diagnostics, used) =
        apply_suppressions(&mut findings, &ctx.config, profile);
    diagnostics.extend(supp_diagnostics);

    let _ = suppressed_count;
    sort_findings(&mut findings);

    let unused_suppressions = unused_suppression_list(&ctx.config.suppressions, &used);
    for id in &unused_suppressions {
        diagnostics.push(Diagnostic {
            level: DiagnosticLevel::Info,
            message: format!("unused suppression: {id}"),
            location: None,
        });
    }

    // Surface CI commands the pragmatic shell tokenizer cannot fully model so a
    // shell-derived rule (SD002/SD008/SD009) result is not silently trusted. These
    // are informational — the command is still analyzed best-effort, so they are
    // NOT counted as parse failures. Only commands that still resolve to a
    // package-manager invocation are flagged, so unrelated complex shell (e.g.
    // `echo $(date)`) does not add noise. `ci_facts.commands` is pre-sorted by
    // (file, line), so this is deterministic.
    for cmd in &ci_facts.commands {
        let Some(reason) = ci::command::uncertainty(&cmd.command) else {
            continue;
        };
        let pm_relevant = ci::command::segments(&cmd.command)
            .iter()
            .any(|seg| ci::command::invocation(seg).is_some());
        if pm_relevant {
            diagnostics.push(Diagnostic {
                level: DiagnosticLevel::Info,
                // The file lives in `location`; the reporter prints it as a
                // prefix, so the message carries only the line to avoid a
                // duplicated path.
                message: format!(
                    "complex-shell-not-fully-parsed ({reason}) at line {}; CI-derived findings \
                     (SD002/SD008/SD009) for this command may be incomplete",
                    cmd.line
                ),
                location: Some(cmd.file.clone()),
            });
        }
    }

    let has_error_diagnostic = diagnostics
        .iter()
        .any(|d| d.level == DiagnosticLevel::Error);

    AnalysisResult {
        findings,
        diagnostics,
        unused_suppressions,
        parse_failures,
        has_error_diagnostic,
    }
}

fn apply_rule_overrides(findings: &mut [Finding], config: &Config) {
    for finding in findings.iter_mut() {
        if let Some(rule_cfg) = config.rules.get(finding.rule_id.as_str()) {
            if let Some(level) = rule_cfg.level {
                finding.severity = level;
            }
        }
    }
}

fn apply_suppressions(
    findings: &mut Vec<Finding>,
    config: &Config,
    profile: Profile,
) -> (usize, Vec<Diagnostic>, HashSet<String>) {
    let mut used: HashSet<String> = HashSet::new();
    let mut diagnostics = Vec::new();

    let parsed: Vec<(usize, ParsedSuppression)> = config
        .suppressions
        .iter()
        .enumerate()
        .filter_map(|(idx, supp)| ParsedSuppression::new(idx, supp).map(|p| (idx, p)))
        .collect();

    let mut keep = Vec::with_capacity(findings.len());
    for finding in findings.drain(..) {
        let mut suppressed = false;
        for (idx, p) in &parsed {
            if p.matches(&finding) {
                if let Some(expired) = &p.expired {
                    let level = if profile == Profile::Strict {
                        DiagnosticLevel::Error
                    } else {
                        DiagnosticLevel::Warning
                    };
                    diagnostics.push(Diagnostic {
                        level,
                        message: format!(
                            "suppression for {} at {} expired on {expired}",
                            p.rule, p.path
                        ),
                        location: None,
                    });
                    // An expired suppression that matched a finding has been
                    // acted on (it surfaced an expiry diagnostic), so it is not
                    // also "unused". Mark it used to avoid a redundant report.
                    used.insert(format!("{}@{}", p.rule, p.path));
                } else {
                    used.insert(format!("{}@{}", p.rule, p.path));
                    suppressed = true;
                    break;
                }
            }
            let _ = idx;
        }
        if !suppressed {
            keep.push(finding);
        }
    }
    *findings = keep;

    (used.len(), diagnostics, used)
}

fn unused_suppression_list(suppressions: &[Suppression], used: &HashSet<String>) -> Vec<String> {
    let mut unused = Vec::new();
    for supp in suppressions {
        let key = format!("{}@{}", supp.rule, supp.path);
        if !used.contains(&key) {
            unused.push(key);
        }
    }
    unused.sort();
    unused
}

struct ParsedSuppression {
    rule: String,
    path: String,
    glob: Glob,
    expired: Option<String>,
    ecosystem: Option<String>,
    package_manager: Option<String>,
    line: Option<u32>,
}

impl ParsedSuppression {
    fn new(idx: usize, supp: &Suppression) -> Option<Self> {
        let glob = Glob::new(&supp.path).ok()?;
        let today = crate::config::today_ymd();
        let expired = supp.expires.as_ref().and_then(|expires| {
            // A suppression is expired on or after its expiry date. Compare
            // parsed dates, not strings, so `2026-6-1` and boundary dates work.
            // A malformed date is treated as expired rather than granting an
            // indefinite suppression (config::validate rejects it earlier).
            let is_expired = match crate::config::parse_iso_date(expires) {
                Some(date) => date <= today,
                None => true,
            };
            is_expired.then(|| expires.clone())
        });
        let _ = idx;
        Some(Self {
            rule: supp.rule.clone(),
            path: supp.path.clone(),
            glob,
            expired,
            ecosystem: supp.ecosystem.clone(),
            package_manager: supp.package_manager.clone(),
            line: supp.line,
        })
    }

    fn matches(&self, finding: &Finding) -> bool {
        if finding.rule_id.as_str() != self.rule {
            return false;
        }
        let path = finding.location_path_string();
        let path = path.strip_prefix("./").unwrap_or(&path);
        let target = self.path.strip_prefix("./").unwrap_or(&self.path);
        if !self.glob.compile_matcher().is_match(path) && path != target {
            return false;
        }
        if let Some(eco) = &self.ecosystem {
            if finding.ecosystem.as_str() != eco {
                return false;
            }
        }
        if let Some(pm) = &self.package_manager {
            if finding.package_manager.map(|p| p.as_str()) != Some(pm.as_str()) {
                return false;
            }
        }
        if let Some(line) = self.line {
            if finding.location.as_ref().and_then(|l| l.line) != Some(line) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostics::{Diagnostic, DiagnosticLevel};

    /// Helper: build an [`AnalysisResult`] with the given diagnostics and no
    /// findings/parse-failures, to test `has_error_diagnostic` in isolation.
    fn result_with_diagnostics(diags: Vec<Diagnostic>) -> AnalysisResult {
        let has_error = diags.iter().any(|d| d.level == DiagnosticLevel::Error);
        AnalysisResult {
            findings: vec![],
            diagnostics: diags,
            unused_suppressions: vec![],
            parse_failures: 0,
            has_error_diagnostic: has_error,
        }
    }

    #[test]
    fn has_error_diagnostic_is_false_with_no_diagnostics() {
        let r = result_with_diagnostics(vec![]);
        assert!(!r.has_error_diagnostic);
    }

    #[test]
    fn has_error_diagnostic_is_false_for_warning_only() {
        let r = result_with_diagnostics(vec![
            Diagnostic::warn("some warning"),
            Diagnostic {
                level: DiagnosticLevel::Info,
                message: "info msg".into(),
                location: None,
            },
        ]);
        assert!(!r.has_error_diagnostic);
    }

    #[test]
    fn has_error_diagnostic_is_true_for_error_level() {
        let r = result_with_diagnostics(vec![
            Diagnostic::warn("a warning"),
            Diagnostic::error("an error"),
        ]);
        assert!(r.has_error_diagnostic);
    }

    #[test]
    fn has_error_diagnostic_is_true_for_error_only() {
        let r = result_with_diagnostics(vec![Diagnostic::error("fatal config problem")]);
        assert!(r.has_error_diagnostic);
    }
}
