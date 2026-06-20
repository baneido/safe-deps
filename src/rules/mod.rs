//! Rule registry and analysis engine.
//!
//! The engine detects projects, extracts facts, runs all rules, then applies
//! config rule-level overrides and suppressions. Findings and diagnostics are
//! kept separate.

use std::collections::HashSet;

use globset::Glob;

use crate::ci::CiFacts;
use crate::config::{Config, Suppression};
use crate::diagnostics::{Diagnostic, DiagnosticLevel};
use crate::ecosystems::{detect_all, facts_for};
use crate::filesystem::WorkspaceContext;
use crate::project::refine_kinds;
use crate::report::sort_findings;
use crate::rule::{Finding, Profile, Rule, RuleInput};

pub mod sd001_lockfile_missing;
pub mod sd002_non_frozen_ci_install;
pub mod sd003_insecure_registry;
pub mod sd004_integrity_disabled;

/// Returns all built-in rules.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(sd001_lockfile_missing::Sd001),
        Box::new(sd002_non_frozen_ci_install::Sd002),
        Box::new(sd003_insecure_registry::Sd003),
        Box::new(sd004_integrity_disabled::Sd004),
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
}

/// Runs all rules over all detected projects.
pub fn analyze(ctx: &WorkspaceContext, profile: Profile, ci_facts: &CiFacts) -> AnalysisResult {
    let mut diagnostics = Vec::new();

    let mut projects = detect_all(ctx);
    refine_kinds(&mut projects, ctx);

    let mut parse_failures = 0;
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
                .flat_map(|rule| rule.evaluate(&input))
                .collect::<Vec<_>>()
        })
        .collect();

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

    AnalysisResult {
        findings,
        diagnostics,
        unused_suppressions,
        parse_failures,
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
        let expired = supp.expires.as_ref().and_then(|expires| {
            if expires.as_str() < today_string().as_str() {
                Some(expires.clone())
            } else {
                None
            }
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

fn today_string() -> String {
    let (y, m, d) = today_ymd();
    format!("{y:04}-{m:02}-{d:02}")
}

fn today_ymd() -> (i64, u32, u32) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86400);
    civil_from_days(days)
}

/// Converts days since the Unix epoch to a proleptic Gregorian (year, month, day).
/// Based on Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
