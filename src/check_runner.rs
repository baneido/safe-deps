//! The `check` application service.
//!
//! Owns the offline analysis pipeline — scan → CI facts → rules → report →
//! exit code — so `cli` is left with argument parsing and turning args into a
//! [`CheckRequest`]. The request carries already-resolved, already-validated
//! inputs; this module performs no argument interpretation.

use std::collections::HashSet;
use std::path::PathBuf;

use crate::ci;
use crate::cli::CliError;
use crate::config::{Config, FailLevel, OutputFormat};
use crate::ecosystems::PackageManager;
use crate::filesystem::{scan, ScanOptions};
use crate::report::{reporter_for, Report};
use crate::rule::Profile;
use crate::rules;

const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Resolved, validated inputs for one `check` run, produced by the CLI layer.
pub struct CheckRequest {
    pub path: PathBuf,
    pub scan_options: ScanOptions,
    pub config: Config,
    pub profile: Profile,
    pub format: OutputFormat,
    pub fail_on: FailLevel,
    /// Restrict findings to one package manager (already parsed/validated).
    pub ecosystem: Option<PackageManager>,
    /// Restrict findings to these normalized rule ids; empty means all rules.
    pub rules: HashSet<String>,
    /// Write the report here instead of stdout.
    pub output: Option<PathBuf>,
    pub strict_parser_errors: bool,
    pub verbose: bool,
}

/// Runs the offline `check` pipeline and returns the process exit code
/// (`0` clean, `1` findings at/above `fail_on` **or** any error-level
/// diagnostic, `4` parse failure under `strict_parser_errors`).
pub fn run(req: CheckRequest) -> Result<u8, CliError> {
    let ctx = scan(&req.path, req.config, &req.scan_options).map_err(CliError::from_scan_error)?;

    if req.verbose {
        eprintln!(
            "scanned {} files under {}",
            ctx.files.len(),
            crate::path::normalize_separators(&ctx.root)
        );
    }

    let ci_facts = ci::extract(&ctx);
    if req.verbose {
        eprintln!(
            "extracted {} CI command(s) and {} env assignment(s)",
            ci_facts.commands.len(),
            ci_facts.env.len()
        );
    }

    let mut result = rules::analyze(&ctx, req.profile, &ci_facts);

    if let Some(pm) = req.ecosystem {
        result.findings.retain(|f| f.package_manager == Some(pm));
    }
    if !req.rules.is_empty() {
        result
            .findings
            .retain(|f| req.rules.contains(f.rule_id.as_str()));
    }

    let parse_failures = result.parse_failures;
    let has_error_diagnostic = result.has_error_diagnostic;
    let mut report = Report::new(req.path.clone(), req.profile, TOOL_VERSION);
    report.findings = result.findings;
    report.diagnostics = result.diagnostics;

    let bytes = reporter_for(req.format)
        .format(&report)
        .map_err(CliError::internal)?;

    if let Some(out) = &req.output {
        std::fs::write(out, &bytes).map_err(CliError::internal)?;
    } else {
        std::io::Write::write_all(&mut std::io::stdout(), &bytes).map_err(CliError::internal)?;
    }

    let failing = report
        .findings
        .iter()
        .any(|f| req.fail_on.triggers(f.severity));
    let strict_parse_failure = req.strict_parser_errors && parse_failures > 0;

    if strict_parse_failure {
        Ok(4)
    } else if failing || has_error_diagnostic {
        Ok(1)
    } else {
        Ok(0)
    }
}
