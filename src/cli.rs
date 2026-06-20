//! CLI definition and dispatch.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use crate::ci::CiFacts;
use crate::config::{self, Config, FailLevel, OutputFormat, ResolvedConfig};
use crate::ecosystems::PackageManager;
use crate::filesystem::{scan, ScanOptions};
use crate::report::{reporter_for, Report};
use crate::rule::{Profile, RuleId};
use crate::rules::{self, all_rules};

const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "safe-deps",
    version,
    about = "Static linter for package-management security practices."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
// `Check` carries all the analysis flags and is intentionally the large variant;
// boxing it would complicate the clap-derived parsing for no real benefit.
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Run the linter (default when no subcommand is given).
    Check(CheckArgs),
    /// Explain a rule in detail.
    Explain(ExplainArgs),
    /// List all available rules.
    ListRules,
    /// Write a minimal commented safe-deps.toml.
    Init,
}

#[derive(Args, Default)]
pub struct CheckArgs {
    /// Path to analyze, defaults to the current directory.
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Config path. Defaults to ./safe-deps.toml when present.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Analysis profile: balanced, strict, permissive.
    #[arg(long)]
    pub profile: Option<String>,

    /// Output format: text, json, sarif, junit.
    #[arg(long)]
    pub format: Option<String>,

    /// Write the report to a file instead of stdout.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Fail threshold: error, warning, info, none.
    #[arg(long = "fail-on")]
    pub fail_on: Option<String>,

    /// Ignore .gitignore while scanning.
    #[arg(long)]
    pub no_gitignore: bool,

    /// Additional include glob (repeatable).
    #[arg(long = "include")]
    pub includes: Vec<String>,

    /// Additional exclude glob (repeatable).
    #[arg(long = "exclude")]
    pub excludes: Vec<String>,

    /// Restrict to a package manager: npm, yarn, pnpm, bun, pip, uv.
    #[arg(long)]
    pub ecosystem: Option<String>,

    /// Restrict to a rule ID (repeatable).
    #[arg(long = "rule")]
    pub rules: Vec<String>,

    /// Exit non-zero when supported files cannot be parsed.
    #[arg(long)]
    pub strict_parser_errors: bool,

    /// Explicit offline flag (default behavior for check).
    #[arg(long)]
    pub offline: bool,

    /// Print detection details.
    #[arg(long)]
    pub verbose: bool,

    /// Only print the findings summary.
    #[arg(long, short = 'q')]
    pub quiet: bool,
}

#[derive(Args)]
pub struct ExplainArgs {
    /// Rule ID to explain, e.g. SD001.
    pub rule_id: String,
}

/// Entry point used by `main`.
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command.unwrap_or(Command::Check(CheckArgs {
        path: PathBuf::from("."),
        ..Default::default()
    })) {
        Command::Check(args) => run_check(args),
        Command::Explain(args) => run_explain(&args.rule_id),
        Command::ListRules => run_list_rules(),
        Command::Init => run_init(),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(err.exit_code())
        }
    }
}

fn run_check(args: CheckArgs) -> Result<u8, CliError> {
    let resolved = resolve_config(&args)?;

    let config = resolved.config.clone();
    let scan_options = ScanOptions {
        no_gitignore: args.no_gitignore,
        includes: args.includes.clone(),
        excludes: args.excludes.clone(),
    };
    let ctx = scan(&args.path, config, &scan_options).map_err(CliError::internal)?;

    if args.verbose {
        eprintln!(
            "scanned {} files under {}",
            ctx.files.len(),
            ctx.root.display()
        );
    }

    let ci_facts = CiFacts::empty();
    let mut result = rules::analyze(&ctx, resolved.profile, &ci_facts);

    if let Some(pm) = ecosystem_filter(args.ecosystem.as_deref())? {
        result.findings.retain(|f| f.package_manager == Some(pm));
    }
    if !args.rules.is_empty() {
        let allowed: std::collections::HashSet<String> =
            args.rules.iter().map(|s| s.to_string()).collect();
        result
            .findings
            .retain(|f| allowed.contains(f.rule_id.as_str()));
    }

    let parse_failures = result.parse_failures;
    let mut report = Report::new(args.path.clone(), resolved.profile, TOOL_VERSION);
    report.findings = result.findings;
    report.diagnostics = result.diagnostics;

    let reporter = reporter_for(resolved.format);
    let bytes = reporter.format(&report).map_err(CliError::internal)?;

    if let Some(out) = &args.output {
        std::fs::write(out, &bytes).map_err(CliError::internal)?;
    } else {
        std::io::Write::write_all(&mut std::io::stdout(), &bytes).map_err(CliError::internal)?;
    }

    let failing = report
        .findings
        .iter()
        .any(|f| resolved.fail_on.triggers(f.severity));
    let strict_parse_failure = args.strict_parser_errors && parse_failures > 0;

    if strict_parse_failure {
        Ok(4)
    } else if failing {
        Ok(1)
    } else {
        Ok(0)
    }
}

fn run_explain(rule_id: &str) -> Result<u8, CliError> {
    let id = normalize_rule_id(rule_id);
    for rule in all_rules() {
        if rule.id() == id {
            println!("{}: {}", rule.id(), rule.summary());
            println!();
            println!("{}", rule.explanation());
            return Ok(0);
        }
    }
    Err(CliError::usage(format!("unknown rule {rule_id}")))
}

fn run_list_rules() -> Result<u8, CliError> {
    println!("{:<8}  Summary", "ID");
    for rule in all_rules() {
        println!("{:<8}  {}", rule.id(), rule.summary());
    }
    Ok(0)
}

fn run_init() -> Result<u8, CliError> {
    let path = Path::new("safe-deps.toml");
    if path.exists() {
        return Err(CliError::usage(
            "safe-deps.toml already exists in the current directory".to_string(),
        ));
    }
    std::fs::write(path, DEFAULT_CONFIG).map_err(CliError::internal)?;
    println!("wrote safe-deps.toml");
    Ok(0)
}

fn resolve_config(args: &CheckArgs) -> Result<ResolvedConfig, CliError> {
    let config = load_config(args.config.as_deref())?;
    let profile = resolve_value(
        args.profile.as_deref(),
        config.profile,
        config::env::PROFILE,
        Profile::Balanced,
        config::parse_profile,
    )?;
    let format = resolve_value(
        args.format.as_deref(),
        config.format,
        config::env::FORMAT,
        OutputFormat::Text,
        config::parse_format,
    )?;
    let fail_on = match args.fail_on.as_deref() {
        Some(s) => Some(config::parse_fail_on(s)?),
        None => config.fail_on,
    }
    .unwrap_or(FailLevel::Error);

    Ok(ResolvedConfig {
        profile,
        fail_on,
        format,
        config,
    })
}

fn load_config(explicit: Option<&Path>) -> Result<Config, CliError> {
    if let Some(path) = explicit {
        return Ok(config::load(path)?);
    }
    let default = Path::new("safe-deps.toml");
    if default.is_file() {
        return Ok(config::load(default)?);
    }
    Ok(Config::default())
}

fn resolve_value<T>(
    cli: Option<&str>,
    config: Option<T>,
    env_name: &str,
    default: T,
    parse: fn(&str) -> Result<T, config::ConfigError>,
) -> Result<T, CliError> {
    if let Some(s) = cli {
        return Ok(parse(s)?);
    }
    if let Some(value) = config {
        return Ok(value);
    }
    if let Ok(s) = std::env::var(env_name) {
        if !s.is_empty() {
            return Ok(parse(&s)?);
        }
    }
    Ok(default)
}

fn ecosystem_filter(name: Option<&str>) -> Result<Option<PackageManager>, CliError> {
    let Some(name) = name else { return Ok(None) };
    let pm = match name.to_ascii_lowercase().as_str() {
        "npm" => PackageManager::Npm,
        "yarn" => PackageManager::Yarn,
        "pnpm" => PackageManager::Pnpm,
        "bun" => PackageManager::Bun,
        "pip" => PackageManager::Pip,
        "uv" => PackageManager::Uv,
        other => return Err(CliError::usage(format!("unknown ecosystem '{other}'"))),
    };
    Ok(Some(pm))
}

fn normalize_rule_id(raw: &str) -> RuleId {
    let upper = raw.to_ascii_uppercase();
    let digits = upper.strip_prefix("SD").unwrap_or(&upper);
    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        if let Ok(n) = digits.parse::<u32>() {
            // Zero-pad so `SD3`, `sd3`, and `3` all resolve to `SD003`.
            return RuleId::new(format!("SD{n:03}"));
        }
    }
    RuleId::new(if upper.starts_with("SD") {
        upper
    } else {
        format!("SD{upper}")
    })
}

/// CLI error with an associated exit code.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct CliError {
    message: String,
    kind: CliErrorKind,
}

#[derive(Debug)]
enum CliErrorKind {
    Usage,
    Internal,
}

impl CliError {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: CliErrorKind::Usage,
        }
    }

    fn internal<E: std::fmt::Display>(err: E) -> Self {
        Self {
            message: err.to_string(),
            kind: CliErrorKind::Internal,
        }
    }

    pub fn exit_code(&self) -> u8 {
        match self.kind {
            CliErrorKind::Usage => 2,
            CliErrorKind::Internal => 3,
        }
    }
}

impl From<config::ConfigError> for CliError {
    fn from(err: config::ConfigError) -> Self {
        Self {
            message: err.to_string(),
            kind: CliErrorKind::Usage,
        }
    }
}

const DEFAULT_CONFIG: &str = "\
# safe-deps configuration. See https://github.com/baneido/safe-deps
profile = \"balanced\"
fail_on = \"error\"
format = \"text\"

[workspace]
exclude = []

[policy]
# application_roots = [\"apps/**\", \"services/**\"]
# library_roots = [\"packages/**\"]
allow_local_path_dependencies = false
allow_git_dependencies = false
require_audit_in_ci = true

# [[suppressions]]
# rule = \"SD006\"
# path = \"tools/dev-fixtures/package.json\"
# reason = \"Fixture intentionally uses a git dependency\"
# expires = \"2026-12-31\"
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_rule_id_variants() {
        assert_eq!(normalize_rule_id("SD003"), "SD003");
        assert_eq!(normalize_rule_id("sd003"), "SD003");
        assert_eq!(normalize_rule_id("SD3"), "SD003");
        assert_eq!(normalize_rule_id("sd3"), "SD003");
        assert_eq!(normalize_rule_id("3"), "SD003");
    }

    #[test]
    fn ecosystem_filter_parses_known_names() {
        assert_eq!(
            ecosystem_filter(Some("pnpm")).unwrap(),
            Some(PackageManager::Pnpm)
        );
        assert_eq!(ecosystem_filter(None).unwrap(), None);
        assert!(ecosystem_filter(Some("cargo")).is_err());
    }

    #[test]
    fn cli_parses_without_panicking() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
