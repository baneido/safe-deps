//! CLI definition and dispatch.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use crate::check_runner::{self, CheckRequest};
use crate::config::{self, Config, FailLevel, OutputFormat, ResolvedConfig};
use crate::ecosystems::PackageManager;
use crate::filesystem::{scan, ScanOptions};
use crate::rule::{Profile, RuleId};
use crate::rules::all_rules;

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
    /// Query a vulnerability database (OSV) for known advisories. Unlike
    /// `check`, this is an explicit network operation.
    Audit(AuditArgs),
    /// Explain a rule in detail.
    Explain(ExplainArgs),
    /// List all available rules.
    ListRules,
    /// Write a minimal commented safe-deps.toml.
    Init,
}

#[derive(Args, Default)]
pub struct AuditArgs {
    /// Path to analyze, defaults to the current directory.
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Config path. Overrides discovery; otherwise `<target>/safe-deps.toml`
    /// (relative to the analyzed path) is used when present.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Output format: text or json.
    #[arg(long)]
    pub format: Option<String>,

    /// Use only the local cache; make no network requests.
    #[arg(long)]
    pub offline: bool,

    /// Do not read or write the on-disk cache.
    #[arg(long)]
    pub no_cache: bool,

    /// Cache directory (defaults to the per-user cache dir).
    #[arg(long)]
    pub cache_dir: Option<PathBuf>,

    /// Cache freshness in seconds (default 86400 = 24h).
    #[arg(long = "cache-ttl", default_value_t = 86_400)]
    pub cache_ttl: u64,

    /// Ignore .gitignore while scanning for lockfiles.
    #[arg(long)]
    pub no_gitignore: bool,

    /// Print transport details (e.g. the resolved curl path under the
    /// `curl-transport` build).
    #[arg(long)]
    pub verbose: bool,
}

#[derive(Args, Default)]
pub struct CheckArgs {
    /// Path to analyze, defaults to the current directory.
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Config path. Overrides discovery; otherwise `<target>/safe-deps.toml`
    /// (relative to the analyzed path) is used when present.
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

    /// Restrict to a package manager: npm, yarn, pnpm, bun, pip, uv, cargo, go.
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
        Command::Audit(args) => run_audit_cmd(args),
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

/// Resolves config and arg filters into a [`CheckRequest`], then hands the
/// pipeline to `check_runner`. All argument interpretation/validation lives
/// here; the orchestration does not.
fn run_check(args: CheckArgs) -> Result<u8, CliError> {
    let resolved = resolve_config(&args)?;

    // Validate the ecosystem filter (a bad value is a usage error) and normalize
    // rule ids so `--rule sd3` and `--rule SD003` both match (mirroring
    // `explain`); without normalization a short/lowercase id silently drops
    // every finding and the run exits 0.
    let ecosystem = ecosystem_filter(args.ecosystem.as_deref())?;
    let rules: std::collections::HashSet<String> =
        args.rules.iter().map(|s| normalize_rule_id(s).0).collect();

    let request = CheckRequest {
        path: args.path,
        scan_options: ScanOptions {
            no_gitignore: args.no_gitignore,
            includes: args.includes,
            excludes: args.excludes,
        },
        config: resolved.config,
        profile: resolved.profile,
        format: resolved.format,
        fail_on: resolved.fail_on,
        ecosystem,
        rules,
        output: args.output,
        strict_parser_errors: args.strict_parser_errors,
        verbose: args.verbose,
    };
    check_runner::run(request)
}

fn run_audit_cmd(args: AuditArgs) -> Result<u8, CliError> {
    let config = load_config(args.config.as_deref(), &args.path)?;
    let scan_options = ScanOptions {
        no_gitignore: args.no_gitignore,
        ..Default::default()
    };
    let ctx = scan(&args.path, config.clone(), &scan_options).map_err(CliError::from_scan_error)?;

    let collected = crate::audit::collect::collect(&ctx);
    let coords = collected.coordinates;

    let cache = if args.no_cache {
        None
    } else {
        let dir = args
            .cache_dir
            .clone()
            .unwrap_or_else(crate::audit::cache::Cache::default_dir);
        Some(crate::audit::cache::Cache::new(dir, args.cache_ttl))
    };

    // In offline mode only cached coordinates are actually checked; count the
    // misses so an offline gap is not mistaken for a clean bill of health.
    let offline_unchecked = if args.offline {
        coords
            .iter()
            .filter(|c| !cache.as_ref().is_some_and(|cache| cache.contains(c)))
            .count()
    } else {
        0
    };

    let transport = crate::audit::osv::default_transport();
    // Surface exactly which external binary the curl fallback will invoke so an
    // operator can audit the process boundary. Only meaningful (and only
    // compiled) for the curl-transport build; the default native-http build has
    // no external process to report.
    #[cfg(all(not(feature = "native-http"), feature = "curl-transport"))]
    if args.verbose {
        eprintln!("audit: using curl at {}", transport.curl_path().display());
    }
    let source = crate::audit::osv::OsvSource::new(transport, cache, args.offline);

    let mut report = crate::audit::run_audit(
        &coords,
        &source,
        &config.advisory_ignores,
        config::today_ymd(),
    )
    .map_err(CliError::internal)?;

    // Surface lockfile read/parse failures so an unparsed lockfile is not read
    // as a clean result, plus any directory-walk failures from scanning.
    report
        .diagnostics
        .extend(ctx.scan_diagnostics.iter().map(|d| d.message.clone()));
    report.diagnostics.extend(collected.diagnostics);

    if offline_unchecked > 0 {
        report.packages_audited = coords.len().saturating_sub(offline_unchecked);
        report.diagnostics.push(format!(
            "offline: {offline_unchecked} package(s) not in the cache were not checked"
        ));
    }

    // Resolve format with the same precedence as `check` (CLI flag, then config,
    // then the SAFE_DEPS_FORMAT env var); audit supports text and json.
    let format = resolve_value(
        args.format.as_deref(),
        config.format,
        config::env::FORMAT,
        OutputFormat::Text,
        config::parse_format,
    )?;
    let as_json = match format {
        OutputFormat::Json => true,
        OutputFormat::Text => false,
        other => {
            return Err(CliError::usage(format!(
                "audit does not support '{}' output; use text or json",
                other.as_str()
            )))
        }
    };
    let text = if as_json {
        crate::audit::render_json(&report).map_err(CliError::internal)?
    } else {
        crate::audit::render_text(&report)
    };
    std::io::Write::write_all(&mut std::io::stdout(), text.as_bytes())
        .map_err(CliError::internal)?;
    if !as_json && !text.ends_with('\n') {
        println!();
    }

    Ok(if report.has_findings() { 1 } else { 0 })
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
    let config = load_config(args.config.as_deref(), &args.path)?;
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

/// Loads configuration. An explicit `--config` path always wins; otherwise the
/// default search is anchored at the analysis target (`target/safe-deps.toml`),
/// not the process's current directory, so `safe-deps check /path/to/repo` picks
/// up that repo's config rather than silently using defaults.
fn load_config(explicit: Option<&Path>, target: &Path) -> Result<Config, CliError> {
    if let Some(path) = explicit {
        return Ok(config::load(path)?);
    }
    let default = target.join("safe-deps.toml");
    if default.is_file() {
        return Ok(config::load(&default)?);
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
        "cargo" => PackageManager::Cargo,
        "go" => PackageManager::Go,
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
    pub(crate) fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: CliErrorKind::Usage,
        }
    }

    pub(crate) fn internal<E: std::fmt::Display>(err: E) -> Self {
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

    /// Converts a [`crate::filesystem::FsError`] into the appropriate
    /// [`CliError`] variant: user-input errors (path missing or not a
    /// directory) become `Usage` (exit 2); all other filesystem errors become
    /// `Internal` (exit 3).
    pub(crate) fn from_scan_error(err: crate::filesystem::FsError) -> Self {
        if err.is_user_input_error() {
            Self::usage(err.to_string())
        } else {
            Self::internal(err)
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

# Advisory ignores apply to `safe-deps audit` (the networked OSV mode).
# [[advisory_ignores]]
# id = \"RUSTSEC-2024-0001\"
# reason = \"Not reachable; tracked in TICKET-123\"
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
        assert_eq!(
            ecosystem_filter(Some("cargo")).unwrap(),
            Some(PackageManager::Cargo)
        );
        assert_eq!(
            ecosystem_filter(Some("go")).unwrap(),
            Some(PackageManager::Go)
        );
        assert!(ecosystem_filter(Some("composer")).is_err());
    }

    #[test]
    fn cli_parses_without_panicking() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
