//! SD003: Insecure registry or TLS bypass.
//!
//! Flags plaintext HTTP registries and explicit TLS verification bypasses:
//! npm/pnpm `strict-ssl=false` and HTTP registries, Yarn `unsafeHttpWhitelist`,
//! pip `--trusted-host` and HTTP indexes, and uv `allow-insecure-host`.

use crate::ecosystems::{PackageManager, Sourced};
use crate::rule::{Confidence, Finding, Location, Rule, RuleId, RuleInput, Severity};
use crate::rules::{config_loc, config_loc_at, pip_config_loc};

pub struct Sd003;

impl Rule for Sd003 {
    fn id(&self) -> RuleId {
        RuleId::new("SD003")
    }

    fn summary(&self) -> &'static str {
        "Registry or index uses HTTP or TLS verification is disabled."
    }

    fn explanation(&self) -> &'static str {
        "Use HTTPS registries and keep TLS verification enabled. Flagged \
signals include npm/pnpm strict-ssl=false and http:// registries, Yarn \
unsafeHttpWhitelist, pip --trusted-host and HTTP indexes, and uv \
allow-insecure-host. Local test exceptions should be scoped narrowly."
    }

    fn evaluate(&self, input: &RuleInput) -> Vec<Finding> {
        let facts = input.facts;
        let settings = &facts.install_settings;
        let pm = facts.project.package_manager;
        let mut findings = Vec::new();

        match pm {
            PackageManager::Npm | PackageManager::Pnpm => {
                if settings.strict_ssl == Some(false) {
                    findings.push(finding(
                        input,
                        "strict-ssl=false disables TLS verification for the registry.",
                        Some("set strict-ssl=true (the default) or remove the override."),
                        config_loc_at(facts, ".npmrc", settings.strict_ssl_line),
                    ));
                }
                for url in &settings.http_registries {
                    findings.push(finding(
                        input,
                        format!("registry uses plaintext HTTP: {url}"),
                        Some("use an https:// registry URL."),
                        config_loc(facts, ".npmrc"),
                    ));
                }
            }
            PackageManager::Yarn => {
                if !settings.unsafe_http_whitelist.is_empty() {
                    findings.push(finding(
                        input,
                        format!(
                            "unsafeHttpWhitelist is non-empty ({} entr{}); HTTP downloads are allowed for these hosts.",
                            settings.unsafe_http_whitelist.len(),
                            if settings.unsafe_http_whitelist.len() == 1 { "y" } else { "ies" }
                        ),
                        Some("remove unsafeHttpWhitelist or scope it to local test hosts only."),
                        config_loc(facts, ".yarnrc.yml"),
                    ));
                }
            }
            PackageManager::Pip => {
                for host in &settings.trusted_hosts {
                    findings.push(finding(
                        input,
                        format!(
                            "trusted-host '{}' bypasses TLS verification for pip.",
                            host.value
                        ),
                        Some("remove --trusted-host or scope it to a pinned internal host."),
                        sourced_loc(host, || {
                            pip_config_loc(facts).or_else(|| config_loc(facts, "requirements.txt"))
                        }),
                    ));
                }
                for url in settings
                    .index_urls
                    .iter()
                    .chain(settings.extra_index_urls.iter())
                    .filter(|u| crate::ecosystems::is_http_url(&u.value))
                {
                    findings.push(finding(
                        input,
                        format!("pip index URL uses plaintext HTTP: {}", url.value),
                        Some("use an https:// index URL."),
                        sourced_loc(url, || {
                            pip_config_loc(facts).or_else(|| config_loc(facts, "requirements.txt"))
                        }),
                    ));
                }
            }
            PackageManager::Uv => {
                for host in &settings.allow_insecure_hosts {
                    findings.push(finding(
                        input,
                        format!("allow-insecure-host '{host}' bypasses TLS verification for uv."),
                        Some("remove allow-insecure-host or scope it to a pinned internal host."),
                        config_loc(facts, "uv.toml")
                            .or_else(|| config_loc(facts, "pyproject.toml")),
                    ));
                }
                for url in settings
                    .index_urls
                    .iter()
                    .chain(settings.extra_index_urls.iter())
                    .filter(|u| crate::ecosystems::is_http_url(&u.value))
                {
                    findings.push(finding(
                        input,
                        format!("uv index URL uses plaintext HTTP: {}", url.value),
                        Some("use an https:// index URL."),
                        sourced_loc(url, || {
                            config_loc(facts, "uv.toml")
                                .or_else(|| config_loc(facts, "pyproject.toml"))
                        }),
                    ));
                }
            }
            PackageManager::Bun | PackageManager::Cargo | PackageManager::Go => {}
        }

        findings
    }
}

fn finding(
    input: &RuleInput,
    message: impl Into<String>,
    remediation: Option<&str>,
    location: Option<Location>,
) -> Finding {
    let facts = input.facts;
    Finding {
        rule_id: RuleId::new("SD003"),
        severity: Severity::Error,
        confidence: Confidence::High,
        message: message.into(),
        location,
        project_root: facts.project.root.clone(),
        ecosystem: facts.project.ecosystem,
        package_manager: Some(facts.project.package_manager),
        remediation: remediation.map(|s| s.to_string()),
    }
}

/// Locates a finding on the exact file that declared `setting`, falling back to
/// `default` (the usual config heuristic) when the source file is unknown. This
/// keeps a `pip.ini`-only setting off `pip.conf` when both files exist.
fn sourced_loc<T>(
    setting: &Sourced<T>,
    default: impl FnOnce() -> Option<Location>,
) -> Option<Location> {
    match &setting.source {
        Some(path) => Some(Location::file(path)),
        None => default(),
    }
}
