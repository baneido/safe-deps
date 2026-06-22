//! Optional networked audit mode (`safe-deps audit`).
//!
//! `safe-deps check` is static and offline by design; this module is the
//! deliberately-separate networked path. It collects pinned package coordinates
//! from lockfiles, queries a vulnerability source (OSV by default), applies the
//! configured advisory ignores, and renders a report. Network access is
//! confined to the [`VulnerabilitySource`] implementation, so the rest of the
//! tool — and `check` — never touches the network.

use serde::{Deserialize, Serialize};

use crate::config::AdvisoryIgnore;

pub mod cache;
pub mod collect;
pub mod osv;

/// A pinned package, identified the way OSV expects: an ecosystem string
/// (`crates.io`, `npm`, `PyPI`, `Go`), a name, and an exact version.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PackageCoordinate {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

impl PackageCoordinate {
    /// A stable, collision-free, filesystem-safe cache key. A readable but
    /// lossy prefix aids debugging; an FNV-1a hash of the exact coordinate
    /// (ecosystem, name, version, NUL-separated) guarantees distinct
    /// coordinates never share a key even when their punctuation sanitizes the
    /// same (e.g. `@scope/pkg` vs `scope_pkg`).
    pub fn cache_key(&self) -> String {
        let readable: String = format!("{}_{}", self.ecosystem, self.name)
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .take(48)
            .collect();
        let canonical = format!("{}\0{}\0{}", self.ecosystem, self.name, self.version);
        format!("{readable}-{:016x}", fnv1a64(&canonical))
    }
}

/// FNV-1a 64-bit hash; deterministic and dependency-free, used only for cache
/// key disambiguation (not security).
fn fnv1a64(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// A vulnerability advisory affecting a specific package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub severity: Option<String>,
    pub package: PackageCoordinate,
}

impl Advisory {
    /// Whether this advisory is referenced by `id` (its own id or an alias).
    fn matches_id(&self, id: &str) -> bool {
        self.id == id || self.aliases.iter().any(|a| a == id)
    }
}

/// A source of vulnerability data for a set of package coordinates.
///
/// The `Ok` variant carries both the advisories and any non-fatal diagnostic
/// strings (e.g. cache write failures) the source encountered. Callers should
/// surface those strings alongside the rest of the report diagnostics.
pub trait VulnerabilitySource {
    fn query(
        &self,
        coords: &[PackageCoordinate],
    ) -> Result<(Vec<Advisory>, Vec<String>), AuditError>;
}

/// Errors produced during an audit run.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit transport error: {0}")]
    Transport(String),
    #[error("failed to parse vulnerability response: {0}")]
    Parse(String),
}

/// An advisory that matched an active ignore entry.
#[derive(Debug, Clone, Serialize)]
pub struct IgnoredAdvisory {
    pub advisory: Advisory,
    pub reason: String,
}

/// The result of an audit run.
#[derive(Debug, Default, Serialize)]
pub struct AuditReport {
    /// Active (non-ignored) advisories.
    pub advisories: Vec<Advisory>,
    /// Advisories suppressed by an active ignore entry.
    pub ignored: Vec<IgnoredAdvisory>,
    /// Non-fatal notes (e.g. expired ignores, offline cache misses).
    pub diagnostics: Vec<String>,
    /// Number of package coordinates queried.
    pub packages_audited: usize,
}

impl AuditReport {
    /// Whether the run found active vulnerabilities (drives the exit code).
    pub fn has_findings(&self) -> bool {
        !self.advisories.is_empty()
    }
}

/// Runs an audit: queries `source` for `coords`, then partitions the resulting
/// advisories into active vs ignored using `ignores`, honoring each ignore's
/// expiry against `today` (`(year, month, day)`).
pub fn run_audit(
    coords: &[PackageCoordinate],
    source: &dyn VulnerabilitySource,
    ignores: &[AdvisoryIgnore],
    today: (i64, u32, u32),
) -> Result<AuditReport, AuditError> {
    let mut report = AuditReport {
        packages_audited: coords.len(),
        ..Default::default()
    };

    // Partition ignores into active and expired, surfacing a diagnostic for
    // each expired one (it no longer suppresses, matching the suppression model).
    let mut active_ignores: Vec<&AdvisoryIgnore> = Vec::new();
    for ignore in ignores {
        match ignore.expires.as_deref().map(crate::config::parse_iso_date) {
            Some(Some(date)) if date <= today => report.diagnostics.push(format!(
                "advisory_ignore for {} expired on {}",
                ignore.id,
                ignore.expires.as_deref().unwrap_or("")
            )),
            // Malformed dates are rejected by config::validate; treat an
            // unparseable one here defensively as expired.
            Some(None) => report.diagnostics.push(format!(
                "advisory_ignore for {} has an unparseable expiry",
                ignore.id
            )),
            _ => active_ignores.push(ignore),
        }
    }

    let (mut advisories, source_diagnostics) = source.query(coords)?;
    report.diagnostics.extend(source_diagnostics);
    // Deterministic ordering: by package (incl. version, since a name can appear
    // at multiple versions) then advisory id.
    advisories.sort_by_key(|a| {
        (
            a.package.ecosystem.clone(),
            a.package.name.clone(),
            a.package.version.clone(),
            a.id.clone(),
        )
    });

    for advisory in advisories {
        match active_ignores.iter().find(|ig| advisory.matches_id(&ig.id)) {
            Some(ignore) => report.ignored.push(IgnoredAdvisory {
                advisory,
                reason: ignore.reason.clone(),
            }),
            None => report.advisories.push(advisory),
        }
    }
    Ok(report)
}

/// Renders an audit report as deterministic plain text.
pub fn render_text(report: &AuditReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("audited {} package(s)\n", report.packages_audited));
    if report.advisories.is_empty() {
        out.push_str("No known vulnerabilities.\n");
    } else {
        out.push_str(&format!(
            "\nVulnerabilities ({}):\n",
            report.advisories.len()
        ));
        for a in &report.advisories {
            out.push_str(&format!(
                "  {} {}@{} [{}]\n    {}\n",
                a.id,
                a.package.name,
                a.package.version,
                a.severity.as_deref().unwrap_or("unknown severity"),
                if a.summary.is_empty() {
                    "(no summary)"
                } else {
                    &a.summary
                }
            ));
        }
    }
    if !report.ignored.is_empty() {
        out.push_str(&format!("\nIgnored ({}):\n", report.ignored.len()));
        for i in &report.ignored {
            out.push_str(&format!(
                "  {} {}@{} — {}\n",
                i.advisory.id, i.advisory.package.name, i.advisory.package.version, i.reason
            ));
        }
    }
    for d in &report.diagnostics {
        out.push_str(&format!("note: {d}\n"));
    }
    out
}

/// Renders an audit report as stable JSON.
pub fn render_json(report: &AuditReport) -> Result<String, AuditError> {
    serde_json::to_string_pretty(report).map_err(|e| AuditError::Parse(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coord(name: &str) -> PackageCoordinate {
        PackageCoordinate {
            ecosystem: "crates.io".to_string(),
            name: name.to_string(),
            version: "1.0.0".to_string(),
        }
    }

    fn advisory(id: &str, aliases: &[&str], pkg: &str) -> Advisory {
        Advisory {
            id: id.to_string(),
            aliases: aliases.iter().map(|s| s.to_string()).collect(),
            summary: "boom".to_string(),
            severity: Some("HIGH".to_string()),
            package: coord(pkg),
        }
    }

    struct Fake(Vec<Advisory>);
    impl VulnerabilitySource for Fake {
        fn query(
            &self,
            _coords: &[PackageCoordinate],
        ) -> Result<(Vec<Advisory>, Vec<String>), AuditError> {
            Ok((self.0.clone(), vec![]))
        }
    }

    fn ignore(id: &str, expires: Option<&str>) -> AdvisoryIgnore {
        AdvisoryIgnore {
            id: id.to_string(),
            reason: "tracked elsewhere".to_string(),
            expires: expires.map(|s| s.to_string()),
        }
    }

    #[test]
    fn active_advisory_is_reported() {
        let src = Fake(vec![advisory("RUSTSEC-1", &[], "left-pad")]);
        let r = run_audit(&[coord("left-pad")], &src, &[], (2026, 1, 1)).unwrap();
        assert_eq!(r.advisories.len(), 1);
        assert!(r.has_findings());
    }

    #[test]
    fn ignore_by_id_or_alias_suppresses() {
        let src = Fake(vec![advisory("RUSTSEC-1", &["CVE-9"], "left-pad")]);
        let by_id = run_audit(
            &[coord("x")],
            &src,
            &[ignore("RUSTSEC-1", None)],
            (2026, 1, 1),
        )
        .unwrap();
        assert!(by_id.advisories.is_empty());
        assert_eq!(by_id.ignored.len(), 1);
        let by_alias =
            run_audit(&[coord("x")], &src, &[ignore("CVE-9", None)], (2026, 1, 1)).unwrap();
        assert_eq!(by_alias.ignored.len(), 1);
    }

    #[test]
    fn expired_ignore_does_not_suppress_and_warns() {
        let src = Fake(vec![advisory("RUSTSEC-1", &[], "left-pad")]);
        let r = run_audit(
            &[coord("x")],
            &src,
            &[ignore("RUSTSEC-1", Some("2020-01-01"))],
            (2026, 1, 1),
        )
        .unwrap();
        assert_eq!(r.advisories.len(), 1, "expired ignore must not suppress");
        assert!(r.diagnostics.iter().any(|d| d.contains("expired")));
    }

    #[test]
    fn future_expiry_ignore_still_suppresses() {
        let src = Fake(vec![advisory("RUSTSEC-1", &[], "left-pad")]);
        let r = run_audit(
            &[coord("x")],
            &src,
            &[ignore("RUSTSEC-1", Some("2999-01-01"))],
            (2026, 1, 1),
        )
        .unwrap();
        assert_eq!(r.ignored.len(), 1);
        assert!(r.advisories.is_empty());
    }
}
