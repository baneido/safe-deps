//! OSV.dev vulnerability source.
//!
//! Queries <https://osv.dev> for the given coordinates. Network I/O is behind
//! the [`HttpTransport`] trait so the audit logic is testable without a network,
//! and so the HTTP mechanism (the default shells out to `curl`, which is
//! ubiquitous and keeps the binary dependency-free) can be swapped later. A
//! single `querybatch` POST covers all packages; advisory details are fetched
//! once per unique vulnerability id and cached.

use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};

use serde::Deserialize;

use crate::audit::cache::Cache;
use crate::audit::{Advisory, AuditError, PackageCoordinate, VulnerabilitySource};

const QUERYBATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const VULN_URL: &str = "https://api.osv.dev/v1/vulns/";

/// An HTTP transport abstraction. Implementations must perform real network I/O
/// only here; everything else in the audit path stays offline.
pub trait HttpTransport {
    fn post_json(&self, url: &str, body: &str) -> Result<String, AuditError>;
    fn get(&self, url: &str) -> Result<String, AuditError>;
}

/// Default transport: invokes the system `curl`.
pub struct CurlTransport;

impl HttpTransport for CurlTransport {
    fn post_json(&self, url: &str, body: &str) -> Result<String, AuditError> {
        let mut child = Command::new("curl")
            .args([
                "-sS",
                "--max-time",
                "30",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "--data-binary",
                "@-",
                url,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| AuditError::Transport(format!("could not run curl: {e}")))?;
        child
            .stdin
            .take()
            .ok_or_else(|| AuditError::Transport("curl stdin unavailable".into()))?
            .write_all(body.as_bytes())
            .map_err(|e| AuditError::Transport(e.to_string()))?;
        finish(child)
    }

    fn get(&self, url: &str) -> Result<String, AuditError> {
        let child = Command::new("curl")
            .args(["-sS", "--max-time", "30", url])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| AuditError::Transport(format!("could not run curl: {e}")))?;
        finish(child)
    }
}

fn finish(child: std::process::Child) -> Result<String, AuditError> {
    let out = child
        .wait_with_output()
        .map_err(|e| AuditError::Transport(e.to_string()))?;
    if !out.status.success() {
        return Err(AuditError::Transport(format!(
            "curl failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Queries OSV for advisories, using `cache` to avoid refetching.
pub struct OsvSource<T: HttpTransport> {
    transport: T,
    cache: Option<Cache>,
    offline: bool,
}

impl<T: HttpTransport> OsvSource<T> {
    pub fn new(transport: T, cache: Option<Cache>, offline: bool) -> Self {
        Self {
            transport,
            cache,
            offline,
        }
    }
}

impl<T: HttpTransport> VulnerabilitySource for OsvSource<T> {
    fn query(&self, coords: &[PackageCoordinate]) -> Result<Vec<Advisory>, AuditError> {
        let mut out = Vec::new();
        let mut to_fetch = Vec::new();

        for coord in coords {
            if let Some(cache) = &self.cache {
                if let Some(hit) = cache.get_fresh(coord) {
                    out.extend(hit);
                    continue;
                }
                if self.offline {
                    if let Some(stale) = cache.get_any(coord) {
                        out.extend(stale);
                    }
                    continue;
                }
            } else if self.offline {
                continue;
            }
            to_fetch.push(coord.clone());
        }

        if !to_fetch.is_empty() {
            out.extend(self.fetch(&to_fetch)?);
        }
        Ok(out)
    }
}

impl<T: HttpTransport> OsvSource<T> {
    fn fetch(&self, coords: &[PackageCoordinate]) -> Result<Vec<Advisory>, AuditError> {
        let body = querybatch_body(coords);
        let response = self.transport.post_json(QUERYBATCH_URL, &body)?;
        let ids_per_coord = parse_querybatch(&response, coords.len())?;

        // Fetch each unique vulnerability's details once.
        let mut details: BTreeMap<String, VulnDetail> = BTreeMap::new();
        for ids in &ids_per_coord {
            for id in ids {
                if !details.contains_key(id) {
                    let raw = self.transport.get(&format!("{VULN_URL}{id}"))?;
                    details.insert(id.clone(), parse_vuln_detail(&raw, id));
                }
            }
        }

        let mut out = Vec::new();
        for (coord, ids) in coords.iter().zip(ids_per_coord.iter()) {
            let advisories: Vec<Advisory> = ids
                .iter()
                .map(|id| {
                    let d = details.get(id).cloned().unwrap_or_default();
                    Advisory {
                        id: id.clone(),
                        aliases: d.aliases,
                        summary: d.summary,
                        severity: d.severity,
                        package: coord.clone(),
                    }
                })
                .collect();
            if let Some(cache) = &self.cache {
                cache.put(coord, &advisories);
            }
            out.extend(advisories);
        }
        Ok(out)
    }
}

/// Builds the OSV `querybatch` request body for a set of coordinates.
fn querybatch_body(coords: &[PackageCoordinate]) -> String {
    let queries: Vec<serde_json::Value> = coords
        .iter()
        .map(|c| {
            serde_json::json!({
                "package": { "ecosystem": c.ecosystem, "name": c.name },
                "version": c.version,
            })
        })
        .collect();
    serde_json::json!({ "queries": queries }).to_string()
}

/// Parses a `querybatch` response into a list of vulnerability ids per query,
/// in query order.
fn parse_querybatch(response: &str, expected: usize) -> Result<Vec<Vec<String>>, AuditError> {
    let value: serde_json::Value =
        serde_json::from_str(response).map_err(|e| AuditError::Parse(e.to_string()))?;
    let results = value
        .get("results")
        .and_then(|r| r.as_array())
        .ok_or_else(|| AuditError::Parse("missing results array".into()))?;
    let mut out: Vec<Vec<String>> = results
        .iter()
        .map(|r| {
            r.get("vulns")
                .and_then(|v| v.as_array())
                .map(|vulns| {
                    vulns
                        .iter()
                        .filter_map(|v| v.get("id").and_then(|i| i.as_str()).map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        })
        .collect();
    // Be lenient: pad/truncate to the expected length so zipping stays aligned.
    out.resize(expected, Vec::new());
    Ok(out)
}

#[derive(Default, Clone)]
struct VulnDetail {
    summary: String,
    aliases: Vec<String>,
    severity: Option<String>,
}

/// Parses an OSV vulnerability detail document. Falls back to the id for a
/// summary when the document omits one.
fn parse_vuln_detail(raw: &str, id: &str) -> VulnDetail {
    #[derive(Deserialize, Default)]
    struct Doc {
        #[serde(default)]
        summary: Option<String>,
        #[serde(default)]
        details: Option<String>,
        #[serde(default)]
        aliases: Vec<String>,
        #[serde(default)]
        severity: Vec<Sev>,
        #[serde(default)]
        database_specific: Option<DbSpecific>,
    }
    #[derive(Deserialize)]
    struct Sev {
        #[serde(default)]
        score: Option<String>,
    }
    #[derive(Deserialize, Default)]
    struct DbSpecific {
        #[serde(default)]
        severity: Option<String>,
    }

    let doc: Doc = serde_json::from_str(raw).unwrap_or_default();
    let summary = doc
        .summary
        .or_else(|| {
            doc.details
                .map(|d| d.lines().next().unwrap_or("").to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| id.to_string());
    let severity = doc
        .database_specific
        .and_then(|d| d.severity)
        .or_else(|| doc.severity.into_iter().find_map(|s| s.score));
    VulnDetail {
        summary,
        aliases: doc.aliases,
        severity,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A transport returning canned responses, recording requested URLs.
    struct FakeTransport {
        batch: String,
        vulns: BTreeMap<String, String>,
        gets: RefCell<Vec<String>>,
    }

    impl HttpTransport for FakeTransport {
        fn post_json(&self, _url: &str, _body: &str) -> Result<String, AuditError> {
            Ok(self.batch.clone())
        }
        fn get(&self, url: &str) -> Result<String, AuditError> {
            self.gets.borrow_mut().push(url.to_string());
            let id = url.rsplit('/').next().unwrap();
            Ok(self.vulns.get(id).cloned().unwrap_or_else(|| "{}".into()))
        }
    }

    fn coord(name: &str) -> PackageCoordinate {
        PackageCoordinate {
            ecosystem: "crates.io".into(),
            name: name.into(),
            version: "1.0.0".into(),
        }
    }

    #[test]
    fn querybatch_body_is_well_formed() {
        let body = querybatch_body(&[coord("a")]);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["queries"][0]["package"]["name"], "a");
        assert_eq!(v["queries"][0]["package"]["ecosystem"], "crates.io");
        assert_eq!(v["queries"][0]["version"], "1.0.0");
    }

    #[test]
    fn parses_detail_severity_and_aliases() {
        let raw = r#"{"id":"RUSTSEC-1","summary":"bad","aliases":["CVE-9"],
            "database_specific":{"severity":"HIGH"}}"#;
        let d = parse_vuln_detail(raw, "RUSTSEC-1");
        assert_eq!(d.summary, "bad");
        assert_eq!(d.aliases, vec!["CVE-9"]);
        assert_eq!(d.severity.as_deref(), Some("HIGH"));
    }

    #[test]
    fn end_to_end_with_fake_transport() {
        let mut vulns = BTreeMap::new();
        vulns.insert(
            "RUSTSEC-1".to_string(),
            r#"{"id":"RUSTSEC-1","summary":"boom","severity":[{"score":"9.8"}]}"#.to_string(),
        );
        let transport = FakeTransport {
            batch: r#"{"results":[{"vulns":[{"id":"RUSTSEC-1"}]},{}]}"#.to_string(),
            vulns,
            gets: RefCell::new(Vec::new()),
        };
        let source = OsvSource::new(transport, None, false);
        let advisories = source
            .query(&[coord("vuln-pkg"), coord("safe-pkg")])
            .unwrap();
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].id, "RUSTSEC-1");
        assert_eq!(advisories[0].package.name, "vuln-pkg");
        assert_eq!(advisories[0].severity.as_deref(), Some("9.8"));
    }

    #[test]
    fn offline_without_cache_makes_no_requests() {
        let transport = FakeTransport {
            batch: "{}".into(),
            vulns: BTreeMap::new(),
            gets: RefCell::new(Vec::new()),
        };
        let source = OsvSource::new(transport, None, true);
        let advisories = source.query(&[coord("a")]).unwrap();
        assert!(advisories.is_empty());
    }
}
