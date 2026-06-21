//! OSV.dev vulnerability source.
//!
//! Queries <https://osv.dev> for the given coordinates. Network I/O is behind
//! the [`HttpTransport`] trait so the audit logic is testable without a network.
//! The transport is pluggable: the default `native-http` build uses an
//! in-process `ureq` client (so the binary is self-contained and cross-platform),
//! and the `curl-transport` feature falls back to the system `curl`. A single
//! `querybatch` POST covers all packages; advisory details are fetched once per
//! unique vulnerability id and cached.

use std::collections::BTreeMap;
#[cfg(feature = "curl-transport")]
use std::io::Write;
#[cfg(feature = "curl-transport")]
use std::process::{Command, Stdio};

use serde::Deserialize;

use crate::audit::cache::Cache;
use crate::audit::{Advisory, AuditError, PackageCoordinate, VulnerabilitySource};

#[cfg(not(any(feature = "native-http", feature = "curl-transport")))]
compile_error!("enable either the `native-http` (default) or `curl-transport` feature");

const QUERYBATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const VULN_URL: &str = "https://api.osv.dev/v1/vulns/";

/// Overall per-request network timeout.
#[cfg(feature = "native-http")]
const TIMEOUT_SECS: u64 = 30;

/// An HTTP transport abstraction. Implementations must perform real network I/O
/// only here; everything else in the audit path stays offline.
pub trait HttpTransport {
    fn post_json(&self, url: &str, body: &str) -> Result<String, AuditError>;
    fn get(&self, url: &str) -> Result<String, AuditError>;
}

/// The default transport for this build: the in-process `ureq` client when the
/// `native-http` feature is enabled, otherwise the `curl` fallback.
#[cfg(feature = "native-http")]
pub fn default_transport() -> UreqTransport {
    UreqTransport::new()
}

/// The default transport for this build (the `curl` fallback, when `native-http`
/// is disabled).
#[cfg(all(not(feature = "native-http"), feature = "curl-transport"))]
pub fn default_transport() -> CurlTransport {
    CurlTransport
}

/// In-process transport using the `ureq` HTTP client (rustls/`ring` TLS). No
/// external process or system `curl` is required.
#[cfg(feature = "native-http")]
pub struct UreqTransport {
    agent: ureq::Agent,
}

#[cfg(feature = "native-http")]
impl UreqTransport {
    pub fn new() -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(TIMEOUT_SECS))
                .build(),
        }
    }
}

#[cfg(feature = "native-http")]
impl Default for UreqTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "native-http")]
impl HttpTransport for UreqTransport {
    fn post_json(&self, url: &str, body: &str) -> Result<String, AuditError> {
        read_response(
            self.agent
                .post(url)
                .set("Content-Type", "application/json")
                .send_string(body),
        )
    }

    fn get(&self, url: &str) -> Result<String, AuditError> {
        read_response(self.agent.get(url).call())
    }
}

/// Turns a `ureq` result into a response body or an [`AuditError`]. An HTTP
/// 4xx/5xx is an error (so an error page is never parsed as a vulnerability
/// response), keeping the response body for context — mirroring curl's
/// `--fail-with-body`.
#[cfg(feature = "native-http")]
fn read_response(result: Result<ureq::Response, ureq::Error>) -> Result<String, AuditError> {
    match result {
        Ok(resp) => resp
            .into_string()
            .map_err(|e| AuditError::Transport(e.to_string())),
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            let detail = body.trim();
            if detail.is_empty() {
                Err(AuditError::Transport(format!("HTTP {code}")))
            } else {
                Err(AuditError::Transport(format!("HTTP {code}: {detail}")))
            }
        }
        Err(e) => Err(AuditError::Transport(e.to_string())),
    }
}

/// Fallback transport: invokes the system `curl`.
#[cfg(feature = "curl-transport")]
pub struct CurlTransport;

#[cfg(feature = "curl-transport")]
impl HttpTransport for CurlTransport {
    fn post_json(&self, url: &str, body: &str) -> Result<String, AuditError> {
        let mut child = Command::new("curl")
            .args([
                "-sS",
                // Fail (non-zero exit) on HTTP 4xx/5xx so an error page is never
                // parsed as a vulnerability response; keep the body for context.
                "--fail-with-body",
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
            .args(["-sS", "--fail-with-body", "--max-time", "30", url])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| AuditError::Transport(format!("could not run curl: {e}")))?;
        finish(child)
    }
}

#[cfg(feature = "curl-transport")]
fn finish(child: std::process::Child) -> Result<String, AuditError> {
    let out = child
        .wait_with_output()
        .map_err(|e| AuditError::Transport(e.to_string()))?;
    if !out.status.success() {
        // With `--fail-with-body` curl prints the HTTP error response to stdout;
        // prefer that for context and fall back to stderr otherwise.
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let detail = match stdout.trim() {
            "" => stderr.trim(),
            body => body,
        };
        return Err(AuditError::Transport(format!("curl failed: {detail}")));
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

/// OSV's `querybatch` accepts at most 1000 queries per request.
const MAX_BATCH: usize = 1000;

impl<T: HttpTransport> OsvSource<T> {
    fn fetch(&self, coords: &[PackageCoordinate]) -> Result<Vec<Advisory>, AuditError> {
        // Chunk against OSV's per-request query cap so a large monorepo does not
        // overflow the batch and fail.
        let mut out = Vec::new();
        for chunk in coords.chunks(MAX_BATCH) {
            out.extend(self.fetch_chunk(chunk)?);
        }
        Ok(out)
    }

    fn fetch_chunk(&self, coords: &[PackageCoordinate]) -> Result<Vec<Advisory>, AuditError> {
        let body = querybatch_body(coords);
        let response = self.transport.post_json(QUERYBATCH_URL, &body)?;
        let ids_per_coord = parse_querybatch(&response, coords.len())?;

        // Fetch each unique vulnerability's details once. A transient failure on
        // one detail page must not abort the whole audit; fall back to the bare
        // id and keep going.
        let mut details: BTreeMap<String, VulnDetail> = BTreeMap::new();
        for ids in &ids_per_coord {
            for id in ids {
                if !details.contains_key(id) {
                    let detail = match self.transport.get(&format!("{VULN_URL}{id}")) {
                        Ok(raw) => parse_vuln_detail(&raw, id),
                        Err(_) => parse_vuln_detail("{}", id),
                    };
                    details.insert(id.clone(), detail);
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
    // OSV returns exactly one result per query, in order. A mismatch means a
    // truncated/garbled response; fail rather than silently mark coordinates
    // clean by padding.
    if results.len() != expected {
        return Err(AuditError::Parse(format!(
            "expected {expected} results, got {}",
            results.len()
        )));
    }
    let out: Vec<Vec<String>> = results
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
    fn detail_fetch_failure_is_non_fatal() {
        // A transient failure on the vuln-detail GET must not abort the audit;
        // the advisory is still reported (with the id as its summary).
        struct FailingGet {
            batch: String,
        }
        impl HttpTransport for FailingGet {
            fn post_json(&self, _u: &str, _b: &str) -> Result<String, AuditError> {
                Ok(self.batch.clone())
            }
            fn get(&self, _u: &str) -> Result<String, AuditError> {
                Err(AuditError::Transport("boom".into()))
            }
        }
        let source = OsvSource::new(
            FailingGet {
                batch: r#"{"results":[{"vulns":[{"id":"RUSTSEC-1"}]}]}"#.into(),
            },
            None,
            false,
        );
        let advisories = source.query(&[coord("vuln-pkg")]).unwrap();
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].id, "RUSTSEC-1");
        assert_eq!(advisories[0].summary, "RUSTSEC-1");
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
