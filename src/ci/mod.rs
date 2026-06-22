//! CI fact extraction.
//!
//! Populates `CiFacts` from CI configuration files via pluggable providers
//! (GitHub Actions, GitLab CI, CircleCI): shell commands (with file/line
//! locations) and `env` assignments. These facts activate the CI-aware rules
//! SD002, SD008, and SD009.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::filesystem::WorkspaceContext;

pub mod circleci;
pub mod command;
pub mod github_actions;
pub mod gitlab_ci;
pub mod yaml;

/// Commands and env extracted from one CI configuration file.
#[derive(Debug, Default)]
pub struct ParsedCi {
    pub commands: Vec<CiCommand>,
    pub env: Vec<EnvAssignment>,
}

/// A CI provider recognizes its configuration files and extracts the shell
/// commands and env assignments the CI-aware rules reason about.
pub trait CiProvider: Sync {
    /// Human-readable name, used in `explain`/coverage docs.
    fn name(&self) -> &'static str;
    /// Whether a workspace-relative path is one of this provider's config files.
    fn matches(&self, relative: &Path) -> bool;
    /// Parses a recognized file into CI facts.
    fn parse(&self, relative: &Path, text: &str) -> ParsedCi;
}

/// All built-in CI providers, in coverage order.
pub fn providers() -> &'static [&'static dyn CiProvider] {
    &[
        &github_actions::GithubActions,
        &gitlab_ci::GitlabCi,
        &circleci::CircleCi,
    ]
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CiFacts {
    pub commands: Vec<CiCommand>,
    pub env: Vec<EnvAssignment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiCommand {
    pub file: std::path::PathBuf,
    pub line: u32,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvAssignment {
    pub name: String,
    pub value: String,
}

impl CiFacts {
    pub fn empty() -> Self {
        Self::default()
    }
}

/// Extracts CI facts from every supported CI file in the workspace, dispatching
/// each file to the first provider that recognizes it. Unparseable files yield
/// no commands (best effort).
pub fn extract(ctx: &WorkspaceContext) -> CiFacts {
    let mut facts = CiFacts::default();
    for file in &ctx.files {
        let Some(provider) = providers().iter().find(|p| p.matches(&file.relative)) else {
            continue;
        };
        if let Ok(text) = crate::filesystem::read_text(ctx, &file.relative) {
            let parsed = provider.parse(&file.relative, &text);
            facts.commands.extend(parsed.commands);
            facts.env.extend(parsed.env);
        }
    }
    // `ctx.files` is already sorted, so iteration is deterministic; keep
    // commands ordered by (file, line) for stable downstream findings.
    facts
        .commands
        .sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
    facts
}

/// Environment variable name fragments that indicate a secret value.
const SECRET_NAME_HINTS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "KEY",
    "PASSWORD",
    "PASSWD",
    "AUTH",
    "SIGNATURE",
    "CREDENTIAL",
];

/// Query-parameter name fragments that indicate a secret value.
/// Checked case-insensitively against each key in a URL query string.
const SECRET_QUERY_HINTS: &[&str] = &[
    "token",
    "secret",
    "key",
    "password",
    "passwd",
    "auth",
    "signature",
    "credential",
];

/// Redacts a CI env value before it is stored or rendered. A value whose
/// variable name suggests a secret is fully redacted; otherwise URL userinfo
/// (`user:token@host`) and secret-like query parameters are redacted.
/// Conservative and deterministic.
pub fn redact_env_value(name: &str, value: &str) -> String {
    let upper = name.to_ascii_uppercase();
    if SECRET_NAME_HINTS.iter().any(|h| upper.contains(h)) {
        return "<redacted>".to_string();
    }
    redact_url_credentials(value)
}

/// Replaces `scheme://user:pass@host` userinfo with `scheme://<redacted>@host`
/// and removes the values of secret-like query parameters
/// (e.g. `?token=abc` → `?token=`). Non-secret query parameters are preserved.
/// Leaves values that do not look like URLs untouched. Never panics.
pub fn redact_url_credentials(value: &str) -> String {
    let Some(scheme_end) = value.find("://") else {
        return value.to_string();
    };
    let after = scheme_end + 3;
    let rest = &value[after..];

    // --- userinfo redaction ---------------------------------------------------
    // Userinfo ends at the first `@` that precedes the next `/`, `?`, or `#`.
    let host_boundary = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let working = if let Some(at) = rest[..host_boundary].find('@') {
        let mut out = String::with_capacity(value.len());
        out.push_str(&value[..after]);
        out.push_str("<redacted>");
        out.push_str(&rest[at..]);
        // Continue query-param redaction on the rebuilt string.
        Some(out)
    } else {
        None
    };

    // Use the string after potential userinfo redaction for query processing.
    let base: &str = working.as_deref().unwrap_or(value);

    // --- query / fragment redaction ------------------------------------------
    // Find the query string: first `?` after the scheme authority.
    // The authority ends at the first `/`, `?`, or `#` following `://host`.
    // Treating `?` and `#` as terminators handles URLs with no path component,
    // e.g. `https://registry.example.com?token=abc`.
    let scheme_plus = scheme_end + 3; // points past `://`
    let authority_end = base[scheme_plus..]
        .find(['/', '?', '#'])
        .map(|i| scheme_plus + i)
        .unwrap_or(base.len());

    let Some(q_start_rel) = base[authority_end..].find('?') else {
        // No query string — userinfo redaction result (if any) is sufficient.
        return base.to_string();
    };
    let q_start = authority_end + q_start_rel; // index of `?` in `base`

    // Split off any fragment (`#`) after the query.
    let after_q = &base[q_start + 1..];
    let (query_part, fragment_part) = match after_q.find('#') {
        Some(h) => (&after_q[..h], &after_q[h..]),
        None => (after_q, ""),
    };

    // Rebuild the query, redacting secret parameter values.
    let mut new_query = String::with_capacity(query_part.len());
    for (idx, pair) in query_part.split('&').enumerate() {
        if idx > 0 {
            new_query.push('&');
        }
        match pair.split_once('=') {
            Some((k, _v)) if is_secret_query_key(k) => {
                new_query.push_str(k);
                new_query.push('=');
                // value intentionally omitted (redacted)
            }
            _ => new_query.push_str(pair),
        }
    }

    let mut out = base[..q_start + 1].to_string();
    out.push_str(&new_query);
    out.push_str(fragment_part);
    out
}

/// Returns `true` if the query-parameter key `k` contains a secret-like hint.
fn is_secret_query_key(k: &str) -> bool {
    let lower = k.to_ascii_lowercase();
    SECRET_QUERY_HINTS.iter().any(|h| lower.contains(h))
}

/// Compatibility alias kept so callers that were testing `redact_url_userinfo`
/// directly continue to compile.
#[cfg(test)]
pub fn redact_url_userinfo(value: &str) -> String {
    redact_url_credentials(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_secret_named_env_values() {
        assert_eq!(redact_env_value("NPM_TOKEN", "abc"), "<redacted>");
        assert_eq!(redact_env_value("aws_secret_key", "x"), "<redacted>");
        assert_eq!(redact_env_value("NODE_ENV", "production"), "production");
    }

    #[test]
    fn redacts_url_userinfo_only() {
        assert_eq!(
            redact_url_userinfo("https://user:tok@example.com/path"),
            "https://<redacted>@example.com/path"
        );
        assert_eq!(
            redact_url_userinfo("https://example.com/a@b"),
            "https://example.com/a@b"
        );
        assert_eq!(redact_url_userinfo("plain-value"), "plain-value");
    }

    #[test]
    fn providers_match_root_gitlab_ci_but_not_nested() {
        // The root `.gitlab-ci.yml` must be recognized by a provider.
        let root = Path::new(".gitlab-ci.yml");
        assert!(
            providers().iter().any(|p| p.matches(root)),
            "no provider matched root .gitlab-ci.yml"
        );
        // A nested file with the same name must NOT be matched by any provider —
        // it is not the canonical GitLab CI configuration file for the repository.
        let nested = Path::new("vendor/example/.gitlab-ci.yml");
        assert!(
            !providers().iter().any(|p| p.matches(nested)),
            "a provider incorrectly matched nested .gitlab-ci.yml"
        );
        let subdir = Path::new("sub/.gitlab-ci.yml");
        assert!(
            !providers().iter().any(|p| p.matches(subdir)),
            "a provider incorrectly matched sub/.gitlab-ci.yml"
        );
    }

    // --- query-parameter redaction -------------------------------------------

    #[test]
    fn redacts_token_query_param() {
        assert_eq!(
            redact_url_credentials("https://registry.example/simple?token=super-secret&user=bot"),
            "https://registry.example/simple?token=&user=bot"
        );
    }

    #[test]
    fn redacts_api_key_query_param() {
        assert_eq!(
            redact_url_credentials("https://api.example.com/pkg?api_key=abc123"),
            "https://api.example.com/pkg?api_key="
        );
    }

    #[test]
    fn redacts_password_query_param() {
        assert_eq!(
            redact_url_credentials("https://host/path?password=hunter2"),
            "https://host/path?password="
        );
    }

    #[test]
    fn redacts_passwd_query_param() {
        assert_eq!(
            redact_url_credentials("https://host/path?passwd=hunter2"),
            "https://host/path?passwd="
        );
        // Mixed: passwd alongside a non-secret param.
        assert_eq!(
            redact_url_credentials("https://registry.example/simple?user=bot&passwd=s3cr3t"),
            "https://registry.example/simple?user=bot&passwd="
        );
    }

    #[test]
    fn redacts_signature_query_param() {
        assert_eq!(
            redact_url_credentials("https://host/path?signature=abcdef"),
            "https://host/path?signature="
        );
    }

    #[test]
    fn preserves_non_secret_query_params() {
        assert_eq!(
            redact_url_credentials("https://example.com/path?format=json&user=bot"),
            "https://example.com/path?format=json&user=bot"
        );
    }

    #[test]
    fn redacts_only_secret_params_when_mixed() {
        assert_eq!(
            redact_url_credentials(
                "https://registry.example/simple?token=super-secret&user=bot&format=xml"
            ),
            "https://registry.example/simple?token=&user=bot&format=xml"
        );
    }

    #[test]
    fn redacts_userinfo_and_query_together() {
        assert_eq!(
            redact_url_credentials("https://user:pass@registry.example/simple?token=abc&user=bot"),
            "https://<redacted>@registry.example/simple?token=&user=bot"
        );
    }

    #[test]
    fn non_url_value_is_unchanged() {
        assert_eq!(redact_url_credentials("plain-value"), "plain-value");
        assert_eq!(
            redact_url_credentials("not-a-url?token=abc"),
            "not-a-url?token=abc"
        );
    }

    #[test]
    fn registry_url_non_secret_name_redacts_query_token() {
        // The env var name is not secret-like, so it goes to URL redaction.
        // The token= query param must be redacted even though REGISTRY_URL is safe.
        assert_eq!(
            redact_env_value(
                "REGISTRY_URL",
                "https://registry.example/simple?token=super-secret&user=bot"
            ),
            "https://registry.example/simple?token=&user=bot"
        );
    }

    #[test]
    fn url_without_query_is_unchanged_by_query_redaction() {
        assert_eq!(
            redact_url_credentials("https://registry.example/simple"),
            "https://registry.example/simple"
        );
    }

    #[test]
    fn fragment_is_preserved_after_query_redaction() {
        assert_eq!(
            redact_url_credentials("https://host/path?token=abc#section"),
            "https://host/path?token=#section"
        );
    }

    // --- no-path URL regression tests (reviewer comment, issue #88) ----------

    #[test]
    fn redacts_token_in_no_path_url() {
        // `?` immediately follows the authority — no `/` in the URL.
        assert_eq!(
            redact_url_credentials("https://registry.example.com?token=abc"),
            "https://registry.example.com?token="
        );
    }

    #[test]
    fn redacts_secret_and_preserves_non_secret_in_no_path_url() {
        assert_eq!(
            redact_url_credentials("https://host.example?api_key=abc&keep=1"),
            "https://host.example?api_key=&keep=1"
        );
    }

    #[test]
    fn redacts_fragment_query_secret_in_no_path_url() {
        // Fragment immediately follows the authority with a secret-like key.
        // `?` is absent; the URL has no query, only a fragment — the function
        // preserves this (no query to redact) but must not expose the fragment
        // as a query. Verify no panic and that the value is returned unchanged
        // (fragments are not query params and have no `=`-key structure we parse).
        let result = redact_url_credentials("https://host.example#token=abc");
        // The fragment is not a query string — we do not strip it — but we must
        // not accidentally include it as a secret query param.
        assert_eq!(result, "https://host.example#token=abc");
    }
}
