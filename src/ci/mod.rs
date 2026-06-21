//! CI fact extraction.
//!
//! Phase 2 populates `CiFacts` from GitHub Actions workflows: shell commands
//! from `run:` blocks (with file/line locations) and `env` assignments at the
//! workflow, job, and step levels. These facts activate the CI-aware rules
//! SD002, SD008, and SD009.

use serde::{Deserialize, Serialize};

use crate::filesystem::WorkspaceContext;

pub mod command;
pub mod github_actions;

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

/// Extracts CI facts from every supported CI file in the workspace. Currently
/// GitHub Actions only; unparseable files are skipped (best effort).
pub fn extract(ctx: &WorkspaceContext) -> CiFacts {
    let mut facts = CiFacts::default();
    for file in &ctx.files {
        if github_actions::is_workflow_file(&file.relative) {
            if let Ok(text) = crate::filesystem::read_text(ctx, &file.relative) {
                let parsed = github_actions::parse(&file.relative, &text);
                facts.commands.extend(parsed.commands);
                facts.env.extend(parsed.env);
            }
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

/// Redacts a CI env value before it is stored or rendered. A value whose
/// variable name suggests a secret is fully redacted; otherwise only URL
/// userinfo (`user:token@host`) is stripped. Conservative and deterministic.
pub fn redact_env_value(name: &str, value: &str) -> String {
    let upper = name.to_ascii_uppercase();
    if SECRET_NAME_HINTS.iter().any(|h| upper.contains(h)) {
        return "<redacted>".to_string();
    }
    redact_url_userinfo(value)
}

/// Replaces `scheme://user:pass@host` userinfo with `scheme://<redacted>@host`.
/// Leaves values without credential userinfo untouched.
pub fn redact_url_userinfo(value: &str) -> String {
    let Some(scheme_end) = value.find("://") else {
        return value.to_string();
    };
    let after = scheme_end + 3;
    let rest = &value[after..];
    // Userinfo ends at the first `@` that precedes the next `/`, `?`, or `#`.
    let host_boundary = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    if let Some(at) = rest[..host_boundary].find('@') {
        let mut out = String::with_capacity(value.len());
        out.push_str(&value[..after]);
        out.push_str("<redacted>");
        out.push_str(&rest[at..]);
        return out;
    }
    value.to_string()
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
}
