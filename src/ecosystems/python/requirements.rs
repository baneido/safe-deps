//! `requirements*.txt` parsing for pip workflows.
//!
//! pip accepts options inline in requirements files. This parser captures the
//! security-relevant flags: `--require-hashes`, `--trusted-host`,
//! `--index-url`, `--extra-index-url`, and the presence of `--hash=` pins.
//! It also follows `-r`/`--requirement` and `-c`/`--constraint` includes,
//! resolving paths relative to the including file with cycle detection.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::ecosystems::EcoError;

#[derive(Debug, Clone, Default)]
pub struct RequirementsSettings {
    pub require_hashes: bool,
    pub trusted_hosts: Vec<String>,
    pub index_urls: Vec<String>,
    pub extra_index_urls: Vec<String>,
    /// True only when every requirement is hash-pinned, mirroring pip's
    /// `--require-hashes` rule that rejects any unpinned requirement.
    pub has_hash_pins: bool,
    /// Count of requirement lines (excluding options, comments, blanks).
    pub requirement_count: usize,
    /// Count of requirement lines that carry at least one `--hash=` pin.
    pub hashed_requirement_count: usize,
    /// Raw requirement specs (and `-e`/`--editable` targets) for SD006 source
    /// classification.
    pub specs: Vec<String>,
    /// Include paths referenced by `-r`/`--requirement` directives.
    pub requirement_includes: Vec<PathBuf>,
    /// Include paths referenced by `-c`/`--constraint` directives.
    pub constraint_includes: Vec<PathBuf>,
}

pub fn load(
    ctx: &crate::filesystem::WorkspaceContext,
    relative: &Path,
) -> Result<RequirementsSettings, EcoError> {
    let text = crate::filesystem::read_text(ctx, relative).map_err(|source| EcoError::Read {
        path: relative.to_path_buf(),
        source,
    })?;
    Ok(parse(&text))
}

/// Maximum include nesting depth. Real requirement trees are shallow; this is
/// a safety net so a cycle that escapes the `visited` check (e.g. via an
/// unexpected path spelling) can never cause unbounded recursion / stack
/// overflow on any platform.
const MAX_INCLUDE_DEPTH: usize = 50;

/// Loads a requirements file and follows all `-r`/`-c` includes recursively,
/// merging the resulting settings. Cyclic includes are detected and skipped;
/// missing includes are reported as diagnostics. Include paths are normalized
/// to a canonical workspace-relative form (forward slashes, `.`/`..` resolved)
/// before they are read or recorded in `visited`, so the same file maps to a
/// single key on every platform.
pub fn load_recursive(
    ctx: &crate::filesystem::WorkspaceContext,
    relative: &Path,
    visited: &mut HashSet<PathBuf>,
    diagnostics: &mut Vec<crate::diagnostics::Diagnostic>,
) -> RequirementsSettings {
    load_recursive_inner(ctx, relative, visited, diagnostics, 0)
}

fn load_recursive_inner(
    ctx: &crate::filesystem::WorkspaceContext,
    relative: &Path,
    visited: &mut HashSet<PathBuf>,
    diagnostics: &mut Vec<crate::diagnostics::Diagnostic>,
    depth: usize,
) -> RequirementsSettings {
    // Canonical, platform-independent key (forward slashes, no `.`/`..`). Using
    // it for both `visited` and the read keeps cycle detection reliable and the
    // `read_text` lookup consistent with the workspace's normalized entries.
    let key = normalize_rel(relative);

    if depth > MAX_INCLUDE_DEPTH {
        diagnostics.push(crate::diagnostics::Diagnostic::warn_at(
            format!(
                "requirements include nesting too deep (possible cycle): {}",
                key.display()
            ),
            key.clone(),
        ));
        return RequirementsSettings::default();
    }

    if !visited.insert(key.clone()) {
        // Already visited — cyclic include.
        diagnostics.push(crate::diagnostics::Diagnostic::warn_at(
            format!("cyclic requirements include detected: {}", key.display()),
            key.clone(),
        ));
        return RequirementsSettings::default();
    }

    let text = match crate::filesystem::read_text(ctx, &key) {
        Ok(t) => t,
        Err(e) => {
            diagnostics.push(crate::diagnostics::Diagnostic::warn_at(
                format!("could not read {}: {}", key.display(), e),
                key.clone(),
            ));
            return RequirementsSettings::default();
        }
    };

    let mut merged = parse(&text);

    // The parent directory of the including file, for resolving relative paths.
    let parent = key
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    // Follow -r (requirement) includes.
    let req_includes: Vec<PathBuf> = merged.requirement_includes.clone();
    for inc_path in req_includes {
        let resolved = resolve_include(&parent, &inc_path);
        let included = load_recursive_inner(ctx, &resolved, visited, diagnostics, depth + 1);
        merge_settings(&mut merged, included);
    }

    // Follow -c (constraint) includes — constraints declare version bounds only,
    // but they may reference VCS/path specs that SD006 should flag.
    let con_includes: Vec<PathBuf> = merged.constraint_includes.clone();
    for inc_path in con_includes {
        let resolved = resolve_include(&parent, &inc_path);
        let included = load_recursive_inner(ctx, &resolved, visited, diagnostics, depth + 1);
        merge_settings(&mut merged, included);
    }

    merged
}

/// Normalizes a workspace-relative include path to a canonical form: forward
/// slashes, with `.` and empty segments dropped and `..` segments resolved.
/// This makes the `visited` key and the `read_text` lookup identical for the
/// same file regardless of platform path separators or `./` spellings.
fn normalize_rel(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy().replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();
    for seg in raw.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    PathBuf::from(parts.join("/"))
}

/// Resolves an include path relative to the including file's directory.
fn resolve_include(parent: &Path, inc: &Path) -> PathBuf {
    if parent == Path::new(".") {
        inc.to_path_buf()
    } else {
        parent.join(inc)
    }
}

/// Merges `other` into `base`, combining all lists and picking the stricter
/// boolean flags.
fn merge_settings(base: &mut RequirementsSettings, other: RequirementsSettings) {
    base.require_hashes |= other.require_hashes;
    base.trusted_hosts.extend(other.trusted_hosts);
    base.index_urls.extend(other.index_urls);
    base.extra_index_urls.extend(other.extra_index_urls);
    base.specs.extend(other.specs);
    base.requirement_count += other.requirement_count;
    base.hashed_requirement_count += other.hashed_requirement_count;
    // Recompute hash pin enforcement after merging counts.
    if base.requirement_count > 0 && base.hashed_requirement_count == base.requirement_count {
        base.has_hash_pins = true;
        base.require_hashes = true;
    }
}

pub fn parse(text: &str) -> RequirementsSettings {
    let mut settings = RequirementsSettings::default();
    // pip joins lines ending in `\` into one logical requirement, so hashes on
    // continuation lines belong to the requirement above them.
    for logical in logical_lines(text) {
        let line = logical.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('-') {
            parse_option_line(line, &mut settings);
            continue;
        }
        settings.requirement_count += 1;
        // Capture the requirement up to the first `--hash`/option for SD006.
        settings.specs.push(requirement_spec(line));
        if line_has_hash(line) {
            settings.hashed_requirement_count += 1;
        }
    }
    // Integrity is only enforced when the explicit flag is present or every
    // requirement is hash-pinned. A single hashed requirement is not enough.
    if settings.requirement_count > 0
        && settings.hashed_requirement_count == settings.requirement_count
    {
        settings.has_hash_pins = true;
        settings.require_hashes = true;
    }
    settings
}

/// Joins physical lines into logical lines, honoring trailing `\` continuations
/// and stripping inline comments first.
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for raw in text.lines() {
        let stripped = strip_inline_comment(raw);
        if let Some(prefix) = stripped.trim_end().strip_suffix('\\') {
            current.push_str(prefix);
            current.push(' ');
        } else {
            current.push_str(stripped);
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

/// The requirement portion of a line, excluding any trailing options such as
/// `--hash=…`. Tokens are re-joined with single spaces.
fn requirement_spec(line: &str) -> String {
    line.split_whitespace()
        .take_while(|tok| !tok.starts_with("--"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether a requirement's logical line carries a `--hash` pin in any form.
fn line_has_hash(line: &str) -> bool {
    line.split_whitespace()
        .any(|t| t == "--hash" || t.starts_with("--hash="))
}

fn strip_inline_comment(line: &str) -> &str {
    // Requirements may carry inline comments preceded by `  # `. A leading `#`
    // is handled by the caller. We avoid splitting on `#` inside URLs.
    if let Some(idx) = find_inline_comment(line) {
        &line[..idx]
    } else {
        line
    }
}

fn find_inline_comment(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut in_url = false;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b':' && i + 2 < bytes.len() && bytes[i + 1] == b'/' && bytes[i + 2] == b'/' {
            in_url = true;
        }
        if !in_url && c == b'#' && i > 0 && bytes[i - 1] == b' ' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn parse_option_line(line: &str, settings: &mut RequirementsSettings) {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let mut i = 0;
    while i < tokens.len() {
        // Options accept both `--flag value` and `--flag=value`.
        let (flag, inline) = match tokens[i].split_once('=') {
            Some((f, v)) => (f, Some(v)),
            None => (tokens[i], None),
        };
        match flag {
            "--require-hashes" => settings.require_hashes = true,
            "--trusted-host" => {
                if let Some(host) = take_value(inline, &tokens, &mut i) {
                    settings.trusted_hosts.push(host);
                }
            }
            "--index-url" | "-i" => {
                if let Some(url) = take_value(inline, &tokens, &mut i) {
                    settings.index_urls.push(url);
                }
            }
            "--extra-index-url" => {
                if let Some(url) = take_value(inline, &tokens, &mut i) {
                    settings.extra_index_urls.push(url);
                }
            }
            "-e" | "--editable" => {
                // Editable installs are typically local paths or VCS refs;
                // record them for SD006 (they cannot be hash-pinned).
                if let Some(target) = take_value(inline, &tokens, &mut i) {
                    settings.specs.push(format!("-e {target}"));
                }
            }
            "-r" | "--requirement" => {
                if let Some(path) = take_value(inline, &tokens, &mut i) {
                    settings.requirement_includes.push(PathBuf::from(path));
                }
            }
            "-c" | "--constraint" => {
                if let Some(path) = take_value(inline, &tokens, &mut i) {
                    settings.constraint_includes.push(PathBuf::from(path));
                }
            }
            _ => {}
        }
        i += 1;
    }
}

/// Resolves an option value from either the inline `=value` or the next token,
/// advancing the cursor when the next token is consumed.
fn take_value(inline: Option<&str>, tokens: &[&str], i: &mut usize) -> Option<String> {
    if let Some(value) = inline {
        return Some(value.to_string());
    }
    if let Some(value) = tokens.get(*i + 1) {
        *i += 1;
        return Some(value.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_requirements_and_ignores_options() {
        let s = parse("--index-url https://pypi.org/simple\nrequests==2.31.0\nflask==3.0.0\n");
        assert_eq!(s.requirement_count, 2);
        assert_eq!(s.index_urls, vec!["https://pypi.org/simple"]);
    }

    #[test]
    fn captures_require_hashes() {
        let s = parse("--require-hashes\nrequests==2.31.0\n");
        assert!(s.require_hashes);
    }

    #[test]
    fn captures_trusted_host_and_extra_index() {
        let s = parse("--trusted-host pypi.internal\n--extra-index-url http://pypi.internal/simple\nrequests==2.31.0\n");
        assert_eq!(s.trusted_hosts, vec!["pypi.internal"]);
        assert_eq!(s.extra_index_urls, vec!["http://pypi.internal/simple"]);
    }

    #[test]
    fn hash_pins_imply_require_hashes() {
        let s = parse("requests==2.31.0 --hash=sha256:abc123\n");
        assert!(s.has_hash_pins);
        assert!(s.require_hashes);
    }

    #[test]
    fn strips_inline_comment_but_keeps_url() {
        let s = parse("requests==2.31.0  # pinned\n--index-url https://pypi.org/simple\n");
        assert_eq!(s.requirement_count, 1);
        assert_eq!(s.index_urls, vec!["https://pypi.org/simple"]);
    }

    #[test]
    fn skips_blank_and_comment_lines() {
        let s = parse("\n# a comment\nrequests==2.31.0\n");
        assert_eq!(s.requirement_count, 1);
    }

    #[test]
    fn parses_equals_joined_options() {
        // Regression: `--flag=value` was dropped because parsing assumed the
        // value was the next whitespace-separated token.
        let s = parse(
            "--index-url=http://pypi.internal/simple\n--trusted-host=pypi.internal\n--extra-index-url=https://extra/simple\nrequests==2.31.0\n",
        );
        assert_eq!(s.index_urls, vec!["http://pypi.internal/simple"]);
        assert_eq!(s.trusted_hosts, vec!["pypi.internal"]);
        assert_eq!(s.extra_index_urls, vec!["https://extra/simple"]);
    }

    #[test]
    fn partial_hash_pinning_is_not_treated_as_enforced() {
        // Regression: a single `--hash` used to mark the whole file as pinned.
        let s = parse("requests==2.31.0 --hash=sha256:aaa\nflask==3.0.0\n");
        assert_eq!(s.requirement_count, 2);
        assert_eq!(s.hashed_requirement_count, 1);
        assert!(!s.has_hash_pins);
        assert!(!s.require_hashes);
    }

    #[test]
    fn all_requirements_hashed_is_enforced() {
        let s = parse("requests==2.31.0 --hash=sha256:aaa\nflask==3.0.0 --hash=sha256:bbb\n");
        assert!(s.has_hash_pins);
        assert!(s.require_hashes);
    }

    #[test]
    fn hash_on_continuation_line_counts_for_requirement() {
        let s = parse("requests==2.31.0 \\\n    --hash=sha256:aaa\n");
        assert_eq!(s.requirement_count, 1);
        assert_eq!(s.hashed_requirement_count, 1);
        assert!(s.require_hashes);
    }

    // --- include directives ---------------------------------------------------

    #[test]
    fn parse_captures_r_include() {
        let s = parse("-r requirements/base.txt\nrequests==2.31.0\n");
        assert_eq!(
            s.requirement_includes,
            vec![PathBuf::from("requirements/base.txt")]
        );
        assert_eq!(s.requirement_count, 1);
    }

    #[test]
    fn parse_captures_long_requirement_include() {
        let s = parse("--requirement requirements/base.txt\n");
        assert_eq!(
            s.requirement_includes,
            vec![PathBuf::from("requirements/base.txt")]
        );
    }

    #[test]
    fn parse_captures_c_constraint_include() {
        let s = parse("-c constraints.txt\nrequests==2.31.0\n");
        assert_eq!(
            s.constraint_includes,
            vec![PathBuf::from("constraints.txt")]
        );
        assert_eq!(s.requirement_count, 1);
    }

    #[test]
    fn parse_captures_long_constraint_include() {
        let s = parse("--constraint constraints.txt\n");
        assert_eq!(
            s.constraint_includes,
            vec![PathBuf::from("constraints.txt")]
        );
    }

    #[test]
    fn parse_captures_equals_joined_r_include() {
        let s = parse("-r=requirements/base.txt\n");
        assert_eq!(
            s.requirement_includes,
            vec![PathBuf::from("requirements/base.txt")]
        );
    }

    // --- load_recursive -------------------------------------------------------

    fn make_ctx(
        files: &[(&str, &str)],
    ) -> (crate::filesystem::WorkspaceContext, tempfile::TempDir) {
        use crate::config::Config;
        use crate::filesystem::{scan, ScanOptions};
        let dir = tempfile::TempDir::new().unwrap();
        for (rel, contents) in files {
            let p = dir.path().join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(p, contents).unwrap();
        }
        let ctx = scan(dir.path(), Config::default(), &ScanOptions::default()).unwrap();
        (ctx, dir)
    }

    #[test]
    fn load_recursive_follows_r_include() {
        let (ctx, _d) = make_ctx(&[
            ("requirements.txt", "-r requirements/base.txt\n"),
            ("requirements/base.txt", "requests==2.31.0\nflask==3.0.0\n"),
        ]);
        let mut visited = std::collections::HashSet::new();
        let mut diags = Vec::new();
        let s = load_recursive(
            &ctx,
            std::path::Path::new("requirements.txt"),
            &mut visited,
            &mut diags,
        );
        assert!(diags.is_empty(), "unexpected diagnostics: {diags:?}");
        assert_eq!(s.requirement_count, 2);
        assert!(s.specs.contains(&"requests==2.31.0".to_string()));
        assert!(s.specs.contains(&"flask==3.0.0".to_string()));
    }

    #[test]
    fn load_recursive_follows_c_constraint_include() {
        let (ctx, _d) = make_ctx(&[
            ("requirements.txt", "-c constraints.txt\nrequests==2.31.0\n"),
            ("constraints.txt", "flask==3.0.0\n"),
        ]);
        let mut visited = std::collections::HashSet::new();
        let mut diags = Vec::new();
        let s = load_recursive(
            &ctx,
            std::path::Path::new("requirements.txt"),
            &mut visited,
            &mut diags,
        );
        assert!(diags.is_empty(), "unexpected diagnostics: {diags:?}");
        assert_eq!(s.requirement_count, 2);
    }

    #[test]
    fn load_recursive_detects_cycle_and_emits_diagnostic() {
        // a.txt includes b.txt which includes a.txt — must not loop forever.
        let (ctx, _d) = make_ctx(&[
            ("a.txt", "-r b.txt\nrequests==2.31.0\n"),
            ("b.txt", "-r a.txt\nflask==3.0.0\n"),
        ]);
        let mut visited = std::collections::HashSet::new();
        let mut diags = Vec::new();
        let s = load_recursive(
            &ctx,
            std::path::Path::new("a.txt"),
            &mut visited,
            &mut diags,
        );
        // The cycle should produce a diagnostic.
        assert!(
            diags.iter().any(|d| d.message.contains("cyclic")),
            "expected cyclic diagnostic, got: {diags:?}"
        );
        // Despite the cycle we still get the non-cyclic requirements.
        assert!(s.requirement_count >= 1);
    }

    #[test]
    fn load_recursive_emits_diagnostic_for_missing_include() {
        let (ctx, _d) = make_ctx(&[("requirements.txt", "-r missing.txt\n")]);
        let mut visited = std::collections::HashSet::new();
        let mut diags = Vec::new();
        let _s = load_recursive(
            &ctx,
            std::path::Path::new("requirements.txt"),
            &mut visited,
            &mut diags,
        );
        assert!(
            diags.iter().any(|d| d.message.contains("missing.txt")),
            "expected missing-file diagnostic, got: {diags:?}"
        );
    }

    #[test]
    fn load_recursive_resolves_nested_include_relative_to_including_file() {
        // requirements.txt → requirements/base.txt → requirements/common.txt
        let (ctx, _d) = make_ctx(&[
            ("requirements.txt", "-r requirements/base.txt\n"),
            ("requirements/base.txt", "-r common.txt\nrequests==2.31.0\n"),
            ("requirements/common.txt", "flask==3.0.0\n"),
        ]);
        let mut visited = std::collections::HashSet::new();
        let mut diags = Vec::new();
        let s = load_recursive(
            &ctx,
            std::path::Path::new("requirements.txt"),
            &mut visited,
            &mut diags,
        );
        assert!(diags.is_empty(), "unexpected diagnostics: {diags:?}");
        assert_eq!(s.requirement_count, 2, "expected requests + flask");
    }
}
