//! Pragmatic shell-command tokenizing shared by CI-aware rules.
//!
//! CI `run` blocks contain shell, not structured data. This module splits a
//! command line into independent sub-command segments on the common operators
//! (`&&`, `||`, `;`, `|`, `&`) and tokenizes each segment on whitespace,
//! stripping simple quotes. It performs no variable expansion and does not try
//! to be a real shell parser: complex constructs are intentionally treated as
//! lower-confidence, matching the design's "pragmatic" CI parsing strategy.

/// Splits a command line into sub-command segments, each a list of tokens.
///
/// Quoting (`'…'`, `"…"`) suppresses operator and whitespace splitting inside
/// the quotes; the surrounding quote characters are removed from the token.
/// Empty segments are dropped.
pub fn segments(command: &str) -> Vec<Vec<String>> {
    let mut segments = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut has_word = false;
    let mut quote: Option<char> = None;

    let bytes: Vec<char> = command.chars().collect();
    let mut i = 0;

    let flush_word = |word: &mut String, has_word: &mut bool, current: &mut Vec<String>| {
        if *has_word {
            current.push(std::mem::take(word));
            *has_word = false;
        }
    };

    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else {
                word.push(c);
                has_word = true;
            }
            i += 1;
            continue;
        }
        match c {
            '\'' | '"' => {
                quote = Some(c);
                has_word = true; // an empty quoted string is still a token
            }
            c if c.is_whitespace() => {
                flush_word(&mut word, &mut has_word, &mut current);
            }
            '&' | '|' | ';' => {
                flush_word(&mut word, &mut has_word, &mut current);
                if !current.is_empty() {
                    segments.push(std::mem::take(&mut current));
                }
                // Consume a paired operator (`&&`, `||`) as one separator.
                if (c == '&' || c == '|') && i + 1 < bytes.len() && bytes[i + 1] == c {
                    i += 1;
                }
            }
            _ => {
                word.push(c);
                has_word = true;
            }
        }
        i += 1;
    }
    flush_word(&mut word, &mut has_word, &mut current);
    if !current.is_empty() {
        segments.push(current);
    }
    segments
}

/// The leaf program name of a segment, with any path prefix removed
/// (`/usr/bin/npm` -> `npm`). Returns `None` for an empty segment or a leading
/// environment assignment such as `CI=true` (which is skipped to the program).
pub fn program(tokens: &[String]) -> Option<&str> {
    for tok in tokens {
        // Skip leading `VAR=value` environment-prefix assignments.
        if tok.contains('=') && !tok.starts_with('-') {
            continue;
        }
        let name = tok.rsplit(['/', '\\']).next().unwrap_or(tok.as_str());
        return Some(name);
    }
    None
}

/// The first non-flag token after the program, e.g. the `install` in
/// `npm install --foo`. Environment-prefix assignments before the program are
/// skipped. Flags (`-x`, `--y`) are not treated as subcommands.
pub fn subcommand(tokens: &[String]) -> Option<&str> {
    let mut seen_program = false;
    for tok in tokens {
        if !seen_program {
            if tok.contains('=') && !tok.starts_with('-') {
                continue;
            }
            seen_program = true;
            continue;
        }
        if tok.starts_with('-') {
            continue;
        }
        return Some(tok.as_str());
    }
    None
}

/// Whether a segment carries `flag` (exactly, or as `flag=value`).
pub fn has_flag(tokens: &[String], flag: &str) -> bool {
    let with_eq = format!("{flag}=");
    tokens.iter().any(|t| t == flag || t.starts_with(&with_eq))
}

/// Whether any of `flags` is present.
pub fn has_any_flag(tokens: &[String], flags: &[&str]) -> bool {
    flags.iter().any(|f| has_flag(tokens, f))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(s: &str) -> Vec<Vec<String>> {
        segments(s)
    }

    #[test]
    fn splits_on_and_and_pipe() {
        let s = seg("npm install && npm test | tee log");
        assert_eq!(s.len(), 3);
        assert_eq!(s[0], vec!["npm", "install"]);
        assert_eq!(s[1], vec!["npm", "test"]);
        assert_eq!(s[2], vec!["tee", "log"]);
    }

    #[test]
    fn respects_quotes() {
        let s = seg("echo 'a && b' \"c d\"");
        assert_eq!(s.len(), 1);
        assert_eq!(s[0], vec!["echo", "a && b", "c d"]);
    }

    #[test]
    fn program_strips_path_and_env_prefix() {
        let s = seg("CI=true /usr/local/bin/pnpm install");
        assert_eq!(program(&s[0]), Some("pnpm"));
        assert_eq!(subcommand(&s[0]), Some("install"));
    }

    #[test]
    fn has_flag_matches_exact_and_valued() {
        let s = seg("uv sync --locked");
        assert!(has_flag(&s[0], "--locked"));
        let s2 = seg("pnpm install --frozen-lockfile=true");
        assert!(has_flag(&s2[0], "--frozen-lockfile"));
        assert!(!has_flag(&s2[0], "--immutable"));
    }

    #[test]
    fn bare_program_has_no_subcommand() {
        let s = seg("yarn");
        assert_eq!(program(&s[0]), Some("yarn"));
        assert_eq!(subcommand(&s[0]), None);
    }

    #[test]
    fn double_operators_do_not_create_empty_segments() {
        let s = seg("a||b ; ; c");
        assert_eq!(s, vec![vec!["a"], vec!["b"], vec!["c"]]);
    }
}
