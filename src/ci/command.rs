//! Pragmatic shell-command tokenizing shared by CI-aware rules.
//!
//! CI `run` blocks contain shell, not structured data. This module splits a
//! command line into independent sub-command segments on the common operators
//! (`&&`, `||`, `;`, `|`, `&`, redirections) and tokenizes each segment on
//! whitespace, stripping simple quotes. It performs no variable expansion and
//! does not try to be a real shell parser: complex constructs are intentionally
//! treated as lower-confidence, matching the design's "pragmatic" CI parsing
//! strategy.
//!
//! It also normalizes a segment into an [`Invocation`] — the package manager and
//! subcommand it runs — so SD002, SD008, and SD009 share one definition of "what
//! command is this" instead of each re-deriving it.

use crate::ecosystems::PackageManager;

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
            '&' | '|' | ';' | '<' | '>' => {
                flush_word(&mut word, &mut has_word, &mut current);
                if !current.is_empty() {
                    segments.push(std::mem::take(&mut current));
                }
                // Consume a paired operator (`&&`, `||`, `>>`) as one separator.
                if (c == '&' || c == '|' || c == '>') && i + 1 < bytes.len() && bytes[i + 1] == c {
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

/// Whether a segment carries `flag` as enabled — either bare (`--frozen`) or
/// `flag=<truthy>`. An explicit false value (`--frozen-lockfile=false`) counts
/// as NOT present, so it does not suppress a finding the way the enabled form
/// would.
pub fn has_flag(tokens: &[String], flag: &str) -> bool {
    let with_eq = format!("{flag}=");
    tokens.iter().any(|t| {
        if t == flag {
            return true;
        }
        match t.strip_prefix(&with_eq) {
            Some(value) => !is_falsey(value),
            None => false,
        }
    })
}

/// Whether a `flag=value` value explicitly disables the flag.
fn is_falsey(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "false" | "0" | "no" | "off"
    )
}

/// Whether any of `flags` is present.
pub fn has_any_flag(tokens: &[String], flags: &[&str]) -> bool {
    flags.iter().any(|f| has_flag(tokens, f))
}

/// A normalized package-manager invocation: which manager, and its subcommand.
///
/// Wrapper forms are unwrapped to the underlying manager: `python -m pip …` and
/// `uv pip …` both normalize to [`PackageManager::Pip`] so rules see a single
/// pip shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub pm: PackageManager,
    pub sub: Option<String>,
}

/// The positional (non-flag) arguments of a segment after the program, with
/// leading `VAR=value` environment prefixes and the program token removed.
fn positionals(tokens: &[String]) -> Vec<&str> {
    let mut seen_program = false;
    let mut out = Vec::new();
    for tok in tokens {
        if tok.starts_with('-') {
            continue;
        }
        if !seen_program {
            // Skip `VAR=value` env prefixes that precede the program.
            if tok.contains('=') {
                continue;
            }
            seen_program = true;
            continue;
        }
        out.push(tok.as_str());
    }
    out
}

/// Normalizes a segment into an [`Invocation`], or `None` if the program is not
/// a recognized package manager.
pub fn invocation(tokens: &[String]) -> Option<Invocation> {
    use PackageManager::*;
    let program = program(tokens)?;
    let pos = positionals(tokens);
    let (pm, sub) = match program {
        "npm" => (Npm, pos.first().copied()),
        "yarn" => (Yarn, pos.first().copied()),
        "pnpm" => (Pnpm, pos.first().copied()),
        "bun" => (Bun, pos.first().copied()),
        "pip" | "pip3" => (Pip, pos.first().copied()),
        // `uv pip <sub>` is uv's pip interface; treat it as pip. Plain `uv <sub>`
        // (e.g. `uv sync`) stays uv.
        "uv" => {
            if pos.first() == Some(&"pip") {
                (Pip, pos.get(1).copied())
            } else {
                (Uv, pos.first().copied())
            }
        }
        // `python -m pip <sub>` (the `-m` flag is filtered out, so `pip` is the
        // first positional). Plain `python script.py` is not a manager.
        "python" | "python3" if pos.first() == Some(&"pip") => (Pip, pos.get(1).copied()),
        _ => return None,
    };
    Some(Invocation {
        pm,
        sub: sub.map(|s| s.to_string()),
    })
}

/// Whether an invocation installs project dependencies (the install family for
/// its manager). Used to gate CI-aware rules to install commands only, so that
/// non-install package-manager commands (e.g. `npm cache clean --force`) are not
/// flagged.
pub fn is_install(inv: &Invocation) -> bool {
    use PackageManager::*;
    let sub = inv.sub.as_deref();
    match inv.pm {
        Npm | Bun => matches!(sub, Some("install") | Some("i") | Some("ci") | Some("add")),
        Pnpm => matches!(sub, Some("install") | Some("i") | Some("add")),
        // Bare `yarn` is equivalent to `yarn install`.
        Yarn => matches!(sub, None | Some("install") | Some("add")),
        Pip => matches!(sub, Some("install")),
        Uv => matches!(sub, Some("sync") | Some("install")),
    }
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
    fn explicit_false_value_is_not_enabled() {
        // `--frozen-lockfile=false` must NOT count as the protection being on,
        // so SD002/SD009 still flag the install.
        for falsey in ["false", "0", "no", "off"] {
            let s = seg(&format!("pnpm install --frozen-lockfile={falsey}"));
            assert!(
                !has_flag(&s[0], "--frozen-lockfile"),
                "=`{falsey}` should not be enabled"
            );
        }
        let truthy = seg("uv sync --locked=true");
        assert!(has_flag(&truthy[0], "--locked"));
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

    #[test]
    fn redirections_split_install_from_target() {
        let s = seg("npm install --force > build.log 2>&1");
        // The install command survives as its own clean segment.
        assert_eq!(s[0], vec!["npm", "install", "--force"]);
    }

    #[test]
    fn invocation_normalizes_wrapper_forms() {
        use PackageManager::*;
        let inv = |c: &str| invocation(&seg(c)[0]);
        assert_eq!(
            inv("npm ci"),
            Some(Invocation {
                pm: Npm,
                sub: Some("ci".into())
            })
        );
        assert_eq!(
            inv("yarn"),
            Some(Invocation {
                pm: Yarn,
                sub: None
            })
        );
        // `python -m pip install` and `uv pip install` both normalize to pip.
        assert_eq!(
            inv("python -m pip install -r r.txt"),
            Some(Invocation {
                pm: Pip,
                sub: Some("install".into())
            })
        );
        assert_eq!(
            inv("uv pip install -r r.txt"),
            Some(Invocation {
                pm: Pip,
                sub: Some("install".into())
            })
        );
        assert_eq!(
            inv("uv sync"),
            Some(Invocation {
                pm: Uv,
                sub: Some("sync".into())
            })
        );
        assert_eq!(inv("git push"), None);
    }

    #[test]
    fn is_install_gates_to_install_family() {
        let inv = |c: &str| invocation(&seg(c)[0]).unwrap();
        assert!(is_install(&inv("npm ci")));
        assert!(is_install(&inv("npm install")));
        assert!(is_install(&inv("yarn")));
        assert!(is_install(&inv("uv sync")));
        assert!(is_install(&inv("uv pip install -r r.txt")));
        // Non-install package-manager commands must not be treated as installs.
        assert!(!is_install(&inv("npm cache clean --force")));
        assert!(!is_install(&inv("pnpm dlx create-app --force")));
        assert!(!is_install(&inv("npm run build")));
    }
}
