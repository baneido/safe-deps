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

/// Command wrappers that prefix the real program (`sudo npm ci`,
/// `env FOO=1 pip install`, `xvfb-run -a pytest`). They are skipped so the
/// underlying package manager is still recognized.
const WRAPPERS: &[&str] = &[
    "sudo",
    "doas",
    "env",
    "command",
    "nice",
    "ionice",
    "xvfb-run",
    "time",
    "exec",
    "setsid",
    "stdbuf",
    "caffeinate",
];

fn leaf(token: &str) -> &str {
    token.rsplit(['/', '\\']).next().unwrap_or(token)
}

fn is_env_assignment(token: &str) -> bool {
    token.contains('=') && !token.starts_with('-')
}

/// The index of the real program token, skipping leading `VAR=value` env
/// assignments and wrapper commands (with their dashed flags).
fn effective_start(tokens: &[String]) -> Option<usize> {
    let mut idx = 0;
    loop {
        while idx < tokens.len() && is_env_assignment(&tokens[idx]) {
            idx += 1;
        }
        let tok = tokens.get(idx)?;
        if WRAPPERS.contains(&leaf(tok)) {
            idx += 1;
            while idx < tokens.len() && tokens[idx].starts_with('-') {
                idx += 1;
            }
            continue;
        }
        return Some(idx);
    }
}

/// The leaf program name of a segment, with any path prefix removed
/// (`/usr/bin/npm` -> `npm`), skipping leading env assignments and wrapper
/// commands. Returns `None` for an empty segment.
pub fn program(tokens: &[String]) -> Option<&str> {
    effective_start(tokens).map(|s| leaf(&tokens[s]))
}

/// The first non-flag token after the program, e.g. the `install` in
/// `npm install --foo` (also seeing through wrappers like `sudo npm install`).
pub fn subcommand(tokens: &[String]) -> Option<&str> {
    let start = effective_start(tokens)?;
    tokens[start + 1..]
        .iter()
        .find(|t| !t.starts_with('-'))
        .map(|t| t.as_str())
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

/// The positional (non-flag) arguments of a segment after the program (skipping
/// env prefixes and wrappers). For `npm install left-pad` this is
/// `["install", "left-pad"]`; SD002 uses the count to tell a full install from
/// adding a specific package.
pub fn positionals(tokens: &[String]) -> Vec<&str> {
    let Some(start) = effective_start(tokens) else {
        return Vec::new();
    };
    tokens[start + 1..]
        .iter()
        .filter(|t| !t.starts_with('-'))
        .map(|t| t.as_str())
        .collect()
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
        "cargo" => (Cargo, pos.first().copied()),
        "go" => (Go, pos.first().copied()),
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
        // Cargo/Go are not recognized as CI install invocations (no npm-style
        // resolving install is gated here).
        Cargo | Go => false,
    }
}

/// Shell constructs the pragmatic tokenizer does not model. When present, the
/// `segments`/`invocation` view of a command may mis-split or miss a sub-command,
/// so callers can surface a low-confidence diagnostic instead of silently
/// trusting the parse. Returns a short, fixed description of the first construct
/// found (for a deterministic message), or `None` for a cleanly tokenizable line.
///
/// Single-quoted spans are literal in shell, so their contents are ignored (a
/// literal `echo '$(x)'` is not flagged). Double-quoted spans are kept because
/// command substitution still runs inside them.
pub fn uncertainty(command: &str) -> Option<&'static str> {
    let scanned = scannable(command);
    if scanned.contains("$(") {
        Some("command substitution")
    } else if scanned.contains('`') {
        Some("backtick command substitution")
    } else if scanned.contains("<(") || scanned.contains(">(") {
        Some("process substitution")
    } else if scanned.contains("<<") {
        // Covers heredocs (`<<EOF`) and herestrings (`<<<`).
        Some("heredoc or herestring")
    } else if scanned.contains("() {") || scanned.contains("(){") {
        Some("shell function definition")
    } else {
        None
    }
}

/// Returns a view of the command suitable for scanning for special constructs,
/// with shell-inert text removed: single-quoted spans (everything inside is
/// literal) and backslash-escaped characters are dropped. Double-quoted spans are
/// kept because command substitution and backticks still run inside them — but a
/// single quote inside a double-quoted span is an ordinary character, not a span
/// delimiter (POSIX), so it does not start stripping. An unterminated quote drops
/// the remainder, matching how a shell would treat it as continuing.
fn scannable(s: &str) -> String {
    enum State {
        Normal,
        Single,
        Double,
    }
    let mut out = String::with_capacity(s.len());
    let mut state = State::Normal;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match state {
            // Outside quotes: a backslash escapes (and thus neutralizes) the next
            // character, so `\$(` is not a substitution.
            State::Normal => match c {
                '\\' => {
                    chars.next();
                }
                '\'' => state = State::Single,
                '"' => state = State::Double,
                _ => out.push(c),
            },
            // Single quotes: no escapes, everything literal until the next `'`.
            State::Single => {
                if c == '\'' {
                    state = State::Normal;
                }
            }
            // Double quotes: substitutions still run, so keep the text, but a
            // backslash escapes the next character (e.g. `\$` is literal).
            State::Double => match c {
                '\\' => {
                    chars.next();
                }
                '"' => state = State::Normal,
                _ => out.push(c),
            },
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(s: &str) -> Vec<Vec<String>> {
        segments(s)
    }

    #[test]
    fn uncertainty_flags_complex_constructs() {
        assert_eq!(
            uncertainty("npm install $(cat pkgs)"),
            Some("command substitution")
        );
        assert_eq!(
            uncertainty("npm install `cat pkgs`"),
            Some("backtick command substitution")
        );
        assert_eq!(
            uncertainty("diff <(npm ls) <(cat baseline)"),
            Some("process substitution")
        );
        assert_eq!(
            uncertainty("cat <<EOF\nnpm install\nEOF"),
            Some("heredoc or herestring")
        );
        assert_eq!(
            uncertainty("grep npm <<< \"$pkgs\""),
            Some("heredoc or herestring")
        );
        assert_eq!(
            uncertainty("install() { npm ci; }"),
            Some("shell function definition")
        );
    }

    #[test]
    fn uncertainty_is_none_for_clean_commands() {
        assert_eq!(uncertainty("npm ci && npm test | tee log"), None);
        assert_eq!(uncertainty("pnpm install --frozen-lockfile"), None);
        // A literal inside single quotes is not a real construct.
        assert_eq!(uncertainty("echo '$(not a command)'"), None);
        assert_eq!(uncertainty("echo 'use `backticks` literally'"), None);
    }

    #[test]
    fn uncertainty_is_double_quote_and_escape_aware() {
        // Single quotes inside a double-quoted span are literal, so the
        // substitution still runs and must be flagged.
        assert_eq!(
            uncertainty("npm install \"'$(cat pkgs)'\""),
            Some("command substitution")
        );
        // A backslash-escaped `$` is literal, not a substitution.
        assert_eq!(uncertainty("echo \\$(not really)"), None);
        assert_eq!(uncertainty("echo \"\\$(not really)\""), None);
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
    fn sees_through_wrapper_commands() {
        for cmd in [
            "sudo pip install --break-system-packages requests",
            "env PIP_NO_INPUT=1 pip install --break-system-packages requests",
            "sudo -H pip install --break-system-packages requests",
        ] {
            let s = seg(cmd);
            assert_eq!(program(&s[0]), Some("pip"), "{cmd}");
            assert_eq!(subcommand(&s[0]), Some("install"), "{cmd}");
            assert!(has_flag(&s[0], "--break-system-packages"), "{cmd}");
        }
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
