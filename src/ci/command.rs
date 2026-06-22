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

/// Options that consume the following token as their value (space-separated
/// form), keyed by the leaf program name. When a command uses `--flag value`
/// the `value` token must not be mistaken for a subcommand or positional.
///
/// The `=` form (`--flag=value`) is already handled by the tokenizer because
/// it arrives as a single token and is never split; only the two-token form
/// needs explicit treatment here.
fn value_taking_options(prog: &str) -> &'static [&'static str] {
    match prog {
        "npm" => &[
            "--prefix",
            "--workspace",
            "-w",
            "--workspaces-update",
            "--userconfig",
            "--globalconfig",
            "--registry",
            "--cache",
            "--tag",
            "--otp",
        ],
        "pnpm" => &[
            "--filter",
            "-F",
            "--workspace-root",
            "--dir",
            "-C",
            "--reporter",
            "--registry",
            "--store-dir",
            "--virtual-store-dir",
            "--tag",
        ],
        "yarn" => &[
            "--cwd",
            "--registry",
            "--network-concurrency",
            "--network-timeout",
            "--proxy",
            "--https-proxy",
            "--offline",
            "--prefer-offline",
            "--modules-folder",
            "--emoji",
        ],
        "bun" => &["--cwd", "--registry", "--tag", "--filter", "-F"],
        "uv" => &[
            "--project",
            "--directory",
            "-p",
            "--python",
            "--index",
            "--index-url",
            "--extra-index-url",
            "--constraint",
            "--override",
            "--config-file",
            "--env-file",
            "--python-preference",
            "--python-fetch",
            "--installer-parallelism",
            "--cache-dir",
            "--link-mode",
        ],
        "pip" | "pip3" => &[
            "-r",
            "--requirement",
            "-c",
            "--constraint",
            "-i",
            "--index-url",
            "--extra-index-url",
            "--trusted-host",
            "--target",
            "-t",
            "--prefix",
            "--root",
            "--find-links",
            "-f",
            "--log",
            "--proxy",
            "--retries",
            "--timeout",
            "--exists-action",
            "--cert",
            "--client-cert",
            "--isolated",
            "--cache-dir",
            "--no-cache-dir",
            "--disable-pip-version-check",
        ],
        _ => &[],
    }
}

/// Returns the set of token indices (relative to `tokens`) that are values
/// consumed by a value-taking option in its space-separated form.  Only tokens
/// after the real program start are examined; the program token itself is at
/// `start`.
fn option_value_indices(tokens: &[String], start: usize) -> std::collections::HashSet<usize> {
    let prog = leaf(&tokens[start]);
    let vto = value_taking_options(prog);
    let mut skip = std::collections::HashSet::new();
    let mut i = start + 1;
    while i < tokens.len() {
        let t = &tokens[i];
        // `--flag=value` is a single token — no index to skip.
        if t.starts_with('-') && !t.contains('=') && vto.contains(&t.as_str()) {
            // The next token is the value; mark it.
            if i + 1 < tokens.len() {
                skip.insert(i + 1);
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    skip
}

/// The first non-flag token after the program, e.g. the `install` in
/// `npm install --foo` (also seeing through wrappers like `sudo npm install`).
/// Values of value-taking options (e.g. the `web` in `npm --prefix web ci`)
/// are excluded.
pub fn subcommand(tokens: &[String]) -> Option<&str> {
    let start = effective_start(tokens)?;
    let skip = option_value_indices(tokens, start);
    tokens[start + 1..]
        .iter()
        .enumerate()
        .filter(|(rel_i, t)| !t.starts_with('-') && !skip.contains(&(start + 1 + rel_i)))
        .map(|(_, t)| t.as_str())
        .next()
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
///
/// Values consumed by value-taking options (e.g. the `web` in
/// `npm --prefix web install`) are excluded so they are not mistaken for
/// subcommands or package names.
pub fn positionals(tokens: &[String]) -> Vec<&str> {
    let Some(start) = effective_start(tokens) else {
        return Vec::new();
    };
    let skip = option_value_indices(tokens, start);
    tokens[start + 1..]
        .iter()
        .enumerate()
        .filter(|(rel_i, t)| !t.starts_with('-') && !skip.contains(&(start + 1 + rel_i)))
        .map(|(_, t)| t.as_str())
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

/// Detects shell constructs the pragmatic tokenizer cannot fully or accurately
/// parse, returning a short human-readable reason. The tokenizer still produces
/// a best-effort segmentation; this exposes the uncertainty so a reduced-
/// confidence parse is not mistaken for a clean one (surfaced as the
/// `complex-shell-not-fully-parsed` diagnostic). Returns the first construct
/// found, in a fixed order, so the message is deterministic.
pub fn uncertainty(command: &str) -> Option<&'static str> {
    // `$((…))` arithmetic is neither command substitution nor (for its inner
    // `<<` left-shift) a heredoc, so strip it before both scans below.
    let cleaned = strip_arithmetic(command);
    // Substitution scan: keep double-quoted content (substitutions still run
    // inside `"…"`), drop single-quoted literals and backslash-escaped chars.
    let subst = scannable(&cleaned);
    if subst.contains("$(") {
        return Some("command substitution");
    }
    if subst.contains('`') {
        return Some("backtick command substitution");
    }
    // Redirection operators never appear inside quotes, so strip all quoted
    // spans before looking for process substitution and heredocs/here-strings.
    let ops = strip_quoted(&cleaned);
    if ops.contains("<(") || ops.contains(">(") {
        return Some("process substitution");
    }
    if has_heredoc(&ops) {
        return Some("heredoc / here-string");
    }
    // Function definitions are command-position constructs, so check the
    // quote-aware segments rather than the raw string: this flags `function f {`
    // and `f() { … }` but not a `function`/`()` inside an argument or comment.
    if is_function_definition(command) {
        return Some("shell function definition");
    }
    None
}

/// Whether `command` declares a shell function, in either the `function name { … }`
/// keyword form or the POSIX `name() { … }` form, at the start of any statement.
/// An opening `{` body token is required, so a command whose program merely ends
/// in `()` (or is literally `function`) without a brace block is not flagged.
fn is_function_definition(command: &str) -> bool {
    segments(command).iter().any(|seg| {
        let Some(first) = seg.first() else {
            return false;
        };
        // `name(){ … }` with the brace attached to the name (no space).
        if first.contains("(){") {
            return true;
        }
        // `name() { … }` — the name token ends in an empty `()` pair and the body
        // brace follows as the next token. (Process/command substitution put `(`
        // mid-token or after `<`/`$`, so their first segment token does not end
        // in `()`.)
        if first.len() > 2 && first.ends_with("()") {
            return seg.get(1).is_some_and(|t| t.starts_with('{'));
        }
        // `function name { … }` keyword form, with a brace body somewhere after.
        if first == "function" {
            return seg.iter().skip(1).any(|t| t.starts_with('{'));
        }
        false
    })
}

/// Removes `$((…))` arithmetic spans, where a `<<` is a left-shift rather than a
/// heredoc. Approximate (matches the first `))`), which is sufficient here.
fn strip_arithmetic(command: &str) -> String {
    let mut out = String::with_capacity(command.len());
    let mut rest = command;
    while let Some(start) = rest.find("$((") {
        out.push_str(&rest[..start]);
        rest = match rest[start..].find("))") {
            Some(end) => &rest[start + end + 2..],
            None => &rest[start + 3..],
        };
    }
    out.push_str(rest);
    out
}

/// Returns a view of the command for substitution scanning, with shell-inert
/// text removed: single-quoted spans (everything inside is literal) and
/// backslash-escaped characters are dropped. Double-quoted spans are kept because
/// command substitution and backticks still run inside them — but a single quote
/// inside a double-quoted span is an ordinary character, not a span delimiter
/// (POSIX), so it does not start stripping. An unterminated quote drops the
/// remainder, matching how a shell would treat it as continuing.
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

/// Removes single- and double-quoted spans (and their quote characters), so a
/// `<<`/`<(` inside a string literal is not mistaken for a real operator. Used
/// for redirection-operator detection, which never occurs inside quotes.
///
/// Backslash escaping is honored outside quotes and inside double quotes (so an
/// escaped quote `\"` does not end the span and an escaped `\<` is not an
/// operator). Inside single quotes a backslash is literal, per POSIX.
fn strip_quoted(command: &str) -> String {
    let mut out = String::with_capacity(command.len());
    let mut quote: Option<char> = None;
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        match quote {
            // Single quotes: no escapes; only another `'` ends the span.
            Some('\'') => {
                if c == '\'' {
                    quote = None;
                }
            }
            // Double quotes: a backslash escapes the next char (so `\"` does not
            // end the span); otherwise `"` ends it. Content is dropped either way.
            Some(_) => match c {
                '\\' => {
                    chars.next();
                }
                '"' => quote = None,
                _ => {}
            },
            // Outside quotes a backslash neutralizes the next char, so `\<`/`\"`
            // are literal and start neither an operator nor a quoted span.
            None => match c {
                '\\' => {
                    chars.next();
                }
                '\'' | '"' => quote = Some(c),
                _ => out.push(c),
            },
        }
    }
    out
}

/// Whether `skeleton` (quotes/arithmetic already stripped) contains a heredoc
/// (`<<DELIM`, `<<-DELIM`) or here-string (`<<<`). A bare `<<` followed by a
/// digit/operator (a left-shift the arithmetic strip missed) is not a heredoc.
fn has_heredoc(skeleton: &str) -> bool {
    let chars: Vec<char> = skeleton.chars().collect();
    let mut i = 0;
    while i + 1 < chars.len() {
        if chars[i] == '<' && chars[i + 1] == '<' {
            // Here-string `<<<`.
            if chars.get(i + 2) == Some(&'<') {
                return true;
            }
            let mut j = i + 2;
            if chars.get(j) == Some(&'-') {
                j += 1;
            }
            while matches!(chars.get(j), Some(' ') | Some('\t')) {
                j += 1;
            }
            // A heredoc delimiter is a word; it may start with a letter, digit,
            // `_`, or a quote/backslash. (A `<<` followed by an operator or end
            // of input is a left-shift the arithmetic strip missed, not a heredoc.)
            if let Some(&d) = chars.get(j) {
                if d.is_alphanumeric() || d == '_' || d == '"' || d == '\'' || d == '\\' {
                    return true;
                }
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(s: &str) -> Vec<Vec<String>> {
        segments(s)
    }

    #[test]
    fn uncertainty_flags_all_unparseable_constructs() {
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
            Some("heredoc / here-string")
        );
        assert_eq!(
            uncertainty("grep npm <<< \"$pkgs\""),
            Some("heredoc / here-string")
        );
        assert_eq!(
            uncertainty("install() { npm ci; }"),
            Some("shell function definition")
        );
        assert_eq!(
            uncertainty("function deploy { npm ci; }"),
            Some("shell function definition")
        );
    }

    #[test]
    fn uncertainty_is_none_for_clean_commands() {
        assert_eq!(uncertainty("npm ci && npm test | tee log"), None);
        assert_eq!(uncertainty("pnpm install --frozen-lockfile"), None);
        assert_eq!(uncertainty("pip install -r requirements.txt"), None);
        // A literal inside single quotes is not a real construct.
        assert_eq!(uncertainty("echo '$(not a command)'"), None);
        assert_eq!(uncertainty("echo 'use `backticks` literally'"), None);
    }

    #[test]
    fn uncertainty_is_quote_arithmetic_and_escape_aware() {
        // Single quotes inside a double-quoted span are literal, so the
        // substitution still runs and must be flagged.
        assert_eq!(
            uncertainty("npm install \"'$(cat pkgs)'\""),
            Some("command substitution")
        );
        // A backslash-escaped `$` is literal, not a substitution.
        assert_eq!(uncertainty("echo \\$(not really)"), None);
        assert_eq!(uncertainty("echo \"\\$(not really)\""), None);
        // `<<` inside quotes or as an arithmetic left-shift is not a heredoc.
        assert_eq!(uncertainty("echo \"value << shifted\""), None);
        assert_eq!(uncertainty("echo $((1 << 2))"), None);
        assert_eq!(uncertainty("RESULT=$((x<<y)) make"), None);
        // An escaped quote does not end a double-quoted span, so a `<<` that
        // appears only inside the string literal is still not a heredoc.
        assert_eq!(uncertainty("echo \"a \\\"<<\\\" b\""), None);
    }

    #[test]
    fn heredoc_delimiter_may_start_with_a_digit() {
        // POSIX here-doc delimiters are general words, so `<<1` is valid.
        assert_eq!(
            uncertainty("npm ci <<1\nfoo\n1"),
            Some("heredoc / here-string")
        );
    }

    #[test]
    fn uncertainty_function_detection_avoids_false_positives() {
        // `function`/`()` only count at command position, not inside arguments,
        // flag values, or comment lines.
        assert_eq!(uncertainty("echo \"this function checks the build\""), None);
        assert_eq!(uncertainty("firebase deploy --only function"), None);
        assert_eq!(uncertainty("# helper function to install deps"), None);
        assert_eq!(uncertainty("python -c \"def f(): pass\""), None);
        // A definition requires a `{` body: a program ending in `()` or a bare
        // `function` keyword without a brace block is not flagged.
        assert_eq!(uncertainty("weird() arg"), None);
        assert_eq!(uncertainty("function deploy"), None);
        // The brace may be attached to the name (`name(){`).
        assert_eq!(
            uncertainty("deploy(){ npm ci; }"),
            Some("shell function definition")
        );
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

    // Tests for value-taking option filtering (issue #87).

    #[test]
    fn value_taking_option_prefix_does_not_leak_into_subcommand() {
        // `npm --prefix web ci` — `web` is the value of --prefix, not a positional.
        let s = seg("npm --prefix web ci");
        assert_eq!(subcommand(&s[0]), Some("ci"));
        assert_eq!(positionals(&s[0]), vec!["ci"]);
    }

    #[test]
    fn value_taking_option_filter_does_not_leak_into_subcommand() {
        // `pnpm --filter app install` — `app` is the value of --filter.
        let s = seg("pnpm --filter app install");
        assert_eq!(subcommand(&s[0]), Some("install"));
        assert_eq!(positionals(&s[0]), vec!["install"]);
    }

    #[test]
    fn value_taking_option_cwd_does_not_leak_into_subcommand() {
        // `yarn --cwd web install` — `web` is the value of --cwd.
        let s = seg("yarn --cwd web install");
        assert_eq!(subcommand(&s[0]), Some("install"));
        assert_eq!(positionals(&s[0]), vec!["install"]);
    }

    #[test]
    fn value_taking_option_project_does_not_leak_into_subcommand() {
        // `uv --project . sync` — `.` is the value of --project.
        let s = seg("uv --project . sync");
        assert_eq!(subcommand(&s[0]), Some("sync"));
        assert_eq!(positionals(&s[0]), vec!["sync"]);
    }

    #[test]
    fn workspace_option_value_not_counted_as_package_positional() {
        // `npm install --workspace packages/app` — the workspace path is a value,
        // not a named package being added. positionals = ["install"] (length 1).
        let s = seg("npm install --workspace packages/app");
        assert_eq!(positionals(&s[0]), vec!["install"]);
    }

    #[test]
    fn eq_form_does_not_consume_next_token() {
        // `npm --prefix=web ci` — `=value` is attached; the next token `ci` is
        // still a positional/subcommand, not a consumed value.
        let s = seg("npm --prefix=web ci");
        assert_eq!(subcommand(&s[0]), Some("ci"));
        assert_eq!(positionals(&s[0]), vec!["ci"]);
    }

    #[test]
    fn invocation_sees_through_monorepo_flags() {
        use PackageManager::*;
        let inv = |c: &str| invocation(&seg(c)[0]);
        assert_eq!(
            inv("npm --prefix web ci"),
            Some(Invocation {
                pm: Npm,
                sub: Some("ci".into())
            })
        );
        assert_eq!(
            inv("pnpm --filter app install"),
            Some(Invocation {
                pm: Pnpm,
                sub: Some("install".into())
            })
        );
        assert_eq!(
            inv("yarn --cwd web install"),
            Some(Invocation {
                pm: Yarn,
                sub: Some("install".into())
            })
        );
        assert_eq!(
            inv("uv --project . sync"),
            Some(Invocation {
                pm: Uv,
                sub: Some("sync".into())
            })
        );
    }
}
