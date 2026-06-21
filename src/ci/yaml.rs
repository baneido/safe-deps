//! Small line-oriented YAML helpers shared by the CI provider parsers.
//!
//! The providers (GitHub Actions, GitLab CI, CircleCI) read shell commands out
//! of YAML while preserving exact file/line locations, so they scan lines rather
//! than fully deserializing. These helpers are the common primitives.

/// Number of leading space characters (YAML indentation; tabs are not valid
/// YAML indentation).
pub fn leading_spaces(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ').count()
}

/// Drops up to `n` leading spaces, returning the remainder (the block-scalar
/// content with its base indentation removed).
pub fn dedent(line: &str, n: usize) -> &str {
    let mut idx = 0;
    for (count, (byte_idx, c)) in line.char_indices().enumerate() {
        if count >= n || c != ' ' {
            idx = byte_idx;
            return &line[idx..];
        }
        idx = byte_idx + c.len_utf8();
    }
    &line[idx..]
}

/// Strips a trailing YAML comment (` #…`) that is not inside a quoted scalar. A
/// `#` with no preceding whitespace (e.g. inside `a#b`) is not a comment. A
/// quote only opens a quoted scalar at a value boundary (start, after a space,
/// `-`, `:`, …), so a shell apostrophe such as `don't` is not treated as a YAML
/// quote and a following ` # comment` is still stripped.
pub fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut quote: Option<u8> = None;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                }
            }
            None => {
                if (c == b'"' || c == b'\'') && is_scalar_boundary(bytes, i) {
                    quote = Some(c);
                } else if c == b'#' && (i == 0 || bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') {
                    return &line[..i];
                }
            }
        }
        i += 1;
    }
    line
}

/// Whether byte `i` is at a YAML value boundary where a quoted scalar may begin.
fn is_scalar_boundary(bytes: &[u8], i: usize) -> bool {
    i == 0
        || matches!(
            bytes[i - 1],
            b' ' | b'\t' | b'-' | b':' | b',' | b'[' | b'{' | b'('
        )
}

/// If `line` is a block-mapping key (`key: value`, optionally introduced by a
/// `- ` sequence marker), returns `(key_column, key, value_after_colon)`.
/// `key_column` is the column at which the key begins — for the `- key:` form it
/// is the column of the key, not of the `-`, so sibling keys (which align with
/// the key) are correctly treated as outside a block scalar.
pub fn mapping_key(line: &str) -> Option<(usize, &str, &str)> {
    let indent = leading_spaces(line);
    let mut key_column = indent;
    let mut rest = &line[indent..];
    if let Some(stripped) = rest.strip_prefix("- ") {
        let trimmed = stripped.trim_start();
        key_column += rest.len() - trimmed.len();
        rest = trimmed;
    }
    let colon = rest.find(':')?;
    let key = &rest[..colon];
    // A bare key only: no whitespace (so command lines like `npm i` or a flow
    // `echo a: b` content are not mistaken for keys; block content is consumed
    // separately and never reaches here).
    if key.is_empty() || key.chars().any(|c| c.is_whitespace()) {
        return None;
    }
    let value = &rest[colon + 1..];
    if !(value.is_empty() || value.starts_with([' ', '\t'])) {
        return None;
    }
    Some((key_column, key, value.trim_start()))
}

/// Whether a scalar value introduces a YAML block scalar (`|` or `>` with
/// optional chomping/indentation indicators such as `|-`, `>2`). A trailing
/// comment (`| # note`) is permitted and ignored.
pub fn is_block_scalar_indicator(value: &str) -> bool {
    let v = value.trim();
    // A YAML comment requires whitespace before `#`; strip it before checking.
    let v = match v.find(" #") {
        Some(idx) => v[..idx].trim_end(),
        None => v,
    };
    let mut chars = v.chars();
    match chars.next() {
        Some('|') | Some('>') => chars.all(|c| c == '+' || c == '-' || c.is_ascii_digit()),
        _ => false,
    }
}

/// Removes a single pair of matching surrounding quotes from a scalar.
pub fn unquote(s: &str) -> &str {
    let s = s.trim();
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        if (first == b'"' || first == b'\'') && bytes[bytes.len() - 1] == first {
            return &s[1..s.len() - 1];
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedents_and_counts_indent() {
        assert_eq!(leading_spaces("    x"), 4);
        assert_eq!(dedent("      cmd", 4), "  cmd");
        assert_eq!(dedent("cmd", 4), "cmd");
    }

    #[test]
    fn strips_unquoted_trailing_comment() {
        assert_eq!(strip_comment("npm ci # frozen"), "npm ci ");
        assert_eq!(strip_comment("echo \"a # b\""), "echo \"a # b\"");
        assert_eq!(strip_comment("url#anchor"), "url#anchor");
        // A shell apostrophe is not a YAML quote, so the comment still strips.
        assert_eq!(strip_comment("don't deploy # disabled"), "don't deploy ");
        assert_eq!(strip_comment("echo 'a # b'"), "echo 'a # b'");
    }

    #[test]
    fn unquotes_matching_pairs() {
        assert_eq!(unquote("\"npm ci\""), "npm ci");
        assert_eq!(unquote("'npm ci'"), "npm ci");
        assert_eq!(unquote("npm ci"), "npm ci");
    }
}
