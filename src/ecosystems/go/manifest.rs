//! `go.mod` parsing: required-module count and `//` comment stripping.

/// Counts required modules in a `go.mod`, across both the block form
/// (`require ( … )`) and single-line `require path version` directives.
pub(super) fn parse_requires(text: &str) -> usize {
    let mut count = 0;
    let mut in_block = false;
    for raw in text.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if in_block {
            if line == ")" {
                in_block = false;
            } else {
                count += 1;
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("require") {
            // Require a keyword boundary so a module path like `require-utils…`
            // is not mistaken for the `require` directive.
            let boundary = match rest.chars().next() {
                Some(c) => c.is_whitespace() || c == '(',
                None => true,
            };
            if !boundary {
                continue;
            }
            let rest = rest.trim_start();
            if rest.starts_with('(') {
                in_block = true;
            } else if !rest.is_empty() {
                count += 1;
            }
        }
    }
    count
}

/// Strips a `//` line comment, ignoring `//` inside nothing in particular
/// (go.mod has no strings, so a simple scan is correct).
pub(super) fn strip_comment(line: &str) -> &str {
    match line.find("//") {
        Some(idx) => &line[..idx],
        None => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_block_and_single_requires() {
        let block = "module m\n\ngo 1.21\n\nrequire (\n\tgithub.com/x/y v1.2.3\n\tgithub.com/a/b v0.1.0 // indirect\n)\n";
        assert_eq!(parse_requires(block), 2);
        let single = "module m\n\ngo 1.21\n\nrequire github.com/x/y v1.0.0\n";
        assert_eq!(parse_requires(single), 1);
        let none = "module m\n\ngo 1.21\n";
        assert_eq!(parse_requires(none), 0);
        // A module path beginning with "require" is not the require directive.
        let tricky = "module m\nrequire-utils.example/x v1.0.0 is not a directive\n";
        assert_eq!(parse_requires(tricky), 0);
    }

    #[test]
    fn malformed_input_counts_zero_requires() {
        // Malformed input must not panic; this fragment degrades to a zero
        // count (the trailing `require (` opens a block that never adds rows).
        let garbage = "}{ not really go.mod (((\nreplace =>\nrequire (\n";
        assert_eq!(parse_requires(garbage), 0);
    }
}
