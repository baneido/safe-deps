//! Go dependency-source extraction for SD006: unsafe (local-path) `replace`
//! directive targets.

use std::path::Path;

use crate::ecosystems::{
    classify_go_replace_target, Dependency, DependencyGroup, DependencySource,
};

use super::manifest::strip_comment;

/// Extracts SD006-relevant dependencies from `replace` directives. A `replace`
/// to a local filesystem path is unsafe (it is ignored outside the main module,
/// so consumers cannot resolve it); module-to-module replacements and ordinary
/// `require`d modules are proxy-resolved and checksummed (safe), so they are not
/// emitted.
pub(super) fn dependencies(text: &str, file: &Path) -> Vec<Dependency> {
    let mut out = Vec::new();
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
                push_replace(line, file, &mut out);
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("replace") {
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
            } else {
                push_replace(rest, file, &mut out);
            }
        }
    }
    out
}

/// Parses one `old[ ver] => new[ ver]` replacement; pushes a dependency only for
/// an unsafe (local-path) target.
fn push_replace(spec: &str, file: &Path, out: &mut Vec<Dependency>) {
    let Some((lhs, rhs)) = spec.split_once("=>") else {
        return;
    };
    let name = lhs.split_whitespace().next().unwrap_or("");
    let target = rhs.trim();
    if name.is_empty() || target.is_empty() {
        return;
    }
    let source = classify_go_replace_target(target);
    if matches!(source, DependencySource::Registry) {
        return;
    }
    // Drop any version suffix from the target for a readable spec.
    let spec = target.split_whitespace().next().unwrap_or(target);
    out.push(Dependency {
        name: name.to_string(),
        spec: spec.to_string(),
        group: DependencyGroup::Production,
        source,
        file: file.to_path_buf(),
    });
}
