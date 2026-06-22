//! Single-source guard for rule metadata (#66).
//!
//! The `Rule` trait (`id` / `summary` / `explanation`) is the source of truth
//! for rule metadata. These tests assert the README rule table and the rule
//! registry stay in sync with it, so adding or editing a rule cannot silently
//! drift from the documentation — the historical failure mode this guards.

use std::collections::BTreeMap;

use safe_deps::rules::all_rules;

/// Parses the `## Rules` table in README.md into `id -> summary`. That table's
/// rows are the only ones starting with `| SD` (the coverage matrix rows start
/// with an ecosystem name), so the filter is unambiguous.
fn readme_rule_table() -> BTreeMap<String, String> {
    let readme = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"));
    let mut table = BTreeMap::new();
    for line in readme.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("| SD") {
            continue;
        }
        let cells: Vec<&str> = trimmed
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        if cells.len() == 2 {
            table.insert(cells[0].to_string(), cells[1].to_string());
        }
    }
    table
}

#[test]
fn readme_rule_table_matches_the_registry() {
    let readme = readme_rule_table();
    let registry: BTreeMap<String, String> = all_rules()
        .iter()
        .map(|r| (r.id().as_str().to_string(), r.summary().to_string()))
        .collect();

    // Same set of rule ids: no rule missing from the README, none stale.
    let readme_ids: Vec<&String> = readme.keys().collect();
    let registry_ids: Vec<&String> = registry.keys().collect();
    assert_eq!(
        registry_ids, readme_ids,
        "README rule table and rules::all_rules() list different rule ids"
    );

    // Summaries are byte-for-byte the registry's `summary()` (README mirrors the
    // code, which is what `list-rules`/`explain` print).
    for (id, summary) in &registry {
        assert_eq!(
            readme.get(id),
            Some(summary),
            "README summary for {id} drifted from Rule::summary()"
        );
    }
}

#[test]
fn every_rule_has_nonempty_metadata() {
    for rule in all_rules() {
        let id = rule.id().as_str().to_string();
        assert!(id.starts_with("SD"), "unexpected rule id: {id}");
        assert!(
            !rule.summary().trim().is_empty(),
            "{id} has an empty summary"
        );
        assert!(
            rule.summary().ends_with('.'),
            "{id} summary should be a sentence ending in '.'"
        );
        assert!(
            !rule.explanation().trim().is_empty(),
            "{id} has an empty explanation"
        );
    }
}

#[test]
fn rule_ids_are_unique_and_sorted_in_the_registry() {
    let ids: Vec<String> = all_rules()
        .iter()
        .map(|r| r.id().as_str().to_string())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        ids, sorted,
        "rules::all_rules() must be unique and id-sorted"
    );
}
