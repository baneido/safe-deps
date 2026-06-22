//! Single-source guard for rule metadata (#66).
//!
//! The declarative `rules::meta::ALL_RULE_META` registry is the source of truth
//! for rule metadata (id / summary / explanation / default severity /
//! applicable ecosystems / SARIF help URI). These tests assert that:
//!
//!   * `rules::all_rules()` (the behavior registry) has exactly the same rule
//!     ids as the metadata registry — no rule can ship without metadata, none
//!     can leave stale metadata behind;
//!   * each rule's `summary()`/`explanation()` resolve to the declared metadata
//!     (the `Rule` trait defaults read from it), so a rule cannot silently
//!     re-declare drifting copies;
//!   * the README rule table mirrors the metadata summaries.
//!
//! This is the historical failure mode this guards: docs and code drifting.

use std::collections::BTreeMap;

use safe_deps::rules::all_rules;
use safe_deps::rules::meta::ALL_RULE_META;

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

/// `id -> summary` from the declarative metadata registry (the single source).
fn metadata_table() -> BTreeMap<String, String> {
    ALL_RULE_META
        .iter()
        .map(|m| (m.id.to_string(), m.summary.to_string()))
        .collect()
}

#[test]
fn registry_and_metadata_cover_the_same_rule_ids() {
    let metadata_ids: Vec<String> = ALL_RULE_META.iter().map(|m| m.id.to_string()).collect();
    let registry_ids: Vec<String> = all_rules()
        .iter()
        .map(|r| r.id().as_str().to_string())
        .collect();
    assert_eq!(
        registry_ids, metadata_ids,
        "rules::all_rules() and rules::meta::ALL_RULE_META list different (or differently ordered) rule ids"
    );
}

#[test]
fn rule_trait_metadata_resolves_to_the_declarative_source() {
    // The `Rule::summary`/`Rule::explanation` defaults must read from the
    // declarative registry, so list-rules/explain (which derive from metadata)
    // never disagree with a rule's own reported metadata.
    let by_id: BTreeMap<String, &safe_deps::rules::meta::RuleMeta> = ALL_RULE_META
        .iter()
        .map(|m| (m.id.to_string(), m))
        .collect();
    for rule in all_rules() {
        let id = rule.id().as_str().to_string();
        let meta = by_id
            .get(&id)
            .unwrap_or_else(|| panic!("{id} has no entry in ALL_RULE_META"));
        assert_eq!(
            rule.summary(),
            meta.summary,
            "{id} Rule::summary() does not resolve to the declarative metadata"
        );
        assert_eq!(
            rule.explanation(),
            meta.explanation,
            "{id} Rule::explanation() does not resolve to the declarative metadata"
        );
    }
}

#[test]
fn readme_rule_table_matches_the_metadata() {
    let readme = readme_rule_table();
    let metadata = metadata_table();

    // Same set of rule ids: no rule missing from the README, none stale.
    let readme_ids: Vec<&String> = readme.keys().collect();
    let metadata_ids: Vec<&String> = metadata.keys().collect();
    assert_eq!(
        metadata_ids, readme_ids,
        "README rule table and the metadata registry list different rule ids"
    );

    // Summaries are byte-for-byte the metadata's `summary` (README mirrors the
    // single source, which is what `list-rules`/`explain` print).
    for (id, summary) in &metadata {
        assert_eq!(
            readme.get(id),
            Some(summary),
            "README summary for {id} drifted from ALL_RULE_META"
        );
    }
}

#[test]
fn every_rule_has_nonempty_metadata() {
    for meta in ALL_RULE_META {
        let id = meta.id;
        assert!(id.starts_with("SD"), "unexpected rule id: {id}");
        assert!(!meta.summary.trim().is_empty(), "{id} has an empty summary");
        assert!(
            meta.summary.ends_with('.'),
            "{id} summary should be a sentence ending in '.'"
        );
        assert!(
            !meta.explanation.trim().is_empty(),
            "{id} has an empty explanation"
        );
        assert!(
            !meta.ecosystems.is_empty(),
            "{id} declares no applicable ecosystems"
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

    let meta_ids: Vec<&str> = ALL_RULE_META.iter().map(|m| m.id).collect();
    let mut sorted_meta = meta_ids.clone();
    sorted_meta.sort_unstable();
    sorted_meta.dedup();
    assert_eq!(
        meta_ids, sorted_meta,
        "rules::meta::ALL_RULE_META must be unique and id-sorted"
    );
}
