//! Declarative rule metadata — the single source for everything *about* a rule
//! that is not its `evaluate` logic (#66).
//!
//! Summary, explanation, default severity, applicable ecosystems, and the SARIF
//! help URI used to live in three different places (each `Rule` impl, the SARIF
//! reporter, and the README table) and drifted. They are now declared once here.
//! `Rule::summary`/`Rule::explanation` default-read from this table by id, and
//! `list-rules` / `explain` / the SARIF rule registry all derive from it. The
//! `tests/rule_metadata.rs` guard keeps the README table in sync with this
//! source.
//!
//! `evaluate` is intentionally *not* described here: severity is frequently a
//! function of `Profile`/`ProjectKind` (see `sd001_severity`), so `default_severity`
//! is the documented baseline used for `explain`/SARIF descriptors, not a value
//! the engine enforces.

use crate::ecosystems::Ecosystem;
use crate::rule::Severity;

/// Help URI attached to every SARIF rule descriptor; points at the rule
/// taxonomy in the design docs.
pub const HELP_URI: &str =
    "https://github.com/baneido/safe-deps/blob/main/docs/design/safe-deps-cli-design.md";

/// Static, declarative description of a rule. Carries everything documentation
/// and reporting need; the behavior stays in the rule's `evaluate`.
#[derive(Debug, Clone, Copy)]
pub struct RuleMeta {
    /// Canonical id, e.g. `SD001`.
    pub id: &'static str,
    /// One-line summary used by `explain`, `list-rules`, the README table, and
    /// the SARIF short description. Must end in `.`.
    pub summary: &'static str,
    /// Longer rationale used by `explain` and the SARIF full description.
    pub explanation: &'static str,
    /// Documented baseline severity for the rule. The engine may raise or lower
    /// this per `Profile`/`ProjectKind`; this is the value `explain` reports.
    pub default_severity: Severity,
    /// Ecosystems the rule can fire for today.
    pub ecosystems: &'static [Ecosystem],
    /// Whether the rule is derived from CI command facts (only fires when a
    /// supported CI configuration is present).
    pub ci_derived: bool,
}

use Ecosystem::{Go, JavaScript, Python, Rust};

/// The canonical, id-sorted rule metadata registry — the single source of
/// truth. Keep this in sync with `rules::all_rules()` (one entry per rule); the
/// `tests/rule_metadata.rs` guard enforces it.
pub const ALL_RULE_META: &[RuleMeta] = &[
    RuleMeta {
        id: "SD001",
        summary: "Lockfile missing for a manifest that declares dependencies.",
        explanation: "Committing a lockfile makes dependency resolution reproducible and \
reviewable. npm expects package-lock.json (or npm-shrinkwrap.json), Yarn \
expects yarn.lock, pnpm expects pnpm-lock.yaml, Bun 1.2+ expects bun.lock, \
and uv expects uv.lock. pip has no conventional lockfile and is assessed via \
--require-hashes (SD004) instead. In workspaces, a root-level lockfile \
covers member packages.",
        default_severity: Severity::Warning,
        ecosystems: &[JavaScript, Python, Rust, Go],
        ci_derived: false,
    },
    RuleMeta {
        id: "SD002",
        summary: "CI installs should use a frozen/locked command, not a resolving one.",
        explanation: "CI should fail when the manifest and lockfile disagree. Use npm ci, \
yarn install --immutable, pnpm install --frozen-lockfile, \
bun install --frozen-lockfile (or bun ci), uv sync --locked, \
pip install --require-hashes for deployment requirements, cargo build/test \
--locked, and Go's default -mod=readonly (avoid -mod=mod). This rule reads CI \
command facts extracted from GitHub Actions, GitLab CI, and CircleCI \
configurations.",
        default_severity: Severity::Error,
        ecosystems: &[JavaScript, Python, Rust, Go],
        ci_derived: true,
    },
    RuleMeta {
        id: "SD003",
        summary: "Registry or index uses HTTP or TLS verification is disabled.",
        explanation: "Use HTTPS registries and keep TLS verification enabled. Flagged \
signals include npm/pnpm strict-ssl=false and http:// registries, Yarn \
unsafeHttpWhitelist, pip --trusted-host and HTTP indexes, and uv \
allow-insecure-host. Local test exceptions should be scoped narrowly.",
        default_severity: Severity::Error,
        ecosystems: &[JavaScript, Python],
        ci_derived: false,
    },
    RuleMeta {
        id: "SD004",
        summary: "Integrity or checksum validation is disabled.",
        explanation: "Lockfile hashes and checksums should not be disabled or silently \
regenerated. Flagged signals include npm package-lock=false, Yarn Berry \
checksumBehavior: ignore (with update treated as suspicious), and pip \
deployment requirements that lack --require-hashes.",
        default_severity: Severity::Error,
        ecosystems: &[JavaScript, Python],
        ci_derived: false,
    },
    RuleMeta {
        id: "SD005",
        summary: "Dependency build/lifecycle scripts are broadly enabled.",
        explanation: "Running build or postinstall scripts for every dependency lets any \
package in the tree execute code at install time. pnpm's \
dangerouslyAllowAllBuilds and a Bun trustedDependencies wildcard remove the \
build allowlist that normally contains this. Prefer an explicit allowlist \
(pnpm onlyBuiltDependencies, named Bun trustedDependencies) scoped to the few \
packages that genuinely need a build step.",
        default_severity: Severity::Warning,
        ecosystems: &[JavaScript],
        ci_derived: false,
    },
    RuleMeta {
        id: "SD006",
        summary: "Dependency resolves from an unsafe source (floating git, tarball, path).",
        explanation: "Dependencies pulled from a moving Git ref, an SSH VCS URL, a direct \
tarball, or a local filesystem path are not reproducible or integrity-checked \
the way registry releases are. A Cargo [source] replace-with redirect to a remote \
registry/git source reroutes the whole crate graph; Go CI that globally disables \
the checksum database (GOSUMDB=off, or GONOSUMCHECK/GONOSUMDB set to the wildcard \
'*') installs modules without integrity checks. Pin Git dependencies to a commit, \
publish internal packages to a registry, keep local path dependencies out of \
production groups, review remote source redirects, and leave Go's checksum \
database enabled. Declare [policy] allow_git_dependencies or \
allow_local_path_dependencies to accept a deliberate choice.",
        default_severity: Severity::Warning,
        ecosystems: &[JavaScript, Python, Rust, Go],
        ci_derived: false,
    },
    RuleMeta {
        id: "SD007",
        summary: "Index/source config exposes the project to dependency confusion.",
        explanation: "An extra package index or a cross-index resolution strategy lets a \
public package shadow an internal one of the same name (dependency confusion). \
Prefer a single trusted index, or pin internal packages to a dedicated index \
with explicit ownership. uv's index-strategy = unsafe-best-match resolves the \
best version across all configured indexes and should be avoided. This rule is \
an error under the strict profile and a warning otherwise.",
        default_severity: Severity::Warning,
        ecosystems: &[Python],
        ci_derived: false,
    },
    RuleMeta {
        id: "SD008",
        summary: "CI installs dependencies but no audit command is visible.",
        explanation: "When CI installs dependencies, a dependency audit step gives a path to \
catch known-vulnerable packages. Use npm/yarn/pnpm/bun audit or pip-audit/safety. \
If audits run in a separate workflow, a SaaS scanner, or an organization-wide \
schedule, declare [policy] external_audit = true to acknowledge that control. \
This rule reads CI command facts extracted from GitHub Actions, GitLab CI, and \
CircleCI configurations.",
        default_severity: Severity::Warning,
        ecosystems: &[JavaScript, Python],
        ci_derived: true,
    },
    RuleMeta {
        id: "SD009",
        summary: "CI install commands use a flag that bypasses dependency safety checks.",
        explanation: "Flags such as --force, --legacy-peer-deps, --no-lockfile, \
--ignore-platform-reqs, --break-system-packages, and --no-build-isolation \
suppress resolution, lockfile, or environment checks. They turn an enforced \
install into a best-effort one and can mask supply-chain or compatibility \
problems. Remove them or scope them to a documented exception.",
        default_severity: Severity::Warning,
        ecosystems: &[JavaScript, Python],
        ci_derived: true,
    },
];

/// Looks up the declarative metadata for a rule id. Returns `None` for an
/// unknown id. `ALL_RULE_META` is guaranteed id-sorted (enforced by
/// `metadata_is_id_sorted_and_unique` and `tests/rule_metadata.rs`), so this is
/// a binary search.
pub fn meta_for(id: &str) -> Option<&'static RuleMeta> {
    ALL_RULE_META
        .binary_search_by(|m| m.id.cmp(id))
        .ok()
        .map(|i| &ALL_RULE_META[i])
}

/// The metadata declared for `id`. Panics on an unknown id: the `Rule::summary`/
/// `Rule::explanation` defaults read through here, so a registered rule lacking
/// a metadata entry — or an external `Rule` impl that forgot to override — is a
/// programmer error we surface loudly rather than emitting blank CLI/SARIF text.
/// Every registered rule has an entry (enforced by `tests/rule_metadata.rs`), so
/// this never panics at runtime for a real rule.
fn require_meta(id: &str) -> &'static RuleMeta {
    meta_for(id).unwrap_or_else(|| {
        panic!(
            "no rule metadata registered for id `{id}`; add an entry to rules::meta::ALL_RULE_META"
        )
    })
}

/// The summary declared for `id`. Panics on an unknown id (see `require_meta`).
/// Used by the `Rule::summary` default so each rule's metadata is read from the
/// single source rather than re-declared in the impl.
pub fn summary_for(id: &str) -> &'static str {
    require_meta(id).summary
}

/// The explanation declared for `id`. Panics on an unknown id (see
/// `require_meta`).
pub fn explanation_for(id: &str) -> &'static str {
    require_meta(id).explanation
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_is_id_sorted_and_unique() {
        let mut sorted: Vec<&str> = ALL_RULE_META.iter().map(|m| m.id).collect();
        let original = sorted.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            original, sorted,
            "ALL_RULE_META must be unique and id-sorted"
        );
    }

    #[test]
    fn lookup_finds_known_rule_and_rejects_unknown() {
        assert_eq!(
            summary_for("SD001"),
            "Lockfile missing for a manifest that declares dependencies."
        );
        assert!(meta_for("SD999").is_none());
    }

    #[test]
    #[should_panic(expected = "no rule metadata registered for id `SD999`")]
    fn summary_for_unknown_id_panics() {
        let _ = summary_for("SD999");
    }

    #[test]
    #[should_panic(expected = "no rule metadata registered for id `SD999`")]
    fn explanation_for_unknown_id_panics() {
        let _ = explanation_for("SD999");
    }

    #[test]
    fn every_meta_summary_is_a_sentence() {
        for m in ALL_RULE_META {
            assert!(m.id.starts_with("SD"), "unexpected id {}", m.id);
            assert!(!m.summary.trim().is_empty(), "{} empty summary", m.id);
            assert!(m.summary.ends_with('.'), "{} summary must end in '.'", m.id);
            assert!(
                !m.explanation.trim().is_empty(),
                "{} empty explanation",
                m.id
            );
            assert!(!m.ecosystems.is_empty(), "{} has no ecosystems", m.id);
        }
    }
}
