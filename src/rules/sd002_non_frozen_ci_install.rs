//! SD002: Non-frozen CI install.
//!
//! Flags resolving install commands in CI (e.g. `npm install`, `yarn install`
//! without `--immutable`, `pnpm install` without `--frozen-lockfile`,
//! `bun install` without `--frozen-lockfile`, `uv sync` without `--locked`).
//!
//! Phase 1 keeps the rule registered and documented so `list-rules` and
//! `explain` surface it. CI command extraction arrives in Phase 2, which will
//! populate `CiFacts` and activate this rule's findings.

use crate::rule::{Finding, Rule, RuleId, RuleInput};

pub struct Sd002;

impl Rule for Sd002 {
    fn id(&self) -> RuleId {
        RuleId::new("SD002")
    }

    fn summary(&self) -> &'static str {
        "CI installs should use a frozen/locked command, not a resolving one."
    }

    fn explanation(&self) -> &'static str {
        "CI should fail when the manifest and lockfile disagree. Use npm ci, \
yarn install --immutable, pnpm install --frozen-lockfile, \
bun install --frozen-lockfile (or bun ci), uv sync --locked, and \
pip install --require-hashes for deployment requirements. This rule is \
activated once CI command facts are available (Phase 2)."
    }

    fn evaluate(&self, _input: &RuleInput) -> Vec<Finding> {
        // CI command analysis is implemented in Phase 2 alongside the GitHub
        // Actions parser. No static config equivalent exists for Phase 1.
        Vec::new()
    }
}
