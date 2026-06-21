//! `safe-deps` static linter for package-management security practices.
//!
//! Phase 1 scope: workspace scanning, config loading, ecosystem detection for
//! npm/Yarn/pnpm/Bun/pip/uv, rules SD001-SD004, and text/JSON output.

pub mod audit;
pub mod check_runner;
pub mod ci;
pub mod cli;
pub mod config;
pub mod diagnostics;
pub mod ecosystems;
pub mod filesystem;
pub(crate) mod path;
pub mod project;
pub mod report;
pub mod rule;
pub mod rules;

pub use diagnostics::Diagnostic;
pub use rule::{Confidence, Finding, Location, RuleId, Severity};
