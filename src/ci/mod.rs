//! CI fact extraction.
//!
//! Phase 1 keeps a minimal `CiFacts` so the rule engine and data model are
//! ready for CI-aware rules. GitHub Actions parsing and command extraction
//! arrive in Phase 2, which will populate `CiFacts` and activate SD002, SD008,
//! and SD009 CI-based detection.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CiFacts {
    pub commands: Vec<CiCommand>,
    pub env: Vec<EnvAssignment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiCommand {
    pub file: std::path::PathBuf,
    pub line: u32,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvAssignment {
    pub name: String,
    pub value: String,
}

impl CiFacts {
    pub fn empty() -> Self {
        Self::default()
    }
}
