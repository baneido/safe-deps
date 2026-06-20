//! Linter-side diagnostics, separate from rule findings.
//!
//! Findings represent policy issues in the target project. Diagnostics
//! represent limitations or failures of the linter run itself, such as
//! unreadable files or parse failures.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticLevel {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub level: DiagnosticLevel,
    pub message: String,
    pub location: Option<PathBuf>,
}

impl Diagnostic {
    pub fn warn(message: impl Into<String>) -> Self {
        Self {
            level: DiagnosticLevel::Warning,
            message: message.into(),
            location: None,
        }
    }

    pub fn warn_at(message: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            level: DiagnosticLevel::Warning,
            message: message.into(),
            location: Some(path.into()),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            level: DiagnosticLevel::Error,
            message: message.into(),
            location: None,
        }
    }
}
