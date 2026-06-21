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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn warn_has_warning_level_and_no_location() {
        let d = Diagnostic::warn("oops");
        assert_eq!(d.level, DiagnosticLevel::Warning);
        assert_eq!(d.message, "oops");
        assert!(d.location.is_none());
    }

    #[test]
    fn warn_at_carries_location() {
        let d = Diagnostic::warn_at("bad file", PathBuf::from("a/b.toml"));
        assert_eq!(d.level, DiagnosticLevel::Warning);
        assert_eq!(d.message, "bad file");
        assert_eq!(d.location.as_deref(), Some(Path::new("a/b.toml")));
    }

    #[test]
    fn error_has_error_level() {
        let d = Diagnostic::error("fatal");
        assert_eq!(d.level, DiagnosticLevel::Error);
        assert!(d.location.is_none());
    }

    #[test]
    fn level_serializes_lowercase() {
        // Reporters (JSON/SARIF) rely on the lowercase serde rename.
        assert_eq!(
            serde_json::to_string(&DiagnosticLevel::Error).unwrap(),
            "\"error\""
        );
        assert_eq!(
            serde_json::to_string(&DiagnosticLevel::Warning).unwrap(),
            "\"warning\""
        );
        assert_eq!(
            serde_json::to_string(&DiagnosticLevel::Info).unwrap(),
            "\"info\""
        );
    }

    #[test]
    fn diagnostic_round_trips_through_json() {
        let d = Diagnostic::warn_at("m", PathBuf::from("x/y"));
        let s = serde_json::to_string(&d).unwrap();
        let back: Diagnostic = serde_json::from_str(&s).unwrap();
        assert_eq!(back.level, d.level);
        assert_eq!(back.message, d.message);
        assert_eq!(back.location, d.location);
    }
}
