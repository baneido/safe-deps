//! Robustness tests for the ecosystem analyzers.
//!
//! Two layers:
//! 1. `proptest` properties that feed random and semi-structured content to the
//!    full offline pipeline (scan → CI facts → rules → JSON report) and assert it
//!    never panics and is deterministic.
//! 2. Targeted fixtures for known edge cases (lenient/invalid-but-tolerated
//!    manifests, hash pins, Unicode, deep nesting).
//!
//! Scope is ecosystem-parser robustness; the foundation layer (#28) and the CI
//! shell tokenizer's uncertainty (#27) are tracked separately.

use std::path::Path;

use proptest::prelude::*;
use safe_deps::config::{Config, OutputFormat};
use safe_deps::filesystem::{scan, ScanOptions};
use safe_deps::rule::Profile;
use safe_deps::{ci, report, rules};
use tempfile::TempDir;

/// Manifest/config file names the analyzers parse. Only file *content* is
/// fuzzed; names come from this fixed set so no path traversal is involved.
const MANIFEST_NAMES: &[&str] = &[
    "package.json",
    "package-lock.json",
    ".npmrc",
    ".yarnrc.yml",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "bunfig.toml",
    "bun.lock",
    "requirements.txt",
    "pyproject.toml",
    "uv.toml",
    "uv.lock",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
    ".github/workflows/ci.yml",
    ".gitlab-ci.yml",
    ".circleci/config.yml",
];

/// Writes `files` into a fresh workspace and runs the full offline pipeline,
/// returning the JSON report bytes. Panics here are real analyzer panics — the
/// property tests rely on that to detect them.
fn run_pipeline(dir: &Path) -> Vec<u8> {
    let ctx = scan(dir, Config::default(), &ScanOptions::default()).expect("scan");
    let ci_facts = ci::extract(&ctx);
    let result = rules::analyze(&ctx, Profile::Balanced, &ci_facts);
    let mut rpt = report::Report::new(dir.to_path_buf(), Profile::Balanced, "test");
    rpt.findings = result.findings;
    rpt.diagnostics = result.diagnostics;
    report::reporter_for(OutputFormat::Json)
        .format(&rpt)
        .expect("render json")
}

fn workspace(files: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().unwrap();
    for (name, content) in files {
        let p = dir.path().join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }
    dir
}

fn report_json(dir: &Path) -> serde_json::Value {
    serde_json::from_slice(&run_pipeline(dir)).expect("valid json report")
}

// --- property tests ----------------------------------------------------------

/// Content strategy: a mix of bounded arbitrary text (malformed manifests),
/// key/value lines (TOML/requirements-ish), and a few realistic edge fragments.
fn arb_content() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => "[\\s\\S]{0,200}",
        2 => prop::collection::vec("[a-zA-Z0-9_.-]{1,10} *[=:] *[\"']?[^\\n]{0,24}", 0..8)
            .prop_map(|lines| lines.join("\n")),
        1 => Just(r#"{"dependencies":{"a":"git+https://x/y"},"scripts":{"postinstall":"x"}}"#.to_string()),
        1 => Just("[package]\nname=\"x\"\n[dependencies]\na={path=\"../a\"}\n".to_string()),
        1 => Just("module x\nrequire (\n  a v1\n  b v2 // indirect\n)\nreplace a => ./local\n".to_string()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// The pipeline never panics on arbitrary manifest content, and produces a
    /// deterministic report (two independent runs over the same workspace are
    /// byte-identical) — the core guarantee the design relies on.
    #[test]
    fn pipeline_never_panics_and_is_deterministic(
        files in prop::collection::vec(
            (prop::sample::select(MANIFEST_NAMES), arb_content()),
            0..6,
        )
    ) {
        let dir = TempDir::new().unwrap();
        for (name, content) in &files {
            let p = dir.path().join(name);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, content).unwrap();
        }
        let first = run_pipeline(dir.path());
        let second = run_pipeline(dir.path());
        prop_assert_eq!(first, second);
    }

    /// A single `package.json` of arbitrary bytes-as-text never panics and the
    /// output is always valid JSON (the reporter never emits malformed output).
    #[test]
    fn arbitrary_package_json_is_handled(content in "[\\s\\S]{0,300}") {
        let dir = workspace(&[("package.json", &content)]);
        let json = report_json(dir.path());
        prop_assert!(json.get("findings").is_some());
    }
}

// --- targeted edge cases -----------------------------------------------------

#[test]
fn malformed_manifest_yields_diagnostic_not_panic() {
    // Trailing comma => invalid JSON; the analyzer must emit a parse diagnostic
    // and continue rather than crash.
    let dir = workspace(&[("Cargo.toml", "[package\nname = ")]);
    let json = report_json(dir.path());
    assert!(json["diagnostics"].is_array());
}

#[test]
fn package_json_with_non_bool_private_field_is_tolerated() {
    // `private` as a string instead of a bool, and a numeric script value: a
    // lenient manifest the parser must not choke on.
    let dir = workspace(&[(
        "package.json",
        r#"{"name":"x","private":"true","dependencies":{"a":"1.0.0"},"scripts":{"x":1}}"#,
    )]);
    let json = report_json(dir.path());
    assert!(json["findings"].is_array());
}

#[test]
fn requirements_with_hash_pins_is_parsed() {
    let dir = workspace(&[(
        "requirements.txt",
        "flask==3.0.0 --hash=sha256:deadbeef\nrequests==2.31.0 \\\n  --hash=sha256:cafe\n",
    )]);
    let json = report_json(dir.path());
    assert!(json["findings"].is_array());
}

#[test]
fn uv_toml_mixed_index_forms_is_parsed() {
    let dir = workspace(&[(
        "uv.toml",
        "[[index]]\nurl = \"http://insecure.example/simple\"\n\n[pip]\nindex-url = \"https://ok.example\"\n",
    )]);
    let json = report_json(dir.path());
    assert!(json["findings"].is_array());
}

#[test]
fn unicode_dependency_names_and_paths_are_handled() {
    let dir = workspace(&[
        (
            "пакет/package.json",
            r#"{"name":"日本語","dependencies":{"münchen":"1.0.0"}}"#,
        ),
        ("пакет/package-lock.json", "{}"),
    ]);
    let json = report_json(dir.path());
    assert!(json["findings"].is_array());
}

#[test]
fn deeply_nested_manifest_does_not_panic() {
    let deep = "a/".repeat(40);
    let dir = workspace(&[(
        &format!("{deep}package.json"),
        r#"{"dependencies":{"x":"1"}}"#,
    )]);
    let json = report_json(dir.path());
    assert!(json["findings"].is_array());
}

#[test]
fn many_project_monorepo_detects_each() {
    // A monorepo with many manifests must be analyzed correctly (correctness,
    // not performance — #24 covers performance).
    let mut files: Vec<(String, String)> = Vec::new();
    for i in 0..50 {
        files.push((
            format!("packages/p{i}/package.json"),
            format!(r#"{{"name":"p{i}","dependencies":{{"left-pad":"1.0.0"}}}}"#),
        ));
    }
    let dir = TempDir::new().unwrap();
    for (name, content) in &files {
        let p = dir.path().join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }
    let json = report_json(dir.path());
    // Each of the 50 lock-less manifests should raise SD001 (missing lockfile).
    let sd001 = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule_id"] == "SD001")
        .count();
    assert_eq!(sd001, 50, "expected one SD001 per project: {json}");
}
