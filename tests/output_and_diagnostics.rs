//! Output-schema and diagnostic regression tests (#68).
//!
//! Pins three things that are easy to break without a guard:
//! 1. the SARIF 2.1.0 and JUnit XML structure consumed by GitHub code scanning
//!    and CI dashboards (a backward-compatibility contract),
//! 2. the `complex-shell-not-fully-parsed` uncertainty diagnostic firing for the
//!    constructs the pragmatic CI tokenizer cannot fully parse, and
//! 3. malformed `pyproject.toml` / `uv.toml` surfacing a parse diagnostic and
//!    escalating under `--strict-parser-errors` rather than being silently
//!    treated as "no config".

use std::process::Output;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

fn workspace(files: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().unwrap();
    for (rel, content) in files {
        let p = dir.path().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }
    dir
}

fn run(dir: &TempDir, args: &[&str]) -> Output {
    Command::cargo_bin("safe-deps")
        .unwrap()
        .current_dir(dir.path())
        .args(args)
        .output()
        .unwrap()
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap()
}

fn check_json(dir: &TempDir) -> Value {
    let out = run(dir, &["check", ".", "--format", "json"]);
    serde_json::from_slice(&out.stdout).expect("check --format json emits JSON")
}

// A small JS project whose insecure `.npmrc` raises SD003 (an error-severity
// finding with a file location) — exercises the report formats end to end.
const NPM_PACKAGE: &str = r#"{"name":"x","version":"1.0.0","dependencies":{"lodash":"4.17.21"}}"#;
const NPM_LOCK: &str = "{}";
const NPMRC_HTTP: &str = "registry=http://registry.example.com/\n";

fn sd003_workspace() -> TempDir {
    workspace(&[
        ("package.json", NPM_PACKAGE),
        ("package-lock.json", NPM_LOCK),
        (".npmrc", NPMRC_HTTP),
    ])
}

// --- SARIF / JUnit schema conformance ----------------------------------------

#[test]
fn sarif_output_conforms_to_2_1_0_structure() {
    let ws = sd003_workspace();
    let out = run(&ws, &["check", ".", "--format", "sarif"]);
    let v: Value = serde_json::from_slice(&out.stdout).expect("SARIF is JSON");

    assert_eq!(v["version"], "2.1.0", "{v}");
    assert!(
        v["$schema"].as_str().unwrap_or("").contains("sarif"),
        "missing/!sarif $schema"
    );
    let run0 = &v["runs"][0];
    assert_eq!(run0["tool"]["driver"]["name"], "safe-deps");

    let rules = run0["tool"]["driver"]["rules"]
        .as_array()
        .expect("driver.rules array");
    assert!(!rules.is_empty(), "driver.rules should not be empty");
    for r in rules {
        assert!(
            r["id"].as_str().unwrap_or("").starts_with("SD"),
            "rule without SD id: {r}"
        );
    }
    let rule_ids: Vec<&str> = rules.iter().filter_map(|r| r["id"].as_str()).collect();

    let results = run0["results"].as_array().expect("results array");
    assert!(
        !results.is_empty(),
        "expected at least the SD003 result: {v}"
    );
    for res in results {
        let id = res["ruleId"].as_str().expect("result ruleId");
        assert!(id.starts_with("SD"), "bad ruleId {id}");
        // Every reported rule must be declared in the tool's rule registry.
        assert!(
            rule_ids.contains(&id),
            "ruleId {id} not declared in driver.rules"
        );
        let level = res["level"].as_str().expect("result level");
        assert!(
            matches!(level, "error" | "warning" | "note" | "none"),
            "invalid SARIF level {level}"
        );
        assert!(res["message"]["text"].is_string(), "result message.text");
        assert!(
            res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].is_string(),
            "result location uri: {res}"
        );
    }
}

#[test]
fn junit_output_is_well_formed_with_a_recorded_issue() {
    let ws = sd003_workspace();
    let out = run(&ws, &["check", ".", "--format", "junit"]);
    let xml = String::from_utf8(out.stdout).expect("JUnit is UTF-8");

    assert!(xml.starts_with("<?xml"), "missing XML prolog: {xml}");
    assert!(xml.contains("<testsuites "), "missing <testsuites>");
    assert!(xml.contains("<testsuite "), "missing <testsuite>");
    assert!(xml.contains("<testcase "), "missing <testcase>");
    // SD003 is error-severity, so it is recorded as <error>; some findings map to
    // <failure>. Either way an issue must be present.
    assert!(
        xml.contains("<error ") || xml.contains("<failure "),
        "no <error>/<failure> recorded: {xml}"
    );
    // Tags are balanced for the container elements.
    assert_eq!(
        xml.matches("<testsuites ").count(),
        xml.matches("</testsuites>").count(),
        "unbalanced <testsuites>"
    );
    assert_eq!(
        xml.matches("<testsuite ").count(),
        xml.matches("</testsuite>").count(),
        "unbalanced <testsuite>"
    );
}

// --- complex-shell uncertainty diagnostic ------------------------------------

fn workflow_with_run(run_block: &str) -> String {
    format!(
        "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n{run_block}"
    )
}

#[test]
fn complex_shell_in_a_package_manager_command_raises_the_diagnostic() {
    // Each command resolves to a package-manager invocation (so the diagnostic is
    // not suppressed as noise) AND uses a construct the tokenizer cannot fully
    // parse. The diagnostic must fire so reduced-confidence CI coverage is shown.
    let cases = [
        (
            "command substitution",
            "      - run: npm ci $(echo --prod)\n",
        ),
        (
            "process substitution",
            "      - run: npm ci <(echo extra)\n",
        ),
        (
            "heredoc",
            "      - run: |\n          npm ci <<EOF\n          extra\n          EOF\n",
        ),
    ];
    for (label, run_block) in cases {
        let ws = workspace(&[(".github/workflows/ci.yml", &workflow_with_run(run_block))]);
        let json = check_json(&ws);
        let diags = json["diagnostics"].as_array().unwrap();
        assert!(
            diags.iter().any(|d| d["message"]
                .as_str()
                .unwrap_or("")
                .contains("complex-shell-not-fully-parsed")),
            "{label}: expected complex-shell-not-fully-parsed diagnostic, got {diags:?}"
        );
    }
}

#[test]
fn ordinary_ci_command_does_not_raise_the_complex_shell_diagnostic() {
    // A plain `npm ci` carries no ambiguous construct — no noise.
    let ws = workspace(&[(
        ".github/workflows/ci.yml",
        &workflow_with_run("      - run: npm ci\n"),
    )]);
    let json = check_json(&ws);
    let diags = json["diagnostics"].as_array().unwrap();
    assert!(
        !diags.iter().any(|d| d["message"]
            .as_str()
            .unwrap_or("")
            .contains("complex-shell")),
        "unexpected complex-shell diagnostic on a plain command: {diags:?}"
    );
}

// --- malformed config is diagnosed, not silently defaulted -------------------

#[test]
fn malformed_pyproject_is_diagnosed_and_escalates_under_strict() {
    let ws = workspace(&[("pyproject.toml", "[project\nname = ")]);

    let json = check_json(&ws);
    assert!(
        json["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["message"]
                .as_str()
                .unwrap_or("")
                .contains("could not parse")),
        "malformed pyproject must surface a parse diagnostic, not silently default: {json}"
    );

    // A parse failure is a warning diagnostic, so a default run is not escalated…
    assert_ne!(code(&run(&ws, &["check", "."])), 4);
    // …but `--strict-parser-errors` turns it into exit code 4.
    assert_eq!(
        code(&run(&ws, &["check", ".", "--strict-parser-errors"])),
        4,
        "malformed pyproject must escalate under --strict-parser-errors"
    );
}

#[test]
fn malformed_uv_toml_is_diagnosed_and_escalates_under_strict() {
    // A valid pyproject makes the project detectable; the broken uv.toml beside it
    // must not be swallowed as "no uv config".
    let ws = workspace(&[
        (
            "pyproject.toml",
            "[project]\nname = \"x\"\nversion = \"0\"\n",
        ),
        ("uv.toml", "[[index\nurl = "),
    ]);
    let json = check_json(&ws);
    assert!(
        json["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["message"].as_str().unwrap_or("").contains("uv.toml")),
        "malformed uv.toml must surface a parse diagnostic: {json}"
    );
    assert_eq!(
        code(&run(&ws, &["check", ".", "--strict-parser-errors"])),
        4,
        "malformed uv.toml must escalate under --strict-parser-errors"
    );
}
