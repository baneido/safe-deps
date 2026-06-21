//! CLI integration tests for `safe-deps check` and friends.
//!
//! Each test builds a throwaway workspace in a tempdir, runs the binary with
//! its working directory set to that workspace (so config discovery and output
//! paths are deterministic and relative), and asserts on output and exit code.

use std::path::Path;
use std::process::Output;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

/// Builds a workspace from `(relative path, contents)` pairs.
fn workspace(files: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new().unwrap();
    for (rel, contents) in files {
        write(dir.path(), rel, contents);
    }
    dir
}

fn write(root: &Path, rel: &str, contents: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

fn bin() -> Command {
    Command::cargo_bin("safe-deps").unwrap()
}

/// Runs `safe-deps` in `dir` with `args` and returns the raw output.
fn run(dir: &TempDir, args: &[&str]) -> Output {
    bin().current_dir(dir.path()).args(args).output().unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap()
}

/// Runs `check . --format json` and parses the report.
fn check_json(dir: &TempDir, extra: &[&str]) -> Value {
    let mut args = vec!["check", ".", "--format", "json"];
    args.extend_from_slice(extra);
    let out = run(dir, &args);
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("invalid JSON: {e}\n{}", stdout(&out)))
}

fn rule_ids(report: &Value) -> Vec<String> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap().to_string())
        .collect()
}

const NPM_DEPS: &str = r#"{ "name": "demo", "dependencies": { "left-pad": "^1.3.0" } }"#;

// --- text output and exit codes ----------------------------------------------

#[test]
fn npm_unsafe_text_output_reports_findings() {
    let ws = workspace(&[
        ("package.json", NPM_DEPS),
        (
            ".npmrc",
            "strict-ssl=false\nregistry=http://registry.example.com/\n",
        ),
    ]);
    let out = run(&ws, &["check", "."]);
    let text = stdout(&out);
    assert!(text.contains("SD001"), "missing SD001:\n{text}");
    assert!(text.contains("SD003"), "missing SD003:\n{text}");
    assert!(text.contains("strict-ssl=false"));
    assert!(text.contains("remediation:"));
    assert_eq!(code(&out), 1, "errors present should fail by default");
}

#[test]
fn safe_project_has_no_findings_and_exit_zero() {
    let ws = workspace(&[
        ("package.json", NPM_DEPS),
        ("package-lock.json", r#"{ "lockfileVersion": 3 }"#),
    ]);
    let out = run(&ws, &["check", "."]);
    assert!(stdout(&out).contains("No findings."));
    assert_eq!(code(&out), 0);
}

#[test]
fn root_level_project_is_detected() {
    // Regression: a project at the workspace root (dir == ".") must still have
    // its manifest, config, and lockfile resolved.
    let ws = workspace(&[("package.json", NPM_DEPS), (".npmrc", "strict-ssl=false\n")]);
    let report = check_json(&ws, &[]);
    let ids = rule_ids(&report);
    assert!(ids.contains(&"SD001".to_string()), "ids: {ids:?}");
    assert!(ids.contains(&"SD003".to_string()), "ids: {ids:?}");
    // Location points at the real config file, not the project root fallback.
    let sd003 = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == "SD003")
        .unwrap();
    assert_eq!(sd003["location"]["file"], ".npmrc");
}

// --- JSON schema -------------------------------------------------------------

#[test]
fn json_report_has_stable_schema() {
    let ws = workspace(&[("package.json", NPM_DEPS), (".npmrc", "strict-ssl=false\n")]);
    let report = check_json(&ws, &[]);
    assert_eq!(report["schema_version"], "1");
    assert_eq!(report["tool"]["name"], "safe-deps");
    assert!(report["tool"]["version"].is_string());
    assert_eq!(report["profile"], "balanced");
    assert!(report["summary"]["total"].as_u64().unwrap() >= 2);
    assert!(report["summary"]["errors"].as_u64().unwrap() >= 1);

    let first = &report["findings"][0];
    for key in [
        "rule_id",
        "severity",
        "confidence",
        "message",
        "project_root",
        "ecosystem",
    ] {
        assert!(first.get(key).is_some(), "missing key {key}");
    }
}

// --- fail-on threshold -------------------------------------------------------

#[test]
fn fail_on_none_exits_zero_despite_errors() {
    let ws = workspace(&[("package.json", NPM_DEPS), (".npmrc", "strict-ssl=false\n")]);
    let out = run(&ws, &["check", ".", "--fail-on", "none"]);
    assert_eq!(code(&out), 0);
}

#[test]
fn fail_on_warning_fails_on_warning() {
    // Only SD001 (warning) present; default fail-on=error would pass.
    let ws = workspace(&[("package.json", NPM_DEPS)]);
    let pass = run(&ws, &["check", "."]);
    assert_eq!(
        code(&pass),
        0,
        "warning alone should pass with fail-on=error"
    );
    let fail = run(&ws, &["check", ".", "--fail-on", "warning"]);
    assert_eq!(code(&fail), 1);
}

// --- filters -----------------------------------------------------------------

#[test]
fn rule_filter_restricts_to_one_rule() {
    let ws = workspace(&[("package.json", NPM_DEPS), (".npmrc", "strict-ssl=false\n")]);
    let report = check_json(&ws, &["--rule", "SD003"]);
    let ids = rule_ids(&report);
    assert!(!ids.is_empty());
    assert!(ids.iter().all(|id| id == "SD003"), "ids: {ids:?}");
}

#[test]
fn ecosystem_filter_restricts_to_one_manager() {
    let ws = workspace(&[
        ("js/package.json", NPM_DEPS),
        (
            "py/requirements.txt",
            "--trusted-host pypi.internal\nrequests==2.31.0\n",
        ),
    ]);
    let report = check_json(&ws, &["--ecosystem", "pip"]);
    let findings = report["findings"].as_array().unwrap();
    assert!(!findings.is_empty());
    assert!(findings.iter().all(|f| f["package_manager"] == "pip"));
}

// --- explain / list-rules / init ---------------------------------------------

#[test]
fn explain_outputs_rule_details() {
    let ws = workspace(&[]);
    let out = run(&ws, &["explain", "SD003"]);
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).contains("SD003"));
}

#[test]
fn explain_normalizes_short_ids() {
    let ws = workspace(&[]);
    let out = run(&ws, &["explain", "sd3"]);
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).starts_with("SD003"));
}

#[test]
fn explain_unknown_rule_is_usage_error() {
    let ws = workspace(&[]);
    let out = run(&ws, &["explain", "SD999"]);
    assert_eq!(code(&out), 2);
}

#[test]
fn list_rules_lists_sd001_through_sd004() {
    let ws = workspace(&[]);
    let out = run(&ws, &["list-rules"]);
    let text = stdout(&out);
    for id in ["SD001", "SD002", "SD003", "SD004"] {
        assert!(text.contains(id), "missing {id}:\n{text}");
    }
}

#[test]
fn init_writes_config_and_refuses_overwrite() {
    let ws = workspace(&[]);
    let first = run(&ws, &["init"]);
    assert_eq!(code(&first), 0);
    assert!(ws.path().join("safe-deps.toml").is_file());
    let second = run(&ws, &["init"]);
    assert_eq!(code(&second), 2, "second init should refuse to overwrite");
}

#[test]
fn no_subcommand_defaults_to_check() {
    let ws = workspace(&[("package.json", NPM_DEPS), (".npmrc", "strict-ssl=false\n")]);
    let out = bin().current_dir(ws.path()).output().unwrap();
    assert_eq!(code(&out), 1);
    assert!(stdout(&out).contains("SD003"));
}

#[test]
fn version_flag_prints_version() {
    let ws = workspace(&[]);
    let out = run(&ws, &["--version"]);
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).contains("safe-deps"));
}

// --- config file behavior ----------------------------------------------------

#[test]
fn config_file_fail_on_none_overrides_default() {
    let ws = workspace(&[
        ("package.json", NPM_DEPS),
        (".npmrc", "strict-ssl=false\n"),
        ("safe-deps.toml", "fail_on = \"none\"\n"),
    ]);
    let out = run(&ws, &["check", "."]);
    assert_eq!(code(&out), 0, "config fail_on=none should not fail");
}

#[test]
fn config_rule_level_override_downgrades_severity() {
    let ws = workspace(&[
        ("package.json", NPM_DEPS),
        (".npmrc", "strict-ssl=false\n"),
        ("safe-deps.toml", "[rules.SD003]\nlevel = \"warning\"\n"),
    ]);
    let report = check_json(&ws, &[]);
    let sd003 = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == "SD003")
        .unwrap();
    assert_eq!(sd003["severity"], "warning");
}

#[test]
fn cli_profile_overrides_config_profile() {
    // pip without --require-hashes: SD004 is info in balanced, warning in strict.
    let files = &[("requirements.txt", "requests==2.31.0\n")];
    let ws = workspace(files);
    let balanced = check_json(&ws, &[]);
    let sd004_balanced = balanced["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == "SD004")
        .expect("SD004 expected in balanced");
    assert_eq!(sd004_balanced["severity"], "info");

    let strict = check_json(&ws, &["--profile", "strict"]);
    let sd004_strict = strict["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == "SD004")
        .expect("SD004 expected in strict");
    assert_eq!(sd004_strict["severity"], "warning");
}

#[test]
fn env_var_sets_profile() {
    let ws = workspace(&[("requirements.txt", "requests==2.31.0\n")]);
    let out = bin()
        .current_dir(ws.path())
        .env("SAFE_DEPS_PROFILE", "permissive")
        .args(["check", ".", "--format", "json"])
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["profile"], "permissive");
    // Permissive drops the pip require-hashes finding entirely.
    assert!(rule_ids(&report).iter().all(|id| id != "SD004"));
}

#[test]
fn invalid_config_is_usage_error() {
    let ws = workspace(&[
        ("package.json", NPM_DEPS),
        // Suppression without a reason is a configuration error.
        (
            "safe-deps.toml",
            "[[suppressions]]\nrule = \"SD001\"\npath = \"package.json\"\n",
        ),
    ]);
    let out = run(&ws, &["check", "."]);
    assert_eq!(code(&out), 2);
}

// --- suppressions ------------------------------------------------------------

#[test]
fn suppression_removes_matching_finding() {
    let config = "[[suppressions]]\nrule = \"SD001\"\npath = \"package.json\"\nreason = \"tracked in backlog\"\n";
    let ws = workspace(&[("package.json", NPM_DEPS), ("safe-deps.toml", config)]);
    let report = check_json(&ws, &[]);
    assert!(!rule_ids(&report).contains(&"SD001".to_string()));
}

#[test]
fn expired_suppression_reports_and_keeps_finding() {
    let config = "[[suppressions]]\nrule = \"SD001\"\npath = \"package.json\"\nreason = \"temporary\"\nexpires = \"2000-01-01\"\n";
    let ws = workspace(&[("package.json", NPM_DEPS), ("safe-deps.toml", config)]);
    let report = check_json(&ws, &[]);
    // Finding is retained because the suppression has expired.
    assert!(rule_ids(&report).contains(&"SD001".to_string()));
    let diags = report["diagnostics"].as_array().unwrap();
    assert!(diags
        .iter()
        .any(|d| d["message"].as_str().unwrap().contains("expired")));
    // It must not be double-reported as an unused suppression.
    assert!(!diags.iter().any(|d| d["message"]
        .as_str()
        .unwrap()
        .contains("unused suppression")));
}

// --- ecosystem fixtures ------------------------------------------------------

#[test]
fn yarn_berry_checksum_ignore_is_error() {
    let ws = workspace(&[
        (
            "package.json",
            r#"{ "name": "y", "packageManager": "yarn@4.1.0", "dependencies": { "lodash": "^4" } }"#,
        ),
        ("yarn.lock", "__metadata:\n  version: 8\n"),
        (".yarnrc.yml", "checksumBehavior: ignore\n"),
    ]);
    let report = check_json(&ws, &[]);
    let sd004 = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == "SD004")
        .expect("SD004 expected");
    assert_eq!(sd004["severity"], "error");
    assert_eq!(sd004["package_manager"], "yarn");
}

#[test]
fn uv_allow_insecure_host_is_flagged() {
    let ws = workspace(&[
        ("pyproject.toml", "[project]\nname = \"d\"\ndependencies = [\"requests\"]\n[tool.uv]\nallow-insecure-host = [\"internal.example\"]\n"),
        ("uv.lock", "version = 1\n"),
    ]);
    let report = check_json(&ws, &[]);
    let ids = rule_ids(&report);
    assert!(ids.contains(&"SD003".to_string()), "ids: {ids:?}");
    let sd003 = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == "SD003")
        .unwrap();
    assert_eq!(sd003["package_manager"], "uv");
}

#[test]
fn bun_legacy_lockb_is_migration_info() {
    let ws = workspace(&[
        (
            "package.json",
            r#"{ "name": "b", "packageManager": "bun@1.1.0", "dependencies": { "left-pad": "^1" } }"#,
        ),
        ("bun.lockb", "binary-lockfile-placeholder"),
    ]);
    let report = check_json(&ws, &[]);
    let sd001 = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == "SD001")
        .expect("SD001 expected");
    assert_eq!(sd001["severity"], "info");
    assert!(sd001["message"].as_str().unwrap().contains("bun.lockb"));
}

#[test]
fn pip_trusted_host_is_error() {
    let ws = workspace(&[(
        "requirements.txt",
        "--trusted-host pypi.internal\nrequests==2.31.0\n",
    )]);
    let report = check_json(&ws, &[]);
    let sd003 = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == "SD003")
        .expect("SD003 expected");
    assert_eq!(sd003["severity"], "error");
    assert_eq!(sd003["package_manager"], "pip");
}

// --- monorepo ----------------------------------------------------------------

#[test]
fn monorepo_member_covered_by_root_lockfile() {
    let ws = workspace(&[
        (
            "package.json",
            r#"{ "name": "root", "private": true, "workspaces": ["packages/*"], "packageManager": "pnpm@9" }"#,
        ),
        ("pnpm-workspace.yaml", "packages:\n  - \"packages/*\"\n"),
        ("pnpm-lock.yaml", "lockfileVersion: 9\n"),
        (
            "packages/a/package.json",
            r#"{ "name": "a", "dependencies": { "left-pad": "^1" } }"#,
        ),
    ]);
    let report = check_json(&ws, &[]);
    // Member has no own lockfile but the root workspace lockfile covers it.
    assert!(
        !rule_ids(&report).contains(&"SD001".to_string()),
        "unexpected SD001: {:?}",
        rule_ids(&report)
    );
}

// --- diagnostics / partial progress ------------------------------------------

#[test]
fn malformed_manifest_emits_diagnostic_and_continues() {
    let ws = workspace(&[("package.json", "{ \"name\": \"broken\", ")]);
    let report = check_json(&ws, &[]);
    let diags = report["diagnostics"].as_array().unwrap();
    assert!(
        diags
            .iter()
            .any(|d| d["message"].as_str().unwrap().contains("parse")),
        "diags: {diags:?}"
    );
    // Default run still exits 0 (partial progress, no findings).
    let out = run(&ws, &["check", "."]);
    assert_eq!(code(&out), 0);
}

#[test]
fn strict_parser_errors_exit_code_four() {
    let ws = workspace(&[("package.json", "{ \"name\": \"broken\", ")]);
    let out = run(&ws, &["check", ".", "--strict-parser-errors"]);
    assert_eq!(code(&out), 4);
}

#[test]
fn missing_path_is_usage_or_internal_error() {
    let ws = workspace(&[]);
    let out = run(&ws, &["check", "does-not-exist"]);
    assert_ne!(code(&out), 0);
}

// --- review regressions ------------------------------------------------------

#[test]
fn package_manager_field_drives_detection_without_lockfile() {
    // Only the camelCase `packageManager` field identifies the manager; SD001
    // must name yarn.lock, not package-lock.json.
    let ws = workspace(&[(
        "package.json",
        r#"{ "name": "a", "packageManager": "yarn@4.1.0", "dependencies": { "lodash": "^4" } }"#,
    )]);
    let report = check_json(&ws, &[]);
    let sd001 = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == "SD001")
        .expect("SD001 expected");
    assert_eq!(sd001["package_manager"], "yarn");
    assert!(sd001["message"].as_str().unwrap().contains("yarn.lock"));
}

#[test]
fn pip_equals_joined_insecure_index_is_flagged() {
    let ws = workspace(&[(
        "requirements.txt",
        "--index-url=http://pypi.internal/simple\nrequests==2.31.0\n",
    )]);
    let report = check_json(&ws, &[]);
    assert!(rule_ids(&report).contains(&"SD003".to_string()));
}

#[test]
fn rule_filter_normalizes_short_and_lowercase_ids() {
    let ws = workspace(&[("package.json", NPM_DEPS), (".npmrc", "strict-ssl=false\n")]);
    let report = check_json(&ws, &["--rule", "sd3"]);
    let ids = rule_ids(&report);
    assert!(!ids.is_empty(), "lowercase short id dropped all findings");
    assert!(ids.iter().all(|id| id == "SD003"), "ids: {ids:?}");
}

#[test]
fn partial_hash_pinning_still_reports_sd004() {
    // One requirement hashed, one not -> integrity is not actually enforced.
    let ws = workspace(&[(
        "requirements.txt",
        "requests==2.31.0 --hash=sha256:aaa\nflask==3.0.0\n",
    )]);
    let report = check_json(&ws, &[]);
    assert!(rule_ids(&report).contains(&"SD004".to_string()));
}

#[test]
fn fully_hash_pinned_requirements_suppress_sd004() {
    let ws = workspace(&[(
        "requirements.txt",
        "requests==2.31.0 --hash=sha256:aaa\nflask==3.0.0 --hash=sha256:bbb\n",
    )]);
    let report = check_json(&ws, &[]);
    assert!(!rule_ids(&report).contains(&"SD004".to_string()));
}

#[test]
fn uppercase_http_scheme_is_flagged() {
    let ws = workspace(&[
        ("package.json", NPM_DEPS),
        (".npmrc", "registry=HTTP://registry.internal/\n"),
    ]);
    let report = check_json(&ws, &[]);
    assert!(rule_ids(&report).contains(&"SD003".to_string()));
}

#[test]
fn malformed_structured_config_emits_diagnostic_and_strict_exits_four() {
    let ws = workspace(&[
        (
            "package.json",
            r#"{ "name": "a", "packageManager": "bun@1.2.0", "dependencies": { "x": "^1" } }"#,
        ),
        ("bunfig.toml", "this is = not valid = toml\n"),
    ]);
    let report = check_json(&ws, &[]);
    let diags = report["diagnostics"].as_array().unwrap();
    assert!(diags
        .iter()
        .any(|d| d["message"].as_str().unwrap().contains("bunfig.toml")));
    let strict = run(&ws, &["check", ".", "--strict-parser-errors"]);
    assert_eq!(code(&strict), 4);
}

#[test]
fn uv_workspace_member_covered_by_root_lock() {
    let ws = workspace(&[
        (
            "pyproject.toml",
            "[project]\nname = \"root\"\nversion = \"0\"\n[tool.uv.workspace]\nmembers = [\"pkgs/*\"]\n",
        ),
        ("uv.lock", "version = 1\n"),
        (
            "pkgs/a/pyproject.toml",
            "[project]\nname = \"a\"\nversion = \"0\"\ndependencies = [\"requests\"]\n[tool.uv]\npackage = true\n",
        ),
    ]);
    let report = check_json(&ws, &[]);
    assert!(
        !rule_ids(&report).contains(&"SD001".to_string()),
        "unexpected SD001: {:?}",
        rule_ids(&report)
    );
}

#[test]
fn uv_member_without_workspace_declaration_still_flags_sd001() {
    // Guards the test above: drop the workspace declaration and SD001 returns,
    // proving the coverage logic is what suppresses it.
    let ws = workspace(&[
        ("pyproject.toml", "[project]\nname = \"root\"\nversion = \"0\"\n"),
        ("uv.lock", "version = 1\n"),
        (
            "pkgs/a/pyproject.toml",
            "[project]\nname = \"a\"\nversion = \"0\"\ndependencies = [\"requests\"]\n[tool.uv]\npackage = true\n",
        ),
    ]);
    let report = check_json(&ws, &[]);
    assert!(rule_ids(&report).contains(&"SD001".to_string()));
}

#[test]
fn malformed_expires_is_config_error() {
    let ws = workspace(&[
        ("package.json", NPM_DEPS),
        (
            "safe-deps.toml",
            "[[suppressions]]\nrule = \"SD001\"\npath = \"package.json\"\nreason = \"r\"\nexpires = \"soon\"\n",
        ),
    ]);
    let out = run(&ws, &["check", "."]);
    assert_eq!(code(&out), 2);
}

#[test]
fn far_future_suppression_is_active() {
    let ws = workspace(&[
        ("package.json", NPM_DEPS),
        (
            "safe-deps.toml",
            "[[suppressions]]\nrule = \"SD001\"\npath = \"package.json\"\nreason = \"r\"\nexpires = \"2999-01-01\"\n",
        ),
    ]);
    let report = check_json(&ws, &[]);
    assert!(!rule_ids(&report).contains(&"SD001".to_string()));
}

#[test]
fn json_findings_are_severity_ordered() {
    let ws = workspace(&[("package.json", NPM_DEPS), (".npmrc", "strict-ssl=false\n")]);
    let report = check_json(&ws, &[]);
    let severities: Vec<&str> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["severity"].as_str().unwrap())
        .collect();
    // Errors must come before warnings; a string sort would invert this.
    let first_warning = severities.iter().position(|s| *s == "warning");
    let last_error = severities.iter().rposition(|s| *s == "error");
    if let (Some(w), Some(e)) = (first_warning, last_error) {
        assert!(e < w, "error after warning: {severities:?}");
    }
}

#[test]
fn npmrc_finding_carries_line_and_line_suppression_matches() {
    let ws = workspace(&[
        ("package.json", NPM_DEPS),
        (".npmrc", "registry=https://ok/\nstrict-ssl=false\n"),
    ]);
    let report = check_json(&ws, &[]);
    let sd003 = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == "SD003")
        .unwrap();
    assert_eq!(sd003["location"]["line"], 2);

    // A line-scoped suppression now matches that exact line.
    write(
        ws.path(),
        "safe-deps.toml",
        "[[suppressions]]\nrule = \"SD003\"\npath = \".npmrc\"\nreason = \"r\"\nline = 2\n",
    );
    let suppressed = check_json(&ws, &[]);
    assert!(!rule_ids(&suppressed).contains(&"SD003".to_string()));
    let diags = suppressed["diagnostics"].as_array().unwrap();
    assert!(!diags
        .iter()
        .any(|d| d["message"].as_str().unwrap().contains("unused")));
}

#[test]
fn suppression_path_matches_nested_member() {
    let ws = workspace(&[(
        "packages/app/package.json",
        r#"{ "name": "app", "dependencies": { "x": "^1" } }"#,
    )]);
    write(
        ws.path(),
        "safe-deps.toml",
        "[[suppressions]]\nrule = \"SD001\"\npath = \"packages/app/package.json\"\nreason = \"r\"\n",
    );
    let report = check_json(&ws, &[]);
    assert!(!rule_ids(&report).contains(&"SD001".to_string()));
}

// --- supply-chain hardening rules (Phase 3) ----------------------------------

const NPM_LOCK_OK: &str = r#"{ "lockfileVersion": 3 }"#;

fn findings_of(report: &Value, rule: &str) -> Vec<Value> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule_id"] == rule)
        .cloned()
        .collect()
}

#[test]
fn sd006_flags_unsafe_js_sources_but_not_registry() {
    let pkg = r#"{
      "name": "demo",
      "dependencies": {
        "floating": "github:user/repo#main",
        "tarball": "https://example.com/x.tgz",
        "localpath": "file:../local",
        "registry": "^1.2.3"
      }
    }"#;
    let ws = workspace(&[("package.json", pkg), ("package-lock.json", NPM_LOCK_OK)]);
    let report = check_json(&ws, &[]);
    let sd006 = findings_of(&report, "SD006");
    assert_eq!(sd006.len(), 3, "expected 3 SD006: {report}");
    let msgs: String = sd006
        .iter()
        .map(|f| f["message"].as_str().unwrap())
        .collect();
    assert!(msgs.contains("floating"));
    assert!(msgs.contains("tarball"));
    assert!(msgs.contains("localpath"));
    assert!(!msgs.contains("registry"));
}

#[test]
fn sd006_pinned_git_sha_is_safe() {
    let pkg = r#"{ "name": "d", "dependencies": {
        "pinned": "github:user/repo#3a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b" } }"#;
    let ws = workspace(&[("package.json", pkg), ("package-lock.json", NPM_LOCK_OK)]);
    let report = check_json(&ws, &[]);
    assert!(findings_of(&report, "SD006").is_empty(), "{report}");
}

#[test]
fn sd006_dev_path_is_allowed_but_prod_path_flagged() {
    let pkg = r#"{ "name": "d",
        "dependencies": { "prod": "file:../prod" },
        "devDependencies": { "dev": "file:../dev" } }"#;
    let ws = workspace(&[("package.json", pkg), ("package-lock.json", NPM_LOCK_OK)]);
    let sd006 = findings_of(&check_json(&ws, &[]), "SD006");
    assert_eq!(sd006.len(), 1);
    assert!(sd006[0]["message"].as_str().unwrap().contains("prod"));
}

#[test]
fn sd006_policy_opts_out_of_git_and_path() {
    let pkg = r#"{ "name": "d", "dependencies": {
        "g": "github:u/r#main", "p": "file:../p" } }"#;
    let ws = workspace(&[
        ("package.json", pkg),
        ("package-lock.json", NPM_LOCK_OK),
        (
            "safe-deps.toml",
            "[policy]\nallow_git_dependencies = true\nallow_local_path_dependencies = true\n",
        ),
    ]);
    assert!(findings_of(&check_json(&ws, &[]), "SD006").is_empty());
}

#[test]
fn sd006_flags_python_git_dependency() {
    let pyproject = "\
[project]
name = \"x\"
dependencies = [\"requests>=2\", \"internal @ git+https://h/r.git\"]
";
    let ws = workspace(&[("pyproject.toml", pyproject), ("uv.lock", "")]);
    let sd006 = findings_of(&check_json(&ws, &[]), "SD006");
    assert_eq!(sd006.len(), 1, "{:?}", sd006);
    assert!(sd006[0]["message"].as_str().unwrap().contains("internal"));
}

#[test]
fn sd005_flags_pnpm_dangerously_allow_all_builds() {
    let ws = workspace(&[
        (
            "package.json",
            r#"{ "name": "d", "dependencies": { "a": "^1" } }"#,
        ),
        ("pnpm-lock.yaml", ""),
        (
            "pnpm-workspace.yaml",
            "packages:\n  - 'pkgs/*'\ndangerouslyAllowAllBuilds: true\n",
        ),
    ]);
    let sd005 = findings_of(&check_json(&ws, &[]), "SD005");
    assert_eq!(sd005.len(), 1, "{:?}", sd005);
    assert_eq!(sd005[0]["severity"], "error");
    assert_eq!(sd005[0]["location"]["file"], "pnpm-workspace.yaml");
}

#[test]
fn sd005_pnpm_without_flag_is_clean() {
    let ws = workspace(&[
        (
            "package.json",
            r#"{ "name": "d", "dependencies": { "a": "^1" } }"#,
        ),
        ("pnpm-lock.yaml", ""),
        ("pnpm-workspace.yaml", "packages:\n  - 'pkgs/*'\n"),
    ]);
    assert!(findings_of(&check_json(&ws, &[]), "SD005").is_empty());
}

#[test]
fn sd005_bun_trusted_wildcard_flagged_named_is_safe() {
    let wildcard = workspace(&[
        (
            "package.json",
            r#"{ "name": "d", "dependencies": { "a": "^1" } }"#,
        ),
        ("bun.lock", ""),
        ("bunfig.toml", "[install]\ntrustedDependencies = [\"*\"]\n"),
    ]);
    assert_eq!(findings_of(&check_json(&wildcard, &[]), "SD005").len(), 1);

    let named = workspace(&[
        (
            "package.json",
            r#"{ "name": "d", "dependencies": { "a": "^1" } }"#,
        ),
        ("bun.lock", ""),
        (
            "bunfig.toml",
            "[install]\ntrustedDependencies = [\"esbuild\"]\n",
        ),
    ]);
    assert!(findings_of(&check_json(&named, &[]), "SD005").is_empty());
}

#[test]
fn sd007_uv_index_config_is_profile_gated() {
    let pyproject = "\
[project]
name = \"x\"
dependencies = [\"requests>=2\"]
[tool.uv]
extra-index-url = [\"https://pypi.internal/simple\"]
index-strategy = \"unsafe-best-match\"
";
    let ws = workspace(&[("pyproject.toml", pyproject), ("uv.lock", "")]);
    let sd007 = findings_of(&check_json(&ws, &[]), "SD007");
    assert_eq!(sd007.len(), 2, "{:?}", sd007);
    assert!(sd007.iter().all(|f| f["severity"] == "warning"));
    // Strict profile escalates to error and fails the run.
    let out = run(&ws, &["check", ".", "--profile", "strict"]);
    assert_eq!(code(&out), 1);
    let strict = check_json(&ws, &["--profile", "strict"]);
    assert!(findings_of(&strict, "SD007")
        .iter()
        .all(|f| f["severity"] == "error"));
}

#[test]
fn sd007_pip_extra_index_url_in_requirements() {
    let ws = workspace(&[(
        "requirements.txt",
        "requests==2.0 --hash=sha256:abc\n--extra-index-url https://pypi.internal/simple\n",
    )]);
    let sd007 = findings_of(&check_json(&ws, &[]), "SD007");
    assert_eq!(sd007.len(), 1, "{:?}", sd007);
    assert!(sd007[0]["message"]
        .as_str()
        .unwrap()
        .contains("extra index"));
}

#[test]
fn list_rules_includes_supply_chain_rules() {
    let ws = workspace(&[]);
    let text = stdout(&run(&ws, &["list-rules"]));
    for id in ["SD005", "SD006", "SD007"] {
        assert!(text.contains(id), "missing {id}:\n{text}");
    }
}

#[test]
fn sd006_flags_uv_dev_dependency_source() {
    let pyproject = "\
[project]
name = \"x\"
dependencies = [\"requests>=2\"]
[tool.uv]
dev-dependencies = [\"internal @ git+https://h/r.git\"]
";
    let ws = workspace(&[("pyproject.toml", pyproject), ("uv.lock", "")]);
    let sd006 = findings_of(&check_json(&ws, &[]), "SD006");
    assert_eq!(sd006.len(), 1, "{:?}", sd006);
    assert!(sd006[0]["message"].as_str().unwrap().contains("internal"));
}

#[test]
fn sd006_points_at_the_requirements_file_it_came_from() {
    let ws = workspace(&[(
        "requirements-dev.txt",
        "pytest==7.0\ntooling @ git+https://h/r.git\n",
    )]);
    let sd006 = findings_of(&check_json(&ws, &[]), "SD006");
    assert_eq!(sd006.len(), 1, "{:?}", sd006);
    assert_eq!(sd006[0]["location"]["file"], "requirements-dev.txt");
}

#[test]
fn sd007_does_not_duplicate_when_index_declared_twice() {
    // extra-index-url in both pyproject [tool.uv] and uv.toml must yield one.
    let pyproject = "\
[project]
name = \"x\"
dependencies = [\"requests>=2\"]
[tool.uv]
extra-index-url = [\"https://pypi.internal/simple\"]
";
    let ws = workspace(&[
        ("pyproject.toml", pyproject),
        ("uv.lock", ""),
        (
            "uv.toml",
            "extra-index-url = [\"https://pypi.internal/simple\"]\n",
        ),
    ]);
    let sd007 = findings_of(&check_json(&ws, &[]), "SD007");
    assert_eq!(sd007.len(), 1, "expected dedup to one finding: {:?}", sd007);
}

// --- Phase 3 review follow-ups (036-jp) --------------------------------------

#[test]
fn sd006_keeps_unsafe_requirements_source_over_safe_pyproject() {
    // pyproject declares a safe `foo`; requirements declares the unsafe git
    // `foo`. Name-only dedup would drop the git one — it must be flagged.
    let ws = workspace(&[
        (
            "pyproject.toml",
            "[project]\nname = \"x\"\ndependencies = [\"foo>=1\"]\n",
        ),
        ("requirements.txt", "foo @ git+https://h/r.git\n"),
        ("uv.lock", ""),
    ]);
    let sd006 = findings_of(&check_json(&ws, &[]), "SD006");
    assert_eq!(sd006.len(), 1, "{:?}", sd006);
    assert_eq!(sd006[0]["location"]["file"], "requirements.txt");
}

#[test]
fn sd006_dev_requirements_editable_path_is_not_flagged() {
    // A local editable path in requirements-dev.txt is the intended dev pattern.
    let ws = workspace(&[("requirements-dev.txt", "-e ./tools/mylib\n")]);
    assert!(findings_of(&check_json(&ws, &[]), "SD006").is_empty());
}

#[test]
fn sd006_flags_pep735_dependency_group_git() {
    let pyproject = "\
[project]
name = \"x\"
dependencies = [\"requests>=2\"]
[dependency-groups]
dev = [\"internal @ git+https://h/r.git\"]
";
    let ws = workspace(&[("pyproject.toml", pyproject), ("uv.lock", "")]);
    let sd006 = findings_of(&check_json(&ws, &[]), "SD006");
    assert_eq!(sd006.len(), 1, "{:?}", sd006);
    assert!(sd006[0]["message"].as_str().unwrap().contains("internal"));
}

#[test]
fn sd005_flags_bun_trusted_wildcard_in_package_json() {
    // Bun reads trustedDependencies from package.json, not bunfig.toml.
    let ws = workspace(&[
        (
            "package.json",
            r#"{ "name": "d", "dependencies": { "a": "^1" }, "trustedDependencies": ["*"] }"#,
        ),
        ("bun.lock", ""),
    ]);
    assert_eq!(findings_of(&check_json(&ws, &[]), "SD005").len(), 1);
}

#[test]
fn sd006_floating_ssh_git_remediation_covers_both() {
    // A dep that is both floating and SSH must get a remediation that addresses
    // both, so following it actually clears the finding.
    let ws = workspace(&[(
        "package.json",
        r#"{ "name": "d", "dependencies": { "internal": "git+ssh://git@host/org/repo.git#main" } }"#,
    )]);
    let report = check_json(&ws, &[]);
    let sd006 = findings_of(&report, "SD006");
    assert_eq!(sd006.len(), 1, "{report}");
    let rem = sd006[0]["remediation"].as_str().unwrap();
    assert!(rem.contains("SHA"), "{rem}");
    assert!(rem.contains("https"), "{rem}");
}
