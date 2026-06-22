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
fn config_is_discovered_relative_to_the_target_path() {
    // Regression: safe-deps.toml must be discovered in the analyzed directory,
    // not the process CWD. Running `check sub` from a CWD that has no config
    // must still pick up sub/safe-deps.toml.
    let ws = workspace(&[
        ("sub/package.json", NPM_DEPS),
        ("sub/safe-deps.toml", "profile = \"strict\"\n"),
    ]);
    // CWD is the tempdir root (no safe-deps.toml here); analyze ./sub.
    let out = run(&ws, &["check", "sub", "--format", "json"]);
    let report: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("invalid JSON: {e}\n{}", stdout(&out)));
    assert_eq!(
        report["profile"], "strict",
        "config in the target dir must be applied: {report}"
    );
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

#[test]
fn invalid_application_root_glob_is_usage_error() {
    // A malformed root glob must be a loud config error (exit 2), not a silent
    // disable of the application_roots/library_roots policy.
    let ws = workspace(&[
        ("package.json", NPM_DEPS),
        (
            "safe-deps.toml",
            "[policy]\napplication_roots = [\"apps/*\", \"[bad\"]\n",
        ),
    ]);
    let out = run(&ws, &["check", "."]);
    assert_eq!(code(&out), 2, "{}", stdout(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("application_roots"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
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

// --- audit mode (Phase 5) ----------------------------------------------------

const CARGO_LOCK_LEFTPAD: &str = r#"
[[package]]
name = "left-pad"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

// A cache entry that `audit --offline` will read without any network. The
// cache key mirrors PackageCoordinate::cache_key (non-alphanumeric -> '_').
const CACHED_ADVISORY: &str = r#"{
  "fetched": 9999999999,
  "advisories": [
    { "id": "RUSTSEC-2099-0001", "aliases": ["CVE-2099-1"],
      "summary": "left-pad is doomed", "severity": "HIGH",
      "package": { "ecosystem": "crates.io", "name": "left-pad", "version": "1.0.0" } }
  ]
}"#;

/// Seeds the OSV cache for left-pad@1.0.0 under `<ws>/cache`, computing the
/// filename from the same public key logic the binary uses.
fn seed_leftpad_cache(ws: &TempDir) {
    let key = safe_deps::audit::PackageCoordinate {
        ecosystem: "crates.io".to_string(),
        name: "left-pad".to_string(),
        version: "1.0.0".to_string(),
    }
    .cache_key();
    write(ws.path(), &format!("cache/{key}.json"), CACHED_ADVISORY);
}

#[test]
fn audit_offline_reports_cached_advisory_and_exits_one() {
    let ws = workspace(&[("Cargo.lock", CARGO_LOCK_LEFTPAD)]);
    seed_leftpad_cache(&ws);
    let cache = ws.path().join("cache");
    let out = run(
        &ws,
        &[
            "audit",
            ".",
            "--offline",
            "--cache-dir",
            cache.to_str().unwrap(),
        ],
    );
    let text = stdout(&out);
    assert!(text.contains("RUSTSEC-2099-0001"), "{text}");
    assert!(text.contains("left-pad@1.0.0"), "{text}");
    assert_eq!(code(&out), 1, "vulnerabilities present should exit 1");
}

#[test]
fn audit_respects_advisory_ignore_by_alias() {
    let ws = workspace(&[
        ("Cargo.lock", CARGO_LOCK_LEFTPAD),
        (
            "safe-deps.toml",
            "[[advisory_ignores]]\nid = \"CVE-2099-1\"\nreason = \"patched downstream\"\n",
        ),
    ]);
    seed_leftpad_cache(&ws);
    let cache = ws.path().join("cache");
    let out = run(
        &ws,
        &[
            "audit",
            ".",
            "--offline",
            "--cache-dir",
            cache.to_str().unwrap(),
        ],
    );
    let text = stdout(&out);
    assert!(text.contains("Ignored"), "{text}");
    assert_eq!(code(&out), 0, "an ignored advisory should not fail the run");
}

#[test]
fn audit_offline_without_cache_notes_unchecked_packages() {
    let ws = workspace(&[("Cargo.lock", CARGO_LOCK_LEFTPAD)]);
    let out = run(&ws, &["audit", ".", "--offline", "--no-cache"]);
    let text = stdout(&out);
    assert!(text.contains("No known vulnerabilities"), "{text}");
    // An offline cache miss must not read as a clean bill of health.
    assert!(text.contains("not in the cache were not checked"), "{text}");
}

// --- additional ecosystems + JUnit (Phase 4) ---------------------------------

#[test]
fn cargo_crate_missing_lock_is_flagged() {
    let ws = workspace(&[
        (
            "Cargo.toml",
            "[package]\nname = \"app\"\n[dependencies]\nserde = \"1\"\n",
        ),
        ("src/main.rs", "fn main() {}\n"),
    ]);
    let report = check_json(&ws, &[]);
    let ids = rule_ids(&report);
    assert!(ids.contains(&"SD001".to_string()), "ids: {ids:?}");
    let sd001 = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == "SD001")
        .unwrap();
    assert_eq!(sd001["package_manager"], "cargo");
    assert_eq!(sd001["ecosystem"], "rust");
    assert_eq!(sd001["severity"], "error");
}

#[test]
fn cargo_crate_with_lock_is_clean() {
    let ws = workspace(&[
        (
            "Cargo.toml",
            "[package]\nname = \"app\"\n[dependencies]\nserde = \"1\"\n",
        ),
        ("src/main.rs", "fn main() {}\n"),
        ("Cargo.lock", "version = 3\n"),
    ]);
    assert!(!rule_ids(&check_json(&ws, &[])).contains(&"SD001".to_string()));
}

#[test]
fn go_module_missing_sum_is_flagged() {
    let ws = workspace(&[(
        "go.mod",
        "module example.com/m\n\ngo 1.21\n\nrequire github.com/x/y v1.0.0\n",
    )]);
    let report = check_json(&ws, &[]);
    let sd001 = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == "SD001");
    let sd001 = sd001.expect("SD001 for go module");
    assert_eq!(sd001["package_manager"], "go");
    assert_eq!(sd001["ecosystem"], "go");
}

#[test]
fn go_module_with_sum_is_clean() {
    let ws = workspace(&[
        (
            "go.mod",
            "module m\ngo 1.21\nrequire github.com/x/y v1.0.0\n",
        ),
        ("go.sum", "github.com/x/y v1.0.0 h1:abc=\n"),
    ]);
    assert!(!rule_ids(&check_json(&ws, &[])).contains(&"SD001".to_string()));
}

#[test]
fn junit_output_is_well_formed() {
    let ws = workspace(&[
        (
            "Cargo.toml",
            "[package]\nname = \"app\"\n[dependencies]\nserde = \"1\"\n",
        ),
        ("src/main.rs", "fn main() {}\n"),
    ]);
    let out = run(&ws, &["check", ".", "--format", "junit"]);
    let xml = stdout(&out);
    assert!(xml.starts_with("<?xml version=\"1.0\""), "{xml}");
    assert!(xml.contains("<testsuites name=\"safe-deps\""));
    assert!(xml.contains("<testcase"));
    assert!(xml.contains("type=\"SD001\""));
    // Errors present → process exits 1 by default.
    assert_eq!(code(&out), 1);
}

// --- Phase 4 review follow-ups (036-jp) --------------------------------------

#[test]
fn cargo_user_library_root_overrides_inferred_kind() {
    // A lib crate (would infer Library->Warning) configured as a library root
    // stays a warning; but a configured application_root must win and escalate
    // to error, proving detect emits Unknown and refine_kinds applies first.
    let ws = workspace(&[
        (
            "Cargo.toml",
            "[package]\nname = \"lib\"\n[dependencies]\nserde = \"1\"\n",
        ),
        ("src/lib.rs", "\n"),
        ("safe-deps.toml", "[policy]\napplication_roots = [\"**\"]\n"),
    ]);
    let report = check_json(&ws, &[]);
    let sd001 = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == "SD001")
        .expect("SD001");
    assert_eq!(
        sd001["severity"], "error",
        "configured application_root must win"
    );
}

// --- CI-aware rules (Phase 2) ------------------------------------------------

const NPM_LOCK: &str = r#"{ "lockfileVersion": 3 }"#;

fn findings_for(report: &Value, rule: &str) -> Vec<Value> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule_id"] == rule)
        .cloned()
        .collect()
}

// --- supply-chain hardening rules (Phase 3) ----------------------------------

const NPM_LOCK_OK: &str = r#"{ "lockfileVersion": 3 }"#;

fn findings_of(report: &Value, rule: &str) -> Vec<Value> {
    findings_for(report, rule)
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

const WORKFLOW_NPM_INSTALL: &str = "\
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install
";

#[test]
fn ci_npm_install_flags_sd002_with_workflow_location() {
    let ws = workspace(&[
        ("package.json", NPM_DEPS),
        ("package-lock.json", NPM_LOCK),
        (".github/workflows/ci.yml", WORKFLOW_NPM_INSTALL),
    ]);
    let report = check_json(&ws, &[]);
    let sd002 = findings_for(&report, "SD002");
    assert_eq!(sd002.len(), 1, "expected one SD002: {report}");
    assert_eq!(sd002[0]["location"]["file"], ".github/workflows/ci.yml");
    assert_eq!(sd002[0]["location"]["line"], 8);
    assert_eq!(sd002[0]["severity"], "error");
    // An SD002 error should fail the run by default.
    let out = run(&ws, &["check", "."]);
    assert_eq!(code(&out), 1);
}

#[test]
fn ci_complex_shell_command_emits_uncertainty_diagnostic() {
    // A package-manager command wrapped in a construct the tokenizer cannot model
    // must surface a low-confidence diagnostic.
    let workflow = WORKFLOW_NPM_INSTALL.replace("npm install", "npm install $(cat extra.txt)");
    let ws = workspace(&[("package.json", NPM_DEPS), ("package-lock.json", NPM_LOCK)]);
    write(ws.path(), ".github/workflows/ci.yml", &workflow);
    let report = check_json(&ws, &[]);
    let diags = report["diagnostics"].as_array().unwrap();
    assert!(
        diags.iter().any(|d| {
            let m = d["message"].as_str().unwrap_or("");
            m.contains("complex-shell-not-fully-parsed") && m.contains("command substitution")
        }),
        "expected uncertainty diagnostic: {report}"
    );
}

#[test]
fn ci_clean_shell_command_has_no_uncertainty_diagnostic() {
    let ws = workspace(&[
        ("package.json", NPM_DEPS),
        ("package-lock.json", NPM_LOCK),
        (".github/workflows/ci.yml", WORKFLOW_NPM_INSTALL),
    ]);
    let report = check_json(&ws, &[]);
    let diags = report["diagnostics"].as_array().unwrap();
    assert!(
        !diags.iter().any(|d| d["message"]
            .as_str()
            .unwrap_or("")
            .contains("complex-shell-not-fully-parsed")),
        "a cleanly tokenized command should not emit an uncertainty diagnostic: {report}"
    );
}

#[test]
fn ci_complex_non_pm_command_does_not_emit_uncertainty() {
    // Complex shell that does not invoke a package manager is not the CI rules'
    // concern, so it must not add diagnostic noise.
    let workflow = WORKFLOW_NPM_INSTALL.replace("npm install", "echo $(date)");
    let ws = workspace(&[("package.json", NPM_DEPS), ("package-lock.json", NPM_LOCK)]);
    write(ws.path(), ".github/workflows/ci.yml", &workflow);
    let report = check_json(&ws, &[]);
    let diags = report["diagnostics"].as_array().unwrap();
    assert!(
        !diags.iter().any(|d| d["message"]
            .as_str()
            .unwrap_or("")
            .contains("complex-shell-not-fully-parsed")),
        "non-package-manager complex command should not emit uncertainty: {report}"
    );
}

#[test]
fn ci_npm_ci_is_frozen_and_clears_sd002() {
    let workflow = WORKFLOW_NPM_INSTALL.replace("npm install", "npm ci");
    let ws = workspace(&[("package.json", NPM_DEPS), ("package-lock.json", NPM_LOCK)]);
    write(ws.path(), ".github/workflows/ci.yml", &workflow);
    let report = check_json(&ws, &[]);
    assert!(findings_for(&report, "SD002").is_empty(), "{report}");
}

#[test]
fn ci_uncertainty_diagnostic_is_info_and_not_a_parse_failure() {
    // A here-string on a package-manager install: pm-relevant and uncertain.
    let workflow = WORKFLOW_NPM_INSTALL.replace("npm install", "npm install <<< \"$DEPS\"");
    let ws = workspace(&[("package.json", NPM_DEPS), ("package-lock.json", NPM_LOCK)]);
    write(ws.path(), ".github/workflows/ci.yml", &workflow);
    let report = check_json(&ws, &[]);
    let diags = report["diagnostics"].as_array().unwrap();
    let diag = diags
        .iter()
        .find(|d| {
            d["message"]
                .as_str()
                .unwrap_or("")
                .contains("complex-shell-not-fully-parsed")
        })
        .unwrap_or_else(|| panic!("expected uncertainty diagnostic, got: {diags:?}"));
    assert_eq!(diag["level"], "info");
    assert_eq!(diag["location"], ".github/workflows/ci.yml");
    // Informational only: it is not a parse failure, so --strict-parser-errors
    // does not escalate to exit code 4. `--fail-on none` isolates this from the
    // SD002 finding the non-frozen install also produces.
    let out = run(
        &ws,
        &["check", ".", "--strict-parser-errors", "--fail-on", "none"],
    );
    assert_eq!(code(&out), 0);
}

#[test]
fn ci_dangerous_force_flag_reports_sd009() {
    // `npm ci --force` is frozen (no SD002) but --force is a dangerous bypass.
    let workflow = WORKFLOW_NPM_INSTALL.replace("npm install", "npm ci --force");
    let ws = workspace(&[("package.json", NPM_DEPS), ("package-lock.json", NPM_LOCK)]);
    write(ws.path(), ".github/workflows/ci.yml", &workflow);
    let report = check_json(&ws, &[]);
    assert!(findings_for(&report, "SD002").is_empty(), "{report}");
    let sd009 = findings_for(&report, "SD009");
    assert_eq!(sd009.len(), 1, "expected one SD009: {report}");
    assert_eq!(sd009[0]["location"]["file"], ".github/workflows/ci.yml");
    assert!(sd009[0]["message"].as_str().unwrap().contains("--force"));
}

#[test]
fn ci_clean_install_has_no_sd009() {
    // A safe install (no dangerous flags) must produce no SD009 finding.
    let workflow = WORKFLOW_NPM_INSTALL.replace("npm install", "npm ci");
    let ws = workspace(&[("package.json", NPM_DEPS), ("package-lock.json", NPM_LOCK)]);
    write(ws.path(), ".github/workflows/ci.yml", &workflow);
    assert!(findings_for(&check_json(&ws, &[]), "SD009").is_empty());
}

#[test]
fn ci_install_without_audit_reports_sd008() {
    let workflow = WORKFLOW_NPM_INSTALL.replace("npm install", "npm ci");
    let ws = workspace(&[("package.json", NPM_DEPS), ("package-lock.json", NPM_LOCK)]);
    write(ws.path(), ".github/workflows/ci.yml", &workflow);
    let report = check_json(&ws, &[]);
    let sd008 = findings_for(&report, "SD008");
    assert_eq!(sd008.len(), 1, "expected SD008: {report}");
    assert_eq!(sd008[0]["severity"], "warning");
    // Warnings do not fail the run by default.
    let out = run(&ws, &["check", "."]);
    assert_eq!(code(&out), 0);
}

#[test]
fn audit_json_format() {
    let ws = workspace(&[("Cargo.lock", CARGO_LOCK_LEFTPAD)]);
    seed_leftpad_cache(&ws);
    let cache = ws.path().join("cache");
    let out = run(
        &ws,
        &[
            "audit",
            ".",
            "--offline",
            "--format",
            "json",
            "--cache-dir",
            cache.to_str().unwrap(),
        ],
    );
    let v: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("invalid JSON: {e}\n{}", stdout(&out)));
    assert_eq!(v["advisories"][0]["id"], "RUSTSEC-2099-0001");
    assert_eq!(v["packages_audited"], 1);
}

#[test]
fn audit_invalid_advisory_ignore_is_config_error() {
    let ws = workspace(&[
        ("Cargo.lock", CARGO_LOCK_LEFTPAD),
        ("safe-deps.toml", "[[advisory_ignores]]\nid = \"CVE-1\"\n"),
    ]);
    let out = run(&ws, &["audit", ".", "--offline", "--no-cache"]);
    assert_eq!(
        code(&out),
        2,
        "missing reason should be a usage/config error"
    );
}

// --- Phase 5 review follow-ups (036-jp) --------------------------------------

#[test]
fn audit_malformed_lockfile_is_not_silently_clean() {
    let ws = workspace(&[("Cargo.lock", "this is not valid toml {{{")]);
    let out = run(&ws, &["audit", ".", "--offline", "--no-cache"]);
    let text = stdout(&out);
    assert!(text.contains("could not parse"), "{text}");
}

#[test]
fn audit_format_honors_env_var() {
    let ws = workspace(&[("Cargo.lock", CARGO_LOCK_LEFTPAD)]);
    let out = bin()
        .current_dir(ws.path())
        .env("SAFE_DEPS_FORMAT", "json")
        .args(["audit", ".", "--offline", "--no-cache"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("expected JSON via SAFE_DEPS_FORMAT: {e}\n{}", stdout(&out)));
    assert!(v.get("advisories").is_some());
}

#[test]
fn audit_config_discovered_relative_to_target_not_cwd() {
    // Mirrors `config_is_discovered_relative_to_the_target_path` for the audit path:
    // the default `safe-deps.toml` must be discovered relative to the analysis
    // target, not the process cwd. Here `format = "json"` lives in the target's
    // config; running `audit` from an unrelated cwd must still honor it.
    let ws = workspace(&[
        ("Cargo.lock", CARGO_LOCK_LEFTPAD),
        ("safe-deps.toml", "format = \"json\"\n"),
    ]);
    let elsewhere = TempDir::new().unwrap();
    let out = bin()
        .current_dir(elsewhere.path())
        .args(["audit", "--offline", "--no-cache"])
        .arg(ws.path())
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "expected JSON from target-relative safe-deps.toml: {e}\n{}",
            stdout(&out)
        )
    });
    assert!(v.get("advisories").is_some());
}

#[test]
fn ci_audit_command_clears_sd008() {
    let workflow = WORKFLOW_NPM_INSTALL.replace("npm install", "npm ci && npm audit");
    let ws = workspace(&[("package.json", NPM_DEPS), ("package-lock.json", NPM_LOCK)]);
    write(ws.path(), ".github/workflows/ci.yml", &workflow);
    let report = check_json(&ws, &[]);
    assert!(findings_for(&report, "SD008").is_empty(), "{report}");
}

#[test]
fn ci_bootstrap_install_without_ecosystem_deps_does_not_report_sd008() {
    // A Rust repo whose CI bootstraps a Python helper (`pip install tox`) has
    // no Python project dependencies. SD008 must not fire for Python: the
    // dependency-presence gate requires real deps in the ecosystem, not just a
    // CI install command (regression for review on src/rules/sd008).
    let manifest = "[package]\nname = \"app\"\n[dependencies]\nserde = \"1\"\n";
    let ws = workspace(&[("Cargo.toml", manifest), ("Cargo.lock", "version = 3\n")]);
    let workflow = WORKFLOW_NPM_INSTALL.replace("npm install", "pip install tox");
    write(ws.path(), ".github/workflows/ci.yml", &workflow);
    let report = check_json(&ws, &[]);
    assert!(
        findings_for(&report, "SD008").is_empty(),
        "a bootstrap helper install with no Python deps must not trip SD008: {report}"
    );
}

#[test]
fn external_audit_policy_opts_out_of_sd008() {
    let workflow = WORKFLOW_NPM_INSTALL.replace("npm install", "npm ci");
    let ws = workspace(&[
        ("package.json", NPM_DEPS),
        ("package-lock.json", NPM_LOCK),
        ("safe-deps.toml", "[policy]\nexternal_audit = true\n"),
    ]);
    write(ws.path(), ".github/workflows/ci.yml", &workflow);
    let report = check_json(&ws, &[]);
    assert!(findings_for(&report, "SD008").is_empty(), "{report}");
}

#[test]
fn monorepo_audit_missing_reports_sd008_once() {
    // A monorepo where the workflow installs every package but never runs an
    // audit command. SD008 is workspace-scoped: it must fire exactly once (not
    // once per package) for the entire workspace.
    let pkg = |name: &str| format!(r#"{{ "name": "{name}", "dependencies": {{ "x": "^1" }} }}"#);
    let ws = workspace(&[
        ("package.json", r#"{ "name": "root", "private": true }"#),
        ("package-lock.json", NPM_LOCK),
        ("packages/app/package.json", &pkg("app")),
        ("packages/lib/package.json", &pkg("lib")),
    ]);
    write(
        ws.path(),
        ".github/workflows/ci.yml",
        "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          cd packages/app && npm ci\n          cd packages/lib && npm ci\n",
    );
    let report = check_json(&ws, &[]);
    let sd008 = findings_for(&report, "SD008");
    assert_eq!(
        sd008.len(),
        1,
        "SD008 must fire once for the workspace, not once per package: {report}"
    );
    assert_eq!(sd008[0]["ecosystem"], "javascript");
    assert_eq!(sd008[0]["location"]["file"], ".github/workflows/ci.yml");
}

#[test]
fn monorepo_single_package_audit_clears_sd008() {
    // Same monorepo, but now the CI audits (anywhere) for the ecosystem. SD008
    // is cleared workspace-wide; it does not duplicate or partially fire.
    let pkg = |name: &str| format!(r#"{{ "name": "{name}", "dependencies": {{ "x": "^1" }} }}"#);
    let ws = workspace(&[
        ("package.json", r#"{ "name": "root", "private": true }"#),
        ("package-lock.json", NPM_LOCK),
        ("packages/app/package.json", &pkg("app")),
        ("packages/lib/package.json", &pkg("lib")),
    ]);
    write(
        ws.path(),
        ".github/workflows/ci.yml",
        "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          cd packages/app && npm ci && npm audit\n          cd packages/lib && npm ci\n",
    );
    let report = check_json(&ws, &[]);
    assert!(
        findings_for(&report, "SD008").is_empty(),
        "an audit in CI clears SD008 for the whole ecosystem: {report}"
    );
}

#[test]
fn sarif_output_is_valid_and_maps_results() {
    let ws = workspace(&[
        ("package.json", NPM_DEPS),
        ("package-lock.json", NPM_LOCK),
        (".github/workflows/ci.yml", WORKFLOW_NPM_INSTALL),
    ]);
    let out = run(&ws, &["check", ".", "--format", "sarif"]);
    let sarif: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("invalid SARIF: {e}\n{}", stdout(&out)));
    assert_eq!(sarif["version"], "2.1.0");
    assert!(sarif["$schema"].is_string());
    let run0 = &sarif["runs"][0];
    assert_eq!(run0["tool"]["driver"]["name"], "safe-deps");
    assert!(run0["tool"]["driver"]["rules"].as_array().unwrap().len() >= 6);
    let result = run0["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["ruleId"] == "SD002")
        .expect("SD002 result present");
    assert_eq!(result["level"], "error");
    let idx = result["ruleIndex"].as_u64().unwrap() as usize;
    assert_eq!(run0["tool"]["driver"]["rules"][idx]["id"], "SD002");
    assert_eq!(
        result["locations"][0]["physicalLocation"]["region"]["startLine"],
        8
    );
}

#[test]
fn go_module_missing_sum_remediation_is_go_specific() {
    let ws = workspace(&[(
        "go.mod",
        "module example.com/m\n\ngo 1.21\n\nrequire github.com/x/y v1.0.0\n",
    )]);
    let report = check_json(&ws, &[]);
    let sd001 = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == "SD001")
        .expect("SD001");
    let rem = sd001["remediation"].as_str().unwrap();
    assert!(
        rem.contains("go mod tidy") || rem.contains("-mod=readonly"),
        "{rem}"
    );
    assert!(!rem.contains("install from"));
}

#[test]
fn monorepo_unsafe_install_reports_sd002_once() {
    // A single unsafe CI command must not be duplicated per project.
    let pkg = |name: &str| format!(r#"{{ "name": "{name}", "dependencies": {{ "x": "^1" }} }}"#);
    let ws = workspace(&[
        ("package.json", r#"{ "name": "root", "private": true }"#),
        ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
        ("packages/a/package.json", &pkg("a")),
        ("packages/b/package.json", &pkg("b")),
        ("pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n"),
    ]);
    write(
        ws.path(),
        ".github/workflows/ci.yml",
        "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          pnpm install\n          pnpm audit\n",
    );
    let report = check_json(&ws, &[]);
    let sd002 = findings_for(&report, "SD002");
    assert_eq!(
        sd002.len(),
        1,
        "SD002 should fire once for one command: {report}"
    );
    assert_eq!(sd002[0]["package_manager"], "pnpm");
}

#[test]
fn list_rules_includes_ci_aware_rules() {
    let ws = workspace(&[]);
    let out = run(&ws, &["list-rules"]);
    let text = stdout(&out);
    for id in ["SD002", "SD008", "SD009"] {
        assert!(text.contains(id), "missing {id}:\n{text}");
    }
}

// --- SD006 for Cargo / Go (#21) ----------------------------------------------

#[test]
fn sd006_flags_cargo_git_and_path_deps_but_not_registry() {
    let manifest = "\
[package]
name = \"app\"
[dependencies]
serde = \"1\"
internal = { git = \"https://h/r.git\", branch = \"main\" }
local = { path = \"../local\" }
pinned = { git = \"https://h/r.git\", rev = \"abc1234\" }
";
    let ws = workspace(&[("Cargo.toml", manifest), ("Cargo.lock", "version = 3\n")]);
    let sd006 = findings_of(&check_json(&ws, &[]), "SD006");
    let msgs: String = sd006
        .iter()
        .map(|f| f["message"].as_str().unwrap())
        .collect();
    // floating git `internal` and production path `local` are flagged.
    assert!(msgs.contains("internal"), "{msgs}");
    assert!(msgs.contains("local"), "{msgs}");
    // registry `serde` and rev-pinned `pinned` are not.
    assert!(!msgs.contains("serde"), "{msgs}");
    assert!(!msgs.contains("pinned"), "{msgs}");
}

#[test]
fn sd006_flags_cargo_patch_redirect() {
    let manifest = "\
[package]
name = \"app\"
[dependencies]
serde = \"1\"
[patch.crates-io]
serde = { git = \"https://h/serde.git\" }
";
    let ws = workspace(&[("Cargo.toml", manifest), ("Cargo.lock", "version = 3\n")]);
    let sd006 = findings_of(&check_json(&ws, &[]), "SD006");
    assert_eq!(sd006.len(), 1, "{sd006:?}");
    assert!(sd006[0]["message"].as_str().unwrap().contains("serde"));
}

#[test]
fn sd006_cargo_registry_only_is_clean() {
    let manifest = "[package]\nname = \"app\"\n[dependencies]\nserde = \"1\"\n";
    let ws = workspace(&[("Cargo.toml", manifest), ("Cargo.lock", "version = 3\n")]);
    assert!(findings_of(&check_json(&ws, &[]), "SD006").is_empty());
}

#[test]
fn sd006_flags_go_local_path_replace() {
    let go_mod = "\
module example.com/m

go 1.21

require github.com/x/y v1.2.3

replace github.com/x/y => ../local/y
";
    let ws = workspace(&[
        ("go.mod", go_mod),
        ("go.sum", "github.com/x/y v1.2.3 h1:abc=\n"),
    ]);
    let sd006 = findings_of(&check_json(&ws, &[]), "SD006");
    assert_eq!(sd006.len(), 1, "{sd006:?}");
    assert!(sd006[0]["message"]
        .as_str()
        .unwrap()
        .contains("github.com/x/y"));
}

#[test]
fn sd006_go_normal_requires_are_clean() {
    let go_mod = "module m\ngo 1.21\nrequire github.com/x/y v1.2.3\n";
    let ws = workspace(&[
        ("go.mod", go_mod),
        ("go.sum", "github.com/x/y v1.2.3 h1:abc=\n"),
    ]);
    assert!(findings_of(&check_json(&ws, &[]), "SD006").is_empty());
}

// --- workspace-scan error surfacing (#18) ------------------------------------

#[test]
#[cfg(unix)]
fn unreadable_directory_is_surfaced_and_escalates_under_strict() {
    use std::os::unix::fs::PermissionsExt;

    // A clean project (lockfile present, no config) so the run is otherwise
    // exit 0; any non-zero exit must come from the walk error.
    let ws = workspace(&[
        ("package.json", NPM_DEPS),
        ("package-lock.json", r#"{ "lockfileVersion": 3 }"#),
    ]);
    let locked = ws.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::write(locked.join("x.txt"), "x").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

    let normal = run(&ws, &["check", "."]);
    let strict = run(&ws, &["check", ".", "--strict-parser-errors"]);

    // Restore permissions so the TempDir can be cleaned up.
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();

    let text = stdout(&normal);
    if !text.contains("could not scan") {
        // Permissions were not enforced (e.g. running as root); nothing to assert.
        eprintln!("skipping: directory permissions not enforced (root?)");
        return;
    }
    // The walk error is surfaced as a diagnostic but is only a warning, so a
    // default run does not fail.
    assert_eq!(
        code(&normal),
        0,
        "scan diagnostic should not fail a default run"
    );
    // Under --strict-parser-errors the coverage gap escalates to exit 4.
    assert_eq!(code(&strict), 4, "strict mode should escalate a walk error");
}

// --- CI provider plugins: GitLab CI / CircleCI + Cargo/Go (#22) ---------------

#[test]
fn gitlab_ci_non_frozen_install_reports_sd002() {
    let ws = workspace(&[("package.json", NPM_DEPS), ("package-lock.json", NPM_LOCK)]);
    write(
        ws.path(),
        ".gitlab-ci.yml",
        "build:\n  script:\n    - npm install\n",
    );
    let report = check_json(&ws, &[]);
    let sd002 = findings_for(&report, "SD002");
    assert_eq!(sd002.len(), 1, "{report}");
    assert_eq!(sd002[0]["location"]["file"], ".gitlab-ci.yml");
}

#[test]
fn circleci_non_frozen_install_reports_sd002() {
    let ws = workspace(&[("package.json", NPM_DEPS), ("package-lock.json", NPM_LOCK)]);
    write(
        ws.path(),
        ".circleci/config.yml",
        "jobs:\n  build:\n    steps:\n      - run: npm install\n",
    );
    let report = check_json(&ws, &[]);
    let sd002 = findings_for(&report, "SD002");
    assert_eq!(sd002.len(), 1, "{report}");
    assert_eq!(sd002[0]["location"]["file"], ".circleci/config.yml");
}

#[test]
fn ci_cargo_build_without_locked_reports_sd002() {
    let manifest = "[package]\nname = \"app\"\n[dependencies]\nserde = \"1\"\n";
    let ws = workspace(&[("Cargo.toml", manifest), ("Cargo.lock", "version = 3\n")]);
    write(
        ws.path(),
        ".github/workflows/ci.yml",
        "jobs:\n  build:\n    steps:\n      - run: cargo build\n",
    );
    let sd002 = findings_for(&check_json(&ws, &[]), "SD002");
    assert_eq!(sd002.len(), 1);
    assert_eq!(sd002[0]["package_manager"], "cargo");
}

#[test]
fn ci_cargo_build_locked_is_clean() {
    let manifest = "[package]\nname = \"app\"\n[dependencies]\nserde = \"1\"\n";
    let ws = workspace(&[("Cargo.toml", manifest), ("Cargo.lock", "version = 3\n")]);
    write(
        ws.path(),
        ".github/workflows/ci.yml",
        "jobs:\n  build:\n    steps:\n      - run: cargo build --locked\n",
    );
    assert!(findings_for(&check_json(&ws, &[]), "SD002").is_empty());
}
