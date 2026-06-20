# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`safe-deps` is a Rust CLI static linter for package-management security practices
(reproducibility, integrity, registry/TLS safety). It scans a workspace and emits
findings without installing dependencies, executing project code, or making network
calls — `safe-deps check` is deterministic and offline by design.

Note: `README.md` still says "design/docs only, no released CLI." That status line
is **stale** — the Phase 1 MVP (scanner, npm/Yarn/pnpm/Bun/pip/uv detection, rules
SD001–SD004, text/JSON output) is implemented and lives under `src/`. Trust the code
over the README status banner.

## Commands

```bash
cargo build                      # debug build
cargo build --release            # release build (LTO, codegen-units=1)
cargo test                       # all tests (inline unit tests + tests/cli.rs)
cargo test <name>                # run tests matching a substring
cargo test --test cli <name>     # run one CLI integration test by name
cargo clippy --all-targets       # lint (no clippy.toml; uses defaults)
cargo fmt                        # format (no rustfmt.toml; uses defaults)
cargo run -- check .             # run the linter against the current dir
cargo run -- check . --format json
cargo run -- explain SD003
cargo run -- list-rules
```

There is **no Rust CI workflow** — only `docs.yml` (markdown lint, spell check,
link check, zizmor). Run `cargo test` / `cargo clippy` locally before committing.

Docs/markdown changes must pass the docs CI:

```bash
npm ci                  # installs markdownlint-cli2 + cspell
npm run lint:markdown
npm run lint:spelling   # add new technical terms to .cspell.json "words"
```

## Architecture

The pipeline is layered, mirroring `docs/design/safe-deps-cli-design.md`. Each stage
hands typed data to the next; `cli::run_check` wires them together:

```
scan (filesystem.rs)          → WorkspaceContext (file list, no content)
detect_all (ecosystems)       → Vec<Project>   (root + package_manager + kind)
facts_for (ecosystems)        → ProjectFacts    (parsers; NO policy decisions)
rules::analyze (rules/mod.rs) → Findings + Diagnostics
reporter_for (report/)        → bytes (text or json)
```

**Parsers produce facts; rules turn facts into findings.** Never put policy/severity
decisions in `ecosystems/` parser code — they belong in `rules/`. The normalized
cross-package-manager settings struct is `InstallSettings` in `ecosystems/mod.rs`;
parsers populate only the fields relevant to their manager, and `None`/empty means
"not declared" (distinct from an explicit unsafe value).

### Key module boundaries

- `rule.rs` owns the core types **and** `Profile` + `Policy`. They live here, not in
  `config.rs`, to break a module cycle: `rule` depends on `ecosystems`/`ci`, and
  `config` depends on `rule`. Don't move `Profile`/`Policy` into `config`.
- `ecosystems/` has two analyzers (`javascript/`, `python/`) registered in
  `ecosystems::analyzers()`, each implementing the `Analyzer` trait
  (`detect` + `facts`). `javascript/mod.rs` is the fullest example (package-manager
  detection, workspace inheritance, monorepo lockfile coverage).
- `ci/mod.rs` is a **Phase 1 stub**: `CiFacts::empty()`. GitHub Actions parsing and
  the CI-dependent rules (SD002/SD008/SD009 command detection) are Phase 2.
- `report/`: `reporter_for` maps `OutputFormat`. SARIF and JUnit are accepted as CLI
  values but currently **fall back to the text reporter** (Phase 2). Only text and
  JSON are real.

### Findings vs Diagnostics

These are deliberately separate. A **Finding** is a policy issue in the target repo
(has rule_id, severity, confidence, remediation). A **Diagnostic** is a limitation of
the linter run itself (unparseable file, expired/unused suppression). Parse failures
emit warning Diagnostics and analysis continues; `--strict-parser-errors` escalates a
run with any parse failure to exit code 4.

### Adding a rule

1. Create `src/rules/sdNNN_name.rs` implementing `Rule` (`id`, `summary`,
   `explanation`, `evaluate`). Co-locate `#[cfg(test)]` unit tests (see
   `sd001_lockfile_missing.rs` for the fixture pattern).
2. Register it in `rules::all_rules()` in `src/rules/mod.rs`.
3. Add CLI integration coverage in `tests/cli.rs` (one safe + one unsafe fixture).

Severity is frequently a function of both `Profile` (balanced/strict/permissive) and
`ProjectKind` (Application/Library/ToolingOnly/Unknown) — `Unknown` stays low-severity
unless the user configures `application_roots`/`library_roots`. See `sd001_severity`.

### Config resolution & determinism

- Precedence (in `cli::resolve_config`): CLI flag → `safe-deps.toml` → env var
  (`SAFE_DEPS_PROFILE`, `SAFE_DEPS_FORMAT`) → default. Invalid config = exit 2.
- All output is deterministically ordered via `report::sort_findings` (severity desc,
  confidence desc, project path, rule id, file, line). The JSON reporter re-sorts the
  **typed** findings, not the serialized strings, so "error" stays ahead of "warning".
- Exit codes: `0` clean, `1` findings at/above `--fail-on`, `2` usage/config error,
  `3` internal error, `4` parse failure under `--strict-parser-errors`.

### Path normalization gotchas

- A project at the workspace root has `dir == "."`. Use `filesystem::project_join`
  (not `Path::join`) to build child paths — it drops the leading `.` so lookups match
  the normalized entries in `WorkspaceContext::files`.
- `Finding::location_path_string` normalizes separators to `/` so suppression globs
  (always written with `/`) match on Windows.
- `cli::normalize_rule_id` resolves `SD3`, `sd3`, and `3` all to `SD003`; reuse it for
  any new rule-id input so filters don't silently drop findings.

## Rule status

SD001–SD004 are implemented. SD005–SD010 are specified in
`docs/design/safe-deps-cli-design.md` (the rule taxonomy and roadmap) but not yet
built. `docs/security-best-practices.md` is the research backing the rule IDs.
