# Development

How to build, test, and navigate `safe-deps`. For contribution process see
[CONTRIBUTING.md](CONTRIBUTING.md); for releases see [RELEASING.md](RELEASING.md).

## Prerequisites

- A Rust toolchain. The crate targets **edition 2021** with an **MSRV of 1.80**;
  develop on stable. `rustfmt` and `clippy` components are required for the
  local gate (`rustup component add rustfmt clippy`).
- Node.js (only for the Markdown/spelling lint: `markdownlint-cli2`, `cspell`).
- Optional: [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) and
  [`cargo-audit`](https://github.com/rustsec/rustsec) to run the supply-chain
  gate locally (CI runs them regardless).

## Common commands

```bash
cargo build                      # debug build
cargo build --release            # release build (LTO, codegen-units=1)
cargo test                       # all tests (inline unit tests + tests/cli.rs)
cargo test <name>                # tests matching a substring
cargo test --test cli <name>     # one CLI integration test by name
cargo clippy --all-targets       # lint (defaults; no clippy.toml)
cargo fmt                        # format (defaults; no rustfmt.toml)

cargo run -- check .             # run the linter against the current dir
cargo run -- check . --format json
cargo run -- explain SD003
cargo run -- list-rules
```

## Architecture

The `check` pipeline is layered; each stage hands typed data to the next and
`check_runner::run` wires them together:

```text
scan (filesystem.rs)          -> WorkspaceContext (file list, no content)
detect_all (ecosystems)       -> Vec<Project>   (root + package_manager + kind)
facts_for (ecosystems)        -> ProjectFacts    (parsers; NO policy decisions)
rules::analyze (rules/mod.rs) -> Findings + Diagnostics
reporter_for (report/)        -> bytes (text, json, sarif, or junit)
```

`safe-deps audit` (`audit/`) is a **separate, explicitly-networked** pipeline
that bypasses rules/report: `scan -> audit::collect -> VulnerabilitySource (OSV
over the HTTP transport) -> audit::render`. Network access lives **only** in the
transport. `check` never touches the network — keep it that way.

### Module boundaries

- **Parsers produce facts; rules turn facts into findings.** Never put
  policy/severity decisions in `src/ecosystems/` parser code — they belong in
  `src/rules/`. The normalized cross-package-manager settings struct is
  `InstallSettings` in `ecosystems/mod.rs`; `None`/empty means "not declared",
  distinct from an explicit unsafe value.
- `src/ecosystems/` has four analyzers (`javascript`, `python`, `cargo`, `go`)
  registered in `ecosystems::analyzers()`, each implementing the `Analyzer`
  trait (`detect` + `facts`).
- `src/ci/` parses CI workflows into `CiFacts` (run commands with file/line plus
  `env`) via pluggable providers (GitHub Actions, GitLab CI, CircleCI). These
  feed the CI-derived rules (SD002/SD008/SD009). `ci/command.rs` is a pragmatic
  shell tokenizer — not a full shell parser.
- `src/report/`: `reporter_for` maps an `OutputFormat` to a reporter. Text, JSON,
  SARIF (2.1.0), and JUnit are all implemented.

### Findings vs Diagnostics

A **Finding** is a policy issue in the target repo (rule id, severity,
confidence, remediation). A **Diagnostic** is a limitation of the linter run
itself (unparseable file, expired/unused suppression). Parse failures emit
warning Diagnostics and analysis continues;
`--strict-parser-errors` escalates a run with any parse failure to exit code 4.

### Determinism and exit codes

- Config precedence (`cli::resolve_config`): CLI flag -> `safe-deps.toml` -> env
  var (`SAFE_DEPS_PROFILE`, `SAFE_DEPS_FORMAT`) -> default. Invalid config exits 2.
- All output is deterministically ordered via `report::sort_findings` (severity,
  confidence, project path, rule id, file, line).
- Exit codes: `0` clean, `1` findings at/above `--fail-on`, `2` usage/config
  error, `3` internal error, `4` parse failure under `--strict-parser-errors`.

## Adding a rule

1. Create `src/rules/sdNNN_name.rs` implementing `Rule` (`id`, `summary`,
   `explanation`, `evaluate`), with co-located `#[cfg(test)]` tests. See
   `sd001_lockfile_missing.rs` for the fixture pattern.
2. Register it in `rules::all_rules()` in `src/rules/mod.rs`.
3. Add CLI integration coverage in `tests/cli.rs` (one safe + one unsafe fixture).
4. Update the rule tables in [README.md](README.md) and the taxonomy in
   `docs/design/safe-deps-cli-design.md`.

Severity is often a function of both `Profile` (balanced/strict/permissive) and
`ProjectKind` (Application/Library/ToolingOnly/Unknown); `Unknown` stays
low-severity unless the user configures `application_roots`/`library_roots`.

## Further reading

- [CLI architecture design](docs/design/safe-deps-cli-design.md) — full pipeline
  and rule roadmap.
- [Security best practices research](docs/security-best-practices.md) — the
  research backing the rule IDs.
