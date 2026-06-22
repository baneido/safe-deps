# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/). The CLI
is implemented but not yet published to crates.io, so everything below is
unreleased and not yet tagged.

## Unreleased

- Added a single-source guard for rule metadata (`tests/rule_metadata.rs`): the
  README rule table must match `Rule::summary()` for every registered rule (and
  list the same ids), so documentation can no longer silently drift from the
  code that `list-rules`/`explain` print. Reconciled two pre-existing drifts
  (SD003, SD006) by regenerating the README table from the registry. First
  increment toward #66.
- Hardened the optional `curl-transport` audit fallback: the system `curl` is now
  resolved to a concrete path up front — honoring a `SAFE_DEPS_CURL` override,
  then preferring trusted absolute directories over `PATH`, and skipping relative
  `PATH` entries during the scan — instead of relying solely on exec-time `PATH`
  resolution. When `curl` is found this way a poisoned `PATH` cannot shadow it;
  if it is found in none of those locations the code falls back to the bare name
  (legacy behavior, no regression). The resolved path is surfaced by
  `audit --verbose` and in spawn-error messages, and a CI step now runs the
  `curl-transport` test suite. The default `native-http` build is unaffected.
- Added output-schema and diagnostic regression tests (`tests/output_and_diagnostics.rs`):
  SARIF 2.1.0 structure (driver rules + results contract) and well-formed JUnit
  XML, the `complex-shell-not-fully-parsed` diagnostic firing for
  command/process substitution and heredocs in package-manager commands (and
  staying silent on plain ones), and malformed `pyproject.toml`/`uv.toml`
  surfacing a parse diagnostic that escalates under `--strict-parser-errors`
  rather than being silently treated as no config.
- Added a `docs lint` CI job that runs `markdownlint-cli2` and `cspell` on every
  push and pull request, so the existing Markdown/spelling checks are now a PR
  gate rather than local-only. Uses an SHA-pinned `actions/setup-node` with
  `persist-credentials: false`, matching the repository's CI hardening posture.
- Added a tag-triggered release workflow that publishes per-target binaries
  (Linux and macOS on x86-64 + arm64, Windows on x86-64) to GitHub Releases with
  SHA-256 checksums, a cosign-signed `SHA256SUMS` manifest, and a CycloneDX SBOM.
  README documents downloading and verifying them.
- Corrected the MSRV from `1.80` to **1.86** (dependencies require it; any
  toolchain older than 1.86 fails to build) and added an `msrv` CI job that pins
  it. Added crates.io metadata (`readme`/`keywords`/`categories`) toward a future
  publish.
- Hardened CI to production quality: a Linux/Windows/macOS test matrix,
  informational coverage (`cargo llvm-cov`), GitHub Actions static analysis
  (`actionlint` blocking, `zizmor` informational), and a release-build smoke
  test. SHA-pinned actions, least privilege, and `--locked` are preserved.
- Normalized rendered report paths to `/` separators across text, JSON, JUnit,
  SARIF, and diagnostics output so Windows and Unix runs produce stable paths
  for fixtures, suppressions, and downstream consumers.
- Added `proptest`-based robustness tests for the ecosystem analyzers: property
  tests assert the offline pipeline never panics and is deterministic on random
  and semi-structured manifest content, plus targeted fixtures for edge cases
  (invalid-but-tolerated manifests, hash pins, mixed `uv.toml`, Unicode names,
  deep nesting, and a many-project monorepo).
- `safe-deps audit` now uses an in-process HTTP client (`ureq` + rustls/`ring`)
  by default, so the binary no longer depends on the system `curl` and works on
  minimal containers and Windows out of the box. The previous curl transport is
  retained behind the `curl-transport` feature (build with
  `--no-default-features --features curl-transport`). `--offline` and the cache
  TTL contract are unchanged.
- Added a `complex-shell-not-fully-parsed` info diagnostic that flags CI `run`
  commands using constructs the pragmatic tokenizer cannot fully parse (command
  and process substitution, backticks, heredocs/here-strings, and shell function
  definitions), so reduced-confidence CI rule coverage is surfaced rather than
  silent. Only emitted for commands that resolve to a package-manager invocation
  (to avoid noise) and informational only — it is not a parse failure.
- Added contributor documentation (`CONTRIBUTING.md`, `DEVELOPMENT.md`,
  `RELEASING.md`) and a generated `THIRD_PARTY_LICENSES.md` dependency-license
  report.
- Replaced the unmaintained `serde_yaml` dependency with the maintained
  `serde_yaml_ng` fork (imported under the same name; no API changes).
- Added package-manager security best-practices research.
- Added Rust CLI architecture design.
- Added README roadmap and project status.
- Added a GitHub Actions parser that extracts `run` commands with file and line
  locations plus workflow, job, and step `env` assignments (secret values
  redacted).
- Activated rule `SD002` (non-frozen CI install) using CI command facts.
- Added rule `SD008` (audit missing or disabled), honoring
  `[policy] external_audit`.
- Added rule `SD009` (dangerous install flags such as `--force` and
  `--break-system-packages`).
- Added SARIF 2.1.0 output for GitHub code scanning.
- Added dependency-source classification (registry/git/path/tarball/workspace)
  for npm/Yarn/pnpm/Bun and pip/uv manifests.
- Added rule `SD005` (install-time script/build bypass): pnpm
  `dangerouslyAllowAllBuilds` and a Bun `trustedDependencies` wildcard.
- Added rule `SD006` (unsafe dependency source): floating Git refs, SSH VCS
  sources, direct tarball URLs, and production local-path dependencies, honoring
  `[policy] allow_git_dependencies` and `allow_local_path_dependencies`.
- Added rule `SD007` (dependency confusion): pip/uv `--extra-index-url` and uv
  `index-strategy = "unsafe-best-match"`, escalated to an error under the strict
  profile.
- Added a Cargo (Rust) ecosystem analyzer: detects crates, infers
  application/library kind, and reports a missing `Cargo.lock` via SD001.
- Added a Go modules ecosystem analyzer: detects modules and reports a missing
  `go.sum` via SD001.
- Added JUnit XML output (`--format junit`) for generic CI test dashboards.
- Added `safe-deps audit`, an explicit networked mode that queries OSV for known
  vulnerabilities in pinned dependencies (`Cargo.lock`, `package-lock.json`).
  `safe-deps check` remains fully offline and static.
- Added an on-disk OSV cache with a configurable TTL and an `--offline`
  cache-only mode; HTTP is performed via the system `curl`.
- Added `[[advisory_ignores]]` config (id + required reason + optional expiry),
  honored by `audit`; expired ignores stop applying and surface a note.
