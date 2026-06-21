# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/). The CLI
is implemented but not yet published to crates.io, so everything below is
unreleased and not yet tagged.

## Unreleased

- `safe-deps audit` now uses an in-process HTTP client (`ureq` + rustls/`ring`)
  by default, so the binary no longer depends on the system `curl` and works on
  minimal containers and Windows out of the box. The previous curl transport is
  retained behind the `curl-transport` feature (build with
  `--no-default-features --features curl-transport`). `--offline` and the cache
  TTL contract are unchanged.
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
