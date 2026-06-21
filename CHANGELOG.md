# Changelog

All notable changes to this project will be documented in this file.

This project is in the design stage. There is no released CLI yet.

## Unreleased

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
