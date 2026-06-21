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
