# Changelog

All notable changes to this project will be documented in this file.

This project is in the design stage. There is no released CLI yet.

## Unreleased

- Added package-manager security best-practices research.
- Added Rust CLI architecture design.
- Added README roadmap and project status.
- Added `safe-deps audit`, an explicit networked mode that queries OSV for known
  vulnerabilities in pinned dependencies (`Cargo.lock`, `package-lock.json`).
  `safe-deps check` remains fully offline and static.
- Added an on-disk OSV cache with a configurable TTL and an `--offline`
  cache-only mode; HTTP is performed via the system `curl`.
- Added `[[advisory_ignores]]` config (id + required reason + optional expiry),
  honored by `audit`; expired ignores stop applying and surface a note.
