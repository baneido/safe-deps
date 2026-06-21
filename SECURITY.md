# Security Policy

`safe-deps` is implemented (CLI, ecosystem analyzers, rules SD001–SD009, and the
optional networked `audit` mode) at version `0.1.0`. It is not yet published to
crates.io, so it is currently used by building from source. There is no stable
release line with backported fixes yet; fixes land on `main`.

## Reporting Security Issues

Please report security issues privately through GitHub's private vulnerability
reporting if it is enabled for this repository. If private reporting is not
available, open a GitHub issue that describes the impact without publishing
exploit details or secrets.

## Scope

In scope:

- Vulnerabilities in `safe-deps` built from source (and in released binaries or
  packages, once releases exist).
- Any case where `safe-deps check` executes untrusted project code, installs
  dependencies, or makes network calls — `check` is designed to be fully static
  and offline; network access is confined to the explicit `safe-deps audit` mode.
- Incorrect handling of secrets in diagnostics or reports (the GitHub Actions
  parser redacts `env` values; a regression that leaks them is in scope).

Out of scope:

- Findings `safe-deps` reports about package-manager behavior in the third-party
  projects it scans (these are linter output, not vulnerabilities in this tool).
- Vulnerabilities in tools mentioned only as future implementation options.
