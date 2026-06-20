# Security Policy

`safe-deps` is currently design/docs only. There is no released CLI or
supported production version yet.

## Reporting Security Issues

Please report security issues privately through GitHub's private vulnerability
reporting if it is enabled for this repository. If private reporting is not
available, open a GitHub issue that describes the impact without publishing
exploit details or secrets.

## Scope

In scope:

- Vulnerabilities in released `safe-deps` binaries or packages, once releases
  exist.
- Design issues that would cause `safe-deps check` to execute untrusted project
  code, install dependencies, or make network calls unexpectedly.
- Incorrect handling of secrets in future diagnostics or reports.

Out of scope while the project is design-only:

- Findings about package-manager behavior in third-party projects.
- Vulnerabilities in tools mentioned only as future implementation options.
