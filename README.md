# safe-deps

`safe-deps` is a Rust CLI linter for package-management security practices
(reproducibility, integrity, registry/TLS safety, supply-chain hardening). It is
built for both developer terminals and CI/CD pipelines.

`safe-deps check` is **static, deterministic, and offline by design**: it does
not install dependencies, execute project code, or make network calls. The
separate `safe-deps audit` command is the *only* networked mode — it explicitly
queries a vulnerability database (OSV).

> Status: the CLI is implemented (Phases 1–5). It is **not yet published to
> crates.io**; install a prebuilt binary from GitHub Releases or build from
> source (both below). Minimum supported Rust version (MSRV): **1.85**.

## Install

### Prebuilt binaries (recommended)

Each tagged release publishes binaries for Linux, macOS, and Windows
(x86-64 and arm64) to [GitHub Releases](https://github.com/baneido/safe-deps/releases),
with a SHA-256 checksum per archive, a signed `SHA256SUMS` manifest, and a
CycloneDX SBOM.

Download the archive for your platform, then verify it before use:

```bash
# Linux, or macOS with GNU coreutils:
sha256sum --check --ignore-missing SHA256SUMS

# macOS default tools:
shasum -a 256 --check --ignore-missing SHA256SUMS

# Windows PowerShell:
Get-FileHash .\safe-deps-<target>.zip -Algorithm SHA256
# Compare the hash with the matching line in SHA256SUMS or the .sha256 file.

# Verify the manifest signature with cosign (keyless; no key to manage).
cosign verify-blob \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp '^https://github\.com/baneido/safe-deps/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

Then extract the archive and put `safe-deps` on your `PATH`.

### From source

```bash
cargo build --release        # binary at target/release/safe-deps
cargo run -- check .         # or run directly from source
```

`cargo install --path .` installs it into `~/.cargo/bin`. A crates.io release is
planned; until then use the binaries or a source build.

## Usage

```bash
safe-deps check .                    # lint the current directory (offline)
safe-deps check . --format json      # text | json | sarif | junit
safe-deps check . --profile strict   # balanced (default) | strict | permissive
safe-deps check . --fail-on warning  # error (default) | warning | info | none
safe-deps audit .                    # query OSV for known vulnerabilities (network)
safe-deps audit . --offline          # use only the local OSV cache
safe-deps explain SD006              # describe a rule
safe-deps list-rules                 # list all rules
safe-deps init                       # write a commented safe-deps.toml
```

`check` exit codes: `0` clean, `1` findings at/above `--fail-on`, `2`
usage/config error, `3` internal error, `4` parse failure under
`--strict-parser-errors`.

## Supported ecosystems

| Ecosystem  | Package managers     |
| ---------- | -------------------- |
| JavaScript | npm, Yarn, pnpm, Bun |
| Python     | pip, uv              |
| Rust       | Cargo                |
| Go         | Go modules           |

## Rules

| ID    | Summary                                                                        |
| ----- | ------------------------------------------------------------------------------ |
| SD001 | Lockfile missing for a manifest that declares dependencies.                    |
| SD002 | CI installs should use a frozen/locked command, not a resolving one.           |
| SD003 | Registry or index uses HTTP, or TLS verification is disabled.                  |
| SD004 | Integrity or checksum validation is disabled.                                  |
| SD005 | Dependency build/lifecycle scripts are broadly enabled.                        |
| SD006 | Dependency resolves from an unsafe source (floating git, tarball, local path). |
| SD007 | Index/source config exposes the project to dependency confusion.               |
| SD008 | CI installs dependencies but no audit command is visible.                      |
| SD009 | CI install commands use a flag that bypasses dependency safety checks.         |

`safe-deps explain <ID>` prints the full rationale and remediation for a rule.

### Ecosystem × rule coverage

`✓` = the rule can fire for that ecosystem today; `–` = not applicable or not yet
implemented. Rules marked **(CI)** are derived from CI commands and only fire
when a supported CI configuration is present (see CI provider support below).

| Ecosystem | SD001 | SD002 (CI) | SD003 | SD004 | SD005 | SD006 | SD007 | SD008 (CI) | SD009 (CI) |
| --------- | :---: | :--------: | :---: | :---: | :---: | :---: | :---: | :--------: | :--------: |
| npm       |   ✓   |     ✓      |   ✓   |   ✓   |   –   |   ✓   |   –   |     ✓      |     ✓      |
| Yarn      |   ✓   |     ✓      |   ✓   |   ✓   |   –   |   ✓   |   –   |     ✓      |     ✓      |
| pnpm      |   ✓   |     ✓      |   ✓   |   –   |   ✓   |   ✓   |   –   |     ✓      |     ✓      |
| Bun       |   ✓   |     ✓      |   –   |   –   |   ✓   |   ✓   |   –   |     ✓      |     ✓      |
| pip       |   –   |     ✓      |   ✓   |   ✓   |   –   |   ✓   |   ✓   |     ✓      |     ✓      |
| uv        |   ✓   |     ✓      |   ✓   |   –   |   –   |   ✓   |   ✓   |     ✓      |     ✓      |
| Cargo     |   ✓   |     ✓      |   –   |   –   |   –   |   –   |   –   |     –      |     –      |
| Go        |   ✓   |     ✓      |   –   |   –   |   –   |   –   |   –   |     –      |     –      |

Notes:

- pip has no conventional lockfile, so SD001 does not apply; its integrity is
  assessed through `--require-hashes` (SD004) instead.
- SD006 (unsafe dependency source) covers JavaScript and Python manifests today.
  Extending it to Cargo/Go is tracked separately.
- For Cargo/Go, SD002 flags a non-reproducible CI build (`cargo build`/`test`
  without `--locked`/`--frozen`; `go build`/`test` with `-mod=mod`). SD008/SD009
  do not yet recognize Cargo/Go commands.

## CI provider support

CI-aware rules (SD002, SD008, SD009) read commands and `env` from these CI
providers:

| Provider       | Config file(s)                |
| -------------- | ----------------------------- |
| GitHub Actions | `.github/workflows/*.yml\|yaml` |
| GitLab CI      | `.gitlab-ci.yml`              |
| CircleCI       | `.circleci/config.yml`        |

Other providers (Jenkins, Azure Pipelines, …) are not yet parsed.

## Output formats

`text` (default) and `json` are the primary formats. `sarif` (2.1.0, for GitHub
code scanning) and `junit` (for generic CI test dashboards) are also supported.

## Configuration

Configuration is optional. `safe-deps init` writes a commented `safe-deps.toml`.
Resolution precedence is: CLI flag → `safe-deps.toml` → environment variable
(`SAFE_DEPS_PROFILE`, `SAFE_DEPS_FORMAT`) → default.

Key settings:

- **Profiles** — `balanced` (default), `strict`, `permissive` adjust severities.
- **`[policy]`** — `application_roots` / `library_roots` (globs that classify a
  project's kind), `allow_git_dependencies`, `allow_local_path_dependencies`,
  and `external_audit` (opt out of SD008 when audits run elsewhere).
- **`[[suppressions]]`** — silence a rule for a path, with an optional expiry.
- **`[[advisory_ignores]]`** — for `audit`: ignore an advisory id with a required
  reason and optional expiry; expired ignores stop applying and surface a note.

## `safe-deps audit`

`audit` is a separate, explicitly-networked pipeline. It extracts pinned,
registry-sourced coordinates from `Cargo.lock` and `package-lock.json`, queries
OSV for known advisories, and caches results on disk (default TTL 24h; HTTP via
the system `curl`). `--offline` uses only the cache. `check` never touches the
network.

## Contributing

- [CONTRIBUTING.md](CONTRIBUTING.md) — how to report issues and land a change.
- [DEVELOPMENT.md](DEVELOPMENT.md) — build, test, and architecture.
- [RELEASING.md](RELEASING.md) — the release checklist (maintainers).

## Design documents

- [Security best practices research](docs/security-best-practices.md)
- [CLI architecture design](docs/design/safe-deps-cli-design.md)

## Roadmap

The detailed roadmap lives in the
[CLI architecture design](docs/design/safe-deps-cli-design.md#roadmap). At a high
level, Phases 1–5 below are implemented; remaining work is tracked in the issue
tracker.

- Phase 0: design and research. ✅
- Phase 1: Rust static linter MVP for npm, Yarn, pnpm, Bun, pip, and uv. ✅
- Phase 2: CI-aware checks (GitHub Actions) and SARIF output. ✅
- Phase 3: supply-chain hardening rules and policy profiles. ✅
- Phase 4: additional ecosystems (Cargo, Go) and JUnit output. ✅
- Phase 5: explicit networked audit mode (OSV). ✅

Planned next: a production Rust CI workflow, more CI providers, SD006 for
Cargo/Go, and additional ecosystems (Composer, Bundler, Gradle/Maven, NuGet).

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
Third-party dependency licenses are catalogued in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
