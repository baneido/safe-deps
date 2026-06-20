# safe-deps

`safe-deps` is a planned Rust CLI linter for package-management security best
practices. It is intended for both developer terminals and CI/CD pipelines.

The default `safe-deps check` workflow will be static and deterministic: it
should not install dependencies, execute project code, or make network calls.

## Initial Scope

MVP package managers:

- npm
- Yarn
- pnpm
- Bun
- pip
- uv

Future package managers and ecosystems:

- Composer
- Bundler
- Cargo
- Go modules
- Gradle and Maven
- NuGet

## Design Documents

- [Security best practices research](docs/security-best-practices.md)
- [CLI architecture design](docs/design/safe-deps-cli-design.md)

## Roadmap

### Phase 0: Design and Research

- Security best-practice research across major package managers.
- CLI architecture and rule model design.
- Initial rule taxonomy for supply-chain linting.

### Phase 1: MVP Static Linter

- Rust CLI scaffold.
- Workspace scanning and project detection.
- `safe-deps.toml` configuration and suppression support.
- npm, Yarn, pnpm, Bun, pip, and uv analyzers.
- Initial rules for lockfiles, frozen installs, insecure registries, and
  disabled integrity checks.
- Text and JSON output.

### Phase 2: CI-Aware Checks

- GitHub Actions parsing.
- CI install-command checks.
- Audit-command detection.
- Dangerous install flag detection.
- SARIF output for code scanning integrations.

### Phase 3: Supply-Chain Hardening

- Install-time script and build allowlist checks.
- Unsafe dependency source checks.
- Dependency-confusion checks for multi-index and registry configurations.
- Strict, balanced, and permissive profiles.

### Phase 4: Publishing and Ecosystem Expansion

- Publishing provenance checks.
- Composer, Bundler, Cargo, Go modules, Gradle/Maven, and NuGet support.
- JUnit output.
- GitHub Action wrapper.

### Phase 5: Optional Audit Mode

- Explicit `safe-deps audit` command for networked vulnerability checks.
- OSV or package-manager audit integration.
- Advisory ignore metadata with required reasons and optional expiry.
