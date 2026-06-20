# safe-deps

> Status: design/docs only. There is no released CLI or installable crate yet.
> This repository has docs-only CI, but no production `safe-deps` CI integration.

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

The detailed roadmap lives in the
[CLI architecture design](docs/design/safe-deps-cli-design.md#roadmap).

At a high level:

- Phase 0: design and research.
- Phase 1: Rust static linter MVP for npm, Yarn, pnpm, Bun, pip, and uv.
- Phase 2: CI-aware checks and SARIF output.
- Phase 3: supply-chain hardening rules and policy profiles.
- Phase 4: publishing checks and additional ecosystems.
- Phase 5: explicit networked audit mode.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
