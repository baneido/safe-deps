# safe-deps CLI Design

Last reviewed: 2026-06-21

## Summary

`safe-deps` is a Rust CLI linter for package-management security practices. It
is designed for developer terminals and CI/CD, with deterministic static
analysis as the default behavior: no package installation, no project code
execution, and no network access during `safe-deps check`.

The MVP targets:

- JavaScript and TypeScript: npm, Yarn, pnpm, Bun
- Python: pip, uv

Future releases can add Composer, Bundler, Cargo, Go modules, Gradle, Maven,
and NuGet without changing the user-facing model.

## Goals

- Provide fast, deterministic checks for package-management security posture.
- Detect reproducibility, integrity, script-execution, registry, source, audit,
  dangerous flag, and provenance issues.
- Work well in local terminals, pre-commit hooks, and CI pipelines.
- Emit human-readable output and machine-readable reports, including SARIF.
- Keep rule behavior configurable without making configuration mandatory.
- Preserve a clean internal boundary for future analyzer plugins.

## Non-Goals for the MVP

- Do not execute package managers.
- Do not install dependencies.
- Do not query vulnerability databases during the default lint run.
- Do not build a plugin ABI in the first release.
- Do not attempt full shell interpretation.
- Do not auto-fix manifests or CI workflows in the MVP.

Networked vulnerability lookup can be added later as a separate command such as
`safe-deps audit`, while `safe-deps check` remains static and reproducible.

## Recommended Architecture

The first implementation should be a Rust native CLI with embedded analyzers and
rules. This gives the project a single distributable binary, predictable CI
performance, good parser ergonomics, and no dependency on the package-manager
runtime being linted.

```text
CLI
  -> Workspace Scanner
  -> Project Detector
  -> Ecosystem Fact Extractors
     -> npm / yarn / pnpm / bun / pip / uv
  -> CI Fact Extractors
     -> GitHub Actions / GitLab CI / shell best effort
  -> Rule Engine
  -> Finding Aggregator
  -> Reporters
     -> text / json / sarif / junit
```

The system is layered:

1. Scanning discovers files and candidate project roots.
2. Fact extraction parses manifests, lockfiles, configs, and CI files.
3. Rules evaluate normalized facts and emit findings.
4. Reporters render findings without re-running rule logic.

Parsers produce facts. Rules turn facts into findings based on profile and
configuration.

## Core Data Model

```rust
pub struct WorkspaceContext {
    pub root: PathBuf,
    pub files: Vec<WorkspaceFile>,
    pub config: Config,
}

pub struct Project {
    pub root: PathBuf,
    pub ecosystem: Ecosystem,
    pub package_manager: PackageManager,
    pub kind: ProjectKind,
}

pub enum ProjectKind {
    Application,
    Library,
    ToolingOnly,
    Unknown,
}

pub struct ProjectFacts {
    pub project: Project,
    pub manifest: Option<FileFact>,
    pub lockfiles: Vec<FileFact>,
    pub configs: Vec<ConfigFact>,
    pub dependencies: Vec<DependencySpec>,
    pub package_sources: Vec<PackageSource>,
    pub install_settings: InstallSettings,
}

pub struct CiFacts {
    pub files: Vec<CiFile>,
    pub commands: Vec<CiCommand>,
    pub env: Vec<EnvAssignment>,
}

pub struct Finding {
    pub rule_id: RuleId,
    pub severity: Severity,
    pub confidence: Confidence,
    pub message: String,
    pub location: Option<Location>,
    pub project_root: PathBuf,
    pub ecosystem: Ecosystem,
    pub package_manager: Option<PackageManager>,
    pub remediation: Option<String>,
}

pub enum Severity {
    Error,
    Warning,
    Info,
}

pub enum Confidence {
    High,
    Medium,
    Low,
}
```

Checks vary in precision. `strict-ssl=false` is exact; "audit command not found
in CI" is heuristic. CI exit decisions should be severity-based, while display
ordering should consider severity and confidence.

## Internal Interfaces

```rust
pub trait Analyzer {
    fn name(&self) -> &'static str;
    fn detect(&self, ctx: &WorkspaceContext) -> Vec<Project>;
    fn facts(&self, project: &Project, ctx: &WorkspaceContext) -> Result<ProjectFacts>;
}

pub trait Rule {
    fn id(&self) -> RuleId;
    fn evaluate(&self, input: &RuleInput) -> Vec<Finding>;
}

pub trait Reporter {
    fn format(&self, report: &Report) -> Result<Vec<u8>>;
}
```

The MVP should keep these as in-process traits. A later plugin system can move
analyzers into separate crates or WASM modules once the rule and report formats
stabilize.

## Proposed Rust Layout

Start with one crate and clear module boundaries. Splitting into multiple crates
too early adds release and API overhead before the core model has settled.

```text
safe-deps/
  Cargo.toml
  src/
    main.rs
    cli.rs
    config.rs
    diagnostics.rs
    filesystem.rs
    project.rs
    rule.rs
    report/
      mod.rs
      text.rs
      json.rs
      sarif.rs
      junit.rs
    ci/
      mod.rs
      github_actions.rs
      gitlab_ci.rs
      shell.rs
    ecosystems/
      mod.rs
      javascript/
        mod.rs
        package_json.rs
        npm.rs
        yarn.rs
        pnpm.rs
        bun.rs
      python/
        mod.rs
        requirements.rs
        pyproject.rs
        pip.rs
        uv.rs
    rules/
      mod.rs
      sd001_lockfile_missing.rs
      sd002_non_frozen_ci_install.rs
      sd003_insecure_registry.rs
      sd004_integrity_disabled.rs
      sd005_script_build_bypass.rs
      sd006_unsafe_package_source.rs
      sd007_dependency_confusion.rs
      sd008_audit_missing.rs
      sd009_dangerous_install_flags.rs
      sd010_publish_provenance.rs
```

### Module Responsibilities

`cli.rs`

- Define CLI with `clap`.
- Support `check`, `explain`, `list-rules`, and eventually `init`.
- Keep all command defaults visible and documented.

`filesystem.rs`

- Walk the repository with the `ignore` crate.
- Respect `.gitignore` and configured include/exclude patterns.
- Exclude heavy generated directories by default: `.git`, `node_modules`,
  `.venv`, `venv`, `target`, `vendor`, `.tox`, `.mypy_cache`, `.pytest_cache`.

`project.rs`

- Represent detected projects and monorepo relationships.
- Infer `ProjectKind` conservatively from manifest metadata and configured
  roots. Unknown projects should avoid high-severity findings for rules where
  library/application policy differs.

`ci/`

- Extract commands and environment assignments from CI files.
- MVP priority: GitHub Actions first, GitLab CI second, shell scripts best
  effort.
- Preserve file and line locations so findings point at the exact unsafe
  command where possible.

`ecosystems/`

- Parse manifests, lockfiles, and package-manager config into normalized facts.
- Avoid policy decisions in parser code.
- Keep ecosystem-specific type definitions local where possible, then map into
  common `ProjectFacts`.

`rules/`

- Evaluate facts against policy.
- Emit findings with rule ID, severity, confidence, location, and remediation.
- Keep each rule focused on one security principle, even when implementation
  contains package-manager-specific branches.

`report/`

- Render a stable `Report`.
- Keep output formatting independent from rule execution.
- Support terminal text, JSON, SARIF, and JUnit.

## CLI UX

The default command should be optimized for the common path:

```bash
safe-deps check
safe-deps check --format sarif --output safe-deps.sarif
safe-deps check --profile strict --fail-on warning
safe-deps explain SD003
safe-deps list-rules
safe-deps init
```

Recommended options:

```text
safe-deps check [PATH]
  --config <PATH>          Config path, default safe-deps.toml if present
  --profile <NAME>         balanced, strict, permissive
  --format <NAME>          text, json, sarif, junit
  --output <PATH>          Write report to file
  --fail-on <LEVEL>        error, warning, info, none
  --no-gitignore           Ignore .gitignore while scanning
  --include <GLOB>         Additional include glob
  --exclude <GLOB>         Additional exclude glob
  --ecosystem <NAME>       Restrict to npm, yarn, pnpm, bun, pip, uv
  --rule <ID>              Restrict to a rule ID
  --offline                Default behavior for check; explicit for clarity
  --verbose                Print detection details
  --quiet                  Only print findings summary
```

### Exit Codes

```text
0  No findings at or above fail threshold
1  Findings at or above fail threshold
2  Usage or configuration error
3  Internal error
4  Partial analysis due to unreadable files or parse failures, when strict
   failure behavior is enabled
```

Parse failures should normally emit warning-level diagnostics and continue. CI
users can opt into strict parser failure behavior later.

## Configuration

Use `safe-deps.toml` as the project-level configuration file.

```toml
profile = "balanced"
fail_on = "error"
format = "text"

[workspace]
exclude = ["fixtures/**", "vendor/**"]

[policy]
application_roots = ["apps/**", "services/**"]
library_roots = ["packages/**"]
allow_local_path_dependencies = false
allow_git_dependencies = false
require_audit_in_ci = true

[rules.SD001]
level = "error"

[rules.SD008]
level = "warning"

[[suppressions]]
rule = "SD006"
path = "tools/dev-fixtures/package.json"
reason = "Fixture intentionally uses a git dependency"
expires = "2026-12-31"
```

All CLI options that change analysis behavior should have a config-file
equivalent. CLI arguments override config values. Environment variables should
be limited to CI convenience, such as `SAFE_DEPS_PROFILE` and
`SAFE_DEPS_FORMAT`.

### Profiles

`balanced`

- Default profile.
- High-confidence TLS, lockfile, and integrity failures are errors.
- Audit absence, script policy gaps, and provenance gaps are warnings or info.

`strict`

- Recommended for CI on public repositories and release pipelines.
- Audit absence, dependency-confusion risk, and script/build bypasses can fail
  the build.
- Expired suppressions are errors.

`permissive`

- Recommended for initial adoption.
- Only the highest-signal findings fail by default.
- Most compatibility and workflow gaps remain warnings or info.

## Suppression Model

Use centralized suppressions in `safe-deps.toml`. Avoid inline suppressions in
manifests because many target files are JSON, TOML, lockfiles, or CI YAML where
comments and tool-specific metadata are inconsistent.

Every suppression should require:

- `rule`
- `path`
- `reason`

Every suppression should support:

- `expires`
- `line`
- `package_manager`
- `ecosystem`

Rules:

- Missing reasons are configuration errors.
- Expired suppressions are warnings in `balanced` and errors in `strict`.
- Unused suppressions should be reported as info by default.
- Suppressions should match normalized paths relative to the workspace root.

## MVP Rule Set

The MVP rule IDs should match the research document in
`docs/security-best-practices.md`.

| ID | Name | Default |
| --- | --- | --- |
| SD001 | Lockfile missing | error for applications, warning for unknown/library |
| SD002 | Non-frozen CI install | error |
| SD003 | Insecure registry or TLS bypass | error |
| SD004 | Integrity/checksum validation disabled | error |
| SD005 | Install-time script/build bypass | warning |
| SD006 | Unsafe dependency source | warning |
| SD007 | Dependency confusion via index/source config | warning, error in strict |
| SD008 | Audit missing or disabled | warning |
| SD009 | Dangerous install flags | warning, error for high-risk flags |
| SD010 | Publish provenance missing | info, warning in strict |

### Rule Details

SD001: Lockfile missing

- npm: `package.json` with dependencies but no `package-lock.json` or
  `npm-shrinkwrap.json`.
- Yarn: `package.json` with Yarn evidence but no `yarn.lock`.
- pnpm: `pnpm-lock.yaml` missing for pnpm projects.
- Bun: `bun.lock` missing for Bun projects.
- pip: requirements-based deploy projects without pinned/hash-controlled
  requirements should not be treated as having a conventional lockfile.
- uv: `uv.lock` missing for uv-managed projects.

SD002: Non-frozen CI install

- Flag `npm install` in CI when `npm ci` is expected.
- Flag `yarn install` without `--immutable` for Yarn Berry.
- Flag `pnpm install` without `--frozen-lockfile` when CI default cannot be
  proven.
- Flag `bun install` without `--frozen-lockfile`; allow `bun ci`.
- Flag `uv sync` without `--locked` for CI reproducibility checks.
- Flag `pip install -r requirements.txt` without `--require-hashes` in strict
  deploy profiles.

SD003: Insecure registry or TLS bypass

- Flag HTTP registries outside local/test exceptions.
- Flag npm/pnpm `.npmrc` `strict-ssl=false`.
- Flag Yarn `unsafeHttpWhitelist` outside allowed hosts.
- Flag pip `--trusted-host`, `PIP_TRUSTED_HOST`, and HTTP indexes.
- Flag uv `allow-insecure-host`.

SD004: Integrity/checksum validation disabled

- Flag npm `package-lock=false`.
- Flag Yarn `checksumBehavior: ignore`; treat `update` in CI as suspicious.
- Flag pnpm `--update-checksums` in normal CI installs.
- Flag Bun environment variables that skip lockfile load/save in CI.
- Flag pip deployment requirements that lack hashes in strict profile.

SD005: Install-time script/build bypass

- Flag broad lifecycle script enablement in high-risk contexts.
- Flag pnpm `dangerouslyAllowAllBuilds`.
- Flag Bun broad or unexplained `trustedDependencies`.
- Flag Composer-style plugin execution later when Composer support is added.

SD006: Unsafe dependency source

- Flag floating Git dependencies such as branch refs.
- Flag direct tarball URLs without integrity metadata.
- Flag local path dependencies in production dependency groups.
- Flag SSH-based VCS dependencies in CI release workflows as warning.

SD007: Dependency confusion via index/source config

- Flag pip `--extra-index-url` without configured mitigation.
- Flag uv `index-strategy = "unsafe-best-match"`.
- Flag unscoped private registries or multiple package sources where package
  ownership is ambiguous.

SD008: Audit missing or disabled

- Detect whether CI contains package-manager audit commands.
- Do not run audits during `check`.
- Warn when a project has external dependencies and no audit path is visible.

SD009: Dangerous install flags

- Flag `--force`, `--legacy-peer-deps`, `--no-lockfile`,
  `--ignore-platform-reqs`, `--break-system-packages`, `--no-build-isolation`,
  and similar bypass flags.
- Severity depends on context and profile.

SD010: Publish provenance missing

- Detect publish workflows for npm and uv.
- Warn or inform when trusted publishing/OIDC/provenance is absent.
- Treat this as lower priority than install safety in the MVP.

## Ecosystem Detection

Detection should combine file presence, package-manager metadata, and lockfile
evidence.

JavaScript:

- `package.json` is the base signal.
- `packageManager` field identifies npm, Yarn, pnpm, or Bun when present.
- Lockfiles refine detection: `package-lock.json`, `npm-shrinkwrap.json`,
  `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`.
- Config files refine behavior: `.npmrc`, `.yarnrc.yml`, `pnpm-workspace.yaml`,
  `bunfig.toml`.

Python:

- `pyproject.toml` is a base signal.
- `uv.lock` or `[tool.uv]` identifies uv.
- `requirements*.txt` and `constraints*.txt` identify pip workflows.
- `pip.conf`, `pip.ini`, and CI env assignments affect pip behavior.

Monorepos:

- Detect every project root independently.
- Avoid duplicate findings when one root-level lockfile intentionally covers
  child packages.
- Prefer package-manager workspace declarations over directory heuristics.

## CI Parsing Strategy

MVP priority:

1. GitHub Actions: `.github/workflows/*.yml`, `.yaml`
2. GitLab CI: `.gitlab-ci.yml`
3. Shell scripts referenced by common CI files, best effort

GitHub Actions parsing should extract:

- `jobs.*.steps[*].run`
- `jobs.*.steps[*].env`
- workflow-level and job-level `env`
- matrix-expanded content is not required in MVP

Command parsing should be pragmatic:

- Split simple commands enough to find package-manager invocations and flags.
- Preserve line locations for direct `run` lines.
- Treat complex shell constructs as lower-confidence findings.
- Do not execute shell or expand variables.

## Output Formats

Text:

- Default for terminals.
- Group by severity, then project, then rule.
- Include remediation text and config suppression hint.

JSON:

- Stable schema for integrations.
- Include tool version, config profile, analyzed path, findings, and
  diagnostics.

SARIF:

- First-class CI output for GitHub code scanning and compatible platforms.
- Map each rule to SARIF `rules`.
- Map findings to file regions when available.

JUnit:

- Useful for generic CI test-report dashboards.
- Each rule/project combination can be represented as a testcase.

## Error Handling

The tool should prefer partial progress over failing the entire analysis.

- Unreadable files: emit diagnostic, continue.
- Unsupported lockfile version: emit warning-level diagnostic, continue.
- Invalid config: fail with exit code 2.
- Internal invariant violation: fail with exit code 3.
- Parse failure in strict parser mode: fail with exit code 4.

Diagnostics are separate from findings. Findings represent policy issues in the
target project; diagnostics represent limitations or failures of the linter run.

## Performance Design

Expected repositories can be large monorepos. The implementation should:

- Use the `ignore` crate for fast walking and ignore-file handling.
- Parse independent project roots in parallel with `rayon`.
- Avoid reading lockfiles repeatedly.
- Cache parsed file contents in a workspace-level file store.
- Skip generated directories by default.
- Keep network access out of `check`.

The target for MVP should be sub-second on small projects and a few seconds on
large monorepos with thousands of files.

## Recommended Dependencies

Core:

- `clap` for CLI.
- `serde`, `serde_json`, `toml`, `serde_yaml` for parsing and output.
- `miette` or `ariadne` for readable diagnostics.
- `thiserror` for error types.
- `ignore` for workspace scanning.
- `globset` for include/exclude/suppression matching.
- `rayon` for parallel project analysis.

Format-specific:

- `serde_json` for JSON and SARIF.
- `quick-xml` or manual XML writer for JUnit.

Testing:

- `insta` for snapshot output.
- `assert_cmd` and `predicates` for CLI tests.
- `tempfile` for fixture-based integration tests.

Avoid adding a JavaScript or Python runtime dependency. The tool should parse
files directly.

## Testing Strategy

Unit tests:

- Parser behavior for each manifest/config format.
- Rule evaluation for each rule and package manager.
- Suppression matching and profile severity overrides.

Fixture tests:

- Minimal npm, Yarn, pnpm, Bun, pip, and uv projects.
- Monorepo fixtures with multiple package managers.
- GitHub Actions workflows with safe and unsafe installs.
- Invalid YAML/TOML/JSON fixtures to verify diagnostics.

CLI integration tests:

- `safe-deps check` text output.
- JSON schema stability.
- SARIF file generation.
- Exit-code behavior for `--fail-on`.
- Config override behavior.

Snapshot tests:

- Human text output.
- `explain SDxxx` output.
- SARIF skeleton and rule metadata.

Regression tests:

- Every false positive fixed in the future should get a fixture.
- Every new rule should include at least one safe and one unsafe fixture.

## Security Considerations

`safe-deps` analyzes potentially untrusted repositories. It must not execute
project code, install dependencies, source shell files, or import target
language modules during default checks.

Additional precautions:

- Treat all parsed files as untrusted input.
- Avoid following symlinks outside the workspace by default.
- Do not print secret-looking environment variable values from CI files.
- Redact tokens in URLs and environment assignments.
- Avoid automatic network calls in `check`.
- Keep SARIF messages concise and non-secret-bearing.

## Release and Distribution

MVP distribution should target:

- GitHub releases with static binaries for Linux, macOS, and Windows.
- `cargo install safe-deps` once crate publication is appropriate.
- GitHub Action wrapper after the CLI stabilizes.

Nice-to-have later:

- Homebrew tap.
- npm package wrapper that downloads the binary.
- pre-commit hook.
- Docker image for locked CI environments.

## Roadmap

### Phase 0: Design and Research

- Security best-practice research document.
- CLI architecture design.
- Rule taxonomy and output model.

### Phase 1: MVP Static Linter

- Rust CLI scaffold.
- Workspace scanner.
- Config loading and suppression matching.
- npm, Yarn, pnpm, Bun, pip, and uv detection.
- SD001-SD004 implemented.
- Text and JSON output.
- Basic CLI integration tests.

### Phase 2: CI-Aware Rules

- GitHub Actions parser.
- SD002, SD008, and SD009 implemented with CI command facts.
- SARIF output.
- Monorepo fixture coverage.

### Phase 3: Supply-Chain Hardening Rules

- SD005-SD007 implemented across MVP package managers.
- Dependency source classification.
- Registry/index policy checks.
- Strict/permissive profile refinements.

### Phase 4: Publishing and Ecosystem Expansion

- SD010 for npm and uv publishing workflows.
- Composer, Bundler, Cargo, Go modules, Gradle/Maven, and NuGet analyzers.
- JUnit output.
- GitHub Action wrapper.

### Phase 5: Optional Audit Mode

- `safe-deps audit` as an explicit networked mode.
- OSV or ecosystem audit-tool integration.
- Caching and rate-limit strategy.
- Advisory ignore metadata with expiry and reason.

## Final Design Decisions

- `safe-deps init` should be non-interactive by default and create a minimal
  commented `safe-deps.toml`. Interactive setup can be added later as
  `safe-deps init --interactive`.
- SARIF output belongs in Phase 2 with the first CI-aware rules. Phase 1 should
  focus on the static analysis core, text output, and JSON output.
- `ProjectKind::Unknown` should remain unknown unless the tool has strong
  evidence or the user configures application/library roots. Unknown projects
  should receive lower-severity lockfile findings when package-type policy
  differs.
- `pip --require-hashes` should be a strict-profile warning by default, and an
  error only when the project declares a deploy/release profile that expects
  hash-locked requirements.
- The default command should be `safe-deps check`, but invoking `safe-deps`
  without a subcommand should behave the same as `safe-deps check`.
- The MVP should not implement autofix. Fix suggestions should be remediation
  text only until the parser and rule model are stable.
