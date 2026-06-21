# Contributing to safe-deps

Thanks for your interest in improving `safe-deps`. This guide covers how to
report issues and land a change. For local setup and architecture see
[DEVELOPMENT.md](DEVELOPMENT.md); for cutting a release see
[RELEASING.md](RELEASING.md).

## Ground rules

`safe-deps check` is **static, deterministic, and offline by design**: it must
not install dependencies, execute project code, or make network calls. The only
networked command is `safe-deps audit` (it queries OSV), and network access
lives **only** in its transport. A change that adds I/O or network access to the
`check` path will not be accepted. Keep output deterministically ordered.

By contributing you agree that your contributions are licensed under the
project's [MIT License](LICENSE).

## Reporting issues

- **Security vulnerabilities**: follow [SECURITY.md](SECURITY.md) — do not open a
  public issue.
- **Bugs**: include the `safe-deps` version (`safe-deps --version`), the command
  you ran, a minimal workspace that reproduces it, and the actual vs expected
  output. A failing fixture is the most useful report.
- **False positives / negatives**: name the rule (e.g. `SD003`) and paste the
  manifest or config snippet that is mis-classified.

## Making a change

1. **Open or claim an issue** first for anything beyond a typo, so the approach
   can be agreed before you write code.
2. **Branch** from `main` (e.g. `feat/…`, `fix/…`, `docs/…`, `refactor/…`).
3. **Keep parsers and rules separate.** Parsers in `src/ecosystems/` produce
   facts; rules in `src/rules/` turn facts into findings. Never put
   policy/severity decisions in parser code. See [DEVELOPMENT.md](DEVELOPMENT.md).
4. **Add tests.** A new rule needs one safe and one unsafe fixture in
   `tests/cli.rs`, plus co-located unit tests. A bug fix needs a regression test.
5. **Run the full local gate** before pushing (see below).
6. **Open a pull request** against `main` with a clear description of the problem
   and the fix. Link the issue. Keep PRs focused.

## Local checks (must pass before review)

CI (`.github/workflows/ci.yml`) runs these; run them locally first so it stays
green:

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo deny check          # licenses + advisories (see deny.toml)
```

Documentation and Markdown are linted separately — run these when you touch any
`*.md` or `docs/`:

```bash
npm ci
npm run lint:markdown
npm run lint:spelling     # add new technical terms to .cspell.json "words"
```

## Commit and PR conventions

- Write imperative, scoped commit subjects (`feat: …`, `fix: …`, `docs: …`,
  `refactor: …`, `test: …`, `ci: …`, `deps: …`).
- Update [CHANGELOG.md](CHANGELOG.md) under **Unreleased** for any user-visible
  change.
- Keep the diff reviewable; unrelated cleanups belong in their own PR.

## Adding a rule (quick reference)

1. Create `src/rules/sdNNN_name.rs` implementing the `Rule` trait (`id`,
   `summary`, `explanation`, `evaluate`), with co-located `#[cfg(test)]` tests.
2. Register it in `rules::all_rules()` in `src/rules/mod.rs`.
3. Add CLI integration coverage in `tests/cli.rs` (one safe + one unsafe fixture).
4. Update the rule tables in [README.md](README.md) and the rule taxonomy in
   `docs/design/safe-deps-cli-design.md`.

The full rationale lives in [DEVELOPMENT.md](DEVELOPMENT.md) and the design doc.
