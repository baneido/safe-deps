# Releasing

`safe-deps` is **not yet published to crates.io**; it is built from source. This
document is the checklist for when a tagged release (and eventual crates.io
publish) is cut. It is for maintainers.

## Versioning

The crate follows [Semantic Versioning](https://semver.org/). While pre-1.0,
breaking changes to the CLI surface, rule IDs, or output schemas bump the minor
version. Rule **semantics** can tighten within a minor version (a rule may begin
flagging a case it previously missed); call this out in the changelog.

## Pre-release checklist

1. **Green main.** Ensure CI is passing on `main`:
   - `cargo fmt --check`
   - `cargo clippy --all-targets --locked -- -D warnings`
   - `cargo test --locked`
   - `cargo audit` and `cargo deny check`
   - `npm run lint:markdown` and `npm run lint:spelling`
2. **Update [CHANGELOG.md](CHANGELOG.md).** Rename the `Unreleased` section to the
   new version with a date, and start a fresh empty `Unreleased`.
3. **Refresh third-party licenses.** Regenerate
   [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) if dependencies changed (see
   the command in that file's header), and confirm `cargo deny check` passes so no
   new license slipped past the [`deny.toml`](deny.toml) allow-list.
4. **Bump the version** in `Cargo.toml` and commit the updated `Cargo.lock`.
5. **Verify the release build:**

   ```bash
   cargo build --release
   cargo run --release -- check .
   ```

## Tagging

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

## Publishing to crates.io (when ready)

The crate is not published yet. When it is:

```bash
cargo publish --dry-run     # verify the package contents and metadata
cargo publish
```

Ensure `Cargo.toml` carries the required metadata (`description`, `license`,
`repository`, `readme`, `keywords`, `categories`) before the first publish.

## Advisory baseline

CI runs `cargo audit` and `cargo deny check` against a freshly fetched RUSTSEC
database on every run, so advisories are caught continuously. The accepted
baseline is the **empty** `ignore = []` in [`deny.toml`](deny.toml): no
advisories are currently suppressed. If a release ever must ship with a known,
accepted advisory, add it to `ignore` with a dated comment explaining why, and
record the decision in the changelog.

## Networked-mode reminder

`safe-deps check` is offline and deterministic; only `safe-deps audit` makes
network calls (to OSV). Releasing does not change this invariant — do not add
network access to the `check` path.
