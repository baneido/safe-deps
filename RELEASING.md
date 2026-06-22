# Releasing

`safe-deps` is distributed three ways: prebuilt binaries on the GitHub Release, the
crate on **crates.io** (`cargo install safe-deps` / as a library dependency), and a
**Homebrew** formula on [`baneido/homebrew-tap`](https://github.com/baneido/homebrew-tap)
(`brew install baneido/tap/safe-deps`). All three are produced automatically by
[`.github/workflows/release.yml`](.github/workflows/release.yml) when a `vX.Y.Z` tag
exists. You never create that tag by hand: **bumping the `version` in `Cargo.toml`
on `main` is the release action.**
[`release-tag.yml`](.github/workflows/release-tag.yml) derives the matching tag from
the manifest and dispatches the release, so the tag and the crate version can never
disagree. This document is the maintainer checklist for that bump.

> **First publish is a one-time manual bootstrap (already completed for `v0.2.1`).** The automated `publish-crate`
> job authenticates with crates.io Trusted Publishing (GitHub OIDC, no long-lived
> token) — but unlike PyPI, crates.io has **no "pending publisher"**: the Trusted
> Publishing settings only appear *after* the crate exists, so they cannot be
> configured before the first publish. See
> [Bootstrapping the first crates.io release](#bootstrapping-the-first-cratesio-release) for the one-time steps.

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
5. **Verify the release build and the package:**

   ```bash
   cargo build --release
   cargo run --release -- check .
   cargo package --locked      # builds the .crate and runs the verify build
   cargo package --list        # confirm no dev-only files crept in (the `exclude`
                               # list in Cargo.toml trims examples/, docs/, the
                               # Node lint toolchain, and CI config)
   ```

## Bootstrapping the first crates.io release

The very first publish is manual — crates.io has no pending-publisher flow, so the
Trusted Publishing settings do not exist until the crate does. Do this once:

1. **Create a scoped API token.** On crates.io → *Account Settings → API Tokens*,
   create one with the `publish-new` scope. Treat it as a secret; you discard it
   in step 3 — automation never stores a token.
2. **Publish from your machine** after the pre-release checklist passes:

   ```bash
   cargo publish --locked --token "$CRATES_IO_TOKEN"
   ```

   This creates the `safe-deps` crate on crates.io.
3. **Register the Trusted Publisher.** Now that the crate exists, open the crate's
   *Settings → Trusted Publishing* and add a GitHub Actions publisher: repository
   `baneido/safe-deps`, workflow `release.yml`, environment blank. Then revoke the
   step-1 token.

You still cut the matching `vX.Y.Z` binary release, SBOM, and signatures for this
first version the normal way — bump the version on `main` (see
[Releasing](#releasing-the-version-bump-is-what-publishes) below) so
`release-tag.yml` tags and dispatches the release. The `publish-crate` job will fail
with "crate already uploaded", which is harmless: it is an independent job, so the
build/sign/sbom jobs still complete. Every version *after* the bootstrap publishes
fully automatically over OIDC.

## Releasing (the version bump is what publishes)

`Cargo.toml` is the single source of truth. Releasing is **landing a version bump on
`main`** — there is no separate tagging step, and nothing for the tag and the crate
version to disagree about:

1. Open a PR that bumps `version` in `Cargo.toml`, commits the refreshed
   `Cargo.lock`, and moves the `Unreleased` changelog notes under a new
   `## X.Y.Z` heading. The `version bump completeness` CI check (in
   [`ci.yml`](.github/workflows/ci.yml)) enforces all three — plus a strictly
   increasing version that has not already been released — before the PR can merge.
2. Merge it. On the push to `main`,
   [`release-tag.yml`](.github/workflows/release-tag.yml) reads the version, creates
   the annotated tag `vX.Y.Z`, and dispatches `release.yml` against it.
3. `release.yml` verifies the tag matches `Cargo.toml` (a backstop), builds the
   per-target binaries, **publishes the crate to crates.io** (`publish-crate` job,
   gated on a green build matrix), signs the checksums, and attaches the SBOM.

**Do not `git tag` by hand.** A manually pushed tag now triggers nothing — only the
version bump does. To re-run a release for a tag that already exists (e.g. after a
transient infrastructure failure), dispatch it manually instead of re-tagging:

```bash
gh workflow run release.yml --ref vX.Y.Z
```

A crates.io publish is irreversible — a version can only be yanked, never
replaced — so the workflow publishes only after every release target compiles. If
the `publish-crate` job fails after the crate is already live (e.g. a re-run for a
version that published successfully), do **not** reuse the version; bump to the next
patch version instead. Re-merging without a new version is a no-op — the tag already
exists, so `release-tag.yml` skips — so recover a failed release by bumping forward,
never by re-tagging.

### Manual publish (fallback)

Only if the automated `publish-crate` job is unavailable. Requires a crates.io API
token with publish scope:

```bash
cargo publish --dry-run     # verify the package contents and metadata
cargo publish --locked
```

`Cargo.toml` already carries the required metadata (`description`, `license`,
`repository`, `readme`, `keywords`, `categories`) and an `exclude` list that keeps
the published `.crate` lean.

## Homebrew formula

After the binaries are built and the checksums signed, the `homebrew` job renders
[`scripts/safe-deps.rb.tmpl`](scripts/safe-deps.rb.tmpl) — filling in the version
and the per-target SHA-256s read from the signed `SHA256SUMS` manifest — and opens a
PR on [`baneido/homebrew-tap`](https://github.com/baneido/homebrew-tap) updating
`Formula/safe-deps.rb`. The formula installs the prebuilt binary (no Rust toolchain
on the user's machine). The tap's `main` is protected, so the job opens a PR rather
than pushing; **merge that PR** to make the new version installable via
`brew install baneido/tap/safe-deps`.

The job authenticates to the tap with the `TAP_GITHUB_TOKEN` repository secret (a
token with push + PR permission on `baneido/homebrew-tap`, shared with the
shipsafe/jp-pii-detect release bots). If the secret is unset, the job logs a warning
and skips — the rest of the release still succeeds. If the formula is already current
for the tag, the job is a no-op. Edit the generated `Formula/safe-deps.rb` only
through `scripts/safe-deps.rb.tmpl`, never by hand in the tap.

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
