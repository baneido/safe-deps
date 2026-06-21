# Examples

Small, self-contained projects to run `safe-deps check` against and watch each
rule fire. Unlike the integration tests (which exist for regression coverage),
these are for learning and onboarding — copy one, tweak it, and see the finding
change.

| Example                                           | Demonstrates                                              |
| ------------------------------------------------- | --------------------------------------------------------- |
| [`missing-lockfile/`](missing-lockfile)           | SD001 — dependencies declared but no lockfile committed   |
| [`npm-insecure-registry/`](npm-insecure-registry) | SD003 — registry configured over plaintext HTTP           |
| [`pip-extra-index/`](pip-extra-index)             | SD007 — extra package index (dependency-confusion risk)   |
| [`clean-baseline/`](clean-baseline)               | a hardened project that produces no findings (exit `0`)   |

Run one:

```bash
safe-deps check examples/npm-insecure-registry              # text report
safe-deps check examples/npm-insecure-registry --format json
safe-deps explain SD003                                     # why it matters
```

`check` exits `0` when clean and `1` when it finds an issue at or above
`--fail-on` (default `error`), so these double as a quick CI smoke test.
`safe-deps init` writes a commented `safe-deps.toml` to start configuring your
own project.
