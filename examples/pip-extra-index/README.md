# pip-extra-index (SD007)

`requirements.txt` adds `--extra-index-url`, which merges a second package index
with PyPI — a classic dependency-confusion vector. This example also surfaces
**SD004**, because the requirements are not hash-pinned.

```bash
safe-deps check examples/pip-extra-index
```

Expected: **SD007** (dependency confusion) and **SD004** (integrity). Prefer a
single trusted index, or pin hashes with `--require-hashes`.
