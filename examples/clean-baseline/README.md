# clean-baseline (no findings)

A minimal but hardened npm project: a committed `package-lock.json` and an
`https://` registry. `safe-deps check` reports nothing and exits `0`.

```bash
safe-deps check examples/clean-baseline   # exit 0, no findings
```

Use it as the "after" to the other examples' "before".
