# missing-lockfile (SD001)

`package.json` declares a dependency but no `package-lock.json` is committed, so
installs are not reproducible — a teammate or CI can resolve different versions.

```bash
safe-deps check examples/missing-lockfile
```

Expected: **SD001** (lockfile missing). Commit a lockfile (`npm install` then
check in `package-lock.json`) to fix it.
