# npm-insecure-registry (SD003)

`.npmrc` points the registry at `http://…`, so packages are fetched over
plaintext HTTP and can be tampered with in transit.

```bash
safe-deps check examples/npm-insecure-registry
```

Expected: **SD003** (insecure registry / TLS). Use an `https://` registry to fix.
