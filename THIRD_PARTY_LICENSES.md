# Third-party licenses

`safe-deps` itself is MIT-licensed (see [LICENSE](LICENSE)). This report lists
every third-party crate in the resolved dependency graph (`Cargo.lock`) — normal,
build, and dev/test dependencies — together with its SPDX license expression.

Every dependency is permissively licensed; the set of licenses is enforced in CI
by `cargo deny check` against the allow-list in [`deny.toml`](deny.toml).

This file is generated. To regenerate it after a dependency change:

```bash
cargo metadata --format-version 1 \
  | jq -r '.packages | map(select(.name!="safe-deps")) | sort_by(.name)[]
           | "| `\(.name)` | \(.version) | \(.license // "—") |"'
```

See [RELEASING.md](RELEASING.md) for when to refresh it.

## License summary

| Count | License expression |
| ----: | ------------------ |
| 54 | MIT OR Apache-2.0 |
| 9 | MIT |
| 6 | Apache-2.0 OR MIT |
| 5 | Unlicense OR MIT |
| 3 | Apache-2.0 |
| 2 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| 2 | Unlicense/MIT |
| 1 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| 1 | Apache-2.0 OR BSL-1.0 |
| 1 | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| 1 | MIT/Apache-2.0 |

## Crates

| Crate | Version | License |
| ----- | ------- | ------- |
| `aho-corasick` | 1.1.4 | Unlicense OR MIT |
| `anstream` | 1.0.0 | MIT OR Apache-2.0 |
| `anstyle` | 1.0.14 | MIT OR Apache-2.0 |
| `anstyle-parse` | 1.0.0 | MIT OR Apache-2.0 |
| `anstyle-query` | 1.1.5 | MIT OR Apache-2.0 |
| `anstyle-wincon` | 3.0.11 | MIT OR Apache-2.0 |
| `assert_cmd` | 2.2.2 | MIT OR Apache-2.0 |
| `autocfg` | 1.5.1 | Apache-2.0 OR MIT |
| `bitflags` | 2.13.0 | MIT OR Apache-2.0 |
| `bstr` | 1.12.1 | MIT OR Apache-2.0 |
| `cfg-if` | 1.0.4 | MIT OR Apache-2.0 |
| `clap` | 4.6.1 | MIT OR Apache-2.0 |
| `clap_builder` | 4.6.0 | MIT OR Apache-2.0 |
| `clap_derive` | 4.6.1 | MIT OR Apache-2.0 |
| `clap_lex` | 1.1.0 | MIT OR Apache-2.0 |
| `colorchoice` | 1.0.5 | MIT OR Apache-2.0 |
| `console` | 0.16.3 | MIT |
| `crossbeam-deque` | 0.8.6 | MIT OR Apache-2.0 |
| `crossbeam-epoch` | 0.9.18 | MIT OR Apache-2.0 |
| `crossbeam-utils` | 0.8.21 | MIT OR Apache-2.0 |
| `difflib` | 0.4.0 | MIT |
| `either` | 1.16.0 | MIT OR Apache-2.0 |
| `encode_unicode` | 1.0.0 | Apache-2.0 OR MIT |
| `equivalent` | 1.0.2 | Apache-2.0 OR MIT |
| `errno` | 0.3.14 | MIT OR Apache-2.0 |
| `fastrand` | 2.4.1 | Apache-2.0 OR MIT |
| `float-cmp` | 0.10.0 | MIT |
| `getrandom` | 0.4.3 | MIT OR Apache-2.0 |
| `globset` | 0.4.18 | Unlicense OR MIT |
| `hashbrown` | 0.17.1 | MIT OR Apache-2.0 |
| `heck` | 0.5.0 | MIT OR Apache-2.0 |
| `ignore` | 0.4.26 | Unlicense OR MIT |
| `indexmap` | 2.14.0 | Apache-2.0 OR MIT |
| `insta` | 1.48.0 | Apache-2.0 |
| `is_terminal_polyfill` | 1.70.2 | MIT OR Apache-2.0 |
| `itoa` | 1.0.18 | MIT OR Apache-2.0 |
| `libc` | 0.2.186 | MIT OR Apache-2.0 |
| `linux-raw-sys` | 0.12.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| `log` | 0.4.32 | MIT OR Apache-2.0 |
| `memchr` | 2.8.2 | Unlicense OR MIT |
| `normalize-line-endings` | 0.3.0 | Apache-2.0 |
| `num-traits` | 0.2.19 | MIT OR Apache-2.0 |
| `once_cell` | 1.21.4 | MIT OR Apache-2.0 |
| `once_cell_polyfill` | 1.70.2 | MIT OR Apache-2.0 |
| `predicates` | 3.1.4 | MIT OR Apache-2.0 |
| `predicates-core` | 1.0.10 | MIT OR Apache-2.0 |
| `predicates-tree` | 1.0.13 | MIT OR Apache-2.0 |
| `proc-macro2` | 1.0.106 | MIT OR Apache-2.0 |
| `quote` | 1.0.45 | MIT OR Apache-2.0 |
| `r-efi` | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| `rayon` | 1.12.0 | MIT OR Apache-2.0 |
| `rayon-core` | 1.13.0 | MIT OR Apache-2.0 |
| `regex` | 1.12.4 | MIT OR Apache-2.0 |
| `regex-automata` | 0.4.14 | MIT OR Apache-2.0 |
| `regex-syntax` | 0.8.11 | MIT OR Apache-2.0 |
| `rustix` | 1.1.4 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| `ryu` | 1.0.23 | Apache-2.0 OR BSL-1.0 |
| `same-file` | 1.0.6 | Unlicense/MIT |
| `serde` | 1.0.228 | MIT OR Apache-2.0 |
| `serde_core` | 1.0.228 | MIT OR Apache-2.0 |
| `serde_derive` | 1.0.228 | MIT OR Apache-2.0 |
| `serde_json` | 1.0.150 | MIT OR Apache-2.0 |
| `serde_spanned` | 0.6.9 | MIT OR Apache-2.0 |
| `serde_yaml_ng` | 0.10.0 | MIT |
| `similar` | 2.7.0 | Apache-2.0 |
| `strsim` | 0.11.1 | MIT |
| `syn` | 2.0.118 | MIT OR Apache-2.0 |
| `tempfile` | 3.27.0 | MIT OR Apache-2.0 |
| `termtree` | 0.5.1 | MIT |
| `thiserror` | 2.0.18 | MIT OR Apache-2.0 |
| `thiserror-impl` | 2.0.18 | MIT OR Apache-2.0 |
| `toml` | 0.8.23 | MIT OR Apache-2.0 |
| `toml_datetime` | 0.6.11 | MIT OR Apache-2.0 |
| `toml_edit` | 0.22.27 | MIT OR Apache-2.0 |
| `toml_write` | 0.1.2 | MIT OR Apache-2.0 |
| `unicode-ident` | 1.0.24 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| `unsafe-libyaml` | 0.2.11 | MIT |
| `utf8parse` | 0.2.2 | Apache-2.0 OR MIT |
| `wait-timeout` | 0.2.1 | MIT/Apache-2.0 |
| `walkdir` | 2.5.0 | Unlicense/MIT |
| `winapi-util` | 0.1.11 | Unlicense OR MIT |
| `windows-link` | 0.2.1 | MIT OR Apache-2.0 |
| `windows-sys` | 0.61.2 | MIT OR Apache-2.0 |
| `winnow` | 0.7.15 | MIT |
| `zmij` | 1.0.21 | MIT |
