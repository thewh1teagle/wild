# PE/COFF parser fuzzing

The `coff_parsers` target exercises standard and bigobj COFF objects, archive
member discovery, import-library members, short import objects, relocations,
COMDAT/auxiliary records, section payloads, and symbol names.

Install `cargo-fuzz` once, then run from the repository root:

```console
cargo install cargo-fuzz --locked
cargo +nightly fuzz run coff_parsers
```

For a bounded local smoke run, append
`-- -max_total_time=30`. Crashes and minimized reproducers are written below
`fuzz/artifacts/`; do not commit generated artifacts. The checked-in corpus
contains a valid empty COFF archive so archive parsing is reached immediately.
