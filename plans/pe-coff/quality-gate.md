# PE/COFF quality gate

Audit baseline: `15c261d0`.

## Focused workflow

`.github/workflows/pe-coff.yml` intentionally contains two jobs only:

- macOS builds and inspects the freestanding PE/COFF corpus with LLVM tools;
- Windows x86-64 builds Wild, copies it to `link.exe` to select the COFF driver,
  then executes both the `lld-link` reference images and Wild images.

The Python inspector self-test and its `setup-uv` action were removed from CI;
the real macOS corpus supersedes that synthetic parser check. Windows now uses
`cargo test --no-run` to build Wild and the corpus in one dependency graph
before selecting the linker flavor, then executes the already-built test.

## Passing local checks

- `actionlint .github/workflows/pe-coff.yml`
- `taplo check .typos.toml Cargo.toml wild/Cargo.toml libwild/Cargo.toml linker-utils/Cargo.toml`
- `cargo metadata --format-version 1 --no-deps`
- `cargo +1.94.0 check --workspace --all-targets`
- `cargo +1.94.0 clippy -p wild-linker --test windows_pe_smoke --no-default-features --features pe -- -D warnings`
- `cargo +1.94.0 test --profile ci -p wild-linker --test windows_pe_smoke --no-default-features --features pe --no-run`; this produces `target/ci/wild` as required by the optimized Windows workflow.
- `cargo +1.94.0 test -p wild-linker --test windows_pe_smoke --no-default-features --features pe`
- `cargo +1.95.0 test --workspace --no-fail-fast`, including the xwin-backed C,
  C++, DLL, and Rust reference corpus on macOS: all pass (one explicitly ignored
  local CRT archive probe).

`typos` is not installed locally. Taplo accepts the narrow typo configuration;
the authoritative check remains `crate-ci/typos@v1.48.0`. The allowlist covers
only the official `IMPORT_OBJECT_NAME_EXPORTAS` identifier and the exact
clang-cl `/Fo{}` spelling.

## Remaining failures

`cargo +nightly fmt --all -- --check` reports these Rust-owned files:

```text
libwild/src/args/coff.rs
libwild/src/pe_entry.rs
libwild/src/pe_imports.rs
libwild/src/pe_resolver.rs
libwild/src/pe_writer.rs
linker-utils/src/coff.rs
linker-utils/src/coff_archives.rs
linker-utils/src/coff_def.rs
linker-utils/src/coff_import_library_writer.rs
linker-utils/src/coff_imports.rs
linker-utils/src/coff_runtime.rs
linker-utils/src/coff_symbols.rs
linker-utils/src/pe_base_relocs.rs
linker-utils/src/pe_checksum.rs
linker-utils/src/pe_debug.rs
linker-utils/src/pe_exports.rs
linker-utils/src/pe_load_config.rs
linker-utils/src/pe_resources.rs
linker-utils/src/pe_sections.rs
linker-utils/src/pe_tls.rs
wild/tests/windows_pe_runtime.rs
wild/tests/windows_pe_smoke.rs
```

`cargo +1.94.0 clippy --workspace --all-targets -- -D warnings` has one finding:
`libwild/src/pe_entry.rs:129` triggers `needless_pass_by_value` in the test-only
`choose` helper.

`cargo +1.94.0 check --workspace --all-targets --all-features` enables both
`mimalloc` and `dhat`, so `wild/src/main.rs` correctly rejects two global
allocators. The repository CI does not use this incompatible feature union.

`cargo +1.94.0 test --workspace` cannot compile the Rust Windows runtime fixture
because that toolchain has no `x86_64-pc-windows-msvc` standard library locally.
The target is installed for 1.95, and the full workspace passes under 1.95, so
this is a local toolchain installation gap rather than a code failure.
