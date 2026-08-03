# Wild linker (PE/COFF fork)

Fork of the [Wild linker](https://github.com/wild-linker/wild) with experimental
**x86-64 Windows (PE/COFF) support** behind the `pe` feature — link
`x86_64-pc-windows-msvc` binaries with Wild, on Windows or cross from Linux/macOS,
alongside Wild's normal ELF targets.

Status: works for real x64 release builds (C/C++/Rust/Tauri apps run on real
Windows; ~lld-link link speed). Not yet implemented: PDB debug info, `/LTCG`,
`/INCREMENTAL`, `/GUARD:CF`, non-x64 targets — these fail explicitly rather than
mislink. See `plans/pe-coff/feature-matrix.md` for the full parity table.

## Install

Two options; both come with the `pe` feature enabled.

### 1. Prebuilt binary (cargo binstall)

```sh
cargo binstall wild-linker --git https://github.com/thewh1teagle/wild
```

Binaries are published on this fork's [releases page](https://github.com/thewh1teagle/wild/releases)
(Linux x86-64/aarch64 and Windows x86-64) — you can also just download a tarball
from there and put `wild` on your PATH.

### 2. Build from source (cargo install)

```sh
cargo install --locked --bin wild --git https://github.com/thewh1teagle/wild --branch dev wild-linker --features pe
```

## Use it in your project

In the repo you want to link with Wild, add to `.cargo/config.toml`
(or `~/.cargo/config.toml` globally):

### Windows (MSVC target)

```toml
[target.x86_64-pc-windows-msvc]
linker = "wild"
```

### Linux

```toml
[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-C", "link-arg=--ld-path=wild"]
```

Or as a one-off without config:

```sh
# Windows target
RUSTFLAGS="-C linker=wild" cargo build --target x86_64-pc-windows-msvc --release
# Linux
RUSTFLAGS="-C linker=clang -C link-arg=--ld-path=wild" cargo build --release
```

For C/C++ on Windows, invoke `wild` with lld-link-style arguments (it accepts
`link.exe`/`lld-link` command lines, `/`- and `-`-style options, and response
files), e.g. set `CMAKE_LINKER=wild` with the MSVC toolchain.

## Releasing (fork maintenance)

Push a tag matching `pe-v*` (e.g. `pe-v0.1.0`) to trigger
`.github/workflows/pe-release.yml`, a lean 3-target build that uploads tarballs
to GitHub releases. Upstream's full `release.yml` matrix is left untouched.

## Upstream

Everything else — design docs, benchmarks, ELF usage, contributing — see the
[upstream README](https://github.com/wild-linker/wild#readme). This fork tracks
upstream; PE work lives on `feature/pe-coff-v1`, `feature/pe-coff-performance`,
and is integrated on `dev`.

## License

MIT or Apache-2.0, same as upstream.
