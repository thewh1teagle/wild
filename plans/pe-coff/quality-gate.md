# PE/COFF quality gate

Evidence captured on 2026-08-03. Run IDs and commit hashes are included so a
passing result is not accidentally attributed to a later revision.

## Local macOS M4 verification

The following checks pass with the x86-64 MSVC Rust target, LLVM 18, and the
local xwin CRT/SDK:

```console
cargo +nightly fmt --all -- --check
cargo +1.94.0 clippy -p linker-utils -p libwild -p wild-linker \
  --all-targets --no-default-features --features pe -- -D warnings
cargo +1.95.0 test -p linker-utils -p libwild \
  --no-default-features --features pe
actionlint .github/workflows/pe-coff.yml .github/workflows/pe-runtime.yml \
  .github/workflows/pe-tauri.yml .github/workflows/pe-vibe.yml
taplo check .typos.toml Cargo.toml wild/Cargo.toml libwild/Cargo.toml \
  linker-utils/Cargo.toml
uv run plans/pe-coff/pe-repro_001.py --self-test
uv run plans/pe-coff/pe-repro_001.py --wild target/debug/wild
uv run plans/pe-coff/pe-perf_001.py --wild-budget-seconds 30
```

The Rust unit run executes 209 `libwild` tests and 132 `linker-utils` tests;
one opt-in local xwin archive probe remains ignored. The reproducibility matrix
links all six freestanding fixtures with `lld-link` and twice with Wild, checks
the bounded PE-layout equivalences documented in `pe-repro_001.md`, and passes
all semantic and byte-determinism checks. The performance probe passes its
30-second budget; the captured warm run measured complete Rust compile/link
times of 0.98 seconds for Wild and 0.21 seconds for `lld-link`.

The full xwin-backed candidate command also passes at `7381d52a`:

```console
cargo +1.95.0 build -p wild-linker --no-default-features --features pe
WILD_PE_LINKER_FULL=/absolute/path/to/link.exe \
  cargo +1.95.0 test -p wild-linker --test windows_pe_runtime \
  --no-default-features --features pe -- --nocapture
```

`link.exe` above is a symlink to the freshly built `target/debug/wild`; the test
links identical C, C++, DLL, Rust-std, and TLS inputs with `lld-link` and Wild.
macOS validates their PE structure; execution is covered by Windows below.

## Real Windows x86-64 verification

- Focused freestanding/TLS workflow: run
  [30781828633](https://github.com/thewh1teagle/wild/actions/runs/30781828633),
  commit `7381d52a`, passed. It copies Wild to `link.exe`, sets both candidate
  environment variables, and executes the `lld-link` and Wild images.
- Full C, C++, DLL, Rust-std, and TLS runtime workflow: run
  [30782264599](https://github.com/thewh1teagle/wild/actions/runs/30782264599),
  commit `7381d52a`, passed. It builds Wild, selects it as `link.exe`, then links
  and executes both reference and candidate corpora with stdout and exit-code
  assertions.
- Minimal Tauri debug and release workflow: run
  [30781450278](https://github.com/thewh1teagle/wild/actions/runs/30781450278),
  commit `fae3aeab`, passed. Both profiles use Wild as Cargo's x86-64 MSVC
  linker and must reach Tauri's Ready event and exit with code 73.
- Real Vibe debug and release workflow: run
  [30782027875](https://github.com/thewh1teagle/wild/actions/runs/30782027875),
  commit `7381d52a`, is pending. Completion requires both profile jobs to build
  with the uploaded Wild `link.exe`, produce AMD64 executables and sidecars,
  and pass the real-Windows `vibe.exe --help` smoke test.

Vibe remains an open acceptance gate until both matrix jobs complete
successfully. No result in this document claims otherwise.
