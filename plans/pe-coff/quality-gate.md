# PE/COFF quality gate

Evidence captured on 2026-08-03. Run IDs and commit hashes are included so a
passing result is not accidentally attributed to a later revision.

## Local macOS M4 verification (original host)

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

The Rust unit run executes 223 `libwild` tests and 137 `linker-utils` tests;
one opt-in local xwin archive probe remains ignored. The reproducibility matrix
links all six freestanding fixtures with `lld-link` and twice with Wild, checks
the bounded PE-layout equivalences documented in `pe-repro_001.md`, and passes
all semantic and byte-determinism checks. The performance probe passes its
30-second budget; the final captured run measured complete Rust compile/link
times of 0.98 seconds for Wild and 0.18 seconds for `lld-link`. This is a
correctness gate, not evidence that the experimental PE linker is faster.

The full xwin-backed candidate command also passes at `a242d132`:

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
  [30787127729](https://github.com/thewh1teagle/wild/actions/runs/30787127729),
  commit `a242d132`, passed. It copies Wild to `link.exe`, sets both candidate
  environment variables, and executes the `lld-link` and Wild images.
- Full C, C++, DLL, Rust-std, and TLS runtime workflow: run
  [30787127495](https://github.com/thewh1teagle/wild/actions/runs/30787127495),
  commit `a242d132`, passed. It builds Wild, selects it as `link.exe`, then links
  and executes both reference and candidate corpora with exact stdout and
  exit-code assertions. The corpus includes C and C++ executables, C and C++
  DLLs and consumers, a Rust-std executable, a Rust cdylib and C consumer, and
  compiler TLS/callback behavior.
- Minimal Tauri debug and release workflow: run
  [30787128668](https://github.com/thewh1teagle/wild/actions/runs/30787128668),
  commit `a242d132`, passed. Both profiles use Wild as Cargo's x86-64 MSVC
  linker and must reach Tauri's Ready event and exit with code 73.
- Real Vibe debug and release workflow: run
  [30789529875](https://github.com/thewh1teagle/wild/actions/runs/30789529875),
  commit `fee26749`, passed. Both isolated jobs remove the pinned Vibe package
  from Cargo's restored target cache, then compile and link it with the Wild
  artifact built by the same workflow. The resulting debug (79,326,720-byte)
  and release (12,269,568-byte) executables are valid AMD64 PE images; their
  real sona and ffmpeg sidecars pass native probes; and each no-argument Vibe
  process creates a top-level GUI window and remains alive on real Windows.
  Vibe's separate undocumented `--help` forwarding path is diagnostic-only at
  this revision: it times out in debug and exits with `0xc0000409` in release,
  while the supported GUI application path passes in both profiles.

## Local Linux aarch64 verification (current host, 2026-08-03)

The same local gates were re-verified on an Ubuntu aarch64 machine at commit
`f2392c1a` after the setup documented in `host-tooling.md` (LLVM 18.1.3, the
same major version as the macOS evidence):

- fmt, clippy (`pe` feature), actionlint, and taplo gates pass.
- `cargo +1.95.0 test -p linker-utils -p libwild --no-default-features
  --features pe`: 223 + 137 tests pass (1 opt-in xwin probe ignored), matching
  the macOS counts. Requires `clang-format` installed.
- `pe-repro_001.py --wild target/debug/wild`: all six fixtures are
  byte-deterministic across Wild links and semantically equivalent to
  `lld-link`.
- `pe-perf_001.py --wild-budget-seconds 30`: pass; Wild/lld complete
  compile+link ratio ≈ 3.3× on this 20-core host (correctness budget only).
- Known gap: `wild/tests/windows_pe_runtime.rs` is cfg-gated to Windows/macOS
  and compiles to a no-op skip on Linux even though this host satisfies its
  capability probe. See `host-tooling.md` and `goal1-gaps.md`.

## Paired Vibe Wild-versus-lld-link control

Run [30801348499](https://github.com/thewh1teagle/wild/actions/runs/30801348499),
commit `52aeac2d`, passed — the definitive application-level control. Each
Windows job builds the same pinned Vibe revision
(`1c5466b21b2228d708d9140d0f2ec71f69c0bb3e`) once with Wild and once with
`lld-link`, with explicit stale-output deletion and freshness markers.

- Debug: Wild 79,326,720 bytes (SHA-256 `60B9671F…`), lld 42,254,848 bytes
  (`1EE3AB83…`); not byte identical (first difference at offset `0x2`). Both
  CLI wrappers printed the identical 305-byte sona help, hit the same
  Vibe/Aptabase panic, and timed out; both GUIs created a top-level window and
  stayed alive; both sidecars exited 0.
- Release: Wild 12,269,568 bytes (`3F9C220F…`), lld 10,984,448 bytes
  (`F957CB01…`); both CLI wrappers exited `0xc0000409` (Vibe's own
  panic-abort); both GUIs created a top-level window and stayed alive; both
  sidecars exited 0.

Identical behavior from the lld control confirms the CLI defect belongs to
Vibe/Tauri, not Wild. Byte identity is not a goal; loader-visible semantic
equivalence is. The size gap is consistent with `/OPT:REF`/`ICF` being no-ops
in Wild (see `goal1-gaps.md`).
