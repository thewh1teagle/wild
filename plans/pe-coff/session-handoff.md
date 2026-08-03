# PE/COFF goals 1 through 3 session handoff

Last updated: 2026-08-03 at the stopped Goal 3 native-Windows checkpoint. This is the continuity document
for a new agent session.
Read it together with [`GOAL.md`](../../GOAL.md) and
[`quality-gate.md`](quality-gate.md), but treat this file as the broad narrative and
current-state summary.

## Update 2026-08-03: native Windows Goal 3 checkpoint

This is the current resume point and supersedes older host, branch, and priority
instructions below where they conflict. The user stopped the optimization session
before authoritative Goal 3 baselines or linker-code changes were made.

### Current repository state

- Native workspace: `C:\Users\user1\Documents\wild` on Windows 11 x86-64.
- Branch: `feature/pe-coff-windows-performance`.
- Current tip before this handoff update: `209f8e67`.
- The branch is based on completed Goal 2 tip `fa49995a`; linker code is still the
  Goal 2 code. Goal 3 has changed only plans, benchmark, and corpus tooling so far.
- Do not open a PR. The user requested that this checkpoint be committed and pushed
  to `origin/feature/pe-coff-windows-performance`.
- Goal 3 is **not complete**. No authoritative Goal 3 baseline or optimization claim
  exists yet.

Goal 3 commits before this handoff:

- `e36f431f`: defines the native Windows performance goal.
- `db91b464`: adds the native Windows benchmark harness.
- `a9686abb`: adds selective Rust final-binary `/reproduce` capture.
- `6fbaf8bd`: adds safe short-path archive expansion and replay tooling.
- `209f8e67`: fixes native Wild version metadata probing.

Read [`windows-native-performance.md`](windows-native-performance.md) for the protocol
and [`tools/README.md`](tools/README.md) for capture/replay usage. The completion bar
in `GOAL.md` is a Wild/lld geometric-mean win of at least 20% across Rust std,
ripgrep, rust-analyzer, and uv, individual Wild wins on uv and rust-analyzer, no
unaccepted primary-corpus regression above 3%, and green correctness, determinism,
native execution, and bounded-memory evidence.

### Windows host and installed tools

- AMD Ryzen 5 4500U, 6 physical/logical cores, approximately 16 GB RAM.
- Windows 11 (`10.0.26200` as recorded by the harness); Balanced is the only exposed
  power scheme.
- Visual Studio 2022 17.14, MSVC 14.44, Windows SDK 10.0.26100.
- LLVM 22.1.8 in `C:\Program Files\LLVM\bin`.
- Rust 1.95.0, 1.94.0, and nightly; NASM 3.02; WPR/WPA/xperf; `uv` installed.
- Nothing else was identified as required. Ask before installing additional tools.

### Completed native harness and corpus tooling

`plans/pe-coff/pe-link-bench_001.py` now uses native Win32 process creation: it starts
the linker suspended, applies affinity before resume, and records wall/user/kernel
time plus peak working set. Windows warm-cache runs, randomized pairing, 1--6 thread
sweeps, validation, determinism, JSON output, Program Files LLVM discovery, and
Wild/lld metadata probing are implemented. Windows cold-cache requests are refused
because the harness cannot make a defensible global cold-cache claim.

Verification completed at this checkpoint:

- 20 Windows harness self-tests pass.
- Ruff lint and formatting checks pass.
- Capture/replay tooling tests preserve response-file bytes exactly, including LF and
  quoting; path-length, traversal, destination, and response-count guards pass.
- A live fixture replays with both lld and Wild and executes with the expected output.
- `cargo +1.95.0 test -p linker-utils -p libwild --no-default-features --features pe`
  ran 258 tests: 251 passed. The seven failures were checkout-policy issues from
  system `core.autocrlf=true` and Unix path assumptions, not PE logic. The focused
  COFF argument set passed 39/39. Use a clean LF worktree for a final full gate.

The Windows release linker used for smoke work is
`target\release\wild.exe`, 7,937,536 bytes, SHA-256
`AC678E13CF035F6D857C77C4FD4A884D08F3170B73ACE9B9B7D4B918B4054122`.
Record the exact source commit separately because its embedded version reports the
older base revision with `-modified`.

### Corpus checkpoint

Ripgrep is ready:

- Release 15.2.0, source commit
  `e89fff89ac9af12e8d4ce9d5fd07beb408ca730f`.
- Archive:
  `C:\Users\user1\Documents\wild-pe-corpora\captures\ripgrep-15.2.0\e89fff89ac9a\ripgrep-rg-release-a4c4460be04a2af7\link-repro.tar`.
- Size 92,064,256 bytes; SHA-256
  `2BA9666315A5BE7F15A875BCD7056FFF930AE78279CBE82830738919EE48B93C`.
- Preferred retained short replay root:
  `C:\wr3\r-2ba9666315a5be7f\link-repro`.
- Both linkers replay successfully and Wild's output runs as ripgrep 15.2.0.

Rust-analyzer capture finished immediately before the stop request, but extraction
and replay validation did not finish:

- Release tag `2026-08-03`, source commit
  `b54a82b321c9617c5cf0b07ac0f12c08f7bc5902`.
- Archive:
  `C:\wc\captures\captures\rust-analyzer-2026-08-03\b54a82b321c9\rust-analyzer-rust-analyzer-release-f56a8e08b5edd2d7\link-repro.tar`.
- Size 421,525,504 bytes; SHA-256
  `576BBCCEE34A48A06B9D7699A290EC9E15ED833D203A94A138D33DE1DECD553A`.
- Next session must expand it under a short fresh root with
  `Expand-LldRepro.ps1`, replay both linkers, run the produced executable, and retain
  the replay JSON before treating it as ready.

uv is incomplete:

- Release 0.12.1, source commit
  `329541a503de8a4d9bb021814f9c0875efe033c8`.
- Source checkout:
  `C:\Users\user1\Documents\wild-pe-corpora\sources\uv-0.12.1`.
- Its final fat-LTO rustc process was deliberately terminated at the user's request.
  No complete archive was produced. Re-run the selective final-binary capture; the
  existing Cargo target cache should make the retry cheaper.

Several fixture archives exist under
`C:\Users\user1\Documents\wild-pe-corpora\captures\wild-corpus-fixture`, but a
single immutable representative Rust-std primary corpus still needs to be selected,
validated, and recorded. Do not silently average multiple fixture attempts.

### Measurements so far are smoke-only

- A tiny hello corpus under load measured Wild around 53--57 ms and lld around
  94--100 ms across the 1--6 thread smoke; it is not authoritative.
- A one-sample ripgrep replay under simultaneous compilation measured Wild
  1058.467 ms versus lld 1166.440 ms, with peak RSS 77.8 MiB versus 100.8 MiB.
  The JSON is `C:\wc\rg-15.2.0\harness-smoke.json`. It proves harness operation,
  not a performance claim.
- Preliminary `/time` observations were also taken while compiles were active and
  were inconsistent. Do not use them to choose or justify an optimization.

### Exact next-session order

1. Confirm there are no background Cargo/rustc jobs and the machine is otherwise
   quiet. At this checkpoint all capture subagents were stopped and no
   `cargo.exe`, `rustc.exe`, or `rustup.exe` remained.
2. Expand and fully validate rust-analyzer, retry uv capture, and select the immutable
   Rust-std corpus. Keep all replay roots short.
3. Build and hash Wild from the exact pre-optimization source, then run sequential
   warm 1--6 thread sweeps for all four primary corpora using at least 15 samples,
   five accumulated seconds per row, warmups, randomized pairs, CPU affinity, RSS,
   output validation, and Wild determinism.
4. Record that immutable baseline before changing linker code. Then collect `/time`
   profiles outside measured runs and choose work only from repeatable hot phases.
5. Iterate one optimization at a time. Require correctness gates plus matched
   before/after primary-corpus measurements; revert neutral or regressive ideas.
6. Finish with direct best-configuration pairs, geometric-mean calculation, individual
   uv/rust-analyzer results, regression/memory accounting, native execution, and a
   new Goal 3 evidence document. Do not mark Goal 3 complete below its `GOAL.md` bar.

## Executive summary

The original upstream discussion was
[`wild-linker/wild#2320`](https://github.com/wild-linker/wild/issues/2320). The first
proposal was a small, incremental PE/COFF milestone. The user deliberately expanded
that into one much larger feature branch: implement an **experimental but genuinely
usable x86-64 Windows PE/COFF linker**, validate it locally from an Apple-silicon Mac,
execute it on real Windows in GitHub Actions, compile a minimal Tauri app in debug and
release, then compile and run the real Vibe application in both profiles.

The work is in the user's fork only. Do **not** open a PR. Goal 1 is complete at
`547c72f309dc8dd73e5a43166e183491138395e7`. Goal 2 is complete for benchmarked
code `a68ba65237ea98c29f166f7ee10fb8dfbbb1a5e0`. Exact correctness and bounded
performance evidence is recorded in `quality-gate.md` and
`pe-link-bench_001.md`.

Current headline results:

- Wild links and Windows executes the C, C++, DLL, Rust `std`, Rust `cdylib`, TLS,
  freestanding, minimal Tauri, and real Vibe corpora.
- Minimal Tauri builds and runs in both debug and release.
- Pinned Vibe builds in debug and release, produces valid AMD64 PE images in both,
  starts its real GUI, creates a top-level window, and remains alive.
- Vibe's undocumented argument-forwarding path has an application bug independent of
  Wild: it panics after the sidecar returns. A paired `lld-link` build reproduces it.
- Wild output is deterministic across identical Wild links. Wild and `lld-link` output
  is semantically equivalent for the acceptance corpus but is **not byte identical**.
- The final pinned Vibe warm sweep measured Wild's best row at 100.356 ms and
  lld's at 98.909 ms. The direct randomized best-configuration pair measured
  Wild `/threads:10` at 99.576 ms versus lld `/threads:1` at 103.823 ms, a
  4.247 ms (4.1%) tool-median difference; paired Wild-minus-lld deltas were
  -4.084 ± 2.522 ms with 35/50 Wild wins. The sweep residual remains disclosed.
- The Rust-std link-only reproduction favors Wild at every measured warm
  1/2/4/8/10-thread point and advisory-cold 2/4/8/10. Advisory-cold one-thread
  Rust std remains slower. Advisory cold is not a global cold-cache claim.
- Goal 2 is complete under that direct warm best-versus-best interpretation.
  Advisory-cold direct tool medians favor lld by 2.801 ms, but paired deltas
  favor Wild by 3.319 ms (MAD 20.399 ms; 14/24 wins). High-thread Wild RSS
  remains higher, so the result is not a universal speed or memory claim.

## Repository and branch state

- Workspace: `/home/yakov/Documents/wild`
- Fork/`origin`: `https://github.com/thewh1teagle/wild`
- Upstream: `https://github.com/wild-linker/wild.git`
- Branch: `feature/pe-coff-performance`
- Goal 1 closeout tip: `547c72f309dc8dd73e5a43166e183491138395e7`
- Remote tracking: `origin/feature/pe-coff-performance`
- Base `main` at the start/current local main: `8e106f2d`
- Goal 1 feature range: `9e698d9c..547c72f3`.
- Goal 2 code feature range: `65185605..a68ba652`.
- No PR has been opened and none should be opened without an explicit new request.
- The fork's default branch is `main`. It was temporarily changed to
  `feature/pe-coff-v1` so GitHub could register and dispatch branch-only workflows,
  then restored after the final paired run completed.
- Preserve `AGENTS.md`; do not modify it as part of linker work.

Important milestone commits:

- `9e698d9c`: defines the PE/COFF goal.
- `0c3356bb` through `603c0a7a`: core format, parser, relocation, import, archive,
  resolution, layout, and writer foundations.
- `0358883c`, `da1595fb`, `a0edc515`: DLL/import-library, CRT, and integrated TLS
  support.
- `4e1f4aba`: minimal Tauri acceptance harness.
- `214e79cb`: initial real Vibe acceptance workflow.
- `a242d132`: final CRT load-config-directory fix that unlocked the full acceptance
  suite.
- `fee26749`: makes the supported Vibe GUI path authoritative and records the CLI path
  as diagnostic.
- `b5dd7b19`: records the completed core acceptance evidence.
- `88da9252`: adds paired, same-revision Wild and `lld-link` Vibe builds, hashes, PE
  inspection, CLI comparison, and GUI comparison.
- `52aeac2d`: guarantees fresh paired links by explicitly deleting the exact cached
  `vibe.exe` after Cargo's package-scoped clean proved insufficient.
- `547c72f3`: closes Goal 1 with option compatibility, real `/OPT:REF`, delay
  imports and unwind records, stability/fuzz coverage, ordinal/forwarder and
  malformed-image fixtures, and manifest embedding.
- `65185605`: adds the reproducible link-only benchmark harness.
- `1c7b0c26` and `2ea4ee1a`: add phase instrumentation used to select work.
- `ff0b4f34..bc33fb6b`: integrate measured archive, resolution, COMDAT,
  relocation, layout, hashing, lookup, parallelism, and allocator wins.
- `8dd69ea6`: caches selected-object symbol metadata at the interim checkpoint.
- `73ed705d`/`c26319f4`: incrementally lay out the relocation section and avoid
  a redundant full relocation relayout.
- `2bd5f06c`/`82a890d5`: speed resolver lookups and reuse selected-object
  metadata from import resolution.
- `d2ac1ff3`: flattens COMDAT reachability adjacency.
- `3960ae2d`: adds direct thread-pair benchmark support.
- `a68ba652`: overlaps build-ID hashing with output copying and is the exact
  benchmarked Goal 2 closeout code.

Use `git log --oneline --reverse main..feature/pe-coff-performance` for the
complete detailed commit history. Many old `codex/*` and `perf/*` worktree
branches are historical experiments, not the integration target.

## Scope and success definition

The intended v1 is “production-usable experimental,” not full `link.exe`/`lld-link`
parity and not yet equal in maturity to Wild's Linux ELF linker.

In scope and demonstrated:

- AMD64/x86-64 PE32+ executables and DLLs.
- MSVC-flavored command-line and response-file handling, including UTF-16 response
  files and common rustc/MSVC compatibility flags.
- Standard and bigobj COFF objects; MSVC/GNU-style self-contained archives; archive
  extraction to a default-library fixpoint.
- AMD64 relocations, weak externals, `/alternatename`, absolute symbols, COMDAT
  selection/associative liveness, and deterministic section contribution ordering.
- Import libraries and imports/IAT, exports, generated import libraries, `.def` files,
  default entry-point inference, base relocations, resources, TLS and callbacks,
  exception/unwind tables, load-config preservation, PE checksums, reproducible debug
  directory metadata, long section names, and CRT linker directives.
- C/C++ executables, C/C++ DLLs and consumers, Rust `std`, Rust `cdylib` and C consumer,
  compiler-generated TLS, Tauri/WebView2, and the real Vibe app.
- Deterministic repeated Wild output and semantic differential checks against
  `lld-link`.

Explicitly out of v1:

- PDB generation. `/DEBUG`, `/PDB`, `/PDBALTPATH`, and `/NATVIS` are accepted as
  needed for compiler-driver compatibility, but no PDB is emitted; in-image/debug
  metadata behavior is narrower than MSVC's.
- LTO (`/LTCG`) and incremental linking (`/INCREMENTAL`); both are intentionally
  rejected rather than silently misimplemented.
- Non-x86-64 Windows targets, including ARM64 and x86.
- Full Control Flow Guard production. Existing CRT guard/load-config metadata is
  handled conservatively; asking for unsupported enabled CFG must not silently weaken
  security.
- Thin COFF archives, every obscure `.def` directive, and `/MERGE` of `.pdata`.
- Complete `link.exe` or `lld-link` option parity, every Windows SDK/CRT version, PDB
  tooling parity, and the production/performance maturity of Linux Wild.

Format helpers are claimed end-to-end only where the feature matrix records an
integrated driver/writer path and acceptance evidence. Delay imports now meet that
bar; other standalone helpers do not gain support status merely by existing.

## Implementation architecture

PE is behind the opt-in Cargo feature `pe`; it remains explicitly experimental and is
not enabled by default.

The implementation is split deliberately:

1. `linker-utils/src/coff*.rs` parses and validates COFF objects, symbols, standard and
   bigobj records, archives, import libraries, runtime directives, weak externals, and
   `.def` inputs. `linker-utils/src/pe_*.rs` provides deterministic, independently
   tested builders/validators for sections and PE data directories.
2. `libwild/src/args/coff.rs` supplies the MSVC/link.exe-compatible argument layer.
   `libwild/src/file_kind.rs`, `coff.rs`, and `coff_x86_64.rs` identify AMD64 COFF and
   expose the platform relocation semantics.
3. `libwild/src/pe_resolver.rs` performs archive/default-library resolution,
   `/alternatename` fallback, roots, and selection. `pe_entry.rs` chooses executable or
   DLL entry semantics. `pe_imports.rs` maps import definitions.
4. `libwild/src/pe_writer.rs` integrates selection, COMDAT filtering, section layout,
   symbol binding, relocations, imports/exports, loader directories, and deterministic
   PE emission. On Windows, the normal Wild driver chooses COFF natively; in cross-host
   tests Wild is copied/symlinked to `link.exe` so flavor detection matches Cargo/MSVC.

Correctness work that mattered for real applications included transitive
`/DEFAULTLIB` resolution, object-local COMDAT identity, redirecting relocations from
discarded COMDATs, zero-sized-section handling, `.pdata` canonical ordering, unused
frame offsets, UTF-16 response files, long section names, CRT guard/load-config
semantics, and correct load-config data-directory sizing.

## Local development on macOS M4

The Mac is sufficient for almost all development. It can compile Windows objects,
cross-link them with both linkers, inspect PE structures, compare semantics, and run
all Rust unit tests. It cannot provide the authoritative Windows loader; native
execution belongs in the Windows workflows.

The user already verified this local tool state:

```console
rustc 1.95.0 (59807616e 2026-04-14)
x86_64-pc-windows-msvc installed
taplo 0.10.0
xwin 0.9.0
~/.xwin/crt present
~/.xwin/sdk present
```

Also needed by the documented gates: Rust `nightly` for formatting, Rust `1.94.0` and
`1.95.0` toolchains as named below, LLVM tools (`clang-cl`, `lld-link`,
`llvm-readobj`), `uv`, and `actionlint`. At the time of the core acceptance there was
no missing local blocker.

Why this is valid without a physical Windows PC:

- Unit tests and format builders are host-independent.
- `xwin` supplies real Windows SDK and CRT import libraries for cross-linking.
- The local differential suite gives the same inputs to Wild and `lld-link` and
  compares loader-visible semantics.
- GitHub's `windows-latest` x86-64 runner supplies the actual Microsoft loader and
  runtime. That is the authoritative final execution test.
- Wine or a Windows 11 ARM64 VM can be optional convenience probes, but neither is
  required for this branch. A physical Windows machine adds little for this scope.

## Local validation commands

Run from the repository root:

```console
cargo +nightly fmt --all -- --check
cargo +1.94.0 clippy -p linker-utils -p libwild -p wild-linker \
  --all-targets --no-default-features --features pe -- -D warnings
cargo +1.95.0 test -p linker-utils -p libwild \
  --no-default-features --features pe

cargo build -p wild-linker --features pe
uv run plans/pe-coff/pe-repro_001.py --self-test
uv run plans/pe-coff/pe-repro_001.py --wild target/debug/wild
uv run plans/pe-coff/pe-perf_001.py --wild-budget-seconds 30

actionlint .github/workflows/pe-coff.yml .github/workflows/pe-runtime.yml \
  .github/workflows/pe-tauri.yml .github/workflows/pe-vibe.yml
taplo check .typos.toml Cargo.toml wild/Cargo.toml libwild/Cargo.toml \
  linker-utils/Cargo.toml
```

The fuller xwin-backed integration test uses an absolute symlink named `link.exe`:

```console
cargo +1.95.0 build -p wild-linker --no-default-features --features pe
WILD_PE_LINKER_FULL=/absolute/path/to/link.exe \
  cargo +1.95.0 test -p wild-linker --test windows_pe_runtime \
  --no-default-features --features pe -- --nocapture
```

The Python plans are self-documenting:

- `pe-coff_001.py`: normalize and compare two already-linked PE images.
- `pe-repro_001.py`: compile six freestanding fixtures once, link with `lld-link` and
  Wild twice, prove Wild-to-Wild byte determinism, then compare normalized semantics.
- `pe-perf_001.py`: compile/link a representative Rust `std` program with both
  linkers, inspect both images, and enforce only a generous Wild time budget.

## GitHub Actions verification

Focused workflows were added so the branch does not pay for the repository's entire
unrelated matrix. The normal CI Windows job was also upgraded from build-only to a
reference PE smoke execution.

- `.github/workflows/pe-coff.yml`: push on `feature/pe-coff-v1` plus manual dispatch;
  macOS structural corpus and real-Windows freestanding/TLS execution.
- `.github/workflows/pe-runtime.yml`: manual; full C, C++, DLL, Rust `std`, Rust
  `cdylib`, consumer, and TLS reference/Wild runtime corpus.
- `.github/workflows/pe-tauri.yml`: manual; builds and executes the small Tauri fixture
  in debug and release, requiring exit code 73 after Tauri's Ready event.
- `.github/workflows/pe-vibe.yml`: manual; pinned Vibe debug/release matrix. At the
  current tip, each job builds the same source once with Wild and once with `lld-link`,
  preserves both outputs, validates PE headers, records sizes/SHA-256/first different
  byte, probes sidecars and CLI behavior, and requires both GUIs to create a native
  top-level window and remain alive.

Dispatch and inspect:

```console
gh workflow run pe-coff.yml -R thewh1teagle/wild \
  --ref feature/pe-coff-v1
gh workflow run pe-runtime.yml -R thewh1teagle/wild \
  --ref feature/pe-coff-v1
gh workflow run pe-tauri.yml -R thewh1teagle/wild \
  --ref feature/pe-coff-v1
gh workflow run pe-vibe.yml -R thewh1teagle/wild \
  --ref feature/pe-coff-v1

gh run list -R thewh1teagle/wild --workflow pe-vibe.yml --limit 10
gh run view RUN_ID -R thewh1teagle/wild --json status,conclusion,jobs,url
gh run view RUN_ID -R thewh1teagle/wild --log-failed
gh run download RUN_ID -R thewh1teagle/wild --dir /tmp/wild-run-RUN_ID
```

Authoritative passing evidence before the paired Vibe control:

- PE freestanding/TLS: run
  [30787127729](https://github.com/thewh1teagle/wild/actions/runs/30787127729),
  commit `a242d132`, passed.
- Full runtime: run
  [30787127495](https://github.com/thewh1teagle/wild/actions/runs/30787127495),
  commit `a242d132`, passed.
- Minimal Tauri debug/release: run
  [30787128668](https://github.com/thewh1teagle/wild/actions/runs/30787128668),
  commit `a242d132`, passed.
- Real Vibe Wild-only debug/release: run
  [30789529875](https://github.com/thewh1teagle/wild/actions/runs/30789529875),
  commit `fee26749`, passed.

The Wild-only Vibe run produced:

- Debug: valid AMD64 PE, 79,326,720 bytes; sona/ffmpeg sidecars passed; GUI created a
  top-level window and remained alive; `--help` emitted sona help and then timed out.
- Release: valid AMD64 PE, 12,269,568 bytes; sidecars passed; GUI created a top-level
  window and remained alive; `--help` exited `0xc0000409`.

## Paired Vibe `lld-link` control and byte identity

The earlier local differential gate **never claimed** that `lld-link` and Wild files
were byte identical. It proved:

- Wild link A equals Wild link B byte-for-byte (reproducibility).
- Wild and `lld-link` agree after normalizing irrelevant producer choices and allowing
  two tightly checked layout equivalences.

The known layout equivalences are intentional: Wild keeps the writable IAT in
`.idata`, while `lld-link` may fold it into `.rdata`; Wild preserves one zero-fill
contribution as `.bss`, while `lld-link` may represent the equivalent mapping as
`.data`. Section order, padding, debug encoding, addresses, and other legal producer
choices also need not match. Loader-visible correctness, not byte cloning lld, is the
target.

Commits `88da9252` and `52aeac2d` add the definitive application-level control: build
the same pinned Vibe revision and profile in the same Windows job, first with Wild and
then with `lld-link`; preserve both before the target directory is reused; execute the
same CLI/GUI probes; inspect both with `llvm-readobj`; record SHA-256, sizes, and the
first differing byte.

Run
[`30801348499`](https://github.com/thewh1teagle/wild/actions/runs/30801348499)
at commit `52aeac2d` is the definitive paired-control run. The Wild build, debug
job, and release job all completed green with zero acceptance failures.

Debug evidence:

- Wild debug: 79,326,720 bytes,
  SHA-256 `60B9671F9FE2CC1031220ED5A970FC264C8190878A07D83F8DB15416CAD0FBD8`.
- lld debug: 42,254,848 bytes,
  SHA-256 `1EE3AB831B4AD878EE1D5BF2F06B2F3137D0587CF5EF269C1E6E94B5CDA9C569`.
- `byte_identical=false`; the first differing file offset is 2 (`0x2`).
- Both CLI wrappers printed the exact same 305-byte sona help output (SHA-256 prefix
  `1935c428`), both hit the same Aptabase panic, and both timed out.
- Both no-argument GUI processes created a top-level native window and remained alive.
- Direct sona and ffmpeg sidecars both exited 0.

Release evidence:

- Wild release: 12,269,568 bytes,
  SHA-256 `3F9C220FA05DC9B0C86D96E7747063961375455B6641320D3CC2743FC76E53E6`.
- lld release: 10,984,448 bytes,
  SHA-256 `F957CB01356BCB7A41CAE9043220F9CF5B9EA7240159111AB206D7E1C3E15FB1`.
- `byte_identical=false`; the first differing file offset is again 2 (`0x2`).
- Both CLI wrappers exited `-1073740791` (`0xc0000409`). Captured stdout was empty for
  both because of Vibe's release `CONOUT$` behavior described below.
- Both no-argument GUI processes created a top-level native window and remained alive.
- Direct sona and ffmpeg sidecars both exited 0.

## Exact Vibe CLI hang/crash diagnosis

Pinned Vibe revision:
`1c5466b21b2228d708d9140d0f2ec71f69c0bb3e` from
`thewh1teagle/vibe`.

The apparently linker-related debug hang was diagnosed from captured stdout/stderr in
failure run
[`30788795304`](https://github.com/thewh1teagle/wild/actions/runs/30788795304),
not guessed from the timeout:

1. Vibe treats any `argv[1]` as CLI-forwarding mode. Its `cli::run` starts `sona.exe`,
   forwards the arguments, waits for it, and joins its output threads.
2. The sidecar succeeds and prints a complete, correct help page to stdout.
3. After the sidecar exits, Vibe calls `app_handle.flush_events_blocking()`.
4. That path accesses
   `Arc<tauri_plugin_aptabase::client::AptabaseClient>` through Tauri `state()` even
   though the state was never `manage()`d when Aptabase was not configured.
5. Tauri 2.10.3 panics with:

   ```text
   state() called before manage() for alloc::sync::Arc<tauri_plugin_aptabase::client::AptabaseClient>
   ```

6. Debug uses unwinding. The panic occurs on the spawned `tokio-rt-worker`; that worker
   dies, but the main Tauri event loop remains alive without a CLI window, so the
   harness times out.
7. Vibe's release Cargo profile uses `panic = "abort"`. The same panic aborts the whole
   process and Windows reports `0xc0000409`.
8. Release also calls an `attach_console()` path using `freopen(CONOUT$)`. That replaces
   the harness's redirected handles, explaining why captured release stdout/stderr can
   be empty even when the sidecar printed output.

The no-argument GUI path is the supported application path and passes in both profiles.
The paired `lld-link` control reproducing the same debug behavior is strong evidence
that this CLI defect belongs to Vibe/Tauri plugin state management, not Wild's PE.

## CI pitfalls already discovered

- Never trust a cached Vibe executable merely because a Tauri build command succeeded.
  Cargo can reuse the final link product even when the linker environment changed.
- `cargo clean --manifest-path Cargo.toml --package vibe --target
  x86_64-pc-windows-msvc` reported `Removed 0 files` for the release target in paired
  run
  [30799889404](https://github.com/thewh1teagle/wild/actions/runs/30799889404).
  The old `target/x86_64-pc-windows-msvc/release/vibe.exe` remained, so the freshness
  assertion correctly failed.
- The fix in `52aeac2d` is explicit: after package-scoped clean, compute the exact
  profile path, remove that exact `vibe.exe` with `Remove-Item -LiteralPath ... -Force`,
  assert it is absent, then create a timestamp marker. After linking, assert the output
  is newer than the marker.
- Preserve the Wild output before the lld build reuses the Cargo target directory.
- A saved Wild response directory is not automatically a replayable final link. Earlier
  attempts found multiple numbered save directories and Cargo hashed outputs; selecting
  the wrong invocation or missing `run-with` produced misleading evidence. The clean
  paired rebuild is more authoritative.
- `dumpbin` output parsing was brittle. The workflow now validates PE headers directly
  and uses `llvm-readobj` for diagnostics.
- CLI stdout/stderr must always be uploaded before diagnosing a timeout or crash. The
  stdout proved sona completed; stderr exposed the exact Aptabase panic.
- GUI success is not “process started.” The workflow requires a top-level window and
  continued liveness. It isolates each process, kills only the PID it started, and uses
  separate temporary application-data directories.

## Remaining work and priorities

The original v1 is usable and accepted, but it is not “as good as Linux Wild” yet.
Recommended order:

1. Preserve the exact-SHA Goal 1 and Goal 2 evidence in `quality-gate.md`; the
   fork default branch has already been restored to `main`.
2. Preserve the existing correctness gates. Add malformed-image/negative tests when
   touching loader directories; keep real-Windows execution authoritative.
3. Preserve Goal 2's benchmark protocol and rerun it when changing archive,
   symbol, layout, relocation, allocation, or parallel behavior. Do not widen
   the bounded Vibe and Rust-std claims without new evidence.
4. Add real PDB emission and debugger validation. This is a substantial feature, not
   merely accepting `/PDB`.
5. Add LTO interoperability (`/LTCG`) with explicit ownership of who runs the codegen
   plugin. Study `lld/COFF` and LLVM's LTO APIs as primary references, while retaining
   independent tests rather than requiring byte-identical output.
6. Design incremental linking only after deterministic full links and PDB behavior are
   stable. Incremental state format, invalidation, and debug information make this
   another substantial project.
7. Expand compatibility across Windows SDK/MSVC versions, more real applications,
   sanitizers/security metadata, delay-loaded DLL use, unusual `.def` inputs, and
   negative loader cases.
8. Broaden the benchmark matrix to C++, Tauri, debug links, `link.exe`, and a
   controlled true-cold environment before making claims about those cases.
9. For parity with Linux Wild, continue with production hardening, diagnostics, feature
   breadth, memory/performance work, fuzzing, and sustained real-world use. PDB + LTO +
   incremental support would improve usability greatly but would not alone equal the
   Linux linker's maturity.

Looking at lld's source is useful for understanding undocumented conventions and
option semantics, especially PE loader edge cases, PDB, and LTO. Treat the PE/COFF
specification, Windows execution, and focused differential tests as the truth; do not
turn “correct” into “byte-identical to lld.”

## Safe next-session checklist

```console
cd /home/yakov/Documents/wild
git status --short --branch
git log -5 --oneline --decorate
for id in 30826452916 30826455326 30826457947 30826460336; do
  gh run view "$id" -R thewh1teagle/wild \
    --json status,conclusion,headSha,jobs,url
done
```

Then:

- Confirm Goal 1 remains pinned at or after `547c72f3`; attribute Goal 2
  benchmark claims specifically to code `a68ba652` and its recorded binary.
- Do not touch untracked `AGENTS.md`.
- Read `vibe-debug-comparison-diagnostics/binary-comparison.txt` and the corresponding
  release file before making claims about byte identity.
- Read the closeout Goal 2 JSON paths in `quality-gate.md` before making speed or
  memory claims.
- Run format/actionlint checks for any changed workflow or Markdown-adjacent config.
- Commit only intended tracked files, push the feature branch, and do not open a PR.

## Historical update 2026-08-03: Goal 1 closeout and Goal 2 checkpoint

This section supersedes the paths, priorities, and "remaining work" above
where they conflict.

- Development moved from the macOS M4 to a Linux aarch64 workstation at
  `/home/yakov/Documents/wild` (20 cores, 121 GB RAM). Setup, quirks
  (clang-cl/lld-link wrapper scripts, rustup override, clang-format), and full
  gate verification are in `host-tooling.md`. All local quality gates and the
  full xwin reference/candidate corpus pass at Goal 1 closeout.
- Goal 1 completed at `547c72f309dc8dd73e5a43166e183491138395e7`.
  The option sweep, real `/OPT:REF`, delay imports with unwind metadata,
  stability/fuzz/negative-loader coverage, and embedded manifests are all
  implemented and re-audited.
- Exact native evidence on that SHA is runtime
  [30809478091](https://github.com/thewh1teagle/wild/actions/runs/30809478091),
  PE [30809478302](https://github.com/thewh1teagle/wild/actions/runs/30809478302),
  Vibe [30809478008](https://github.com/thewh1teagle/wild/actions/runs/30809478008),
  and Tauri
  [30809478031](https://github.com/thewh1teagle/wild/actions/runs/30809478031);
  all passed.
- Goal 2 had reached checkpoint `8dd69ea6`. The 78.1 MB Vibe
  reproduction improved from 617–652 ms warm at 1/2/4/8/10 threads to
  180/152/141/141/138 ms. A separate 30-pair confirmation proves wins over
  `lld-link` at the same 8 and 10-thread settings; it does not prove
  best-vs-best or lower-thread superiority.
- Checkpoint warm/advisory-cold medians, MAD, RSS, scaling, paired deltas, binary and
  corpus hashes, and all evidence paths are in `pe-link-bench_001.md`. Advisory
  cold uses `POSIX_FADV_DONTNEED`, not a global cache drop.
- Accepted work covers measured archive/symbol/COMDAT/layout/relocation/hash
  reuse and parallelism plus mimalloc v2. Neutral or regressive whole-stage
  layout, lazy-archive, and aggressive parallel prototypes were not integrated.
  High-thread Vibe RSS remains above lld and is an explicit tradeoff.
- PDB, full CFG/security metadata, LTO, incremental linking and niche
  compatibility remain deferred unchanged as specified in `GOAL.md`.
- Goal 2 remained open: best-vs-best Vibe was about 33.5% behind warm and
  14.8% behind advisory-cold. The checkpoint's `min_seconds=0`, unpinned runs
  are below the documented authority protocol. Continue optimizing, then rerun
  with homogeneous CPU affinity and the five-second accumulated-time floor.
- Reading order for a new session: `GOAL.md` → `goal1-gaps.md` →
  `host-tooling.md` → this file → `quality-gate.md` → `feature-matrix.md`.

## Update 2026-08-03: Goal 2 closeout

This update supersedes the historical interim performance status above.

- Goal 2 completed for exact benchmarked code
  `a68ba65237ea98c29f166f7ee10fb8dfbbb1a5e0`. The eventual documentation tip
  is a later evidence-only commit and must not be substituted for that source
  or binary identity.
- The final protocol pinned homogeneous CPUs
  `5,6,7,8,9,15,16,17,18,19`, accumulated at least five seconds per row, and
  recorded randomized paired latency, MAD, RSS, output validation and Wild
  determinism. Exact tool/corpus hashes and seven artifacts are in
  `pe-link-bench_001.md`.
- The standard warm sweep's independent best medians were Wild 100.356 ms and
  lld 98.909 ms. The direct best-configuration pair measured Wild
  `/threads:10` at 99.576 ms and lld `/threads:1` at 103.823 ms, a 4.247 ms
  (4.1%) tool-median difference. Paired Wild-minus-lld deltas were
  -4.084 ± 2.522 ms with 35/50 Wild wins. Completion is explicitly bounded to
  that direct warm
  authority; cold evidence is mixed and Wild's high-thread RSS is higher.
- Accepted late work covers incremental relocation-section layout, avoided
  relocation relayout, foldhash resolver/archive lookup, reuse of import-time
  selected-object metadata, flat COMDAT adjacency, and overlap of build-ID
  hashing with output copying. The broad payload-borrow prototype was rejected,
  so it is not part of the accepted inventory.
- Exact-SHA native Windows PE run 30826452916, runtime run 30826455326,
  Tauri run 30826457947 and Vibe run 30826460336 all completed successfully;
  the Vibe release and debug jobs both passed.
- PDB, full CFG/security metadata, LTO, incremental linking and niche
  compatibility remain separate deferred phases as specified in `GOAL.md`.
