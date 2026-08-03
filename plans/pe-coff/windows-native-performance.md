# Native Windows PE/COFF performance harness

Recorded 2026-08-03 for the native x86-64 Windows optimization host. This is a
new plan only; it does not supersede the completed Goal 2 evidence in
`pe-link-bench_001.md`.

## Objective

Create a fast, repeatable native-Windows loop for comparing Wild with
`lld-link`, profiling the slow Wild phases, making one measured change at a
time, and rejecting regressions. Compilation and corpus preparation must never
be included in timed linker samples.

The first new application corpus should be a pinned release build of `uv`.
Vibe remains the application-scale regression corpus, and the existing
Rust-std corpus remains the small latency corpus. Later, add a large C++ corpus
such as Clang to prevent Rust-only overfitting.

## Current Windows host

- Windows x86-64 on an AMD Ryzen 5 4500U: 6 cores and 6 logical processors.
- Approximately 16 GB RAM.
- Visual Studio Community 2022 17.14 with MSVC 14.44 tools.
- Windows SDK 10.0.26100.0.
- LLVM 22.1.8 in `C:\Program Files\LLVM\bin`, including `clang-cl.exe`,
  `lld-link.exe`, and `llvm-readobj.exe`.
- Rust 1.95.0 with Clippy and rustfmt.
- Rust 1.94.0 with Clippy.
- Rust nightly 1.99.0-nightly with rustfmt.
- Native `x86_64-pc-windows-msvc` target.
- `uv` 0.8.15 with a managed CPython 3.12.11 interpreter.
- NASM 3.02 at `C:\Users\user1\AppData\Local\bin\NASM\nasm.exe`.
- Windows Performance Recorder, Analyzer, and `xperf` are installed.

LLVM and NASM are not guaranteed to appear in the environment inherited by an
already-running terminal. The harness should discover the paths above or accept
explicit command-line paths; it must not require a permanent `PATH` edit.

No additional installation is currently required for the initial harness and
`uv` corpus work. Ask the user before installing anything else.

## Existing harness status

There is no native-Windows performance harness yet.

`pe-link-bench_001.py` is the correct protocol and report-format starting point,
but it currently fails during import on Windows because Python has no `resource`
module. It also relies on Unix-only facilities:

- `taskset` for CPU affinity;
- GNU `time` for maximum RSS;
- `os.posix_fadvise(..., POSIX_FADV_DONTNEED)` for advisory input eviction.

The general `benchmarks/runner` is not a Windows alternative. It assumes Unix
`wait4`, executable shell `run-with` files, `stat`, and tmpfs.

The native `windows_pe_runtime` and PE/Tauri tests are correctness harnesses.
They should remain correctness gates but should not be presented as performance
measurements.

## Harness implementation requirements

Port or extend `pe-link-bench_001.py` without weakening its existing Unix
behavior or changing the meaning of historical results.

The native-Windows path must provide:

1. High-resolution elapsed time using `time.perf_counter()` around a fresh
   linker process.
2. Per-process user and kernel CPU time using `GetProcessTimes`.
3. Peak working set using `GetProcessMemoryInfo`, a Job Object, or another
   documented Windows API. Record exactly which metric is used.
4. Processor affinity set before timed work begins. Use a Windows API rather
   than `start /affinity` or a delayed PowerShell property assignment that can
   race a short linker invocation.
5. Randomized paired Wild/`lld-link` blocks with identical inputs and output
   locations.
6. Three warmups, at least 15 measured samples, and at least five accumulated
   seconds per tool and configuration for authoritative rows.
7. Full raw samples, median, MAD, p95, paired Wild-minus-lld deltas, paired-win
   count, tool hashes, corpus hashes, host identity, and settings in JSON.
8. Fresh output deletion before each sample, valid AMD64 PE inspection after
   timing, and two-run Wild byte-determinism validation.
9. A warm mode that works without elevated privileges.
10. Clear refusal or an explicitly different Windows definition for
    `cold-input-cache`. Do not label a Windows standby-list or filesystem-cache
    experiment equivalent to POSIX `FADV_DONTNEED` without proving it.
11. Corpus-independent self-tests that run on Windows and Unix.
12. No third-party Python dependency unless it materially improves correctness;
    prefer the standard library plus `ctypes` Windows bindings.

Preserve the existing JSON schema where fields retain the same meaning. If a
Windows metric differs, add a named platform-specific field or increment the
schema version rather than silently reusing a Unix field.

## `uv` corpus

Pin an exact released `uv` source revision and record its commit, Cargo lockfile
hash, rustc version, MSVC/SDK version, profile, feature flags, and final
executable hash.

Build `uv` once with `lld-link` and add `/reproduce:<path>` only to the final
`uv.exe` link. Do not add one shared reproduction path to every Cargo linker
invocation: build scripts and proc macros also link and may overwrite it. Use a
small linker wrapper that detects the final `/OUT:...uv.exe` invocation,
forwards every original argument unchanged, and adds `/reproduce` only there.

Extract the reproduction outside the repository. Do not commit it: the archive
can be large and contains copied toolchain and SDK inputs. Keep its relative
layout intact because `response.txt` paths are relative to the reproduction
root.

Before benchmarking, prove that both linkers can replay the same response file,
that both outputs are valid AMD64 PE images, and that both execute
`uv.exe --version` successfully. Semantic comparison and native execution are
correctness checks outside the timed region.

`uv` is suitable for fast iteration only in replay form. Rebuilding it is corpus
preparation, not a benchmark loop.

## Measurement protocol for this machine

Start with a complete warm sweep at `/threads:1,2,3,4,5,6`. This CPU has only
six logical processors, so the former Linux 10-thread optimum must not be
carried over.

Select each linker's lowest-median configuration independently, then run a new
randomized direct thread-pair comparison. Use the direct pair as the primary
best-versus-best result while retaining the complete sweep as sensitivity and
scaling evidence.

Run on AC power with Windows power mode fixed, background updates and indexing
quiet, and the machine thermally stable. Record the power mode and affinity
mask. Prefer a homogeneous affinity set; this CPU has no hybrid performance and
efficiency core split, but affinity still reduces scheduler movement.

Write both linkers' outputs to the same filesystem and directory class. The
initial paired warm loop may use the local SSD. If output I/O dominates or adds
large variance, investigate a RAM-backed output location as a separate setup
decision; do not silently compare one linker on RAM and the other on disk.

## Optimization loop

For every candidate change:

1. Build an optimized Wild binary with the exact source SHA recorded.
2. Run the focused PE correctness tests and the harness self-tests.
3. Run the pinned `uv` replay with Wild phase timing enabled outside the
   authoritative wall-time samples.
4. Identify the largest measured phase or hot function; do not optimize from
   intuition alone.
5. Make one coherent change.
6. Rerun correctness, determinism, and a quick paired smoke comparison.
7. Run the full randomized paired protocol only for promising changes.
8. Keep the change only when the distributions show a repeatable improvement;
   record neutral and rejected experiments so they are not repeated.
9. Periodically rerun Vibe and Rust-std to detect workload-specific regressions.

Wild's `--time` phase instrumentation is the first diagnostic. Use Windows
Performance Recorder/Analyzer for deeper CPU, scheduling, file-I/O, and working
set analysis when phase timing is insufficient. Profiling runs are diagnostic
and must remain separate from authoritative elapsed-time samples.

## Acceptance criteria

The native-Windows harness is ready when:

- all self-tests pass on Windows and the existing Unix behavior remains green;
- it produces a complete JSON result for a pinned corpus without manual steps;
- affinity, elapsed time, CPU time, and peak working set are verified against
  small controlled child-process tests;
- paired ordering and thread-pair behavior have regression tests;
- Wild determinism and AMD64 PE output validation run automatically;
- the same `uv` corpus replays through both Wild and `lld-link` and the resulting
  executable behavior is validated outside timing;
- the documentation states the exact limits of warm and any Windows cold-cache
  measurements.

