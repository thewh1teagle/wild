# Goal

Make Wild's x86-64 PE/COFF support production-usable and stable, then fast,
then substantially faster than the established linker alternatives across a
broad real-world corpus. Three sequential goals on three branches; optional
heavyweight features are deferred to the end.

## Goal 1 — production-usable and stable (complete on `feature/pe-coff-v1`)

Match `lld-link` in loader-visible behavior for real release builds; byte
identity is not the target. In priority order:

1. Option compatibility: accept or cleanly no-op the common MSVC/CMake/MSBuild
   flags that today hard-fail (`/INCREMENTAL:NO`, `/IGNORE`, `/ERRORREPORT`,
   `/TLBID`, `/MANIFESTUAC`, `-`-prefixed spellings, …); unknown-option policy
   becomes warn-not-fatal where lld does the same.
2. `/OPT:REF` dead-code elimination (real rather than a parser-only no-op);
   `/OPT:ICF` may follow later.
3. Delay imports end-to-end (`/DELAYLOAD`, `.didat`, helper thunks) — the
   format layer already exists in `linker-utils`.
4. Stability hardening: fuzz targets for object/archive parsers, the AMD64
   relocation application test matrix, forwarded-export and ordinal-import
   fixtures, negative loader tests.
5. Manifest embedding (`/MANIFEST:EMBED`) for GUI apps.

Keep the existing acceptance gates green (runtime corpus, Tauri, Vibe; local
gates per `plans/pe-coff/host-tooling.md`, native execution on GitHub Actions).
Keep resolution/layout/writer stages cleanly separated so Goal 2 is a layer,
not a rewrite, and keep history topical for later small upstream PRs.

"Production-usable" here means release-mode builds; debugging via PDB is
deliberately deferred below.

Completed at `547c72f309dc8dd73e5a43166e183491138395e7` on 2026-08-03. The
option sweep, real `/OPT:REF`, delay imports with AMD64 unwind information,
stability/fuzz coverage, and manifest embedding all pass the local gates and
the native Windows runtime, PE, Tauri, and Vibe workflows recorded in
`plans/pe-coff/quality-gate.md`.

## Goal 2 — performance (complete on `feature/pe-coff-performance`)

Completed for code commit `a68ba65237ea98c29f166f7ee10fb8dfbbb1a5e0`
on 2026-08-03. The eventual documentation commit is evidence about that exact
code revision, not a different benchmarked binary. Goal 2 added a link-only
replay harness and phase instrumentation, then optimized measured archive,
resolution, COMDAT, layout, relocation, hashing, allocation, and symbol-metadata
costs without weakening the Goal 1 gates.

The authoritative warm Vibe sweep pinned both linkers to the same homogeneous
CPU set and accumulated at least five seconds per row. Wild improved from
143.839 ms at one thread to 100.356 ms at ten; `lld-link`'s best independent
sweep row was 98.909 ms at one thread. A direct randomized best-configuration
comparison removed sweep-position effects by interleaving those selected
configurations: Wild `/threads:10`
measured 99.576 ± 1.178 ms versus `lld-link` `/threads:1` at
103.823 ± 0.966 ms, a 4.247 ms (4.1%) difference between tool medians. The
paired Wild-minus-lld delta median was -4.084 ± 2.522 ms (median ± MAD), and
Wild won 35/50 pairs. The independent sweep's
1.447 ms residual is disclosed rather than hidden; Goal 2's bounded completion
claim rests on the direct best-versus-best authority run, not universal
superiority on every thread count or cache state.

Wild also won the pinned warm Vibe rows at 4/8/10 threads and all supplemental
3/5/6/7/9-thread rows. The advisory cold-input-cache sweep favored Wild
best-versus-best (201.344 versus 208.002 ms). In the noisy direct 10:1 result,
tool medians favored lld by 2.801 ms (204.166 versus 201.365 ms), while the
paired delta median favored Wild by 3.319 ms (MAD 20.399 ms; 14/24 wins); this
mode uses advisory
`POSIX_FADV_DONTNEED` and is not a machine-cold claim. On the 32.9 MB Rust-std
reproduction Wild won every warm row and advisory-cold 2/4/8/10, but not
advisory-cold one thread. Exact medians, MAD, RSS, scaling, protocol, binary and
corpus hashes, and evidence paths are recorded in
`plans/pe-coff/pe-link-bench_001.md` and `plans/pe-coff/quality-gate.md`.

## Goal 3 — native Windows performance (`feature/pe-coff-windows-performance`)

Make PE/COFF performance reflect Wild's core purpose: link real programs as
fast as possible. Goal 2 established one bounded best-versus-best Vibe result;
Goal 3 must generalize the performance work across several pinned Rust
applications on a physical x86-64 Windows machine and make Wild decisively,
repeatably faster than `lld-link`, not merely competitive in one configuration.

In priority order:

1. Implement the native-Windows link-only replay harness specified in
   `plans/pe-coff/windows-native-performance.md`. Preserve randomized paired
   execution, per-linker thread sweeps, direct best-versus-best confirmation,
   raw samples, median/MAD/p95, CPU time, peak working set, affinity, binary and
   corpus hashes, PE validation, and Wild determinism.
2. Capture exact, immutable `lld-link /reproduce` corpora outside the repository
   for a tiered Rust matrix: Rust hello-world as the process-startup floor,
   Rust-std for the fastest inner loop, ripgrep for a small real application,
   rust-analyzer for a larger symbol/archive/COMDAT workload, and uv as the
   primary substantial Windows application. Keep Vibe as the periodic
   application-scale regression corpus.
3. Establish an immutable baseline for the branch on this Windows host. Sweep
   `/threads:1,2,3,4,5,6` for both linkers, independently select each linker's
   fastest configuration, and compare those configurations in randomized
   direct pairs. Do not carry the previous Linux ten-thread optimum onto this
   six-logical-CPU machine.
4. Use the smallest representative corpus for rapid iteration, but confirm
   every promising change on uv or rust-analyzer so process startup and one
   narrow workload do not drive the design. Periodically rerun the complete
   matrix to catch cross-corpus regressions.
5. Optimize only measured costs. Start with Wild's phase timings, then use
   Windows Performance Recorder/Analyzer when phase totals are insufficient.
   Investigate archive preparation and extraction, symbol resolution, COMDAT
   reachability, relocation analysis/application, layout, hashing, allocation,
   output copying, synchronization, scheduling, and shutdown according to the
   profiles rather than a predetermined rewrite plan.
6. Keep each optimization coherent and independently measurable. Run a quick
   paired smoke comparison during iteration, the full statistical floor for
   candidates, and preserve rejected or neutral experiment evidence so the
   same ideas are not repeatedly rediscovered.
7. Preserve all Goal 1 correctness, native execution, semantic-equivalence,
   malformed-input, and determinism gates. Performance changes must not rely on
   unsafe option weakening, skipped loader metadata, stale outputs, or unequal
   work between Wild and `lld-link`.

Goal 3 completes only when authoritative warm, direct best-versus-best Windows
measurements show all of the following on pinned inputs and binaries:

- Wild is at least 20% faster than `lld-link` on the geometric mean of the
  primary Rust-std, ripgrep, rust-analyzer, and uv corpora.
- Wild is individually faster on both uv and rust-analyzer, so the result is
  not carried by tiny links.
- No primary corpus regresses by more than 3% from the immutable Goal 3 Wild
  baseline without an explicitly justified corpus-wide tradeoff.
- Correctness, deterministic output, and native execution remain green.
- Peak working set and scaling are recorded and bounded; a speed win must not
  be presented as a memory win unless the measurements also prove that claim.

This goal is optimization only. PDB generation, CFG/security expansion, LTO,
incremental linking, new architectures, and niche compatibility work are out of
scope even if encountered during profiling. Do not expand feature scope to make
a benchmark pass; use supported release-mode inputs and keep deferred work
deferred.

## Deferred to final phases (after all three goals, each separate)

- Optional debug tooling: PDB emission (MSF/CodeView/type merging) with
  debugger validation; real `/MAP` output. Until then `/DEBUG`/`/PDB` stay
  accepted no-ops with the deterministic debug directory.
- Optional security hardening: full Control Flow Guard (`/GUARD:CF`),
  `/GUARD:EHCONT`, `/CETCOMPAT`. Keep the current safe behavior: conservative
  preservation of CRT metadata, explicit rejection instead of incomplete
  security metadata.
- LTO (`/LTCG`), after PDB.
- Incremental linking (`/INCREMENTAL`), last — needs stable full links and PDB.
- Niche compatibility: thin archives, exotic `.def` directives,
  `/MERGE:.pdata`, non-x86-64 targets.

## All goals

- Use parallel subagents in worktrees; the manager reviews and merges their work.
- Work only in our fork. Do not open a pull request; upstreaming happens later
  as small separate PRs.
