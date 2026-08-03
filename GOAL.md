# Goal

Make Wild's x86-64 PE/COFF support production-usable and stable, then fast.
Two sequential goals on two branches; optional heavyweight features are
deferred to the end.

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

## Goal 2 — performance (in progress on `feature/pe-coff-performance`)

The current performance checkpoint is code commit
`8dd69ea6b4adba060782cafbba33bd57b44dee4d` on 2026-08-03. The work first
added a link-only replay harness and phase instrumentation, then optimized the
measured archive, resolution, COMDAT, layout, relocation, hashing, allocation,
and symbol-metadata costs without weakening the Goal 1 correctness gates.

On the pinned 78.1 MB Vibe release reproduction, the original Wild baseline
of 617/618/650/652/627 ms at 1/2/4/8/10 threads fell to
180/152/141/141/138 ms. A separate randomized 30-pair confirmation measured
Wild at 138.2 ms versus `lld-link` at 146.2 ms at 8 threads, and 138.8 ms
versus 156.3 ms at 10 threads. Wild won 19/30 and 25/30 paired samples,
respectively. The advisory cold-input-cache confirmation also favored Wild at
8 and 10 threads; it is not a machine-cold-cache claim.

On the smaller 32.9 MB Rust-std reproduction, Wild beat `lld-link` in every
measured warm configuration (1/4/8/10 threads) and in advisory-cold 4/8/10;
the advisory-cold one-thread case remained 10.1% slower. Exact protocol,
medians, MAD, RSS, scaling, tool/corpus hashes, and evidence paths are recorded
in `plans/pe-coff/pe-link-bench_001.md` and
`plans/pe-coff/quality-gate.md`. These are useful same-`/threads` results, but
they do not yet satisfy Goal 2: on Vibe, Wild's best warm result is about
138 ms versus lld's best 103 ms, and its best advisory-cold result is about
244 ms versus lld's best 212 ms. The checkpoint also used no CPU affinity on a
heterogeneous host and `min_seconds=0`, below the documented authoritative
five-second sampling floor. Goal 2 remains open pending an authoritative,
best-vs-best win.

## Deferred to final phases (after both goals, each separate)

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

## Both goals

- Use parallel subagents in worktrees; the manager reviews and merges their work.
- Work only in our fork. Do not open a pull request; upstreaming happens later
  as small separate PRs.
