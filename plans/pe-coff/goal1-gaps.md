# Goal 1 gap assessment

Codebase audit performed 2026-08-03 on `feature/pe-coff-v1` at `f2392c1a`
(four parallel read-only subagents; findings spot-verified). This is the
evidence behind the Goal 1 priority list in `GOAL.md`. Overall verdict: the
accepted "works on real apps" milestone is real, but Goal 1
("production-usable and stable") still has the items below. With PDB, LTO,
full CFG, and incremental deferred (see `GOAL.md`), everything remaining is
small-to-medium.

## 1. Option compatibility (small, do first)

Unknown options are a fatal error (`libwild/src/args/coff.rs:554`,
`args.rs:358`), and ~30 common lld-link/link.exe options are entirely
unhandled. A stock CMake Release link line fails on at least
`/INCREMENTAL:NO`, `/MANIFESTUAC`, `/ERRORREPORT`, `/TLBID`, and
`/MANIFEST:EMBED` (only bare/`:NO` parse, `coff.rs:766`). Also missing:
`/IGNORE`, `/WX`, `/MAP`, `/ORDER`, `/STUB`, `/RELEASE`, `/APPCONTAINER`,
`/LARGEADDRESSAWARE`, `/HIGHENTROPYVA`, `/CETCOMPAT`, `/DEPENDENTLOADFLAG`,
`/FUNCTIONPADMIN`, `/SWAPRUN`, `/OPT:LBR` and `/OPT:ICF=N` spellings
(`coff.rs:783` bails), and every `-`-prefixed spelling (`coff.rs:332` only
accepts `/`; `-out:` is silently treated as an input file). Rust builds work
because that path was tuned; generic MSVC builds do not link today.

Currently accepted no-ops (fine): `/DEBUG`, `/PDB`, `/PDBALTPATH`, `/NATVIS`,
`/MANIFEST[:NO]`, `/MANIFESTDEPENDENCY`, `/GUARDSYM`, `/EDITANDCONTINUE`,
`/THROWINGNEW`. 31 options are fully honored end-to-end.

## 2. `/OPT:REF` and `/OPT:ICF` are pure no-ops (medium-large)

Parsed into `CoffArgs::optimization` (`coff.rs:507`, `:776-789`) and never
read anywhere in the tree — there is no section-GC pass and no COMDAT-folding
pass on the PE path. Consequence: Wild PE images are materially larger than
lld's (consistent with 79 MB vs 42 MB debug Vibe). `/OPT:NOREF`/`NOICF`
currently "match" lld only because nothing is stripped. Goal 1 requires real
`/OPT:REF`; ICF may follow later.

## 3. Delay imports (medium, best effort-to-value)

`linker-utils/src/pe_delay_imports.rs` (1146 lines, tested) implements the
whole binary format: descriptor array, INT/IAT/bound/unload thunk tables,
symbolic helper-thunk relocations. Integration is zero: `/DELAYLOAD` is a
fatal unrecognized option; no eager-versus-delayed partitioning in the
resolver; no `__delayLoadHelper2`/`delayimp.lib` handling; no `.didat`
layout, directory entry (`pe_writer.rs:3042` region), helper thunk emission,
or delay-IAT base relocations. The remaining work closely mirrors the
existing eager path in `libwild/src/pe_imports.rs`.

## 4. Stability/test gaps (medium, alongside everything)

- No fuzzing anywhere in the workspace (no cargo-fuzz/proptest/arbitrary).
- AMD64 relocation application has one unit test (`libwild/src/coff_x86_64.rs`);
  REL32_1..5, ADDR32, SECREL/SECREL7, SECTION, and overflow diagnostics are
  untested.
- Forwarded exports and ordinal-only imports have directory-encoding tests but
  no runtime fixture (DLL forwarding to another DLL, import-by-ordinal).
- `wild/tests/windows_pe_runtime.rs` is compiled out on Linux
  (`:591`, placeholder test) even though this host satisfies its capability
  probe — extend the cfg (see `host-tooling.md`).
- The runtime test never structurally diffs Wild output against the lld
  reference; `linker-diff` has no PE backend.
- Archives/resolver tested only on tiny synthetic archives; exception-heavy
  C++ at `.pdata` scale untested.

## 5. Manifest embedding (small)

`/MANIFEST:EMBED`, `/MANIFESTUAC`, `/MANIFESTFILE`, `/MANIFESTINPUT` are
unhandled or rejected; `manifest`/`manifest_dependencies` fields are stored
but never read. GUI apps expect embedded UAC/common-controls manifests.
Accept-and-warn is an acceptable interim; real embedding is smallish.

## Deferred (per `GOAL.md`) — state recorded for later phases

- **PDB (large; comparable to the whole existing PE writer).** Done and
  reusable: `linker-utils/src/pe_debug.rs` debug-directory + RSDS container +
  deterministic build-id, wired for a single REPRO entry
  (`pe_writer.rs:1035`, `:1266-1321`). Absent: MSF container, `.debug$S`
  symbol pipeline, `.debug$T` TPI/IPI type merging (dominant cost), line
  info, GUID/age generation, `%_PDB%` substitution. `DebugRecord::CodeView`
  exists but is never constructed by the writer.
- **Full CFG (large).** `/GUARD:CF` hard-rejects (`pe_writer.rs:1571-1575`,
  verified); guard sections `.gfids`/`.giats`/`.gljmp`/`.gehcont` are
  discarded (`guard_metadata_policy`, `:1682`); the nine `__guard_*` symbols
  are absolute zero (`:40-51`); `linker-utils/src/pe_load_config.rs` encoder
  (854 lines) exists but is entirely unwired; `/GUARDSYM` is parsed but never
  consumed. Current behavior is safe and honest — keep it until this phase.
- **LTO, incremental linking**: intentionally rejected; no code.
