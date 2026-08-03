# Goal

Make Wild's x86-64 PE/COFF support production-usable and stable, then fast.
Two sequential goals on two branches; optional heavyweight features are
deferred to the end.

## Goal 1 — production-usable and stable, no optimization (current: `feature/pe-coff-v1`)

Match `lld-link` in loader-visible behavior for real release builds; byte
identity is not the target. In priority order:

1. Option compatibility: accept or cleanly no-op the common MSVC/CMake/MSBuild
   flags that today hard-fail (`/INCREMENTAL:NO`, `/IGNORE`, `/ERRORREPORT`,
   `/TLBID`, `/MANIFESTUAC`, `-`-prefixed spellings, …); unknown-option policy
   becomes warn-not-fatal where lld does the same.
2. `/OPT:REF` dead-code elimination (real, not the current no-op); `/OPT:ICF`
   may follow later.
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

## Goal 2 — performance (new branch, after Goal 1)

- Profile link-only workloads first (cold/warm, RSS, thread scaling) against
  `lld-link`; only then parallelize the proven hot stages.
- Target beating `lld-link`, in the spirit of Wild's Linux ELF linker.
- Rebase regularly on the Goal 1 branch.

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
