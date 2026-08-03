# Goal 1 closeout assessment

The initial audit was performed on `f2392c1a`. Its five findings were closed
and re-audited on 2026-08-03 at
`547c72f309dc8dd73e5a43166e183491138395e7`. Local unit, lint, formatting,
fuzz-smoke, reproducibility and full xwin corpus gates passed; the exact native
Windows runtime, PE, Tauri and Vibe workflows are recorded in
[`quality-gate.md`](quality-gate.md). Goal 1 has no remaining material gap.

## Closed findings

1. **Option compatibility:** common CMake/MSBuild options and `-`-prefixed
   spellings are parsed; safe compatibility flags no-op cleanly and unknown
   options warn. Enabled CET, CFG, LTO and incremental linking remain explicit
   failures because their metadata/stages are deferred.
2. **`/OPT:REF`:** selected COMDAT groups now have a real relocation-driven
   liveness pass, including associative groups, weak externals,
   `/ALTERNATENAME`, exported/entry/include roots and CRT load-config roots.
   Dead eager/delay imports and unused public thunks are pruned. `/OPT:ICF`
   remains deferred.
3. **Delay imports:** `/DELAYLOAD` is integrated through archive selection,
   `.didat`, directory 13, delay IAT base relocations and
   `__delayLoadHelper2`. Generated AMD64 resolver thunks preserve integer and
   vector argument registers and publish valid `.pdata`/unwind records. The
   native runtime corpus executes a delay-loaded DLL.
4. **Stability:** `fuzz/coff_parsers` exercises standard/bigobj COFF, archives,
   import libraries, relocations, COMDAT and weak records; AMD64 relocation
   kinds and overflows have a matrix; Linux runs the full xwin corpus; ordinal
   imports, forwarded exports, structural comparison and malformed-image
   behavior are covered locally and on Windows.
5. **Manifests:** `/MANIFEST:EMBED[,ID=n]`, `/MANIFESTUAC`,
   `/MANIFESTDEPENDENCY`, `/MANIFESTINPUT` and `/MANIFESTFILE` are integrated,
   including UTF-8/UTF-16 merge input, executable/DLL IDs, conflict checks,
   sidecars and a native GUI-subsystem fixture.

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

## Distribution UX note (until upstream lands PE support)

The fork is the distribution channel while the upstream PR stack is in
review. Target UX for users:

```console
cargo binstall wild-linker --git https://github.com/thewh1teagle/wild   # prebuilt
cargo install wild-linker --git https://github.com/thewh1teagle/wild    # from source
```

Then two config lines (wild.exe lands in `~/.cargo/bin`, already on PATH):

```toml
[target.x86_64-pc-windows-msvc]
linker = "wild"
```

Work needed when cutting the first fork release: `[package.metadata.binstall]`
in `wild/Cargo.toml` (pkg-url pointing at fork GitHub Releases), a release
workflow uploading `wild-{version}-{target}.zip` artifacts built on
`windows-latest`, release notes leading with the config snippet and the
experimental scope (release-mode only, no PDB), and one end-to-end
confirmation that `linker = "wild"` auto-selects COFF mode on a real Windows
host. This channel retires once upstream ships PE support.
