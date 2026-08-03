# Goal

Make Wild's x86-64 PE/COFF support production-usable and stable, then fast.
Three sequential goals on separate branches; optional heavyweight features are
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

## Goal 3 — DGX PE/ELF performance parity (`feature/pe-coff-dgx-performance`)

Preserve the production usability and correctness established by Goals 1 and
2 while bringing the PE backend to the relative performance maturity of
Wild's ELF backend. Iterate on the DGX Spark rather than on a slow Windows
development machine. This goal measures native AArch64 Linux linker processes
that emit x86-64 PE or ELF output; it does **not** by itself claim that Wild is
faster on a native Windows host.

### Frozen workloads and binaries

Use four primary release-mode, full-link workload families: Rust standard
library, ripgrep, rust-analyzer, and uv. Freeze and publish, before tuning:

- the exact project revision, Rust/toolchain revision, target, feature set,
  build profile, environment, and final linker arguments for every workload;
- self-contained PE and ELF replay corpora, with manifests and cryptographic
  hashes for every input and response file;
- matched PE/ELF workload pairs built from the same project revision and as
  nearly the same features and release configuration as their target formats
  permit; target-format differences must be listed rather than silently
  normalized;
- exact native AArch64 Linux Wild, `lld-link`, and `ld.lld` binaries, including
  source revision, build command, configuration, version output, and binary
  hash. Wrapper and underlying linker hashes must be recorded separately. The
  `lld-link`/`ld.lld` versions, hashes, effective flags, and, after the sweep,
  selected thread configurations are immutable denominators for the final
  series; rebuilding them or changing their work cannot move the bar.

The frozen pre-Goal-3 Wild revision is the per-corpus regression baseline.
Changing a corpus, binary build, machine configuration, or protocol starts a
new benchmark series and cannot be mixed into the authoritative result.

### Completion metric

For corpus `i`, select each linker independently at its best thread count in
the pre-registered sweep, freeze those selections, and use only the subsequent
randomized direct-confirmation samples to calculate ratios of tool medians:

```text
PE_i        = median(lld-link_i time) / median(Wild-PE_i time)
ELF_i       = median(ld.lld_i time) / median(Wild-ELF_i time)
PE speedup  = (product over four PE_i values)^(1/4)
ELF speedup = (product over four ELF_i values)^(1/4)
parity      = PE speedup / ELF speedup
```

These are unweighted geometric means: every frozen corpus contributes exactly
one ratio, regardless of input size or run duration. Calculate deterministic,
two-sided 95% paired-block bootstrap intervals with 10,000 resamples and a
frozen, published seed. A block is one randomized/interleaved comparison pair;
resample whole blocks with replacement within each corpus, recompute both tool
medians and the corpus ratio, independently resample the PE and ELF families,
then recompute both geometric means and parity on every replicate.

Goal 3 is complete only when the lower bound of that 95% interval is `> 1.0`
for PE speedup and `>= 1.0` for parity. Point estimates alone do not pass; an
interval that overlaps the boundary is inconclusive and means optimization and
a fresh holdout must continue. Thus Wild PE must demonstrably beat `lld-link`
in aggregate, and its aggregate relative advantage must be at least the mature
Wild-versus-`ld.lld` ELF advantage on the matched suite. These aggregate
conditions do not excuse a hidden outlier:

- the lower 95% speedup bound must be `> 1.0` individually for rust-analyzer
  and uv;
- for every primary PE corpus, the upper 95% bound on the Wild-PE/`lld-link`
  median-time ratio must be `<= 1.03`;
- for every primary PE corpus, the upper 95% bound on the final-Wild/frozen-
  baseline-Wild median-time ratio must be `<= 1.03`, using a dedicated paired
  direct comparison at independently selected and frozen best thread counts;
  and
- any accepted optimization must preserve deterministic output and the
  existing PE correctness gates.

The ELF ratio is a demanding maturity target, not a claim that PE and ELF do
identical work. Report the four individual ratios, both geometric means, and
parity; do not substitute a favorable single corpus or thread count.

### Authoritative measurement protocol

- Pin every timed process to the same documented physical CPU list on the DGX.
  Record CPU topology, frequency/governor state, kernel, memory, storage, and
  interference controls. Report an all-core run separately as diagnostic data;
  do not mix it into the pinned result.
- Perform a complete documented thread-count sweep for each linker and corpus.
  Select each linker's best configuration from that sweep and commit the
  choices to the benchmark manifest, then run a fresh, randomized, interleaved
  direct comparison of the selected configurations. Sweep samples are never
  confirmation samples. Treat confirmation as a holdout: if its result informs
  another code or protocol change, invalidate it and acquire a new holdout.
- Use at least 15 measured samples **and** at least five accumulated seconds per
  linker/configuration after warmups. Report medians, dispersion, paired deltas,
  win counts, all point estimates and bootstrap intervals, the bootstrap seed,
  raw JSON, commands, and environment metadata. Warm filesystem cache is
  authoritative; explicitly labelled cache-drop results are advisory.
- Measure peak RSS for every timed configuration and report per-corpus and
  geometric-mean memory ratios alongside time. Compare final Wild RSS with both
  `lld` and the frozen Wild baseline; investigate and disclose any material
  tradeoff rather than treating speed alone as sufficient evidence.
- Before timing, validate that paired commands request equivalent release-link
  work. After every measured link, verify success, parse the output, validate
  the expected machine/subsystem/import/export/relocation properties, and hash
  it. Repeat identical Wild links and require byte-for-byte determinism.
- Profile and accept changes from evidence on the frozen suite. At closeout,
  rebuild exact final binaries, rerun the full authoritative suite, and bind all
  evidence to the exact code revision that produced it.

The final code revision must also pass the existing local PE gates and the
native Windows PE, runtime, Tauri, and Vibe workflows. Windows is the authority
for loader and application correctness. Native-Windows timing is an optional
separate diagnostic and is required before making any claim about native
Windows speed; neither Windows timing nor the old laptop is part of the DGX
parity completion metric.

Goal 3 deliberately excludes incremental linking, PDB generation, LTO, and new
security-feature work. Existing supported security and loader behavior must not
regress, but expanding `/GUARD:CF`, `/GUARD:EHCONT`, `/CETCOMPAT`, debugging, or
incremental-link capabilities belongs to later, separately scoped work.

## Deferred to final phases (after the performance goals, each separate)

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
