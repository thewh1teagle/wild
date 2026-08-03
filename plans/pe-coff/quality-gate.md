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
  linker-utils/Cargo.toml fuzz/Cargo.toml
uv run plans/pe-coff/pe-repro_001.py --self-test
uv run plans/pe-coff/pe-repro_001.py --wild target/debug/wild
uv run plans/pe-coff/pe-perf_001.py --wild-budget-seconds 30
```

The Goal 1 Rust unit run executes 244 `libwild` tests and 144 `linker-utils`
tests;
one opt-in local xwin archive probe remains ignored. The reproducibility matrix
links all six freestanding fixtures with `lld-link` and twice with Wild, checks
the bounded PE-layout equivalences documented in `pe-repro_001.md`, and passes
all semantic and byte-determinism checks. The performance probe passes its
30-second budget; the final captured run measured complete Rust compile/link
times of 0.98 seconds for Wild and 0.18 seconds for `lld-link`. This is a
correctness gate, not evidence that the experimental PE linker is faster.

The full xwin-backed candidate command also passes at
`547c72f309dc8dd73e5a43166e183491138395e7`:

```console
cargo +1.95.0 build -p wild-linker --no-default-features --features pe
WILD_PE_LINKER_FULL=/absolute/path/to/link.exe \
  cargo +1.95.0 test -p wild-linker --test windows_pe_runtime \
  --no-default-features --features pe -- --nocapture
```

`link.exe` above is a symlink to the freshly built `target/debug/wild`; the test
links identical C, C++, DLL, Rust-std, TLS, ordinal, forwarder, delay-import
and manifest inputs with `lld-link` and Wild. Non-Windows hosts validate PE
structure; execution is covered by Windows below.

## Real Windows x86-64 verification

Goal 1 closeout at exact commit
`547c72f309dc8dd73e5a43166e183491138395e7` passed all four authoritative
workflows:

- [Runtime run 30809478091](https://github.com/thewh1teagle/wild/actions/runs/30809478091): full C/C++/DLL/Rust/TLS corpus plus ordinal-only imports,
  forwarded exports, delay loading with unwind metadata, embedded GUI manifests
  and malformed-image checks.
- [PE run 30809478302](https://github.com/thewh1teagle/wild/actions/runs/30809478302): macOS structure and native Windows execution jobs.
- [Tauri run 30809478031](https://github.com/thewh1teagle/wild/actions/runs/30809478031): debug and release application acceptance.
- [Vibe run 30809478008](https://github.com/thewh1teagle/wild/actions/runs/30809478008): paired Wild/`lld-link` debug and release builds, PE checks,
  sidecars and native GUI behavior.

The earlier evidence below remains useful historical coverage.

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
`547c72f309dc8dd73e5a43166e183491138395e7` after the setup documented in
`host-tooling.md` (LLVM 18.1.3, the
same major version as the macOS evidence):

- fmt, clippy (`pe` feature), actionlint, and taplo gates pass.
- `cargo +1.95.0 test -p linker-utils -p libwild --no-default-features
  --features pe`: 244 + 144 tests pass (1 opt-in xwin probe ignored). Requires
  `clang-format` installed.
- `pe-repro_001.py --wild target/debug/wild`: all six fixtures are
  byte-deterministic across Wild links and semantically equivalent to
  `lld-link`.
- `pe-perf_001.py --wild-budget-seconds 30`: pass; Wild/lld complete
  compile+link ratio ≈ 3.3× on this 20-core host (correctness budget only).
- The full `windows_pe_runtime.rs` reference/candidate corpus runs on Linux
  with xwin and passes both tests; native execution remains authoritative in
  the workflows above.

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
equivalence is. Those historical sizes predate real `/OPT:REF`; the Goal 2
link-only size/time/RSS evidence below supersedes them for performance claims.

## Historical Goal 2 interim performance checkpoint

Goal 2's superseded interim checkpoint was
`8dd69ea6b4adba060782cafbba33bd57b44dee4d` (2026-08-03). The Goal 1 native
Windows runs above remain the loader/runtime acceptance baseline; Goal 2 did
not change its deferred feature scope. The performance branch preserved the
focused unit, xwin reference/candidate, formatting, clippy, reproducibility,
and benchmark-harness self-test gates while optimizing the measured hot paths.
It was not a Goal 2 closeout.

The checkpoint benchmark artifacts are:

- Vibe warm 1/2/4/8/10: `/tmp/wild-goal2-vibe-round6.json`
- Vibe warm 8/10 confirmation: `/tmp/wild-goal2-vibe-round6-confirm.json`
- Vibe advisory-cold 1/2/4/8/10:
  `/tmp/wild-goal2-vibe-round6-cold.json`
- Vibe advisory-cold 8/10 confirmation:
  `/tmp/wild-goal2-vibe-round6-cold-confirm.json`
- Rust-std warm 1/4/8/10: `/tmp/wild-goal2-ruststd-round6.json`
- Rust-std advisory-cold 1/4/8/10:
  `/tmp/wild-goal2-ruststd-round6-cold.json`

Every file reports `status: pass`. Its validation records a valid AMD64 PE,
stable entry point/subsystem/section count, and two-run byte determinism for
Wild at every measured thread count. The benchmarked Wild binary SHA-256 is
`3f1d6eb2d7052e1b2a95335df96b45e78f3666c7d6e5b29a7f496b4a304ed000`;
the Ubuntu LLD 18.1.3 wrapper SHA-256 is
`a83526824838107da2986370885f6e6e89e620507071367f0693d38ced9be778`.
Both corpora, response files, tool identities, raw samples, execution order,
settings, medians, MAD, p95, RSS, and scaling are embedded in the JSON. The
settings also show `min_accumulated_seconds=0` and `cpu_list=null` on a
heterogeneous host. Those are below the documented main protocol's five-second
floor and homogeneous affinity recommendation, so these files are diagnostic
checkpoint evidence rather than final performance authority.

The application-scale acceptance result is the independent 30-pair Vibe
confirmation: Wild beat `lld-link` at 8 threads (138.2 versus 146.2 ms; 19/30
paired wins) and 10 threads (138.8 versus 156.3 ms; 25/30 paired wins). The
advisory-cold confirmations also favored Wild at those thread counts. The full
tables and paired deltas are in `pe-link-bench_001.md`.

The smaller Rust-std reproduction independently favored Wild in all measured
warm cases (1/4/8/10) and advisory-cold 4/8/10. Advisory-cold one-thread Rust
std remained 10.1% slower, and Vibe below eight threads remained slower. Thus
the interim claim is deliberately bounded: Wild beats lld at the same
`/threads` value on confirmed Vibe 8/10-thread runs and in the listed Rust-std
cases, not universally.

“Cold” in those filenames means only advisory `POSIX_FADV_DONTNEED` for corpus
files and linker executables. Shared libraries and the global page cache were
not evicted; these results are advisory and are not evidence of a true
machine-cold cache.

Goal 2 remained open under a best-vs-best interpretation. In the complete Vibe
sweeps, Wild's best warm median was about 138 ms versus lld's 103 ms, and its
best advisory-cold median was about 244 ms versus lld's 212 ms. Completion
requires closing that gap and confirming it with CPU affinity and the
documented five-second sampling floor.

## Goal 2 authoritative closeout

Goal 2 is complete for benchmarked code SHA
`a68ba65237ea98c29f166f7ee10fb8dfbbb1a5e0`; the documentation commit that
records this evidence is intentionally distinct. The seven authoritative JSON
artifacts and their exact tables are listed in `pe-link-bench_001.md`. All
report `status: pass`, valid AMD64 output and deterministic Wild output.

The exact-SHA local closeout audit passed 258 `libwild` and 154
`linker-utils` unit tests (one ignored), 347 integration tests (1,232 ignored),
and the 2/2 xwin candidate suite, plus formatting, clippy, actionlint, Taplo,
six-case reproducibility, ten benchmark self-tests, `pe-perf`, Python checks and
allocator verification. Its independently rebuilt workspace-release Wild hash
was reported as `4726d40f…fe2f72`; the immutable benchmarked binary remains the
separate fully recorded `24ec6b7f…e8c27` artifact below.

The affinity-controlled protocol used CPUs
`5,6,7,8,9,15,16,17,18,19`, at least 15 samples and five accumulated seconds
per row, three warmups, randomized execution order and five RSS samples.
Compilation was excluded. The code-revision authority is `a68ba652`, not the
binary's embedded base-version string. Wild binary SHA-256 was
`24ec6b7f582d6ce3e31fd0f68114aec9ddf00d535f4015f28a99114ccaae8c27`
(7,450,840 bytes); Ubuntu LLD 18.1.3 SHA-256 was
`f8835e48488195c65fb3dcb946053284ddf6b1369922893785209a9073c4e57b`
(5,121,920 bytes). Vibe corpus/response hashes were
`cce61253001efa22280721ab91b53aa83ae4fff7406c07448af9f50ac1ab51d6`
and `adc5675be472359390b99e36318a93b0839c05126606b315a3416d2089d7de1e`;
Rust-std hashes were
`65336c4df9cb15676775453780e0f5135491b15ec2e4ff90efd8cdd92c88d617`
and `5576b5bea227f80ff3a8270cfa263510e952f8e2fd68962c2b14c4ef7eb6e207`.

The standard warm Vibe sweep's best medians were Wild 100.356 ms at ten
threads and lld 98.909 ms at one, a 1.447 ms sweep residual. The direct
randomized comparison of those configurations measured Wild
99.576 ± 1.178 ms versus lld 103.823 ± 0.966 ms, a 4.247 ms (4.1%) difference
between tool medians. Blockwise, the paired Wild-minus-lld delta median was
-4.084 ± 2.522 ms (median ± MAD), with Wild winning 35/50 pairs.
That direct warm best-versus-best result is the bounded completion authority.
Advisory-cold evidence is explicitly mixed: the sweep best favored Wild by
6.658 ms. In the noisy direct 10:1 result, tool medians favored lld by 2.801 ms,
but paired deltas favored Wild: median -3.319 ms, MAD 20.399 ms, with 14/24
Wild wins. It is not a machine-cold claim. The all-core and Rust-std supplements bound, but do not
widen, the completion statement.

Exact-SHA native Windows acceptance also passed:

- [PE run 30826452916](https://github.com/thewh1teagle/wild/actions/runs/30826452916),
  head `a68ba65237ea98c29f166f7ee10fb8dfbbb1a5e0`: success.
- [Runtime run 30826455326](https://github.com/thewh1teagle/wild/actions/runs/30826455326),
  same head: success.
- [Tauri run 30826457947](https://github.com/thewh1teagle/wild/actions/runs/30826457947),
  same head: success.
- [Vibe run 30826460336](https://github.com/thewh1teagle/wild/actions/runs/30826460336),
  same head: success for both release and debug jobs.
