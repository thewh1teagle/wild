# PE/COFF link-only benchmark

`pe-link-bench_001.py` replays an extracted `lld-link /reproduce` corpus through
release builds of Wild and `lld-link`. Compilation and corpus preparation are
never part of a timed sample. Both linkers receive the response file captured by
lld, followed only by their output path and the requested `/threads:N` value.
Ordinary sweeps pass the same value to both linkers; the optional direct-pair
confirmation described below can pass independently selected values.

The original PE CLI and schema remain the default. Goal 3 additionally uses
`--format elf` to replay a frozen Wild save directory through native AArch64
Wild and `ld.lld`; that opt-in mode is documented below.

## Prepare a corpus

Add `/reproduce:rust-std.tar` to one successful lld link. For a direct rustc
probe this can be passed as a link argument; for Cargo applications, use a
linker wrapper that adds it only to the final executable link. Extract the tar
and use the directory containing `response.txt` as `--corpus`:

```console
mkdir -p /tmp/rust-std-repro
tar -xf /tmp/rust-std.tar -C /tmp/rust-std-repro
find /tmp/rust-std-repro -name response.txt -print
```

Do not commit captured corpora. They contain toolchain and SDK inputs and can be
large. Preserve the original relative layout: paths in lld's response file are
relative to the extracted reproduction root.

## Build and run

Measure an optimized binary, not Wild's development or `ci` profile:

```console
cargo +1.95.0 build --release \
  -p wild-linker --no-default-features --features pe

uv run plans/pe-coff/pe-link-bench_001.py \
  --corpus /tmp/rust-std-repro/repro \
  --wild target/release/wild \
  --lld-link lld-link \
  --threads 1,2,4,8,10 \
  --cpu-list 5-9,15-19 \
  --output /tmp/pe-link-bench.json
```

The default protocol runs three warmups, then randomized paired Wild/lld blocks
until each linker has at least 15 samples and five accumulated seconds, capped
at 1,000 samples. Five separate GNU-time runs collect maximum RSS. Output PE
headers are validated after timing, and two-run byte determinism is recorded
without assuming that debug/PDB-producing lld links are deterministic. JSON
records raw samples, median, median absolute deviation, p95, minimum, user/system CPU,
maximum RSS, one-thread-relative scaling, tool hashes, corpus hashes, execution
order, and all settings.

Use a stable machine with other load minimized. CPU affinity is optional, but
recommended. On heterogeneous CPUs, choose a homogeneous CPU set for the main
comparison and report any all-core result separately.

## Direct best-vs-best confirmation

First run a complete `--threads` sweep and independently select each linker's
lowest-median configuration. If those thread counts differ, confirm that direct
best-vs-best comparison without wrappers by replacing `--threads` with one or
more repeatable `--thread-pair WILD:LLD` values:

```console
uv run plans/pe-coff/pe-link-bench_001.py \
  --corpus /tmp/vibe-repro/repro \
  --wild target/release/wild \
  --lld-link /usr/lib/llvm-18/bin/lld-link \
  --mode warm \
  --thread-pair 10:1 \
  --selection-sweep /tmp/pe-link-sweep.json \
  --tmpfs-output-dir /benchmark \
  --output-expectations /corpora/vibe-pe-properties.json \
  --cpu-list 5-9,15-19 \
  --environment-note 'dedicated idle DGX; fixed performance governor' \
  --output /tmp/pe-link-best-vs-best.json
```

`--thread-pair` is mutually exclusive with `--threads`; its left side is
Wild's count and its right side is `lld-link`'s. Each randomized block still
runs each tool exactly once. The configuration JSON records
`configuration: direct-thread-pair`, the two counts at both configuration and
tool level, raw samples, execution order, median ratio, paired Wild-minus-lld
deltas, paired-win count, RSS, and per-tool validation using the selected
count. Tool and corpus provenance is unchanged. This confirmation does not
measure thread scaling and should not replace the full sweep used to select
the two configurations. Goal 3 authority runs always provide
`--selection-sweep`; its SHA-256 is embedded in the direct report. Use a fresh
seed for the direct run. Sweep samples are selection data, never holdout data.
If a holdout result informs another implementation or protocol change, discard
it and collect a new direct holdout.

Goal 3 PE sweeps and holdouts must pass `--tmpfs-output-dir`, just like ELF.
Legacy PE runs may omit it for compatibility, but the parity aggregator rejects
those reports. Freeze an output-expectation JSON per corpus and pass it to every
sweep and holdout. PE expectations are exact:

```json
{
  "format": "pe",
  "machine": "IMAGE_FILE_MACHINE_AMD64",
  "subsystem": 3,
  "entry_point_nonzero": true,
  "exports": false,
  "imports": true,
  "base_relocations": true
}
```

Use the values appropriate to the frozen workload; `subsystem: 3` and the
presence booleans above are examples. Validation parses the PE data-directory
RVAs and sizes and fails when machine, subsystem, entry-point presence, export,
import, or base-relocation presence differs. It also rejects a silent semantic
property disagreement between the paired linkers.

## ELF save-directory replay on the DGX

Capture the final ELF link with `WILD_SAVE_BASE`, identify the numbered save
directory whose executable `run-with` script represents the intended final
release link, and freeze the entire directory. `--corpus` is that save
directory. The harness invokes exactly:

```text
run-with <native-linker> --threads=N
```

Each process receives a unique `OUT` path below the explicitly supplied tmpfs.
The harness rejects a non-tmpfs output directory. Build a native AArch64 Wild
binary with ELF support and use the native AArch64 `ld.lld`, then perform the
selection sweep:

```console
uv run plans/pe-coff/pe-link-bench_001.py \
  --format elf \
  --corpus /corpora/ripgrep-elf/save-dir \
  --wild target/release/wild \
  --ld-lld /usr/bin/ld.lld \
  --tmpfs-output-dir /benchmark \
  --output-expectations /corpora/ripgrep-elf-properties.json \
  --mode warm \
  --threads 1,2,4,8,10,20 \
  --cpu-list 0-19 \
  --environment-note 'dedicated idle DGX; fixed performance governor' \
  --seed 1101 \
  --output /evidence/ripgrep-elf-sweep.json
```

Select each tool's lowest-median thread count independently, freeze that pair,
and collect a separate randomized holdout:

```console
uv run plans/pe-coff/pe-link-bench_001.py \
  --format elf \
  --corpus /corpora/ripgrep-elf/save-dir \
  --wild target/release/wild \
  --ld-lld /usr/bin/ld.lld \
  --tmpfs-output-dir /benchmark \
  --output-expectations /corpora/ripgrep-elf-properties.json \
  --mode warm \
  --thread-pair 20:1 \
  --selection-sweep /evidence/ripgrep-elf-sweep.json \
  --cpu-list 0-19 \
  --environment-note 'dedicated idle DGX; fixed performance governor' \
  --seed 2202 \
  --output /evidence/ripgrep-elf-direct.json
```

ELF reports use the same sampling floors, randomized paired blocks, CPU
affinity, cache definitions, raw timing samples, GNU-time peak RSS sampling,
tool/corpus hashes, and provenance as PE reports. Validation parses the native
x86-64 ELF header and program-header bounds, records the output hash, and
requires two identical outputs from each ELF linker. The linker processes are
native AArch64 Linux executables; the replayed output is x86-64 ELF.
Freeze ELF type and entry-point presence too:

```json
{
  "format": "elf",
  "machine": "EM_X86_64",
  "type": 3,
  "entry_point_nonzero": true
}
```

`type: 3` is an example for a PIE/shared object; use the inspected type of the
frozen workload. The harness rejects a Wild/`ld.lld` structural disagreement.

## Frozen PE baseline regression holdout

Goal 3's per-corpus 3% regression guard needs a paired comparison between the
final candidate and the frozen pre-Goal-3 Wild binary. Use `--baseline-wild`
for both its selection sweep and its separate direct holdout. The candidate is
still `--wild`; `--baseline-wild` replaces `lld-link` as the second PE tool and
is invoked with the same Wild PE flavor arguments:

```console
uv run plans/pe-coff/pe-link-bench_001.py \
  --corpus /corpora/ripgrep-pe/repro \
  --wild /build/final/wild \
  --baseline-wild /build/frozen-baseline/wild \
  --tmpfs-output-dir /benchmark \
  --output-expectations /corpora/ripgrep-pe-properties.json \
  --mode warm \
  --thread-pair 10:10 \
  --selection-sweep /evidence/ripgrep-pe-baseline-sweep.json \
  --cpu-list 0-19 \
  --environment-note 'dedicated idle DGX; fixed performance governor' \
  --seed 3303 \
  --output /evidence/ripgrep-pe-baseline-direct.json
```

The pair must come from an independently selected full sweep; `10:10` above is
only illustrative. `dgx-parity_001.py` verifies the sweep selection and rejects
an unbound, reused, stale, or protocol-incompatible holdout.

## Cache modes

The default includes two deliberately distinct modes:

- `warm`: repeated fresh linker processes without explicit cache eviction.
- `cold-input-cache`: before every invocation, issue advisory
  `POSIX_FADV_DONTNEED` for every corpus file and both linker executables.

The latter is accurately named: it is not a global cold cache. The kernel may
retain advised pages, shared libraries are not evicted, and no privileged cache
drop occurs. A true machine-cold result requires a controlled dedicated runner
or administrator-managed reboot/cache-drop protocol and must be reported as a
separate experiment.

Select one mode explicitly by repeating `--mode` as needed:

```console
uv run plans/pe-coff/pe-link-bench_001.py \
  --corpus /tmp/rust-std-repro/repro \
  --mode warm \
  --threads 1,4,10
```

For a quick smoke run, reduce the statistical floor and omit RSS samples:

```console
uv run plans/pe-coff/pe-link-bench_001.py \
  --corpus /tmp/rust-std-repro/repro \
  --mode warm --threads 1 \
  --warmups 1 --min-samples 3 --min-seconds 0 --rss-samples 0
```

Run the corpus-independent harness tests with:

```console
uv run plans/pe-coff/pe-link-bench_001.py --self-test
```

The Rust-std corpus is useful for smoke tests and latency. Use a pinned Vibe
release reproduction, captured from its final executable link, for the
application-scale result and for conclusions about thread scaling.

## Historical Goal 2 interim checkpoint

The superseded interim performance checkpoint was
`8dd69ea6b4adba060782cafbba33bd57b44dee4d` (2026-08-03). All numbers below
come from the JSON files named in this section, not from terminal summaries.
The benchmarked Wild executable is SHA-256
`3f1d6eb2d7052e1b2a95335df96b45e78f3666c7d6e5b29a7f496b4a304ed000`;
the `lld-link` wrapper is SHA-256
`a83526824838107da2986370885f6e6e89e620507071367f0693d38ced9be778`
and reports Ubuntu LLD 18.1.3.

The host was Linux 6.17.0 aarch64 with 20 logical CPUs. Compilation was never
timed. Every row used fresh linker processes, randomized paired Wild/lld
execution order, five RSS samples, output-header validation, and two-run Wild
byte-determinism checks. Warm means no explicit eviction. “Advisory cold” means
`POSIX_FADV_DONTNEED` was issued for corpus inputs and linker executables; it
does **not** mean a global or machine-cold page cache. Elapsed columns are
median ± median absolute deviation in milliseconds; RSS is median MiB.

These runs are an optimization checkpoint, not the authoritative Goal 2
closeout. They set `min_accumulated_seconds=0` and `cpu_list=null` on a
heterogeneous host, whereas the documented main protocol requires at least
five accumulated seconds and recommends a homogeneous pinned CPU set. The
same-`/threads` comparisons and raw distributions remain useful, but must be
confirmed under that protocol before completion.

### Pinned Vibe release reproduction

The application corpus contains 51 files and 78,092,087 bytes. Its manifest is
`cce61253001efa22280721ab91b53aa83ae4fff7406c07448af9f50ac1ab51d6`;
`response.txt` is
`adc5675be472359390b99e36318a93b0839c05126606b315a3416d2089d7de1e`.
The full sweeps use 15 samples per linker after three warmups.

| Mode | Threads | Wild ms ± MAD | Wild RSS | lld ms ± MAD | lld RSS | Wild/lld | Wild scaling |
|---|---:|---:|---:|---:|---:|---:|---:|
| Warm | 1 | 179.9 ± 2.4 | 156.2 | 103.3 ± 3.6 | 138.7 | 1.741x | 1.00x |
| Warm | 2 | 152.3 ± 0.9 | 164.4 | 116.9 ± 2.7 | 139.0 | 1.302x | 1.18x |
| Warm | 4 | 141.2 ± 2.9 | 211.7 | 129.7 ± 4.8 | 138.6 | 1.089x | 1.27x |
| Warm | 8 | 141.1 ± 5.3 | 225.3 | 140.3 ± 6.3 | 138.0 | 1.006x | 1.27x |
| Warm | 10 | 138.0 ± 4.3 | 232.8 | 148.0 ± 9.8 | 137.8 | **0.932x** | **1.30x** |
| Advisory cold | 1 | 337.9 ± 19.2 | 150.1 | 231.4 ± 19.9 | 138.2 | 1.460x | 1.00x |
| Advisory cold | 2 | 309.7 ± 7.7 | 159.6 | 212.3 ± 15.1 | 138.6 | 1.459x | 1.09x |
| Advisory cold | 4 | 261.8 ± 22.3 | 207.7 | 250.1 ± 9.9 | 138.3 | 1.047x | 1.29x |
| Advisory cold | 8 | 243.8 ± 17.7 | 227.9 | 247.3 ± 19.9 | 138.0 | **0.986x** | **1.39x** |
| Advisory cold | 10 | 245.5 ± 22.6 | 229.5 | 295.0 ± 14.2 | 137.3 | **0.832x** | **1.38x** |

The warm sweep's one-to-ten-thread scaling was 1.30x for Wild and 0.70x for
lld. Advisory-cold scaling was 1.38x for Wild and 0.78x for lld. The rising
Wild RSS is the cost of its parallel and allocator strategy: at ten threads it
used 232.8 MiB warm versus lld's 137.8 MiB. This is an accepted speed/memory
tradeoff, not a memory-efficiency win.

The winning 8/10-thread points were rerun independently with 30 samples per
linker, five warmups, a new random seed, and five RSS samples:

| Mode | Threads | Wild ms ± MAD | Wild RSS | lld ms ± MAD | lld RSS | Median advantage | Paired wins |
|---|---:|---:|---:|---:|---:|---:|---:|
| Warm | 8 | 138.2 ± 5.2 | 227.7 | 146.2 ± 13.9 | 138.0 | 5.5% | 19/30 |
| Warm | 10 | 138.8 ± 6.7 | 240.5 | 156.3 ± 13.1 | 137.9 | 11.2% | 25/30 |
| Advisory cold | 8 | 239.2 ± 18.0 | 225.0 | 264.2 ± 24.4 | 137.5 | 9.5% | 19/30 |
| Advisory cold | 10 | 229.3 ± 13.6 | 230.8 | 289.2 ± 17.6 | 137.5 | 20.7% | 25/30 |

“Paired wins” counts blocks in which Wild's elapsed time was lower. The median
of paired Wild-minus-lld deltas was -9.6/-14.5 ms warm and -15.7/-48.1 ms
advisory-cold at 8/10 threads. The source artifacts are:

- `/tmp/wild-goal2-vibe-round6.json`
- `/tmp/wild-goal2-vibe-round6-confirm.json`
- `/tmp/wild-goal2-vibe-round6-cold.json`
- `/tmp/wild-goal2-vibe-round6-cold-confirm.json`

The original Vibe baseline was 617/618/650/652/627 ms warm and
799/824/796/807/831 ms advisory-cold at 1/2/4/8/10 threads. The checkpoint
sweeps therefore reduced Wild warm latency by 70.8%/75.4%/78.3%/78.4%/78.0%
and advisory-cold latency by 57.7%/62.4%/67.1%/69.8%/70.4%. The original data
is `/tmp/wild-goal2-vibe-baseline.json`.

### Rust-std reproduction

This latency corpus contains 50 files and 32,868,792 bytes. Its manifest is
`65336c4df9cb15676775453780e0f5135491b15ec2e4ff90efd8cdd92c88d617`;
`response.txt` is
`5576b5bea227f80ff3a8270cfa263510e952f8e2fd68962c2b14c4ef7eb6e207`.
Each row has 30 samples per linker after five warmups.

| Mode | Threads | Wild ms ± MAD | Wild RSS | lld ms ± MAD | lld RSS | Wild/lld | Wild scaling |
|---|---:|---:|---:|---:|---:|---:|---:|
| Warm | 1 | 16.3 ± 1.8 | 36.1 | 23.8 ± 0.4 | 67.1 | **0.685x** | 1.00x |
| Warm | 4 | 14.2 ± 1.5 | 52.0 | 54.5 ± 5.2 | 67.0 | **0.261x** | 1.15x |
| Warm | 8 | 12.8 ± 2.4 | 68.0 | 58.5 ± 11.6 | 66.4 | **0.219x** | 1.27x |
| Warm | 10 | 12.6 ± 2.2 | 72.0 | 61.4 ± 13.4 | 66.6 | **0.205x** | **1.29x** |
| Advisory cold | 1 | 59.7 ± 7.2 | 35.7 | 54.2 ± 1.6 | 67.0 | 1.101x | 1.00x |
| Advisory cold | 4 | 55.1 ± 4.9 | 51.7 | 78.6 ± 4.2 | 66.8 | **0.701x** | 1.08x |
| Advisory cold | 8 | 56.2 ± 3.3 | 66.3 | 83.2 ± 12.2 | 66.4 | **0.675x** | 1.06x |
| Advisory cold | 10 | 56.8 ± 4.2 | 69.3 | 89.8 ± 6.4 | 66.4 | **0.632x** | 1.05x |

The source artifacts are `/tmp/wild-goal2-ruststd-round6.json` and
`/tmp/wild-goal2-ruststd-round6-cold.json`. These results support a warm win at
all measured thread counts and an advisory-cold win at 4/8/10, not at one
thread.

### Integrated and rejected work at the interim checkpoint

Accepted changes include indexed and parallel archive preparation; compact and
contiguous archive metadata; linear definition deduplication; demand snapshot
reuse; selected-import, relocation-layout, COMDAT-graph, and selected-symbol
metadata reuse; optimized SHA-256; faster map
and set lookups; parallel relocation application; and mimalloc v2. The exact
integrated sequence is `65185605..8dd69ea6`.

Allocator selection is another explicit tradeoff. The controlled
`/tmp/wild-goal2-allocator-exact-current.json` versus
`/tmp/wild-goal2-allocator-exact-v2.json` comparison improved Vibe latency
177.6→172.6 ms at one thread and 137.0→133.6 ms at four, while reducing median
RSS 192.2→141.2 MiB and 242.3→194.9 MiB. Even after that improvement, the
checkpoint's high-thread Vibe RSS remains above lld as shown above.

Broader whole-stage layout rewrites, alternate lazy-archive variants, and more
aggressive COMDAT/layout parallel prototypes were not integrated when they
were neutral, regressive, noisy, or could not clear the same correctness and
determinism gates. For example, the isolated layout prototype moved the
five-sample one-thread median from 653.6 to 655.0 ms
(`/tmp/wild-goal2-layout-baseline.json` and
`/tmp/wild-goal2-layout-optimized.json`). The checkpoint retained only
measured wins. Optional PDB, CFG/security, LTO, incremental-link, and niche
compatibility work remains deferred exactly as specified in `GOAL.md`.

### Why Goal 2 remained open at that checkpoint

The 8/10-thread Vibe confirmations compare identical `/threads:N` settings and
prove those narrow wins. The goal's “beat `lld-link`” target is best-vs-best:
in the complete warm sweep Wild's best median was 138.0 ms at ten threads,
while lld's was 103.3 ms at one; in the complete advisory-cold sweep Wild's
best was 243.8 ms at eight, while lld's was 212.3 ms at two. Wild therefore
remained about 33.5% behind warm and 14.8% behind advisory-cold best-vs-best.
Further optimization plus a pinned, five-second-floor rerun was required before
Goal 2 could be marked complete.

## Goal 2 authoritative closeout

Goal 2 is complete for benchmarked code commit
`a68ba65237ea98c29f166f7ee10fb8dfbbb1a5e0`. A later documentation commit does
not change the identity of the measured code. Every closeout artifact reports
`status: pass`; validates AMD64 PE headers, entry point, subsystem and section
count; and checks two-run Wild byte determinism.

The authority host was Linux 6.17.0 aarch64 with 20 logical CPUs. The pinned
runs used CPUs `5,6,7,8,9,15,16,17,18,19`, at least 15 samples and five
accumulated seconds per linker/configuration, three warmups, randomized paired
execution order, five RSS samples, and excluded compilation. The all-core
supplement deliberately used no affinity. The measured Wild binary was
7,450,840 bytes, SHA-256
`24ec6b7f582d6ce3e31fd0f68114aec9ddf00d535f4015f28a99114ccaae8c27`;
its embedded version names the repository base and is not the source-revision
authority. The source revision is the full code SHA above. Ubuntu LLD 18.1.3
was 5,121,920 bytes, SHA-256
`f8835e48488195c65fb3dcb946053284ddf6b1369922893785209a9073c4e57b`.

The Vibe corpus remained 51 files and 78,092,087 bytes, manifest SHA-256
`cce61253001efa22280721ab91b53aa83ae4fff7406c07448af9f50ac1ab51d6`,
with response-file SHA-256
`adc5675be472359390b99e36318a93b0839c05126606b315a3416d2089d7de1e`.
Elapsed columns below are median ± MAD milliseconds and RSS is median MiB.

### Pinned Vibe warm sweep and supplement

| Threads | Wild ms ± MAD | Wild RSS | lld ms ± MAD | lld RSS |
|---:|---:|---:|---:|---:|
| 1 | 143.839 ± 1.273 | 147.9 | 98.909 ± 2.688 | 138.8 |
| 2 | 122.829 ± 2.298 | 174.3 | 111.981 ± 2.119 | 138.9 |
| 3 | 111.284 ± 1.265 | 195.7 | 120.829 ± 2.403 | 138.7 |
| 4 | 103.869 ± 1.365 | 212.0 | 118.298 ± 3.921 | 138.7 |
| 5 | 104.190 ± 1.285 | 230.1 | 123.960 ± 3.339 | 138.5 |
| 6 | 109.098 ± 2.451 | 223.3 | 127.977 ± 5.509 | 138.3 |
| 7 | 108.383 ± 3.838 | 231.9 | 128.582 ± 5.878 | 138.2 |
| 8 | 101.161 ± 2.438 | 233.9 | 130.892 ± 4.518 | 138.1 |
| 9 | 101.992 ± 2.771 | 240.2 | 127.985 ± 5.317 | 138.0 |
| 10 | 100.356 ± 1.825 | 237.8 | 133.490 ± 6.206 | 138.3 |

Wild scaled 1.433x from one to ten threads; lld's ten-thread row was 0.741x
its one-thread result. The independent sweep's best medians leave Wild
1.447 ms behind lld. The direct randomized comparison of those exact best
configurations measured Wild `/threads:10` at **99.576 ± 1.178 ms** and
250.8 MiB versus lld `/threads:1` at **103.823 ± 0.966 ms** and 138.8 MiB:
a 4.247 ms (4.1%) difference between tool medians. The paired Wild-minus-lld
delta median was -4.084 ms with 2.522 ms MAD, and Wild won 35/50 blocks. This
direct best-versus-best comparison is the
bounded Goal 2 closeout authority; the independent sweep residual is retained
as a sensitivity result, and no claim is made that Wild wins every thread
count.

### Advisory cold-input-cache Vibe results

| Threads | Wild ms ± MAD | Wild RSS | lld ms ± MAD | lld RSS |
|---:|---:|---:|---:|---:|
| 1 | 308.830 ± 29.638 | 144.6 | 208.002 ± 15.907 | 138.2 |
| 2 | 264.443 ± 15.227 | 173.8 | 227.364 ± 22.235 | 138.4 |
| 4 | 207.099 ± 7.912 | 211.7 | 247.394 ± 13.674 | 138.2 |
| 8 | 215.805 ± 24.957 | 240.1 | 245.726 ± 22.602 | 137.7 |
| 10 | 201.344 ± 11.053 | 247.8 | 239.989 ± 16.103 | 137.8 |

The sweep's independent best medians favor Wild by 6.658 ms. The direct 10:1
pair measured Wild 204.166 ± 8.673 ms and lld 201.365 ± 8.745 ms, so the tool
medians favored lld by 2.801 ms. Blockwise paired deltas instead favored Wild:
median -3.319 ms, MAD 20.399 ms, and 14/24 Wild wins. The disagreement and
large dispersion make this mixed evidence. “Cold” here means advisory `POSIX_FADV_DONTNEED` for inputs and
linker executables, not a global or machine-cold cache; it is not the warm
completion criterion.

### All-core and Rust-std bounds

The unpinned all-core Vibe warm supplement was:

| Threads | Wild ms ± MAD | Wild RSS | lld ms ± MAD | lld RSS |
|---:|---:|---:|---:|---:|
| 1 | 145.479 ± 2.205 | 147.8 | 105.176 ± 0.780 | 138.7 |
| 2 | 121.585 ± 3.772 | 174.2 | 119.645 ± 5.228 | 138.8 |
| 4 | 113.262 ± 2.609 | 206.9 | 124.595 ± 4.493 | 138.6 |
| 8 | 109.178 ± 3.329 | 238.9 | 151.754 ± 12.584 | 138.1 |
| 10 | 110.205 ± 4.995 | 244.1 | 166.877 ± 11.294 | 137.9 |
| 20 | 113.330 ± 9.019 | 287.3 | 238.755 ± 20.882 | 137.4 |

It confirms the high-thread direction but is not the affinity-controlled
authority.

The Rust-std corpus contained 50 files and 32,868,792 bytes, manifest SHA-256
`65336c4df9cb15676775453780e0f5135491b15ec2e4ff90efd8cdd92c88d617`,
response-file SHA-256
`5576b5bea227f80ff3a8270cfa263510e952f8e2fd68962c2b14c4ef7eb6e207`.

| Mode | Threads | Wild ms ± MAD | Wild RSS | lld ms ± MAD | lld RSS |
|---|---:|---:|---:|---:|---:|
| Warm | 1 | 9.575 ± 0.299 | 36.1 | 23.552 ± 0.506 | 67.1 |
| Warm | 2 | 9.271 ± 0.154 | 42.2 | 33.369 ± 0.665 | 67.1 |
| Warm | 4 | 8.904 ± 0.146 | 51.9 | 42.298 ± 1.317 | 66.8 |
| Warm | 8 | 9.111 ± 0.250 | 68.0 | 35.873 ± 0.917 | 66.6 |
| Warm | 10 | 9.251 ± 0.199 | 72.3 | 34.955 ± 0.615 | 66.6 |
| Advisory cold | 1 | 60.317 ± 4.600 | 35.7 | 51.005 ± 0.833 | 66.9 |
| Advisory cold | 2 | 48.073 ± 1.461 | 41.8 | 60.623 ± 1.198 | 67.0 |
| Advisory cold | 4 | 50.966 ± 3.258 | 51.7 | 72.874 ± 3.830 | 66.7 |
| Advisory cold | 8 | 36.748 ± 1.999 | 65.5 | 65.870 ± 5.897 | 66.3 |
| Advisory cold | 10 | 36.864 ± 2.010 | 71.6 | 65.043 ± 4.814 | 66.3 |

Wild won every warm row and advisory-cold 2/4/8/10, but not advisory-cold one
thread.

The source artifacts are:

- `/tmp/wild-goal2-authoritative-vibe-warm-a68ba652.json`
- `/tmp/wild-goal2-authoritative-vibe-warm-supplement-a68ba652.json`
- `/tmp/wild-goal2-authoritative-vibe-direct-warm-a68ba652.json`
- `/tmp/wild-goal2-authoritative-vibe-cold-a68ba652.json`
- `/tmp/wild-goal2-authoritative-vibe-direct-cold-a68ba652.json`
- `/tmp/wild-goal2-authoritative-vibe-all-core-warm-a68ba652.json`
- `/tmp/wild-goal2-authoritative-ruststd-warm-cold-a68ba652.json`

### Integrated and rejected work at closeout

The integrated range is `65185605..a68ba652`. Accepted work includes indexed
and parallel archive preparation; compact contiguous archive metadata and
linear definition deduplication; demand snapshots; selected-import,
relocation-layout, COMDAT-graph and selected-symbol metadata reuse; mimalloc
v2; optimized SHA-256; faster foldhash lookups; parallel relocation
application; incremental relocation-section layout and avoided full relayout;
reuse of selected-object metadata from import resolution; flat COMDAT
reachability adjacency; and overlap of build-ID hashing with output copying.
`3960ae2d` added direct thread-pair measurement support but is harness work,
not a linker speedup.

The interim record's payload-borrow description was too broad: the `284ae85c`
prototype was not integrated. The accepted
layout work is specifically relocation-layout analysis reuse plus incremental
relocation-section layout (`73ed705d`/`c26319f4`). Whole-stage layout rewrites,
alternate lazy-archive variants, aggressive COMDAT/layout parallel prototypes,
zero-copy COMDAT keys, and import-record reuse were rejected when neutral,
regressive or noisy. The old bounded resolver-set experiment is subsumed and
strengthened by the integrated foldhash/incremental resolver bookkeeping in
`2bd5f06c`.

Goal 2 is complete only in the documented warm, direct best-versus-best sense.
The final record preserves the sweep sensitivity, cold disagreement and higher
Wild RSS rather than generalizing beyond the evidence.
