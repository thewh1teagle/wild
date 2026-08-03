# PE/COFF link-only benchmark

`pe-link-bench_001.py` replays an extracted `lld-link /reproduce` corpus through
release builds of Wild and `lld-link`. Compilation and corpus preparation are
never part of a timed sample. Both linkers receive the response file captured by
lld, followed only by their output path and the requested `/threads:N` value.
Ordinary sweeps pass the same value to both linkers; the optional direct-pair
confirmation described below can pass independently selected values.

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
  --cpu-list 5-9,15-19 \
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
the two configurations.

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

## Goal 2 interim checkpoint

Goal 2's current performance checkpoint is
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

### Integrated and rejected work at this checkpoint

Accepted changes include indexed and parallel archive preparation; compact and
contiguous archive metadata; linear definition deduplication; demand snapshot
reuse; selected-import, relocation-layout, COMDAT-graph, and selected-symbol
metadata reuse; borrowed layout/payload inputs; optimized SHA-256; faster map
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

### Why Goal 2 remains open

The 8/10-thread Vibe confirmations compare identical `/threads:N` settings and
prove those narrow wins. The goal's “beat `lld-link`” target is best-vs-best:
in the complete warm sweep Wild's best median was 138.0 ms at ten threads,
while lld's was 103.3 ms at one; in the complete advisory-cold sweep Wild's
best was 243.8 ms at eight, while lld's was 212.3 ms at two. Wild therefore
remained about 33.5% behind warm and 14.8% behind advisory-cold best-vs-best.
Further optimization plus a pinned, five-second-floor rerun is required before
Goal 2 can be marked complete.
