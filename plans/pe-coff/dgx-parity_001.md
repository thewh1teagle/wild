# DGX PE/ELF parity authority

`dgx-parity_001.py` is the Goal 3 decision tool. It consumes frozen PE, ELF,
and PE-baseline sweeps plus fresh direct holdouts for exactly four workload
families: Rust standard library, ripgrep, rust-analyzer, and uv. It rejects
unhashed or protocol-incompatible evidence before calculating a result.

This is a DGX cross-link performance claim. Wild, `lld-link`, and `ld.lld` are
native AArch64 Linux processes; their outputs are x86-64 PE or ELF. Native
Windows correctness remains a separate required gate, and this result alone is
not a native-Windows speed claim.

## Evidence sequence

For every PE and ELF corpus:

1. Freeze the corpus, final invocation, tool binaries, versions, hashes, and
   complete thread-count matrix. Inspect a known-good output, write the PE/ELF
   output-expectation JSON, and freeze its SHA-256 before any sweep.
2. Run a warm, affinity-pinned thread sweep with
   `pe-link-bench_001.py`. The same thread matrix is required everywhere.
3. Independently select the lowest-median configuration for each tool. Ties
   select the smaller thread count.
4. Record those selected counts in the matrix manifest and run a new randomized
   direct pair with a different seed and `--selection-sweep`.
5. For PE, repeat steps 2–4 with `--baseline-wild` to compare final Wild with
   the frozen pre-Goal-3 Wild binary.

The direct run must start after its referenced sweep finishes. Its JSON embeds
the sweep SHA-256. Sweep samples never enter the final estimator. If a direct
result informs another code, corpus, configuration, or protocol change, it is
no longer a holdout; collect a new one.

The same frozen output-expectation file must be passed to the sweep, direct
holdout, and PE baseline comparison. Record its SHA-256 and exact properties in
each matrix entry; the aggregator checks both, so replacing the expectation
after seeing measurements invalidates the series.

Every report must contain only authoritative warm mode, run on the same fixed
CPU list, with at least 15 paired samples and at least five accumulated seconds
per tool/configuration. Raw samples are checked rather than trusting settings.
RSS samples, execution-order blocks, AArch64 host identity, output validation,
and output determinism are mandatory for both tools in every authority pair.
Every PE and ELF authority output must be written to the same verified tmpfs
policy; non-tmpfs compatibility runs are rejected. PDB/debug links are outside
Goal 3, so nondeterministic debug artifacts cannot waive this requirement.

## Frozen matrix manifest

Paths may be absolute or relative to the manifest. Every artifact reference is
exactly `{path, sha256}`. `invocation_sha256` is `response.txt` for PE and the
`run-with` script for ELF. Identities freeze both the binary hash and exact
version text, preventing a new lld build from silently moving the denominator.

```json
{
  "schema_version": 1,
  "bootstrap": {
    "resamples": 10000,
    "seed": 8675309
  },
  "protocol": {
    "mode": "warm",
    "cpu_list": "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19",
    "thread_counts": [1, 2, 4, 8, 10, 20],
    "min_samples": 15,
    "min_accumulated_seconds": 5.0,
    "rss_samples": 5,
    "environment_note": "dedicated idle DGX; fixed performance governor"
  },
  "identities": {
    "wild-pe": {"sha256": "...", "version": "..."},
    "wild-elf": {"sha256": "...", "version": "..."},
    "baseline-wild-pe": {"sha256": "...", "version": "..."},
    "lld-link": {"sha256": "...", "version": "..."},
    "ld.lld": {"sha256": "...", "version": "..."}
  },
  "corpora": [
    {
      "name": "rust-std",
      "workload": {
        "project_revision": "...",
        "rust_toolchain": "...",
        "profile": "release",
        "feature_set": "...",
        "pe_target": "x86_64-pc-windows-msvc",
        "elf_target": "x86_64-unknown-linux-gnu"
      },
      "pe": {
        "sweep": {"path": "rust-std-pe-sweep.json", "sha256": "..."},
        "direct": {"path": "rust-std-pe-direct.json", "sha256": "..."},
        "baseline_sweep": {
          "path": "rust-std-pe-baseline-sweep.json",
          "sha256": "..."
        },
        "baseline_direct": {
          "path": "rust-std-pe-baseline-direct.json",
          "sha256": "..."
        },
        "expected": {
          "corpus_manifest_sha256": "...",
          "invocation_sha256": "...",
          "selected_threads": {"wild": 10, "lld-link": 1},
          "output_expectations_sha256": "...",
          "output_properties": {
            "format": "pe",
            "machine": "IMAGE_FILE_MACHINE_AMD64",
            "subsystem": 3,
            "entry_point_nonzero": true,
            "exports": false,
            "imports": true,
            "base_relocations": true
          }
        },
        "baseline_expected": {
          "corpus_manifest_sha256": "...",
          "invocation_sha256": "...",
          "selected_threads": {"wild": 10, "baseline-wild": 10},
          "output_expectations_sha256": "...",
          "output_properties": {
            "format": "pe",
            "machine": "IMAGE_FILE_MACHINE_AMD64",
            "subsystem": 3,
            "entry_point_nonzero": true,
            "exports": false,
            "imports": true,
            "base_relocations": true
          }
        }
      },
      "elf": {
        "sweep": {"path": "rust-std-elf-sweep.json", "sha256": "..."},
        "direct": {"path": "rust-std-elf-direct.json", "sha256": "..."},
        "expected": {
          "corpus_manifest_sha256": "...",
          "invocation_sha256": "...",
          "selected_threads": {"wild": 20, "ld.lld": 1},
          "output_expectations_sha256": "...",
          "output_properties": {
            "format": "elf",
            "machine": "EM_X86_64",
            "type": 3,
            "entry_point_nonzero": true
          }
        }
      }
    },
    {"name": "ripgrep", "pe": {}, "elf": {}},
    {"name": "rust-analyzer", "pe": {}, "elf": {}},
    {"name": "uv", "pe": {}, "elf": {}}
  ]
}
```

The abbreviated corpus objects must have the same complete shape as
`rust-std`; empty objects are shown only to keep the example readable. Generate
the manifest after all selection sweeps and before direct holdouts, then freeze
it apart from filling direct artifact hashes. Do not alter selected counts in
response to holdout results.

## Estimator and hard decision

For each corpus, the estimator is the ratio of direct-holdout tool medians at
the independently selected best thread counts:

```text
PE_i        = median(lld-link_i) / median(Wild-PE_i)
ELF_i       = median(ld.lld_i) / median(Wild-ELF_i)
PE speedup  = unweighted geometric mean of the four PE_i values
ELF speedup = unweighted geometric mean of the four ELF_i values
parity      = PE speedup / ELF speedup
```

The deterministic paired-block percentile bootstrap uses exactly 10,000
resamples and the manifest's frozen seed. A block contains one interleaved Wild
and comparator run. Whole blocks are sampled with replacement. Independent RNG
streams resample the PE, ELF, and baseline families, after which corpus ratios,
unweighted geometric means, and parity are recomputed. Reported intervals are
two-sided 95% percentile intervals.

Goal 3 passes only if all of these are true:

- PE speedup's lower 95% bound is greater than 1.0;
- parity's lower 95% bound is at least 1.0;
- rust-analyzer and uv PE speedup lower bounds are each greater than 1.0;
- every corpus's upper 95% Wild-PE/`lld-link` time-ratio bound is at most 1.03;
- every corpus's upper 95% final-Wild/baseline-Wild time-ratio bound is at most
  1.03; and
- all separately required correctness and native Windows gates pass.

The aggregator decides the statistical conditions and reports RSS ratios. The
external Windows gates are intentionally not inferred from benchmark JSON.
Point estimates do not pass an overlapping interval; an inconclusive result
means continue optimizing and acquire a fresh holdout.

## Run

```console
uv run plans/pe-coff/dgx-parity_001.py \
  --matrix /evidence/dgx-parity-matrix.json \
  --output /evidence/dgx-parity-result.json \
  --require-pass
```

Exit code 2 means invalid evidence. With `--require-pass`, exit code 3 means the
evidence is valid but one or more hard statistical conditions did not pass.
Without that option, a valid aggregate exits zero and records the decision in
`statistics.goal_pass`.

Run corpus-independent tests with:

```console
uv run plans/pe-coff/pe-link-bench_001.py --self-test
uv run plans/pe-coff/dgx-parity_001.py --self-test
```
