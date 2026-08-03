# Goal 3 PE byte-identity oracle

`pe-byte-oracle_001.py` is the correctness gate for changing Wild's PE/COFF
architecture. It is deliberately not a benchmark. It replays the four frozen
PE corpora (`ruststd`, `ripgrep`, `rust-analyzer`, and `uv`) with a pinned
reference executable and a candidate at thread counts `1`, `4`, and `N`.

The gate passes only when:

- every frozen inventory, metadata, manifest, materialized corpus, and response
  file passes its recorded SHA-256 checks before execution;
- both linkers exit successfully and emit a valid PE file for every replay;
- each candidate output is byte-identical to its corresponding reference
  output;
- each linker's output is deterministic across all requested thread counts;
- optional resolution/member dumps match when dump hooks are configured; and
- the frozen materialized corpora still match their manifests after execution.

Missing or malformed inputs fail closed. Evidence must be written to a fresh
directory outside every frozen corpus. The script stages evidence next to that
directory and publishes it atomically, so a failed invocation cannot look like
a completed oracle run.

## Replay contract

The command template, response-file token, working directory, and any replay
environment overlay come directly from each frozen `metadata.json`. The oracle
only substitutes the documented `${OUTPUT}`, `${THREADS}`, and optional
`${DUMP}` placeholders. It starts each process with a small deterministic base
environment (`C` locale, UTC, system default `PATH`, and a run-local temporary
directory), applies the frozen overlay, and records the complete resulting
environment and its digest.

Each run records the executable and optional Git tree provenance, command,
cwd, environment, timestamps, exit status, timeout state, complete stdout and
stderr (files plus base64 and SHA-256), output SHA-256, and selected PE headers.
On a mismatch, the report also gives the first differing byte offset. Evidence
lives under `artifacts/<corpus>/threads-<n>/<role>/`; the machine-readable
decision is `report.json`.

## Usage

First validate the harness without touching the frozen evidence:

```sh
python3 plans/pe-coff/pe-byte-oracle_001.py --self-test
python3 plans/pe-coff/pe-byte-oracle_001.py \
  --reference /absolute/path/to/pinned-wild \
  --reference-sha256 <sha256> \
  --candidate /absolute/path/to/candidate-wild \
  --candidate-sha256 <sha256> \
  --reference-tree /absolute/path/to/reference-tree \
  --candidate-tree /absolute/path/to/candidate-tree \
  --dry-run
```

The dry run verifies all pins and all four frozen corpora, reconstructs every
command, and prints the plan. It executes no linker and creates no evidence
directory. `--smoke --dry-run` limits the plan to `ruststd` at one thread.

Run the full gate into a new external directory:

```sh
python3 plans/pe-coff/pe-byte-oracle_001.py \
  --reference /absolute/path/to/pinned-wild \
  --reference-sha256 <sha256> \
  --candidate /absolute/path/to/candidate-wild \
  --candidate-sha256 <sha256> \
  --reference-tree /absolute/path/to/reference-tree \
  --candidate-tree /absolute/path/to/candidate-tree \
  --threads 1,4,N \
  --n-threads "$(nproc)" \
  --output-dir /absolute/path/to/new-oracle-evidence
```

Exit status is `0` for a passing oracle, `1` for a completed comparison that
found a mismatch, and `2` when the invocation or frozen input is unsafe or
invalid.

## Resolution/member dump hook

Wild does not currently expose a stable selected-archive-member dump switch.
When one is available, pass symmetric argument templates containing `${DUMP}`:

```sh
--reference-dump-arg '/dump-members:${DUMP}' \
--candidate-dump-arg '/dump-members:${DUMP}'
```

If dump arguments are enabled, both tools must produce the dump and its SHA-256
must match. Until then, output byte identity and the recorded PE metadata are
the authoritative migration gate.

The oracle measures no elapsed duration and must not be used to make a
performance claim. Performance qualification belongs to the separately frozen
benchmark protocol after this correctness gate passes.
