# PE/COFF link-only benchmark

`pe-link-bench_001.py` replays an extracted `lld-link /reproduce` corpus through
release builds of Wild and `lld-link`. Compilation and corpus preparation are
never part of a timed sample. Both linkers receive the response file captured by
lld, followed only by their output path and the same `/threads:N` value.

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
