# PE/COFF Rust std performance validation

This probe builds Wild, compiles the same representative
`x86_64-pc-windows-msvc` Rust `std` program through `lld-link` and Wild, measures
both complete rustc/link invocations, and validates that both outputs are AMD64
PE images with readable imports. Its stdout is a single machine-readable JSON
document; success, budget failure, and setup/timeout failure exit 0, 1, and 2.

This remains a correctness/time-budget smoke test, not Goal 2 performance
evidence: compilation is included and the sample count is too small for a
linker comparison. Use `pe-link-bench_001.py` and its documented statistical,
affinity, RSS, cache-mode, and best-vs-best protocol for performance claims.

Run it from the repository root on macOS with the Windows Rust target and xwin
CRT/SDK already installed:

```console
uv run plans/pe-coff/pe-perf_001.py
```

The default limits are five minutes to build Wild, two minutes per rustc/link
invocation, and a 30-second Wild budget. Override them for a cold machine or a
tighter regression gate:

```console
uv run plans/pe-coff/pe-perf_001.py \
  --build-timeout-seconds 600 \
  --link-timeout-seconds 180 \
  --wild-budget-seconds 20
```

Tools can be selected with `--cargo`, `--rustc`, `--lld-link`, and
`--llvm-readobj`, or their uppercase environment variables. `--xwin-root`
defaults to `$XWIN_ROOT` or `~/.xwin`. Use `--keep-artifacts NEW_DIRECTORY` to
preserve the generated source and PE files; an existing destination is refused.
