# Native Windows ripgrep linker comparison

Date: 2026-08-06

This diagnostic checks whether the PE performance work developed and measured on
the DGX translates into an end-to-end improvement on a real Windows laptop. It is
not part of the authoritative DGX Goal 3 parity metric: compilation is included,
the corpus is intentionally small, and the sample count is too low for a formal
performance claim.

## Result

| Scenario | MSVC `link.exe` | LLVM `lld-link` | Wild | Wild time reduction vs MSVC | Wild time reduction vs LLD |
|---|---:|---:|---:|---:|---:|
| Clean release build | 47.178 s | 47.794 s | **42.906 s** | **9.1%** | **10.2%** |
| Final-crate edit/rebuild | 14.691 s | 14.616 s | **14.528 s** | **1.1%** | **0.6%** |

The clean-build improvement is real in this run: Wild won all three matched
rounds against both other linkers. The edit/rebuild result is much smaller because
about 14 seconds is spent compiling and optimizing ripgrep's final crate; this
small program leaves little linker work to accelerate. The result therefore says
that Wild is already usable and beneficial on this Windows machine, not that a
small ripgrep rebuild should reproduce the roughly 2x link-only DGX ratios seen on
large frozen corpora.

Wild's one-time release bootstrap build on this laptop took 4 minutes 46 seconds.
That bootstrap is excluded from all ripgrep measurements.

## Frozen inputs and tools

- Windows benchmark workspace:
  `C:\Users\user1\wild-pe-bench-20260806`.
- Wild revision: `68acfe3c77df05c37bdd3f4ef513afb104313624`.
- ripgrep revision: `3fce3b5bb0236da2df6d99672afb8a719642eca7`
  (`ripgrep 15.2.0`).
- Rust: `rustc 1.96.0 (ac68faa20 2026-05-25)`.
- MSVC linker: Visual Studio 2022 Community toolset `14.44.35207`.
- LLVM linker: LLD 22.1.8, LLVM revision
  `ca7933e47d3a3451d81e72ac174dcb5aa28b59d1`.
- Wild binary SHA-256:
  `94E4F3EE7DE80D10E608C49B80C5529FE3114399C8B2CBABA09B1CA491DD909F`.

Host:

- AMD Ryzen 5 4500U, 6 physical and 6 logical processors.
- 15.37 GiB RAM.
- Windows 11 Pro `10.0.26200`.
- Windows Defender real-time protection enabled.
- Windows Balanced power plan.

No security exclusions were added and the power plan was not changed for the
benchmark.

## Method

Wild was built from the pushed feature branch with PE enabled:

```console
cargo +1.95.0 build --locked --release -p wild-linker \
  --no-default-features --features pe
```

The resulting `wild.exe` was copied to an isolated directory as `link.exe`, so
Rust selected the MSVC/COFF linker flavor. Each linker was supplied through
`CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER`. Every measured output was executed
with `rg.exe --version`; all outputs reported the expected ripgrep revision and
exited successfully.

The clean-build comparison used nine distinct Cargo target directories—one per
linker and round—and pre-fetched dependencies before timing. The balanced order
was:

```text
round 1: link, lld, Wild
round 2: Wild, link, lld
round 3: lld, Wild, link
```

The edit/rebuild comparison retained each linker's dependency cache, changed only
the modification time of `crates/core/main.rs`, and then rebuilt the final release
binary. File contents remained unchanged and both Git checkouts were clean after
the run. Cargo incremental compilation was disabled.

## Raw timings

Clean release builds, seconds:

| Round | MSVC `link.exe` | LLVM `lld-link` | Wild |
|---:|---:|---:|---:|
| 1 | 42.132647 | 41.396785 | **40.478412** |
| 2 | 47.624116 | 48.252473 | **42.905742** |
| 3 | 47.178283 | 47.794341 | **47.012701** |
| Median | 47.178283 | 47.794341 | **42.905742** |
| Mean | 45.645015 | 45.814533 | **43.465618** |

Final-crate edit/rebuilds, seconds:

| Round | MSVC `link.exe` | LLVM `lld-link` | Wild |
|---:|---:|---:|---:|
| 1 | **14.314323** | 14.598471 | 14.438056 |
| 2 | 14.741258 | 14.680799 | 14.768447 |
| 3 | 14.691451 | 14.616082 | **14.527701** |
| Median | 14.691451 | 14.616082 | **14.527701** |
| Mean | 14.582344 | 14.631784 | **14.578068** |

The clean-build samples span several seconds even with balanced ordering, showing
that compiler, filesystem, Defender, and power-management noise is material on
this laptop. The median end-to-end speedups are 1.100x over MSVC and 1.114x over
LLD. The edit/rebuild medians are only 1.011x and 1.006x respectively and should
not be over-interpreted.

## Output evidence

Median-run output sizes differed by linker, as permitted by the project goal:

- MSVC: 4,645,376 bytes.
- LLD: 4,629,504 bytes.
- Wild: 4,946,432 bytes.

Wild produced the same SHA-256 across all independently built target directories:
`85B5D8FA1C1E493B6A124AA87C1AA88BA240476F9FE5DC12B84F99848B58B577`.
MSVC and LLD outputs changed across rounds because this diagnostic did not request
reproducible timestamp normalization. Cross-linker byte identity is not expected.

The raw Windows artifacts remain outside the repository at:

- `ripgrep-full-build-results.ndjson`;
- `ripgrep-edit-rebuild-results.ndjson`; and
- `ripgrep-benchmark-summary.json`.

All are under `C:\Users\user1\wild-pe-bench-20260806`.

