# PE/COFF reproducibility matrix

This validation compiles the six freestanding smoke fixtures once, links each
with `lld-link` and twice with Wild, and checks that both Wild outputs are byte
identical. It reports SHA-256 digests and sizes, then compares normalized PE
headers, sections, symbols, imports, exports, base relocations, and unwind data
with `llvm-readobj`.

Build Wild and run the matrix from the repository root:

```console
cargo build -p wild-linker --features pe
uv run plans/pe-coff/pe-repro_001.py --wild target/debug/wild
```

The script discovers `clang-cl`, `lld-link`, and `llvm-readobj` on `PATH`; each
also has an explicit path option. On macOS, it discovers `kernel32.lib` below
`$XWIN_ROOT` or `~/.xwin`. It never executes PE files on macOS. On Windows it
executes both linkers' outputs and verifies each fixture's expected exit code;
use `--no-execute` to disable that step.

The normalizer's tool-free regression test is:

```console
uv run plans/pe-coff/pe-repro_001.py --self-test
```

Use `--keep-temp DIR` to preserve a copy of generated objects and images for
diagnosis. The destination must not already exist, preventing accidental
overwrites. Semantic differences fail the matrix and are summarized by case;
`--diff-lines` controls the diagnostic detail.
