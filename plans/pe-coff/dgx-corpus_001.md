# DGX frozen linker corpus capture

`dgx-corpus_001.py` captures one final release link as an immutable replay
corpus. It supports both sides of the Goal 3 parity measurement:

- PE/COFF uses an `lld-link /reproduce` archive. The capture linker appends
  `/OPT:REF`, `/OPT:NOICF`, and `/DEBUG:NONE`, in that order after the build's
  arguments. This keeps dead-code elimination enabled while ensuring neither
  linker is timed doing ICF or PDB work that Wild deliberately does not support.
- ELF uses Wild's `WILD_SAVE_BASE` mechanism and freezes exactly one selected
  `run-with` directory.

The build is corpus preparation and is never part of a benchmark sample.

## Safety and provenance

The command after `--` is executed as an argument vector, not through a shell.
The placeholders `{linker}`, `{project}`, and `{capture_root}` may occur within
an argument. The tool also exports `DGX_CAPTURE_LINKER` and
`DGX_CAPTURE_ROOT`; ELF capture additionally exports `WILD_SAVE_BASE`.

The source revision must resolve to the project's current `HEAD`. Dirty source
is rejected unless `--allow-dirty` is explicit. The capture records the source
commit and state, Cargo lockfile hash, exact build argv, profile, target,
features, explicitly supplied environment/labels, and linker hashes and
versions. Repeatable `--tool NAME=EXECUTABLE` entries record the exact rustc,
Cargo, C compiler, archiver, or other toolchain executables by path, version,
size, and SHA-256; the build command's executable is recorded automatically.

Archives reject absolute paths, drive prefixes, traversal, backslashes,
symlinks, hardlinks, and special files. ELF save-dir symlinks are resolved and
materialized. Every frozen input is a new byte copy rather than a hardlink.
`manifest.json` records each relative path, size, and SHA-256 plus a stable
whole-corpus digest. `corpus.tar` is deterministic and is extracted and
rehashed before capture succeeds. The original lld reproduction archive and
its byte-exact `response.txt` are retained for PE.

The completed directory is made read-only. Permissions are only an accidental
mutation guard; hashes in `metadata.json` and `manifest.json` are the authority.
The recorded replay commands use `${OUTPUT}` and `${THREADS}` placeholders and
must be smoke-tested before an authoritative benchmark.

## PE example

Use `cargo rustc` for one package and binary so the temporary linker is applied
only to the intended final target. Native dependency tool variables and xwin
include/library flags, when required, are explicit `--env` values and therefore
become provenance.

```console
uv run plans/pe-coff/dgx-corpus_001.py pe \
  --name ripgrep-pe \
  --output-root /var/tmp/wild-goal3-corpora \
  --project /var/tmp/wild-goal3-sources/ripgrep \
  --source-revision <FULL_COMMIT> \
  --lockfile /var/tmp/wild-goal3-sources/ripgrep/Cargo.lock \
  --profile release \
  --target x86_64-pc-windows-msvc \
  --final-output rg.exe \
  --wild /absolute/path/to/frozen-wild \
  --lld-link /usr/lib/llvm-18/bin/lld-link \
  --tool cargo=/home/yakov/.rustup/toolchains/1.95.0-aarch64-unknown-linux-gnu/bin/cargo \
  --tool rustc=/home/yakov/.rustup/toolchains/1.95.0-aarch64-unknown-linux-gnu/bin/rustc \
  -- \
  cargo +1.95.0 rustc --locked --release \
    --target x86_64-pc-windows-msvc --bin rg -- \
    -C linker={linker}
```

The selected invocation is recognized by its final `/OUT:rg.exe`. If no
invocation or more than one invocation matches, capture fails rather than
guessing. The reproduction must contain exactly one `response.txt`, and the
response is checked for the three enforced fairness flags.

## ELF example

The build must actually select `{linker}` as its linker and use Goal 3's
`x86_64-unknown-linux-gnu` comparison target. The selected Wild save-dir is
identified by the exact basename in its `# Original output file:` line;
ambiguity is an error.

```console
uv run plans/pe-coff/dgx-corpus_001.py elf \
  --name ripgrep-elf \
  --output-root /var/tmp/wild-goal3-corpora \
  --project /var/tmp/wild-goal3-sources/ripgrep \
  --source-revision <FULL_COMMIT> \
  --lockfile /var/tmp/wild-goal3-sources/ripgrep/Cargo.lock \
  --profile release \
  --target x86_64-unknown-linux-gnu \
  --final-output rg \
  --wild /absolute/path/to/frozen-wild \
  --reference-linker /usr/lib/llvm-18/bin/ld.lld \
  --tool cargo=/home/yakov/.rustup/toolchains/1.95.0-aarch64-unknown-linux-gnu/bin/cargo \
  --tool rustc=/home/yakov/.rustup/toolchains/1.95.0-aarch64-unknown-linux-gnu/bin/rustc \
  -- \
  cargo +1.95.0 rustc --locked --release \
    --target x86_64-unknown-linux-gnu --bin rg -- \
    -C linker={linker}
```

Because Wild's `run-with` script accepts the linker command as its arguments,
the frozen corpus can replay through both the recorded Wild and `ld.lld`.
Always set `OUT` to an external writable path: the corpus itself is read-only.

## Verification

Run the corpus-independent tests on every platform change:

```console
uv run plans/pe-coff/dgx-corpus_001.py --self-test
```

Before timing a new corpus:

1. inspect `metadata.json`, `manifest.json`, and the exact response or
   `run-with` bytes;
2. extract `corpus.tar` independently and confirm its recorded SHA-256;
3. execute both recorded replay commands with the same external output
   filesystem;
4. validate the produced PE/ELF and Wild determinism outside timed samples;
5. run native Windows correctness for PE separately from DGX link timing.
