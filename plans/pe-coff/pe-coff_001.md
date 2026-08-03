# PE/COFF semantic differential check

Compare a trusted PE (normally produced by `lld-link`) with Wild's output:

```console
uv run plans/pe-coff/pe-coff_001.py reference.exe candidate.exe --verbose
```

The script discovers `llvm-readobj` (or accepts `--llvm-readobj PATH` /
`LLVM_READOBJ`), probes the installed LLVM's capabilities, and compares headers,
sections, symbols, imports, exports, base relocations, and unwind information.
Timestamps, checksums, producer versions, DOS-stub details, alignment/padding, and
linker-chosen addresses are normalized. Names, meaningful sizes, flags, counts,
relocation kinds, import/export identities, and unwind semantics are retained;
record order is canonicalized. A semantic mismatch exits 1; setup or inspection
errors exit 2. This is a focused structural signal, not a replacement for execution
on Windows or malformed-image validation.

The dependency-free normalization self-test does not need LLVM or a PE file:

```console
uv run plans/pe-coff/pe-coff_001.py --self-test
```
