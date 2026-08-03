# Rust PE/COFF corpus capture

`Capture-RustLldCorpus.ps1` captures the final link of one Cargo binary as an
LLVM `lld-link /reproduce` archive. It uses `cargo rustc --bin ... -- -C ...`,
so the capture flags apply only to that selected binary and not to dependency
build scripts or proc macros.

The output root must be outside both this repository and the source project's
repository. A successful capture contains:

- `link-repro.tar`: the validated lld reproduce archive;
- `response.txt`: the response file extracted from that archive;
- `metadata.json`: source commit/state, Cargo selection, profile, target, and
  Rust/MSVC/SDK/LLVM/NASM versions and paths;
- `cargo-build.log`: the Cargo output from the capturing build.

The staged `response.txt` is extracted and copied as raw bytes; PowerShell does
not decode or rewrite its line endings. Run `Test-CorpusTools.ps1` for the
LF-only and quoted-content byte-preservation regression.

Repeated invocation with the same inputs returns the existing validated
capture. Pass `-Force` to recapture it. Cargo build artifacts are cached under
`<OutputRoot>/.cargo-target`, never in the source repository.

The helper activates the installed x64 MSVC/Windows SDK environment, puts the
configured LLVM and NASM directories on `PATH`, and clears ambient Cargo
rustflags for the capture. `-CargoArgs` accepts feature, lock, and offline
options, but rejects options that could replace the selected package, binary,
target, profile, build location, or Cargo configuration.

## Small project

```powershell
.\plans\pe-coff\tools\Capture-RustLldCorpus.ps1 `
  -ProjectPath C:\src\hello-rust `
  -Bin hello-rust `
  -OutputRoot C:\corpora\wild-pe-coff
```

## Workspace package (for example, uv)

```powershell
.\plans\pe-coff\tools\Capture-RustLldCorpus.ps1 `
  -ProjectPath C:\src\uv `
  -Package uv `
  -Bin uv `
  -Profile release `
  -CargoArgs @('--locked') `
  -OutputRoot C:\corpora\wild-pe-coff
```

`-CargoArgs` are inserted before Cargo's final `--`, so feature selection and
lock/offline flags remain available without changing which linker invocation
is captured.

## Short-path extraction and replay

`Expand-LldRepro.ps1` safely extracts a reproduce archive under a deliberately
short replay root, runs `lld-link @response.txt`, and optionally runs Wild with
the same response file. It prints the exact directory containing
`response.txt`; replay logs, copied outputs, and `replay-results.json` are kept
there.

```powershell
$responseDir = .\plans\pe-coff\tools\Expand-LldRepro.ps1 `
  -ArchivePath C:\corpora\capture\link-repro.tar `
  -ReplayRoot C:\wr `
  -WildPath C:\src\wild\target\release\wild.exe
```

The destination is a new `r-<archive-hash>` directory. Existing destinations
and destinations inside this repository are rejected. Before creating it, the
helper rejects absolute or traversing archive entries, requires exactly one
`response.txt`, and calculates the longest extracted path. By default
`ReplayRoot` is limited to 64 characters and every extracted path to 240;
`-MaxReplayRootLength` and `-MaxExtractedPathLength` make those constraints
explicit when a different Windows environment needs other limits.
