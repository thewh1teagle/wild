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
