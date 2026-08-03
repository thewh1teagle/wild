# Host tooling for PE/COFF development and verification

What a development host (human or agent session) needs to build and locally verify
`feature/pe-coff-v1`. The host architecture and OS mostly do not matter: all local
gates cross-compile x86-64 Windows objects and inspect PE structure. Native
execution is always authoritative on GitHub Actions `windows-latest`; no local
Windows machine, VM, or Wine is required on any host.

Verified working hosts so far:

- macOS Apple silicon (M4) — original development host (see `session-handoff.md`).
- Linux aarch64 (Ubuntu, 20 cores, 121 GB RAM) — current host, verified 2026-08-03.

## Required tools (all hosts)

| Tool | Purpose | Notes |
|---|---|---|
| Rust `1.95.0` toolchain | build + `cargo test` gates | pinned by `quality-gate.md` |
| Rust `1.94.0` toolchain | clippy gate | pinned |
| Rust `nightly` toolchain | `cargo fmt` gate | any recent nightly |
| `x86_64-pc-windows-msvc` target | compiling Windows objects/fixtures | add on 1.95.0 and default toolchain |
| `clang-cl`, `lld-link`, `llvm-readobj` | MSVC-style compiles, reference linker, PE inspection | LLVM 18 is the version the recorded evidence used; a newer major should work but re-baseline diffs deliberately |
| `xwin` + `~/.xwin/{crt,sdk}` | real Windows CRT/SDK import libraries for cross-linking | `xwin splat` downloads several GB once |
| `uv` | runs the `plans/pe-coff/*.py` gates | |
| `actionlint` | workflow lint gate | |
| `taplo` | TOML lint gate | |
| `cargo-fuzz` | bounded and sustained COFF/archive parser fuzzing | install with `cargo install cargo-fuzz --locked` |
| `gh` (authenticated) | dispatching and downloading the `pe-*.yml` Actions runs | account needs access to `thewh1teagle/wild` |

## Install per host

### Linux (Debian/Ubuntu, any arch)

```console
sudo apt install -y clang lld llvm        # provides clang-cl, lld-link, llvm-readobj
rustup toolchain install nightly 1.94.0 1.95.0 --component clippy,rustfmt
rustup target add x86_64-pc-windows-msvc
rustup target add x86_64-pc-windows-msvc --toolchain 1.95.0
cargo install xwin taplo-cli --locked
cargo install cargo-fuzz --locked
xwin --accept-license splat --output ~/.xwin
go install github.com/rhysd/actionlint/cmd/actionlint@latest   # or download release binary
curl -LsSf https://astral.sh/uv/install.sh | sh                # if uv missing
```

Linux quirks found while bringing up the Ubuntu aarch64 host (2026-08-03):

- Ubuntu's `clang` package ships no `clang-cl` binary, and a plain symlink does
  not work: the Python gates call `Path.resolve()` on the tool, which follows
  the symlink back to `clang` and loses cl-mode. Use a wrapper script instead:

  ```console
  printf '#!/bin/sh\nexec /usr/bin/clang-18 --driver-mode=cl "$@"\n' \
    > ~/.local/bin/clang-cl && chmod +x ~/.local/bin/clang-cl
  ```

- Same for `lld-link` if only the generic `lld` resolves; wrap the *named*
  symlink so argv[0] keeps the COFF flavor (do not add `-flavor link` yourself —
  rustc already passes it and lld rejects the duplicate):

  ```console
  printf '#!/bin/sh\nexec /usr/lib/llvm-18/bin/lld-link "$@"\n' \
    > ~/.local/bin/lld-link && chmod +x ~/.local/bin/lld-link
  ```

- `sudo apt install clang-format` is additionally required: the
  `libwild` unit suite's `tidy_tests::check_sources_format` spawns
  `clang-format` and fails without it.
- If the default rustup toolchain is older than 1.94, `pe-perf_001.py` fails
  when it invokes plain `cargo`; fix with `rustup override set 1.95.0` in the
  repository root (stored in `~/.rustup`, not in the repo).

### macOS (Apple silicon or Intel)

```console
brew install llvm gh go actionlint taplo uv
# brew's llvm is keg-only; put $(brew --prefix llvm)/bin on PATH for clang-cl/lld-link/llvm-readobj
rustup toolchain install nightly 1.94.0 1.95.0 --component clippy,rustfmt
rustup target add x86_64-pc-windows-msvc
rustup target add x86_64-pc-windows-msvc --toolchain 1.95.0
cargo install xwin --locked
cargo install cargo-fuzz --locked
xwin --accept-license splat --output ~/.xwin
```

### Windows x86-64 (optional local host)

A Windows host is the only one that can also execute the linked images locally,
but CI already covers that; treat local execution as a convenience.

```powershell
winget install Rustlang.Rustup GitHub.cli astral-sh.uv LLVM.LLVM GoLang.Go
rustup toolchain install nightly 1.94.0 1.95.0
rustup target add x86_64-pc-windows-msvc   # host target; xwin not needed if VS Build Tools or xwin CRT/SDK present
cargo install taplo-cli --locked
go install github.com/rhysd/actionlint/cmd/actionlint@latest
```

With Visual Studio Build Tools installed, the real MSVC CRT/SDK replaces xwin.
Wild can be selected as the linker by copying/renaming it to `link.exe` exactly as
the CI workflows do.

## Sanity check after install

```console
for c in clang-cl lld-link llvm-readobj uv actionlint taplo xwin gh; do
  command -v "$c" || echo "MISSING: $c"; done
rustup toolchain list          # expect nightly, 1.94.0, 1.95.0
rustup target list --installed # expect x86_64-pc-windows-msvc
ls ~/.xwin                     # expect crt/ and sdk/
gh auth status
```

Then run the local validation commands in `session-handoff.md`
("Local validation commands") from the repository root. If they all pass, the
host is fully capable of PE/COFF development; only native Windows execution
remains on the Actions workflows.

## Linux aarch64 host verification results (2026-08-03)

After the installs and fixes above, this host passes every local gate from
`quality-gate.md`:

- `cargo +nightly fmt --all -- --check` — pass.
- `cargo +1.94.0 clippy` with the `pe` feature — pass.
- `cargo +1.95.0 test -p linker-utils -p libwild --no-default-features
  --features pe` — 258 + 154 tests pass (1 opt-in xwin probe ignored). The
  exact-SHA closeout also passed 347 integration tests (1,232 ignored) and the
  2/2 full xwin candidate suite.
  Requires `clang-format` installed.
- `cargo +nightly fuzz run coff_parsers -- -runs=10000` — bounded parser
  smoke passes; generated corpus/artifact files remain ignored or outside the
  checked-in seed directory.
- `actionlint` and `taplo` gates — pass.
- `uv run plans/pe-coff/pe-repro_001.py --wild target/debug/wild` — all six
  fixtures byte-deterministic across Wild links and semantically equivalent to
  `lld-link` (LLVM 18.1.3, same major version as the original evidence).
- `uv run plans/pe-coff/pe-perf_001.py --wild-budget-seconds 30` — pass;
  measured Wild/lld-link complete compile+link ratio ≈ 3.3× on this 20-core
  machine (versus ≈ 5.5× recorded on the M4). Still a correctness budget, not a
  speed claim.

The full xwin-backed integration suite in `wild/tests/windows_pe_runtime.rs`
now runs on Linux. At Goal 1 closeout it passes the complete lld/Wild corpus
and malformed-image checks locally. Native-Windows CI remains authoritative
for execution, while Linux covers compilation, loader-visible structure,
delay-unwind inspection and semantic comparison.

## Host caveats

- ARM hosts (Apple silicon, Linux aarch64): fine — every target artifact is
  x86-64 PE, produced and inspected cross-host. Wine cannot run x86-64 PEs on
  aarch64 without emulation, but no gate uses Wine.
- `session-handoff.md` shows the original macOS workspace path
  `/Users/yqbqwlny/Documents/wild`; substitute the current host's checkout path.
- The `xwin splat` download is the only large one-time cost (several GB);
  everything else installs in minutes.
