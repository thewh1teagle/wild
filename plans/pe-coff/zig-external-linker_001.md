# Frozen Zig external-linker bridge

`zig-external-linker_001.py` lets native AArch64 Wild and `ld.lld`
cross-link the same x86-64 GNU ELF inputs. Compilation and Zig sysroot planning
happen only while preparing a replay corpus; neither belongs in a timed linker
sample.

The bridge is deliberately bound to Zig 0.16.0 and target
`x86_64-linux-gnu`. It asks Zig for the exact in-process `ld.lld` plan with
`-###`, validates one `elf_x86_64` plan, then replaces `ld.lld` with the
absolute executable in `GOAL3_LINKER`. It strips only these non-semantic Zig
implementation controls, which Wild does not accept:

- `-mllvm -float-abi=hard`
- `--error-limit=0`
- `--image-base=0`

Every other parsed argument is forwarded in the same order and with the same
token bytes. A missing control, a changed value, an unfamiliar plan-output
line, multiple link commands, another emulation, another Zig version, a Zig
binary hash mismatch, relative tool paths, or a target override fails closed.

## One-time setup on the DGX

Use the pinned Rust toolchain and add only its target standard library:

```sh
rustup target add x86_64-unknown-linux-gnu \
  --toolchain 1.95.0-aarch64-unknown-linux-gnu
```

The proven DGX setup uses:

- `rustc 1.95.0 (59807616e 2026-04-14)`, LLVM 22.1.2;
- native AArch64 Zig 0.16.0 at `/snap/zig/current/zig`, SHA-256
  `6e2989a7efbd4e81acbacb6c6378e34340d8e88bb023b10c4a941021be55cdcb`;
- native AArch64 Ubuntu LLD 18.1.3 at `/usr/bin/ld.lld`, SHA-256
  `f8835e48488195c65fb3dcb946053284ddf6b1369922893785209a9073c4e57b`.

Recheck hashes and versions rather than assuming paths identify immutable
binaries:

```sh
/snap/zig/current/zig version
sha256sum /snap/zig/current/zig /usr/bin/ld.lld
rustc +1.95.0 -vV
```

## Capture

Build the exact Wild revision first and record its source and executable
SHA-256. Then point rustc or Cargo at the bridge. The bridge inherits
`WILD_SAVE_DIR` or `WILD_SAVE_BASE`, so Wild's normal self-contained `run-with`
capture remains the replay format.

For one direct rustc link:

```sh
export GOAL3_ZIG=/snap/zig/current/zig
export GOAL3_LINKER=/absolute/path/to/exact/wild
export GOAL3_LINK_PROVENANCE_DIR=/absolute/path/to/provenance
export WILD_SAVE_DIR=/absolute/path/to/corpus

rustc +1.95.0 --target x86_64-unknown-linux-gnu -C opt-level=3 \
  -C linker="$PWD/plans/pe-coff/zig-external-linker_001.py" \
  source.rs -o /absolute/path/to/preparation-output
```

For Cargo, configure the target linker and keep the frozen source revision,
`Cargo.lock`, profile, features, Rust version, Zig version, and all binary
hashes with the corpus:

```sh
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$PWD/plans/pe-coff/zig-external-linker_001.py"
export GOAL3_ZIG=/snap/zig/current/zig
export GOAL3_LINKER=/absolute/path/to/exact/wild
export GOAL3_LINK_PROVENANCE_DIR=/absolute/path/to/provenance
export WILD_SAVE_BASE=/absolute/path/to/save-base

cargo +1.95.0 build --locked --release --target x86_64-unknown-linux-gnu
```

Each bridge invocation writes a unique JSON provenance record before invoking
the linker. It includes the bridge, Zig, and linker paths and hashes; the raw
driver tokens; Zig's parsed plan; the exact stripped controls; the effective
external-linker tokens; working directory; target; and active Wild capture
path. Setting both Wild save variables is rejected as ambiguous.

After preparation, select the final application save directory using the
`# Original output file:` comment in `run-with`, freeze it by copying or
tar/extracting it (Wild may initially hard-link inputs), hash a sorted manifest,
and verify both linkers outside timing:

```sh
OUT=/dev/shm/wild-elf ./run-with /absolute/path/to/wild --threads=10
OUT=/dev/shm/lld-elf  ./run-with /usr/bin/ld.lld --threads=1
readelf -h /dev/shm/wild-elf
readelf -h /dev/shm/lld-elf
```

The DGX has no x86-64 execution layer by default. Successful native-AArch64
cross-linking plus ELF inspection proves structural replay, not execution.
Execute the frozen x86-64 outputs on a native x86-64 Linux runner for semantic
validation; do not silently install or treat emulation as native execution.

Run the corpus-independent bridge tests with:

```sh
python3 plans/pe-coff/zig-external-linker_001.py --self-test
python3 -m py_compile plans/pe-coff/zig-external-linker_001.py
```
