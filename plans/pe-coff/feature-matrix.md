# PE/COFF feature matrix

Snapshot of completed Goal 1 at commit `547c72f309dc8dd73e5a43166e183491138395e7`
(2026-08-03; audited in [`goal1-gaps.md`](goal1-gaps.md)). This
describes demonstrated behavior, not intended future behavior. See
[`GOAL.md`](../../GOAL.md), [`quality-gate.md`](quality-gate.md), and
[`session-handoff.md`](session-handoff.md) for scope and reproducible evidence.

## Status legend

| Status | Meaning |
|---|---|
| **Supported + verified** | Implemented and exercised by focused tests, differential checks, or native Windows execution. |
| **Supported / limited** | Implemented, but deliberately narrower than `link.exe`/`lld-link` or not broadly exercised. |
| **Accepted / no-op compatibility** | Accepted so compiler drivers work, but does not provide the feature normally associated with the option. |
| **Intentionally rejected** | Fails explicitly instead of silently producing a misleading or unsafe image. |
| **Not implemented** | No end-to-end implementation is claimed. |
| **Performance gap** | Correctness exists, but measured performance or scaling is behind the reference. |

## Targets and application coverage

| Area / feature | Status | Current evidence or behavior | Gap or next action |
|---|---|---|---|
| AMD64 PE32+ executables | **Supported + verified** | Freestanding, C, C++, Rust and GUI executables execute on real x86-64 Windows. | Broaden SDK, compiler and application coverage. |
| AMD64 PE32+ DLLs | **Supported + verified** | C/C++ DLLs and consumers, plus a Rust `cdylib` and C consumer, execute on Windows. Generated import libraries are exercised. | Add more complex export/versioning cases. |
| C and C++ with MSVC CRT | **Supported + verified** | Full runtime workflow links and runs executables, DLLs and consumers against real CRT/SDK libraries. | Test more CRT/SDK releases and exception-heavy C++. |
| Rust `std` executable | **Supported + verified** | x86-64 MSVC Rust `std` program links, executes, and is also used by the local performance probe. | Expand crate/application corpus. |
| Rust `cdylib` | **Supported + verified** | Rust DLL plus C consumer executes on Windows. | Add mixed-language and larger DLL graphs. |
| Compiler-generated TLS and callbacks | **Supported + verified** | Dedicated local and native-Windows TLS cases pass. | Add more TLS models and destructor cases. |
| Minimal Tauri, debug and release | **Supported + verified** | Both profiles reach Tauri's Ready event on Windows and exit with the expected code 73. | Keep as a regression gate. |
| Pinned Vibe, debug and release | **Supported + verified** | Both Wild-linked profiles produce valid AMD64 images; real GUI windows appear and stay alive; sidecars pass. Same-revision `lld-link` controls match behavior. | Test newer pinned revisions intentionally, not silently. |
| Native Windows execution | **Supported + verified** | GitHub `windows-latest` runs the Microsoft loader/runtime for all acceptance tiers. | A physical Windows machine or local VM is optional, not a blocker. |
| x86, ARM64, other PE targets | **Not implemented** | `/MACHINE` accepts only `X64`/`AMD64`; other machine values are rejected. | Add one architecture at a time with relocation and native-runtime suites. |
| Linux Wild maturity parity | **Not implemented** | PE is an opt-in experimental feature; it lacks Linux Wild's breadth, hardening, diagnostics and performance maturity. | Requires sustained compatibility, fuzzing, profiling and production use, not only PDB/LTO work. |

## Inputs, resolution, and command-line compatibility

| Area / feature | Status | Current evidence or behavior | Gap or next action |
|---|---|---|---|
| Standard COFF objects | **Supported + verified** | Parsed and linked across the complete acceptance corpus; the standalone cargo-fuzz target exercises standard/bigobj object and archive parsing. | Add more producer versions and sustained fuzzing. |
| Bigobj COFF objects | **Supported + verified** | Unified standard/bigobj parser and focused tests cover AMD64 bigobj records. | Broaden end-to-end producer coverage. |
| Self-contained COFF archives | **Supported + verified** | MSVC/GNU-style archives, symbol lookup, lazy extraction and `/WHOLEARCHIVE` behavior are implemented; default libraries resolve to a fixpoint. | Add large-archive performance cases. |
| Thin COFF archives | **Intentionally rejected** | Parser reports that non-self-contained thin archives are unsupported. | Implement path/member ownership and hermetic tests before accepting them. |
| Import libraries | **Supported + verified** | Existing import libraries are consumed; DLL builds generate import libraries used by consumers. | Expand unusual import-name and ordinal combinations. |
| Response files | **Supported + verified** | UTF-8, UTF-16LE/BE, quoting, nested relative paths, recursion detection and depth limits have focused tests; real rustc/Tauri/Vibe invocations use them. | Continue compatibility testing against compiler-driver edge cases. |
| `.def` files | **Supported / limited** | Definition-file parsing and integration exist; one command-line `/DEF` is supported. | Not every obscure `.def` directive or combination is implemented. |
| `/DEFAULTLIB`, `/NODEFAULTLIB`, `/DISALLOWLIB` | **Supported + verified** | Directives and command-line forms drive archive selection, including transitive fixpoint behavior and invalidation. | Add diagnostics for more conflicting library graphs. |
| `/ALTERNATENAME`, weak externals, absolute symbols | **Supported + verified** | Fallback chains, cycle detection, precedence and relocation behavior have resolver/writer tests and real CRT use. | Expand malformed and uncommon weak-external cases. |
| COMDAT selection and associative liveness | **Supported + verified** | Object-local identity, deterministic selection, associative liveness and relocation redirection from discarded COMDATs are covered. | Add scale/performance and more selection-kind cases. |
| Common MSVC/rustc compatibility flags | **Supported + verified** | Common CMake/MSBuild release options, `/` and `-` spellings, and safe no-op compatibility forms are accepted. Unknown options warn instead of failing; enabled CET, CFG, LTO and incremental linking remain explicitly rejected. | Expand only from observed production link lines. |
| `/OPT:REF` and `/OPT:ICF` | **Supported / limited** | `/OPT:REF` performs real COMDAT-group reachability and dead-import pruning, with lld-compatible release/debug defaults and explicit `/OPT:NOREF`. `/OPT:ICF` remains an accepted no-op. | Profile the GC pass in Goal 2; implement ICF later if justified. |
| Diagnostics and invalid-input handling | **Supported + verified** | Unsupported machines and unsafe deferred features fail explicitly; parser/unit coverage includes overflow cases and native Windows negative-loader fixtures. | Continue fuzzing and improve diagnostics from production reports. |

## PE image and loader features

| Area / feature | Status | Current evidence or behavior | Gap or next action |
|---|---|---|---|
| AMD64 relocations | **Supported + verified** | Required COFF AMD64 relocation forms link the C/C++/Rust/Tauri/Vibe corpus. | Expand rare relocation and overflow diagnostics. |
| Imports and IAT | **Supported + verified** | Import descriptors, thunks and writable IAT work with CRT, SDK, DLL consumers, Tauri and Vibe. | Add unusual bound/import edge cases. |
| Exports and generated import library | **Supported + verified** | `/EXPORT`, ordinal-only imports, forwarded exports, DLL exports and generated consumer import libraries pass native runtime tests. | Broaden unusual aliases and forwarder chains. |
| Resources | **Supported + verified** | Resource contributions are emitted and exercised by real Tauri/Vibe application images. | Add focused malformed-resource and merge-order cases. |
| TLS directory and callbacks | **Supported + verified** | Integrated compiler TLS and callback execution passes on Windows. | Add broader runtime patterns. |
| Exception/unwind tables (`.pdata`/`.xdata`) | **Supported + verified** | Canonical `.pdata` ordering and unwind data support real C++, Rust, Tauri and Vibe. | `/MERGE` of `.pdata` is deliberately unsupported; add exception-heavy runtime tests. |
| Load-config directory | **Supported + verified** | CRT load-config contributions are preserved and sized correctly; the fix unlocked the full runtime corpus. | Extend security metadata conservatively and test more toolchain versions. |
| Base relocations and ASLR controls | **Supported + verified** | Base-relocation directory plus `/DYNAMICBASE`, `/FIXED`, image-base handling and loader execution are covered. | Add relocation-under-forced-rebase native tests. |
| NX compatibility and core image controls | **Supported / limited** | `/NXCOMPAT`, alignments, stack/heap sizes, subsystem and image/version controls are implemented. | Broaden exact option/interoperability coverage. |
| PE checksum | **Supported + verified** | Independent calculation, patching and validation have focused tests; emitted image support is integrated. | Add comparison with more external producers/signing flows. |
| Reproducible debug directory | **Supported / limited** | Deterministic in-image debug metadata is emitted and validated; this is not PDB generation. | Validate debugger-facing behavior when real PDB support lands. |
| Long COFF/PE section names | **Supported + verified** | Long-name string-table handling is tested and required by real Rust/Vibe inputs. | Keep producer-compatibility cases. |
| Delay-import directory | **Supported + verified** | `/DELAYLOAD` partitions eager/delayed imports, extracts `__delayLoadHelper2`, emits `.didat`, writable delay IAT entries and DIR64 relocations, plus ABI-preserving AMD64 resolver thunks with `.pdata`/unwind information. A delay-loaded DLL executes on Windows. | Data imports remain unsupported, matching the practical helper-thunk scope. |
| Embedded manifests | **Supported + verified** | `/MANIFEST:EMBED[,ID=n]`, UAC/dependencies, UTF-8/UTF-16 `/MANIFESTINPUT` merging, sidecars and DLL/executable resource IDs are integrated. A GUI-subsystem fixture is linked and executed on Windows. | Extend schema-aware merging only when real inputs require it. |
| `/MERGE` | **Supported / limited** | General section merges are implemented and validated. | `.pdata` merge is explicitly rejected because the exception-directory range must remain exact. |

## Debugging, optimization, incremental linking, and security

| Area / feature | Status | Current evidence or behavior | Gap or next action |
|---|---|---|---|
| PDB generation | **Not implemented** | No PDB file is emitted. `/DEBUG`, `/PDB`, `/PDBALTPATH` and `/NATVIS` are accepted where needed for driver compatibility; debug sections remain in the image. | Implement PDB emission, type/public data, path handling, determinism and debugger validation. |
| `/PDB`, `/PDBALTPATH`, `/NATVIS` flags | **Accepted / no-op compatibility** | Values are parsed/stored or ignored as appropriate so rustc and MSVC-style builds proceed. | Their full meaning depends on real PDB generation. |
| LTO / `/LTCG` | **Intentionally rejected** | `/LTCG` is diagnosed as unsupported rather than pretending to consume LLVM bitcode. | Study LLVM LTO APIs and `lld/COFF`; define plugin/codegen ownership and add mixed native/bitcode tests. |
| Incremental linking / `/INCREMENTAL` | **Intentionally rejected** | Unsupported option is diagnosed; links are full deterministic links. | Design state format, invalidation and PDB interaction only after full-link/PDB stability. |
| Control Flow Guard `/GUARD:CF` | **Intentionally rejected** | Existing CRT guard/load-config inputs are handled conservatively, but an explicit enabled CFG request fails instead of emitting incomplete security metadata. `/GUARD:NO` compatibility is supported. | Implement complete GFIDS/IAT/longjmp/EH metadata and validate with Windows tooling/runtime. |
| Other security hardening/signing | **Supported / limited** | Core ASLR/base relocations, NX compatibility, load config and checksum behavior exist. Authenticode hashing exclusions have utility-level tests. | End-to-end signing, sanitizers and wider security metadata are not established. |

## Correctness, reproducibility, and performance

| Area / feature | Status | Current evidence or behavior | Gap or next action |
|---|---|---|---|
| Wild deterministic output | **Supported + verified** | Each of six freestanding fixtures links twice with Wild and produces byte-identical output. | Extend determinism gates to larger cached/non-cached links and multiple hosts. |
| `lld-link` semantic parity | **Supported + verified** | Six normalized differential fixtures pass, and paired debug/release Vibe builds have matching CLI/GUI behavior on Windows. | Keep bounded equivalences explicit and expand the corpus. |
| Wild versus `lld-link` byte identity | **Not implemented** | Byte identity is not a goal and is disproven: all differential fixtures differ; Vibe differs from offset `0x2`. Legal section/layout choices also differ. | Compare loader-visible semantics and behavior, not producer bytes. |
| PE linker parallelism | **Performance gap** | No demonstrated PE-specific parallel resolution/layout/writer speedup is present in the current implementation. | Profile first, then parallelize proven hot stages with scaling benchmarks. |
| Current link speed | **Performance gap** | The latest local complete Rust compile/link probe remains slower than `lld-link`; the 30-second check is only a correctness budget. | Goal 2 begins with link-only cold/warm, RSS and thread-scaling profiles before optimization. |
| Focused CI and local verification | **Supported + verified** | macOS M4 runs unit, xwin, structural, differential and budget checks; focused Actions run the real Windows loader for core, runtime, Tauri and Vibe tiers. | Preserve fast focused gates and add negative/fuzz/performance jobs separately. |

## Prioritized next milestones

Restructured 2026-08-03; the authoritative plan is [`GOAL.md`](../../GOAL.md)
with evidence in [`goal1-gaps.md`](goal1-gaps.md).

**Goal 1 is complete** at `547c72f309dc8dd73e5a43166e183491138395e7`:
option compatibility, real `/OPT:REF`, delay imports, stability/fuzz hardening,
and manifest embedding all pass local and native Windows acceptance gates.

**Goal 2 — performance (next, on a new branch):** profile link-only workloads
(cold/warm/RSS/thread scaling) against `lld-link` first, then parallelize the
proven hot stages; remove the measured slowdown before making speed claims.

**Deferred final phases (each separate):** PDB emission with debugger
validation and real `/MAP`; full CFG/`/GUARD:EHCONT`/`/CETCOMPAT` security
metadata; LTO after PDB; incremental linking last; niche compatibility
(thin archives, exotic `.def`, `/MERGE:.pdata`, non-x64 targets); continued
hardening toward Linux Wild maturity.
