# PE architecture demolition map

This document freezes the deletion plan for Goal 3. The new `pe_ir`, `pe_symbol_db`, and `pe_gc`
modules are interface contracts; they are not permission to keep both architectures indefinitely.
Each milestone is complete only when its listed re-derivations are removed and the semantic
invariants below remain covered.

## Ownership split

- Opened-input storage owns file bytes for the whole link. `SourceFiles` borrows those allocations;
  `SourceRange` is the only payload reference stored in PE IR.
- `PeIr` owns dense object, section, symbol-occurrence, name, and relocation records. `SymbolId`
  identifies one per-object COFF symbol occurrence; its `SymbolRecord` maps to canonical `NameId`.
  It parses each selected object once and is immutable after construction.
- `SymbolDb` owns one global resolution entry per canonical `NameId`, provider lists and
  selections, weak-fallback `NameId` relationships, weak/common/strong precedence, import identity,
  and absolute/linker-defined values.
- `GcOutput` owns liveness, canonical section IDs, redirects, and deterministic visitation order.
- Layout owns output placement only. It consumes borrowed source ranges and dense decisions; it does
  not parse COFF, resolve symbols, run GC, or own another copy of input payloads.
- Emission owns the output allocation. It copies each live source range once while applying the
  already-decoded relocation CSR and then emits synthetic tables.

## M1 — one parse, one name, one resolution

Build `PeIr` and `SymbolDb` beside the current pipeline, switch resolution consumers, then delete:

### Selected-symbol metadata re-derivation

- `SelectedObjectMetadata`, `SelectedObjectMetadata::new_with_undefined`, `definition_names`, and
  `weak` in `pe_writer.rs`.
- The test-only `selected_symbol_snapshot` raw object scan and `undefined_symbols` duplicate.
- Every construction at import resolution, `build_image`, contribution tests, COMDAT tests, and
  live-import tests. There must be no alternate metadata constructor for tests.
- `SelectedGlobalSymbol`/`SelectedSymbolSnapshot` once their data is represented by `SymbolRecord`,
  `SymbolDb`, and the canonical weak-fallback table.

### Repeated name ownership

Replace byte-vector keys with `NameId` and delete production `name.to_vec()`/`name.clone()` sites in:

- resolver `defined`, `unresolved`, roots, weak records, import definitions, fallback demands, and
  archive-demand snapshots;
- `ArchiveProviderCache::by_name`, including the raw-byte `HashMap<Vec<u8>, ...>` provider key;
- writer unresolved/definition sets, absolute-symbol maps, common-symbol maps, relocation
  definitions, weak/alternate bindings, live-import sets, exports, and local-symbol searches;
- repeated section-name ownership where an interned `NameId` plus output-name decision suffices.

Input names remain borrowed `SourceRange`s. The name table may own hashes and collision chains, but
must not own a second copy of every name. Textual command-line names are interned once at ingress.

### Provider and archive identity

- Replace `(archive_index, member_index)`, raw member-name bytes, and `ArchiveProvider` usize pairs
  with dense provider/member IDs.
- Replace incremental raw-byte archive provider probing with `NameId`-keyed provider CSR ranges.
- Keep lazy archive payload parsing, but publish discovered definitions/providers exactly once.
- Short-import definitions become providers in the same database rather than a parallel
  `BTreeSet<Vec<u8>>` plus selected-record list.

### Generic object iterator consumers

After IR parity, no post-parse phase may call `object.file().symbols()`, `symbol_by_index`,
`section_by_index`, or decode a symbol/section name. Initial object validation and the single IR
builder are the only exceptions.

## M2 — event-driven selection and GC

Switch archive selection and `/OPT:REF` roots to canonical `NameId` and section IDs, while keeping
relocation targets as per-object `SymbolId` occurrences that map to `NameId`, then delete:

- `IncrementalSymbolState`'s separately owned defined/unresolved byte sets once `SymbolDb` emits
  provider-selected and unresolved events.
- repeated root reconstruction across command arguments, directives, entry/export inference, weak
  fallbacks, and default-library waves; roots are interned once and appended as ordered events.
- `CompactComdatAnalysis`, `ComdatResolution` hash sets/maps, `ObjectSectionKey`,
  `record_comdat_redirects`, repeated redirect chasing, and per-call definition graphs.
- `unreferenced_comdat_sections`' object/section/relocation iterator walk and its temporary edge
  vectors/linked-list arrays. `EventDrivenGc` consumes CSR edges and emits dense live/canonical
  arrays once.
- separate selected/discarded classification scans in contribution materialization. Layout reads
  `GcOutput::is_live` and `canonical` directly.

Archive extraction remains demand-driven. When a provider selects a new object, parsing appends a
bounded IR batch, resolution publishes ordered provider events, and GC consumes new roots/edges;
there is no global rescan of old objects.

## M3 — one relocation walk and zero-copy input payloads

Route layout and emission through `PeIr`, then delete:

### Generic section and relocation walks

- every `object.file().sections()` and `section.relocations()` consumer outside the IR builder;
- `collect_live_import_references`' relocation scan;
- `discover_dir64_sites` and `discover_dir64_sites_in_contributions` as a separate walk;
- serial and parallel relocation job-discovery scans in `apply_relocations`;
- `apply_section_relocations`/`prepare_relocation` object lookups and symbol-name decoding;
- exact-match COMDAT relocation formatting through generic iterators.

The relocation CSR is decoded once. One event/annotation pass marks import references and DIR64
sites while building GC edges; final application walks only live CSR ranges in deterministic
section/relocation order.

### Payload copies

- `Contribution.data: Vec<u8>` for object-backed sections;
- `section.data()?.to_vec()` in `materialize_object_contributions_into`;
- object-payload cloning performed solely to carry bytes from parsing to layout.

Object contributions carry `SourceRange`; synthetic contributions may still own generated bytes.
Emission copies a live source range directly into its final output placement once. BSS has no
source range and is zero-filled by output allocation policy.

### Parallel maps and temporary identity

- `(usize, object::SectionIndex)` location maps after dense `SectionId -> placement` arrays exist;
- repeated `HashMap<Vec<u8>, u64>` definition/absolute maps after packed resolutions expose final
  values by canonical `NameId`;
- per-consumer relocation chunk vectors once stable CSR ranges provide sharding boundaries.

## Semantic invariants

The demolition is invalid if any of these change:

1. Input object order, section order, symbol order, relocation order, archive order, and member
   precedence define deterministic selection and first-error order.
2. Standard COFF and bigobj produce the same IR semantics; raw-format differences end in parsing.
3. Weak externals, `/alternatename`, common symbols, strong definitions, imports, absolute symbols,
   and linker-defined symbols retain current precedence. A selected strong definition stops every
   fallback chain.
4. Empty global definitions remain definitions. Non-UTF-8 names remain byte identities and do not
   participate in textual directives.
5. Malformed data is diagnosed at the same policy boundary: discarded sections do not trigger
   relocation target/kind errors; local names and section contents remain lazy until required.
6. Non-COMDAT sections are GC roots. Associative COMDAT children follow their ultimate leader;
   redirects are acyclic and relocation targets use the selected canonical section.
7. `/OPT:NOREF` performs no GC/relocation-index allocation. `/OPT:REF` output is identical across
   thread counts.
8. Import retention, DIR64/base-relocation sites, and final relocation application observe the same
   set of live relocations. Absolute symbols never create DIR64 sites.
9. Short-import/archive precedence, default-library fixpoint behavior, whole-archive selection, and
   non-monotonic `/NODEFAULTLIB` rebuilds remain unchanged.
10. Borrowed source ranges never outlive opened-input storage; parallel emission writes disjoint
    final contribution ranges; no IR record contains a self-reference.
11. IDs are dense `u32`; `u32::MAX` is reserved for packed optional/sentinel values and is never a
    valid allocated ID. `NameId` is the global resolution/root namespace; `SymbolId` is the
    per-object occurrence namespace used by relocation records and object-provider payloads.
12. No compatibility bridge may become permanent: each milestone deletes the old producer after
    all of its consumers switch and parity gates pass.
