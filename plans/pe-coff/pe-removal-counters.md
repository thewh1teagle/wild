# PE removal counters

Goal 3 uses process-global work counters to distinguish real algorithmic work
removal from timing noise. They live in `perf::removal_counters` and retain one
stable API on supported and unsupported hardware-counter platforms.

## Enabling and cost

Build diagnostic binaries with `--features pe,wip`. In those builds, every
increment is one relaxed atomic operation. Ordinary production builds without
`wip` retain the same functions, but the increments are inline no-ops and
snapshots are zero. `removal_counters::ENABLED` lets a call site avoid computing
an expensive counter amount; simple amounts already available at the call site
can be passed directly.

The counters are intentionally separate from `perf-event` hardware counters.
They are process-global because PE work is distributed across Rayon workers.
`snapshot()` uses independent relaxed loads, not a transactional multi-counter
read. Callers must join phase workers before taking a milestone snapshot, and
must call `reset()` only while no instrumented work is running. `delta_since()`
uses saturating subtraction so an accidental reset cannot wrap evidence values.

Each counter has both `add_<name>(u64)` and `increment_<name>()`; use `add` when
an existing collection or byte length represents several events, and
`increment` at a single event boundary.

## Counting boundaries and target invariants

| Counter | Increment boundary | Goal 3 target invariant |
|---|---|---|
| `name_bytes_allocated` | Bytes newly heap-owned solely for a symbol/name key. Do not count borrowed input slices, static names, output strings, or container capacity unrelated to name bytes. | Approximately zero owned name bytes in hot PE resolution/layout paths; documented unavoidable output names are reported separately. |
| `name_hash_ops` | One completed hash computation for one name occurrence or table lookup, at the hash invocation rather than at every equality probe. | Approximately one hash per occurrence during indexing and one per actual lookup; no rehashing of the same occurrence inside later phases. |
| `relocation_decodes` | One relocation record decoded from COFF bytes into semantic fields. Bulk decoders add the number of records actually decoded. | Each live relocation is decoded once, stored in indexed IR, and reused by REF traversal, layout, and write. Dead relocations decoded during required indexing must be disclosed separately. |
| `bytes_copied` | Bytes explicitly copied into the final output image or into an intermediate buffer that is subsequently copied again. Count every copy so duplicate staging is visible; do not count zero-fill. | Approximately one output image worth of explicit bytes, plus small documented headers/synthetic data; no second full contribution staging copy. |
| `object_full_parse_passes` | One traversal that reparses all records of an object (symbols, sections, or relocations). Targeted indexed access is not a full pass. | One indexing pass per selected object, followed by indexed write access rather than another full parse. Any format-validation pass is identified separately. |
| `archive_member_probes` | One attempt to inspect or resolve an archive member candidate, including an unsuccessful candidate probe. | Near one indexed candidate lookup per unresolved demand; repeated full archive/member probing approaches zero. |
| `selected_members` | First transition of a unique archive member into the selected set. Never increment when an already-selected member is encountered again. | Exactly the number of unique selected archive members and never greater than member probes. |
| `hot_phase_allocations` | One explicit allocation operation at an annotated PE hot-phase call site (`Vec`/map growth, owned box/string creation, or equivalent). | Approximately zero after capacities and arenas are established. This is a call-site counter, not an allocator-wide count; exact allocator interception is deliberately out of scope. |

Counter additions must name the semantic boundary in a nearby comment when the
increment location is not self-evident. Do not increment both a wrapper and its
callee for the same event.

## Milestone evidence

For each frozen corpus and selected thread count:

1. Build and hash an exact `pe,wip` diagnostic binary and record that removal
   counters are enabled.
2. Reset at the quiescent start of the link, then take snapshots after input
   selection/indexing, after layout/relocation processing, and after the final
   output write. Join all workers before every snapshot.
3. Store the raw snapshots and per-phase `delta_since()` values in JSON using
   the Rust field names in this document. Record selected-object count, live
   relocation count, output file size, selected archive-member count, corpus
   hash, binary hash, threads, and exact command beside them.
4. Repeat an identical link and require identical counter snapshots as well as
   byte-identical output. A timing improvement without the expected counter
   reduction is not accepted as proof of work removal.
5. Report actual/target ratios: name bytes per indexed name, hashes per name
   occurrence/lookup, decodes per live relocation, copied bytes per output
   byte, full parse passes per selected object, probes per selected member, and
   hot allocations per selected object.

Counters are diagnostic evidence only. Final performance binaries are rebuilt
without `wip`; authoritative Goal 3 timing never includes counter overhead.
