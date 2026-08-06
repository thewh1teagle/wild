//! Canonical names and packed symbol/provider storage for PE.

#![allow(dead_code)]

use super::pe_ir::ArchiveId;
use super::pe_ir::ArchiveMemberId;
use super::pe_ir::ImportId;
use super::pe_ir::ImportLibraryId;
use super::pe_ir::NameId;
use super::pe_ir::ObjectId;
use super::pe_ir::ProviderId;
use super::pe_ir::SymbolId;
use hashbrown::HashMap;
use std::fmt;

const NONE_U32: u32 = u32::MAX;

fn note_vec_push<T>(values: &Vec<T>) {
    if values.len() == values.capacity() {
        crate::perf::removal_counters::increment_hot_phase_allocations();
    }
}

fn note_nonempty_allocation(len: usize) {
    if len != 0 {
        crate::perf::removal_counters::increment_hot_phase_allocations();
    }
}

fn into_boxed_slice_counted<T>(values: Vec<T>) -> Box<[T]> {
    if !values.is_empty() && values.len() != values.capacity() {
        crate::perf::removal_counters::increment_hot_phase_allocations();
    }
    values.into_boxed_slice()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum ProviderKind {
    ObjectSymbol,
    ArchiveMember,
    Import,
    Absolute,
    LinkerDefined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum BindingStrength {
    Weak,
    Common,
    Strong,
}

impl BindingStrength {
    const fn rank(self) -> u8 {
        self as u8
    }
}

/// Fixed-width provider payload. `owner` and `subject` are interpreted by `kind`.
///
/// - ObjectSymbol: ObjectId, SymbolId
/// - ArchiveMember: ArchiveId, ArchiveMemberId
/// - Import: ImportLibraryId, ImportId
/// - Absolute/LinkerDefined: zero, value-table index
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct ProviderRecord {
    pub(super) owner: u32,
    pub(super) subject: u32,
    pub(super) kind: ProviderKind,
    pub(super) strength: BindingStrength,
    pub(super) flags: u16,
}

impl ProviderRecord {
    pub(super) const fn object(
        object: ObjectId,
        symbol: SymbolId,
        strength: BindingStrength,
    ) -> Self {
        Self {
            owner: object.get(),
            subject: symbol.get(),
            kind: ProviderKind::ObjectSymbol,
            strength,
            flags: 0,
        }
    }

    pub(super) const fn archive(
        archive: ArchiveId,
        member: ArchiveMemberId,
        strength: BindingStrength,
    ) -> Self {
        Self {
            owner: archive.get(),
            subject: member.get(),
            kind: ProviderKind::ArchiveMember,
            strength,
            flags: 0,
        }
    }

    pub(super) const fn import(import_library: ImportLibraryId, import: ImportId) -> Self {
        Self {
            owner: import_library.get(),
            subject: import.get(),
            kind: ProviderKind::Import,
            strength: BindingStrength::Strong,
            flags: 0,
        }
    }

    pub(super) const fn absolute(value_index: u32, linker_defined: bool) -> Self {
        Self {
            owner: 0,
            subject: value_index,
            kind: if linker_defined {
                ProviderKind::LinkerDefined
            } else {
                ProviderKind::Absolute
            },
            strength: BindingStrength::Strong,
            flags: 0,
        }
    }

    pub(super) const fn kind(self) -> ProviderKind {
        self.kind
    }
}

/// `u32::MAX` is the unresolved provider sentinel, keeping every resolution eight bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct Resolution {
    pub(super) provider: u32,
    pub(super) state: ResolutionState,
    pub(super) binding: BindingStrength,
    pub(super) flags: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum ResolutionState {
    Unresolved,
    Resolved,
    Ambiguous,
    Discarded,
}

impl Resolution {
    pub(super) const UNRESOLVED: Self = Self {
        provider: u32::MAX,
        state: ResolutionState::Unresolved,
        binding: BindingStrength::Weak,
        flags: 0,
    };

    pub(super) const fn resolved(provider: ProviderId, binding: BindingStrength) -> Self {
        Self {
            provider: provider.get(),
            state: ResolutionState::Resolved,
            binding,
            flags: 0,
        }
    }

    pub(super) const fn provider(self) -> Option<ProviderId> {
        if self.provider == u32::MAX {
            None
        } else {
            Some(ProviderId::from_u32(self.provider))
        }
    }

    pub(super) const fn state(self) -> ResolutionState {
        self.state
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct SymbolEntry {
    pub(super) resolution: Resolution,
    pub(super) provider_start: u32,
    pub(super) provider_len: u32,
    pub(super) weak_fallback: u32,
}

impl SymbolEntry {
    pub(super) const NO_FALLBACK: u32 = u32::MAX;

    pub(super) const fn weak_fallback(self) -> Option<NameId> {
        if self.weak_fallback == Self::NO_FALLBACK {
            None
        } else {
            Some(NameId::from_u32(self.weak_fallback))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DeferredInvalidName {
    CoffNameOffset,
    RelocationSymbol,
}

/// A name occurrence whose hash was computed by the one-pass PE input indexer. Invalid
/// occurrences are deliberately un-hashed and always receive a fresh ID.
#[derive(Clone, Copy, Debug)]
pub(super) enum OrderedNameOccurrence<'data> {
    Valid { bytes: &'data [u8], hash: u64 },
    Invalid(DeferredInvalidName),
}

impl<'data> OrderedNameOccurrence<'data> {
    pub(super) const fn valid(bytes: &'data [u8], hash: u64) -> Self {
        Self::Valid { bytes, hash }
    }

    pub(super) const fn invalid(diagnostic: DeferredInvalidName) -> Self {
        Self::Invalid(diagnostic)
    }
}

enum NameStorage<'data> {
    Borrowed(&'data [u8]),
    /// Textual command-line names have no input-file lifetime and are copied once at ingress.
    Owned(Box<[u8]>),
    Invalid(DeferredInvalidName),
}

impl NameStorage<'_> {
    fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Borrowed(bytes) => Some(bytes),
            Self::Owned(bytes) => Some(bytes),
            Self::Invalid(_) => None,
        }
    }
}

/// Deterministic canonical-name interner.
///
/// IDs are assigned only by calls to `intern_*`, never by hash-table iteration. Feeding local
/// occurrences in input/object/symbol order therefore produces the same IDs for every Rayon
/// schedule. The hash table stores only collision chains of dense IDs; input names stay borrowed.
pub(super) struct OrderedNameInterner<'data> {
    names: Vec<NameStorage<'data>>,
    hashes: Vec<u64>,
    /// First dense NameId for each precomputed hash. Collisions continue through
    /// `collision_next`; the pass-through hasher avoids hashing the hash again.
    by_hash: HashMap<u64, NameId, crate::hash::PassThroughHasher>,
    collision_next: Vec<u32>,
}

impl<'data> OrderedNameInterner<'data> {
    pub(super) fn new() -> Self {
        Self {
            names: Vec::new(),
            hashes: Vec::new(),
            by_hash: HashMap::with_hasher(crate::hash::PassThroughHasher::default()),
            collision_next: Vec::new(),
        }
    }

    pub(super) fn len(&self) -> usize {
        self.names.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    pub(super) fn bytes(&self, id: NameId) -> Option<&[u8]> {
        self.names.get(id.index()).and_then(NameStorage::bytes)
    }

    pub(super) fn hash(&self, id: NameId) -> Option<u64> {
        self.hashes.get(id.index()).copied()
    }

    pub(super) fn lookup_prehashed(&self, bytes: &[u8], hash: u64) -> Option<NameId> {
        let mut current = self.by_hash.get(&hash).copied();
        while let Some(id) = current {
            if self.bytes(id) == Some(bytes) {
                return Some(id);
            }
            let next = *self.collision_next.get(id.index())?;
            current = (next != NONE_U32).then(|| NameId::from_u32(next));
        }
        None
    }

    pub(super) fn intern_borrowed_prehashed(&mut self, bytes: &'data [u8], hash: u64) -> NameId {
        if let Some(id) = self.lookup_prehashed(bytes, hash) {
            return id;
        }
        self.push_valid(NameStorage::Borrowed(bytes), hash)
    }

    pub(super) fn intern_owned_prehashed(&mut self, bytes: &[u8], hash: u64) -> NameId {
        if let Some(id) = self.lookup_prehashed(bytes, hash) {
            return id;
        }
        crate::perf::removal_counters::add_name_bytes_allocated(bytes.len() as u64);
        // One owned textual name allocation; borrowed object names do not increment this.
        if !bytes.is_empty() {
            crate::perf::removal_counters::increment_hot_phase_allocations();
        }
        self.push_valid(NameStorage::Owned(bytes.into()), hash)
    }

    pub(super) fn intern_invalid(&mut self, diagnostic: DeferredInvalidName) -> NameId {
        let id = self.push_unhashed(NameStorage::Invalid(diagnostic), 0);
        self.collision_next.push(NONE_U32);
        id
    }

    pub(super) fn invalid_diagnostic(&self, id: NameId) -> Option<DeferredInvalidName> {
        match self.names.get(id.index())? {
            NameStorage::Invalid(diagnostic) => Some(*diagnostic),
            NameStorage::Borrowed(_) | NameStorage::Owned(_) => None,
        }
    }

    fn push_valid(&mut self, name: NameStorage<'data>, hash: u64) -> NameId {
        let id = self.push_unhashed(name, hash);
        let previous = self.by_hash.get(&hash).copied();
        self.collision_next
            .push(previous.map_or(NONE_U32, NameId::get));
        if previous.is_none() && self.by_hash.len() == self.by_hash.capacity() {
            crate::perf::removal_counters::increment_hot_phase_allocations();
        }
        self.by_hash.insert(hash, id);
        id
    }

    fn push_unhashed(&mut self, name: NameStorage<'data>, hash: u64) -> NameId {
        let raw = u32::try_from(self.names.len()).expect("PE canonical name count exceeds u32");
        let id = NameId::from_u32(raw);
        note_vec_push(&self.names);
        self.names.push(name);
        note_vec_push(&self.hashes);
        self.hashes.push(hash);
        note_vec_push(&self.collision_next);
        id
    }
}

impl fmt::Debug for OrderedNameInterner<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OrderedNameInterner")
            .field("names", &self.names.len())
            .field("hash_heads", &self.by_hash.len())
            .finish()
    }
}

/// Result of the single ordered ID-assignment phase. Workstream 1 can parse in parallel, order its
/// local occurrences by input ordinal, and feed that flat sequence here without parallel ID races.
pub(super) struct OrderedNameFinalization<'data> {
    pub(super) names: OrderedNameInterner<'data>,
    pub(super) occurrence_names: Box<[NameId]>,
}

pub(super) fn finalize_ordered_names<'data>(
    occurrences: impl IntoIterator<Item = OrderedNameOccurrence<'data>>,
) -> OrderedNameFinalization<'data> {
    finalize_ordered_names_with(OrderedNameInterner::new(), occurrences)
}

pub(super) fn finalize_ordered_names_with<'data>(
    mut names: OrderedNameInterner<'data>,
    occurrences: impl IntoIterator<Item = OrderedNameOccurrence<'data>>,
) -> OrderedNameFinalization<'data> {
    let mut occurrence_names = Vec::new();
    for occurrence in occurrences {
        let name = match occurrence {
            OrderedNameOccurrence::Valid { bytes, hash } => {
                names.intern_borrowed_prehashed(bytes, hash)
            }
            OrderedNameOccurrence::Invalid(diagnostic) => names.intern_invalid(diagnostic),
        };
        note_vec_push(&occurrence_names);
        occurrence_names.push(name);
    }
    OrderedNameFinalization {
        names,
        occurrence_names: into_boxed_slice_counted(occurrence_names),
    }
}

/// One canonical entry per NameId. Provider rows are CSR ranges in stable provider encounter order.
#[derive(Debug)]
pub(super) struct SymbolDb {
    pub(super) entries: Box<[SymbolEntry]>,
    pub(super) providers: Box<[ProviderRecord]>,
    pub(super) absolute_values: Box<[u64]>,
}

impl SymbolDb {
    pub(super) fn entry(&self, name: NameId) -> Option<&SymbolEntry> {
        self.entries.get(name.index())
    }

    pub(super) fn provider(&self, provider: ProviderId) -> Option<&ProviderRecord> {
        self.providers.get(provider.index())
    }

    pub(super) fn providers_for(&self, name: NameId) -> Option<&[ProviderRecord]> {
        let entry = self.entry(name)?;
        let start = entry.provider_start as usize;
        let end = start.checked_add(entry.provider_len as usize)?;
        self.providers.get(start..end)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum SymbolDbBuildError {
    ProviderCountOverflow,
    NameOutOfRange(NameId),
}

#[derive(Clone, Copy, Debug)]
struct PendingProviderNode {
    record: ProviderRecord,
    next: u32,
}

/// Ordered builder boundary between the input indexer/archive resolver and all resolution users.
pub(super) struct SymbolDbBuilder<'data> {
    names: OrderedNameInterner<'data>,
    provider_nodes: Vec<PendingProviderNode>,
    provider_heads: Vec<u32>,
    provider_tails: Vec<u32>,
    provider_counts: Vec<u32>,
    weak_fallbacks: Vec<Option<NameId>>,
    absolute_values: Vec<u64>,
}

/// Completed canonical name table and its dense resolution database.
pub(super) struct FinalizedSymbolDb<'data> {
    pub(super) names: OrderedNameInterner<'data>,
    pub(super) symbols: SymbolDb,
}

impl<'data> SymbolDbBuilder<'data> {
    pub(super) fn new(names: OrderedNameInterner<'data>) -> Self {
        let count = names.len();
        // Each dense side table is one flat allocation, independent of the number of providers.
        for _ in 0..4 {
            note_nonempty_allocation(count);
        }
        Self {
            names,
            provider_nodes: Vec::new(),
            provider_heads: vec![NONE_U32; count],
            provider_tails: vec![NONE_U32; count],
            provider_counts: vec![0; count],
            weak_fallbacks: vec![None; count],
            absolute_values: Vec::new(),
        }
    }

    pub(super) fn names(&self) -> &OrderedNameInterner<'data> {
        &self.names
    }

    /// Append a borrowed occurrence discovered by a selected object/default-library wave. The
    /// caller serializes waves by archive/input order, so existing IDs and provider rows remain
    /// stable while the database grows.
    pub(super) fn intern_borrowed_prehashed(&mut self, bytes: &'data [u8], hash: u64) -> NameId {
        let id = self.names.intern_borrowed_prehashed(bytes, hash);
        self.extend_name_rows();
        id
    }

    /// Intern one textual directive name at ingress. This is the narrow owned-name path.
    pub(super) fn intern_owned_prehashed(&mut self, bytes: &[u8], hash: u64) -> NameId {
        let id = self.names.intern_owned_prehashed(bytes, hash);
        self.extend_name_rows();
        id
    }

    fn extend_name_rows(&mut self) {
        let count = self.names.len();
        for capacity in [
            self.provider_heads.capacity(),
            self.provider_tails.capacity(),
            self.provider_counts.capacity(),
            self.weak_fallbacks.capacity(),
        ] {
            if count > capacity {
                crate::perf::removal_counters::increment_hot_phase_allocations();
            }
        }
        self.provider_heads.resize(count, NONE_U32);
        self.provider_tails.resize(count, NONE_U32);
        self.provider_counts.resize(count, 0);
        self.weak_fallbacks.resize(self.names.len(), None);
    }

    pub(super) fn add_provider(
        &mut self,
        name: NameId,
        provider: ProviderRecord,
    ) -> Result<(), SymbolDbBuildError> {
        let head = self
            .provider_heads
            .get_mut(name.index())
            .ok_or(SymbolDbBuildError::NameOutOfRange(name))?;
        let new_count = self.provider_counts[name.index()]
            .checked_add(1)
            .ok_or(SymbolDbBuildError::ProviderCountOverflow)?;
        let index = u32::try_from(self.provider_nodes.len())
            .map_err(|_| SymbolDbBuildError::ProviderCountOverflow)?;
        note_vec_push(&self.provider_nodes);
        self.provider_nodes.push(PendingProviderNode {
            record: provider,
            next: NONE_U32,
        });
        let tail = &mut self.provider_tails[name.index()];
        if *head == NONE_U32 {
            *head = index;
        } else {
            self.provider_nodes[*tail as usize].next = index;
        }
        *tail = index;
        self.provider_counts[name.index()] = new_count;
        Ok(())
    }

    pub(super) fn set_weak_fallback(
        &mut self,
        name: NameId,
        fallback: NameId,
    ) -> Result<(), SymbolDbBuildError> {
        *self
            .weak_fallbacks
            .get_mut(name.index())
            .ok_or(SymbolDbBuildError::NameOutOfRange(name))? = Some(fallback);
        Ok(())
    }

    pub(super) fn add_absolute_value(&mut self, value: u64) -> u32 {
        let index =
            u32::try_from(self.absolute_values.len()).expect("PE absolute value count exceeds u32");
        note_vec_push(&self.absolute_values);
        self.absolute_values.push(value);
        index
    }

    pub(super) fn finish(self) -> Result<FinalizedSymbolDb<'data>, SymbolDbBuildError> {
        let mut phase = crate::pe_timing_guard!("PE symbols: Finalize dense symbol database");
        let provider_count = self.provider_nodes.len();
        phase
            .0
            .add(crate::timing::PeMetric::Names, self.provider_heads.len());
        phase
            .0
            .add(crate::timing::PeMetric::Lookups, provider_count);
        note_nonempty_allocation(provider_count);
        let mut providers = Vec::with_capacity(provider_count);
        note_nonempty_allocation(self.provider_heads.len());
        let mut entries = Vec::with_capacity(self.provider_heads.len());
        for name_index in 0..self.provider_heads.len() {
            let start = u32::try_from(providers.len())
                .map_err(|_| SymbolDbBuildError::ProviderCountOverflow)?;
            let len = self.provider_counts[name_index];
            let mut current = self.provider_heads[name_index];
            let mut offset = 0u32;
            let mut selected: Option<(u32, BindingStrength)> = None;
            while current != NONE_U32 {
                let node = self.provider_nodes[current as usize];
                // Strictly stronger replaces; equal strength retains the first provider.
                if selected
                    .is_none_or(|(_, strength)| node.record.strength.rank() > strength.rank())
                {
                    selected = Some((offset, node.record.strength));
                }
                providers.push(node.record);
                current = node.next;
                offset += 1;
            }
            debug_assert_eq!(offset, len);
            let resolution = selected.map_or(Resolution::UNRESOLVED, |(offset, strength)| {
                Resolution::resolved(ProviderId::from_u32(start + offset), strength)
            });
            entries.push(SymbolEntry {
                resolution,
                provider_start: start,
                provider_len: len,
                weak_fallback: self.weak_fallbacks[name_index]
                    .map_or(SymbolEntry::NO_FALLBACK, NameId::get),
            });
        }
        phase.0.add(crate::timing::PeMetric::Events, entries.len());
        Ok(FinalizedSymbolDb {
            names: self.names,
            symbols: SymbolDb {
                entries: into_boxed_slice_counted(entries),
                providers: into_boxed_slice_counted(providers),
                absolute_values: into_boxed_slice_counted(self.absolute_values),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn occurrence(bytes: &'static [u8], hash: u64) -> OrderedNameOccurrence<'static> {
        OrderedNameOccurrence::valid(bytes, hash)
    }

    #[test]
    fn ordered_interner_is_collision_safe_and_schedule_independent() {
        let input = [
            occurrence(b"zeta", 7),
            occurrence(b"alpha", 7),
            occurrence(b"zeta", 7),
            occurrence(b"beta", 11),
        ];
        let first = finalize_ordered_names(input);
        let second = finalize_ordered_names(input);
        assert_eq!(first.occurrence_names, second.occurrence_names);
        assert_eq!(
            first.occurrence_names.as_ref(),
            [
                NameId::from_u32(0),
                NameId::from_u32(1),
                NameId::from_u32(0),
                NameId::from_u32(2),
            ]
        );
        assert_eq!(
            first.names.bytes(NameId::from_u32(1)),
            Some(b"alpha".as_slice())
        );
    }

    #[test]
    fn invalid_occurrences_never_alias_valid_empty_names() {
        let empty_hash = crate::hash::hash_bytes(b"");
        let finalized = finalize_ordered_names([
            OrderedNameOccurrence::valid(b"", empty_hash),
            OrderedNameOccurrence::invalid(DeferredInvalidName::CoffNameOffset),
            OrderedNameOccurrence::invalid(DeferredInvalidName::CoffNameOffset),
        ]);
        assert_eq!(
            finalized.occurrence_names.as_ref(),
            [
                NameId::from_u32(0),
                NameId::from_u32(1),
                NameId::from_u32(2),
            ]
        );
        assert_eq!(finalized.names.bytes(NameId::from_u32(0)), Some(&[][..]));
        assert_eq!(finalized.names.bytes(NameId::from_u32(1)), None);
        assert_eq!(
            finalized.names.invalid_diagnostic(NameId::from_u32(1)),
            Some(DeferredInvalidName::CoffNameOffset)
        );
    }

    #[test]
    fn seeded_finalization_preserves_existing_ids() {
        let root_hash = crate::hash::hash_bytes(b"root");
        let object_hash = crate::hash::hash_bytes(b"object");
        let mut seed = OrderedNameInterner::new();
        let root = seed.intern_borrowed_prehashed(b"root", root_hash);
        let finalized = finalize_ordered_names_with(
            seed,
            [
                OrderedNameOccurrence::valid(b"object", object_hash),
                OrderedNameOccurrence::valid(b"root", root_hash),
            ],
        );
        assert_eq!(root, NameId::from_u32(0));
        assert_eq!(
            finalized.occurrence_names.as_ref(),
            [NameId::from_u32(1), root]
        );
        assert_eq!(
            finalized.names.lookup_prehashed(b"root", root_hash),
            Some(root)
        );
    }

    #[test]
    fn interner_handles_many_unique_names_and_one_large_collision_chain() {
        let unique_bytes = (0..2048)
            .map(|index| format!("unique-{index}").into_bytes())
            .collect::<Vec<_>>();
        let unique = finalize_ordered_names(
            unique_bytes
                .iter()
                .enumerate()
                .map(|(index, bytes)| OrderedNameOccurrence::valid(bytes, index as u64)),
        );
        assert_eq!(unique.names.len(), 2048);
        assert_eq!(unique.names.by_hash.len(), 2048);
        assert_eq!(unique.names.collision_next.len(), 2048);

        let collision_bytes = (0..1024)
            .map(|index| format!("collision-{index}").into_bytes())
            .collect::<Vec<_>>();
        let collision = finalize_ordered_names(
            collision_bytes
                .iter()
                .map(|bytes| OrderedNameOccurrence::valid(bytes, 0xdead_beef)),
        );
        assert_eq!(collision.names.by_hash.len(), 1);
        for (index, bytes) in collision_bytes.iter().enumerate() {
            assert_eq!(
                collision.names.lookup_prehashed(bytes, 0xdead_beef),
                Some(NameId::from_u32(index as u32))
            );
        }
    }

    #[test]
    fn provider_csr_preserves_order_and_first_equal_strength_wins() {
        let finalized = finalize_ordered_names([occurrence(b"target", 1)]);
        let name = finalized.occurrence_names[0];
        let weak = ProviderRecord::object(
            ObjectId::from_u32(0),
            SymbolId::from_u32(0),
            BindingStrength::Weak,
        );
        let first_strong = ProviderRecord::object(
            ObjectId::from_u32(1),
            SymbolId::from_u32(1),
            BindingStrength::Strong,
        );
        let second_strong = ProviderRecord::object(
            ObjectId::from_u32(2),
            SymbolId::from_u32(2),
            BindingStrength::Strong,
        );
        let mut builder = SymbolDbBuilder::new(finalized.names);
        for provider in [weak, first_strong, second_strong] {
            builder.add_provider(name, provider).unwrap();
        }
        let database = builder.finish().unwrap();
        assert_eq!(
            database.symbols.providers_for(name),
            Some(&[weak, first_strong, second_strong][..])
        );
        assert_eq!(
            database.symbols.entry(name).unwrap().resolution.provider(),
            Some(ProviderId::from_u32(1))
        );
    }

    #[test]
    fn appended_archive_wave_extends_names_without_renumbering() {
        let finalized = finalize_ordered_names([occurrence(b"root", 1)]);
        let root = finalized.occurrence_names[0];
        let mut builder = SymbolDbBuilder::new(finalized.names);
        let appended = builder.intern_borrowed_prehashed(b"defaultlib", 2);
        let duplicate = builder.intern_borrowed_prehashed(b"root", 1);
        assert_eq!(root, NameId::from_u32(0));
        assert_eq!(appended, NameId::from_u32(1));
        assert_eq!(duplicate, root);
        builder
            .add_provider(
                appended,
                ProviderRecord::archive(
                    ArchiveId::from_u32(3),
                    ArchiveMemberId::from_u32(4),
                    BindingStrength::Strong,
                ),
            )
            .unwrap();
        let database = builder.finish().unwrap();
        assert_eq!(database.symbols.providers_for(root), Some(&[][..]));
        assert_eq!(database.symbols.providers_for(appended).unwrap().len(), 1);
    }

    #[test]
    fn many_provider_rows_use_one_flat_node_arena_and_preserve_order() {
        const NAME_COUNT: usize = 256;
        const PROVIDERS_PER_NAME: usize = 8;
        let names = (0..NAME_COUNT)
            .map(|index| format!("name-{index}").into_bytes())
            .collect::<Vec<_>>();
        let finalized = finalize_ordered_names(
            names
                .iter()
                .enumerate()
                .map(|(index, bytes)| OrderedNameOccurrence::valid(bytes, index as u64)),
        );
        let mut builder = SymbolDbBuilder::new(finalized.names);
        for name in 0..NAME_COUNT {
            for provider in 0..PROVIDERS_PER_NAME {
                builder
                    .add_provider(
                        NameId::from_u32(name as u32),
                        ProviderRecord::object(
                            ObjectId::from_u32(provider as u32),
                            SymbolId::from_u32(provider as u32),
                            BindingStrength::Strong,
                        ),
                    )
                    .unwrap();
            }
        }
        assert_eq!(
            builder.provider_nodes.len(),
            NAME_COUNT * PROVIDERS_PER_NAME
        );
        assert_eq!(std::mem::size_of::<PendingProviderNode>(), 16);
        let database = builder.finish().unwrap();
        for name in 0..NAME_COUNT {
            let id = NameId::from_u32(name as u32);
            let providers = database.symbols.providers_for(id).unwrap();
            assert_eq!(providers.len(), PROVIDERS_PER_NAME);
            assert_eq!(providers[0].owner, 0);
            assert_eq!(providers[PROVIDERS_PER_NAME - 1].owner, 7);
            assert_eq!(
                database.symbols.entry(id).unwrap().resolution.provider(),
                Some(ProviderId::from_u32((name * PROVIDERS_PER_NAME) as u32))
            );
        }
    }

    #[test]
    fn provider_and_resolution_records_remain_packed() {
        assert_eq!(std::mem::size_of::<ProviderRecord>(), 12);
        assert_eq!(std::mem::size_of::<Resolution>(), 8);
        assert_eq!(Resolution::UNRESOLVED.provider(), None);
    }
}
