//! COFF archive extraction used by the PE writer.

#[cfg(test)]
use crate::ensure;
use crate::error;
use crate::error::Context;
use crate::error::Result;
use foldhash::HashMap;
use foldhash::HashMapExt;
use foldhash::HashSet;
use foldhash::HashSetExt;
use linker_utils::coff_archives::CoffArchive;
use linker_utils::coff_archives::CoffArchiveDefinitionId;
use linker_utils::coff_archives::CoffArchiveMember;
use linker_utils::coff_archives::CoffArchiveMemberKind;
use linker_utils::coff_imports::ShortImportObject;
use linker_utils::coff_runtime::RuntimeResolution;
use linker_utils::coff_runtime::WeakExternalResolution;
use linker_utils::coff_runtime::parse_legacy_alias_object;
#[cfg(test)]
use linker_utils::coff_symbols::ArchiveDemand;
#[cfg(test)]
use linker_utils::coff_symbols::ArchiveDemandKind;
#[cfg(test)]
use object::Object;
#[cfg(test)]
use object::ObjectSymbol;
use rayon::prelude::*;
use smallvec::SmallVec;
#[cfg(test)]
use std::collections::BTreeSet;
use std::sync::OnceLock;

use super::pe_ir::NameId;
use super::pe_ir::{ArchiveId, ArchiveMemberId};
use super::pe_symbol_db::{BindingStrength, OrderedNameInterner};

#[cfg(test)]
type SymbolState = (HashSet<Vec<u8>>, BTreeSet<Vec<u8>>);

/// Compatibility deletion sites after Workstream 1 publishes `PeIr` occurrences:
///
/// - the test-only `SelectedGlobalSymbol` snapshot (legacy COMDAT/layout metadata),
/// - `WeakExternalResolution` raw-name records (replace with the SymbolDb fallback column), and
/// - import-definition compatibility state once all downstream consumers use the SymbolDb.
///
/// None of these bridges participates in archive provider lookup or canonical ID assignment.
const COMPATIBILITY_DELETION_SITES: &[&str] = &[
    "SelectedGlobalSymbol fixed metadata snapshot",
    "WeakExternalResolution raw-name records",
    "import-definition compatibility state",
];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub(super) struct ResolverNameState(u8);

impl ResolverNameState {
    const DEFINED: u8 = 1 << 0;
    const UNRESOLVED: u8 = 1 << 1;
    const DEMANDED: u8 = 1 << 2;

    pub(super) const fn is_defined(self) -> bool {
        self.0 & Self::DEFINED != 0
    }

    pub(super) const fn is_unresolved(self) -> bool {
        self.0 & Self::UNRESOLVED != 0
    }

    /// True once an input/root requested this name, even if archive extraction later defined it.
    pub(super) const fn is_demanded(self) -> bool {
        self.0 & Self::DEMANDED != 0
    }

    fn mark_demanded(&mut self) {
        self.0 |= Self::DEMANDED;
    }

    /// Returns true when this name enters the active unresolved set.
    fn mark_unresolved(&mut self) -> bool {
        self.mark_demanded();
        if self.is_defined() {
            return false;
        }
        let newly_unresolved = !self.is_unresolved();
        self.0 |= Self::UNRESOLVED;
        newly_unresolved
    }

    fn mark_defined(&mut self) -> bool {
        let changed = !self.is_defined();
        self.0 = (self.0 | Self::DEFINED) & !Self::UNRESOLVED;
        changed
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ResolverWeakFallback {
    pub(super) symbol: NameId,
    pub(super) target: NameId,
    pub(super) search: linker_utils::coff_symbols::WeakSearch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ResolverAlternateFallback {
    pub(super) symbol: NameId,
    pub(super) target: NameId,
}

/// Provider coordinates in resolver encounter order. Workstream 1 maps raw object-symbol indices
/// to its dense SymbolIds while retaining this canonical NameId namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ResolverProviderOccurrence {
    Object {
        name: NameId,
        global_symbol: u32,
        strength: BindingStrength,
    },
    Import {
        name: NameId,
        selected_import: u32,
        archive: ArchiveId,
        member: ArchiveMemberId,
    },
    Absolute {
        name: NameId,
        value: u64,
        linker_defined: bool,
    },
}

#[allow(dead_code)]
impl ResolverProviderOccurrence {
    pub(super) const fn name(self) -> NameId {
        match self {
            Self::Object { name, .. } | Self::Import { name, .. } | Self::Absolute { name, .. } => {
                name
            }
        }
    }
}

#[allow(dead_code)]
pub(super) struct ResolverSeed<'data> {
    pub(super) names: OrderedNameInterner<'data>,
    pub(super) states: Box<[ResolverNameState]>,
    pub(super) weak_fallbacks: Box<[ResolverWeakFallback]>,
    pub(super) alternate_fallbacks: Box<[ResolverAlternateFallback]>,
    pub(super) providers: Box<[ResolverProviderOccurrence]>,
}

#[allow(dead_code)]
pub(super) struct ResolverSeedParts<'data> {
    pub(super) names: OrderedNameInterner<'data>,
    pub(super) states: Box<[ResolverNameState]>,
    pub(super) weak_fallbacks: Box<[ResolverWeakFallback]>,
    pub(super) alternate_fallbacks: Box<[ResolverAlternateFallback]>,
    pub(super) providers: Box<[ResolverProviderOccurrence]>,
}

#[allow(dead_code)]
impl<'data> ResolverSeed<'data> {
    pub(super) fn state(&self, name: NameId) -> Option<ResolverNameState> {
        self.states.get(name.index()).copied()
    }

    pub(super) fn into_parts(self) -> ResolverSeedParts<'data> {
        ResolverSeedParts {
            names: self.names,
            states: self.states,
            weak_fallbacks: self.weak_fallbacks,
            alternate_fallbacks: self.alternate_fallbacks,
            providers: self.providers,
        }
    }
}

struct IncrementalSymbolState<'data> {
    names: OrderedNameInterner<'data>,
    states: Vec<ResolverNameState>,
    /// Active unresolved names in dense insertion order, with an O(1) removal index by NameId.
    /// Deterministic archive consumers sort their comparatively infrequent snapshots by bytes;
    /// definitions must not shift the active set once for every resolved symbol.
    unresolved_names: Vec<NameId>,
    unresolved_positions: Vec<u32>,
    weak_resolution: WeakExternalResolution,
    weak_names: Vec<ResolverWeakFallback>,
    alternate_names: Vec<ResolverAlternateFallback>,
    providers: Vec<ResolverProviderOccurrence>,
    global_names: Vec<ResolverGlobalName>,
    archive_demand_events: Vec<ArchiveDemandEvent>,
    #[cfg(test)]
    globals: Vec<SelectedGlobalSymbol>,
    absorbed_objects: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArchiveDemandEvent {
    Unresolved(NameId),
    LibraryWeak { name: NameId, order: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ResolverGlobalName {
    pub(super) object: u32,
    pub(super) name_occurrence: u32,
    pub(super) name: NameId,
}

#[cfg(test)]
#[derive(Debug)]
pub(super) struct SelectedGlobalSymbol {
    pub(super) object: usize,
    #[allow(dead_code)]
    pub(super) index: object::SymbolIndex,
    pub(super) section: Option<object::SectionIndex>,
    pub(super) section_kind: object::SymbolSection,
    pub(super) address: u64,
    pub(super) size: u64,
    pub(super) is_definition: bool,
    pub(super) is_common: bool,
    pub(super) is_undefined: bool,
    pub(super) is_weak: bool,
    #[cfg(test)]
    pub(super) name: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct SelectedSymbolSnapshot {
    pub(super) global_names: Vec<ResolverGlobalName>,
    #[cfg(test)]
    pub(super) globals: Vec<SelectedGlobalSymbol>,
    pub(super) weak_resolution: WeakExternalResolution,
}

pub(super) struct ResolverOutput<'data> {
    #[allow(dead_code)]
    pub(super) seed: ResolverSeed<'data>,
    pub(super) selected_imports: Vec<ShortImportObject<'data>>,
    pub(super) symbols: SelectedSymbolSnapshot,
    #[cfg(test)]
    pub(super) object_scans: usize,
}

fn hash_name(name: &[u8]) -> u64 {
    crate::perf::removal_counters::increment_name_hash_ops();
    crate::hash::hash_bytes(name)
}

fn note_vec_push<T>(values: &Vec<T>) {
    if values.len() == values.capacity() {
        crate::perf::removal_counters::increment_hot_phase_allocations();
    }
}

impl<'data> IncrementalSymbolState<'data> {
    fn new() -> Self {
        Self {
            names: OrderedNameInterner::new(),
            states: Vec::new(),
            unresolved_names: Vec::new(),
            unresolved_positions: Vec::new(),
            weak_resolution: WeakExternalResolution::default(),
            weak_names: Vec::new(),
            alternate_names: Vec::new(),
            providers: Vec::new(),
            global_names: Vec::new(),
            archive_demand_events: Vec::new(),
            #[cfg(test)]
            globals: Vec::new(),
            absorbed_objects: 0,
        }
    }

    fn add_roots(&mut self, roots: &[Vec<u8>]) {
        for root in roots {
            let id = self.intern_owned(root);
            self.mark_unresolved(id);
        }
    }

    fn absorb_object(
        &mut self,
        object: &crate::coff::CoffObject<'data>,
        index: usize,
    ) -> Result<()> {
        self.absorbed_objects += 1;
        let summary = object.resolver_summary()?;
        for &record in summary.weak_externals() {
            let symbol_bytes = record.symbol(object.bytes());
            let target_bytes = record.target(object.bytes());
            let symbol = self.intern_borrowed_prehashed(symbol_bytes, record.symbol_hash);
            let target = self.intern_borrowed_prehashed(target_bytes, record.target_hash);
            // The legacy import bridge considered every selected weak record. Retain that demand
            // bit without promoting it into an ordinary archive demand (search policy still owns
            // extraction behavior below).
            self.states[symbol.index()].mark_demanded();
            let existing = self
                .weak_names
                .iter()
                .position(|fallback| fallback.symbol == symbol);
            let was_library = existing.is_some_and(|position| {
                self.weak_names[position].search == linker_utils::coff_symbols::WeakSearch::Library
            });
            self.weak_resolution.apply(
                linker_utils::coff_runtime::WeakExternalRecord {
                    symbol: symbol_bytes,
                    target: target_bytes,
                    search: record.search,
                },
                &format!("selected COFF object #{index}"),
            )?;
            let fallback = ResolverWeakFallback {
                symbol,
                target,
                search: record.search,
            };
            if let Some(position) = existing {
                let old = self.weak_names[position];
                // Match WeakExternalResolution: a real fallback replaces an earlier incoming
                // anti-dependency; all other accepted duplicates retain the first record.
                if old.search == linker_utils::coff_symbols::WeakSearch::AntiDependency
                    && record.search != linker_utils::coff_symbols::WeakSearch::AntiDependency
                {
                    self.weak_names[position] = fallback;
                }
            } else {
                note_vec_push(&self.weak_names);
                self.weak_names.push(fallback);
            }
            let library_order = self.weak_names.iter().position(|fallback| {
                fallback.symbol == symbol
                    && fallback.search == linker_utils::coff_symbols::WeakSearch::Library
            });
            if let Some(order) = library_order.filter(|_| !was_library) {
                note_vec_push(&self.archive_demand_events);
                self.archive_demand_events
                    .push(ArchiveDemandEvent::LibraryWeak {
                        name: symbol,
                        order: u32::try_from(order)
                            .context("PE weak archive demand count exceeds u32")?,
                    });
            }
        }
        let object_id = u32::try_from(index).context("PE object index exceeds u32")?;
        for symbol in summary.globals() {
            let global_symbol = u32::try_from(self.global_names.len())
                .context("PE global symbol count exceeds u32")?;
            let name_occurrence = symbol.name();
            let source = name_occurrence
                .source()
                .context("invalid COFF symbol name")?;
            let name =
                &object.bytes()[source.start as usize..source.start as usize + source.len as usize];
            let name_id = self.intern_borrowed_prehashed(
                name,
                name_occurrence
                    .hash()
                    .expect("valid resolver summary names are prehashed"),
            );
            note_vec_push(&self.global_names);
            self.global_names.push(ResolverGlobalName {
                object: object_id,
                name_occurrence: symbol.symbol_occurrence,
                name: name_id,
            });
            #[cfg(test)]
            {
                note_vec_push(&self.globals);
                self.globals.push(SelectedGlobalSymbol {
                    object: index,
                    index: object::SymbolIndex(symbol.raw_index as usize),
                    section: symbol.section(),
                    section_kind: symbol.section_kind(),
                    address: u64::from(symbol.address),
                    size: u64::from(symbol.size),
                    is_definition: symbol.is_definition(),
                    is_common: symbol.is_common(),
                    is_undefined: symbol.is_undefined(),
                    is_weak: symbol.is_weak(),
                    #[cfg(test)]
                    name: name.to_vec(),
                });
            }
            if name.is_empty() {
                continue;
            }
            if symbol.is_undefined() && !symbol.is_common() && !symbol.is_weak() {
                self.mark_unresolved(name_id);
            } else if symbol.is_definition() || symbol.is_common() {
                let strength = if symbol.is_common() {
                    BindingStrength::Common
                } else if symbol.is_weak() {
                    BindingStrength::Weak
                } else {
                    BindingStrength::Strong
                };
                note_vec_push(&self.providers);
                self.providers.push(ResolverProviderOccurrence::Object {
                    name: name_id,
                    global_symbol,
                    strength,
                });
                self.define_id(name_id);
            }
        }
        Ok(())
    }

    fn intern_borrowed_prehashed(&mut self, name: &'data [u8], hash: u64) -> NameId {
        let id = self.names.intern_borrowed_prehashed(name, hash);
        self.ensure_state(id);
        id
    }

    fn intern_owned(&mut self, name: &[u8]) -> NameId {
        let id = self.names.intern_owned_prehashed(name, hash_name(name));
        self.ensure_state(id);
        id
    }

    fn ensure_state(&mut self, id: NameId) {
        if self.states.len() <= id.index() {
            if id.index() + 1 > self.states.capacity() {
                crate::perf::removal_counters::increment_hot_phase_allocations();
            }
            self.states
                .resize(id.index() + 1, ResolverNameState::default());
            self.unresolved_positions.resize(id.index() + 1, u32::MAX);
        }
    }

    fn define_id(&mut self, id: NameId) -> bool {
        let was_unresolved = self.states[id.index()].is_unresolved();
        let changed = self.states[id.index()].mark_defined();
        if was_unresolved {
            let position = std::mem::replace(&mut self.unresolved_positions[id.index()], u32::MAX);
            let position = position as usize;
            debug_assert!(position < self.unresolved_names.len());
            self.unresolved_names.swap_remove(position);
            if let Some(&moved) = self.unresolved_names.get(position) {
                self.unresolved_positions[moved.index()] = position as u32;
            }
        }
        changed
    }

    fn mark_unresolved(&mut self, id: NameId) {
        if self.states[id.index()].mark_unresolved() {
            note_vec_push(&self.unresolved_names);
            self.unresolved_positions[id.index()] = self.unresolved_names.len() as u32;
            self.unresolved_names.push(id);
            note_vec_push(&self.archive_demand_events);
            self.archive_demand_events
                .push(ArchiveDemandEvent::Unresolved(id));
        }
    }

    fn define_owned_with_id(&mut self, name: &[u8]) -> (NameId, bool) {
        let id = self.intern_owned(name);
        (id, self.define_id(id))
    }

    fn sync_alternates(&mut self, runtime: &RuntimeResolution) {
        self.alternate_names.clear();
        for (symbol, target) in runtime.alternate_names() {
            let symbol = self.intern_owned(symbol.as_bytes());
            let target = self.intern_owned(target.as_bytes());
            note_vec_push(&self.alternate_names);
            self.alternate_names
                .push(ResolverAlternateFallback { symbol, target });
        }
    }

    fn is_defined(&self, id: NameId) -> bool {
        self.states
            .get(id.index())
            .is_some_and(|state| state.is_defined())
    }

    fn unresolved_in_byte_order(&self) -> Vec<NameId> {
        let mut unresolved = self.unresolved_names.clone();
        unresolved.sort_unstable_by(|&left, &right| {
            self.names
                .bytes(left)
                .expect("unresolved NameId is interned")
                .cmp(
                    self.names
                        .bytes(right)
                        .expect("unresolved NameId is interned"),
                )
        });
        unresolved
    }
}

/// Incremental archive extraction state retained while default libraries are discovered.
struct LazyArchive<'data> {
    bytes: &'data [u8],
    indexed: bool,
    parsed: OnceLock<linker_utils::coff_archives::Result<CoffArchive<'data>>>,
}

impl<'data> LazyArchive<'data> {
    fn new(bytes: &'data [u8]) -> Result<Self> {
        let probe_phase = crate::timing_guard!(super::PE_DETAIL_PROBE_ARCHIVE_INDICES);
        let indexed = CoffArchive::has_symbol_index(bytes).context("invalid AMD64 COFF archive")?;
        drop(probe_phase);
        Ok(Self {
            bytes,
            indexed,
            parsed: OnceLock::new(),
        })
    }

    fn parsed(&self) -> &linker_utils::coff_archives::Result<CoffArchive<'data>> {
        self.parsed.get_or_init(|| CoffArchive::parse(self.bytes))
    }
}

fn prepare_archives(archives: &[LazyArchive<'_>]) {
    crate::timing_phase!("PE detail: Prepare archive indices");
    if rayon::current_num_threads() == 1 {
        for archive in archives {
            let _ = archive.parsed();
        }
    } else {
        archives
            .par_iter()
            .filter(|archive| archive.indexed)
            .for_each(|archive| {
                let _ = archive.parsed();
            });
        // Indexless archives require eager member parsing to discover their definitions. Keep
        // that fallback serial rather than spending cores on members that will not be selected.
        for archive in archives.iter().filter(|archive| !archive.indexed) {
            let _ = archive.parsed();
        }
    }
}

fn parsed_archives<'session, 'data>(
    archives: &'session [LazyArchive<'data>],
) -> Result<Vec<&'session CoffArchive<'data>>> {
    prepare_archives(archives);
    archives
        .iter()
        .map(|archive| match archive.parsed() {
            Ok(archive) => Ok(archive),
            Err(parse_error) => Err(error!("{parse_error}")).context("invalid AMD64 COFF archive"),
        })
        .collect()
}

/// Parse and summarize regular archive members with archive-wide parallelism before the ordered
/// extraction loop starts. Selection remains lazy and deterministic: failures are retained in
/// their member slot and are reported only if that member is actually selected. The cache grows
/// incrementally when a later default-library wave appends archives.
#[inline(never)]
fn prepare_archive_objects<'data>(
    archives: &[&CoffArchive<'data>],
    prepared: &mut Vec<Vec<Option<Result<crate::coff::CoffObject<'data>>>>>,
) {
    let first = prepared.len();
    if first == archives.len() {
        return;
    }
    let mut phase = crate::pe_timing_guard!("PE archive: Precompute resolver summaries");
    phase
        .0
        .add(crate::timing::PeMetric::Archives, archives.len() - first);
    let chunks = archives[first..]
        .par_iter()
        .map(|archive| {
            archive
                .members()
                .par_iter()
                .map(|member| match member.kind() {
                    CoffArchiveMemberKind::CoffObject { .. } => Some(
                        crate::coff::CoffObject::parse(member.data()).and_then(|object| {
                            object.resolver_summary()?;
                            Ok(object)
                        }),
                    ),
                    CoffArchiveMemberKind::ShortImport(_) | CoffArchiveMemberKind::Opaque => None,
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    if phase.0.enabled() {
        phase.0.add(
            crate::timing::PeMetric::Objects,
            chunks
                .iter()
                .map(|members| members.iter().filter(|member| member.is_some()).count())
                .sum(),
        );
    }
    prepared.extend(chunks);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArchiveProvider {
    archive: ArchiveId,
    definition: CoffArchiveDefinitionId,
}

#[derive(Default)]
struct CachedArchiveProviders {
    archives_scanned: usize,
    providers: SmallVec<[ArchiveProvider; 1]>,
}

struct ArchiveProviderCache {
    // Preserve direct indexing for the common low-ID region without letting one sparse high ID
    // resize and later scan a Vec across the entire global symbol namespace.
    by_name: Vec<Option<CachedArchiveProviders>>,
    high_names: HashMap<NameId, CachedArchiveProviders>,
    by_hash_shards: Vec<HashMap<u64, SmallVec<[ArchiveProvider; 1]>>>,
    indexed_archives: usize,
}

const DENSE_ARCHIVE_NAME_CACHE_LIMIT: usize = 1 << 15;

impl ArchiveProviderCache {
    fn new() -> Self {
        Self {
            by_name: Vec::new(),
            high_names: HashMap::new(),
            by_hash_shards: Vec::new(),
            indexed_archives: 0,
        }
    }

    fn extend_index<'data>(&mut self, archives: &[&CoffArchive<'data>]) {
        if self.indexed_archives == archives.len() {
            return;
        }
        let first_archive = self.indexed_archives;
        let chunks = archives[first_archive..]
            .par_iter()
            .enumerate()
            .map(|(offset, archive)| {
                let archive_index = first_archive + offset;
                archive
                    .definition_rows()
                    .map(|(definition, _name, _member_index, hash)| {
                        (
                            hash,
                            ArchiveProvider {
                                archive: ArchiveId::from_u32(
                                    u32::try_from(archive_index)
                                        .expect("PE archive count exceeds u32"),
                                ),
                                definition,
                            },
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        if self.by_hash_shards.is_empty() {
            let shard_count = rayon::current_num_threads().next_power_of_two();
            self.by_hash_shards = (0..shard_count).map(|_| HashMap::new()).collect();
        }
        let shard_mask = self.by_hash_shards.len() - 1;
        let row_count = chunks.iter().map(Vec::len).sum::<usize>();
        let mut partitions = (0..self.by_hash_shards.len())
            .map(|_| Vec::with_capacity(row_count / self.by_hash_shards.len() + 1))
            .collect::<Vec<_>>();
        for chunk in chunks {
            for (hash, provider) in chunk {
                partitions[hash as usize & shard_mask].push((hash, provider));
            }
        }
        self.by_hash_shards
            .par_iter_mut()
            .zip(partitions.into_par_iter())
            .for_each(|(shard, rows)| {
                for (hash, provider) in rows {
                    shard.entry(hash).or_default().push(provider);
                }
            });
        self.indexed_archives = archives.len();
    }

    fn providers<'cache, 'data>(
        &'cache mut self,
        name_id: NameId,
        name: &[u8],
        archives: &[&CoffArchive<'data>],
    ) -> &'cache [ArchiveProvider] {
        self.extend_index(archives);
        let cached = if name_id.index() < DENSE_ARCHIVE_NAME_CACHE_LIMIT {
            if self.by_name.len() <= name_id.index() {
                if name_id.index() + 1 > self.by_name.capacity() {
                    crate::perf::removal_counters::increment_hot_phase_allocations();
                }
                self.by_name.resize_with(name_id.index() + 1, || None);
            }
            self.by_name[name_id.index()].get_or_insert_with(CachedArchiveProviders::default)
        } else {
            if !self.high_names.contains_key(&name_id)
                && self.high_names.len() == self.high_names.capacity()
            {
                crate::perf::removal_counters::increment_hot_phase_allocations();
            }
            self.high_names.entry(name_id).or_default()
        };
        if cached.archives_scanned == archives.len() {
            return &cached.providers;
        }
        if self.by_hash_shards.is_empty() {
            cached.archives_scanned = archives.len();
            return &cached.providers;
        }
        let hash = crate::hash::hash_bytes(name);
        let shard = &self.by_hash_shards[hash as usize & (self.by_hash_shards.len() - 1)];
        if let Some(candidates) = shard.get(&hash) {
            for &provider in candidates {
                let archive_index = provider.archive.index();
                if archive_index < cached.archives_scanned {
                    continue;
                }
                // Hash rows are collision candidates, not an equality claim. Verify through the
                // authoritative archive index before exposing the provider.
                crate::perf::removal_counters::increment_archive_member_probes();
                if archives[archive_index].definition_name(provider.definition) == Some(name) {
                    if cached.providers.len() == cached.providers.capacity() {
                        crate::perf::removal_counters::increment_hot_phase_allocations();
                    }
                    cached.providers.push(provider);
                }
            }
        }
        cached.archives_scanned = archives.len();
        &cached.providers
    }
}

pub(super) struct ResolverSession<'data> {
    archives: Vec<LazyArchive<'data>>,
    prepared_archive_objects: Vec<Vec<Option<Result<crate::coff::CoffObject<'data>>>>>,
    whole_archive: Vec<bool>,
    extracted: HashSet<(usize, usize)>,
    import_definitions: HashSet<NameId>,
    selected_imports: Vec<ShortImportObject<'data>>,
    symbol_state: IncrementalSymbolState<'data>,
    scanned_objects: usize,
    selected_aliases: Vec<(usize, usize)>,
    archive_providers: ArchiveProviderCache,
}

impl<'data> ResolverSession<'data> {
    pub(super) fn new() -> Self {
        Self {
            archives: Vec::new(),
            prepared_archive_objects: Vec::new(),
            whole_archive: Vec::new(),
            extracted: HashSet::new(),
            import_definitions: HashSet::new(),
            selected_imports: Vec::new(),
            symbol_state: IncrementalSymbolState::new(),
            scanned_objects: 0,
            selected_aliases: Vec::new(),
            archive_providers: ArchiveProviderCache::new(),
        }
    }

    pub(super) fn add_archive(&mut self, bytes: &'data [u8], whole_archive: bool) -> Result<()> {
        self.archives.push(LazyArchive::new(bytes)?);
        self.whole_archive.push(whole_archive);
        Ok(())
    }

    /// Returns whether a regular archive member can define `name`.
    ///
    /// PE linkers implicitly retain the CRT's `_load_config_used` object when
    /// it is available, even though ordinary application code does not refer
    /// to that symbol. The caller uses this query to add that conditional root
    /// without turning an absent optional symbol into an unresolved external.
    pub(super) fn has_archive_definition(&self, name: &[u8]) -> bool {
        prepare_archives(&self.archives);
        self.archives
            .iter()
            .filter_map(|archive| archive.parsed().as_ref().ok())
            .any(|archive| archive.has_object_definition(name))
    }

    pub(super) fn define_linker_symbol(&mut self, name: &[u8]) {
        let (name, _) = self.symbol_state.define_owned_with_id(name);
        note_vec_push(&self.symbol_state.providers);
        self.symbol_state
            .providers
            .push(ResolverProviderOccurrence::Absolute {
                name,
                value: 0,
                linker_defined: true,
            });
    }

    #[cfg(test)]
    pub(super) fn selected_imports(&self) -> &[ShortImportObject<'data>] {
        &self.selected_imports
    }

    pub(super) fn finish(self) -> ResolverOutput<'data> {
        let _ = COMPATIBILITY_DELETION_SITES;
        let IncrementalSymbolState {
            names,
            states,
            unresolved_names: _,
            unresolved_positions: _,
            weak_resolution,
            weak_names,
            alternate_names,
            providers,
            global_names,
            archive_demand_events: _,
            #[cfg(test)]
            globals,
            absorbed_objects: _object_scans,
        } = self.symbol_state;
        ResolverOutput {
            seed: ResolverSeed {
                names,
                states: states.into_boxed_slice(),
                weak_fallbacks: weak_names.into_boxed_slice(),
                alternate_fallbacks: alternate_names.into_boxed_slice(),
                providers: providers.into_boxed_slice(),
            },
            selected_imports: self.selected_imports,
            symbols: SelectedSymbolSnapshot {
                global_names,
                #[cfg(test)]
                globals,
                weak_resolution,
            },
            #[cfg(test)]
            object_scans: _object_scans,
        }
    }

    pub(super) fn resolve(
        &mut self,
        objects: &mut Vec<crate::coff::CoffObject<'data>>,
        roots: &[Vec<u8>],
        runtime_resolution: &mut RuntimeResolution,
    ) -> Result<()> {
        let mut resolve_phase = crate::pe_timing_guard!(super::PE_PHASE_RESOLVE_ARCHIVES);
        resolve_phase
            .0
            .add(crate::timing::PeMetric::Archives, self.archives.len());
        resolve_phase
            .0
            .add(crate::timing::PeMetric::Objects, objects.len());
        resolve_phase
            .0
            .add(crate::timing::PeMetric::Names, roots.len());
        let archives = parsed_archives(&self.archives)?;
        // Full-set speculation pays only when many independent libraries provide enough parallel
        // selection work. Keep smaller links on the original lazy member path, including inside
        // the extraction loop, rather than making every selected member probe an empty cache.
        const EAGER_ARCHIVE_SUMMARY_MIN_ARCHIVES: usize = 128;
        if archives.len() >= EAGER_ARCHIVE_SUMMARY_MIN_ARCHIVES {
            prepare_archive_objects(&archives, &mut self.prepared_archive_objects);
        }
        self.symbol_state.add_roots(roots);
        for (index, object) in objects.iter().enumerate().skip(self.scanned_objects) {
            let absorb_phase = crate::timing_guard!(super::PE_DETAIL_ABSORB_SELECTED_SYMBOLS);
            self.symbol_state.absorb_object(object, index)?;
            drop(absorb_phase);
        }
        self.scanned_objects = objects.len();
        // Legacy alias members are not retained as ordinary objects. Reapply their directives
        // because the caller rebuilds runtime directives whenever newly selected objects add
        // another `.drectve` wave.
        for &(archive_index, member_index) in &self.selected_aliases {
            let member = &archives[archive_index].members()[member_index];
            let aliases = parse_legacy_alias_object(member.data())?
                .expect("selected legacy alias member remains a legacy alias");
            for directive in aliases.directives()? {
                runtime_resolution.apply(directive, &String::from_utf8_lossy(member.name()))?;
            }
        }
        self.symbol_state.sync_alternates(runtime_resolution);

        let mut waves = 0usize;
        loop {
            let mut changed = false;
            waves += 1;
            changed |= extract_pass(
                &archives,
                objects,
                &self.whole_archive,
                runtime_resolution,
                &mut self.extracted,
                &mut self.import_definitions,
                &mut self.selected_imports,
                &mut self.symbol_state,
                &mut self.selected_aliases,
                &mut self.archive_providers,
                &mut self.prepared_archive_objects,
                false,
            )?;
            self.scanned_objects = objects.len();
            if changed {
                continue;
            }
            waves += 1;
            changed |= extract_pass(
                &archives,
                objects,
                &self.whole_archive,
                runtime_resolution,
                &mut self.extracted,
                &mut self.import_definitions,
                &mut self.selected_imports,
                &mut self.symbol_state,
                &mut self.selected_aliases,
                &mut self.archive_providers,
                &mut self.prepared_archive_objects,
                true,
            )?;
            self.scanned_objects = objects.len();
            if !changed {
                // Alias members selected in the final extraction waves update runtime state.
                self.symbol_state.sync_alternates(runtime_resolution);
                resolve_phase.0.add(crate::timing::PeMetric::Waves, waves);
                resolve_phase
                    .0
                    .set(crate::timing::PeMetric::Objects, objects.len());
                resolve_phase.0.add(
                    crate::timing::PeMetric::Imports,
                    self.selected_imports.len(),
                );
                resolve_phase.0.add(
                    crate::timing::PeMetric::Symbols,
                    self.symbol_state.global_names.len(),
                );
                return Ok(());
            }
        }
    }
}

/// Extract regular COFF members from all archives until no archive can satisfy
/// another unresolved external. Short import objects remain owned by the
/// import-directory builder.
#[cfg(test)]
fn extract<'data>(
    objects: &mut Vec<crate::coff::CoffObject<'data>>,
    archive_bytes: &[&'data [u8]],
    whole_archive: &[bool],
    roots: &[Vec<u8>],
    runtime_resolution: &mut RuntimeResolution,
) -> Result<()> {
    ensure!(
        archive_bytes.len() == whole_archive.len(),
        "internal archive policy mismatch"
    );
    let mut session = ResolverSession::new();
    for (&bytes, &whole_archive) in archive_bytes.iter().zip(whole_archive) {
        session.add_archive(bytes, whole_archive)?;
    }
    session.resolve(objects, roots, runtime_resolution)
}

#[allow(clippy::too_many_arguments)]
fn extract_pass<'data>(
    archives: &[&CoffArchive<'data>],
    objects: &mut Vec<crate::coff::CoffObject<'data>>,
    whole_archive: &[bool],
    runtime_resolution: &mut RuntimeResolution,
    extracted: &mut HashSet<(usize, usize)>,
    import_definitions: &mut HashSet<NameId>,
    selected_imports: &mut Vec<ShortImportObject<'data>>,
    symbol_state: &mut IncrementalSymbolState<'data>,
    selected_aliases: &mut Vec<(usize, usize)>,
    archive_providers: &mut ArchiveProviderCache,
    prepared_archive_objects: &mut [Vec<Option<Result<crate::coff::CoffObject<'data>>>>],
    use_alternates: bool,
) -> Result<bool> {
    let mut pass_phase = crate::pe_timing_guard!("PE archive: Extraction pass");
    pass_phase
        .0
        .add(crate::timing::PeMetric::Archives, archives.len());
    let instrumentation_enabled = pass_phase.0.enabled();
    let extracted_before = extracted.len();
    if !use_alternates {
        let mut scheduler = PrimaryArchiveScheduler::new(archives, symbol_state, archive_providers);
        let mut changed = false;
        let mut selections = 0usize;
        while let Some((archive_index, selected)) = scheduler.next(
            archives,
            whole_archive,
            extracted,
            symbol_state,
            archive_providers,
        ) {
            selections += 1;
            changed |= process_selected_members(
                selected,
                archive_index,
                objects,
                runtime_resolution,
                extracted,
                import_definitions,
                selected_imports,
                symbol_state,
                selected_aliases,
                prepared_archive_objects,
            )?;
        }
        pass_phase
            .0
            .add(crate::timing::PeMetric::Names, scheduler.lookups);
        pass_phase
            .0
            .add(crate::timing::PeMetric::Lookups, scheduler.lookups);
        pass_phase
            .0
            .add(crate::timing::PeMetric::Waves, selections + 1);
        pass_phase.0.add(
            crate::timing::PeMetric::Events,
            extracted.len() - extracted_before,
        );
        pass_phase
            .0
            .add(crate::timing::PeMetric::Objects, objects.len());
        return Ok(changed);
    }
    let mut changed = false;
    let mut demand_count = 0usize;
    let mut waves = 0usize;
    let mut next_archive = 0;
    while next_archive < archives.len() {
        // A demand snapshot remains valid until an archive selects a member and mutates the
        // symbol state. Reuse it across runs of archives that select nothing instead of cloning,
        // resolving and allocating the same names once per archive.
        let fallback_names;
        let demands = if use_alternates {
            fallback_names = fallback_demands(symbol_state, runtime_resolution)?;
            fallback_names
                .iter()
                .map(|&name| CanonicalArchiveDemand { name })
                .collect::<Vec<_>>()
        } else {
            let mut demands = symbol_state
                .unresolved_in_byte_order()
                .into_iter()
                .map(|name| CanonicalArchiveDemand { name })
                .collect::<Vec<_>>();
            demands.extend(
                symbol_state
                    .weak_names
                    .iter()
                    .filter(|fallback| {
                        fallback.search == linker_utils::coff_symbols::WeakSearch::Library
                            && !symbol_state.is_defined(fallback.symbol)
                    })
                    .map(|fallback| CanonicalArchiveDemand {
                        name: fallback.symbol,
                    }),
            );
            demands
        };
        if instrumentation_enabled {
            demand_count += demands.len();
            waves += 1;
        }
        let selection = next_archive_selection(
            archives,
            whole_archive,
            extracted,
            &demands,
            next_archive,
            archive_providers,
            &symbol_state.names,
        );
        let Some((archive_index, selected)) = selection else {
            break;
        };
        next_archive = archive_index + 1;
        drop(demands);
        changed |= process_selected_members(
            selected,
            archive_index,
            objects,
            runtime_resolution,
            extracted,
            import_definitions,
            selected_imports,
            symbol_state,
            selected_aliases,
            prepared_archive_objects,
        )?;
    }
    pass_phase
        .0
        .add(crate::timing::PeMetric::Names, demand_count);
    pass_phase
        .0
        .add(crate::timing::PeMetric::Lookups, demand_count);
    pass_phase.0.add(crate::timing::PeMetric::Waves, waves);
    pass_phase.0.add(
        crate::timing::PeMetric::Events,
        extracted.len() - extracted_before,
    );
    pass_phase
        .0
        .add(crate::timing::PeMetric::Objects, objects.len());
    Ok(changed)
}

#[allow(clippy::too_many_arguments)]
fn process_selected_members<'data>(
    selected: Vec<&CoffArchiveMember<'data>>,
    archive_index: usize,
    objects: &mut Vec<crate::coff::CoffObject<'data>>,
    runtime_resolution: &mut RuntimeResolution,
    extracted: &mut HashSet<(usize, usize)>,
    import_definitions: &mut HashSet<NameId>,
    selected_imports: &mut Vec<ShortImportObject<'data>>,
    symbol_state: &mut IncrementalSymbolState<'data>,
    selected_aliases: &mut Vec<(usize, usize)>,
    prepared_archive_objects: &mut [Vec<Option<Result<crate::coff::CoffObject<'data>>>>],
) -> Result<bool> {
    let mut changed = false;
    // Selection semantics and diagnostics remain ordered, but parsing and summarizing a large
    // selected batch is independent work. Prepare only the members that the resolver actually
    // selected; unlike full-archive speculation, this does not touch irrelevant object payloads.
    const PARALLEL_SELECTED_PREPARE_MIN: usize = 16;
    let mut selected_objects = if prepared_archive_objects.is_empty()
        && selected.len() >= PARALLEL_SELECTED_PREPARE_MIN
        && rayon::current_num_threads() > 1
    {
        selected
            .par_iter()
            .map(|member| match member.kind() {
                CoffArchiveMemberKind::CoffObject { .. } => Some(
                    crate::coff::CoffObject::parse(member.data()).and_then(|object| {
                        object.resolver_summary()?;
                        Ok(object)
                    }),
                ),
                CoffArchiveMemberKind::ShortImport(_) | CoffArchiveMemberKind::Opaque => None,
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    for (selected_index, member) in selected.into_iter().enumerate() {
        if extracted.len() == extracted.capacity() {
            crate::perf::removal_counters::increment_hot_phase_allocations();
        }
        if !extracted.insert((archive_index, member.index())) {
            unreachable!("the archive-selection scan filters extracted members");
        }
        crate::perf::removal_counters::increment_selected_members();
        match member.kind() {
            CoffArchiveMemberKind::CoffObject { .. } => {
                let object = if let Some(prepared) = selected_objects
                    .get_mut(selected_index)
                    .and_then(Option::take)
                {
                    prepared
                } else if prepared_archive_objects.is_empty() {
                    crate::coff::CoffObject::parse(member.data())
                } else {
                    prepared_archive_objects
                        .get_mut(archive_index)
                        .and_then(|members| members.get_mut(member.index()))
                        .and_then(Option::take)
                        .unwrap_or_else(|| crate::coff::CoffObject::parse(member.data()))
                }
                .with_context(|| {
                    format!(
                        "invalid COFF archive member `{}`",
                        String::from_utf8_lossy(member.name())
                    )
                })?;
                let absorb_phase = crate::timing_guard!(super::PE_DETAIL_ABSORB_SELECTED_SYMBOLS);
                symbol_state.absorb_object(&object, objects.len())?;
                drop(absorb_phase);
                note_vec_push(objects);
                objects.push(object);
                changed = true;
            }
            CoffArchiveMemberKind::ShortImport(import) => {
                let selected_import = u32::try_from(selected_imports.len())
                    .context("selected PE import count exceeds u32")?;
                let archive = ArchiveId::from_u32(
                    u32::try_from(archive_index).context("PE archive index exceeds u32")?,
                );
                let archive_member = ArchiveMemberId::from_u32(
                    u32::try_from(member.index()).context("PE archive member index exceeds u32")?,
                );
                for definition in member.definitions() {
                    let (name, _) = symbol_state.define_owned_with_id(definition);
                    note_vec_push(&symbol_state.providers);
                    symbol_state
                        .providers
                        .push(ResolverProviderOccurrence::Import {
                            name,
                            selected_import,
                            archive,
                            member: archive_member,
                        });
                    if import_definitions.len() == import_definitions.capacity() {
                        crate::perf::removal_counters::increment_hot_phase_allocations();
                    }
                    if import_definitions.insert(name) {
                        changed = true;
                    }
                }
                note_vec_push(selected_imports);
                selected_imports.push(import);
            }
            CoffArchiveMemberKind::Opaque => {
                if let Some(aliases) = parse_legacy_alias_object(member.data())
                    .context("invalid legacy COFF alias member")?
                {
                    for directive in aliases.directives()? {
                        runtime_resolution
                            .apply(directive, &String::from_utf8_lossy(member.name()))?;
                    }
                    note_vec_push(selected_aliases);
                    selected_aliases.push((archive_index, member.index()));
                    changed = true;
                } else {
                    return Err(error!(
                        "unsupported selected COFF archive member `{}`: {}",
                        String::from_utf8_lossy(member.name()),
                        member
                            .opaque_error()
                            .expect("opaque archive members retain their parse error")
                    ));
                }
            }
        }
    }
    Ok(changed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CanonicalArchiveDemand {
    name: NameId,
}

#[derive(Clone, Copy)]
enum ScheduledDemandKind {
    Unresolved,
    LibraryWeak(u32),
}

#[derive(Clone, Copy)]
struct ScheduledArchiveDemand {
    name: NameId,
    member: usize,
    kind: ScheduledDemandKind,
}

/// One primary extraction pass visits archives monotonically. Keep provider rows across member
/// selections and append only demands emitted by newly selected objects; definitions merely make
/// old rows inactive. This removes the whole unresolved-set/provider rescan after every member.
struct PrimaryArchiveScheduler {
    by_archive: Vec<Vec<ScheduledArchiveDemand>>,
    next_archive: usize,
    event_cursor: usize,
    lookups: usize,
    local_definition_epochs: Vec<u32>,
    selected_member_epochs: Vec<u32>,
    selection_epoch: u32,
}

impl PrimaryArchiveScheduler {
    fn new<'data>(
        archives: &[&CoffArchive<'data>],
        symbols: &IncrementalSymbolState<'data>,
        providers: &mut ArchiveProviderCache,
    ) -> Self {
        let mut scheduler = Self {
            by_archive: vec![Vec::new(); archives.len()],
            next_archive: 0,
            event_cursor: symbols.archive_demand_events.len(),
            lookups: 0,
            local_definition_epochs: Vec::new(),
            selected_member_epochs: Vec::new(),
            selection_epoch: 0,
        };
        // `next` sorts active unresolved demands by bytes within each archive before selection.
        // Sorting the entire unresolved namespace here first therefore cannot affect semantics and
        // only adds an O(n log n) pass over the largest demand wave.
        for name in symbols.unresolved_names.iter().copied() {
            scheduler.add(
                archives,
                &symbols.names,
                providers,
                name,
                ScheduledDemandKind::Unresolved,
            );
        }
        for (order, fallback) in symbols.weak_names.iter().enumerate() {
            if fallback.search == linker_utils::coff_symbols::WeakSearch::Library
                && !symbols.is_defined(fallback.symbol)
            {
                scheduler.add(
                    archives,
                    &symbols.names,
                    providers,
                    fallback.symbol,
                    ScheduledDemandKind::LibraryWeak(order as u32),
                );
            }
        }
        scheduler
    }

    fn add<'data>(
        &mut self,
        archives: &[&CoffArchive<'data>],
        names: &OrderedNameInterner<'_>,
        providers: &mut ArchiveProviderCache,
        name: NameId,
        kind: ScheduledDemandKind,
    ) {
        self.lookups += 1;
        let bytes = names
            .bytes(name)
            .expect("archive demands use canonical NameIds");
        for &provider in providers.providers(name, bytes, archives) {
            let archive = provider.archive.index();
            if archive >= self.next_archive {
                let member = archives[archive]
                    .definition_member_index(provider.definition)
                    .expect("cached PE archive definition remains valid");
                self.by_archive[archive].push(ScheduledArchiveDemand { name, member, kind });
            }
        }
    }

    fn refresh<'data>(
        &mut self,
        archives: &[&CoffArchive<'data>],
        symbols: &IncrementalSymbolState<'data>,
        providers: &mut ArchiveProviderCache,
    ) {
        for &event in &symbols.archive_demand_events[self.event_cursor..] {
            let (name, kind) = match event {
                ArchiveDemandEvent::Unresolved(name) => (name, ScheduledDemandKind::Unresolved),
                ArchiveDemandEvent::LibraryWeak { name, order } => {
                    (name, ScheduledDemandKind::LibraryWeak(order))
                }
            };
            self.add(archives, &symbols.names, providers, name, kind);
        }
        self.event_cursor = symbols.archive_demand_events.len();
    }

    fn next<'archive, 'data>(
        &mut self,
        archives: &'archive [&CoffArchive<'data>],
        whole_archive: &[bool],
        extracted: &HashSet<(usize, usize)>,
        symbols: &IncrementalSymbolState<'data>,
        providers: &mut ArchiveProviderCache,
    ) -> Option<(usize, Vec<&'archive CoffArchiveMember<'data>>)> {
        self.refresh(archives, symbols, providers);
        while self.next_archive < archives.len() {
            let archive_index = self.next_archive;
            self.next_archive += 1;
            let demands = &mut self.by_archive[archive_index];
            demands.retain(|demand| match demand.kind {
                ScheduledDemandKind::Unresolved => {
                    symbols.states[demand.name.index()].is_unresolved()
                }
                ScheduledDemandKind::LibraryWeak(_) => !symbols.is_defined(demand.name),
            });
            demands.sort_by(|left, right| match (left.kind, right.kind) {
                (ScheduledDemandKind::Unresolved, ScheduledDemandKind::LibraryWeak(_)) => {
                    std::cmp::Ordering::Less
                }
                (ScheduledDemandKind::LibraryWeak(_), ScheduledDemandKind::Unresolved) => {
                    std::cmp::Ordering::Greater
                }
                (ScheduledDemandKind::Unresolved, ScheduledDemandKind::Unresolved) => symbols
                    .names
                    .bytes(left.name)
                    .cmp(&symbols.names.bytes(right.name)),
                (
                    ScheduledDemandKind::LibraryWeak(left),
                    ScheduledDemandKind::LibraryWeak(right),
                ) => left.cmp(&right),
            });
            let archive = archives[archive_index];
            let mut selected = if whole_archive[archive_index] {
                archive.members().iter().collect::<Vec<_>>()
            } else {
                // All demands are interned. Map definitions from selected members back to their
                // canonical IDs and mark them in generation-stamped dense tables. This preserves
                // exact local-definition suppression while reusing storage across archives,
                // instead of allocating and hashing two fresh sets for every archive visited.
                self.selection_epoch = self.selection_epoch.wrapping_add(1);
                if self.selection_epoch == 0 {
                    self.local_definition_epochs.fill(0);
                    self.selected_member_epochs.fill(0);
                    self.selection_epoch = 1;
                }
                let epoch = self.selection_epoch;
                self.local_definition_epochs.resize(symbols.states.len(), 0);
                self.selected_member_epochs
                    .resize(archive.members().len(), 0);
                let mut selected = Vec::new();
                for demand in demands.iter() {
                    let name_index = demand.name.index();
                    if self.local_definition_epochs[name_index] == epoch
                        || self.selected_member_epochs[demand.member] == epoch
                    {
                        continue;
                    }
                    self.selected_member_epochs[demand.member] = epoch;
                    let member = &archive.members()[demand.member];
                    if member.has_nonfirst_definition() {
                        for definition in member.definitions() {
                            let hash = hash_name(definition);
                            if let Some(name) = symbols.names.lookup_prehashed(definition, hash) {
                                self.local_definition_epochs[name.index()] = epoch;
                            }
                        }
                    }
                    selected.push(member);
                }
                selected
            };
            selected.retain(|member| !extracted.contains(&(archive_index, member.index())));
            if !selected.is_empty() {
                return Some((archive_index, selected));
            }
        }
        None
    }
}

fn next_archive_selection<'archive, 'data>(
    archives: &'archive [&CoffArchive<'data>],
    whole_archive: &[bool],
    extracted: &HashSet<(usize, usize)>,
    demands: &[CanonicalArchiveDemand],
    start: usize,
    archive_providers: &mut ArchiveProviderCache,
    names: &OrderedNameInterner<'_>,
) -> Option<(usize, Vec<&'archive CoffArchiveMember<'data>>)> {
    let mut demands_by_archive = vec![Vec::new(); archives.len()];
    let mut touched_archives = Vec::new();
    for &demand in demands {
        let name = names
            .bytes(demand.name)
            .expect("archive demands use canonical NameIds");
        for &provider in archive_providers.providers(demand.name, name, archives) {
            let archive_index = provider.archive.index();
            let member_index = archives[archive_index]
                .definition_member_index(provider.definition)
                .expect("cached PE archive definition remains valid");
            if archive_index < start {
                continue;
            }
            let archive_demands = &mut demands_by_archive[archive_index];
            if archive_demands.is_empty() {
                touched_archives.push(archive_index);
            }
            archive_demands.push((name, member_index));
        }
    }
    for (archive_index, &is_whole_archive) in whole_archive.iter().enumerate().skip(start) {
        if is_whole_archive && demands_by_archive[archive_index].is_empty() {
            touched_archives.push(archive_index);
        }
    }
    touched_archives.sort_unstable();

    for archive_index in touched_archives {
        let mut selected = archives[archive_index].select_shallow_members_from_provider_indices(
            &demands_by_archive[archive_index],
            whole_archive[archive_index],
        );
        selected.retain(|member| !extracted.contains(&(archive_index, member.index())));
        if !selected.is_empty() {
            return Some((archive_index, selected));
        }
    }
    None
}

#[cfg(test)]
fn next_archive_selection_reference<'archive, 'data>(
    archives: &'archive [&CoffArchive<'data>],
    whole_archive: &[bool],
    extracted: &HashSet<(usize, usize)>,
    defined: &HashSet<Vec<u8>>,
    demands: &[ArchiveDemand<'_>],
    start: usize,
) -> Option<(usize, Vec<&'archive CoffArchiveMember<'data>>)> {
    for archive_index in start..archives.len() {
        let mut selected = archives[archive_index].select_shallow_members_with_defined_lookup(
            demands,
            whole_archive[archive_index],
            |name| defined.contains(name),
        );
        selected.retain(|member| !extracted.contains(&(archive_index, member.index())));
        if !selected.is_empty() {
            return Some((archive_index, selected));
        }
    }
    None
}

fn fallback_demands<'data>(
    state: &mut IncrementalSymbolState<'data>,
    runtime_resolution: &RuntimeResolution,
) -> Result<Vec<NameId>> {
    // Alternate resolution may intern names, so release the active-set borrow before the loop.
    let unresolved = state.unresolved_in_byte_order();
    let mut demands = Vec::with_capacity(unresolved.len() + state.weak_names.len());
    for name in unresolved {
        let resolved = {
            let bytes = state
                .names
                .bytes(name)
                .expect("unresolved NameId is interned");
            let Ok(text) = std::str::from_utf8(bytes) else {
                demands.push(name);
                continue;
            };
            runtime_resolution
                .resolve_alternate_name(text, |candidate| {
                    let bytes = candidate.as_bytes();
                    state
                        .names
                        .lookup_prehashed(bytes, hash_name(bytes))
                        .is_some_and(|id| state.is_defined(id))
                })?
                .as_bytes()
                .to_vec()
        };
        let resolved = state.intern_owned(&resolved);
        if !state.is_defined(resolved) {
            demands.push(resolved);
        }
    }
    let weak_symbols = state
        .weak_names
        .iter()
        .map(|fallback| fallback.symbol)
        .collect::<Vec<_>>();
    for symbol in weak_symbols {
        if state.is_defined(symbol) {
            continue;
        }
        let target = {
            let symbol = state.names.bytes(symbol).expect("weak NameId is interned");
            state
                .weak_resolution
                .resolve(symbol, |name| {
                    state
                        .names
                        .lookup_prehashed(name, hash_name(name))
                        .is_some_and(|id| state.is_defined(id))
                })?
                .to_vec()
        };
        let target = state.intern_owned(&target);
        if !state.is_defined(target) {
            demands.push(target);
        }
    }
    demands.sort_by(|&left, &right| {
        state
            .names
            .bytes(left)
            .expect("fallback NameId is interned")
            .cmp(
                state
                    .names
                    .bytes(right)
                    .expect("fallback NameId is interned"),
            )
    });
    demands.dedup();
    Ok(demands)
}

#[cfg(test)]
fn symbol_state(objects: &[crate::coff::CoffObject<'_>], roots: &[Vec<u8>]) -> Result<SymbolState> {
    let mut state = IncrementalSymbolState::new();
    state.add_roots(roots);
    for (index, object) in objects.iter().enumerate() {
        state.absorb_object(object, index)?;
    }
    let defined = state
        .states
        .iter()
        .enumerate()
        .filter(|(_, item)| item.is_defined())
        .map(|(index, _)| {
            state
                .names
                .bytes(NameId::from_u32(index as u32))
                .expect("state NameId is interned")
                .to_vec()
        })
        .collect();
    let unresolved = state
        .unresolved_in_byte_order()
        .iter()
        .copied()
        .map(|name| state.names.bytes(name).unwrap().to_vec())
        .collect();
    Ok((defined, unresolved))
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::pe;

    fn assert_send_sync<T: Send + Sync>() {}

    fn seed_name(seed: &ResolverSeed<'_>, name: &[u8]) -> NameId {
        seed.names
            .lookup_prehashed(name, crate::hash::hash_bytes(name))
            .unwrap_or_else(|| panic!("seed does not contain {}", String::from_utf8_lossy(name)))
    }

    #[test]
    fn active_unresolved_set_scales_with_demands_not_definitions() {
        let mut state = IncrementalSymbolState::new();
        for index in 0..4096 {
            let name = format!("defined_{index:04}");
            state.define_owned_with_id(name.as_bytes());
        }

        state.add_roots(&[b"z_demand".to_vec(), b"a_demand".to_vec()]);
        state.add_roots(&[b"z_demand".to_vec()]);
        assert_eq!(state.states.len(), 4098);
        assert_eq!(state.unresolved_names.len(), 2);
        let unresolved = state
            .unresolved_in_byte_order()
            .iter()
            .copied()
            .map(|id| state.names.bytes(id).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(unresolved, [b"a_demand".as_slice(), b"z_demand".as_slice()]);

        let z = state.intern_owned(b"z_demand");
        state.define_id(z);
        assert_eq!(state.unresolved_names.len(), 1);
        let unresolved = state
            .unresolved_in_byte_order()
            .iter()
            .copied()
            .map(|id| state.names.bytes(id).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(unresolved, [b"a_demand".as_slice()]);
    }

    #[test]
    fn resolver_snapshot_preserves_direct_and_archive_symbol_order() {
        assert_send_sync::<SelectedSymbolSnapshot>();

        let direct = coff_object(&["direct"], &["arc_sym"]);
        let library = archive(&[("member.obj", coff_object(&["arc_sym", "second"], &[]))]);
        let mut objects = vec![crate::coff::CoffObject::parse(&direct).unwrap()];
        let mut session = ResolverSession::new();
        session.add_archive(&library, false).unwrap();
        session
            .resolve(&mut objects, &[], &mut RuntimeResolution::new())
            .unwrap();

        let output = session.finish();
        assert_eq!(output.object_scans, 2);
        let actual = output
            .symbols
            .globals
            .iter()
            .map(|symbol| {
                (
                    symbol.object,
                    symbol.index,
                    symbol.name.as_slice(),
                    symbol.is_definition,
                    symbol.is_undefined,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            [
                (0, object::SymbolIndex(0), b"direct".as_slice(), true, false),
                (
                    0,
                    object::SymbolIndex(1),
                    b"arc_sym".as_slice(),
                    false,
                    true,
                ),
                (
                    1,
                    object::SymbolIndex(0),
                    b"arc_sym".as_slice(),
                    true,
                    false,
                ),
                (1, object::SymbolIndex(1), b"second".as_slice(), true, false),
            ]
        );
        assert_eq!(output.symbols.weak_resolution.records().count(), 0);
        let provider_signature = output
            .seed
            .providers
            .iter()
            .map(|provider| match *provider {
                ResolverProviderOccurrence::Object {
                    name,
                    global_symbol,
                    ..
                } => (output.seed.names.bytes(name).unwrap(), global_symbol),
                _ => panic!("fixture only selects object providers"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            provider_signature,
            [
                (b"direct".as_slice(), 0),
                (b"arc_sym".as_slice(), 2),
                (b"second".as_slice(), 3),
            ]
        );
    }

    #[test]
    fn resolver_skips_unconsumed_local_symbol_names() {
        let bytes = object_with_malformed_local_name();
        let object = crate::coff::CoffObject::parse(&bytes).unwrap();
        IncrementalSymbolState::new()
            .absorb_object(&object, 0)
            .unwrap();
    }

    #[test]
    fn weak_metadata_error_precedes_later_malformed_local_name() {
        let mut bytes = weak_object(99);
        bytes.truncate(bytes.len() - 4);
        bytes[12..16].copy_from_slice(&4u32.to_le_bytes());
        push_malformed_local_symbol(&mut bytes);
        bytes.extend_from_slice(&4u32.to_le_bytes());
        let object = crate::coff::CoffObject::parse(&bytes).unwrap();

        let error = IncrementalSymbolState::new()
            .absorb_object(&object, 0)
            .unwrap_err();
        let message = format!("{error:?}");
        assert!(
            message.contains("unsupported weak-external search characteristic 99"),
            "{message}"
        );
        assert!(!message.contains("invalid COFF symbol name"), "{message}");
    }

    #[test]
    fn optional_archive_root_extracts_only_when_available() {
        let library = archive(&[("loadcfg.obj", coff_object(&["loadcfg"], &[]))]);
        let mut session = ResolverSession::new();
        session.add_archive(&library, false).unwrap();
        assert!(session.has_archive_definition(b"loadcfg"));
        let mut objects = Vec::new();
        session
            .resolve(
                &mut objects,
                &[b"loadcfg".to_vec()],
                &mut RuntimeResolution::new(),
            )
            .unwrap();
        assert_eq!(objects.len(), 1);

        let unrelated = archive(&[("other.obj", coff_object(&["other"], &[]))]);
        let mut session = ResolverSession::new();
        session.add_archive(&unrelated, false).unwrap();
        assert!(!session.has_archive_definition(b"loadcfg"));
        let mut objects = Vec::new();
        session
            .resolve(&mut objects, &[], &mut RuntimeResolution::new())
            .unwrap();
        assert!(objects.is_empty());
    }

    #[test]
    fn resolver_seed_ids_survive_appended_default_library_wave() {
        let root = coff_object(&[], &["target"]);
        let unrelated = archive(&[("other.obj", coff_object(&["other"], &[]))]);
        let provider = archive(&[("target.obj", coff_object(&["target"], &[]))]);
        let mut objects = vec![crate::coff::CoffObject::parse(&root).unwrap()];
        let mut session = ResolverSession::new();
        session.add_archive(&unrelated, false).unwrap();
        session
            .resolve(&mut objects, &[], &mut RuntimeResolution::new())
            .unwrap();
        let target_before = session
            .symbol_state
            .names
            .lookup_prehashed(b"target", crate::hash::hash_bytes(b"target"))
            .unwrap();

        session.add_archive(&provider, false).unwrap();
        session
            .resolve(&mut objects, &[], &mut RuntimeResolution::new())
            .unwrap();
        let output = session.finish();
        let target_after = seed_name(&output.seed, b"target");
        assert_eq!(target_after, target_before);
        assert!(output.seed.state(target_after).unwrap().is_defined());
        assert!(!output.seed.state(target_after).unwrap().is_unresolved());
        assert!(output.seed.providers.iter().any(|provider| {
            matches!(
                provider,
                ResolverProviderOccurrence::Object {
                    name,
                    global_symbol: 1,
                    ..
                } if *name == target_after
            )
        }));

        let original_count = output.seed.names.len();
        let ResolverSeedParts {
            mut names,
            states,
            weak_fallbacks,
            alternate_fallbacks,
            providers,
        } = output.seed.into_parts();
        let appended = names.intern_borrowed_prehashed(
            b"workstream-one-local",
            crate::hash::hash_bytes(b"workstream-one-local"),
        );
        assert_eq!(
            names.lookup_prehashed(b"target", crate::hash::hash_bytes(b"target")),
            Some(target_before)
        );
        assert_eq!(appended, NameId::from_u32(original_count as u32));
        assert_eq!(states.len(), original_count);
        assert!(weak_fallbacks.is_empty());
        assert!(alternate_fallbacks.is_empty());
        assert!(!providers.is_empty());
    }

    #[test]
    fn resolver_seed_uses_name_ids_for_weak_and_alternate_fallbacks() {
        let weak = weak_object(pe::IMAGE_WEAK_EXTERN_SEARCH_LIBRARY.0);
        let mut objects = vec![crate::coff::CoffObject::parse(&weak).unwrap()];
        let mut runtime = RuntimeResolution::new();
        runtime
            .parse_and_apply("/alternatename:missing=alternate", "root.obj")
            .unwrap();
        let mut session = ResolverSession::new();
        session.resolve(&mut objects, &[], &mut runtime).unwrap();
        let output = session.finish();

        let primary = seed_name(&output.seed, b"primary");
        let fallback = seed_name(&output.seed, b"fallback");
        assert_eq!(
            output.seed.weak_fallbacks.as_ref(),
            [ResolverWeakFallback {
                symbol: primary,
                target: fallback,
                search: linker_utils::coff_symbols::WeakSearch::Library,
            }]
        );
        assert_eq!(
            output.seed.alternate_fallbacks.as_ref(),
            [ResolverAlternateFallback {
                symbol: seed_name(&output.seed, b"missing"),
                target: seed_name(&output.seed, b"alternate"),
            }]
        );
    }

    #[test]
    fn later_archive_observes_definitions_and_demands_from_earlier_archive() {
        let root = coff_object(&[], &["foo"]);
        let first = archive(&[("first.obj", coff_object(&["foo"], &["bar"]))]);
        let second = archive(&[
            ("duplicate.obj", coff_object(&["foo"], &[])),
            ("bar.obj", coff_object(&["bar"], &[])),
        ]);
        let mut objects = vec![crate::coff::CoffObject::parse(&root).unwrap()];

        extract(
            &mut objects,
            &[&first, &second],
            &[false, false],
            &[],
            &mut RuntimeResolution::new(),
        )
        .unwrap();

        assert_eq!(
            objects.len(),
            3,
            "the competing foo definition was extracted"
        );
        let (defined, unresolved) = symbol_state(&objects, &[]).unwrap();
        assert!(defined.contains(b"foo".as_slice()));
        assert!(defined.contains(b"bar".as_slice()));
        assert!(unresolved.is_empty());
    }

    #[test]
    fn later_archive_demands_can_revisit_an_earlier_archive() {
        let root = coff_object(&[], &["foo"]);
        let first = archive(&[("bar.obj", coff_object(&["bar"], &[]))]);
        let second = archive(&[("foo.obj", coff_object(&["foo"], &["bar"]))]);
        let mut objects = vec![crate::coff::CoffObject::parse(&root).unwrap()];

        extract(
            &mut objects,
            &[&first, &second],
            &[false, false],
            &[],
            &mut RuntimeResolution::new(),
        )
        .unwrap();

        assert_eq!(objects.len(), 3);
        let (_, unresolved) = symbol_state(&objects, &[]).unwrap();
        assert!(unresolved.is_empty());
    }

    #[test]
    fn short_import_definition_suppresses_later_regular_member() {
        let root = coff_object(&[], &["foo"]);
        let imports = archive(&[("foo.obj", short_import("foo", "example.dll"))]);
        let fallback = archive(&[("fallback.obj", coff_object(&["foo"], &[]))]);
        let mut objects = vec![crate::coff::CoffObject::parse(&root).unwrap()];

        extract(
            &mut objects,
            &[&imports, &fallback],
            &[false, false],
            &[],
            &mut RuntimeResolution::new(),
        )
        .unwrap();

        assert_eq!(objects.len(), 1, "the fallback definition was extracted");
    }

    #[test]
    fn selected_short_import_records_preserve_archive_precedence_and_order() {
        let root = coff_object(&[], &["foo", "bar"]);
        let first = archive(&[
            ("foo.obj", short_import("foo", "first.dll")),
            ("bar.obj", short_import("bar", "first.dll")),
        ]);
        let duplicate = archive(&[("foo.obj", short_import("foo", "second.dll"))]);
        let mut session = ResolverSession::new();
        session.add_archive(&first, false).unwrap();
        session.add_archive(&duplicate, false).unwrap();
        let mut objects = vec![crate::coff::CoffObject::parse(&root).unwrap()];

        session
            .resolve(&mut objects, &[], &mut RuntimeResolution::new())
            .unwrap();

        let imports = session.selected_imports();
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].symbol(), b"bar");
        assert_eq!(imports[1].symbol(), b"foo");
        assert!(imports.iter().all(|import| import.dll() == b"first.dll"));
        let output = session.finish();
        let import_signature = output
            .seed
            .providers
            .iter()
            .filter_map(|provider| match *provider {
                ResolverProviderOccurrence::Import {
                    name,
                    selected_import,
                    archive,
                    member,
                } => Some((
                    output.seed.names.bytes(name).unwrap(),
                    selected_import,
                    archive.get(),
                    member.get(),
                )),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            import_signature,
            [(b"bar".as_slice(), 0, 0, 1), (b"foo".as_slice(), 1, 0, 0),]
        );
    }

    #[test]
    fn malformed_whole_archive_import_retains_member_diagnostic() {
        let malformed = archive(&[("broken.obj", vec![0, 0, 0xff, 0xff])]);
        let mut session = ResolverSession::new();
        session.add_archive(&malformed, true).unwrap();

        let error = session
            .resolve(&mut Vec::new(), &[], &mut RuntimeResolution::new())
            .unwrap_err();
        let message = format!("{error:?}");
        assert!(message.contains("broken.obj"), "{message}");
        assert!(
            message.contains("unsupported selected COFF archive member"),
            "{message}"
        );
    }

    #[test]
    fn alternatename_extracts_fallback_only_after_primary_search_fails() {
        let root = coff_object(&[], &["primary"]);
        let fallback = archive(&[("fallback.obj", coff_object(&["fallback"], &[]))]);
        let mut objects = vec![crate::coff::CoffObject::parse(&root).unwrap()];
        let mut runtime = RuntimeResolution::new();
        runtime
            .parse_and_apply("/alternatename:primary=fallback", "root.obj")
            .unwrap();

        extract(&mut objects, &[&fallback], &[false], &[], &mut runtime).unwrap();

        assert_eq!(objects.len(), 2);
        let (defined, _) = symbol_state(&objects, &[]).unwrap();
        assert!(defined.contains(b"fallback".as_slice()));
    }

    #[test]
    fn strong_archive_definition_beats_alternatename_fallback() {
        let root = coff_object(&[], &["primary"]);
        let library = archive(&[
            ("fallback.obj", coff_object(&["fallback"], &[])),
            ("primary.obj", coff_object(&["primary"], &[])),
        ]);
        let mut objects = vec![crate::coff::CoffObject::parse(&root).unwrap()];
        let mut runtime = RuntimeResolution::new();
        runtime
            .parse_and_apply("/alternatename:primary=fallback", "root.obj")
            .unwrap();

        extract(&mut objects, &[&library], &[false], &[], &mut runtime).unwrap();

        assert_eq!(objects.len(), 2, "fallback was extracted beside primary");
        let (defined, _) = symbol_state(&objects, &[]).unwrap();
        assert!(defined.contains(b"primary".as_slice()));
        assert!(!defined.contains(b"fallback".as_slice()));
    }

    #[test]
    fn weak_search_policy_controls_primary_archive_extraction() {
        for (search, extracts_primary) in [
            (pe::IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY.0, false),
            (pe::IMAGE_WEAK_EXTERN_SEARCH_ALIAS.0, false),
            (pe::IMAGE_WEAK_EXTERN_SEARCH_LIBRARY.0, true),
            (pe::IMAGE_WEAK_EXTERN_ANTI_DEPENDENCY.0, false),
        ] {
            let root = weak_object(search);
            let library = archive(&[("primary.obj", coff_object(&["primary"], &[]))]);
            let mut objects = vec![crate::coff::CoffObject::parse(&root).unwrap()];

            extract(
                &mut objects,
                &[&library],
                &[false],
                &[],
                &mut RuntimeResolution::new(),
            )
            .unwrap();

            assert_eq!(objects.len() == 2, extracts_primary, "search type {search}");
        }
    }

    #[test]
    fn weak_library_search_precedes_alternate_fallback_wave() {
        let root = weak_object(pe::IMAGE_WEAK_EXTERN_SEARCH_LIBRARY.0);
        let library = archive(&[
            ("alt.obj", coff_object(&["alt"], &[])),
            ("primary.obj", coff_object(&["primary"], &[])),
            ("fallback.obj", coff_object(&["fallback"], &[])),
        ]);
        let mut objects = vec![crate::coff::CoffObject::parse(&root).unwrap()];
        let mut runtime = RuntimeResolution::new();
        runtime
            .parse_and_apply("/alternatename:primary=alt", "root.obj")
            .unwrap();

        extract(&mut objects, &[&library], &[false], &[], &mut runtime).unwrap();

        let definitions = objects
            .iter()
            .skip(1)
            .flat_map(|object| object.file().symbols())
            .filter(|symbol| symbol.is_global() && symbol.is_definition())
            .map(|symbol| symbol.name_bytes().unwrap().to_vec())
            .collect::<Vec<_>>();
        assert_eq!(definitions, [b"primary".to_vec()]);
    }

    #[test]
    fn indexed_archive_selection_matches_reference_across_adversarial_states() {
        let archive_bytes = [
            archive(&[
                ("multi.obj", coff_object(&["alpha", "shared"], &[])),
                ("weak.obj", coff_object(&["weak"], &[])),
            ]),
            archive(&[
                ("shared.obj", coff_object(&["shared"], &[])),
                ("later.obj", coff_object(&["later"], &[])),
            ]),
            archive(&[("whole.obj", coff_object(&["whole"], &[]))]),
        ];
        let parsed = archive_bytes
            .iter()
            .map(|bytes| CoffArchive::parse(bytes).unwrap())
            .collect::<Vec<_>>();
        let archives = parsed.iter().collect::<Vec<_>>();
        let demands = [
            ArchiveDemand {
                name: b"alpha",
                kind: ArchiveDemandKind::Strong,
            },
            ArchiveDemand {
                name: b"later",
                kind: ArchiveDemandKind::Strong,
            },
            ArchiveDemand {
                name: b"shared",
                kind: ArchiveDemandKind::Strong,
            },
            ArchiveDemand {
                name: b"weak",
                kind: ArchiveDemandKind::WeakLibrary,
            },
        ];
        let mut names = OrderedNameInterner::new();
        for demand in demands {
            names.intern_borrowed_prehashed(demand.name, hash_name(demand.name));
        }
        let cases = [
            (0, vec![false, false, false], HashSet::new(), HashSet::new()),
            (1, vec![false, false, false], HashSet::new(), HashSet::new()),
            (0, vec![false, false, true], HashSet::new(), HashSet::new()),
            (2, vec![false, false, true], HashSet::new(), HashSet::new()),
            (
                0,
                vec![false, false, false],
                HashSet::from_iter([(0, 0)]),
                HashSet::new(),
            ),
            (
                0,
                vec![false, false, false],
                HashSet::new(),
                HashSet::from_iter([b"alpha".to_vec()]),
            ),
        ];
        let mut providers = ArchiveProviderCache::new();
        for (start, whole, extracted, defined) in cases {
            let expected = next_archive_selection_reference(
                &archives, &whole, &extracted, &defined, &demands, start,
            );
            let canonical_demands = demands
                .iter()
                .filter(|demand| !defined.contains(demand.name))
                .map(|demand| CanonicalArchiveDemand {
                    name: names
                        .lookup_prehashed(demand.name, hash_name(demand.name))
                        .unwrap(),
                })
                .collect::<Vec<_>>();
            let actual = next_archive_selection(
                &archives,
                &whole,
                &extracted,
                &canonical_demands,
                start,
                &mut providers,
                &names,
            );
            assert_eq!(selection_indices(actual), selection_indices(expected));
        }

        let shared_only = [ArchiveDemand {
            name: b"shared",
            kind: ArchiveDemandKind::Strong,
        }];
        let extracted = HashSet::from_iter([(0, 0)]);
        let expected = selection_indices(next_archive_selection_reference(
            &archives,
            &[false, false, false],
            &extracted,
            &HashSet::new(),
            &shared_only,
            0,
        ));
        let actual = selection_indices(next_archive_selection(
            &archives,
            &[false, false, false],
            &extracted,
            &[CanonicalArchiveDemand {
                name: names
                    .lookup_prehashed(b"shared", hash_name(b"shared"))
                    .unwrap(),
            }],
            0,
            &mut providers,
            &names,
        ));
        assert_eq!(actual, expected);
        assert_eq!(expected, Some((1, vec![0])));
    }

    #[test]
    fn provider_cache_extends_negative_entries_for_appended_default_libraries() {
        let unrelated = archive(&[("other.obj", coff_object(&["other"], &[]))]);
        let provider = archive(&[("target.obj", coff_object(&["target"], &[]))]);
        let parsed = [
            CoffArchive::parse(&unrelated).unwrap(),
            CoffArchive::parse(&provider).unwrap(),
        ];
        let target_definition = parsed[1]
            .definition_rows()
            .find(|(_, definition, _, _)| *definition == b"target")
            .unwrap()
            .0;

        for name in [
            NameId::from_u32(0),
            NameId::from_u32(DENSE_ARCHIVE_NAME_CACHE_LIMIT as u32 + 7),
        ] {
            let mut cache = ArchiveProviderCache::new();
            assert!(cache.providers(name, b"target", &[&parsed[0]]).is_empty());
            assert_eq!(
                cache.providers(name, b"target", &[&parsed[0], &parsed[1]]),
                [ArchiveProvider {
                    archive: ArchiveId::from_u32(1),
                    definition: target_definition,
                }]
            );
        }
    }

    #[test]
    fn cursor_finishes_later_archives_before_revisiting_an_earlier_provider() {
        let root = coff_object(&[], &["foo", "current"]);
        let earlier = archive(&[("new.obj", coff_object(&["new"], &[]))]);
        let middle = archive(&[("foo.obj", coff_object(&["foo"], &["new"]))]);
        let later = archive(&[("current.obj", coff_object(&["current"], &[]))]);
        let mut objects = vec![crate::coff::CoffObject::parse(&root).unwrap()];

        extract(
            &mut objects,
            &[&earlier, &middle, &later],
            &[false, false, false],
            &[],
            &mut RuntimeResolution::new(),
        )
        .unwrap();

        let definitions = objects
            .iter()
            .skip(1)
            .map(|object| {
                object
                    .file()
                    .symbols()
                    .find(|symbol| symbol.is_global() && symbol.is_definition())
                    .unwrap()
                    .name_bytes()
                    .unwrap()
                    .to_vec()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            definitions,
            [b"foo".to_vec(), b"current".to_vec(), b"new".to_vec()]
        );
    }

    fn selection_indices(
        selection: Option<(usize, Vec<&CoffArchiveMember<'_>>)>,
    ) -> Option<(usize, Vec<usize>)> {
        selection.map(|(archive, members)| {
            (
                archive,
                members.into_iter().map(CoffArchiveMember::index).collect(),
            )
        })
    }

    #[test]
    fn archive_preparation_is_deterministic_across_thread_counts() {
        let baseline = extraction_signature(1);
        for threads in [2, 4] {
            assert_eq!(extraction_signature(threads), baseline);
        }
    }

    #[test]
    fn selected_batch_preparation_is_deterministic_across_thread_counts() {
        let baseline = selected_batch_signature(1);
        for threads in [2, 4, 8] {
            assert_eq!(selected_batch_signature(threads), baseline);
        }
    }

    fn selected_batch_signature(threads: usize) -> Vec<Vec<u8>> {
        const MEMBER_COUNT: usize = 20;
        let names = (0..MEMBER_COUNT)
            .map(|index| format!("sym{index}"))
            .collect::<Vec<_>>();
        let undefined = names.iter().map(String::as_str).collect::<Vec<_>>();
        let root = coff_object(&[], &undefined);
        let members = names
            .iter()
            .enumerate()
            .map(|(index, name)| {
                (
                    format!("member{index}.o"),
                    coff_object(&[name.as_str()], &[]),
                )
            })
            .collect::<Vec<_>>();
        let member_refs = members
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.clone()))
            .collect::<Vec<_>>();
        let library = archive(&member_refs);
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
            .install(|| {
                let mut objects = vec![crate::coff::CoffObject::parse(&root).unwrap()];
                extract(
                    &mut objects,
                    &[&library],
                    &[false],
                    &[],
                    &mut RuntimeResolution::new(),
                )
                .unwrap();
                objects
                    .iter()
                    .skip(1)
                    .map(|object| {
                        object
                            .file()
                            .symbols()
                            .find(|symbol| symbol.is_global() && symbol.is_definition())
                            .unwrap()
                            .name_bytes()
                            .unwrap()
                            .to_vec()
                    })
                    .collect()
            })
    }

    fn extraction_signature(threads: usize) -> Vec<Vec<Vec<u8>>> {
        // Keep this at the production eager-preparation threshold so the parallel cache path,
        // not only the small-link lazy path, is covered by the thread-count determinism check.
        const ARCHIVE_COUNT: usize = 128;
        let root = coff_object(&[], &["sym0"]);
        let libraries = (0..ARCHIVE_COUNT)
            .rev()
            .map(|index| {
                let definition = format!("sym{index}");
                let undefined = (index + 1 < ARCHIVE_COUNT).then(|| format!("sym{}", index + 1));
                archive(&[(
                    "member.o",
                    coff_object(
                        &[definition.as_str()],
                        &undefined.as_deref().into_iter().collect::<Vec<_>>(),
                    ),
                )])
            })
            .collect::<Vec<_>>();
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
            .install(|| {
                assert_eq!(rayon::current_num_threads(), threads);
                let mut session = ResolverSession::new();
                for library in &libraries {
                    session.add_archive(library, false).unwrap();
                }
                let mut objects = vec![crate::coff::CoffObject::parse(&root).unwrap()];
                session
                    .resolve(&mut objects, &[], &mut RuntimeResolution::new())
                    .unwrap();
                objects
                    .iter()
                    .map(|object| {
                        object
                            .file()
                            .symbols()
                            .filter(|symbol| symbol.is_global() && symbol.is_definition())
                            .map(|symbol| symbol.name_bytes().unwrap().to_vec())
                            .collect::<Vec<_>>()
                    })
                    .collect()
            })
    }

    fn coff_object(definitions: &[&str], undefined: &[&str]) -> Vec<u8> {
        let symbol_count = definitions.len() + undefined.len();
        let mut bytes = vec![0; 20 + 40];
        bytes[0..2].copy_from_slice(&pe::IMAGE_FILE_MACHINE_AMD64.0.to_le_bytes());
        bytes[2..4].copy_from_slice(&1u16.to_le_bytes());
        bytes[8..12].copy_from_slice(&60u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&(symbol_count as u32).to_le_bytes());
        bytes[20..25].copy_from_slice(b".text");
        bytes[56..60]
            .copy_from_slice(&(pe::IMAGE_SCN_CNT_CODE.0 | pe::IMAGE_SCN_MEM_READ.0).to_le_bytes());
        for name in definitions {
            push_symbol(&mut bytes, name, 1);
        }
        for name in undefined {
            push_symbol(&mut bytes, name, 0);
        }
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes
    }

    fn push_symbol(bytes: &mut Vec<u8>, name: &str, section: i16) {
        assert!(name.len() <= 8);
        let mut symbol = [0; 18];
        symbol[..name.len()].copy_from_slice(name.as_bytes());
        symbol[12..14].copy_from_slice(&section.to_le_bytes());
        symbol[16] = pe::IMAGE_SYM_CLASS_EXTERNAL.0;
        bytes.extend_from_slice(&symbol);
    }

    fn push_malformed_local_symbol(bytes: &mut Vec<u8>) {
        let mut symbol = [0; 18];
        symbol[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        symbol[12..14].copy_from_slice(&1i16.to_le_bytes());
        symbol[16] = pe::IMAGE_SYM_CLASS_STATIC.0;
        bytes.extend_from_slice(&symbol);
    }

    fn object_with_malformed_local_name() -> Vec<u8> {
        let mut bytes = coff_object(&[], &[]);
        bytes.truncate(bytes.len() - 4);
        bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
        push_malformed_local_symbol(&mut bytes);
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes
    }

    fn weak_object(search: u32) -> Vec<u8> {
        let mut bytes = vec![0; 20 + 40];
        bytes[0..2].copy_from_slice(&pe::IMAGE_FILE_MACHINE_AMD64.0.to_le_bytes());
        bytes[2..4].copy_from_slice(&1u16.to_le_bytes());
        bytes[8..12].copy_from_slice(&60u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&3u32.to_le_bytes());
        bytes[20..25].copy_from_slice(b".text");
        bytes[56..60]
            .copy_from_slice(&(pe::IMAGE_SCN_CNT_CODE.0 | pe::IMAGE_SCN_MEM_READ.0).to_le_bytes());
        push_symbol(&mut bytes, "fallback", 1);
        let mut weak = [0; 18];
        weak[..7].copy_from_slice(b"primary");
        weak[16] = pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL.0;
        weak[17] = 1;
        bytes.extend_from_slice(&weak);
        let mut auxiliary = [0; 18];
        auxiliary[..4].copy_from_slice(&0u32.to_le_bytes());
        auxiliary[4..8].copy_from_slice(&search.to_le_bytes());
        bytes.extend_from_slice(&auxiliary);
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes
    }

    fn short_import(symbol: &str, dll: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(symbol.as_bytes());
        payload.push(0);
        payload.extend_from_slice(dll.as_bytes());
        payload.push(0);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&pe::IMPORT_OBJECT_HDR_SIG2.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&pe::IMAGE_FILE_MACHINE_AMD64.0.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&payload);
        bytes
    }

    fn archive(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut bytes = object::archive::MAGIC.to_vec();
        for (name, data) in members {
            let identifier = format!("{name}/");
            let header = format!(
                "{identifier:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                0,
                0,
                0,
                0,
                data.len()
            );
            assert_eq!(header.len(), 60);
            bytes.extend_from_slice(header.as_bytes());
            bytes.extend_from_slice(data);
            if data.len() % 2 != 0 {
                bytes.push(b'\n');
            }
        }
        bytes
    }
}
