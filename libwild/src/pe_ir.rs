//! Dense, source-backed intermediate representation for the PE/COFF linker.
//!
//! Selected `CoffObject`s have already crossed the sole generic-object parsing boundary. This
//! module concatenates their immutable local indices, assigns dense global IDs, and finalizes
//! canonical names in deterministic object/occurrence order without copying name or section bytes.

#![allow(dead_code)]

use super::pe_resolver::ResolverGlobalName;
use super::pe_symbol_db::DeferredInvalidName;
use super::pe_symbol_db::OrderedNameInterner;
use super::pe_symbol_db::ProviderKind;
use super::pe_symbol_db::ResolutionState;
use super::pe_symbol_db::SymbolDb;
use crate::coff::CoffDeferredNameError;
use crate::coff::CoffObject;
use crate::error::Result;
use rayon::prelude::*;
use std::marker::PhantomData;
use std::ops::Range;

macro_rules! dense_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(transparent)]
        pub(super) struct $name(u32);

        impl $name {
            pub(super) const fn from_u32(value: u32) -> Self {
                Self(value)
            }

            pub(super) const fn get(self) -> u32 {
                self.0
            }

            pub(super) const fn index(self) -> usize {
                self.0 as usize
            }
        }
    };
}

dense_id!(FileId);
dense_id!(ObjectId);
dense_id!(SectionId);
dense_id!(SymbolId);
dense_id!(NameId);
dense_id!(ArchiveId);
dense_id!(ArchiveMemberId);
dense_id!(ImportId);
dense_id!(ImportLibraryId);
dense_id!(ProviderId);

/// A half-open dense-ID range. The represented IDs are `start..start + len`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct DenseRange<Id> {
    start: u32,
    len: u32,
    marker: PhantomData<Id>,
}

impl<Id> DenseRange<Id> {
    pub(super) const fn new(start: u32, len: u32) -> Self {
        Self {
            start,
            len,
            marker: PhantomData,
        }
    }

    pub(super) const fn start(self) -> u32 {
        self.start
    }

    pub(super) const fn len(self) -> u32 {
        self.len
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(super) const fn end(self) -> Option<u32> {
        self.start.checked_add(self.len)
    }
}

/// A byte range borrowed from one opened input. The arena that owns the opened inputs outlives IR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct SourceRange {
    pub(super) file: FileId,
    pub(super) start: u32,
    pub(super) len: u32,
}

impl SourceRange {
    pub(super) const fn end(self) -> Option<u32> {
        self.start.checked_add(self.len)
    }
}

/// Borrowed file payloads are the sole owner-facing input to the dense IR.
#[derive(Debug)]
pub(super) struct SourceFiles<'data> {
    files: Box<[&'data [u8]]>,
}

impl<'data> SourceFiles<'data> {
    pub(super) fn new(files: Vec<&'data [u8]>) -> Self {
        Self {
            files: files.into_boxed_slice(),
        }
    }

    pub(super) fn file(&self, id: FileId) -> Option<&'data [u8]> {
        self.files.get(id.index()).copied()
    }

    pub(super) fn bytes(&self, range: SourceRange) -> Option<&'data [u8]> {
        let file = self.file(range.file)?;
        let start = range.start as usize;
        let end = range.end()? as usize;
        file.get(start..end)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct NameRecord {
    pub(super) source: Option<SourceRange>,
    pub(super) hash: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct ObjectRecord {
    pub(super) file: FileId,
    pub(super) sections: DenseRange<SectionId>,
    pub(super) symbols: DenseRange<SymbolId>,
    pub(super) input_ordinal: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum SectionContents {
    Code,
    Data,
    Uninitialized,
    Metadata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct SectionRecord {
    pub(super) object: ObjectId,
    pub(super) raw_index: u32,
    pub(super) name: NameId,
    pub(super) data: Option<SourceRange>,
    pub(super) size: u32,
    pub(super) alignment: u32,
    pub(super) characteristics: u32,
    pub(super) contents: SectionContents,
    pub(super) comdat_selection: u8,
    pub(super) associative_section: OptionalSectionId,
    pub(super) comdat_leader: OptionalSymbolId,
    pub(super) comdat_order: u32,
}

/// `u32::MAX` is the packed no-section value; valid dense section IDs never use it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(super) struct OptionalSectionId(u32);

impl OptionalSectionId {
    pub(super) const NONE: Self = Self(u32::MAX);

    pub(super) const fn some(section: SectionId) -> Self {
        Self(section.get())
    }

    pub(super) const fn get(self) -> Option<SectionId> {
        if self.0 == u32::MAX {
            None
        } else {
            Some(SectionId::from_u32(self.0))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct SymbolRecord {
    pub(super) object: ObjectId,
    pub(super) raw_index: u32,
    pub(super) name: NameId,
    pub(super) section: OptionalSectionId,
    pub(super) value: u64,
    pub(super) size: u32,
    pub(super) flags: u16,
    pub(super) storage_class: u8,
    pub(super) typ: u16,
    pub(super) weak_default: OptionalSymbolId,
    pub(super) diagnostic: SymbolDiagnostic,
}

impl SymbolRecord {
    const GLOBAL: u16 = 1 << 0;
    const COMMON: u16 = 1 << 1;
    const WEAK: u16 = 1 << 2;
    const DEFINITION: u16 = 1 << 3;
    const UNDEFINED: u16 = 1 << 4;
    const ABSOLUTE: u16 = 1 << 5;

    pub(super) const fn is_global(self) -> bool {
        self.flags & Self::GLOBAL != 0
    }

    pub(super) const fn is_common(self) -> bool {
        self.flags & Self::COMMON != 0
    }

    pub(super) const fn is_weak(self) -> bool {
        self.flags & Self::WEAK != 0
    }

    pub(super) const fn is_definition(self) -> bool {
        self.flags & Self::DEFINITION != 0
    }

    pub(super) const fn is_undefined(self) -> bool {
        self.flags & Self::UNDEFINED != 0
    }

    pub(super) const fn is_absolute(self) -> bool {
        self.flags & Self::ABSOLUTE != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(super) struct OptionalSymbolId(u32);

impl OptionalSymbolId {
    pub(super) const NONE: Self = Self(u32::MAX);

    pub(super) const fn some(symbol: SymbolId) -> Self {
        Self(symbol.get())
    }

    pub(super) const fn get(self) -> Option<SymbolId> {
        if self.0 == u32::MAX {
            None
        } else {
            Some(SymbolId::from_u32(self.0))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum SymbolDiagnostic {
    None,
    InvalidRelocationTarget,
}

/// Compact AMD64 COFF relocation. Kind validation remains a relocation-application concern.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct RelocationRecord {
    pub(super) offset: u32,
    pub(super) target: SymbolId,
    pub(super) typ: u16,
    pub(super) flags: u16,
}

/// Compressed sparse row storage: `starts[section]..starts[section + 1]` indexes `records`.
#[derive(Debug)]
pub(super) struct RelocationCsr {
    pub(super) starts: Box<[u32]>,
    pub(super) records: Box<[RelocationRecord]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum ResolvedTargetKind {
    Section,
    Import,
    Absolute,
    Name,
    Diagnostic,
}

/// Canonical semantic outcome shared by section GC and final relocation application. `target` is
/// a SectionId for Section, a canonical NameId for Import/Absolute/Name, and a raw symbol index
/// for Diagnostic. `value` is the section-relative symbol value or selected ImportId.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct ResolvedTarget {
    pub(super) target: u32,
    pub(super) value: u32,
    pub(super) kind: ResolvedTargetKind,
    pub(super) flags: u8,
    pub(super) reserved: u16,
}

impl ResolvedTarget {
    const fn section(section: SectionId, value: u32) -> Self {
        Self {
            target: section.get(),
            value,
            kind: ResolvedTargetKind::Section,
            flags: 0,
            reserved: 0,
        }
    }

    const fn named(kind: ResolvedTargetKind, name: NameId, value: u32) -> Self {
        Self {
            target: name.get(),
            value,
            kind,
            flags: 0,
            reserved: 0,
        }
    }

    const fn diagnostic(raw_symbol: u32) -> Self {
        Self {
            target: raw_symbol,
            value: 0,
            kind: ResolvedTargetKind::Diagnostic,
            flags: 0,
            reserved: 0,
        }
    }

    pub(super) const fn section_id(self) -> Option<SectionId> {
        match self.kind {
            ResolvedTargetKind::Section => Some(SectionId::from_u32(self.target)),
            _ => None,
        }
    }

    pub(super) const fn name_id(self) -> Option<NameId> {
        match self.kind {
            ResolvedTargetKind::Import
            | ResolvedTargetKind::Absolute
            | ResolvedTargetKind::Name => Some(NameId::from_u32(self.target)),
            ResolvedTargetKind::Section | ResolvedTargetKind::Diagnostic => None,
        }
    }
}

#[derive(Debug)]
pub(super) struct ResolvedSymbolTargets {
    kinds: Box<[ResolvedTargetKind]>,
    targets: Box<[u32]>,
    values: Box<[u32]>,
    pub(super) names: Box<[ResolvedTarget]>,
}

impl ResolvedSymbolTargets {
    #[inline(always)]
    pub(super) fn kind_target(&self, symbol: SymbolId) -> Option<(ResolvedTargetKind, u32)> {
        let index = symbol.index();
        Some((*self.kinds.get(index)?, *self.targets.get(index)?))
    }

    #[inline(always)]
    pub(super) fn value(&self, symbol: SymbolId) -> Option<u32> {
        self.values.get(symbol.index()).copied()
    }

    #[inline(always)]
    pub(super) fn symbol(&self, symbol: SymbolId) -> Option<ResolvedTarget> {
        let index = symbol.index();
        Some(ResolvedTarget {
            kind: *self.kinds.get(index)?,
            target: *self.targets.get(index)?,
            value: *self.values.get(index)?,
            flags: 0,
            reserved: 0,
        })
    }

    pub(super) fn name(&self, name: NameId) -> Option<ResolvedTarget> {
        self.names.get(name.index()).copied()
    }
}

impl RelocationCsr {
    pub(super) fn range(&self, section: SectionId) -> Option<Range<usize>> {
        let next = section.index().checked_add(1)?;
        let start = *self.starts.get(section.index())? as usize;
        let end = *self.starts.get(next)? as usize;
        (start <= end && end <= self.records.len()).then_some(start..end)
    }

    pub(super) fn for_section(&self, section: SectionId) -> Option<&[RelocationRecord]> {
        self.records.get(self.range(section)?)
    }

    pub(super) fn is_well_formed(&self, section_count: usize) -> bool {
        self.starts.len() == section_count.saturating_add(1)
            && self.starts.first().copied() == Some(0)
            && self.starts.last().copied() == u32::try_from(self.records.len()).ok()
            && self.starts.windows(2).all(|pair| pair[0] <= pair[1])
    }
}

/// Immutable parsed input. Later phases own dense decisions, never another parsed-object view.
#[derive(Debug)]
pub(super) struct PeIr<'data> {
    pub(super) sources: SourceFiles<'data>,
    pub(super) names: Box<[NameRecord]>,
    pub(super) objects: Box<[ObjectRecord]>,
    pub(super) sections: Box<[SectionRecord]>,
    pub(super) symbols: Box<[SymbolRecord]>,
    pub(super) global_symbols: Box<[SymbolId]>,
    pub(super) relocations: RelocationCsr,
}

/// The selected-object IR and the one canonical namespace that assigned every name in it.
/// `occurrence_names` is flat in object order and then `CoffInputIndex::names` order.
pub(super) struct SelectedObjectFinalization<'data> {
    pub(super) ir: PeIr<'data>,
    pub(super) names: OrderedNameInterner<'data>,
    pub(super) occurrence_names: Box<[NameId]>,
}

#[derive(Clone, Copy)]
struct DenseObjectOffsets {
    section: u32,
    symbol: u32,
    name: usize,
    relocation: u32,
}

struct DenseObjectChunk {
    object: ObjectRecord,
    sections: Vec<SectionRecord>,
    symbols: Vec<SymbolRecord>,
    globals: Vec<SymbolId>,
    relocation_starts: Vec<u32>,
    relocations: Vec<RelocationRecord>,
}

impl<'data> PeIr<'data> {
    pub(super) fn resolve_symbol_targets(
        &self,
        symbols: &SymbolDb,
        alternate_targets: &[u32],
    ) -> ResolvedSymbolTargets {
        let names = (0..symbols.entries.len())
            .map(|index| {
                self.resolve_name_target(symbols, alternate_targets, NameId::from_u32(index as u32))
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let mut kinds = Vec::with_capacity(self.symbols.len());
        let mut targets = Vec::with_capacity(self.symbols.len());
        let mut values = Vec::with_capacity(self.symbols.len());
        for symbol in &self.symbols {
            let target = if symbol.diagnostic == SymbolDiagnostic::InvalidRelocationTarget {
                ResolvedTarget::diagnostic(symbol.raw_index)
            } else if symbol.flags & 1 == 0
                && let Some(section) = symbol.section.get()
            {
                u32::try_from(symbol.value).map_or_else(
                    |_| ResolvedTarget::diagnostic(symbol.raw_index),
                    |value| ResolvedTarget::section(section, value),
                )
            } else {
                names
                    .get(symbol.name.index())
                    .copied()
                    .unwrap_or_else(|| ResolvedTarget::diagnostic(symbol.raw_index))
            };
            kinds.push(target.kind);
            targets.push(target.target);
            values.push(target.value);
        }
        ResolvedSymbolTargets {
            kinds: kinds.into_boxed_slice(),
            targets: targets.into_boxed_slice(),
            values: values.into_boxed_slice(),
            names,
        }
    }

    fn resolve_name_target(
        &self,
        symbols: &SymbolDb,
        alternate_targets: &[u32],
        mut name: NameId,
    ) -> ResolvedTarget {
        for _ in 0..=symbols.entries.len() {
            let Some(entry) = symbols.entry(name) else {
                return ResolvedTarget::diagnostic(name.get());
            };
            if entry.resolution.state() == ResolutionState::Resolved {
                let Some(provider) = entry
                    .resolution
                    .provider()
                    .and_then(|provider| symbols.provider(provider))
                else {
                    return ResolvedTarget::diagnostic(name.get());
                };
                return match provider.kind() {
                    ProviderKind::ObjectSymbol => {
                        let Some(symbol) = self.symbols.get(provider.subject as usize) else {
                            return ResolvedTarget::diagnostic(name.get());
                        };
                        match symbol.section.get() {
                            Some(section) => u32::try_from(symbol.value).map_or_else(
                                |_| ResolvedTarget::diagnostic(symbol.raw_index),
                                |value| ResolvedTarget::section(section, value),
                            ),
                            None => ResolvedTarget::named(ResolvedTargetKind::Name, name, 0),
                        }
                    }
                    ProviderKind::Import => {
                        ResolvedTarget::named(ResolvedTargetKind::Import, name, provider.subject)
                    }
                    ProviderKind::Absolute | ProviderKind::LinkerDefined => {
                        ResolvedTarget::named(ResolvedTargetKind::Absolute, name, provider.subject)
                    }
                    ProviderKind::ArchiveMember => ResolvedTarget::diagnostic(name.get()),
                };
            }
            if let Some(fallback) = entry.weak_fallback() {
                name = fallback;
                continue;
            }
            let alternate = alternate_targets
                .get(name.index())
                .copied()
                .unwrap_or(u32::MAX);
            if alternate == u32::MAX {
                return ResolvedTarget::named(ResolvedTargetKind::Name, name, 0);
            }
            name = NameId::from_u32(alternate);
        }
        ResolvedTarget::diagnostic(name.get())
    }

    /// Authoritative raw COFF symbol to dense-symbol mapping within one selected object.
    pub(super) fn symbol_by_raw(&self, object: ObjectId, raw_symbol: u32) -> Option<SymbolId> {
        let object = self.objects.get(object.index())?;
        let start = object.symbols.start() as usize;
        let end = object.symbols.end()? as usize;
        let local = self.symbols.get(start..end)?;
        let offset = local
            .binary_search_by_key(&raw_symbol, |symbol| symbol.raw_index)
            .ok()?;
        Some(SymbolId::from_u32(u32::try_from(start + offset).ok()?))
    }

    /// Authoritative raw COFF section to dense-section mapping within one selected object.
    pub(super) fn section_by_raw(&self, object: ObjectId, raw_section: u32) -> Option<SectionId> {
        let object = self.objects.get(object.index())?;
        let start = object.sections.start() as usize;
        let end = object.sections.end()? as usize;
        let local = self.sections.get(start..end)?;
        let offset = local
            .binary_search_by_key(&raw_section, |section| section.raw_index)
            .ok()?;
        Some(SectionId::from_u32(u32::try_from(start + offset).ok()?))
    }

    /// Finalize selected objects in input order. The only allocations contain records, CSR starts,
    /// hash collision lists, and dense-ID maps; input payload and name bytes remain borrowed.
    pub(super) fn finalize_selected_objects(
        objects: &[CoffObject<'data>],
        seed: OrderedNameInterner<'data>,
    ) -> Result<SelectedObjectFinalization<'data>> {
        Self::finalize_selected_objects_with_globals(objects, seed, &[])
    }

    pub(super) fn finalize_selected_objects_with_globals(
        objects: &[CoffObject<'data>],
        seed: OrderedNameInterner<'data>,
        globals: &[ResolverGlobalName],
    ) -> Result<SelectedObjectFinalization<'data>> {
        let mut index_phase = crate::pe_timing_guard!("PE index: Finalize selected COFF objects");
        index_phase
            .0
            .add(crate::timing::PeMetric::Objects, objects.len());
        index_phase
            .0
            .add(crate::timing::PeMetric::Names, seed.len());
        let sources = SourceFiles::new(objects.iter().map(CoffObject::bytes).collect());
        let mut names_phase = crate::pe_timing_guard!("PE index: Canonicalize names");
        let (canonical_names, occurrence_names) = finalize_selected_names(objects, seed, globals)?;
        let names = name_records(objects, &canonical_names, &occurrence_names)?;
        names_phase
            .0
            .add(crate::timing::PeMetric::Objects, objects.len());
        names_phase
            .0
            .add(crate::timing::PeMetric::Names, occurrence_names.len());
        names_phase
            .0
            .add(crate::timing::PeMetric::Symbols, globals.len());
        drop(names_phase);
        let section_count = objects
            .iter()
            .try_fold(0usize, |count, object| {
                count.checked_add(object.index().sections().len())
            })
            .ok_or_else(|| crate::error!("Selected COFF section count overflow"))?;
        let symbol_count = objects
            .iter()
            .try_fold(0usize, |count, object| {
                count.checked_add(object.index().symbols().len())
            })
            .ok_or_else(|| crate::error!("Selected COFF symbol count overflow"))?;

        let mut records_phase =
            crate::pe_timing_guard!("PE index: Build dense records and relocation CSR");
        records_phase
            .0
            .add(crate::timing::PeMetric::Objects, objects.len());
        records_phase
            .0
            .add(crate::timing::PeMetric::Sections, section_count);
        records_phase
            .0
            .add(crate::timing::PeMetric::Names, symbol_count);
        // Prefix offsets are assigned once on the caller thread. Independent objects can then
        // build records concurrently without changing any externally visible dense ID or order.
        let mut offsets = Vec::with_capacity(objects.len());
        let (mut section_end, mut symbol_end, mut name_end, mut relocation_end) =
            (0u32, 0u32, 0usize, 0u32);
        for object in objects {
            let index = object.index();
            offsets.push(DenseObjectOffsets {
                section: section_end,
                symbol: symbol_end,
                name: name_end,
                relocation: relocation_end,
            });
            section_end = section_end
                .checked_add(as_u32(index.sections().len(), "selected section")?)
                .ok_or_else(|| crate::error!("Selected COFF section count overflow"))?;
            symbol_end = symbol_end
                .checked_add(as_u32(index.symbols().len(), "selected symbol")?)
                .ok_or_else(|| crate::error!("Selected COFF symbol count overflow"))?;
            name_end = name_end
                .checked_add(index.names().len())
                .ok_or_else(|| crate::error!("Selected COFF name count overflow"))?;
            relocation_end = relocation_end
                .checked_add(as_u32(
                    index
                        .sections()
                        .iter()
                        .map(|section| index.relocations(section).len())
                        .sum(),
                    "selected relocation",
                )?)
                .ok_or_else(|| crate::error!("Selected COFF relocation count overflow"))?;
        }
        crate::ensure!(
            name_end == occurrence_names.len(),
            "Selected COFF name prefix does not match canonical occurrences"
        );
        let chunks = objects
            .par_iter()
            .zip(offsets.par_iter().copied())
            .enumerate()
            .map(|(object_index, (object, offsets))| {
                build_dense_object_chunk(object_index, object, offsets, &occurrence_names)
            })
            .collect::<Vec<_>>();
        let mut object_records = Vec::with_capacity(objects.len());
        let mut sections = Vec::with_capacity(section_count);
        let mut symbols = Vec::with_capacity(symbol_count);
        let mut global_symbols = Vec::with_capacity(globals.len());
        let mut starts = Vec::with_capacity(section_count.saturating_add(1));
        starts.push(0);
        let mut relocations = Vec::with_capacity(relocation_end as usize);
        for chunk in chunks {
            let mut chunk = chunk?;
            object_records.push(chunk.object);
            sections.append(&mut chunk.sections);
            symbols.append(&mut chunk.symbols);
            global_symbols.append(&mut chunk.globals);
            starts.append(&mut chunk.relocation_starts);
            relocations.append(&mut chunk.relocations);
        }

        let relocations = RelocationCsr {
            starts: starts.into_boxed_slice(),
            records: relocations.into_boxed_slice(),
        };
        records_phase.0.add(
            crate::timing::PeMetric::Relocations,
            relocations.records.len(),
        );
        index_phase
            .0
            .add(crate::timing::PeMetric::Sections, section_count);
        index_phase
            .0
            .set(crate::timing::PeMetric::Names, canonical_names.len());
        index_phase.0.add(
            crate::timing::PeMetric::Relocations,
            relocations.records.len(),
        );
        drop(records_phase);
        let ir = Self {
            sources,
            names: names.into_boxed_slice(),
            objects: object_records.into_boxed_slice(),
            sections: sections.into_boxed_slice(),
            symbols: symbols.into_boxed_slice(),
            global_symbols: global_symbols.into_boxed_slice(),
            relocations,
        };
        Ok(SelectedObjectFinalization {
            ir,
            names: canonical_names,
            occurrence_names,
        })
    }

    /// Name decoding is intentionally deferred to the first semantic consumer. This is what keeps
    /// malformed names in discarded sections from changing the link's diagnostic behavior.
    pub(super) fn name_bytes(&self, name: NameId) -> Result<&[u8]> {
        let record = self
            .names
            .get(name.index())
            .ok_or_else(|| crate::error!("Invalid dense PE name ID {}", name.get()))?;
        let source = record
            .source
            .ok_or_else(|| crate::error!("Invalid COFF name offset"))?;
        self.sources
            .bytes(source)
            .ok_or_else(|| crate::error!("Invalid source-backed COFF name range"))
    }

    /// Validate a relocation target only when a live consumer follows the edge. Indexing itself
    /// deliberately does not turn malformed targets in discarded sections into errors.
    pub(super) fn relocation_target(&self, relocation: RelocationRecord) -> Result<&SymbolRecord> {
        let target = self
            .symbols
            .get(relocation.target.index())
            .ok_or_else(|| crate::error!("Invalid dense PE relocation target"))?;
        if target.diagnostic == SymbolDiagnostic::InvalidRelocationTarget {
            return Err(crate::error!(
                "Invalid COFF relocation symbol {}",
                target.raw_index
            ));
        }
        Ok(target)
    }
}

fn build_dense_object_chunk(
    object_index: usize,
    object: &CoffObject<'_>,
    offsets: DenseObjectOffsets,
    occurrence_names: &[NameId],
) -> Result<DenseObjectChunk> {
    let object_id = ObjectId::from_u32(as_u32(object_index, "selected object")?);
    let index = object.index();
    let local_names = occurrence_names
        .get(offsets.name..offsets.name + index.names().len())
        .ok_or_else(|| crate::error!("Missing selected COFF name occurrence mapping"))?;
    let mut sections = Vec::with_capacity(index.sections().len());
    let mut symbols = Vec::with_capacity(index.symbols().len());
    let mut globals = Vec::new();
    let mut relocation_starts = Vec::with_capacity(index.sections().len());
    let mut relocations = Vec::new();
    for section in index.sections() {
        let data = section.data_range.map(|range| SourceRange {
            file: FileId::from_u32(object_id.get()),
            start: range.start,
            len: range.len,
        });
        let associative_section = if section.associative_section == u32::MAX {
            OptionalSectionId::NONE
        } else {
            OptionalSectionId::some(section_from_raw(
                offsets.section,
                object::SectionIndex(section.associative_section as usize),
            )?)
        };
        let comdat_leader = if section.comdat_leader == u32::MAX {
            OptionalSymbolId::NONE
        } else {
            OptionalSymbolId::some(
                offsets
                    .symbol
                    .checked_add(section.comdat_leader)
                    .map(SymbolId::from_u32)
                    .ok_or_else(|| crate::error!("Selected COFF COMDAT leader ID overflow"))?,
            )
        };
        sections.push(SectionRecord {
            object: object_id,
            raw_index: as_u32(section.index.0, "raw COFF section")?,
            name: local_names[section.name.0 as usize],
            data,
            size: u32::try_from(section.size)
                .map_err(|_| crate::error!("COFF section size exceeds u32"))?,
            alignment: u32::try_from(section.align)
                .map_err(|_| crate::error!("COFF section alignment exceeds u32"))?,
            characteristics: section.characteristics.unwrap_or(0),
            contents: section_contents(section.kind),
            comdat_selection: section.comdat_selection,
            associative_section,
            comdat_leader,
            comdat_order: section.comdat_order,
        });
        for relocation in index.relocations(section) {
            relocations.push(RelocationRecord {
                offset: relocation.offset,
                target: SymbolId::from_u32(
                    offsets
                        .symbol
                        .checked_add(relocation.symbol.0)
                        .ok_or_else(|| {
                            crate::error!("Selected COFF relocation symbol ID overflow")
                        })?,
                ),
                typ: relocation.typ,
                flags: 0,
            });
        }
        relocation_starts.push(
            offsets
                .relocation
                .checked_add(as_u32(relocations.len(), "selected relocation")?)
                .ok_or_else(|| crate::error!("Selected COFF relocation count overflow"))?,
        );
    }
    for (local_symbol, symbol) in index.symbols().iter().enumerate() {
        let section = symbol
            .shape
            .as_ref()
            .and_then(|shape| shape.section)
            .map(|raw| section_from_raw(offsets.section, raw))
            .transpose()?
            .map_or(OptionalSectionId::NONE, OptionalSectionId::some);
        let weak_default = symbol
            .weak_default
            .map(|local| {
                offsets
                    .symbol
                    .checked_add(local.0)
                    .map(SymbolId::from_u32)
                    .ok_or_else(|| crate::error!("Selected COFF weak symbol ID overflow"))
            })
            .transpose()?
            .map_or(OptionalSymbolId::NONE, OptionalSymbolId::some);
        let shape = symbol.shape.as_ref();
        let flags = u16::from(shape.is_some_and(|shape| shape.is_global))
            | (u16::from(shape.is_some_and(|shape| shape.is_common)) << 1)
            | (u16::from(shape.is_some_and(|shape| shape.is_weak)) << 2)
            | (u16::from(shape.is_some_and(|shape| shape.is_definition)) << 3)
            | (u16::from(shape.is_some_and(|shape| shape.is_undefined)) << 4)
            | (u16::from(shape.is_some_and(|shape| shape.is_absolute)) << 5);
        if flags & SymbolRecord::GLOBAL != 0 {
            globals.push(SymbolId::from_u32(
                offsets
                    .symbol
                    .checked_add(as_u32(local_symbol, "selected global symbol")?)
                    .ok_or_else(|| crate::error!("Selected global symbol ID overflow"))?,
            ));
        }
        symbols.push(SymbolRecord {
            object: object_id,
            raw_index: symbol.raw_index,
            name: symbol
                .name
                .get()
                .map_or(NameId::from_u32(u32::MAX), |name| local_names[name]),
            section,
            value: u64::from(symbol.value),
            size: symbol.size,
            flags,
            storage_class: symbol.storage_class,
            typ: symbol.typ,
            weak_default,
            diagnostic: if symbol.shape.is_some() {
                SymbolDiagnostic::None
            } else {
                SymbolDiagnostic::InvalidRelocationTarget
            },
        });
    }
    Ok(DenseObjectChunk {
        object: ObjectRecord {
            file: FileId::from_u32(as_u32(object_index, "source file")?),
            sections: DenseRange::new(offsets.section, as_u32(sections.len(), "selected section")?),
            symbols: DenseRange::new(offsets.symbol, as_u32(symbols.len(), "selected symbol")?),
            input_ordinal: as_u32(object_index, "input ordinal")?,
        },
        sections,
        symbols,
        globals,
        relocation_starts,
        relocations,
    })
}

fn finalize_selected_names<'data>(
    objects: &[CoffObject<'data>],
    mut names: OrderedNameInterner<'data>,
    globals: &[ResolverGlobalName],
) -> Result<(OrderedNameInterner<'data>, Box<[NameId]>)> {
    let occurrence_count = objects
        .iter()
        .try_fold(0usize, |count, object| {
            count.checked_add(object.index().names().len())
        })
        .ok_or_else(|| crate::error!("Selected COFF name occurrence count overflow"))?;
    let mut occurrence_names = Vec::with_capacity(occurrence_count);
    let mut global_position = 0usize;
    let mut known = Vec::new();
    for (object_index, object) in objects.iter().enumerate() {
        let index = object.index();
        known.clear();
        while let Some(global) = globals.get(global_position) {
            if global.object as usize != object_index {
                break;
            }
            let occurrence = usize::try_from(global.name_occurrence)
                .map_err(|_| crate::error!("Resolver name occurrence exceeds usize"))?;
            let name_occurrence = index
                .symbols()
                .get(occurrence)
                .and_then(|symbol| symbol.name.get())
                .ok_or_else(|| crate::error!("Resolver global has no indexed COFF symbol name"))?;
            known.push((name_occurrence, global.name));
            global_position += 1;
        }
        let mut known = known.iter().copied().peekable();
        for (local_name, occurrence) in index.names().iter().copied().enumerate() {
            if let Some((_, name)) = known.next_if(|(occurrence, _)| *occurrence == local_name) {
                occurrence_names.push(name);
                continue;
            }
            let name = if let Some(source) = occurrence.source() {
                let end = source
                    .start
                    .checked_add(source.len)
                    .ok_or_else(|| crate::error!("Object-local COFF name range overflow"))?;
                let bytes = object
                    .bytes()
                    .get(source.start as usize..end as usize)
                    .ok_or_else(|| crate::error!("Invalid object-local COFF name range"))?;
                names.intern_borrowed_prehashed(bytes, occurrence.hash_or_compute(bytes))
            } else {
                let diagnostic = match occurrence.deferred_error() {
                    Some(CoffDeferredNameError::InvalidNameOffset) => {
                        DeferredInvalidName::CoffNameOffset
                    }
                    Some(CoffDeferredNameError::InvalidRelocationSymbol) => {
                        DeferredInvalidName::RelocationSymbol
                    }
                    None => return Err(crate::error!("Missing deferred COFF name diagnostic")),
                };
                names.intern_invalid(diagnostic)
            };
            occurrence_names.push(name);
        }
    }
    if global_position != globals.len() {
        return Err(crate::error!(
            "Resolver globals are not ordered by selected COFF object"
        ));
    }
    Ok((names, occurrence_names.into_boxed_slice()))
}

fn name_records<'data>(
    objects: &[CoffObject<'data>],
    interner: &OrderedNameInterner<'data>,
    occurrence_names: &[NameId],
) -> Result<Vec<NameRecord>> {
    let mut records = (0..interner.len())
        .map(|index| {
            let id = NameId::from_u32(index as u32);
            NameRecord {
                source: None,
                hash: interner.hash(id).unwrap_or(0),
            }
        })
        .collect::<Vec<_>>();
    let mut mapped = occurrence_names.iter().copied();
    for (object_index, object) in objects.iter().enumerate() {
        let file = FileId::from_u32(as_u32(object_index, "source file")?);
        for occurrence in object.index().names() {
            let id = mapped
                .next()
                .ok_or_else(|| crate::error!("Missing selected COFF name occurrence mapping"))?;
            if records[id.index()].source.is_none() {
                records[id.index()].source = occurrence.source().map(|source| SourceRange {
                    file,
                    start: source.start,
                    len: source.len,
                });
            }
        }
    }
    if mapped.next().is_some() {
        return Err(crate::error!(
            "Excess selected COFF name occurrence mapping"
        ));
    }
    Ok(records)
}

fn section_from_raw(start: u32, raw: object::SectionIndex) -> Result<SectionId> {
    let local = raw
        .0
        .checked_sub(1)
        .ok_or_else(|| crate::error!("Invalid COFF section index 0"))?;
    Ok(SectionId::from_u32(
        start
            .checked_add(as_u32(local, "raw COFF section")?)
            .ok_or_else(|| crate::error!("Selected COFF section ID overflow"))?,
    ))
}

fn section_contents(kind: object::SectionKind) -> SectionContents {
    match kind {
        object::SectionKind::Text => SectionContents::Code,
        object::SectionKind::UninitializedData => SectionContents::Uninitialized,
        object::SectionKind::Data | object::SectionKind::ReadOnlyData => SectionContents::Data,
        _ => SectionContents::Metadata,
    }
}

fn as_u32(value: usize, what: &str) -> Result<u32> {
    u32::try_from(value).map_err(|_| crate::error!("{what} count exceeds u32"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::Object as _;
    use object::ObjectSection as _;
    use object::write::Object as WritableObject;
    use object::write::Relocation;
    use object::write::Symbol;
    use object::write::SymbolSection;

    fn selected_fixture() -> Vec<u8> {
        let mut object = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let text = object.add_section(
            Vec::new(),
            b".text$long_selected_fixture".to_vec(),
            object::SectionKind::Text,
        );
        object.append_section_data(text, &[0, 0, 0, 0, 0, 0, 0, 0], 1);
        object.add_symbol(Symbol {
            name: b"long_selected_definition".to_vec(),
            value: 0,
            size: 8,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(text),
            flags: object::SymbolFlags::None,
        });
        let target = object.add_symbol(Symbol {
            name: b"shared_long_target_name".to_vec(),
            value: 0,
            size: 0,
            kind: object::SymbolKind::Unknown,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Undefined,
            flags: object::SymbolFlags::None,
        });
        for offset in [0, 4] {
            object
                .add_relocation(
                    text,
                    Relocation {
                        offset,
                        symbol: target,
                        addend: 0,
                        flags: object::RelocationFlags::Coff {
                            typ: object::pe::IMAGE_REL_AMD64_REL32,
                        },
                    },
                )
                .unwrap();
        }
        object.write().unwrap()
    }

    fn first_relocation_offset(bytes: &[u8]) -> usize {
        u32::from_le_bytes(bytes[44..48].try_into().unwrap()) as usize
    }

    #[test]
    fn dense_ids_and_relocation_csr_have_the_frozen_shape() {
        assert_eq!(std::mem::size_of::<SectionId>(), 4);
        assert_eq!(std::mem::size_of::<RelocationRecord>(), 12);
        assert_eq!(std::mem::size_of::<super::ResolverGlobalName>(), 12);
        let csr = RelocationCsr {
            starts: vec![0, 1, 1].into_boxed_slice(),
            records: vec![RelocationRecord {
                offset: 4,
                target: SymbolId::from_u32(3),
                typ: 1,
                flags: 0,
            }]
            .into_boxed_slice(),
        };
        assert!(csr.is_well_formed(2));
        assert_eq!(csr.for_section(SectionId::from_u32(0)).unwrap().len(), 1);
        assert!(csr.for_section(SectionId::from_u32(1)).unwrap().is_empty());
        assert!(csr.for_section(SectionId::from_u32(2)).is_none());
    }

    #[test]
    fn selected_objects_finalize_source_backed_names_and_csr_once() {
        let first = selected_fixture();
        let second = selected_fixture();
        let objects = [
            CoffObject::parse(&first).unwrap(),
            CoffObject::parse(&second).unwrap(),
        ];
        let finalized =
            PeIr::finalize_selected_objects(&objects, OrderedNameInterner::new()).unwrap();
        let ir = &finalized.ir;
        assert!(
            ir.global_symbols
                .iter()
                .all(|&id| ir.symbols[id.index()].is_global())
        );
        assert_eq!(
            ir.global_symbols.len(),
            ir.symbols
                .iter()
                .filter(|symbol| symbol.is_global())
                .count()
        );
        assert_eq!(ir.objects.len(), 2);
        assert_eq!(ir.sections.len(), 2);
        assert_eq!(ir.symbols.len(), 4);
        assert!(ir.relocations.is_well_formed(2));
        assert_eq!(
            ir.relocations
                .for_section(SectionId::from_u32(0))
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            ir.relocations
                .for_section(SectionId::from_u32(1))
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            ir.name_bytes(ir.symbols[1].name).unwrap(),
            b"shared_long_target_name"
        );
        assert_eq!(ir.symbols[1].name, ir.symbols[3].name);
        let mut occurrence_start = 0;
        for (object_index, object) in objects.iter().enumerate() {
            let index = object.index();
            let local = &finalized.occurrence_names
                [occurrence_start..occurrence_start + index.names().len()];
            let object_record = ir.objects[object_index];
            for (local_symbol, symbol) in index.symbols().iter().enumerate() {
                let dense = ir.symbols[object_record.symbols.start() as usize + local_symbol].name;
                if let Some(name) = symbol.name.get() {
                    assert_eq!(dense, local[name]);
                } else {
                    assert_eq!(dense, NameId::from_u32(u32::MAX));
                }
            }
            for (local_section, section) in index.sections().iter().enumerate() {
                assert_eq!(
                    ir.sections[object_record.sections.start() as usize + local_section].name,
                    local[section.name.0 as usize]
                );
            }
            occurrence_start += index.names().len();
        }
        assert_eq!(occurrence_start, finalized.occurrence_names.len());
        let data = ir.sections[0].data.unwrap();
        assert_eq!(
            ir.sources.bytes(data).unwrap(),
            objects[0].file().sections().next().unwrap().data().unwrap()
        );
        let first_target = ir.relocations.records[0].target;
        assert_eq!(first_target, ir.relocations.records[1].target);
        assert_eq!(
            ir.relocation_target(ir.relocations.records[0])
                .unwrap()
                .name,
            ir.symbols[1].name
        );
    }

    #[test]
    fn parallel_dense_chunks_are_identical_at_one_and_twenty_threads() {
        let bytes = (0..24).map(|_| selected_fixture()).collect::<Vec<_>>();
        let objects = bytes
            .iter()
            .map(|bytes| CoffObject::parse(bytes).unwrap())
            .collect::<Vec<_>>();
        let finalize = |threads| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| {
                    PeIr::finalize_selected_objects(&objects, OrderedNameInterner::new()).unwrap()
                })
        };
        let one = finalize(1);
        let twenty = finalize(20);
        assert_eq!(one.ir.objects, twenty.ir.objects);
        assert_eq!(one.ir.sections, twenty.ir.sections);
        assert_eq!(one.ir.symbols, twenty.ir.symbols);
        assert_eq!(one.ir.global_symbols, twenty.ir.global_symbols);
        assert_eq!(one.ir.names, twenty.ir.names);
        assert_eq!(one.ir.relocations.starts, twenty.ir.relocations.starts);
        assert_eq!(one.ir.relocations.records, twenty.ir.relocations.records);
        assert_eq!(one.occurrence_names, twenty.occurrence_names);
    }

    #[test]
    fn selected_objects_append_to_seed_without_renumbering_roots() {
        let bytes = selected_fixture();
        let objects = [CoffObject::parse(&bytes).unwrap()];
        let target = b"shared_long_target_name";
        let target_hash = crate::hash::hash_bytes(target);
        let mut seed = OrderedNameInterner::new();
        let target_id = seed.intern_borrowed_prehashed(target, target_hash);
        let root_id = seed.intern_borrowed_prehashed(b"command-line-root", 17);

        let finalized = PeIr::finalize_selected_objects(&objects, seed).unwrap();
        assert_eq!(target_id, NameId::from_u32(0));
        assert_eq!(root_id, NameId::from_u32(1));
        assert_eq!(finalized.ir.symbols[1].name, target_id);
        assert_eq!(
            finalized.names.lookup_prehashed(target, target_hash),
            Some(target_id)
        );
        assert_eq!(
            finalized.names.bytes(root_id),
            Some(b"command-line-root".as_slice())
        );
    }

    #[test]
    fn discarded_malformed_edge_stays_deferred_until_live_target_lookup() {
        let mut bytes = selected_fixture();
        let relocation = first_relocation_offset(&bytes);
        bytes[relocation + 4..relocation + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        let objects = [CoffObject::parse(&bytes).unwrap()];
        let finalized =
            PeIr::finalize_selected_objects(&objects, OrderedNameInterner::new()).unwrap();
        let ir = &finalized.ir;
        let malformed = ir.relocations.records[0];

        // A discarded source never asks for its target, so construction alone is the non-error
        // half of the diagnostic contract. A live source crosses the boundary here.
        let error = ir.relocation_target(malformed).unwrap_err();
        assert!(format!("{error:?}").contains("Invalid COFF relocation symbol"));
        assert!(ir.relocation_target(ir.relocations.records[1]).is_ok());
    }
}
