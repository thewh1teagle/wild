//! Dense, source-backed intermediate representation for the PE/COFF linker.
//!
//! Selected `CoffObject`s have already crossed the sole generic-object parsing boundary. This
//! module concatenates their immutable local indices, assigns dense global IDs, and finalizes
//! canonical names in deterministic object/occurrence order without copying name or section bytes.

#![allow(dead_code)]

use super::pe_symbol_db::{
    DeferredInvalidName, OrderedNameInterner, OrderedNameOccurrence, finalize_ordered_names_with,
};
use crate::coff::{CoffDeferredNameError, CoffObject};
use crate::error::Result;
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
    pub(super) relocations: RelocationCsr,
}

/// The selected-object IR and the one canonical namespace that assigned every name in it.
/// `occurrence_names` is flat in object order and then `CoffInputIndex::names` order.
pub(super) struct SelectedObjectFinalization<'data> {
    pub(super) ir: PeIr<'data>,
    pub(super) names: OrderedNameInterner<'data>,
    pub(super) occurrence_names: Box<[NameId]>,
}

impl<'data> PeIr<'data> {
    /// Finalize selected objects in input order. The only allocations contain records, CSR starts,
    /// hash collision lists, and dense-ID maps; input payload and name bytes remain borrowed.
    pub(super) fn finalize_selected_objects(
        objects: &[CoffObject<'data>],
        seed: OrderedNameInterner<'data>,
    ) -> Result<SelectedObjectFinalization<'data>> {
        let sources = SourceFiles::new(objects.iter().map(CoffObject::bytes).collect());
        let ordered_occurrences = ordered_name_occurrences(objects)?;
        let finalized = finalize_ordered_names_with(seed, ordered_occurrences);
        let names = name_records(objects, &finalized.names, &finalized.occurrence_names)?;
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

        let mut object_records = Vec::with_capacity(objects.len());
        let mut sections = Vec::with_capacity(section_count);
        let mut symbols = Vec::with_capacity(symbol_count);
        let mut starts = Vec::with_capacity(section_count.saturating_add(1));
        let mut relocations = Vec::new();
        starts.push(0);

        let mut occurrence_start = 0usize;
        for (object_index, object) in objects.iter().enumerate() {
            let object_id = ObjectId::from_u32(as_u32(object_index, "selected object")?);
            let section_start = as_u32(sections.len(), "selected section")?;
            let symbol_start = as_u32(symbols.len(), "selected symbol")?;
            let index = object.index();
            let occurrence_end = occurrence_start
                .checked_add(index.names().len())
                .ok_or_else(|| crate::error!("Selected COFF name occurrence count overflow"))?;
            let local_names = finalized
                .occurrence_names
                .get(occurrence_start..occurrence_end)
                .ok_or_else(|| crate::error!("Missing selected COFF name occurrence mapping"))?;
            occurrence_start = occurrence_end;

            for section in index.sections() {
                let data = section.data_range.map(|range| SourceRange {
                    file: FileId::from_u32(object_id.get()),
                    start: range.start,
                    len: range.len,
                });
                let associative_section = section
                    .associative_section
                    .map(|raw| section_from_raw(section_start, raw))
                    .transpose()?
                    .map_or(OptionalSectionId::NONE, OptionalSectionId::some);
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
                });
                for relocation in index.relocations(section) {
                    relocations.push(RelocationRecord {
                        offset: relocation.offset,
                        target: SymbolId::from_u32(
                            symbol_start
                                .checked_add(relocation.symbol.0)
                                .ok_or_else(|| {
                                    crate::error!("Selected COFF relocation symbol ID overflow")
                                })?,
                        ),
                        typ: relocation.typ,
                        flags: 0,
                    });
                }
                starts.push(as_u32(relocations.len(), "selected relocation")?);
            }

            for symbol in index.symbols() {
                let section = symbol
                    .shape
                    .as_ref()
                    .and_then(|shape| shape.section)
                    .map(|raw| section_from_raw(section_start, raw))
                    .transpose()?
                    .map_or(OptionalSectionId::NONE, OptionalSectionId::some);
                let weak_default = symbol
                    .weak_default
                    .map(|local| {
                        symbol_start
                            .checked_add(local.0)
                            .map(SymbolId::from_u32)
                            .ok_or_else(|| crate::error!("Selected COFF weak symbol ID overflow"))
                    })
                    .transpose()?
                    .map_or(OptionalSymbolId::NONE, OptionalSymbolId::some);
                let shape = symbol.shape.as_ref();
                let flags = u16::from(shape.is_some_and(|shape| shape.is_global))
                    | (u16::from(shape.is_some_and(|shape| shape.is_common)) << 1)
                    | (u16::from(shape.is_some_and(|shape| shape.is_weak)) << 2);
                symbols.push(SymbolRecord {
                    object: object_id,
                    raw_index: symbol.raw_index,
                    name: local_names[symbol.name.0 as usize],
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

            object_records.push(ObjectRecord {
                file: FileId::from_u32(as_u32(object_index, "source file")?),
                sections: DenseRange::new(
                    section_start,
                    as_u32(sections.len(), "selected section")? - section_start,
                ),
                symbols: DenseRange::new(
                    symbol_start,
                    as_u32(symbols.len(), "selected symbol")? - symbol_start,
                ),
                input_ordinal: as_u32(object_index, "input ordinal")?,
            });
        }

        let relocations = RelocationCsr {
            starts: starts.into_boxed_slice(),
            records: relocations.into_boxed_slice(),
        };
        let ir = Self {
            sources,
            names: names.into_boxed_slice(),
            objects: object_records.into_boxed_slice(),
            sections: sections.into_boxed_slice(),
            symbols: symbols.into_boxed_slice(),
            relocations,
        };
        Ok(SelectedObjectFinalization {
            ir,
            names: finalized.names,
            occurrence_names: finalized.occurrence_names,
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

fn ordered_name_occurrences<'data>(
    objects: &[CoffObject<'data>],
) -> Result<Vec<OrderedNameOccurrence<'data>>> {
    let occurrence_count = objects
        .iter()
        .try_fold(0usize, |count, object| {
            count.checked_add(object.index().names().len())
        })
        .ok_or_else(|| crate::error!("Selected COFF name occurrence count overflow"))?;
    let mut ordered = Vec::with_capacity(occurrence_count);
    for object in objects {
        for occurrence in object.index().names() {
            if let Some(source) = occurrence.source() {
                let end = source
                    .start
                    .checked_add(source.len)
                    .ok_or_else(|| crate::error!("Object-local COFF name range overflow"))?;
                let bytes = object
                    .bytes()
                    .get(source.start as usize..end as usize)
                    .ok_or_else(|| crate::error!("Invalid object-local COFF name range"))?;
                ordered.push(OrderedNameOccurrence::valid(bytes, occurrence.hash()));
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
                ordered.push(OrderedNameOccurrence::invalid(diagnostic));
            }
        }
    }
    Ok(ordered)
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
                assert_eq!(
                    ir.symbols[object_record.symbols.start() as usize + local_symbol].name,
                    local[symbol.name.0 as usize]
                );
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
