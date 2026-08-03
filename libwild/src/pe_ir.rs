//! Dense, source-backed intermediate representation for the PE/COFF linker.
//!
//! This module freezes the ownership and indexing boundary used by the Goal 3 migration. It is
//! intentionally not wired into the current writer yet.

#![allow(dead_code)]

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
    pub(super) source: SourceRange,
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
    pub(super) name: NameId,
    pub(super) data: Option<SourceRange>,
    pub(super) size: u32,
    pub(super) alignment: u32,
    pub(super) characteristics: u32,
    pub(super) contents: SectionContents,
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
    pub(super) name: NameId,
    pub(super) section: OptionalSectionId,
    pub(super) value: u64,
    pub(super) size: u32,
    pub(super) flags: u16,
    pub(super) storage_class: u8,
    pub(super) reserved: u8,
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

impl PeIr<'_> {
    pub(super) fn name_bytes(&self, name: NameId) -> Option<&[u8]> {
        self.sources.bytes(self.names.get(name.index())?.source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
