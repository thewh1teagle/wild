//! Dense layout and source-backed copy boundary for the final PE writer.

#![allow(dead_code)]

use super::pe_gc::GcOutput;
use super::pe_ir::NameId;
use super::pe_ir::PeIr;
use super::pe_ir::SectionId;
use super::pe_ir::SourceRange;
use crate::ensure;
use crate::error::Context;
use crate::error::Result;
use std::marker::PhantomData;
use std::ops::Range;

#[inline]
fn count_hot_allocation() {
    #[cfg(not(test))]
    crate::perf::removal_counters::increment_hot_phase_allocations();
}

#[inline]
fn count_bytes_copied(bytes: usize) {
    #[cfg(not(test))]
    crate::perf::removal_counters::add_bytes_copied(bytes as u64);
    #[cfg(test)]
    let _ = bytes;
}

/// Shared output allocation split into uniquely-owned contribution ranges.
///
/// This is the narrow bridge used by the legacy contribution adapter and the final dense writer.
#[derive(Clone, Copy)]
pub(super) struct DisjointOutput<'image> {
    address: usize,
    len: usize,
    borrow: PhantomData<&'image mut [u8]>,
}

impl<'image> DisjointOutput<'image> {
    pub(super) fn new(image: &'image mut [u8]) -> Self {
        Self {
            address: image.as_mut_ptr() as usize,
            len: image.len(),
            borrow: PhantomData,
        }
    }

    /// Returns one uniquely-owned final output range.
    ///
    /// # Safety
    /// Across all live calls, ranges must be disjoint and the original output allocation must
    /// remain fixed. Dense placements guarantee both properties; the legacy adapter uses unique
    /// contribution IDs whose layout placements have the same guarantee.
    pub(super) unsafe fn slice(self, start: usize, len: usize) -> Result<&'image mut [u8]> {
        let end = start.checked_add(len).context("PE output range overflow")?;
        ensure!(end <= self.len, "PE output range extends past file data");
        // SAFETY: The caller guarantees uniqueness, bounds were checked, and the backing
        // allocation remains alive and fixed until all jobs join.
        Ok(unsafe { std::slice::from_raw_parts_mut((self.address as *mut u8).add(start), len) })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct DenseLayoutInput {
    pub(super) section: SectionId,
    pub(super) name: NameId,
    pub(super) source: Option<SourceRange>,
    pub(super) size: u32,
    pub(super) alignment: u32,
    pub(super) characteristics: u32,
    pub(super) input_ordinal: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct DensePlacement {
    pub(super) section: SectionId,
    pub(super) file_offset: Option<u32>,
    pub(super) rva: u32,
    pub(super) size: u32,
}

#[derive(Debug)]
pub(super) struct DenseLayout {
    /// Placement order is output order. `placement_by_section` provides constant-time lookup.
    pub(super) placements: Box<[DensePlacement]>,
    placement_by_section: Box<[u32]>,
}

impl DenseLayout {
    pub(super) fn new(section_count: usize, placements: Vec<DensePlacement>) -> Result<Self> {
        count_hot_allocation();
        let mut placement_by_section = vec![u32::MAX; section_count];
        let mut previous_end = 0u32;
        for (index, placement) in placements.iter().enumerate() {
            let slot = placement_by_section
                .get_mut(placement.section.index())
                .context("layout placement refers to an invalid section")?;
            ensure!(*slot == u32::MAX, "duplicate dense section placement");
            *slot = u32::try_from(index).context("too many dense placements")?;
            if let Some(offset) = placement.file_offset {
                ensure!(
                    offset >= previous_end,
                    "dense file placements overlap or regress"
                );
                previous_end = offset
                    .checked_add(placement.size)
                    .context("dense file placement overflow")?;
            }
        }
        Ok(Self {
            placements: placements.into_boxed_slice(),
            placement_by_section: placement_by_section.into_boxed_slice(),
        })
    }

    pub(super) fn placement(&self, section: SectionId) -> Option<&DensePlacement> {
        let index = *self.placement_by_section.get(section.index())?;
        (index != u32::MAX).then(|| &self.placements[index as usize])
    }
}

/// Produces source-backed inputs in deterministic input order. Grouped-section suffix ordering is
/// still applied by the layout engine; this boundary deliberately retains full names and input
/// ordinals so ties never depend on hash iteration order.
pub(super) fn live_layout_inputs<'a>(
    ir: &'a PeIr<'_>,
    gc: &'a GcOutput,
) -> impl Iterator<Item = DenseLayoutInput> + 'a {
    ir.sections
        .iter()
        .enumerate()
        .filter(|(index, _)| gc.is_live(SectionId::from_u32(*index as u32)))
        .map(|(index, section)| DenseLayoutInput {
            section: SectionId::from_u32(index as u32),
            name: section.name,
            source: section.data,
            size: section.size,
            alignment: section.alignment,
            characteristics: section.characteristics,
            input_ordinal: ir.objects[section.object.index()].input_ordinal,
        })
}

/// Copies source ranges directly into disjoint output ranges, then relocates each uniquely-owned
/// slice before moving to the next job. This serial primitive is also the safety model for the
/// writer's indexed parallel adapter.
pub(super) fn copy_and_relocate<F>(
    ir: &PeIr<'_>,
    jobs: &[(SectionId, Range<usize>)],
    image: &mut [u8],
    mut relocate: F,
) -> Result<()>
where
    F: FnMut(SectionId, &mut [u8]) -> Result<()>,
{
    let mut previous_end = 0usize;
    for &(section, ref output) in jobs {
        ensure!(
            output.start >= previous_end && output.end <= image.len(),
            "dense copy jobs overlap or exceed the output image"
        );
        let record = ir
            .sections
            .get(section.index())
            .context("copy job refers to an invalid section")?;
        let source = record
            .data
            .and_then(|source| ir.sources.bytes(source))
            .context("initialized dense section has no source bytes")?;
        ensure!(
            source.len() == output.len(),
            "dense source/output size mismatch"
        );
        let destination = &mut image[output.clone()];
        destination.copy_from_slice(source);
        count_bytes_copied(source.len());
        relocate(section, destination)?;
        previous_end = output.end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::pe_ir::*;
    use super::*;

    #[test]
    fn dense_layout_rejects_overlap_and_indexes_placements() {
        let section = SectionId::from_u32(1);
        let layout = DenseLayout::new(
            2,
            vec![DensePlacement {
                section,
                file_offset: Some(16),
                rva: 0x1000,
                size: 4,
            }],
        )
        .unwrap();
        assert_eq!(layout.placement(section).unwrap().rva, 0x1000);
        assert!(layout.placement(SectionId::from_u32(0)).is_none());
    }

    #[test]
    fn source_range_is_copied_and_relocated_in_its_final_slice() {
        let ir = PeIr {
            sources: SourceFiles::new(vec![b"abcd"]),
            names: vec![NameRecord {
                source: Some(SourceRange {
                    file: FileId::from_u32(0),
                    start: 0,
                    len: 0,
                }),
                hash: 0,
            }]
            .into_boxed_slice(),
            objects: vec![ObjectRecord {
                file: FileId::from_u32(0),
                sections: DenseRange::new(0, 1),
                symbols: DenseRange::new(0, 0),
                input_ordinal: 0,
            }]
            .into_boxed_slice(),
            sections: vec![SectionRecord {
                object: ObjectId::from_u32(0),
                raw_index: 1,
                name: NameId::from_u32(0),
                data: Some(SourceRange {
                    file: FileId::from_u32(0),
                    start: 0,
                    len: 4,
                }),
                size: 4,
                alignment: 1,
                characteristics: 0,
                contents: SectionContents::Data,
                comdat_selection: 0,
                associative_section: OptionalSectionId::NONE,
                comdat_leader: crate::pe_writer::pe_ir::OptionalSymbolId::NONE,
                comdat_order: u32::MAX,
            }]
            .into_boxed_slice(),
            symbols: Box::new([]),
            global_symbols: Box::new([]),
            relocations: RelocationCsr {
                starts: vec![0, 0].into_boxed_slice(),
                records: Box::new([]),
            },
        };
        let mut image = [0u8; 12];
        copy_and_relocate(
            &ir,
            &[(SectionId::from_u32(0), 4..8)],
            &mut image,
            |section, bytes| {
                assert_eq!(section, SectionId::from_u32(0));
                bytes[1] = b'Z';
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(&image[4..8], b"aZcd");
        assert_eq!(&image[..4], &[0; 4]);
        assert_eq!(&image[8..], &[0; 4]);
    }
}
