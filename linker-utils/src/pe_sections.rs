//! Deterministic layout of COFF section contributions in PE images.

use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use foldhash::HashMap;
use foldhash::HashMapExt;
use object::pe;
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::ops::Index;
use std::sync::Arc;

const MAX_COFF_ALIGNMENT: u32 = 8192;
const CONTENT_MASK: u32 = pe::IMAGE_SCN_CNT_CODE.0
    | pe::IMAGE_SCN_CNT_INITIALIZED_DATA.0
    | pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA.0;
const LINK_ONLY_MASK: u32 = pe::IMAGE_SCN_LNK_OTHER.0
    | pe::IMAGE_SCN_LNK_INFO.0
    | pe::IMAGE_SCN_LNK_REMOVE.0
    | pe::IMAGE_SCN_LNK_COMDAT.0
    | pe::IMAGE_SCN_LNK_NRELOC_OVFL.0;
const PARALLEL_SUBSECTION_SORT_MIN: usize = 4096;
const PARALLEL_GROUP_LAYOUT_MIN_CONTRIBUTIONS: usize = 4096;

/// Stable caller-assigned identity for an input section contribution.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ContributionId(pub u32);

/// Whether a contribution occupies bytes in the output file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContributionKind {
    /// Initialized bytes copied into the PE file.
    Data,
    /// Zero-filled memory that occupies no bytes in the PE file.
    Bss,
}

/// One live input section to place in the output image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SectionContribution {
    pub id: ContributionId,
    /// Original COFF name, including an optional `$` subsection suffix.
    pub name: Arc<[u8]>,
    pub characteristics: u32,
    /// Required placement alignment in bytes.
    pub alignment: u32,
    pub size: u32,
    pub kind: ContributionKind,
}

/// Parameters that determine image and file placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SectionLayoutOptions {
    /// End of the PE headers before section padding is applied.
    pub headers_size: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
}

/// The location assigned to one input contribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContributionPlacement {
    pub output_section: usize,
    pub offset: u32,
    pub rva: u32,
    /// Present only for initialized contributions.
    pub file_offset: Option<u32>,
    pub size: u32,
}

/// Dense reverse map keyed by caller-assigned contribution IDs.
///
/// Gaps remain empty, while lookups avoid the tree walk formerly required for every placement.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ContributionPlacements {
    entries: Vec<Option<ContributionPlacement>>,
}

impl ContributionPlacements {
    pub fn insert(
        &mut self,
        id: ContributionId,
        placement: ContributionPlacement,
    ) -> Result<Option<ContributionPlacement>> {
        let index = id.0 as usize;
        if index >= self.entries.len() {
            let additional = index
                .checked_add(1)
                .and_then(|length| length.checked_sub(self.entries.len()))
                .ok_or_else(|| anyhow::anyhow!("contribution ID range overflow"))?;
            self.entries
                .try_reserve(additional)
                .map_err(|_| anyhow::anyhow!("contribution ID range is too large"))?;
            self.entries.resize_with(index + 1, || None);
        }
        Ok(self.entries[index].replace(placement))
    }

    #[must_use]
    #[inline]
    pub fn get(&self, id: &ContributionId) -> Option<&ContributionPlacement> {
        self.entries.get(id.0 as usize)?.as_ref()
    }

    #[must_use]
    #[inline]
    pub fn contains_key(&self, id: &ContributionId) -> bool {
        self.get(id).is_some()
    }

    pub fn values(&self) -> impl Iterator<Item = &ContributionPlacement> {
        self.entries.iter().filter_map(Option::as_ref)
    }

    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut ContributionPlacement> {
        self.entries.iter_mut().filter_map(Option::as_mut)
    }
}

impl Index<&ContributionId> for ContributionPlacements {
    type Output = ContributionPlacement;

    #[inline]
    fn index(&self, id: &ContributionId) -> &Self::Output {
        self.get(id)
            .unwrap_or_else(|| panic!("no placement for contribution {}", id.0))
    }
}

impl Index<ContributionId> for ContributionPlacements {
    type Output = ContributionPlacement;

    #[inline]
    fn index(&self, id: ContributionId) -> &Self::Output {
        &self[&id]
    }
}

/// One output PE section after subsection grouping and layout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputSection {
    /// Full canonical input name (the part before `$`). The PE image section
    /// header stores only its first eight bytes, but layout must retain the
    /// full name so distinct long input sections are not accidentally merged.
    pub name: Vec<u8>,
    pub characteristics: u32,
    pub rva: u32,
    pub virtual_size: u32,
    /// File offset of raw data, absent for a pure BSS section.
    pub file_offset: Option<u32>,
    /// File-aligned `SizeOfRawData`.
    pub raw_size: u32,
    pub contributions: Vec<ContributionId>,
}

/// Complete deterministic section layout and its stable reverse map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SectionLayout {
    pub sections: Vec<OutputSection>,
    pub placements: ContributionPlacements,
    /// File-aligned end of all headers and section data.
    pub file_size: u32,
    /// Section-aligned exclusive end of the mapped image.
    pub size_of_image: u32,
}

/// PE optional-header data directories derivable from output section names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataDirectoryKind {
    Exception,
    BaseRelocation,
    Import,
    Tls,
    Export,
}

/// An RVA and byte count suitable for an `IMAGE_DATA_DIRECTORY`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataDirectoryRange {
    pub rva: u32,
    pub size: u32,
}

/// Address and file shifts caused by inserting a new synthetic `.reloc`
/// output section without rebuilding an otherwise unchanged layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelocationSectionInsertion {
    pub output_section: usize,
    /// The old RVA at which custom output sections begin. RVAs at or above
    /// this boundary move by [`Self::rva_delta`].
    pub first_shifted_rva: u32,
    pub rva_delta: u32,
    pub file_delta: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContentClass {
    Code,
    Data,
    Bss,
}

struct Group<'a> {
    name: Vec<u8>,
    contributions: Vec<GroupedContribution<'a>>,
    subsection_count: usize,
}

#[derive(Clone, Copy)]
struct GroupedContribution<'a> {
    input_index: usize,
    contribution: &'a SectionContribution,
    suffix: &'a [u8],
    has_separator: bool,
}

struct PreparedGroup<'a> {
    group: Group<'a>,
    characteristics: u32,
    relative_offsets: Vec<u32>,
    virtual_size: u32,
    initialized_extent: u32,
}

/// Groups `$` subsections and lays out all contributions with checked arithmetic.
///
/// Standard PE sections are emitted first in conventional order. Other section
/// names follow lexicographically. Within an output section, `$` suffixes are
/// sorted bytewise and equal suffixes retain input order.
pub fn layout_sections(
    contributions: &[SectionContribution],
    options: SectionLayoutOptions,
) -> Result<SectionLayout> {
    layout_sections_borrowed(contributions.iter(), options)
}

/// Borrowing variant of [`layout_sections`] for callers that embed section
/// specifications in a larger contribution type.
///
/// Accepting an iterator of references avoids cloning names and specifications
/// solely to construct a temporary contiguous slice. The returned layout owns
/// all names and placement data that it retains.
pub fn layout_sections_borrowed<'a>(
    contributions: impl IntoIterator<Item = &'a SectionContribution>,
    options: SectionLayoutOptions,
) -> Result<SectionLayout> {
    validate_options(options)?;
    // Production assigns contribution IDs densely in input order. Stay allocation-free for that
    // common case, but lazily reconstruct the general sparse set at the first mismatch so the
    // public API retains duplicate detection for arbitrary caller-assigned IDs.
    let mut ids = None::<BTreeSet<ContributionId>>;
    let mut groups = HashMap::<Vec<u8>, Group<'_>>::new();
    let mut contribution_count = 0usize;
    for (input_index, contribution) in contributions.into_iter().enumerate() {
        if let Some(ids) = &mut ids {
            ensure!(
                ids.insert(contribution.id),
                "duplicate contribution id {}",
                contribution.id.0
            );
        } else if u32::try_from(input_index).ok() != Some(contribution.id.0) {
            let mut sparse_ids = (0..input_index)
                .map(|index| {
                    u32::try_from(index)
                        .map(ContributionId)
                        .map_err(|_| anyhow::anyhow!("contribution ID range overflow"))
                })
                .collect::<Result<BTreeSet<_>>>()?;
            ensure!(
                sparse_ids.insert(contribution.id),
                "duplicate contribution id {}",
                contribution.id.0
            );
            ids = Some(sparse_ids);
        }
        validate_contribution(contribution)?;
        let (base, suffix) = split_name(&contribution.name);
        ensure!(
            !base.is_empty(),
            "contribution {} has an empty canonical section name",
            contribution.id.0
        );
        let grouped = GroupedContribution {
            input_index,
            contribution,
            suffix,
            has_separator: base.len() != contribution.name.len(),
        };
        if let Some(group) = groups.get_mut(base) {
            group.subsection_count += usize::from(grouped.has_separator);
            group.contributions.push(grouped);
        } else {
            groups.insert(
                base.to_vec(),
                Group {
                    name: base.to_vec(),
                    contributions: vec![grouped],
                    subsection_count: usize::from(grouped.has_separator),
                },
            );
        }
        contribution_count += 1;
    }

    let mut groups = groups.into_values().collect::<Vec<_>>();
    groups.sort_by(|left, right| section_order(&left.name).cmp(&section_order(&right.name)));

    let mut next_rva = align_up(
        options.headers_size,
        options.section_alignment,
        "first section RVA",
    )?;
    let mut next_file = align_up(
        options.headers_size,
        options.file_alignment,
        "first section file offset",
    )?;
    let mut sections = Vec::with_capacity(groups.len());
    let mut placements = ContributionPlacements {
        entries: Vec::with_capacity(contribution_count),
    };

    let prepared_groups = if contribution_count >= PARALLEL_GROUP_LAYOUT_MIN_CONTRIBUTIONS
        && rayon::current_num_threads() > 1
    {
        groups
            .into_par_iter()
            .map(prepare_group)
            .collect::<Vec<_>>()
    } else {
        groups.into_iter().map(prepare_group).collect::<Vec<_>>()
    };

    for prepared in prepared_groups {
        let PreparedGroup {
            group,
            characteristics,
            relative_offsets,
            virtual_size,
            initialized_extent,
        } = prepared?;
        let section_index = sections.len();
        let section_rva = next_rva;
        let section_file = next_file;
        let mut placed_ids = Vec::with_capacity(group.contributions.len());

        for (grouped, offset) in group.contributions.into_iter().zip(relative_offsets) {
            let contribution = grouped.contribution;
            let rva = section_rva
                .checked_add(offset)
                .ok_or_else(|| anyhow::anyhow!("contribution RVA overflow"))?;
            let file_offset = match contribution.kind {
                ContributionKind::Data => Some(
                    section_file
                        .checked_add(offset)
                        .ok_or_else(|| anyhow::anyhow!("contribution file offset overflow"))?,
                ),
                ContributionKind::Bss => None,
            };
            ensure!(
                placements
                    .insert(
                        contribution.id,
                        ContributionPlacement {
                            output_section: section_index,
                            offset,
                            rva,
                            file_offset,
                            size: contribution.size,
                        },
                    )?
                    .is_none(),
                "duplicate contribution id {}",
                contribution.id.0
            );
            placed_ids.push(contribution.id);
        }

        let raw_size = align_up(
            initialized_extent,
            options.file_alignment,
            "section raw size",
        )?;
        let file_offset = (raw_size != 0).then_some(section_file);
        sections.push(OutputSection {
            name: group.name,
            characteristics,
            rva: section_rva,
            virtual_size,
            file_offset,
            raw_size,
            contributions: placed_ids,
        });
        next_rva = align_up(
            section_rva
                .checked_add(virtual_size)
                .ok_or_else(|| anyhow::anyhow!("image RVA overflow"))?,
            options.section_alignment,
            "next section RVA",
        )?;
        next_file = section_file
            .checked_add(raw_size)
            .ok_or_else(|| anyhow::anyhow!("output file size overflow"))?;
    }

    Ok(SectionLayout {
        sections,
        placements,
        file_size: next_file,
        size_of_image: next_rva,
    })
}

fn prepare_group<'a>(mut group: Group<'a>) -> Result<PreparedGroup<'a>> {
    if group.subsection_count == group.contributions.len() {
        sort_subsections(&mut group.contributions);
    } else if group.subsection_count != 0 {
        let mut subsections = Vec::with_capacity(group.subsection_count);
        group.contributions.retain(|grouped| {
            if grouped.has_separator {
                subsections.push(*grouped);
                false
            } else {
                true
            }
        });
        sort_subsections(&mut subsections);
        group.contributions.extend(subsections);
    }
    let characteristics = merged_characteristics(&group)?;
    let mut relative_offsets = Vec::with_capacity(group.contributions.len());
    let mut virtual_cursor = 0u32;
    let mut initialized_extent = 0u32;
    for grouped in &group.contributions {
        let contribution = grouped.contribution;
        let offset = align_up(
            virtual_cursor,
            contribution.alignment,
            "contribution offset",
        )?;
        let end = offset.checked_add(contribution.size).ok_or_else(|| {
            anyhow::anyhow!(
                "section {:?} size overflow",
                String::from_utf8_lossy(&group.name)
            )
        })?;
        relative_offsets.push(offset);
        if contribution.kind == ContributionKind::Data {
            initialized_extent = initialized_extent.max(end);
        }
        virtual_cursor = end;
    }
    Ok(PreparedGroup {
        group,
        characteristics,
        relative_offsets,
        virtual_size: virtual_cursor,
        initialized_extent,
    })
}

#[inline]
fn sort_subsections(contributions: &mut [GroupedContribution<'_>]) {
    if contributions.len() >= PARALLEL_SUBSECTION_SORT_MIN && rayon::current_num_threads() > 1 {
        parallel_sort_subsections(contributions);
    } else {
        contributions.sort_unstable_by(compare_subsections);
    }
}

#[inline]
fn compare_subsections(
    left: &GroupedContribution<'_>,
    right: &GroupedContribution<'_>,
) -> std::cmp::Ordering {
    left.suffix
        .cmp(right.suffix)
        // An exact base name sorts before a `$` subsection with an empty suffix. This distinction
        // is significant for the CRT's `.tls` sentinel versus compiler-emitted `.tls$`.
        .then_with(|| left.has_separator.cmp(&right.has_separator))
        .then_with(|| left.input_index.cmp(&right.input_index))
}

#[inline(never)]
#[cold]
fn parallel_sort_subsections(contributions: &mut [GroupedContribution<'_>]) {
    contributions.par_sort_unstable_by(compare_subsections);
}

/// Tries to insert one new synthetic `.reloc` contribution into an existing
/// layout without regrouping and sorting every input contribution.
///
/// The fast path is deliberately narrow. It applies only when `.reloc` does
/// not already exist, adding its section header does not change the aligned
/// header extent, and the section alignment is at least the 4 KiB PE base
/// relocation page size. Under those conditions `.reloc` is inserted after
/// every standard output section and shifts every custom section by one
/// uniform page-multiple. Callers can therefore adjust already-discovered
/// relocation RVAs using the returned boundary and delta.
///
/// `layout` must have been produced by [`layout_sections`] or
/// [`layout_sections_borrowed`] with `options`. `Ok(None)` leaves it unchanged
/// and requests a full relayout. Invalid relocation contributions are errors.
pub fn try_insert_relocation_section(
    layout: &mut SectionLayout,
    contribution: &SectionContribution,
    options: SectionLayoutOptions,
) -> Result<Option<RelocationSectionInsertion>> {
    const BASE_RELOCATION_PAGE_SIZE: u32 = 0x1000;
    const SECTION_HEADER_SIZE: u32 = 40;

    validate_options(options)?;
    validate_contribution(contribution)?;
    ensure!(
        contribution.name.as_ref() == b".reloc",
        "incremental relocation contribution must be named `.reloc`"
    );
    ensure!(
        contribution.size != 0,
        "incremental relocation contribution must not be empty"
    );
    ensure!(
        content_class(contribution.characteristics, contribution.kind)? == ContentClass::Data,
        "incremental relocation contribution must contain initialized data"
    );
    ensure!(
        !layout.placements.contains_key(&contribution.id),
        "duplicate contribution id {}",
        contribution.id.0
    );

    if options.section_alignment < BASE_RELOCATION_PAGE_SIZE
        || layout
            .sections
            .iter()
            .any(|section| section.name == b".reloc")
        || layout.sections.len() >= usize::from(u16::MAX)
        || layout
            .sections
            .windows(2)
            .any(|pair| section_order(&pair[0].name) >= section_order(&pair[1].name))
    {
        return Ok(None);
    }

    let next_headers_size = options
        .headers_size
        .checked_add(SECTION_HEADER_SIZE)
        .ok_or_else(|| anyhow::anyhow!("PE section headers overflow"))?;
    if align_up(
        options.headers_size,
        options.section_alignment,
        "current section headers",
    )? != align_up(
        next_headers_size,
        options.section_alignment,
        "expanded section headers",
    )? || align_up(
        options.headers_size,
        options.file_alignment,
        "current file headers",
    )? != align_up(
        next_headers_size,
        options.file_alignment,
        "expanded file headers",
    )? {
        return Ok(None);
    }

    let relocation_order = section_order(b".reloc");
    let output_section = layout
        .sections
        .iter()
        .position(|section| section_order(&section.name) > relocation_order)
        .unwrap_or(layout.sections.len());
    let first_shifted_rva = layout
        .sections
        .get(output_section)
        .map_or(layout.size_of_image, |section| section.rva);
    let relocation_file_offset = layout.sections[output_section..]
        .iter()
        .find_map(|section| section.file_offset)
        .unwrap_or(layout.file_size);
    if !first_shifted_rva.is_multiple_of(options.section_alignment)
        || !relocation_file_offset.is_multiple_of(options.file_alignment)
    {
        return Ok(None);
    }

    let rva_delta = align_up(
        contribution.size,
        options.section_alignment,
        "relocation section virtual size",
    )?;
    let file_delta = align_up(
        contribution.size,
        options.file_alignment,
        "relocation section raw size",
    )?;
    let size_of_image = layout
        .size_of_image
        .checked_add(rva_delta)
        .ok_or_else(|| anyhow::anyhow!("image RVA overflow"))?;
    let file_size = layout
        .file_size
        .checked_add(file_delta)
        .ok_or_else(|| anyhow::anyhow!("output file size overflow"))?;
    first_shifted_rva
        .checked_add(contribution.size)
        .ok_or_else(|| anyhow::anyhow!("relocation section RVA overflow"))?;
    relocation_file_offset
        .checked_add(contribution.size)
        .ok_or_else(|| anyhow::anyhow!("relocation section file offset overflow"))?;

    // Check every update before mutating the layout so all fallback and error
    // paths leave the caller's authoritative layout untouched.
    for section in &layout.sections[output_section..] {
        section
            .rva
            .checked_add(rva_delta)
            .ok_or_else(|| anyhow::anyhow!("output section RVA overflow"))?;
        if let Some(file_offset) = section.file_offset {
            file_offset
                .checked_add(file_delta)
                .ok_or_else(|| anyhow::anyhow!("output section file offset overflow"))?;
        }
    }
    for placement in layout
        .placements
        .values()
        .filter(|placement| placement.output_section >= output_section)
    {
        placement
            .output_section
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("output section index overflow"))?;
        placement
            .rva
            .checked_add(rva_delta)
            .ok_or_else(|| anyhow::anyhow!("contribution RVA overflow"))?;
        if let Some(file_offset) = placement.file_offset {
            file_offset
                .checked_add(file_delta)
                .ok_or_else(|| anyhow::anyhow!("contribution file offset overflow"))?;
        }
    }

    for section in &mut layout.sections[output_section..] {
        section.rva += rva_delta;
        if let Some(file_offset) = &mut section.file_offset {
            *file_offset += file_delta;
        }
    }
    for placement in layout
        .placements
        .values_mut()
        .filter(|placement| placement.output_section >= output_section)
    {
        placement.output_section += 1;
        placement.rva += rva_delta;
        if let Some(file_offset) = &mut placement.file_offset {
            *file_offset += file_delta;
        }
    }

    let mut characteristics = contribution.characteristics;
    characteristics &= !(CONTENT_MASK | pe::IMAGE_SCN_ALIGN_MASK | LINK_ONLY_MASK);
    characteristics |= pe::IMAGE_SCN_CNT_INITIALIZED_DATA.0;
    layout.sections.insert(
        output_section,
        OutputSection {
            name: contribution.name.to_vec(),
            characteristics,
            rva: first_shifted_rva,
            virtual_size: contribution.size,
            file_offset: Some(relocation_file_offset),
            raw_size: file_delta,
            contributions: vec![contribution.id],
        },
    );
    ensure!(
        layout
            .placements
            .insert(
                contribution.id,
                ContributionPlacement {
                    output_section,
                    offset: 0,
                    rva: first_shifted_rva,
                    file_offset: Some(relocation_file_offset),
                    size: contribution.size,
                },
            )?
            .is_none(),
        "duplicate contribution id {}",
        contribution.id.0
    );
    layout.file_size = file_size;
    layout.size_of_image = size_of_image;

    Ok(Some(RelocationSectionInsertion {
        output_section,
        first_shifted_rva,
        rva_delta,
        file_delta,
    }))
}

/// Returns the full non-empty output section range for a standard directory.
#[must_use]
pub fn directory_range_for_section(
    layout: &SectionLayout,
    kind: DataDirectoryKind,
) -> Option<DataDirectoryRange> {
    let name: &[u8] = match kind {
        DataDirectoryKind::Exception => b".pdata",
        DataDirectoryKind::BaseRelocation => b".reloc",
        DataDirectoryKind::Import => b".idata",
        DataDirectoryKind::Tls => b".tls",
        DataDirectoryKind::Export => b".edata",
    };
    let section = layout
        .sections
        .iter()
        .find(|section| section.name == name)?;
    (section.virtual_size != 0).then_some(DataDirectoryRange {
        rva: section.rva,
        size: section.virtual_size,
    })
}

/// Returns the exact range occupied by one non-empty contribution.
#[must_use]
pub fn directory_range_for_contribution(
    layout: &SectionLayout,
    id: ContributionId,
) -> Option<DataDirectoryRange> {
    let placement = layout.placements.get(&id)?;
    (placement.size != 0).then_some(DataDirectoryRange {
        rva: placement.rva,
        size: placement.size,
    })
}

/// Returns the exact import-address-table directory range.
///
/// Unlike the import directory, the IAT generally occupies only one subsection
/// of `.idata`, so its synthetic contribution must be identified explicitly.
#[must_use]
pub fn iat_directory_range(
    layout: &SectionLayout,
    iat_contribution: ContributionId,
) -> Option<DataDirectoryRange> {
    directory_range_for_contribution(layout, iat_contribution)
}

fn validate_options(options: SectionLayoutOptions) -> Result<()> {
    validate_power_of_two(options.section_alignment, "section alignment")?;
    validate_power_of_two(options.file_alignment, "file alignment")?;
    ensure!(
        options.section_alignment >= options.file_alignment,
        "section alignment must not be smaller than file alignment"
    );
    Ok(())
}

fn validate_contribution(contribution: &SectionContribution) -> Result<()> {
    ensure!(
        !contribution.name.is_empty(),
        "contribution {} has an empty section name",
        contribution.id.0
    );
    ensure!(
        !contribution.name.contains(&0),
        "contribution {} section name contains NUL",
        contribution.id.0
    );
    validate_power_of_two(contribution.alignment, "contribution alignment")?;
    ensure!(
        contribution.alignment <= MAX_COFF_ALIGNMENT,
        "contribution alignment {} exceeds COFF maximum {MAX_COFF_ALIGNMENT}",
        contribution.alignment
    );
    Ok(())
}

fn validate_power_of_two(value: u32, description: &str) -> Result<()> {
    ensure!(
        value.is_power_of_two(),
        "{description} {value} is not a non-zero power of two"
    );
    Ok(())
}

fn split_name(name: &[u8]) -> (&[u8], &[u8]) {
    match name.iter().position(|byte| *byte == b'$') {
        Some(index) => (&name[..index], &name[index + 1..]),
        None => (name, b""),
    }
}

fn section_order(name: &[u8]) -> (usize, &[u8]) {
    const STANDARD: [&[u8]; 10] = [
        b".text", b".rdata", b".data", b".pdata", b".xdata", b".bss", b".idata", b".edata",
        b".tls", b".reloc",
    ];
    match STANDARD.iter().position(|standard| *standard == name) {
        Some(index) => (index, b""),
        None => (STANDARD.len(), name),
    }
}

fn content_class(characteristics: u32, kind: ContributionKind) -> Result<ContentClass> {
    let bits = characteristics & CONTENT_MASK;
    let class = match bits {
        value if value == pe::IMAGE_SCN_CNT_CODE.0 => ContentClass::Code,
        value if value == pe::IMAGE_SCN_CNT_INITIALIZED_DATA.0 => ContentClass::Data,
        value if value == pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA.0 => ContentClass::Bss,
        0 => match kind {
            ContributionKind::Data => ContentClass::Data,
            ContributionKind::Bss => ContentClass::Bss,
        },
        _ => bail!("section has contradictory content characteristics {bits:#010x}"),
    };
    ensure!(
        kind != ContributionKind::Bss || class != ContentClass::Code,
        "code contribution cannot be BSS"
    );
    ensure!(
        kind != ContributionKind::Bss || class != ContentClass::Data,
        "initialized-data contribution cannot be BSS"
    );
    ensure!(
        kind != ContributionKind::Data || class != ContentClass::Bss,
        "uninitialized-data contribution must be BSS"
    );
    Ok(class)
}

fn merged_characteristics(group: &Group<'_>) -> Result<u32> {
    let mut merged = 0u32;
    let mut has_code = false;
    let mut has_data = false;
    let mut has_bss = false;
    for grouped in &group.contributions {
        let contribution = grouped.contribution;
        match content_class(contribution.characteristics, contribution.kind)? {
            ContentClass::Code => has_code = true,
            ContentClass::Data => has_data = true,
            ContentClass::Bss => has_bss = true,
        }
        merged |= contribution.characteristics;
    }
    ensure!(
        !(has_code && (has_data || has_bss)),
        "output section {:?} mixes code and data",
        String::from_utf8_lossy(&group.name)
    );
    merged &= !(CONTENT_MASK | pe::IMAGE_SCN_ALIGN_MASK | LINK_ONLY_MASK);
    merged |= if has_code {
        pe::IMAGE_SCN_CNT_CODE.0
    } else if has_data {
        pe::IMAGE_SCN_CNT_INITIALIZED_DATA.0
    } else if has_bss {
        pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA.0
    } else {
        0
    };
    Ok(merged)
}

fn align_up(value: u32, alignment: u32, description: &str) -> Result<u32> {
    let mask = alignment - 1;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or_else(|| anyhow::anyhow!("{description} overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contribution(
        id: u32,
        name: &[u8],
        kind: ContributionKind,
        size: u32,
        alignment: u32,
    ) -> SectionContribution {
        let characteristics = match kind {
            ContributionKind::Data => {
                pe::IMAGE_SCN_CNT_INITIALIZED_DATA.0 | pe::IMAGE_SCN_MEM_READ.0
            }
            ContributionKind::Bss => {
                pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA.0
                    | pe::IMAGE_SCN_MEM_READ.0
                    | pe::IMAGE_SCN_MEM_WRITE.0
            }
        };
        SectionContribution {
            id: ContributionId(id),
            name: name.to_vec().into(),
            characteristics,
            alignment,
            size,
            kind,
        }
    }

    fn options() -> SectionLayoutOptions {
        SectionLayoutOptions {
            headers_size: 0x220,
            section_alignment: 0x1000,
            file_alignment: 0x200,
        }
    }

    fn relocation_contribution(id: u32, size: u32) -> SectionContribution {
        SectionContribution {
            id: ContributionId(id),
            name: b".reloc".to_vec().into(),
            characteristics: (pe::IMAGE_SCN_CNT_INITIALIZED_DATA
                | pe::IMAGE_SCN_MEM_READ
                | pe::IMAGE_SCN_MEM_DISCARDABLE)
                .0,
            alignment: 8,
            size,
            kind: ContributionKind::Data,
        }
    }

    fn expanded_header_options(options: SectionLayoutOptions) -> SectionLayoutOptions {
        SectionLayoutOptions {
            headers_size: options.headers_size + 40,
            ..options
        }
    }

    #[test]
    fn groups_subsections_lexically_and_preserves_equal_suffix_order() {
        let inputs = [
            contribution(1, b".text$z", ContributionKind::Data, 3, 1),
            contribution(2, b".text$a", ContributionKind::Data, 5, 4),
            contribution(3, b".text$a", ContributionKind::Data, 2, 8),
            contribution(4, b".text", ContributionKind::Data, 1, 1),
            contribution(5, b".text$", ContributionKind::Data, 1, 1),
        ];
        let layout = layout_sections(&inputs, options()).unwrap();
        assert_eq!(
            layout.sections[0].contributions,
            [
                ContributionId(4),
                ContributionId(5),
                ContributionId(2),
                ContributionId(3),
                ContributionId(1)
            ]
        );
        assert_eq!(layout.placements[&ContributionId(4)].offset, 0);
        assert_eq!(layout.placements[&ContributionId(5)].offset, 1);
        assert_eq!(layout.placements[&ContributionId(2)].offset, 4);
        assert_eq!(layout.placements[&ContributionId(3)].offset, 16);
        assert_eq!(layout.placements[&ContributionId(1)].offset, 18);
    }

    #[test]
    fn cached_subsection_keys_match_the_previous_comparator() {
        let inputs = vec![
            contribution(90, b".text$a", ContributionKind::Data, 3, 1),
            contribution(7, b".text$$", ContributionKind::Data, 5, 2),
            contribution(130, b".text", ContributionKind::Data, 7, 4),
            contribution(2, b".text$a$z", ContributionKind::Data, 11, 8),
            contribution(88, b".text$a", ContributionKind::Data, 13, 16),
            contribution(41, b".text$", ContributionKind::Data, 17, 1),
            contribution(5, b".text$\x80", ContributionKind::Data, 19, 2),
            contribution(77, b".text$\x7f", ContributionKind::Data, 23, 4),
        ];

        let actual = layout_sections(&inputs, options()).unwrap();
        assert_eq!(
            actual.sections[0].contributions,
            [
                ContributionId(130),
                ContributionId(41),
                ContributionId(7),
                ContributionId(90),
                ContributionId(88),
                ContributionId(2),
                ContributionId(77),
                ContributionId(5),
            ]
        );

        let mut old_order = inputs.iter().enumerate().collect::<Vec<_>>();
        old_order.sort_by(|(left_index, left), (right_index, right)| {
            let (_, left_suffix) = split_name(&left.name);
            let (_, right_suffix) = split_name(&right.name);
            left_suffix
                .cmp(right_suffix)
                .then_with(|| left.name.contains(&b'$').cmp(&right.name.contains(&b'$')))
                .then_with(|| left_index.cmp(right_index))
        });
        let old_sorted_inputs = old_order
            .into_iter()
            .map(|(_, contribution)| contribution.clone())
            .collect::<Vec<_>>();
        let expected = layout_sections(&old_sorted_inputs, options()).unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn borrowed_layout_accepts_embedded_contribution_specs() {
        struct Embedded {
            spec: SectionContribution,
            unrelated_payload: Vec<u8>,
        }

        let inputs = [
            Embedded {
                spec: contribution(7, b".rdata$z", ContributionKind::Data, 3, 1),
                unrelated_payload: vec![1, 2, 3],
            },
            Embedded {
                spec: contribution(3, b".text$a", ContributionKind::Data, 5, 4),
                unrelated_payload: vec![4, 5],
            },
        ];
        let expected = layout_sections(
            &inputs
                .iter()
                .map(|input| input.spec.clone())
                .collect::<Vec<_>>(),
            options(),
        )
        .unwrap();
        let actual =
            layout_sections_borrowed(inputs.iter().map(|input| &input.spec), options()).unwrap();

        assert_eq!(actual, expected);
        assert_eq!(inputs[0].unrelated_payload, [1, 2, 3]);
    }

    #[test]
    fn incrementally_inserts_reloc_exactly_like_a_full_layout() {
        let options = options();
        let inputs = vec![
            contribution(0, b".text", ContributionKind::Data, 0x901, 16),
            contribution(1, b".bss", ContributionKind::Bss, 0x123, 16),
            contribution(2, b".00cfg", ContributionKind::Data, 0x38, 8),
            contribution(3, b".midbss", ContributionKind::Bss, 0x20, 8),
            contribution(4, b".rsrc", ContributionKind::Data, 0x701, 8),
        ];
        let relocation = relocation_contribution(5, 0x281c);
        let mut actual = layout_sections(&inputs, options).unwrap();
        let old_custom_rva = actual
            .sections
            .iter()
            .find(|section| section.name == b".00cfg")
            .unwrap()
            .rva;
        let old_file_size = actual.file_size;
        let old_size_of_image = actual.size_of_image;

        let insertion = try_insert_relocation_section(&mut actual, &relocation, options)
            .unwrap()
            .unwrap();
        let mut complete_inputs = inputs;
        complete_inputs.push(relocation);
        let expected = layout_sections(&complete_inputs, expanded_header_options(options)).unwrap();

        assert_eq!(actual, expected);
        assert_eq!(insertion.output_section, 2);
        assert_eq!(insertion.first_shifted_rva, old_custom_rva);
        assert_eq!(insertion.rva_delta, 0x3000);
        assert_eq!(insertion.file_delta, 0x2a00);
        assert_eq!(actual.file_size, old_file_size + insertion.file_delta);
        assert_eq!(
            actual.size_of_image,
            old_size_of_image + insertion.rva_delta
        );
        assert_eq!(
            actual.placements[&ContributionId(2)].output_section,
            insertion.output_section + 1
        );
        assert_eq!(actual.placements[&ContributionId(3)].file_offset, None);
    }

    #[test]
    fn incrementally_appends_reloc_when_there_are_no_custom_sections() {
        let options = options();
        let inputs = vec![
            contribution(0, b".text", ContributionKind::Data, 0x80, 16),
            contribution(1, b".data", ContributionKind::Data, 0x41, 8),
        ];
        let relocation = relocation_contribution(2, 12);
        let mut actual = layout_sections(&inputs, options).unwrap();
        let old_file_size = actual.file_size;
        let old_size_of_image = actual.size_of_image;

        let insertion = try_insert_relocation_section(&mut actual, &relocation, options)
            .unwrap()
            .unwrap();
        let mut complete_inputs = inputs;
        complete_inputs.push(relocation);
        let expected = layout_sections(&complete_inputs, expanded_header_options(options)).unwrap();

        assert_eq!(actual, expected);
        assert_eq!(insertion.first_shifted_rva, old_size_of_image);
        assert_eq!(
            actual.placements[&ContributionId(2)].file_offset,
            Some(old_file_size)
        );
    }

    #[test]
    fn incremental_reloc_fallbacks_leave_layout_unchanged() {
        let default_options = options();
        let relocation = relocation_contribution(20, 12);

        let existing_inputs = [
            contribution(0, b".text", ContributionKind::Data, 8, 1),
            contribution(1, b".reloc$input", ContributionKind::Data, 8, 8),
        ];
        let mut existing = layout_sections(&existing_inputs, default_options).unwrap();
        let before = existing.clone();
        assert_eq!(
            try_insert_relocation_section(&mut existing, &relocation, default_options).unwrap(),
            None
        );
        assert_eq!(existing, before);

        let low_alignment = SectionLayoutOptions {
            headers_size: 0x220,
            section_alignment: 0x200,
            file_alignment: 0x200,
        };
        let inputs = [contribution(0, b".custom", ContributionKind::Data, 8, 1)];
        let mut low = layout_sections(&inputs, low_alignment).unwrap();
        let before = low.clone();
        assert_eq!(
            try_insert_relocation_section(&mut low, &relocation, low_alignment).unwrap(),
            None
        );
        assert_eq!(low, before);

        let growing_headers = SectionLayoutOptions {
            headers_size: 0x200,
            ..default_options
        };
        let mut headers = layout_sections(&inputs, growing_headers).unwrap();
        let before = headers.clone();
        assert_eq!(
            try_insert_relocation_section(&mut headers, &relocation, growing_headers).unwrap(),
            None
        );
        assert_eq!(headers, before);

        let unordered_inputs = [
            contribution(0, b".text", ContributionKind::Data, 8, 1),
            contribution(1, b".custom", ContributionKind::Data, 8, 1),
        ];
        let mut unordered = layout_sections(&unordered_inputs, default_options).unwrap();
        unordered.sections.swap(0, 1);
        let before = unordered.clone();
        assert_eq!(
            try_insert_relocation_section(&mut unordered, &relocation, default_options).unwrap(),
            None
        );
        assert_eq!(unordered, before);
    }

    #[test]
    fn incremental_reloc_errors_leave_layout_unchanged() {
        let options = options();
        let inputs = [contribution(0, b".custom", ContributionKind::Data, 8, 1)];
        let layout = layout_sections(&inputs, options).unwrap();

        let mut duplicate_layout = layout.clone();
        let duplicate = relocation_contribution(0, 12);
        assert!(try_insert_relocation_section(&mut duplicate_layout, &duplicate, options).is_err());
        assert_eq!(duplicate_layout, layout);

        let mut wrong_name_layout = layout.clone();
        let mut wrong_name = relocation_contribution(2, 12);
        wrong_name.name = b".not-reloc".to_vec().into();
        assert!(
            try_insert_relocation_section(&mut wrong_name_layout, &wrong_name, options).is_err()
        );
        assert_eq!(wrong_name_layout, layout);

        let mut empty_layout = layout.clone();
        let empty = relocation_contribution(2, 0);
        assert!(try_insert_relocation_section(&mut empty_layout, &empty, options).is_err());
        assert_eq!(empty_layout, layout);

        let mut overflowing_layout = layout.clone();
        let overflowing_options = SectionLayoutOptions {
            headers_size: u32::MAX - 20,
            ..options
        };
        assert!(
            try_insert_relocation_section(
                &mut overflowing_layout,
                &relocation_contribution(2, 12),
                overflowing_options,
            )
            .is_err()
        );
        assert_eq!(overflowing_layout, layout);
    }

    #[test]
    fn uses_standard_then_lexical_custom_section_order() {
        let names: [&[u8]; 13] = [
            b".zzz",
            b".reloc",
            b".tls",
            b".edata",
            b".idata",
            b".bss",
            b".xdata",
            b".pdata",
            b".data",
            b".rdata",
            b".text",
            b".aaa",
            b".text$mn",
        ];
        let inputs = names
            .iter()
            .enumerate()
            .map(|(index, name)| contribution(index as u32, name, ContributionKind::Data, 1, 1))
            .collect::<Vec<_>>();
        let layout = layout_sections(&inputs, options()).unwrap();
        let actual = layout
            .sections
            .iter()
            .map(|section| section.name.as_slice())
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            [
                b".text".as_slice(),
                b".rdata",
                b".data",
                b".pdata",
                b".xdata",
                b".bss",
                b".idata",
                b".edata",
                b".tls",
                b".reloc",
                b".aaa",
                b".zzz"
            ]
        );
    }

    #[test]
    fn keeps_colliding_long_logical_names_as_distinct_output_sections() {
        let inputs = [
            contribution(1, b".a_very_long_section$z", ContributionKind::Data, 3, 1),
            contribution(2, b".a_very_long_section2", ContributionKind::Data, 5, 1),
            contribution(3, b".eh_frame", ContributionKind::Data, 8, 8),
        ];
        let layout = layout_sections(&inputs, options()).unwrap();
        let actual = layout
            .sections
            .iter()
            .map(|section| section.name.as_slice())
            .collect::<Vec<_>>();

        assert_eq!(
            actual,
            [
                b".a_very_long_section".as_slice(),
                b".a_very_long_section2",
                b".eh_frame",
            ]
        );
        assert_ne!(
            layout.placements[&ContributionId(1)].output_section,
            layout.placements[&ContributionId(2)].output_section
        );
    }

    #[test]
    fn lays_out_rvas_files_data_and_bss_with_padding() {
        let inputs = [
            contribution(1, b".data$a", ContributionKind::Data, 3, 1),
            contribution(2, b".data$b", ContributionKind::Bss, 7, 8),
            contribution(3, b".data$c", ContributionKind::Data, 2, 4),
            contribution(4, b".bss", ContributionKind::Bss, 9, 1),
        ];
        let layout = layout_sections(&inputs, options()).unwrap();
        let data = &layout.sections[0];
        assert_eq!(
            (data.rva, data.virtual_size, data.file_offset, data.raw_size),
            (0x1000, 18, Some(0x400), 0x200)
        );
        assert_eq!(layout.placements[&ContributionId(2)].file_offset, None);
        assert_eq!(
            layout.placements[&ContributionId(3)].file_offset,
            Some(0x410)
        );
        let bss = &layout.sections[1];
        assert_eq!((bss.rva, bss.file_offset, bss.raw_size), (0x2000, None, 0));
        assert_eq!(layout.file_size, 0x600);
        assert_eq!(layout.size_of_image, 0x3000);
    }

    #[test]
    fn zero_sized_contribution_keeps_an_aligned_boundary_location() {
        let inputs = [
            contribution(1, b".rdata$a", ContributionKind::Data, 3, 1),
            contribution(2, b".rdata$b", ContributionKind::Data, 0, 8),
            contribution(3, b".rdata$c", ContributionKind::Data, 4, 1),
        ];
        let layout = layout_sections(&inputs, options()).unwrap();

        let empty = &layout.placements[&ContributionId(2)];
        let following = &layout.placements[&ContributionId(3)];
        assert_eq!((empty.offset, empty.rva, empty.size), (8, 0x1008, 0));
        assert_eq!(following.offset, empty.offset);
        assert_eq!(layout.sections[0].virtual_size, 12);
    }

    #[test]
    fn merges_compatible_flags_and_removes_input_only_bits() {
        let mut first = contribution(1, b".text$a", ContributionKind::Data, 1, 16);
        first.characteristics = pe::IMAGE_SCN_CNT_CODE.0
            | pe::IMAGE_SCN_MEM_READ.0
            | pe::IMAGE_SCN_LNK_COMDAT.0
            | pe::IMAGE_SCN_ALIGN_16BYTES.0;
        let mut second = contribution(2, b".text$b", ContributionKind::Data, 1, 1);
        second.characteristics =
            pe::IMAGE_SCN_CNT_CODE.0 | pe::IMAGE_SCN_MEM_EXECUTE.0 | pe::IMAGE_SCN_LNK_REMOVE.0;
        let layout = layout_sections(&[first, second], options()).unwrap();
        assert_eq!(
            layout.sections[0].characteristics,
            pe::IMAGE_SCN_CNT_CODE.0 | pe::IMAGE_SCN_MEM_READ.0 | pe::IMAGE_SCN_MEM_EXECUTE.0
        );
    }

    #[test]
    fn directory_helpers_cover_standard_sections_and_exact_iat() {
        let inputs = [
            contribution(1, b".pdata", ContributionKind::Data, 12, 4),
            contribution(2, b".reloc", ContributionKind::Data, 8, 4),
            contribution(3, b".idata$2", ContributionKind::Data, 20, 4),
            contribution(4, b".idata$5", ContributionKind::Data, 16, 8),
            contribution(5, b".tls", ContributionKind::Data, 40, 8),
            contribution(6, b".edata", ContributionKind::Data, 24, 4),
        ];
        let layout = layout_sections(&inputs, options()).unwrap();
        for kind in [
            DataDirectoryKind::Exception,
            DataDirectoryKind::BaseRelocation,
            DataDirectoryKind::Import,
            DataDirectoryKind::Tls,
            DataDirectoryKind::Export,
        ] {
            assert!(directory_range_for_section(&layout, kind).is_some());
        }
        assert_eq!(
            iat_directory_range(&layout, ContributionId(4)),
            Some(DataDirectoryRange {
                rva: layout.placements[&ContributionId(4)].rva,
                size: 16
            })
        );
        assert_eq!(
            directory_range_for_contribution(&layout, ContributionId(99)),
            None
        );
    }

    #[test]
    fn rejects_invalid_names_ids_alignments_and_characteristics() {
        let valid = contribution(1, b".text", ContributionKind::Data, 1, 1);
        assert!(
            layout_sections(&[valid.clone(), valid], options())
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
        assert!(
            layout_sections(
                &[contribution(1, b".bad\0", ContributionKind::Data, 1, 1)],
                options()
            )
            .is_err()
        );
        assert!(
            layout_sections(
                &[contribution(1, b".bad", ContributionKind::Data, 1, 3)],
                options()
            )
            .is_err()
        );
        let mut contradictory = contribution(1, b".bad", ContributionKind::Data, 1, 1);
        contradictory.characteristics |= pe::IMAGE_SCN_CNT_CODE.0;
        assert!(layout_sections(&[contradictory], options()).is_err());
        let mut bss_code = contribution(1, b".bad", ContributionKind::Bss, 1, 1);
        bss_code.characteristics = pe::IMAGE_SCN_CNT_CODE.0;
        assert!(layout_sections(&[bss_code], options()).is_err());
    }

    #[test]
    fn rejects_incompatible_groups_and_layout_options() {
        let mut code = contribution(1, b".mix$a", ContributionKind::Data, 1, 1);
        code.characteristics = pe::IMAGE_SCN_CNT_CODE.0;
        let data = contribution(2, b".mix$b", ContributionKind::Data, 1, 1);
        assert!(
            layout_sections(&[code, data], options())
                .unwrap_err()
                .to_string()
                .contains("mixes code and data")
        );
        let bad_options = SectionLayoutOptions {
            headers_size: 0,
            section_alignment: 0x200,
            file_alignment: 0x1000,
        };
        assert!(layout_sections(&[], bad_options).is_err());
    }

    #[test]
    fn parallel_group_preparation_matches_serial_layout() {
        let inputs = (0..5000u32)
            .map(|id| {
                let name = match (id % 3, id % 97) {
                    (0, 0) => b".text$z".as_slice(),
                    (0, _) => b".text".as_slice(),
                    (1, 0) => b".rdata$a".as_slice(),
                    (1, _) => b".rdata".as_slice(),
                    _ => b".pdata".as_slice(),
                };
                contribution(id, name, ContributionKind::Data, id % 31 + 1, 1 << (id % 4))
            })
            .collect::<Vec<_>>();
        let layout_with_threads = |threads| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| layout_sections(&inputs, options()).unwrap())
        };
        assert_eq!(layout_with_threads(1), layout_with_threads(4));
    }

    #[test]
    fn detects_all_address_space_overflows() {
        let near_end = SectionLayoutOptions {
            headers_size: u32::MAX,
            section_alignment: 1,
            file_alignment: 1,
        };
        let input = contribution(1, b".data", ContributionKind::Data, 1, 1);
        assert!(
            layout_sections(&[input], near_end)
                .unwrap_err()
                .to_string()
                .contains("overflow")
        );

        let input = contribution(1, b".data", ContributionKind::Data, u32::MAX, 1);
        let tiny = SectionLayoutOptions {
            headers_size: 1,
            section_alignment: 1,
            file_alignment: 1,
        };
        assert!(
            layout_sections(&[input], tiny)
                .unwrap_err()
                .to_string()
                .contains("overflow")
        );
    }

    #[test]
    fn empty_layout_is_aligned_and_has_no_directories() {
        let layout = layout_sections(&[], options()).unwrap();
        assert!(layout.sections.is_empty());
        assert_eq!((layout.file_size, layout.size_of_image), (0x400, 0x1000));
        assert_eq!(
            directory_range_for_section(&layout, DataDirectoryKind::Import),
            None
        );
    }
}
