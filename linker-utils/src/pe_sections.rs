//! Deterministic layout of COFF section contributions in PE images.

use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use object::pe;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

const MAX_COFF_ALIGNMENT: u32 = 8192;
const CONTENT_MASK: u32 = pe::IMAGE_SCN_CNT_CODE.0
    | pe::IMAGE_SCN_CNT_INITIALIZED_DATA.0
    | pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA.0;
const LINK_ONLY_MASK: u32 = pe::IMAGE_SCN_LNK_OTHER.0
    | pe::IMAGE_SCN_LNK_INFO.0
    | pe::IMAGE_SCN_LNK_REMOVE.0
    | pe::IMAGE_SCN_LNK_COMDAT.0
    | pe::IMAGE_SCN_LNK_NRELOC_OVFL.0;

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
    pub name: Vec<u8>,
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

/// One output PE section after subsection grouping and layout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputSection {
    /// Canonical name (the part before `$`).
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
    pub placements: BTreeMap<ContributionId, ContributionPlacement>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContentClass {
    Code,
    Data,
    Bss,
}

struct Group<'a> {
    name: Vec<u8>,
    contributions: Vec<(usize, &'a SectionContribution)>,
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
    validate_options(options)?;
    let mut ids = BTreeSet::new();
    let mut groups = BTreeMap::<Vec<u8>, Group<'_>>::new();
    for (input_index, contribution) in contributions.iter().enumerate() {
        ensure!(
            ids.insert(contribution.id),
            "duplicate contribution id {}",
            contribution.id.0
        );
        validate_contribution(contribution)?;
        let (base, _) = split_name(&contribution.name);
        ensure!(
            !base.is_empty(),
            "contribution {} has an empty canonical section name",
            contribution.id.0
        );
        ensure!(
            base.len() <= 8,
            "output section name {:?} exceeds the PE 8-byte limit",
            String::from_utf8_lossy(base)
        );
        groups
            .entry(base.to_vec())
            .or_insert_with(|| Group {
                name: base.to_vec(),
                contributions: Vec::new(),
            })
            .contributions
            .push((input_index, contribution));
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
    let mut placements = BTreeMap::new();

    for mut group in groups {
        group
            .contributions
            .sort_by(|(left_index, left), (right_index, right)| {
                let (_, left_suffix) = split_name(&left.name);
                let (_, right_suffix) = split_name(&right.name);
                left_suffix
                    .cmp(right_suffix)
                    // An exact base name sorts before a `$` subsection with an
                    // empty suffix. This distinction is significant for the
                    // CRT's `.tls` sentinel versus compiler-emitted `.tls$`.
                    .then_with(|| left.name.contains(&b'$').cmp(&right.name.contains(&b'$')))
                    .then(left_index.cmp(right_index))
            });
        let characteristics = merged_characteristics(&group)?;
        let section_index = sections.len();
        let section_rva = next_rva;
        let section_file = next_file;
        let mut virtual_cursor = 0u32;
        let mut initialized_extent = 0u32;
        let mut placed_ids = Vec::with_capacity(group.contributions.len());

        for (_, contribution) in group.contributions {
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
            let rva = section_rva
                .checked_add(offset)
                .ok_or_else(|| anyhow::anyhow!("contribution RVA overflow"))?;
            let file_offset = match contribution.kind {
                ContributionKind::Data => {
                    initialized_extent = initialized_extent.max(end);
                    Some(
                        section_file
                            .checked_add(offset)
                            .ok_or_else(|| anyhow::anyhow!("contribution file offset overflow"))?,
                    )
                }
                ContributionKind::Bss => None,
            };
            placements.insert(
                contribution.id,
                ContributionPlacement {
                    output_section: section_index,
                    offset,
                    rva,
                    file_offset,
                    size: contribution.size,
                },
            );
            placed_ids.push(contribution.id);
            virtual_cursor = end;
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
            virtual_size: virtual_cursor,
            file_offset,
            raw_size,
            contributions: placed_ids,
        });
        next_rva = align_up(
            section_rva
                .checked_add(virtual_cursor)
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
    for (_, contribution) in &group.contributions {
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
            name: name.to_vec(),
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
                &[contribution(1, b"toolongxx", ContributionKind::Data, 1, 1)],
                options()
            )
            .is_err()
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
