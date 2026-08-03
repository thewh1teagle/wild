//! Construction and validation of the AMD64 PE TLS directory.
//!
//! A linker using this module must define `_tls_used` at [`TlsLayout::directory_rva`]
//! and `_tls_index` at [`TlsLayout::index_rva`]. MSVC CRT objects conventionally
//! also define `_tls_start` and `_tls_end` as `.tls$AAA`/`.tls$ZZZ` sentinels;
//! those are ordinary input symbols and must retain their offsets in the merged
//! `.tls` contribution. Callback records from `.CRT$XL*` are resolved by the
//! linker before being passed here.

use anyhow::{Context, Result, ensure};

/// Size of `IMAGE_TLS_DIRECTORY64` in bytes.
pub const IMAGE_TLS_DIRECTORY64_SIZE: u32 = 40;

const POINTER_SIZE: u32 = 8;
const TLS_INDEX_SIZE: u32 = 4;
const MAX_COFF_ALIGNMENT: u32 = 8192;
const IMAGE_SCN_ALIGN_MASK: u32 = 0x00f0_0000;

/// One `.tls` or `.tls$*` input-section contribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsContribution<'data> {
    pub section_name: &'data [u8],
    /// Initialized bytes present in the image file.
    pub data: &'data [u8],
    /// Additional trailing bytes initialized to zero by the loader.
    pub zero_fill: u32,
    /// Power-of-two placement alignment, up to the COFF maximum of 8192.
    pub alignment: u32,
    /// Stable input identity used to break equal-name ties.
    pub order: u64,
}

/// Resolved callbacks supplied by one `.CRT$XL*` contribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsCallbackContribution<'data> {
    pub section_name: &'data [u8],
    /// Callback target RVAs. Null sentinels are supplied by this module.
    pub target_rvas: &'data [u32],
    /// Stable input identity used to break equal-name ties.
    pub order: u64,
}

/// Output addresses selected by the PE section-layout pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsLayout {
    pub image_base: u64,
    pub raw_data_rva: u32,
    pub index_rva: u32,
    pub callbacks_rva: u32,
    pub directory_rva: u32,
    /// Exclusive bound of mapped image RVAs.
    pub size_of_image: u32,
}

/// Placement of an input contribution in [`TlsImage::raw_data`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsContributionPlacement {
    pub order: u64,
    pub offset: u32,
    pub initialized_size: u32,
    pub virtual_size: u32,
}

/// TLS optional-header data-directory entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsDataDirectory {
    pub rva: u32,
    pub size: u32,
}

/// Loader-visible TLS directory fields, converted back from VAs to RVAs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedTlsDirectory {
    pub raw_data_start_rva: u32,
    pub raw_data_end_rva: u32,
    pub index_rva: u32,
    pub callbacks_rva: u32,
    pub size_of_zero_fill: u32,
    pub alignment: u32,
}

/// Complete TLS payload emitted into PE sections by the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsImage {
    /// Initialized `.tls` bytes, including materialized internal padding/zeros.
    pub raw_data: Vec<u8>,
    /// Total initialized plus zero-filled template size in memory.
    pub raw_data_virtual_size: u32,
    /// Initial storage for the loader-assigned `_tls_index` value.
    pub index: [u8; TLS_INDEX_SIZE as usize],
    /// Sorted callback VAs followed by one null pointer.
    pub callbacks: Vec<u8>,
    pub directory: [u8; IMAGE_TLS_DIRECTORY64_SIZE as usize],
    pub data_directory: TlsDataDirectory,
    pub placements: Vec<TlsContributionPlacement>,
    /// RVAs of all image-base-dependent 64-bit fields, ready for `.reloc`.
    pub dir64_relocation_rvas: Vec<u32>,
}

/// Builds a canonical PE32+ AMD64 TLS payload.
///
/// `.tls` contributions are ordered bytewise by subsection name, then by
/// `order`. Alignment gaps and zero-fill preceding later initialized data are
/// materialized in `raw_data`; only the final zero-filled tail is recorded in
/// `SizeOfZeroFill`. Callback contributions are similarly ordered, and their
/// targets are written as VAs followed by a null terminator.
pub fn build_amd64_tls_image(
    layout: TlsLayout,
    contributions: &[TlsContribution<'_>],
    callback_contributions: &[TlsCallbackContribution<'_>],
) -> Result<TlsImage> {
    validate_layout(layout)?;
    ensure!(
        !contributions.is_empty(),
        "a TLS directory requires at least one .tls contribution"
    );

    let mut ordered = contributions.to_vec();
    ordered.sort_by(|left, right| {
        left.section_name
            .cmp(right.section_name)
            .then_with(|| left.order.cmp(&right.order))
    });
    validate_unique_orders(ordered.iter().map(|item| item.order), "TLS contribution")?;

    let mut memory = Vec::new();
    let mut last_initialized_end = 0usize;
    let mut placements = Vec::with_capacity(ordered.len());
    let mut maximum_alignment = 1;
    for contribution in ordered {
        validate_tls_name(contribution.section_name)?;
        validate_alignment(contribution.alignment)?;
        maximum_alignment = maximum_alignment.max(contribution.alignment);

        let offset = align_up_usize(memory.len(), contribution.alignment)?;
        memory.resize(offset, 0);
        let initialized_size = u32::try_from(contribution.data.len())
            .context("TLS initialized contribution exceeds 4 GiB")?;
        memory.extend_from_slice(contribution.data);
        if !contribution.data.is_empty() {
            last_initialized_end = memory.len();
        }
        let zero_fill = usize::try_from(contribution.zero_fill)
            .context("TLS zero-fill size does not fit usize")?;
        let end = memory
            .len()
            .checked_add(zero_fill)
            .context("TLS template size overflow")?;
        memory.resize(end, 0);
        let virtual_size = initialized_size
            .checked_add(contribution.zero_fill)
            .context("TLS contribution virtual size overflow")?;
        placements.push(TlsContributionPlacement {
            order: contribution.order,
            offset: u32::try_from(offset).context("TLS contribution offset exceeds 4 GiB")?,
            initialized_size,
            virtual_size,
        });
    }

    let raw_data_virtual_size =
        u32::try_from(memory.len()).context("TLS template exceeds 4 GiB")?;
    let size_of_zero_fill = u32::try_from(memory.len() - last_initialized_end)
        .context("TLS zero-fill tail exceeds 4 GiB")?;
    memory.truncate(last_initialized_end);
    let initialized_size =
        u32::try_from(memory.len()).context("TLS initialized template exceeds 4 GiB")?;

    let raw_data_end_rva = layout
        .raw_data_rva
        .checked_add(initialized_size)
        .context("TLS raw-data RVA range overflow")?;
    let raw_virtual_end = layout
        .raw_data_rva
        .checked_add(raw_data_virtual_size)
        .context("TLS virtual RVA range overflow")?;
    ensure!(
        raw_virtual_end <= layout.size_of_image,
        "TLS template extends past image size"
    );

    let mut ordered_callbacks = callback_contributions.to_vec();
    ordered_callbacks.sort_by(|left, right| {
        left.section_name
            .cmp(right.section_name)
            .then_with(|| left.order.cmp(&right.order))
    });
    validate_unique_orders(
        ordered_callbacks.iter().map(|item| item.order),
        "TLS callback contribution",
    )?;

    let callback_count = ordered_callbacks.iter().try_fold(0usize, |count, item| {
        validate_callback_name(item.section_name)?;
        count
            .checked_add(item.target_rvas.len())
            .context("TLS callback count overflow")
    })?;
    let callback_byte_len = callback_count
        .checked_add(1)
        .and_then(|count| count.checked_mul(POINTER_SIZE as usize))
        .context("TLS callback array size overflow")?;
    let callbacks_size =
        u32::try_from(callback_byte_len).context("TLS callback array exceeds 4 GiB")?;
    validate_range(
        layout.callbacks_rva,
        callbacks_size,
        layout.size_of_image,
        "TLS callback array",
    )?;

    let mut callbacks = Vec::with_capacity(callback_byte_len);
    let mut callback_field_rvas = Vec::with_capacity(callback_count);
    for contribution in ordered_callbacks {
        for target_rva in contribution.target_rvas {
            ensure!(*target_rva != 0, "TLS callback target RVA must not be zero");
            ensure!(
                *target_rva < layout.size_of_image,
                "TLS callback target RVA {target_rva:#x} lies outside the image"
            );
            callbacks.extend_from_slice(&va(layout.image_base, *target_rva)?.to_le_bytes());
            let field_offset = u32::try_from(callbacks.len() - POINTER_SIZE as usize)
                .context("TLS callback field offset exceeds 4 GiB")?;
            callback_field_rvas.push(
                layout
                    .callbacks_rva
                    .checked_add(field_offset)
                    .context("TLS callback relocation RVA overflow")?,
            );
        }
    }
    callbacks.extend_from_slice(&0_u64.to_le_bytes());

    validate_range(
        layout.index_rva,
        TLS_INDEX_SIZE,
        layout.size_of_image,
        "_tls_index",
    )?;
    validate_range(
        layout.directory_rva,
        IMAGE_TLS_DIRECTORY64_SIZE,
        layout.size_of_image,
        "TLS directory",
    )?;

    let characteristics = alignment_characteristics(maximum_alignment)?;
    let mut directory = [0; IMAGE_TLS_DIRECTORY64_SIZE as usize];
    write_u64(
        &mut directory,
        0,
        va(layout.image_base, layout.raw_data_rva)?,
    );
    write_u64(&mut directory, 8, va(layout.image_base, raw_data_end_rva)?);
    write_u64(&mut directory, 16, va(layout.image_base, layout.index_rva)?);
    write_u64(
        &mut directory,
        24,
        va(layout.image_base, layout.callbacks_rva)?,
    );
    write_u32(&mut directory, 32, size_of_zero_fill);
    write_u32(&mut directory, 36, characteristics);

    let mut dir64_relocation_rvas = [0_u32, 8, 16, 24]
        .into_iter()
        .map(|offset| {
            layout
                .directory_rva
                .checked_add(offset)
                .context("TLS directory relocation RVA overflow")
        })
        .collect::<Result<Vec<_>>>()?;
    dir64_relocation_rvas.extend(callback_field_rvas);

    Ok(TlsImage {
        raw_data: memory,
        raw_data_virtual_size,
        index: [0; TLS_INDEX_SIZE as usize],
        callbacks,
        directory,
        data_directory: TlsDataDirectory {
            rva: layout.directory_rva,
            size: IMAGE_TLS_DIRECTORY64_SIZE,
        },
        placements,
        dir64_relocation_rvas,
    })
}

/// Parses and validates one `IMAGE_TLS_DIRECTORY64`.
pub fn parse_amd64_tls_directory(
    directory: &[u8],
    image_base: u64,
    size_of_image: u32,
) -> Result<ParsedTlsDirectory> {
    ensure!(
        directory.len() == IMAGE_TLS_DIRECTORY64_SIZE as usize,
        "IMAGE_TLS_DIRECTORY64 must be exactly {IMAGE_TLS_DIRECTORY64_SIZE} bytes"
    );
    let start = rva_from_va(read_u64(directory, 0), image_base, "TLS raw-data start")?;
    let end = rva_from_va(read_u64(directory, 8), image_base, "TLS raw-data end")?;
    let index = rva_from_va(read_u64(directory, 16), image_base, "_tls_index")?;
    let callbacks = rva_from_va(read_u64(directory, 24), image_base, "TLS callbacks")?;
    ensure!(start <= end, "TLS raw-data start is after its end");
    ensure!(
        end <= size_of_image,
        "TLS raw-data range lies outside the image"
    );
    validate_range(index, TLS_INDEX_SIZE, size_of_image, "_tls_index")?;
    ensure!(
        callbacks < size_of_image,
        "TLS callback array starts outside the image"
    );
    let characteristics = read_u32(directory, 36);
    ensure!(
        characteristics & !IMAGE_SCN_ALIGN_MASK == 0,
        "unsupported TLS characteristics {characteristics:#x}"
    );
    let alignment = decode_alignment_characteristics(characteristics)?;

    Ok(ParsedTlsDirectory {
        raw_data_start_rva: start,
        raw_data_end_rva: end,
        index_rva: index,
        callbacks_rva: callbacks,
        size_of_zero_fill: read_u32(directory, 32),
        alignment,
    })
}

fn validate_layout(layout: TlsLayout) -> Result<()> {
    ensure!(layout.image_base != 0, "PE image base must not be zero");
    ensure!(layout.size_of_image != 0, "PE image size must not be zero");
    Ok(())
}

fn validate_tls_name(name: &[u8]) -> Result<()> {
    ensure!(
        name == b".tls" || name.starts_with(b".tls$"),
        "TLS contribution name {:?} is not .tls or .tls$*",
        String::from_utf8_lossy(name)
    );
    Ok(())
}

fn validate_callback_name(name: &[u8]) -> Result<()> {
    ensure!(
        name.starts_with(b".CRT$XL") && name.len() > b".CRT$XL".len(),
        "TLS callback contribution name {:?} is not .CRT$XL*",
        String::from_utf8_lossy(name)
    );
    Ok(())
}

fn validate_unique_orders(orders: impl IntoIterator<Item = u64>, description: &str) -> Result<()> {
    let mut orders = orders.into_iter().collect::<Vec<_>>();
    orders.sort_unstable();
    ensure!(
        !orders.windows(2).any(|pair| pair[0] == pair[1]),
        "duplicate {description} order"
    );
    Ok(())
}

fn validate_alignment(alignment: u32) -> Result<()> {
    ensure!(
        alignment.is_power_of_two(),
        "TLS alignment {alignment} is not a power of two"
    );
    ensure!(
        alignment <= MAX_COFF_ALIGNMENT,
        "TLS alignment {alignment} exceeds COFF maximum {MAX_COFF_ALIGNMENT}"
    );
    Ok(())
}

fn alignment_characteristics(alignment: u32) -> Result<u32> {
    validate_alignment(alignment)?;
    Ok((alignment.trailing_zeros() + 1) << 20)
}

fn decode_alignment_characteristics(characteristics: u32) -> Result<u32> {
    let encoded = (characteristics & IMAGE_SCN_ALIGN_MASK) >> 20;
    ensure!(
        (1..=14).contains(&encoded),
        "invalid TLS alignment encoding"
    );
    Ok(1 << (encoded - 1))
}

fn align_up_usize(value: usize, alignment: u32) -> Result<usize> {
    let alignment = usize::try_from(alignment).context("TLS alignment does not fit usize")?;
    let mask = alignment - 1;
    value
        .checked_add(mask)
        .map(|value| value & !mask)
        .context("TLS contribution alignment overflow")
}

fn validate_range(start: u32, size: u32, image_size: u32, description: &str) -> Result<()> {
    let end = start
        .checked_add(size)
        .with_context(|| format!("{description} RVA range overflow"))?;
    ensure!(end <= image_size, "{description} extends past image size");
    Ok(())
}

fn va(image_base: u64, rva: u32) -> Result<u64> {
    image_base
        .checked_add(u64::from(rva))
        .context("PE virtual address overflow")
}

fn rva_from_va(value: u64, image_base: u64, description: &str) -> Result<u32> {
    let rva = value
        .checked_sub(image_base)
        .with_context(|| format!("{description} VA lies below the image base"))?;
    u32::try_from(rva).with_context(|| format!("{description} RVA exceeds 32 bits"))
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap())
}

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAYOUT: TlsLayout = TlsLayout {
        image_base: 0x0001_4000_0000,
        raw_data_rva: 0x4000,
        index_rva: 0x5000,
        callbacks_rva: 0x5010,
        directory_rva: 0x6000,
        size_of_image: 0x8000,
    };

    fn contribution<'a>(
        name: &'a [u8],
        data: &'a [u8],
        zero_fill: u32,
        alignment: u32,
        order: u64,
    ) -> TlsContribution<'a> {
        TlsContribution {
            section_name: name,
            data,
            zero_fill,
            alignment,
            order,
        }
    }

    #[test]
    fn builds_directory_template_index_callbacks_and_relocations() {
        let tls = [
            contribution(b".tls$ZZZ", &[], 4, 4, 3),
            contribution(b".tls$AAB", &[3], 2, 8, 2),
            contribution(b".tls$AAA", &[1, 2], 0, 2, 1),
        ];
        let callbacks = [
            TlsCallbackContribution {
                section_name: b".CRT$XLZ",
                target_rvas: &[0x1200],
                order: 12,
            },
            TlsCallbackContribution {
                section_name: b".CRT$XLB",
                target_rvas: &[0x1100, 0x1150],
                order: 11,
            },
        ];
        let image = build_amd64_tls_image(LAYOUT, &tls, &callbacks).unwrap();

        assert_eq!(image.raw_data, vec![1, 2, 0, 0, 0, 0, 0, 0, 3]);
        assert_eq!(image.raw_data_virtual_size, 16);
        assert_eq!(image.index, [0; 4]);
        let pointers = image
            .callbacks
            .chunks_exact(8)
            .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(pointers, vec![0x1400_01100, 0x1400_01150, 0x1400_01200, 0]);
        assert_eq!(
            image.dir64_relocation_rvas,
            vec![0x6000, 0x6008, 0x6010, 0x6018, 0x5010, 0x5018, 0x5020]
        );
        assert_eq!(
            image.data_directory,
            TlsDataDirectory {
                rva: 0x6000,
                size: 40
            }
        );
        assert_eq!(
            image.placements,
            vec![
                TlsContributionPlacement {
                    order: 1,
                    offset: 0,
                    initialized_size: 2,
                    virtual_size: 2,
                },
                TlsContributionPlacement {
                    order: 2,
                    offset: 8,
                    initialized_size: 1,
                    virtual_size: 3,
                },
                TlsContributionPlacement {
                    order: 3,
                    offset: 12,
                    initialized_size: 0,
                    virtual_size: 4,
                }
            ]
        );

        assert_eq!(
            parse_amd64_tls_directory(&image.directory, LAYOUT.image_base, LAYOUT.size_of_image)
                .unwrap(),
            ParsedTlsDirectory {
                raw_data_start_rva: 0x4000,
                raw_data_end_rva: 0x4009,
                index_rva: 0x5000,
                callbacks_rva: 0x5010,
                size_of_zero_fill: 7,
                alignment: 8,
            }
        );
    }

    #[test]
    fn materializes_zero_fill_before_later_initialized_data() {
        let tls = [
            contribution(b".tls$A", &[1], 3, 1, 1),
            contribution(b".tls$B", &[2], 2, 1, 2),
        ];
        let image = build_amd64_tls_image(LAYOUT, &tls, &[]).unwrap();
        assert_eq!(image.raw_data, vec![1, 0, 0, 0, 2]);
        assert_eq!(image.raw_data_virtual_size, 7);
        let parsed =
            parse_amd64_tls_directory(&image.directory, LAYOUT.image_base, 0x8000).unwrap();
        assert_eq!(parsed.raw_data_end_rva, 0x4005);
        assert_eq!(parsed.size_of_zero_fill, 2);
        assert_eq!(image.callbacks, vec![0; 8]);
        assert_eq!(image.dir64_relocation_rvas.len(), 4);
    }

    #[test]
    fn is_deterministic_for_permuted_inputs() {
        let a = contribution(b".tls$A", &[1], 0, 1, 1);
        let b = contribution(b".tls$B", &[2], 0, 1, 2);
        let ca = TlsCallbackContribution {
            section_name: b".CRT$XLA",
            target_rvas: &[0x1000],
            order: 3,
        };
        let cb = TlsCallbackContribution {
            section_name: b".CRT$XLB",
            target_rvas: &[0x2000],
            order: 4,
        };
        let first = build_amd64_tls_image(LAYOUT, &[b, a], &[cb, ca]).unwrap();
        let second = build_amd64_tls_image(LAYOUT, &[a, b], &[ca, cb]).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn rejects_invalid_names_alignment_orders_and_callbacks() {
        let invalid = contribution(b".data", &[1], 0, 1, 1);
        assert!(
            build_amd64_tls_image(LAYOUT, &[invalid], &[])
                .unwrap_err()
                .to_string()
                .contains("not .tls")
        );
        let invalid = contribution(b".tls", &[1], 0, 3, 1);
        assert!(
            build_amd64_tls_image(LAYOUT, &[invalid], &[])
                .unwrap_err()
                .to_string()
                .contains("power of two")
        );
        let duplicate = [
            contribution(b".tls$A", &[1], 0, 1, 7),
            contribution(b".tls$B", &[2], 0, 1, 7),
        ];
        assert!(
            build_amd64_tls_image(LAYOUT, &duplicate, &[])
                .unwrap_err()
                .to_string()
                .contains("duplicate TLS contribution order")
        );
        let tls = contribution(b".tls", &[1], 0, 1, 1);
        let invalid_callback = TlsCallbackContribution {
            section_name: b".CRT$XI",
            target_rvas: &[1],
            order: 2,
        };
        assert!(
            build_amd64_tls_image(LAYOUT, &[tls], &[invalid_callback])
                .unwrap_err()
                .to_string()
                .contains("not .CRT$XL")
        );
        let null_callback = TlsCallbackContribution {
            section_name: b".CRT$XLB",
            target_rvas: &[0],
            order: 2,
        };
        assert!(
            build_amd64_tls_image(LAYOUT, &[tls], &[null_callback])
                .unwrap_err()
                .to_string()
                .contains("must not be zero")
        );
    }

    #[test]
    fn rejects_out_of_bounds_and_va_overflow() {
        let tls = contribution(b".tls", &[1; 16], 0, 1, 1);
        let short = TlsLayout {
            size_of_image: 0x4008,
            ..LAYOUT
        };
        assert!(
            build_amd64_tls_image(short, &[tls], &[])
                .unwrap_err()
                .to_string()
                .contains("extends past image")
        );
        let overflow = TlsLayout {
            image_base: u64::MAX,
            ..LAYOUT
        };
        assert!(
            build_amd64_tls_image(overflow, &[tls], &[])
                .unwrap_err()
                .to_string()
                .contains("virtual address overflow")
        );
    }

    #[test]
    fn parser_rejects_malformed_directories() {
        let tls = contribution(b".tls", &[1], 0, 1, 1);
        let image = build_amd64_tls_image(LAYOUT, &[tls], &[]).unwrap();
        assert!(
            parse_amd64_tls_directory(&image.directory[..39], LAYOUT.image_base, 0x8000).is_err()
        );

        let mut reversed = image.directory;
        write_u64(&mut reversed, 0, LAYOUT.image_base + 0x4100);
        write_u64(&mut reversed, 8, LAYOUT.image_base + 0x4000);
        assert!(
            parse_amd64_tls_directory(&reversed, LAYOUT.image_base, 0x8000)
                .unwrap_err()
                .to_string()
                .contains("after its end")
        );

        let mut invalid_alignment = image.directory;
        write_u32(&mut invalid_alignment, 36, 0x00f0_0000);
        assert!(
            parse_amd64_tls_directory(&invalid_alignment, LAYOUT.image_base, 0x8000)
                .unwrap_err()
                .to_string()
                .contains("alignment encoding")
        );
    }
}
