//! Encoding and validation of PE base relocations used by AMD64 images.
//!
//! PE groups base relocations into 4 KiB pages. Each 16-bit entry contains a
//! four-bit relocation type and a 12-bit offset from the block's page RVA.

use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use rayon::prelude::*;

const PAGE_SIZE: u32 = 0x1000;
const BLOCK_HEADER_SIZE: usize = 8;
const ENTRY_SIZE: usize = 2;
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_DIR64: u16 = 10;

/// Builds an AMD64 PE base-relocation table from the RVAs of 64-bit addresses.
///
/// Entries are sorted and deduplicated, making the result independent of input
/// order. `size_of_image` is the exclusive upper bound of the mapped image. A
/// DIR64 field occupies eight bytes, so every supplied RVA must leave all eight
/// bytes inside the image.
///
/// An empty iterator produces an empty table. DIR64 fields are not required by
/// the PE format to be naturally aligned; alignment validation instead applies
/// to the page and block layout of the encoded table.
pub fn build_amd64_base_relocation_table(
    dir64_rvas: impl IntoIterator<Item = u32>,
    size_of_image: u32,
) -> Result<Vec<u8>> {
    let mut rvas = Vec::new();
    for rva in dir64_rvas {
        validate_dir64_bounds(rva, size_of_image)?;
        rvas.push(rva);
    }
    if rvas.len() >= 8192 && rayon::current_num_threads() > 1 {
        rvas.par_sort_unstable();
    } else {
        rvas.sort_unstable();
    }
    rvas.dedup();

    let mut output = Vec::with_capacity(rvas.len().saturating_mul(ENTRY_SIZE));
    let mut start = 0usize;
    while start < rvas.len() {
        let page_rva = rvas[start] & !(PAGE_SIZE - 1);
        let mut end = start + 1;
        while end < rvas.len() && rvas[end] & !(PAGE_SIZE - 1) == page_rva {
            end += 1;
        }
        let offsets = &rvas[start..end];
        let needs_padding = offsets.len() % 2 != 0;
        let entry_count = offsets
            .len()
            .checked_add(usize::from(needs_padding))
            .ok_or_else(|| anyhow::anyhow!("base relocation entry count overflow"))?;
        let block_size = BLOCK_HEADER_SIZE
            .checked_add(
                entry_count
                    .checked_mul(ENTRY_SIZE)
                    .ok_or_else(|| anyhow::anyhow!("base relocation block size overflow"))?,
            )
            .ok_or_else(|| anyhow::anyhow!("base relocation block size overflow"))?;
        let block_size = u32::try_from(block_size)
            .map_err(|_| anyhow::anyhow!("base relocation block exceeds u32 size"))?;

        output.extend_from_slice(&page_rva.to_le_bytes());
        output.extend_from_slice(&block_size.to_le_bytes());
        for rva in offsets.iter().copied() {
            let offset = u16::try_from(rva - page_rva)
                .map_err(|_| anyhow::anyhow!("base relocation page offset does not fit in u16"))?;
            debug_assert!(offset < PAGE_SIZE as u16);
            let entry = (IMAGE_REL_BASED_DIR64 << 12) | offset;
            output.extend_from_slice(&entry.to_le_bytes());
        }
        if needs_padding {
            output.extend_from_slice(&IMAGE_REL_BASED_ABSOLUTE.to_le_bytes());
        }
        start = end;
    }

    Ok(output)
}

/// Parses and validates an AMD64 PE base-relocation table.
///
/// ABSOLUTE padding entries are discarded. DIR64 entries are returned in file
/// order, allowing callers to inspect non-canonical but valid input. Relocation
/// types other than ABSOLUTE and DIR64 are rejected because this helper models
/// AMD64 64-bit address fixups specifically.
pub fn parse_amd64_base_relocation_table(data: &[u8], size_of_image: u32) -> Result<Vec<u32>> {
    let mut cursor = 0usize;
    let mut dir64_rvas = Vec::new();

    while cursor < data.len() {
        let remaining = data.len() - cursor;
        ensure!(
            remaining >= BLOCK_HEADER_SIZE,
            "truncated base relocation block header at offset {cursor:#x}"
        );

        let page_rva = read_u32(data, cursor);
        let block_size = read_u32(data, cursor + 4);
        ensure!(
            page_rva.is_multiple_of(PAGE_SIZE),
            "base relocation page RVA {page_rva:#x} is not 4 KiB aligned"
        );
        ensure!(
            block_size >= BLOCK_HEADER_SIZE as u32,
            "base relocation block at offset {cursor:#x} is smaller than its header"
        );
        ensure!(
            block_size.is_multiple_of(4),
            "base relocation block size {block_size} at offset {cursor:#x} is not 4-byte aligned"
        );
        let block_size = usize::try_from(block_size)
            .map_err(|_| anyhow::anyhow!("base relocation block size does not fit in usize"))?;
        let block_end = cursor
            .checked_add(block_size)
            .ok_or_else(|| anyhow::anyhow!("base relocation block end overflow"))?;
        ensure!(
            block_end <= data.len(),
            "base relocation block at offset {cursor:#x} extends past the table"
        );

        let mut entry_cursor = cursor + BLOCK_HEADER_SIZE;
        while entry_cursor < block_end {
            let entry = read_u16(data, entry_cursor);
            let relocation_type = entry >> 12;
            let page_offset = u32::from(entry & 0x0fff);
            match relocation_type {
                IMAGE_REL_BASED_ABSOLUTE => {}
                IMAGE_REL_BASED_DIR64 => {
                    let rva = page_rva
                        .checked_add(page_offset)
                        .ok_or_else(|| anyhow::anyhow!("base relocation RVA overflows u32"))?;
                    validate_dir64_bounds(rva, size_of_image)?;
                    dir64_rvas.push(rva);
                }
                _ => bail!(
                    "unsupported AMD64 base relocation type {relocation_type} at table offset {entry_cursor:#x}"
                ),
            }
            entry_cursor += ENTRY_SIZE;
        }

        cursor = block_end;
    }

    Ok(dir64_rvas)
}

fn validate_dir64_bounds(rva: u32, size_of_image: u32) -> Result<()> {
    let end = rva
        .checked_add(8)
        .ok_or_else(|| anyhow::anyhow!("DIR64 base relocation at RVA {rva:#x} overflows u32"))?;
    ensure!(
        end <= size_of_image,
        "DIR64 base relocation at RVA {rva:#x} extends past image size {size_of_image:#x}"
    );
    Ok(())
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(bytes: &[u8]) -> Vec<u16> {
        bytes
            .chunks_exact(2)
            .map(|word| u16::from_le_bytes(word.try_into().unwrap()))
            .collect()
    }

    #[test]
    fn builds_sorted_deduplicated_page_blocks() {
        let table =
            build_amd64_base_relocation_table([0x2120, 0x1008, 0x2120, 0x1ff8, 0x2100], 0x4000)
                .unwrap();

        assert_eq!(read_u32(&table, 0), 0x1000);
        assert_eq!(read_u32(&table, 4), 12);
        assert_eq!(
            words(&table[8..12]),
            vec![0xa008, 0xaff8],
            "first page has two sorted DIR64 entries"
        );
        assert_eq!(read_u32(&table, 12), 0x2000);
        assert_eq!(read_u32(&table, 16), 12);
        assert_eq!(
            words(&table[20..24]),
            vec![0xa100, 0xa120],
            "second page has two sorted, deduplicated DIR64 entries"
        );
        assert_eq!(table.len(), 24);
    }

    #[test]
    fn pads_odd_entry_count_with_absolute() {
        let table = build_amd64_base_relocation_table([0x1234], 0x2000).unwrap();
        assert_eq!(table.len(), 12);
        assert_eq!(read_u32(&table, 0), 0x1000);
        assert_eq!(read_u32(&table, 4), 12);
        assert_eq!(words(&table[8..]), vec![0xa234, 0]);
    }

    #[test]
    fn is_deterministic_across_input_order_and_duplicates() {
        let first = build_amd64_base_relocation_table([0x3008, 0x1010, 0x3008], 0x5000).unwrap();
        let second = build_amd64_base_relocation_table([0x1010, 0x3008], 0x5000).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn round_trips_multiple_pages_and_unaligned_fields() {
        let expected = vec![0x1001, 0x1ff8, 0x2000, 0x3456];
        let table = build_amd64_base_relocation_table(expected.iter().copied(), 0x4000).unwrap();
        assert_eq!(
            parse_amd64_base_relocation_table(&table, 0x4000).unwrap(),
            expected
        );
    }

    #[test]
    fn empty_input_has_empty_encoding() {
        let table = build_amd64_base_relocation_table([], 0).unwrap();
        assert!(table.is_empty());
        assert!(
            parse_amd64_base_relocation_table(&table, 0)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn rejects_out_of_bounds_and_overflowing_dir64_fields() {
        assert_eq!(
            build_amd64_base_relocation_table([0xff9], 0x1000)
                .unwrap_err()
                .to_string(),
            "DIR64 base relocation at RVA 0xff9 extends past image size 0x1000"
        );
        assert_eq!(
            build_amd64_base_relocation_table([u32::MAX], u32::MAX)
                .unwrap_err()
                .to_string(),
            "DIR64 base relocation at RVA 0xffffffff overflows u32"
        );
    }

    #[test]
    fn parser_rejects_malformed_block_layout() {
        let mut unaligned_page = Vec::new();
        unaligned_page.extend_from_slice(&0x1001_u32.to_le_bytes());
        unaligned_page.extend_from_slice(&8_u32.to_le_bytes());
        assert!(
            parse_amd64_base_relocation_table(&unaligned_page, 0x2000)
                .unwrap_err()
                .to_string()
                .contains("not 4 KiB aligned")
        );

        let mut unaligned_size = Vec::new();
        unaligned_size.extend_from_slice(&0x1000_u32.to_le_bytes());
        unaligned_size.extend_from_slice(&10_u32.to_le_bytes());
        unaligned_size.extend_from_slice(&0_u16.to_le_bytes());
        assert!(
            parse_amd64_base_relocation_table(&unaligned_size, 0x2000)
                .unwrap_err()
                .to_string()
                .contains("not 4-byte aligned")
        );

        let mut truncated = Vec::new();
        truncated.extend_from_slice(&0x1000_u32.to_le_bytes());
        truncated.extend_from_slice(&12_u32.to_le_bytes());
        assert!(
            parse_amd64_base_relocation_table(&truncated, 0x2000)
                .unwrap_err()
                .to_string()
                .contains("extends past the table")
        );
    }

    #[test]
    fn parser_rejects_unsupported_types_and_invalid_targets() {
        let mut unsupported = Vec::new();
        unsupported.extend_from_slice(&0x1000_u32.to_le_bytes());
        unsupported.extend_from_slice(&12_u32.to_le_bytes());
        unsupported.extend_from_slice(&0x3008_u16.to_le_bytes());
        unsupported.extend_from_slice(&0_u16.to_le_bytes());
        assert!(
            parse_amd64_base_relocation_table(&unsupported, 0x2000)
                .unwrap_err()
                .to_string()
                .contains("unsupported AMD64 base relocation type 3")
        );

        let mut out_of_bounds = Vec::new();
        out_of_bounds.extend_from_slice(&0x1000_u32.to_le_bytes());
        out_of_bounds.extend_from_slice(&12_u32.to_le_bytes());
        out_of_bounds.extend_from_slice(&0xaff9_u16.to_le_bytes());
        out_of_bounds.extend_from_slice(&0_u16.to_le_bytes());
        assert!(
            parse_amd64_base_relocation_table(&out_of_bounds, 0x2000)
                .unwrap_err()
                .to_string()
                .contains("extends past image size")
        );
    }
}
