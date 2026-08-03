//! PE checksum calculation and Authenticode hashing exclusions.
//!
//! The certificate-table data-directory address is a file offset, unlike the
//! RVA used by every other PE data-directory entry.

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use std::ops::Range;

const DOS_PE_POINTER_OFFSET: usize = 0x3c;
const COFF_HEADER_SIZE: usize = 20;
const OPTIONAL_HEADER_PREFIX_SIZE: usize = 112;
const PE32_PLUS_MAGIC: u16 = 0x20b;
const SIZE_OF_HEADERS_OFFSET: usize = 60;
const CHECKSUM_OFFSET_IN_OPTIONAL_HEADER: usize = 64;
const NUMBER_OF_DIRECTORIES_OFFSET: usize = 108;
const DATA_DIRECTORIES_OFFSET: usize = 112;
const SECURITY_DIRECTORY_INDEX: usize = 4;
const DATA_DIRECTORY_SIZE: usize = 8;

/// PE header locations relevant to checksums and Authenticode hashing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeChecksumLayout {
    /// File range occupied by `IMAGE_OPTIONAL_HEADER64.CheckSum`.
    pub checksum: Range<usize>,
    /// File range occupied by the certificate-table data-directory entry.
    ///
    /// Old or deliberately minimal images may declare fewer than five data
    /// directories, in which case there is no entry to exclude.
    pub certificate_directory: Option<Range<usize>>,
    /// File range occupied by the certificate table itself, when present.
    pub certificate_table: Option<Range<usize>>,
}

/// Parses the PE32+ header locations needed by the checksum algorithms.
pub fn pe_checksum_layout(image: &[u8]) -> Result<PeChecksumLayout> {
    let pe_pointer_end = DOS_PE_POINTER_OFFSET
        .checked_add(4)
        .context("DOS PE-header pointer range overflow")?;
    ensure!(image.len() >= pe_pointer_end, "truncated DOS header");
    ensure!(&image[..2] == b"MZ", "invalid DOS header signature");

    let pe_offset = usize::try_from(read_u32(image, DOS_PE_POINTER_OFFSET)?)
        .context("PE header offset does not fit in usize")?;
    let coff_offset = pe_offset
        .checked_add(4)
        .context("PE signature range overflow")?;
    let optional_offset = coff_offset
        .checked_add(COFF_HEADER_SIZE)
        .context("optional-header offset overflow")?;
    ensure!(
        image.get(pe_offset..coff_offset) == Some(b"PE\0\0"),
        "invalid PE signature"
    );
    ensure!(image.len() >= optional_offset, "truncated PE COFF header");

    let optional_size_offset = coff_offset
        .checked_add(16)
        .context("COFF optional-header-size offset overflow")?;
    let optional_size = usize::from(read_u16(image, optional_size_offset)?);
    ensure!(
        optional_size >= OPTIONAL_HEADER_PREFIX_SIZE,
        "PE32+ optional header is smaller than its fixed fields"
    );
    let optional_end = optional_offset
        .checked_add(optional_size)
        .context("optional-header range overflow")?;
    ensure!(optional_end <= image.len(), "truncated PE optional header");
    ensure!(
        read_u16(image, optional_offset)? == PE32_PLUS_MAGIC,
        "image is not PE32+"
    );

    let checksum_start = optional_offset
        .checked_add(CHECKSUM_OFFSET_IN_OPTIONAL_HEADER)
        .context("checksum offset overflow")?;
    let checksum = checked_range(checksum_start, 4, optional_end, "PE checksum")?;
    let size_of_headers_offset = optional_offset
        .checked_add(SIZE_OF_HEADERS_OFFSET)
        .context("size-of-headers offset overflow")?;
    let size_of_headers = usize::try_from(read_u32(image, size_of_headers_offset)?)
        .context("PE size of headers does not fit in usize")?;
    ensure!(
        size_of_headers >= optional_end && size_of_headers <= image.len(),
        "PE size of headers lies outside the image headers"
    );

    let directory_count_offset = optional_offset
        .checked_add(NUMBER_OF_DIRECTORIES_OFFSET)
        .context("data-directory count offset overflow")?;
    let directory_count = usize::try_from(read_u32(image, directory_count_offset)?)
        .context("data-directory count does not fit in usize")?;
    let available_directories = optional_size
        .checked_sub(DATA_DIRECTORIES_OFFSET)
        .context("optional-header data-directory range underflow")?
        / DATA_DIRECTORY_SIZE;
    ensure!(
        directory_count <= available_directories,
        "data-directory count exceeds the optional header"
    );

    if directory_count <= SECURITY_DIRECTORY_INDEX {
        return Ok(PeChecksumLayout {
            checksum,
            certificate_directory: None,
            certificate_table: None,
        });
    }

    let security_offset = optional_offset
        .checked_add(DATA_DIRECTORIES_OFFSET)
        .and_then(|offset| {
            SECURITY_DIRECTORY_INDEX
                .checked_mul(DATA_DIRECTORY_SIZE)
                .and_then(|index| offset.checked_add(index))
        })
        .context("certificate-directory offset overflow")?;
    let certificate_directory = checked_range(
        security_offset,
        DATA_DIRECTORY_SIZE,
        optional_end,
        "certificate-directory entry",
    )?;
    let certificate_offset = usize::try_from(read_u32(image, security_offset)?)
        .context("certificate-table offset does not fit in usize")?;
    let certificate_size = usize::try_from(read_u32(image, security_offset + 4)?)
        .context("certificate-table size does not fit in usize")?;

    let certificate_table = match (certificate_offset, certificate_size) {
        (0, 0) => None,
        (0, _) | (_, 0) => anyhow::bail!(
            "certificate-table offset and size must either both be zero or both be nonzero"
        ),
        (offset, size) => {
            ensure!(
                offset.is_multiple_of(8),
                "certificate-table file offset is not 8-byte aligned"
            );
            ensure!(
                size.is_multiple_of(8),
                "certificate-table size is not 8-byte aligned"
            );
            let range = checked_range(offset, size, image.len(), "certificate table")?;
            ensure!(
                range.start >= size_of_headers,
                "certificate table overlaps PE headers"
            );
            Some(range)
        }
    };

    Ok(PeChecksumLayout {
        checksum,
        certificate_directory: Some(certificate_directory),
        certificate_table,
    })
}

/// Computes the standard Windows PE checksum.
///
/// The stored checksum field is treated as four zero bytes. Words are summed
/// little-endian with end-around carry, then the file length is added, matching
/// `MapFileAndCheckSum`. Files larger than the representable PE checksum input
/// size are rejected instead of silently truncating their length.
pub fn compute_pe_checksum(image: &[u8]) -> Result<u32> {
    let layout = pe_checksum_layout(image)?;
    let file_size = u32::try_from(image.len()).context("PE image exceeds 4 GiB")?;
    let mut sum = 0u64;

    for (word_index, bytes) in image.chunks(2).enumerate() {
        let offset = word_index
            .checked_mul(2)
            .context("PE checksum word offset overflow")?;
        let low = checksum_byte(image, offset, &layout.checksum);
        let high = if bytes.len() == 2 {
            checksum_byte(image, offset + 1, &layout.checksum)
        } else {
            0
        };
        sum += u64::from(u16::from_le_bytes([low, high]));
        sum = (sum & 0xffff) + (sum >> 16);
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    // `MapFileAndCheckSum` exposes a DWORD result, so the final unsigned
    // addition has the same modulo-2^32 behavior as the Windows routine.
    Ok(u32::from(sum as u16).wrapping_add(file_size))
}

/// Computes and writes the standard PE checksum, returning the stored value.
pub fn patch_pe_checksum(image: &mut [u8]) -> Result<u32> {
    let layout = pe_checksum_layout(image)?;
    let checksum = compute_pe_checksum(image)?;
    image[layout.checksum].copy_from_slice(&checksum.to_le_bytes());
    Ok(checksum)
}

/// Reports whether the stored PE checksum matches the computed value.
pub fn verify_pe_checksum(image: &[u8]) -> Result<bool> {
    let layout = pe_checksum_layout(image)?;
    let stored = u32::from_le_bytes(
        image[layout.checksum]
            .try_into()
            .expect("checksum layout is exactly four bytes"),
    );
    Ok(stored == compute_pe_checksum(image)?)
}

/// Iterator over the byte slices covered by an Authenticode image hash.
///
/// Feed the slices, in iteration order, to any caller-selected digest. The PE
/// checksum, certificate-directory entry, and certificate blob are omitted.
pub struct AuthenticodeHashRanges<'a> {
    image: &'a [u8],
    ranges: std::vec::IntoIter<Range<usize>>,
}

impl<'a> Iterator for AuthenticodeHashRanges<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        self.ranges.next().map(|range| &self.image[range])
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.ranges.size_hint()
    }
}

impl ExactSizeIterator for AuthenticodeHashRanges<'_> {}

/// Returns the ordered byte ranges included in an Authenticode image hash.
pub fn authenticode_hash_ranges(image: &[u8]) -> Result<AuthenticodeHashRanges<'_>> {
    let layout = pe_checksum_layout(image)?;
    let mut exclusions = vec![layout.checksum];
    exclusions.extend(layout.certificate_directory);
    exclusions.extend(layout.certificate_table);
    exclusions.sort_unstable_by_key(|range| range.start);

    let mut included = Vec::with_capacity(exclusions.len() + 1);
    let mut cursor = 0;
    for excluded in exclusions {
        ensure!(
            excluded.start >= cursor,
            "Authenticode excluded ranges overlap"
        );
        if cursor != excluded.start {
            included.push(cursor..excluded.start);
        }
        cursor = excluded.end;
    }
    if cursor != image.len() {
        included.push(cursor..image.len());
    }

    Ok(AuthenticodeHashRanges {
        image,
        ranges: included.into_iter(),
    })
}

fn checksum_byte(image: &[u8], offset: usize, checksum: &Range<usize>) -> u8 {
    if checksum.contains(&offset) {
        0
    } else {
        image[offset]
    }
}

fn checked_range(
    start: usize,
    size: usize,
    limit: usize,
    description: &str,
) -> Result<Range<usize>> {
    let end = start
        .checked_add(size)
        .with_context(|| format!("{description} range overflow"))?;
    ensure!(end <= limit, "{description} lies outside the image");
    Ok(start..end)
}

fn read_u16(image: &[u8], offset: usize) -> Result<u16> {
    let range = checked_range(offset, 2, image.len(), "16-bit PE field")?;
    Ok(u16::from_le_bytes(image[range].try_into().unwrap()))
}

fn read_u32(image: &[u8], offset: usize) -> Result<u32> {
    let range = checked_range(offset, 4, image.len(), "32-bit PE field")?;
    Ok(u32::from_le_bytes(image[range].try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PE_OFFSET: usize = 0x80;
    const OPTIONAL_OFFSET: usize = PE_OFFSET + 4 + COFF_HEADER_SIZE;
    const CHECKSUM_OFFSET: usize = OPTIONAL_OFFSET + CHECKSUM_OFFSET_IN_OPTIONAL_HEADER;
    const SECURITY_OFFSET: usize =
        OPTIONAL_OFFSET + DATA_DIRECTORIES_OFFSET + SECURITY_DIRECTORY_INDEX * DATA_DIRECTORY_SIZE;

    fn image_with_certificate(certificate: Option<Range<usize>>) -> Vec<u8> {
        let length = certificate.as_ref().map_or(0x200, |range| range.end + 16);
        let mut image = (0..length).map(|value| value as u8).collect::<Vec<_>>();
        image[..2].copy_from_slice(b"MZ");
        put_u32(&mut image, DOS_PE_POINTER_OFFSET, PE_OFFSET as u32);
        image[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
        put_u16(&mut image, PE_OFFSET + 4 + 16, 0xf0);
        put_u16(&mut image, OPTIONAL_OFFSET, PE32_PLUS_MAGIC);
        put_u32(&mut image, OPTIONAL_OFFSET + SIZE_OF_HEADERS_OFFSET, 0x200);
        put_u32(
            &mut image,
            OPTIONAL_OFFSET + NUMBER_OF_DIRECTORIES_OFFSET,
            16,
        );
        put_u32(&mut image, CHECKSUM_OFFSET, 0xdead_beef);
        if let Some(range) = certificate {
            put_u32(&mut image, SECURITY_OFFSET, range.start as u32);
            put_u32(
                &mut image,
                SECURITY_OFFSET + 4,
                (range.end - range.start) as u32,
            );
        } else {
            put_u32(&mut image, SECURITY_OFFSET, 0);
            put_u32(&mut image, SECURITY_OFFSET + 4, 0);
        }
        image
    }

    #[test]
    fn checksum_ignores_stored_value_and_patches_it() {
        let mut image = image_with_certificate(None);
        let checksum = compute_pe_checksum(&image).unwrap();
        put_u32(&mut image, CHECKSUM_OFFSET, 0x1234_5678);
        assert_eq!(compute_pe_checksum(&image).unwrap(), checksum);
        assert!(!verify_pe_checksum(&image).unwrap());
        assert_eq!(patch_pe_checksum(&mut image).unwrap(), checksum);
        assert!(verify_pe_checksum(&image).unwrap());
        assert_eq!(read_u32(&image, CHECKSUM_OFFSET).unwrap(), checksum);
    }

    #[test]
    fn checksum_matches_independent_word_sum_fixture() {
        let image = image_with_certificate(None);
        let mut independent = image.clone();
        independent[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].fill(0);
        let word_sum = independent.chunks(2).fold(0u64, |sum, chunk| {
            let word = u16::from_le_bytes([chunk[0], chunk.get(1).copied().unwrap_or(0)]);
            sum + u64::from(word)
        });
        let folded = (word_sum & 0xffff) + (word_sum >> 16);
        let folded = (folded & 0xffff) + (folded >> 16);
        let expected = u32::from(folded as u16) + image.len() as u32;
        assert_eq!(expected, 0x0000_54e8);
        assert_eq!(compute_pe_checksum(&image).unwrap(), expected);
    }

    #[test]
    fn authenticode_ranges_exclude_all_mutable_regions() {
        let certificate = 0x200..0x218;
        let image = image_with_certificate(Some(certificate.clone()));
        let ranges = authenticode_hash_ranges(&image)
            .unwrap()
            .map(|bytes| {
                let start = bytes.as_ptr() as usize - image.as_ptr() as usize;
                start..start + bytes.len()
            })
            .collect::<Vec<_>>();

        assert_eq!(
            ranges,
            vec![
                0..CHECKSUM_OFFSET,
                CHECKSUM_OFFSET + 4..SECURITY_OFFSET,
                SECURITY_OFFSET + 8..certificate.start,
                certificate.end..image.len(),
            ]
        );
        let hashed = authenticode_hash_ranges(&image)
            .unwrap()
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(
            hashed.len(),
            image.len() - 4 - DATA_DIRECTORY_SIZE - certificate.len()
        );
    }

    #[test]
    fn authenticode_supports_absent_security_directory() {
        let mut image = image_with_certificate(None);
        put_u16(
            &mut image,
            PE_OFFSET + 4 + 16,
            OPTIONAL_HEADER_PREFIX_SIZE as u16,
        );
        image.truncate(OPTIONAL_OFFSET + OPTIONAL_HEADER_PREFIX_SIZE);
        let image_len = image.len() as u32;
        put_u32(
            &mut image,
            OPTIONAL_OFFSET + SIZE_OF_HEADERS_OFFSET,
            image_len,
        );
        put_u32(
            &mut image,
            OPTIONAL_OFFSET + NUMBER_OF_DIRECTORIES_OFFSET,
            0,
        );
        let hashed_length = authenticode_hash_ranges(&image)
            .unwrap()
            .map(<[u8]>::len)
            .sum::<usize>();
        assert_eq!(hashed_length, image.len() - 4);
    }

    #[test]
    fn rejects_malformed_and_out_of_bounds_headers() {
        let image = image_with_certificate(None);
        for end in [
            0,
            2,
            DOS_PE_POINTER_OFFSET + 3,
            PE_OFFSET + 3,
            OPTIONAL_OFFSET + 1,
        ] {
            assert!(pe_checksum_layout(&image[..end]).is_err(), "end={end}");
        }

        let mut bad = image.clone();
        put_u16(&mut bad, OPTIONAL_OFFSET, 0x10b);
        assert!(
            pe_checksum_layout(&bad)
                .unwrap_err()
                .to_string()
                .contains("PE32+")
        );

        let mut bad = image.clone();
        put_u32(&mut bad, OPTIONAL_OFFSET + NUMBER_OF_DIRECTORIES_OFFSET, 31);
        assert!(
            pe_checksum_layout(&bad)
                .unwrap_err()
                .to_string()
                .contains("exceeds")
        );

        let mut bad = image;
        put_u32(&mut bad, SECURITY_OFFSET, 0x1f8);
        put_u32(&mut bad, SECURITY_OFFSET + 4, 32);
        assert!(
            pe_checksum_layout(&bad)
                .unwrap_err()
                .to_string()
                .contains("outside")
        );
    }

    #[test]
    fn rejects_inconsistent_unaligned_and_overlapping_certificates() {
        let mut image = image_with_certificate(None);
        put_u32(&mut image, SECURITY_OFFSET + 4, 8);
        assert!(
            pe_checksum_layout(&image)
                .unwrap_err()
                .to_string()
                .contains("both")
        );

        let mut image = image_with_certificate(None);
        put_u32(&mut image, SECURITY_OFFSET, 0x181);
        put_u32(&mut image, SECURITY_OFFSET + 4, 8);
        assert!(
            pe_checksum_layout(&image)
                .unwrap_err()
                .to_string()
                .contains("aligned")
        );

        let mut image = image_with_certificate(None);
        put_u32(&mut image, SECURITY_OFFSET, 0x80);
        put_u32(&mut image, SECURITY_OFFSET + 4, 8);
        assert!(
            pe_checksum_layout(&image)
                .unwrap_err()
                .to_string()
                .contains("overlaps")
        );
    }

    fn put_u16(image: &mut [u8], offset: usize, value: u16) {
        image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(image: &mut [u8], offset: usize, value: u32) {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}
