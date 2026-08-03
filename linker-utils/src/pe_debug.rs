//! Deterministic PE debug-directory encoding and parsing.
//!
//! This module intentionally does not create PDB files. It only describes a
//! reproducible build-id record and passes an existing CodeView RSDS identity
//! through to the image.

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use std::ops::Range;

pub const IMAGE_DEBUG_DIRECTORY_SIZE: usize = 28;
pub const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
pub const IMAGE_DEBUG_TYPE_REPRO: u32 = 16;
pub const REPRO_BUILD_ID_SIZE: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodeViewRsds {
    pub guid: [u8; 16],
    pub age: u32,
    /// PDB path bytes, without the trailing NUL.
    pub pdb_path: Vec<u8>,
}

impl CodeViewRsds {
    pub fn new(guid: [u8; 16], age: u32, pdb_path: impl Into<Vec<u8>>) -> Result<Self> {
        let pdb_path = pdb_path.into();
        ensure!(
            !pdb_path.contains(&0),
            "the RSDS PDB path contains an interior NUL"
        );
        Ok(Self {
            guid,
            age,
            pdb_path,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DebugRecord {
    Repro { build_id: [u8; REPRO_BUILD_ID_SIZE] },
    CodeView(CodeViewRsds),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DebugDirectoryEntry {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub debug_type: u32,
    pub size_of_data: u32,
    pub address_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
}

impl DebugDirectoryEntry {
    fn encode(self, output: &mut Vec<u8>) {
        put_u32(output, self.characteristics);
        put_u32(output, self.time_date_stamp);
        put_u16(output, self.major_version);
        put_u16(output, self.minor_version);
        put_u32(output, self.debug_type);
        put_u32(output, self.size_of_data);
        put_u32(output, self.address_of_raw_data);
        put_u32(output, self.pointer_to_raw_data);
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= IMAGE_DEBUG_DIRECTORY_SIZE,
            "truncated IMAGE_DEBUG_DIRECTORY"
        );
        Ok(Self {
            characteristics: read_u32(bytes, 0),
            time_date_stamp: read_u32(bytes, 4),
            major_version: read_u16(bytes, 8),
            minor_version: read_u16(bytes, 10),
            debug_type: read_u32(bytes, 12),
            size_of_data: read_u32(bytes, 16),
            address_of_raw_data: read_u32(bytes, 20),
            pointer_to_raw_data: read_u32(bytes, 24),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedDebugDirectory {
    /// Directory entries followed immediately by their data records.
    pub bytes: Vec<u8>,
    pub entries: Vec<DebugDirectoryEntry>,
    pub directory_size: u32,
}

/// Encodes a contiguous debug directory and its payloads.
///
/// `directory_rva` and `directory_file_offset` identify where the first byte
/// of the returned buffer will be placed. All arithmetic is checked and every
/// timestamp is zero, making the result deterministic.
pub fn encode_debug_directory(
    records: &[DebugRecord],
    directory_rva: u32,
    directory_file_offset: u32,
) -> Result<EncodedDebugDirectory> {
    ensure!(
        !records.is_empty(),
        "a PE debug directory must contain at least one record"
    );
    let directory_len = records
        .len()
        .checked_mul(IMAGE_DEBUG_DIRECTORY_SIZE)
        .context("debug directory size overflow")?;
    let directory_size = u32::try_from(directory_len).context("debug directory exceeds 4 GiB")?;
    let mut payloads = Vec::with_capacity(records.len());
    for record in records {
        payloads.push(encode_record(record)?);
    }

    let mut entries = Vec::with_capacity(records.len());
    let mut payload_offset = directory_len;
    for (record, payload) in records.iter().zip(&payloads) {
        let payload_offset_u32 =
            u32::try_from(payload_offset).context("debug payload offset exceeds 4 GiB")?;
        let size_of_data = u32::try_from(payload.len()).context("debug payload exceeds 4 GiB")?;
        let address_of_raw_data = directory_rva
            .checked_add(payload_offset_u32)
            .context("debug payload RVA overflow")?;
        let pointer_to_raw_data = directory_file_offset
            .checked_add(payload_offset_u32)
            .context("debug payload file offset overflow")?;
        entries.push(DebugDirectoryEntry {
            characteristics: 0,
            time_date_stamp: 0,
            major_version: 0,
            minor_version: 0,
            debug_type: match record {
                DebugRecord::Repro { .. } => IMAGE_DEBUG_TYPE_REPRO,
                DebugRecord::CodeView(_) => IMAGE_DEBUG_TYPE_CODEVIEW,
            },
            size_of_data,
            address_of_raw_data,
            pointer_to_raw_data,
        });
        payload_offset = payload_offset
            .checked_add(payload.len())
            .context("debug payload layout overflow")?;
    }

    let mut bytes = Vec::with_capacity(payload_offset);
    for entry in &entries {
        entry.encode(&mut bytes);
    }
    for payload in payloads {
        bytes.extend_from_slice(&payload);
    }
    Ok(EncodedDebugDirectory {
        bytes,
        entries,
        directory_size,
    })
}

/// Parses directory entries and their file-backed payloads from a complete PE
/// image. Unknown debug types are rejected rather than silently misread.
pub fn parse_debug_directory(
    image: &[u8],
    directory_file_offset: usize,
    directory_size: usize,
) -> Result<Vec<DebugRecord>> {
    ensure!(
        directory_size.is_multiple_of(IMAGE_DEBUG_DIRECTORY_SIZE),
        "debug directory size is not a multiple of IMAGE_DEBUG_DIRECTORY"
    );
    let directory_end = directory_file_offset
        .checked_add(directory_size)
        .context("debug directory range overflow")?;
    let directory = image
        .get(directory_file_offset..directory_end)
        .context("debug directory lies outside the image")?;
    let mut records = Vec::with_capacity(directory_size / IMAGE_DEBUG_DIRECTORY_SIZE);
    for raw_entry in directory.chunks_exact(IMAGE_DEBUG_DIRECTORY_SIZE) {
        let entry = DebugDirectoryEntry::parse(raw_entry)?;
        ensure!(
            entry.time_date_stamp == 0,
            "non-deterministic debug timestamp"
        );
        let start =
            usize::try_from(entry.pointer_to_raw_data).context("invalid debug payload offset")?;
        let size = usize::try_from(entry.size_of_data).context("invalid debug payload size")?;
        let end = start
            .checked_add(size)
            .context("debug payload range overflow")?;
        let payload = image
            .get(start..end)
            .context("debug payload lies outside the image")?;
        records.push(match entry.debug_type {
            IMAGE_DEBUG_TYPE_REPRO => {
                ensure!(
                    payload.len() == REPRO_BUILD_ID_SIZE,
                    "invalid REPRO build-id size"
                );
                let mut build_id = [0; REPRO_BUILD_ID_SIZE];
                build_id.copy_from_slice(payload);
                DebugRecord::Repro { build_id }
            }
            IMAGE_DEBUG_TYPE_CODEVIEW => DebugRecord::CodeView(parse_rsds(payload)?),
            other => bail!("unsupported PE debug-directory type {other}"),
        });
    }
    Ok(records)
}

fn encode_record(record: &DebugRecord) -> Result<Vec<u8>> {
    match record {
        DebugRecord::Repro { build_id } => Ok(build_id.to_vec()),
        DebugRecord::CodeView(rsds) => {
            ensure!(
                !rsds.pdb_path.contains(&0),
                "the RSDS PDB path contains an interior NUL"
            );
            let capacity = 24usize
                .checked_add(rsds.pdb_path.len())
                .and_then(|value| value.checked_add(1))
                .context("RSDS record size overflow")?;
            let mut output = Vec::with_capacity(capacity);
            output.extend_from_slice(b"RSDS");
            output.extend_from_slice(&rsds.guid);
            put_u32(&mut output, rsds.age);
            output.extend_from_slice(&rsds.pdb_path);
            output.push(0);
            Ok(output)
        }
    }
}

fn parse_rsds(payload: &[u8]) -> Result<CodeViewRsds> {
    ensure!(payload.len() >= 25, "truncated CodeView RSDS record");
    ensure!(&payload[..4] == b"RSDS", "invalid CodeView signature");
    ensure!(
        payload.last() == Some(&0),
        "CodeView PDB path is not NUL terminated"
    );
    let path = &payload[24..payload.len() - 1];
    ensure!(
        !path.contains(&0),
        "CodeView PDB path contains an interior NUL"
    );
    let mut guid = [0; 16];
    guid.copy_from_slice(&payload[4..20]);
    CodeViewRsds::new(guid, read_u32(payload, 20), path.to_vec())
}

/// Computes a stable SHA-256 build id while treating mutable byte ranges as
/// zero. The PE checksum field can be supplied separately for convenience.
/// Ranges must be in-bounds and non-overlapping.
pub fn stable_build_id(
    image: &[u8],
    checksum_offset: Option<usize>,
    excluded_ranges: &[Range<usize>],
) -> Result<[u8; REPRO_BUILD_ID_SIZE]> {
    let mut ranges = excluded_ranges.to_vec();
    if let Some(offset) = checksum_offset {
        let end = offset
            .checked_add(4)
            .context("PE checksum range overflow")?;
        ranges.push(offset..end);
    }
    ranges.sort_unstable_by_key(|range| range.start);
    let mut previous_end = 0;
    for range in &ranges {
        ensure!(range.start <= range.end, "invalid excluded range");
        ensure!(
            range.end <= image.len(),
            "excluded range lies outside the image"
        );
        ensure!(range.start >= previous_end, "excluded ranges overlap");
        previous_end = range.end;
    }

    let mut hasher = StableBuildIdHasher::new();
    let mut cursor = 0;
    const ZEROES: [u8; 64] = [0; 64];
    for range in ranges {
        hasher.update(&image[cursor..range.start]);
        let mut remaining = range.end - range.start;
        while remaining != 0 {
            let count = remaining.min(ZEROES.len());
            hasher.update(&ZEROES[..count]);
            remaining -= count;
        }
        cursor = range.end;
    }
    hasher.update(&image[cursor..]);
    Ok(hasher.finish())
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

/// Preserves the historical build-ID stream semantics while delegating SHA-256
/// block compression to RustCrypto's hardware-dispatched implementation.
///
/// The old implementation discarded a partial block when a subsequent update
/// did not complete it, but still included those bytes in the encoded bit
/// length. Existing build IDs depend on that behavior at excluded-range
/// boundaries, so changing it would break reproducibility across Wild versions.
struct StableBuildIdHasher {
    state: [u32; 8],
    length: u64,
    buffer: [u8; 64],
    buffered: usize,
}

impl StableBuildIdHasher {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            length: 0,
            buffer: [0; 64],
            buffered: 0,
        }
    }

    fn update(&mut self, mut bytes: &[u8]) {
        self.length = self.length.wrapping_add(bytes.len() as u64);
        if self.buffered != 0 {
            let count = (64 - self.buffered).min(bytes.len());
            self.buffer[self.buffered..self.buffered + count].copy_from_slice(&bytes[..count]);
            self.buffered += count;
            bytes = &bytes[count..];
            if self.buffered == 64 {
                sha2::block_api::compress256(&mut self.state, &[self.buffer]);
                self.buffered = 0;
            }
        }
        while let Some((block, remaining)) = bytes.split_first_chunk::<64>() {
            sha2::block_api::compress256(&mut self.state, std::slice::from_ref(block));
            bytes = remaining;
        }
        self.buffer[..bytes.len()].copy_from_slice(bytes);
        self.buffered = bytes.len();
    }

    fn finish(mut self) -> [u8; 32] {
        let bit_length = self.length.wrapping_mul(8);
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;
        if self.buffered > 56 {
            self.buffer[self.buffered..].fill(0);
            sha2::block_api::compress256(&mut self.state, &[self.buffer]);
            self.buffer = [0; 64];
        } else {
            self.buffer[self.buffered..56].fill(0);
        }
        self.buffer[56..].copy_from_slice(&bit_length.to_be_bytes());
        sha2::block_api::compress256(&mut self.state, &[self.buffer]);
        let mut digest = [0; 32];
        for (chunk, value) in digest.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        })
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            hex(&stable_build_id(b"", None, &[]).unwrap()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&stable_build_id(b"abc", None, &[]).unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn stable_hash_ignores_checksum_and_mutable_ranges() {
        let mut first = (0u8..100).collect::<Vec<_>>();
        let mut second = first.clone();
        first[8..12].copy_from_slice(&[1; 4]);
        second[8..12].copy_from_slice(&[9; 4]);
        first[40..55].fill(2);
        second[40..55].fill(7);
        let excluded = std::slice::from_ref(&(40..55));
        assert_eq!(
            stable_build_id(&first, Some(8), excluded).unwrap(),
            stable_build_id(&second, Some(8), excluded).unwrap()
        );
        second[70] ^= 1;
        assert_ne!(
            stable_build_id(&first, Some(8), excluded).unwrap(),
            stable_build_id(&second, Some(8), excluded).unwrap()
        );
    }

    #[test]
    fn large_streaming_hash_preserves_legacy_build_id() {
        let image = (0..8 * 1024 * 1024)
            .map(|index| (index as u8).wrapping_mul(37).wrapping_add(11))
            .collect::<Vec<_>>();
        let checksum = 0x1234;
        let excluded = [0x40_000..0x40_081, 0x70_0000..0x78_0000];
        let first = stable_build_id(&image, Some(checksum), &excluded).unwrap();
        assert_eq!(
            first,
            [
                91, 203, 114, 98, 215, 193, 163, 33, 83, 190, 59, 136, 64, 222, 124, 98, 167, 167,
                58, 224, 130, 79, 33, 68, 182, 153, 217, 200, 112, 226, 64, 83,
            ]
        );
    }

    #[test]
    fn encode_parse_round_trip_is_deterministic() {
        let records = vec![
            DebugRecord::Repro {
                build_id: [0x55; 32],
            },
            DebugRecord::CodeView(
                CodeViewRsds::new([0x33; 16], 7, b"build/output.pdb".to_vec()).unwrap(),
            ),
        ];
        let first = encode_debug_directory(&records, 0x3000, 0x400).unwrap();
        let second = encode_debug_directory(&records, 0x3000, 0x400).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.directory_size, 56);
        assert!(first.entries.iter().all(|entry| entry.time_date_stamp == 0));
        assert_eq!(first.entries[0].pointer_to_raw_data, 0x438);
        assert_eq!(first.entries[0].address_of_raw_data, 0x3038);

        let mut image = vec![0; 0x400];
        image.extend_from_slice(&first.bytes);
        assert_eq!(parse_debug_directory(&image, 0x400, 56).unwrap(), records);
    }

    #[test]
    fn rejects_bad_ranges_and_offsets() {
        assert!(stable_build_id(&[0; 8], None, &[2..5, 4..6]).is_err());
        assert!(stable_build_id(&[0; 8], Some(6), &[]).is_err());
        assert!(encode_debug_directory(&[], 0, 0).is_err());
        assert!(
            encode_debug_directory(&[DebugRecord::Repro { build_id: [0; 32] }], u32::MAX - 2, 0,)
                .is_err()
        );
    }

    #[test]
    fn rejects_malformed_directory_and_records() {
        assert!(parse_debug_directory(&[0; 100], 0, 27).is_err());
        let encoded = encode_debug_directory(
            &[DebugRecord::CodeView(
                CodeViewRsds::new([1; 16], 1, b"a.pdb".to_vec()).unwrap(),
            )],
            0,
            28,
        )
        .unwrap();
        let mut image = vec![0; 28];
        image.extend_from_slice(&encoded.bytes);
        image[28 + 4] = 1;
        assert!(parse_debug_directory(&image, 28, 28).is_err());
    }

    #[test]
    fn rsds_validation() {
        assert!(CodeViewRsds::new([0; 16], 1, b"bad\0path".to_vec()).is_err());
        assert!(CodeViewRsds::new([0; 16], 1, vec![0xff]).is_ok());
    }
}
