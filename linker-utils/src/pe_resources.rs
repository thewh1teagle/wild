//! Parsing of Win32 `.res` files and deterministic construction of PE resources.
//!
//! Resource identifiers are kept as UTF-16 code units rather than converted to
//! Rust strings. This preserves the exact ordering used by the Windows loader
//! and avoids lossy conversion of input produced by resource compilers.

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

const DIRECTORY_SIZE: usize = 16;
const DIRECTORY_ENTRY_SIZE: usize = 8;
const DATA_ENTRY_SIZE: usize = 16;
const STRING_NAME_BIT: u32 = 0x8000_0000;
const SUBDIRECTORY_BIT: u32 = 0x8000_0000;

/// A numeric or UTF-16 resource type/name.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResourceId {
    Id(u16),
    Name(Vec<u16>),
}

impl ResourceId {
    /// Constructs a named identifier from a Rust string.
    #[must_use]
    pub fn named(value: &str) -> Self {
        Self::Name(value.encode_utf16().collect())
    }
}

/// Metadata and payload from one Win32 `.res` record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceRecord {
    pub resource_type: ResourceId,
    pub name: ResourceId,
    pub language: u16,
    pub data_version: u32,
    pub memory_flags: u16,
    pub version: u32,
    pub characteristics: u32,
    pub data: Vec<u8>,
}

/// An RVA and byte count for `IMAGE_DIRECTORY_ENTRY_RESOURCE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceDataDirectory {
    pub rva: u32,
    pub size: u32,
}

/// Complete deterministic contents of a PE `.rsrc` section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceSection {
    pub bytes: Vec<u8>,
    pub data_directory: ResourceDataDirectory,
    /// Number of unique type/name/language leaves.
    pub resource_count: u32,
}

/// Conservatively identifies the standard null record at the start of a Win32 `.res` stream.
///
/// Unlike COFF and archives, `.res` files have no general-purpose magic number. Microsoft resource
/// compilers begin the stream with this exact empty record. Requiring all 32 bytes makes this probe
/// suitable for recognizing resources whose file name has a non-`.res` extension, while callers
/// should still classify known object and archive formats first.
#[must_use]
pub fn has_res_null_header(data: &[u8]) -> bool {
    const NULL_HEADER: [u8; 32] = [
        0, 0, 0, 0, // DataSize
        32, 0, 0, 0, // HeaderSize
        0xff, 0xff, 0, 0, // Type ordinal zero
        0xff, 0xff, 0, 0, // Name ordinal zero
        0, 0, 0, 0, // DataVersion
        0, 0, 0, 0, // MemoryFlags and LanguageId
        0, 0, 0, 0, // Version
        0, 0, 0, 0, // Characteristics
    ];
    data.starts_with(&NULL_HEADER)
}

/// Parses all non-null records from a Microsoft Win32 `.res` byte stream.
///
/// Resource compilers normally place one all-zero null record first. It is a
/// file marker rather than a loader-visible resource and is omitted here.
pub fn parse_res(data: &[u8]) -> Result<Vec<ResourceRecord>> {
    let mut records = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        ensure!(
            offset.is_multiple_of(4),
            "resource record at {offset:#x} is not DWORD aligned"
        );
        ensure!(
            data.len() - offset >= 8,
            "truncated resource record header at {offset:#x}"
        );
        let data_size = read_u32(data, offset)? as usize;
        let header_size = read_u32(data, offset + 4)? as usize;
        ensure!(
            header_size >= 8 && header_size.is_multiple_of(4),
            "invalid resource header size {header_size} at {offset:#x}"
        );
        let header_end = offset
            .checked_add(header_size)
            .context("resource header offset overflow")?;
        ensure!(
            header_end <= data.len(),
            "resource header at {offset:#x} is truncated"
        );

        let fixed_start_limit = header_end
            .checked_sub(16)
            .context("resource header is too short for fixed fields")?;
        let mut cursor = offset + 8;
        let resource_type = parse_identifier(data, &mut cursor, fixed_start_limit)
            .with_context(|| format!("invalid resource type at record {offset:#x}"))?;
        let name = parse_identifier(data, &mut cursor, fixed_start_limit)
            .with_context(|| format!("invalid resource name at record {offset:#x}"))?;
        cursor = align_up(cursor, 4, "resource header fields")?;
        ensure!(
            cursor <= fixed_start_limit,
            "resource identifiers overlap fixed header fields at {offset:#x}"
        );

        let data_version = read_u32(data, cursor)?;
        let memory_flags = read_u16(data, cursor + 4)?;
        let language = read_u16(data, cursor + 6)?;
        let version = read_u32(data, cursor + 8)?;
        let characteristics = read_u32(data, cursor + 12)?;
        ensure!(
            cursor + 16 <= header_end,
            "fixed resource header at {offset:#x} is truncated"
        );

        let data_end = header_end
            .checked_add(data_size)
            .context("resource data offset overflow")?;
        ensure!(
            data_end <= data.len(),
            "resource data at {offset:#x} is truncated"
        );
        let record = ResourceRecord {
            resource_type,
            name,
            language,
            data_version,
            memory_flags,
            version,
            characteristics,
            data: data[header_end..data_end].to_vec(),
        };
        if !is_null_record(&record) {
            validate_record(&record)?;
            records.push(record);
        }

        let next = align_up(data_end, 4, "next resource record")?;
        ensure!(
            next <= data.len(),
            "resource record padding at {offset:#x} is truncated"
        );
        offset = next;
    }
    Ok(records)
}

/// Builds the canonical three-level type/name/language PE resource tree.
///
/// Exact duplicate records are folded. Reusing a type/name/language key with
/// different metadata or bytes is rejected, since selecting one by input order
/// would make the link result ambiguous.
pub fn build_resource_section(
    records: &[ResourceRecord],
    section_rva: u32,
) -> Result<ResourceSection> {
    ensure!(section_rva != 0, "resource section RVA must not be zero");
    ensure!(
        !records.is_empty(),
        "a resource section requires at least one record"
    );

    type Names = BTreeMap<ResourceId, BTreeMap<u16, ResourceRecord>>;
    let mut tree = BTreeMap::<ResourceId, Names>::new();
    for record in records {
        validate_record(record)?;
        let languages = tree
            .entry(record.resource_type.clone())
            .or_default()
            .entry(record.name.clone())
            .or_default();
        if let Some(previous) = languages.get(&record.language) {
            ensure!(
                previous == record,
                "conflicting resource for type {}, name {}, language {:#06x}",
                display_id(&record.resource_type),
                display_id(&record.name),
                record.language
            );
        } else {
            languages.insert(record.language, record.clone());
        }
    }

    let root_size = directory_size(tree.len())?;
    let mut directories_end = root_size;
    let mut type_offsets = BTreeMap::new();
    let mut name_offsets = BTreeMap::new();
    for (resource_type, names) in &tree {
        let offset = as_u32(directories_end, "resource directory offset")?;
        type_offsets.insert(resource_type.clone(), offset);
        directories_end = directories_end
            .checked_add(directory_size(names.len())?)
            .context("resource directories exceed addressable memory")?;
        for (name, languages) in names {
            let offset = as_u32(directories_end, "resource directory offset")?;
            name_offsets.insert((resource_type.clone(), name.clone()), offset);
            directories_end = directories_end
                .checked_add(directory_size(languages.len())?)
                .context("resource directories exceed addressable memory")?;
        }
    }
    ensure!(
        directories_end < STRING_NAME_BIT as usize,
        "resource directory table is too large"
    );
    let mut bytes = vec![0; directories_end];

    let mut named_ids = BTreeSet::new();
    for (resource_type, names) in &tree {
        if let ResourceId::Name(value) = resource_type {
            named_ids.insert(value.clone());
        }
        for name in names.keys() {
            if let ResourceId::Name(value) = name {
                named_ids.insert(value.clone());
            }
        }
    }
    let mut string_offsets = BTreeMap::new();
    for value in named_ids {
        let offset = as_u32(bytes.len(), "resource name offset")?;
        ensure!(
            offset < STRING_NAME_BIT,
            "resource names exceed the PE offset limit"
        );
        string_offsets.insert(value.clone(), offset);
        bytes.extend_from_slice(&u16::try_from(value.len()).unwrap().to_le_bytes());
        for unit in value {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
    }
    pad_to(&mut bytes, 4)?;

    let mut data_entry_offsets = BTreeMap::new();
    for (resource_type, names) in &tree {
        for (name, languages) in names {
            for language in languages.keys() {
                let offset = as_u32(bytes.len(), "resource data-entry offset")?;
                ensure!(
                    offset < SUBDIRECTORY_BIT,
                    "resource data entries exceed the PE offset limit"
                );
                data_entry_offsets.insert((resource_type.clone(), name.clone(), *language), offset);
                bytes.resize(bytes.len() + DATA_ENTRY_SIZE, 0);
            }
        }
    }

    let mut payload_offsets = BTreeMap::new();
    for (resource_type, names) in &tree {
        for (name, languages) in names {
            for (language, record) in languages {
                pad_to(&mut bytes, 4)?;
                let offset = as_u32(bytes.len(), "resource payload offset")?;
                payload_offsets.insert((resource_type.clone(), name.clone(), *language), offset);
                bytes.extend_from_slice(&record.data);
            }
        }
    }

    write_directory(
        &mut bytes,
        0,
        tree.keys()
            .map(|key| (key, type_offsets[key] | SUBDIRECTORY_BIT)),
        &string_offsets,
    )?;
    for (resource_type, names) in &tree {
        let directory_offset = type_offsets[resource_type];
        write_directory(
            &mut bytes,
            directory_offset,
            names.keys().map(|name| {
                let key = (resource_type.clone(), name.clone());
                (name, name_offsets[&key] | SUBDIRECTORY_BIT)
            }),
            &string_offsets,
        )?;
        for (name, languages) in names {
            let key = (resource_type.clone(), name.clone());
            let language_dir = name_offsets[&key];
            write_directory(
                &mut bytes,
                language_dir,
                languages.keys().map(|language| {
                    let leaf = (resource_type.clone(), name.clone(), *language);
                    (ResourceId::Id(*language), data_entry_offsets[&leaf])
                }),
                &string_offsets,
            )?;
            for (language, record) in languages {
                let leaf = (resource_type.clone(), name.clone(), *language);
                let entry_offset = data_entry_offsets[&leaf] as usize;
                let payload_rva = section_rva
                    .checked_add(payload_offsets[&leaf])
                    .context("resource payload RVA overflow")?;
                write_u32(&mut bytes, entry_offset, payload_rva)?;
                write_u32(
                    &mut bytes,
                    entry_offset + 4,
                    as_u32(record.data.len(), "resource payload size")?,
                )?;
            }
        }
    }

    let size = as_u32(bytes.len(), "resource section size")?;
    section_rva
        .checked_add(size)
        .context("resource section RVA range overflow")?;
    let resource_count = as_u32(data_entry_offsets.len(), "resource count")?;
    Ok(ResourceSection {
        bytes,
        data_directory: ResourceDataDirectory {
            rva: section_rva,
            size,
        },
        resource_count,
    })
}

fn parse_identifier(data: &[u8], cursor: &mut usize, limit: usize) -> Result<ResourceId> {
    ensure!(*cursor + 2 <= limit, "missing resource identifier");
    let first = read_u16(data, *cursor)?;
    *cursor += 2;
    if first == 0xffff {
        ensure!(
            *cursor + 2 <= limit,
            "truncated numeric resource identifier"
        );
        let value = read_u16(data, *cursor)?;
        *cursor += 2;
        return Ok(ResourceId::Id(value));
    }
    let mut value = Vec::new();
    let mut unit = first;
    while unit != 0 {
        value.push(unit);
        ensure!(
            *cursor + 2 <= limit,
            "unterminated UTF-16 resource identifier"
        );
        unit = read_u16(data, *cursor)?;
        *cursor += 2;
    }
    ensure!(!value.is_empty(), "empty named resource identifier");
    Ok(ResourceId::Name(value))
}

fn validate_record(record: &ResourceRecord) -> Result<()> {
    validate_id(&record.resource_type, "resource type")?;
    validate_id(&record.name, "resource name")?;
    Ok(())
}

fn validate_id(id: &ResourceId, description: &str) -> Result<()> {
    if let ResourceId::Name(value) = id {
        ensure!(!value.is_empty(), "{description} must not be empty");
        ensure!(
            u16::try_from(value.len()).is_ok(),
            "{description} exceeds 65535 UTF-16 units"
        );
        ensure!(
            !value.contains(&0),
            "{description} contains an embedded null"
        );
    }
    Ok(())
}

fn is_null_record(record: &ResourceRecord) -> bool {
    record.resource_type == ResourceId::Id(0)
        && record.name == ResourceId::Id(0)
        && record.language == 0
        && record.data_version == 0
        && record.memory_flags == 0
        && record.version == 0
        && record.characteristics == 0
        && record.data.is_empty()
}

fn directory_size(entries: usize) -> Result<usize> {
    entries
        .checked_mul(DIRECTORY_ENTRY_SIZE)
        .and_then(|size| size.checked_add(DIRECTORY_SIZE))
        .context("resource directory size overflow")
}

fn write_directory<K, I>(
    bytes: &mut [u8],
    offset: u32,
    entries: I,
    string_offsets: &BTreeMap<Vec<u16>, u32>,
) -> Result<()>
where
    K: std::borrow::Borrow<ResourceId>,
    I: IntoIterator<Item = (K, u32)>,
{
    let mut entries = entries.into_iter().collect::<Vec<_>>();
    entries.sort_by(|(left, _), (right, _)| directory_id_cmp(left.borrow(), right.borrow()));
    let named = entries
        .iter()
        .filter(|(id, _)| matches!(id.borrow(), ResourceId::Name(_)))
        .count();
    let ids = entries.len() - named;
    ensure!(
        u16::try_from(named).is_ok(),
        "too many named resource directory entries"
    );
    ensure!(
        u16::try_from(ids).is_ok(),
        "too many numeric resource directory entries"
    );
    let offset = offset as usize;
    write_u16(bytes, offset + 12, named as u16)?;
    write_u16(bytes, offset + 14, ids as u16)?;
    for (index, (id, target)) in entries.iter().enumerate() {
        let entry = offset + DIRECTORY_SIZE + index * DIRECTORY_ENTRY_SIZE;
        let name = match id.borrow() {
            ResourceId::Id(value) => u32::from(*value),
            ResourceId::Name(value) => STRING_NAME_BIT | string_offsets[value],
        };
        write_u32(bytes, entry, name)?;
        write_u32(bytes, entry + 4, *target)?;
    }
    Ok(())
}

fn directory_id_cmp(left: &ResourceId, right: &ResourceId) -> std::cmp::Ordering {
    match (left, right) {
        (ResourceId::Name(left), ResourceId::Name(right)) => left.cmp(right),
        (ResourceId::Name(_), ResourceId::Id(_)) => std::cmp::Ordering::Less,
        (ResourceId::Id(_), ResourceId::Name(_)) => std::cmp::Ordering::Greater,
        (ResourceId::Id(left), ResourceId::Id(right)) => left.cmp(right),
    }
}

fn display_id(id: &ResourceId) -> String {
    match id {
        ResourceId::Id(value) => format!("#{value}"),
        ResourceId::Name(value) => String::from_utf16_lossy(value),
    }
}

fn pad_to(bytes: &mut Vec<u8>, alignment: usize) -> Result<()> {
    let end = align_up(bytes.len(), alignment, "resource output")?;
    bytes.resize(end, 0);
    Ok(())
}

fn align_up(value: usize, alignment: usize, description: &str) -> Result<usize> {
    let mask = alignment - 1;
    value
        .checked_add(mask)
        .map(|value| value & !mask)
        .with_context(|| format!("{description} alignment overflow"))
}

fn as_u32(value: usize, description: &str) -> Result<u32> {
    u32::try_from(value).with_context(|| format!("{description} exceeds 4 GiB"))
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let value = data
        .get(offset..offset + 2)
        .with_context(|| format!("truncated u16 at {offset:#x}"))?;
    Ok(u16::from_le_bytes(value.try_into().unwrap()))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let value = data
        .get(offset..offset + 4)
        .with_context(|| format!("truncated u32 at {offset:#x}"))?;
    Ok(u32::from_le_bytes(value.try_into().unwrap()))
}

fn write_u16(data: &mut [u8], offset: usize, value: u16) -> Result<()> {
    let output = data
        .get_mut(offset..offset + 2)
        .with_context(|| format!("resource output u16 at {offset:#x} is out of bounds"))?;
    output.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) -> Result<()> {
    let output = data
        .get_mut(offset..offset + 4)
        .with_context(|| format!("resource output u32 at {offset:#x} is out of bounds"))?;
    output.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn append_res_record(output: &mut Vec<u8>, record: &ResourceRecord) {
        let start = output.len();
        output.extend_from_slice(&(record.data.len() as u32).to_le_bytes());
        output.extend_from_slice(&0_u32.to_le_bytes());
        append_id(output, &record.resource_type);
        append_id(output, &record.name);
        while !output.len().is_multiple_of(4) {
            output.push(0);
        }
        output.extend_from_slice(&record.data_version.to_le_bytes());
        output.extend_from_slice(&record.memory_flags.to_le_bytes());
        output.extend_from_slice(&record.language.to_le_bytes());
        output.extend_from_slice(&record.version.to_le_bytes());
        output.extend_from_slice(&record.characteristics.to_le_bytes());
        let header_size = (output.len() - start) as u32;
        output[start + 4..start + 8].copy_from_slice(&header_size.to_le_bytes());
        output.extend_from_slice(&record.data);
        while !output.len().is_multiple_of(4) {
            output.push(0);
        }
    }

    fn append_id(output: &mut Vec<u8>, id: &ResourceId) {
        match id {
            ResourceId::Id(value) => {
                output.extend_from_slice(&0xffff_u16.to_le_bytes());
                output.extend_from_slice(&value.to_le_bytes());
            }
            ResourceId::Name(value) => {
                for unit in value {
                    output.extend_from_slice(&unit.to_le_bytes());
                }
                output.extend_from_slice(&0_u16.to_le_bytes());
            }
        }
    }

    fn record(
        resource_type: ResourceId,
        name: ResourceId,
        language: u16,
        data: &[u8],
    ) -> ResourceRecord {
        ResourceRecord {
            resource_type,
            name,
            language,
            data_version: 7,
            memory_flags: 0x1030,
            version: 2,
            characteristics: 3,
            data: data.to_vec(),
        }
    }

    #[test]
    fn parses_res_and_builds_manifest_icon_and_string_tree() {
        let expected = vec![
            record(ResourceId::Id(24), ResourceId::Id(1), 0x409, b"<assembly/>"),
            record(
                ResourceId::Id(3),
                ResourceId::named("MAIN_ICON"),
                0x409,
                &[1, 2, 3, 4],
            ),
            record(
                ResourceId::Id(6),
                ResourceId::Id(7),
                0x407,
                &[0x03, 0, b'a', 0, b'b', 0, b'c', 0],
            ),
        ];
        let null = ResourceRecord {
            resource_type: ResourceId::Id(0),
            name: ResourceId::Id(0),
            language: 0,
            data_version: 0,
            memory_flags: 0,
            version: 0,
            characteristics: 0,
            data: Vec::new(),
        };
        let mut input = Vec::new();
        append_res_record(&mut input, &null);
        assert!(has_res_null_header(&input));
        for item in &expected {
            append_res_record(&mut input, item);
        }
        let parsed = parse_res(&input).unwrap();
        assert_eq!(parsed, expected);

        let section = build_resource_section(&parsed, 0x5000).unwrap();
        assert_eq!(section.resource_count, 3);
        assert_eq!(section.data_directory.rva, 0x5000);
        assert_eq!(section.data_directory.size as usize, section.bytes.len());
        assert_eq!(read_u16(&section.bytes, 12).unwrap(), 0);
        assert_eq!(read_u16(&section.bytes, 14).unwrap(), 3);
        assert!(
            section
                .bytes
                .windows(b"<assembly/>".len())
                .any(|window| window == b"<assembly/>")
        );
    }

    #[test]
    fn null_header_probe_does_not_claim_coff_or_archives() {
        assert!(!has_res_null_header(&object::archive::MAGIC));
        assert!(!has_res_null_header(&[
            object::pe::IMAGE_FILE_MACHINE_AMD64.0 as u8,
            (object::pe::IMAGE_FILE_MACHINE_AMD64.0 >> 8) as u8,
        ]));

        let mut malformed = vec![0; 32];
        malformed[4..8].copy_from_slice(&32_u32.to_le_bytes());
        malformed[8..12].copy_from_slice(&[0xff, 0xff, 0, 0]);
        malformed[12..16].copy_from_slice(&[0xff, 0xff, 0, 0]);
        malformed.extend_from_slice(&[1, 2, 3, 4]);
        assert!(has_res_null_header(&malformed));
        assert!(parse_res(&malformed).is_err());
    }

    #[test]
    fn emits_named_entries_before_sorted_numeric_entries_deterministically() {
        let records = vec![
            record(ResourceId::Id(24), ResourceId::Id(9), 0x409, b"z"),
            record(ResourceId::named("CUSTOM"), ResourceId::Id(1), 0x409, b"a"),
            record(ResourceId::Id(3), ResourceId::Id(1), 0x409, b"b"),
        ];
        let first = build_resource_section(&records, 0x2000).unwrap();
        let mut reversed = records;
        reversed.reverse();
        let second = build_resource_section(&reversed, 0x2000).unwrap();
        assert_eq!(first, second);
        assert_eq!(read_u16(&first.bytes, 12).unwrap(), 1);
        assert_eq!(read_u16(&first.bytes, 14).unwrap(), 2);
        assert_ne!(read_u32(&first.bytes, 16).unwrap() & STRING_NAME_BIT, 0);
        assert_eq!(read_u32(&first.bytes, 24).unwrap(), 3);
        assert_eq!(read_u32(&first.bytes, 32).unwrap(), 24);
    }

    #[test]
    fn folds_exact_duplicates_and_rejects_conflicts() {
        let one = record(ResourceId::Id(10), ResourceId::Id(1), 0x409, b"data");
        let section = build_resource_section(&[one.clone(), one.clone()], 0x1000).unwrap();
        assert_eq!(section.resource_count, 1);
        let mut conflicting = one.clone();
        conflicting.data.push(0);
        let error = build_resource_section(&[one, conflicting], 0x1000).unwrap_err();
        assert!(error.to_string().contains("conflicting resource"));
    }

    #[test]
    fn rejects_malformed_res_inputs() {
        let item = record(ResourceId::Id(24), ResourceId::Id(1), 0x409, b"abc");
        let mut good = Vec::new();
        append_res_record(&mut good, &item);
        for truncated_at in [4, 7, 12, good.len() - 2] {
            assert!(
                parse_res(&good[..truncated_at]).is_err(),
                "accepted truncation at {truncated_at}"
            );
        }
        let mut bad_header = good.clone();
        bad_header[4..8].copy_from_slice(&12_u32.to_le_bytes());
        assert!(parse_res(&bad_header).is_err());
        let mut unterminated = good;
        unterminated[8..10].copy_from_slice(&0x0058_u16.to_le_bytes());
        assert!(parse_res(&unterminated).is_err());
    }

    #[test]
    fn rejects_invalid_builder_inputs_and_rva_overflow() {
        let mut item = record(ResourceId::Id(1), ResourceId::Id(1), 0, b"x");
        assert!(build_resource_section(&[item.clone()], 0).is_err());
        assert!(build_resource_section(&[item.clone()], u32::MAX).is_err());
        item.name = ResourceId::Name(Vec::new());
        assert!(build_resource_section(&[item], 0x1000).is_err());
    }
}
