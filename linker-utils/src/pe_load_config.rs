//! PE32+ load-configuration metadata for AMD64 images.
//!
//! The encoder uses the 280-byte `IMAGE_LOAD_CONFIG_DIRECTORY64` revision
//! ending with `GuardEHContinuationCount`. This is deliberately conservative:
//! it is new enough for Control Flow Guard and EH-continuation metadata, while
//! avoiding newer fields that the linker does not yet populate.

use anyhow::Result;
use anyhow::ensure;
use std::collections::BTreeSet;

/// Size emitted in the directory's `Size` field.
pub const IMAGE_LOAD_CONFIG_DIRECTORY64_COMPAT_SIZE: u32 = 280;

/// The image has Control Flow Guard instrumentation.
pub const IMAGE_GUARD_CF_INSTRUMENTED: u32 = 0x0000_0100;
/// A sorted Guard CF function table is present.
pub const IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;
/// A sorted EH continuation table is present.
pub const IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT: u32 = 0x0040_0000;
/// Bits encoding extra bytes in each Guard CF function-table entry.
pub const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK: u32 = 0xf000_0000;

const SECURITY_COOKIE_OFFSET: u32 = 88;
const GUARD_CF_CHECK_OFFSET: u32 = 112;
const GUARD_CF_DISPATCH_OFFSET: u32 = 120;
const GUARD_CF_TABLE_OFFSET: u32 = 128;
const GUARD_CF_COUNT_OFFSET: u32 = 136;
const GUARD_FLAGS_OFFSET: u32 = 144;
const GUARD_EH_TABLE_OFFSET: u32 = 264;
const GUARD_EH_COUNT_OFFSET: u32 = 272;

/// Values used to construct one AMD64 load-config directory and its tables.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeLoadConfig64 {
    /// Preferred image base used to convert RVAs to VAs.
    pub image_base: u64,
    /// RVA where the directory itself will be mapped.
    pub directory_rva: u32,
    /// Exclusive upper bound for every mapped RVA.
    pub size_of_image: u32,
    /// RVA of the 64-bit `/GS` cookie, when one is defined.
    pub security_cookie_rva: Option<u32>,
    /// RVA of the writable `__guard_check_icall_fptr` slot.
    pub guard_cf_check_function_pointer_rva: Option<u32>,
    /// RVA of the writable `__guard_dispatch_icall_fptr` slot.
    pub guard_cf_dispatch_function_pointer_rva: Option<u32>,
    /// Valid indirect-call target RVAs. Input order and duplicates are ignored.
    pub guard_cf_function_rvas: Vec<u32>,
    /// Valid exception continuation RVAs. Input order and duplicates are ignored.
    pub guard_eh_continuation_rvas: Vec<u32>,
    /// Guard flags derived from input objects, excluding table-presence bits.
    pub guard_flags: u32,
}

/// Encoded directory followed by its canonical four-byte RVA tables.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedPeLoadConfig64 {
    pub bytes: Vec<u8>,
    /// RVA and size to place in `IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG`.
    pub data_directory_rva: u32,
    pub data_directory_size: u32,
    /// RVAs of 64-bit VA fields that require `IMAGE_REL_BASED_DIR64` entries.
    pub dir64_relocation_rvas: Vec<u32>,
    pub guard_cf_function_table_rva: Option<u32>,
    pub guard_eh_continuation_table_rva: Option<u32>,
    pub guard_flags: u32,
}

/// Decoded semantic values from an encoded load-config blob.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedPeLoadConfig64 {
    pub security_cookie_rva: Option<u32>,
    pub guard_cf_check_function_pointer_rva: Option<u32>,
    pub guard_cf_dispatch_function_pointer_rva: Option<u32>,
    pub guard_cf_function_rvas: Vec<u32>,
    pub guard_eh_continuation_rvas: Vec<u32>,
    pub guard_flags: u32,
    pub dir64_relocation_rvas: Vec<u32>,
}

/// Encodes deterministic AMD64 load-config metadata.
///
/// Guard tables contain sorted, deduplicated RVAs. Presence flags are derived
/// from the resulting tables. Only the standard four-byte Guard CF entry
/// format is emitted, so callers must not request a non-zero table stride.
pub fn encode_pe_load_config64(config: &PeLoadConfig64) -> Result<EncodedPeLoadConfig64> {
    ensure!(
        config.guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK == 0,
        "Guard CF function-table entry extensions are not supported"
    );
    config
        .image_base
        .checked_add(u64::from(config.size_of_image))
        .ok_or_else(|| anyhow::anyhow!("image VA range overflows u64"))?;
    validate_range(
        config.directory_rva,
        IMAGE_LOAD_CONFIG_DIRECTORY64_COMPAT_SIZE,
        config.size_of_image,
        "load-config directory",
    )?;

    validate_optional_pointer(
        config.security_cookie_rva,
        config.size_of_image,
        "security cookie",
    )?;
    validate_optional_pointer(
        config.guard_cf_check_function_pointer_rva,
        config.size_of_image,
        "Guard CF check-function pointer",
    )?;
    validate_optional_pointer(
        config.guard_cf_dispatch_function_pointer_rva,
        config.size_of_image,
        "Guard CF dispatch-function pointer",
    )?;

    let guard_functions = canonical_rvas(
        &config.guard_cf_function_rvas,
        config.size_of_image,
        "Guard CF function",
    )?;
    let eh_continuations = canonical_rvas(
        &config.guard_eh_continuation_rvas,
        config.size_of_image,
        "Guard EH continuation",
    )?;

    let directory_size = usize::try_from(IMAGE_LOAD_CONFIG_DIRECTORY64_COMPAT_SIZE)
        .map_err(|_| anyhow::anyhow!("load-config directory size does not fit usize"))?;
    let guard_table_size = table_size(guard_functions.len(), "Guard CF function table")?;
    let eh_table_size = table_size(eh_continuations.len(), "Guard EH continuation table")?;
    let total_size = directory_size
        .checked_add(guard_table_size)
        .and_then(|size| size.checked_add(eh_table_size))
        .ok_or_else(|| anyhow::anyhow!("load-config metadata size overflow"))?;
    let total_size_u32 = u32::try_from(total_size)
        .map_err(|_| anyhow::anyhow!("load-config metadata exceeds u32 size"))?;
    validate_range(
        config.directory_rva,
        total_size_u32,
        config.size_of_image,
        "load-config metadata",
    )?;

    let guard_table_rva = optional_table_rva(
        config.directory_rva,
        IMAGE_LOAD_CONFIG_DIRECTORY64_COMPAT_SIZE,
        !guard_functions.is_empty(),
        "Guard CF function table RVA",
    )?;
    let guard_table_size_u32 = u32::try_from(guard_table_size)
        .map_err(|_| anyhow::anyhow!("Guard CF function table exceeds u32 size"))?;
    let eh_offset = IMAGE_LOAD_CONFIG_DIRECTORY64_COMPAT_SIZE
        .checked_add(guard_table_size_u32)
        .ok_or_else(|| anyhow::anyhow!("Guard EH continuation table offset overflow"))?;
    let eh_table_rva = optional_table_rva(
        config.directory_rva,
        eh_offset,
        !eh_continuations.is_empty(),
        "Guard EH continuation table RVA",
    )?;

    let mut flags = config.guard_flags
        & !(IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT | IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT);
    if guard_table_rva.is_some() {
        flags |= IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT;
    }
    if eh_table_rva.is_some() {
        flags |= IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT;
    }

    let mut bytes = vec![0; total_size];
    put_u32(&mut bytes, 0, IMAGE_LOAD_CONFIG_DIRECTORY64_COMPAT_SIZE);
    put_optional_va(
        &mut bytes,
        SECURITY_COOKIE_OFFSET,
        config.image_base,
        config.security_cookie_rva,
        "security cookie VA",
    )?;
    put_optional_va(
        &mut bytes,
        GUARD_CF_CHECK_OFFSET,
        config.image_base,
        config.guard_cf_check_function_pointer_rva,
        "Guard CF check-function pointer VA",
    )?;
    put_optional_va(
        &mut bytes,
        GUARD_CF_DISPATCH_OFFSET,
        config.image_base,
        config.guard_cf_dispatch_function_pointer_rva,
        "Guard CF dispatch-function pointer VA",
    )?;
    put_optional_va(
        &mut bytes,
        GUARD_CF_TABLE_OFFSET,
        config.image_base,
        guard_table_rva,
        "Guard CF function table VA",
    )?;
    put_u64(
        &mut bytes,
        GUARD_CF_COUNT_OFFSET,
        u64::try_from(guard_functions.len())
            .map_err(|_| anyhow::anyhow!("Guard CF function count exceeds u64"))?,
    );
    put_u32(&mut bytes, GUARD_FLAGS_OFFSET, flags);
    put_optional_va(
        &mut bytes,
        GUARD_EH_TABLE_OFFSET,
        config.image_base,
        eh_table_rva,
        "Guard EH continuation table VA",
    )?;
    put_u64(
        &mut bytes,
        GUARD_EH_COUNT_OFFSET,
        u64::try_from(eh_continuations.len())
            .map_err(|_| anyhow::anyhow!("Guard EH continuation count exceeds u64"))?,
    );

    let mut cursor = directory_size;
    write_rva_table(&mut bytes, &mut cursor, &guard_functions);
    write_rva_table(&mut bytes, &mut cursor, &eh_continuations);
    debug_assert_eq!(cursor, total_size);

    let mut relocations = Vec::new();
    add_pointer_relocation(
        &mut relocations,
        config.directory_rva,
        SECURITY_COOKIE_OFFSET,
        config.security_cookie_rva.is_some(),
    )?;
    add_pointer_relocation(
        &mut relocations,
        config.directory_rva,
        GUARD_CF_CHECK_OFFSET,
        config.guard_cf_check_function_pointer_rva.is_some(),
    )?;
    add_pointer_relocation(
        &mut relocations,
        config.directory_rva,
        GUARD_CF_DISPATCH_OFFSET,
        config.guard_cf_dispatch_function_pointer_rva.is_some(),
    )?;
    add_pointer_relocation(
        &mut relocations,
        config.directory_rva,
        GUARD_CF_TABLE_OFFSET,
        guard_table_rva.is_some(),
    )?;
    add_pointer_relocation(
        &mut relocations,
        config.directory_rva,
        GUARD_EH_TABLE_OFFSET,
        eh_table_rva.is_some(),
    )?;

    Ok(EncodedPeLoadConfig64 {
        bytes,
        data_directory_rva: config.directory_rva,
        data_directory_size: IMAGE_LOAD_CONFIG_DIRECTORY64_COMPAT_SIZE,
        dir64_relocation_rvas: relocations,
        guard_cf_function_table_rva: guard_table_rva,
        guard_eh_continuation_table_rva: eh_table_rva,
        guard_flags: flags,
    })
}

/// Parses metadata emitted by [`encode_pe_load_config64`] and validates all
/// addresses, counts, presence flags, table ordering, and table bounds.
pub fn parse_pe_load_config64(
    data: &[u8],
    directory_rva: u32,
    image_base: u64,
    size_of_image: u32,
) -> Result<ParsedPeLoadConfig64> {
    image_base
        .checked_add(u64::from(size_of_image))
        .ok_or_else(|| anyhow::anyhow!("image VA range overflows u64"))?;
    let directory_size = usize::try_from(IMAGE_LOAD_CONFIG_DIRECTORY64_COMPAT_SIZE)
        .map_err(|_| anyhow::anyhow!("load-config directory size does not fit usize"))?;
    ensure!(
        data.len() >= directory_size,
        "load-config data is shorter than the 280-byte AMD64 directory"
    );
    ensure!(
        read_u32(data, 0) == IMAGE_LOAD_CONFIG_DIRECTORY64_COMPAT_SIZE,
        "unsupported AMD64 load-config directory size {}",
        read_u32(data, 0)
    );
    let data_size = u32::try_from(data.len())
        .map_err(|_| anyhow::anyhow!("load-config data exceeds u32 size"))?;
    validate_range(
        directory_rva,
        data_size,
        size_of_image,
        "load-config metadata",
    )?;

    let security_cookie_rva = read_optional_va(
        data,
        SECURITY_COOKIE_OFFSET,
        image_base,
        size_of_image,
        "security cookie VA",
    )?;
    let check_rva = read_optional_va(
        data,
        GUARD_CF_CHECK_OFFSET,
        image_base,
        size_of_image,
        "Guard CF check-function pointer VA",
    )?;
    let dispatch_rva = read_optional_va(
        data,
        GUARD_CF_DISPATCH_OFFSET,
        image_base,
        size_of_image,
        "Guard CF dispatch-function pointer VA",
    )?;
    validate_optional_pointer(security_cookie_rva, size_of_image, "security cookie")?;
    validate_optional_pointer(check_rva, size_of_image, "Guard CF check-function pointer")?;
    validate_optional_pointer(
        dispatch_rva,
        size_of_image,
        "Guard CF dispatch-function pointer",
    )?;
    let guard_table_rva = read_optional_va(
        data,
        GUARD_CF_TABLE_OFFSET,
        image_base,
        size_of_image,
        "Guard CF function table VA",
    )?;
    let eh_table_rva = read_optional_va(
        data,
        GUARD_EH_TABLE_OFFSET,
        image_base,
        size_of_image,
        "Guard EH continuation table VA",
    )?;
    let guard_count = count_to_usize(read_u64(data, GUARD_CF_COUNT_OFFSET), "Guard CF")?;
    let eh_count = count_to_usize(read_u64(data, GUARD_EH_COUNT_OFFSET), "Guard EH")?;
    let flags = read_u32(data, GUARD_FLAGS_OFFSET);
    ensure!(
        flags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK == 0,
        "Guard CF function-table entry extensions are not supported"
    );

    validate_table_presence(
        guard_table_rva,
        guard_count,
        flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT != 0,
        "Guard CF function table",
    )?;
    validate_table_presence(
        eh_table_rva,
        eh_count,
        flags & IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT != 0,
        "Guard EH continuation table",
    )?;
    validate_canonical_table_layout(
        data.len(),
        directory_rva,
        guard_table_rva,
        guard_count,
        eh_table_rva,
        eh_count,
    )?;
    let guard_functions = parse_rva_table(
        data,
        directory_rva,
        guard_table_rva,
        guard_count,
        size_of_image,
        "Guard CF function table",
    )?;
    let eh_continuations = parse_rva_table(
        data,
        directory_rva,
        eh_table_rva,
        eh_count,
        size_of_image,
        "Guard EH continuation table",
    )?;

    let mut relocations = Vec::new();
    for (offset, present) in [
        (SECURITY_COOKIE_OFFSET, security_cookie_rva.is_some()),
        (GUARD_CF_CHECK_OFFSET, check_rva.is_some()),
        (GUARD_CF_DISPATCH_OFFSET, dispatch_rva.is_some()),
        (GUARD_CF_TABLE_OFFSET, guard_table_rva.is_some()),
        (GUARD_EH_TABLE_OFFSET, eh_table_rva.is_some()),
    ] {
        add_pointer_relocation(&mut relocations, directory_rva, offset, present)?;
    }

    Ok(ParsedPeLoadConfig64 {
        security_cookie_rva,
        guard_cf_check_function_pointer_rva: check_rva,
        guard_cf_dispatch_function_pointer_rva: dispatch_rva,
        guard_cf_function_rvas: guard_functions,
        guard_eh_continuation_rvas: eh_continuations,
        guard_flags: flags,
        dir64_relocation_rvas: relocations,
    })
}

fn canonical_rvas(values: &[u32], size_of_image: u32, description: &str) -> Result<Vec<u32>> {
    let values = values.iter().copied().collect::<BTreeSet<_>>();
    for rva in values.iter().copied() {
        ensure!(
            rva < size_of_image,
            "{description} RVA {rva:#x} is outside image size {size_of_image:#x}"
        );
    }
    Ok(values.into_iter().collect())
}

fn validate_optional_pointer(
    value: Option<u32>,
    size_of_image: u32,
    description: &str,
) -> Result<()> {
    if let Some(rva) = value {
        validate_range(rva, 8, size_of_image, description)?;
    }
    Ok(())
}

fn validate_range(rva: u32, size: u32, size_of_image: u32, description: &str) -> Result<()> {
    let end = rva
        .checked_add(size)
        .ok_or_else(|| anyhow::anyhow!("{description} RVA range overflows u32"))?;
    ensure!(
        end <= size_of_image,
        "{description} at RVA {rva:#x} with size {size:#x} extends past image size {size_of_image:#x}"
    );
    Ok(())
}

fn table_size(count: usize, description: &str) -> Result<usize> {
    count
        .checked_mul(4)
        .ok_or_else(|| anyhow::anyhow!("{description} size overflow"))
}

fn optional_table_rva(
    directory_rva: u32,
    offset: u32,
    present: bool,
    description: &str,
) -> Result<Option<u32>> {
    present
        .then(|| {
            directory_rva
                .checked_add(offset)
                .ok_or_else(|| anyhow::anyhow!("{description} overflows u32"))
        })
        .transpose()
}

fn put_optional_va(
    data: &mut [u8],
    offset: u32,
    image_base: u64,
    rva: Option<u32>,
    description: &str,
) -> Result<()> {
    let va = rva
        .map(|rva| {
            image_base
                .checked_add(u64::from(rva))
                .ok_or_else(|| anyhow::anyhow!("{description} overflows u64"))
        })
        .transpose()?;
    ensure!(
        va.is_none_or(|va| va != 0),
        "{description} cannot be encoded as the null VA"
    );
    let va = va.unwrap_or(0);
    put_u64(data, offset, va);
    Ok(())
}

fn read_optional_va(
    data: &[u8],
    offset: u32,
    image_base: u64,
    size_of_image: u32,
    description: &str,
) -> Result<Option<u32>> {
    let va = read_u64(data, offset);
    if va == 0 {
        return Ok(None);
    }
    let rva = va.checked_sub(image_base).ok_or_else(|| {
        anyhow::anyhow!("{description} {va:#x} is below image base {image_base:#x}")
    })?;
    let rva = u32::try_from(rva)
        .map_err(|_| anyhow::anyhow!("{description} {va:#x} does not have a 32-bit RVA"))?;
    ensure!(
        rva < size_of_image,
        "{description} {va:#x} is outside image size {size_of_image:#x}"
    );
    Ok(Some(rva))
}

fn validate_table_presence(
    table_rva: Option<u32>,
    count: usize,
    flag_present: bool,
    description: &str,
) -> Result<()> {
    ensure!(
        table_rva.is_some() == (count != 0),
        "{description} VA and count disagree"
    );
    ensure!(
        flag_present == (count != 0),
        "{description} presence flag and count disagree"
    );
    Ok(())
}

fn parse_rva_table(
    data: &[u8],
    directory_rva: u32,
    table_rva: Option<u32>,
    count: usize,
    size_of_image: u32,
    description: &str,
) -> Result<Vec<u32>> {
    let Some(table_rva) = table_rva else {
        return Ok(Vec::new());
    };
    let offset = table_rva.checked_sub(directory_rva).ok_or_else(|| {
        anyhow::anyhow!("{description} RVA {table_rva:#x} precedes the directory")
    })?;
    let offset = usize::try_from(offset)
        .map_err(|_| anyhow::anyhow!("{description} offset does not fit usize"))?;
    let size = table_size(count, description)?;
    let end = offset
        .checked_add(size)
        .ok_or_else(|| anyhow::anyhow!("{description} end overflow"))?;
    ensure!(
        end <= data.len(),
        "{description} extends past supplied data"
    );
    let mut values = Vec::with_capacity(count);
    for entry in data[offset..end].chunks_exact(4) {
        let rva = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
        ensure!(
            rva < size_of_image,
            "{description} entry RVA {rva:#x} is outside image size {size_of_image:#x}"
        );
        ensure!(
            values.last().is_none_or(|previous| *previous < rva),
            "{description} entries are not strictly sorted and unique"
        );
        values.push(rva);
    }
    Ok(values)
}

fn validate_canonical_table_layout(
    data_len: usize,
    directory_rva: u32,
    guard_table_rva: Option<u32>,
    guard_count: usize,
    eh_table_rva: Option<u32>,
    eh_count: usize,
) -> Result<()> {
    let guard_size = table_size(guard_count, "Guard CF function table")?;
    let eh_size = table_size(eh_count, "Guard EH continuation table")?;
    let expected_size = usize::try_from(IMAGE_LOAD_CONFIG_DIRECTORY64_COMPAT_SIZE)
        .map_err(|_| anyhow::anyhow!("load-config directory size does not fit usize"))?
        .checked_add(guard_size)
        .and_then(|size| size.checked_add(eh_size))
        .ok_or_else(|| anyhow::anyhow!("load-config metadata size overflow"))?;
    ensure!(
        data_len == expected_size,
        "load-config data size {data_len} does not match canonical size {expected_size}"
    );

    let expected_guard_rva = optional_table_rva(
        directory_rva,
        IMAGE_LOAD_CONFIG_DIRECTORY64_COMPAT_SIZE,
        guard_count != 0,
        "Guard CF function table RVA",
    )?;
    ensure!(
        guard_table_rva == expected_guard_rva,
        "Guard CF function table is not at its canonical RVA"
    );
    let guard_size = u32::try_from(guard_size)
        .map_err(|_| anyhow::anyhow!("Guard CF function table exceeds u32 size"))?;
    let eh_offset = IMAGE_LOAD_CONFIG_DIRECTORY64_COMPAT_SIZE
        .checked_add(guard_size)
        .ok_or_else(|| anyhow::anyhow!("Guard EH continuation table offset overflow"))?;
    let expected_eh_rva = optional_table_rva(
        directory_rva,
        eh_offset,
        eh_count != 0,
        "Guard EH continuation table RVA",
    )?;
    ensure!(
        eh_table_rva == expected_eh_rva,
        "Guard EH continuation table is not at its canonical RVA"
    );
    Ok(())
}

fn count_to_usize(count: u64, description: &str) -> Result<usize> {
    usize::try_from(count).map_err(|_| anyhow::anyhow!("{description} count does not fit usize"))
}

fn add_pointer_relocation(
    relocations: &mut Vec<u32>,
    directory_rva: u32,
    field_offset: u32,
    present: bool,
) -> Result<()> {
    if present {
        relocations.push(
            directory_rva
                .checked_add(field_offset)
                .ok_or_else(|| anyhow::anyhow!("load-config relocation RVA overflow"))?,
        );
    }
    Ok(())
}

fn write_rva_table(data: &mut [u8], cursor: &mut usize, values: &[u32]) {
    for value in values {
        data[*cursor..*cursor + 4].copy_from_slice(&value.to_le_bytes());
        *cursor += 4;
    }
}

fn put_u32(data: &mut [u8], offset: u32, value: u32) {
    let offset = offset as usize;
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(data: &mut [u8], offset: u32, value: u64) {
    let offset = offset as usize;
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u32(data: &[u8], offset: u32) -> u32 {
    let offset = offset as usize;
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_u64(data: &[u8], offset: u32) -> u64 {
    let offset = offset as usize;
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_config() -> PeLoadConfig64 {
        PeLoadConfig64 {
            image_base: 0x0000_0001_4000_0000,
            directory_rva: 0x5000,
            size_of_image: 0x8000,
            security_cookie_rva: Some(0x4010),
            guard_cf_check_function_pointer_rva: Some(0x4020),
            guard_cf_dispatch_function_pointer_rva: Some(0x4030),
            guard_cf_function_rvas: vec![0x1300, 0x1100, 0x1200, 0x1100],
            guard_eh_continuation_rvas: vec![0x1410, 0x1400, 0x1410],
            guard_flags: IMAGE_GUARD_CF_INSTRUMENTED,
        }
    }

    #[test]
    fn encodes_compatible_layout_and_sorted_tables() {
        let encoded = encode_pe_load_config64(&full_config()).unwrap();

        assert_eq!(read_u32(&encoded.bytes, 0), 280);
        assert_eq!(encoded.data_directory_rva, 0x5000);
        assert_eq!(encoded.data_directory_size, 280);
        assert_eq!(encoded.guard_cf_function_table_rva, Some(0x5118));
        assert_eq!(encoded.guard_eh_continuation_table_rva, Some(0x5124));
        assert_eq!(read_u64(&encoded.bytes, GUARD_CF_COUNT_OFFSET), 3);
        assert_eq!(read_u64(&encoded.bytes, GUARD_EH_COUNT_OFFSET), 2);
        assert_eq!(
            &encoded.bytes[280..292],
            &[0x00, 0x11, 0, 0, 0x00, 0x12, 0, 0, 0x00, 0x13, 0, 0]
        );
        assert_eq!(&encoded.bytes[292..], &[0x00, 0x14, 0, 0, 0x10, 0x14, 0, 0]);
        assert_eq!(
            encoded.guard_flags,
            IMAGE_GUARD_CF_INSTRUMENTED
                | IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT
                | IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT
        );
        assert_eq!(
            encoded.dir64_relocation_rvas,
            vec![0x5058, 0x5070, 0x5078, 0x5080, 0x5108]
        );
    }

    #[test]
    fn round_trips_semantics_and_relocations() {
        let encoded = encode_pe_load_config64(&full_config()).unwrap();
        let parsed = parse_pe_load_config64(
            &encoded.bytes,
            encoded.data_directory_rva,
            full_config().image_base,
            full_config().size_of_image,
        )
        .unwrap();

        assert_eq!(parsed.security_cookie_rva, Some(0x4010));
        assert_eq!(parsed.guard_cf_check_function_pointer_rva, Some(0x4020));
        assert_eq!(parsed.guard_cf_dispatch_function_pointer_rva, Some(0x4030));
        assert_eq!(parsed.guard_cf_function_rvas, vec![0x1100, 0x1200, 0x1300]);
        assert_eq!(parsed.guard_eh_continuation_rvas, vec![0x1400, 0x1410]);
        assert_eq!(parsed.dir64_relocation_rvas, encoded.dir64_relocation_rvas);
    }

    #[test]
    fn empty_tables_clear_presence_bits_and_emit_only_directory() {
        let mut config = full_config();
        config.security_cookie_rva = None;
        config.guard_cf_check_function_pointer_rva = None;
        config.guard_cf_dispatch_function_pointer_rva = None;
        config.guard_cf_function_rvas.clear();
        config.guard_eh_continuation_rvas.clear();
        config.guard_flags |=
            IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT | IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT;

        let encoded = encode_pe_load_config64(&config).unwrap();
        assert_eq!(encoded.bytes.len(), 280);
        assert_eq!(encoded.guard_flags, IMAGE_GUARD_CF_INSTRUMENTED);
        assert!(encoded.dir64_relocation_rvas.is_empty());
        assert_eq!(
            parse_pe_load_config64(
                &encoded.bytes,
                config.directory_rva,
                config.image_base,
                config.size_of_image,
            )
            .unwrap()
            .guard_cf_function_rvas,
            Vec::<u32>::new()
        );
    }

    #[test]
    fn encoding_is_deterministic_across_table_order_and_duplicates() {
        let first = encode_pe_load_config64(&full_config()).unwrap();
        let mut reordered = full_config();
        reordered.guard_cf_function_rvas = vec![0x1200, 0x1100, 0x1300];
        reordered.guard_eh_continuation_rvas = vec![0x1400, 0x1410];
        let second = encode_pe_load_config64(&reordered).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn rejects_invalid_ranges_and_va_overflow() {
        let mut config = full_config();
        config.security_cookie_rva = Some(0x7ff9);
        assert!(
            encode_pe_load_config64(&config)
                .unwrap_err()
                .to_string()
                .contains("security cookie")
        );

        let mut config = full_config();
        config.guard_cf_function_rvas.push(0x8000);
        assert!(
            encode_pe_load_config64(&config)
                .unwrap_err()
                .to_string()
                .contains("outside image")
        );

        let mut config = full_config();
        config.image_base = u64::MAX;
        assert!(
            encode_pe_load_config64(&config)
                .unwrap_err()
                .to_string()
                .contains("VA range overflows")
        );

        let mut config = full_config();
        config.image_base = 0;
        config.security_cookie_rva = Some(0);
        assert!(
            encode_pe_load_config64(&config)
                .unwrap_err()
                .to_string()
                .contains("null VA")
        );
    }

    #[test]
    fn parser_rejects_inconsistent_or_noncanonical_tables() {
        let encoded = encode_pe_load_config64(&full_config()).unwrap();

        let mut bad_count = encoded.bytes.clone();
        put_u64(&mut bad_count, GUARD_CF_COUNT_OFFSET, 0);
        assert!(
            parse_pe_load_config64(&bad_count, 0x5000, 0x0000_0001_4000_0000, 0x8000)
                .unwrap_err()
                .to_string()
                .contains("VA and count disagree")
        );

        let mut bad_order = encoded.bytes.clone();
        bad_order[280..284].copy_from_slice(&0x1300_u32.to_le_bytes());
        assert!(
            parse_pe_load_config64(&bad_order, 0x5000, 0x0000_0001_4000_0000, 0x8000)
                .unwrap_err()
                .to_string()
                .contains("not strictly sorted")
        );

        let mut bad_stride = encoded.bytes;
        let flags = read_u32(&bad_stride, GUARD_FLAGS_OFFSET) | 0x1000_0000;
        put_u32(&mut bad_stride, GUARD_FLAGS_OFFSET, flags);
        assert!(
            parse_pe_load_config64(&bad_stride, 0x5000, 0x0000_0001_4000_0000, 0x8000)
                .unwrap_err()
                .to_string()
                .contains("entry extensions")
        );
    }
}
