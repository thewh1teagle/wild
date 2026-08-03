//! Construction and validation of PE32+ AMD64 delay-import metadata.
//!
//! Delay imports use an `ImgDelayDescr` array and 64-bit thunk arrays. This
//! module deliberately does not emit the architecture-specific resolver stub:
//! it returns symbolic relocation requirements for each helper thunk, allowing
//! the linker to choose and evolve its own code sequence.

use std::cmp::Ordering;

use anyhow::{Context, Result, bail, ensure};

/// Size of one `ImgDelayDescr` record.
pub const IMAGE_DELAY_IMPORT_DESCRIPTOR_SIZE: u32 = 32;
/// `ImgDelayDescr::grAttrs` indicates that pointer fields contain RVAs.
pub const IMAGE_DELAY_IMPORT_ATTRIBUTE_RVA: u32 = 1;

const THUNK_SIZE: usize = 8;
const ORDINAL_FLAG64: u64 = 1 << 63;

/// One loader lookup in a delay-import name table.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DelayImportTarget<'data> {
    Name { name: &'data [u8], hint: u16 },
    Ordinal(u16),
}

/// All delayed symbols imported from one DLL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelayImportDll<'data> {
    pub name: &'data [u8],
    pub imports: &'data [DelayImportTarget<'data>],
    /// Binding timestamp, or zero for an unbound image.
    pub timestamp: u32,
    /// Previously bound target VAs. The length must match `imports`.
    pub bound_iat: Option<&'data [u64]>,
    /// Emit an unload-IAT containing the original lookup values.
    pub emit_unload_iat: bool,
}

/// RVA bounds and starting placement selected by the PE layout pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelayImportLayout {
    pub metadata_rva: u32,
    /// Exclusive upper bound of mapped image RVAs.
    pub size_of_image: u32,
}

/// PE optional-header delay-import data-directory entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelayImportDataDirectory {
    pub rva: u32,
    pub size: u32,
}

/// Placement of one canonical import in its DLL's thunk arrays.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelayImportPlacement {
    pub target: OwnedDelayImportTarget,
    pub int_slot_rva: u32,
    pub iat_slot_rva: u32,
    pub bound_iat_slot_rva: Option<u32>,
    pub unload_iat_slot_rva: Option<u32>,
}

/// Placement of all delay-import metadata for one DLL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelayImportDllPlacement {
    pub name: Vec<u8>,
    pub descriptor_rva: u32,
    pub name_rva: u32,
    pub module_handle_rva: u32,
    pub int_rva: u32,
    pub iat_rva: u32,
    pub bound_iat_rva: Option<u32>,
    pub unload_iat_rva: Option<u32>,
    pub timestamp: u32,
    pub imports: Vec<DelayImportPlacement>,
}

/// A relocation target required by a linker-generated AMD64 delay thunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Amd64DelayThunkRelocationTarget {
    /// The external `__delayLoadHelper2` implementation selected by the CRT.
    DelayLoadHelper,
    /// The containing DLL's `ImgDelayDescr`.
    DescriptorRva(u32),
    /// The import's writable delay-IAT slot.
    IatSlotRva(u32),
}

/// A relocation class suitable for an AMD64 helper-thunk template.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Amd64DelayThunkRelocationKind {
    /// `IMAGE_REL_AMD64_REL32` to the helper routine or an image location.
    Rel32,
    /// `IMAGE_REL_AMD64_ADDR32NB`, an image-relative 32-bit address.
    Addr32Nb,
    /// `IMAGE_REL_AMD64_ADDR64`, an absolute 64-bit VA requiring base relocation.
    Addr64,
}

/// Symbolic fixup needed by a delay helper thunk.
///
/// The code-template owner chooses field offsets; this utility supplies the
/// conventional relocation class and semantic target for each fixup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Amd64DelayThunkRelocation {
    pub kind: Amd64DelayThunkRelocationKind,
    pub target: Amd64DelayThunkRelocationTarget,
}

/// Per-import targets needed to instantiate an AMD64 delay helper thunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Amd64DelayHelperThunkRelocations {
    pub dll: Vec<u8>,
    pub import: OwnedDelayImportTarget,
    pub relocations: [Amd64DelayThunkRelocation; 3],
}

/// Owned form used by encoded and parsed results.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum OwnedDelayImportTarget {
    Name { name: Vec<u8>, hint: u16 },
    Ordinal(u16),
}

/// Complete, contiguous delay-import payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelayImportImage {
    pub bytes: Vec<u8>,
    pub data_directory: DelayImportDataDirectory,
    pub dlls: Vec<DelayImportDllPlacement>,
    pub helper_thunk_relocations: Vec<Amd64DelayHelperThunkRelocations>,
}

/// Semantic representation returned by the validator/parser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedDelayImportDll {
    pub name: Vec<u8>,
    pub imports: Vec<OwnedDelayImportTarget>,
    pub timestamp: u32,
    pub bound_iat: Option<Vec<u64>>,
    pub has_unload_iat: bool,
}

#[derive(Clone, Debug)]
struct CanonicalDll {
    name: Vec<u8>,
    imports: Vec<OwnedDelayImportTarget>,
    timestamp: u32,
    bound_iat: Option<Vec<u64>>,
    emit_unload_iat: bool,
}

/// Builds deterministic PE32+ delay-import metadata.
///
/// DLLs are ordered ASCII-case-insensitively (with a bytewise tie-break), and
/// imports are sorted bytewise. Duplicate DLLs and duplicate targets are
/// rejected because they generally indicate an unresolved linker-level symbol
/// selection error. All descriptors use RVA attributes and the array is
/// terminated by one zero descriptor.
pub fn build_amd64_delay_imports(
    layout: DelayImportLayout,
    dlls: &[DelayImportDll<'_>],
) -> Result<DelayImportImage> {
    if dlls.is_empty() {
        return Ok(DelayImportImage {
            bytes: Vec::new(),
            data_directory: DelayImportDataDirectory { rva: 0, size: 0 },
            dlls: Vec::new(),
            helper_thunk_relocations: Vec::new(),
        });
    }
    ensure!(
        layout.metadata_rva < layout.size_of_image,
        "delay-import metadata RVA lies outside the image"
    );
    ensure!(
        layout.metadata_rva.is_multiple_of(THUNK_SIZE as u32),
        "delay-import metadata RVA is not 8-byte aligned"
    );
    let mut canonical = dlls
        .iter()
        .map(canonicalize_dll)
        .collect::<Result<Vec<_>>>()?;
    canonical.sort_by(|left, right| compare_dll_names(&left.name, &right.name));
    for pair in canonical.windows(2) {
        ensure!(
            !pair[0].name.eq_ignore_ascii_case(&pair[1].name),
            "duplicate delay-import DLL {}",
            display_bytes(&pair[0].name)
        );
    }

    let descriptor_count = canonical
        .len()
        .checked_add(1)
        .context("delay-import descriptor count overflow")?;
    let descriptor_bytes = descriptor_count
        .checked_mul(IMAGE_DELAY_IMPORT_DESCRIPTOR_SIZE as usize)
        .context("delay-import descriptor table size overflow")?;
    let descriptor_size =
        u32::try_from(descriptor_bytes).context("delay-import descriptor table exceeds 4 GiB")?;
    let mut bytes = vec![0; descriptor_bytes];
    let mut placements = Vec::with_capacity(canonical.len());

    for (dll_index, dll) in canonical.iter().enumerate() {
        let descriptor_offset = dll_index
            .checked_mul(IMAGE_DELAY_IMPORT_DESCRIPTOR_SIZE as usize)
            .context("delay-import descriptor offset overflow")?;
        let descriptor_rva = rva_at(layout, descriptor_offset, 32, "delay-import descriptor")?;

        let name_offset = bytes.len();
        let encoded_name_size = dll
            .name
            .len()
            .checked_add(1)
            .context("delay-import DLL name size overflow")?;
        bytes.extend_from_slice(&dll.name);
        bytes.push(0);
        let name_rva = rva_at(
            layout,
            name_offset,
            encoded_name_size,
            "delay-import DLL name",
        )?;

        align_vec(&mut bytes, 2)?;
        let mut lookup_values = Vec::with_capacity(dll.imports.len());
        for import in &dll.imports {
            let value = match import {
                OwnedDelayImportTarget::Name { name, hint } => {
                    let offset = bytes.len();
                    bytes.extend_from_slice(&hint.to_le_bytes());
                    bytes.extend_from_slice(name);
                    bytes.push(0);
                    align_vec(&mut bytes, 2)?;
                    let record_size = name
                        .len()
                        .checked_add(3)
                        .context("delay-import hint/name record size overflow")?;
                    u64::from(rva_at(
                        layout,
                        offset,
                        record_size,
                        "delay-import hint/name record",
                    )?)
                }
                OwnedDelayImportTarget::Ordinal(ordinal) => ORDINAL_FLAG64 | u64::from(*ordinal),
            };
            lookup_values.push(value);
        }

        align_vec(&mut bytes, THUNK_SIZE)?;
        let int_offset = append_thunks(&mut bytes, &lookup_values)?;
        let int_rva = rva_at(
            layout,
            int_offset,
            thunk_array_len(dll.imports.len())?,
            "delay INT",
        )?;
        let iat_offset = append_thunks(&mut bytes, &lookup_values)?;
        let iat_rva = rva_at(
            layout,
            iat_offset,
            thunk_array_len(dll.imports.len())?,
            "delay IAT",
        )?;

        let bound_iat_rva = if let Some(bound_iat) = &dll.bound_iat {
            let offset = append_thunks(&mut bytes, bound_iat)?;
            Some(rva_at(
                layout,
                offset,
                thunk_array_len(dll.imports.len())?,
                "delay bound IAT",
            )?)
        } else {
            None
        };
        let unload_iat_rva = if dll.emit_unload_iat {
            let offset = append_thunks(&mut bytes, &lookup_values)?;
            Some(rva_at(
                layout,
                offset,
                thunk_array_len(dll.imports.len())?,
                "delay unload IAT",
            )?)
        } else {
            None
        };

        let module_handle_offset = bytes.len();
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        let module_handle_rva = rva_at(
            layout,
            module_handle_offset,
            THUNK_SIZE,
            "delay module-handle slot",
        )?;

        put_u32(
            &mut bytes,
            descriptor_offset,
            IMAGE_DELAY_IMPORT_ATTRIBUTE_RVA,
        );
        put_u32(&mut bytes, descriptor_offset + 4, name_rva);
        put_u32(&mut bytes, descriptor_offset + 8, module_handle_rva);
        put_u32(&mut bytes, descriptor_offset + 12, iat_rva);
        put_u32(&mut bytes, descriptor_offset + 16, int_rva);
        put_u32(
            &mut bytes,
            descriptor_offset + 20,
            bound_iat_rva.unwrap_or(0),
        );
        put_u32(
            &mut bytes,
            descriptor_offset + 24,
            unload_iat_rva.unwrap_or(0),
        );
        put_u32(&mut bytes, descriptor_offset + 28, dll.timestamp);

        let imports = dll
            .imports
            .iter()
            .enumerate()
            .map(|(index, target)| {
                let slot_offset = u32::try_from(
                    index
                        .checked_mul(THUNK_SIZE)
                        .context("delay-import thunk slot offset overflow")?,
                )
                .context("delay-import thunk slot offset exceeds 4 GiB")?;
                Ok(DelayImportPlacement {
                    target: target.clone(),
                    int_slot_rva: int_rva
                        .checked_add(slot_offset)
                        .context("delay INT slot RVA overflow")?,
                    iat_slot_rva: iat_rva
                        .checked_add(slot_offset)
                        .context("delay IAT slot RVA overflow")?,
                    bound_iat_slot_rva: optional_add(
                        bound_iat_rva,
                        slot_offset,
                        "delay bound-IAT slot RVA",
                    )?,
                    unload_iat_slot_rva: optional_add(
                        unload_iat_rva,
                        slot_offset,
                        "delay unload-IAT slot RVA",
                    )?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        placements.push(DelayImportDllPlacement {
            name: dll.name.clone(),
            descriptor_rva,
            name_rva,
            module_handle_rva,
            int_rva,
            iat_rva,
            bound_iat_rva,
            unload_iat_rva,
            timestamp: dll.timestamp,
            imports,
        });
    }

    let total_size = u32::try_from(bytes.len()).context("delay-import metadata exceeds 4 GiB")?;
    validate_range(
        layout.metadata_rva,
        total_size,
        layout.size_of_image,
        "delay-import metadata",
    )?;
    let helper_thunk_relocations = placements
        .iter()
        .flat_map(|dll| {
            dll.imports
                .iter()
                .map(|import| Amd64DelayHelperThunkRelocations {
                    dll: dll.name.clone(),
                    import: import.target.clone(),
                    relocations: [
                        Amd64DelayThunkRelocation {
                            kind: Amd64DelayThunkRelocationKind::Rel32,
                            target: Amd64DelayThunkRelocationTarget::DelayLoadHelper,
                        },
                        Amd64DelayThunkRelocation {
                            kind: Amd64DelayThunkRelocationKind::Addr32Nb,
                            target: Amd64DelayThunkRelocationTarget::DescriptorRva(
                                dll.descriptor_rva,
                            ),
                        },
                        Amd64DelayThunkRelocation {
                            kind: Amd64DelayThunkRelocationKind::Addr32Nb,
                            target: Amd64DelayThunkRelocationTarget::IatSlotRva(
                                import.iat_slot_rva,
                            ),
                        },
                    ],
                })
        })
        .collect();

    Ok(DelayImportImage {
        bytes,
        data_directory: DelayImportDataDirectory {
            rva: layout.metadata_rva,
            size: descriptor_size,
        },
        dlls: placements,
        helper_thunk_relocations,
    })
}

/// Parses and strictly validates a contiguous delay-import payload.
pub fn parse_amd64_delay_imports(
    data: &[u8],
    metadata_rva: u32,
    directory: DelayImportDataDirectory,
    size_of_image: u32,
) -> Result<Vec<ParsedDelayImportDll>> {
    if directory.rva == 0 && directory.size == 0 {
        ensure!(
            data.is_empty(),
            "empty delay-import directory has metadata bytes"
        );
        return Ok(Vec::new());
    }
    ensure!(
        directory.rva == metadata_rva,
        "delay-import directory does not start at the metadata RVA"
    );
    ensure!(
        metadata_rva.is_multiple_of(THUNK_SIZE as u32),
        "delay-import metadata RVA is not 8-byte aligned"
    );
    ensure!(
        directory.size >= IMAGE_DELAY_IMPORT_DESCRIPTOR_SIZE,
        "delay-import directory omits its null terminator"
    );
    ensure!(
        directory
            .size
            .is_multiple_of(IMAGE_DELAY_IMPORT_DESCRIPTOR_SIZE),
        "delay-import directory size is not descriptor-aligned"
    );
    let data_size = u32::try_from(data.len()).context("delay-import metadata exceeds 4 GiB")?;
    validate_range(
        metadata_rva,
        data_size,
        size_of_image,
        "delay-import metadata",
    )?;
    ensure!(
        directory.size <= data_size,
        "delay-import directory extends past supplied metadata"
    );
    let descriptor_count = directory.size / IMAGE_DELAY_IMPORT_DESCRIPTOR_SIZE;
    let mut parsed = Vec::new();
    let mut previous_name: Option<Vec<u8>> = None;
    for index in 0..descriptor_count {
        let offset = usize::try_from(index * IMAGE_DELAY_IMPORT_DESCRIPTOR_SIZE).unwrap();
        let descriptor = &data[offset..offset + IMAGE_DELAY_IMPORT_DESCRIPTOR_SIZE as usize];
        if descriptor.iter().all(|byte| *byte == 0) {
            ensure!(
                index + 1 == descriptor_count,
                "delay-import null descriptor is not last"
            );
            return Ok(parsed);
        }
        ensure!(
            index + 1 < descriptor_count,
            "delay-import descriptor table lacks a null terminator"
        );
        ensure!(
            read_u32(descriptor, 0) == IMAGE_DELAY_IMPORT_ATTRIBUTE_RVA,
            "unsupported delay-import attributes {:#x}",
            read_u32(descriptor, 0)
        );
        let name_rva = read_u32(descriptor, 4);
        let hmod_rva = read_u32(descriptor, 8);
        let iat_rva = read_u32(descriptor, 12);
        let int_rva = read_u32(descriptor, 16);
        let bound_rva = nonzero(read_u32(descriptor, 20));
        let unload_rva = nonzero(read_u32(descriptor, 24));
        let timestamp = read_u32(descriptor, 28);
        ensure!(
            name_rva != 0 && hmod_rva != 0 && iat_rva != 0 && int_rva != 0,
            "delay-import descriptor has a required null RVA"
        );
        let name = read_c_string(
            data,
            offset_of(metadata_rva, name_rva, data.len(), "DLL name")?,
            "delay-import DLL name",
        )?
        .to_vec();
        validate_name(&name, "delay-import DLL name")?;
        if let Some(previous) = &previous_name {
            ensure!(
                compare_dll_names(previous, &name) == Ordering::Less
                    && !previous.eq_ignore_ascii_case(&name),
                "delay-import DLL descriptors are not strictly sorted"
            );
        }
        previous_name = Some(name.clone());
        let hmod_offset = offset_of(metadata_rva, hmod_rva, data.len(), "module-handle slot")?;
        ensure!(
            hmod_offset % THUNK_SIZE == 0,
            "delay module-handle slot is not 8-byte aligned"
        );
        ensure!(
            read_u64_checked(data, hmod_offset, "module-handle slot")? == 0,
            "delay module-handle slot is not initially zero"
        );

        let lookup = read_thunks(data, metadata_rva, int_rva, "delay INT")?;
        ensure!(!lookup.is_empty(), "delay-import DLL has no imports");
        let iat = read_thunks(data, metadata_rva, iat_rva, "delay IAT")?;
        ensure!(
            iat == lookup,
            "delay IAT does not contain the initial lookup values"
        );
        let imports = parse_lookup_values(data, metadata_rva, &lookup)?;
        ensure_strict_targets(&imports)?;
        let bound_iat = if let Some(rva) = bound_rva {
            let values = read_thunks(data, metadata_rva, rva, "delay bound IAT")?;
            ensure!(
                values.len() == lookup.len(),
                "delay bound-IAT length does not match INT"
            );
            Some(values)
        } else {
            ensure!(
                timestamp == 0,
                "delay-import timestamp requires a bound IAT"
            );
            None
        };
        if let Some(rva) = unload_rva {
            let values = read_thunks(data, metadata_rva, rva, "delay unload IAT")?;
            ensure!(
                values == lookup,
                "delay unload IAT does not preserve initial lookup values"
            );
        }
        parsed.push(ParsedDelayImportDll {
            name,
            imports,
            timestamp,
            bound_iat,
            has_unload_iat: unload_rva.is_some(),
        });
    }
    bail!("delay-import descriptor table lacks a null terminator")
}

fn canonicalize_dll(input: &DelayImportDll<'_>) -> Result<CanonicalDll> {
    validate_name(input.name, "delay-import DLL name")?;
    ensure!(
        !input.imports.is_empty(),
        "delay-import DLL {} has no imports",
        display_bytes(input.name)
    );
    if let Some(bound) = input.bound_iat {
        ensure!(
            bound.len() == input.imports.len(),
            "bound IAT for {} has {} entries, expected {}",
            display_bytes(input.name),
            bound.len(),
            input.imports.len()
        );
        ensure!(
            input.timestamp != 0,
            "bound IAT for {} requires a non-zero timestamp",
            display_bytes(input.name)
        );
    } else {
        ensure!(
            input.timestamp == 0,
            "timestamp for {} requires a bound IAT",
            display_bytes(input.name)
        );
    }
    let mut indexed = input
        .imports
        .iter()
        .copied()
        .enumerate()
        .collect::<Vec<_>>();
    for (_, target) in &indexed {
        match target {
            DelayImportTarget::Name { name, .. } => {
                validate_name(name, "delay-import symbol name")?;
            }
            DelayImportTarget::Ordinal(ordinal) => {
                ensure!(*ordinal != 0, "delay import ordinal must not be zero");
            }
        }
    }
    indexed.sort_by(|left, right| compare_target(left.1, right.1));
    for pair in indexed.windows(2) {
        ensure!(
            !same_target(pair[0].1, pair[1].1),
            "duplicate delay import in {}",
            display_bytes(input.name)
        );
    }
    let imports = indexed.iter().map(|(_, target)| owned(*target)).collect();
    let bound_iat: Option<Vec<u64>> = input
        .bound_iat
        .map(|bound| indexed.iter().map(|(index, _)| bound[*index]).collect());
    if let Some(bound) = &bound_iat {
        ensure!(
            bound.iter().all(|address| *address != 0),
            "bound IAT for {} contains a null target",
            display_bytes(input.name)
        );
    }
    Ok(CanonicalDll {
        name: input.name.to_vec(),
        imports,
        timestamp: input.timestamp,
        bound_iat,
        emit_unload_iat: input.emit_unload_iat,
    })
}

fn same_target(left: DelayImportTarget<'_>, right: DelayImportTarget<'_>) -> bool {
    match (left, right) {
        (DelayImportTarget::Ordinal(left), DelayImportTarget::Ordinal(right)) => left == right,
        (
            DelayImportTarget::Name { name: left, .. },
            DelayImportTarget::Name { name: right, .. },
        ) => left == right,
        _ => false,
    }
}

fn compare_dll_names(left: &[u8], right: &[u8]) -> Ordering {
    left.iter()
        .map(u8::to_ascii_lowercase)
        .cmp(right.iter().map(u8::to_ascii_lowercase))
        .then_with(|| left.cmp(right))
}

fn compare_target(left: DelayImportTarget<'_>, right: DelayImportTarget<'_>) -> Ordering {
    match (left, right) {
        (DelayImportTarget::Ordinal(left), DelayImportTarget::Ordinal(right)) => left.cmp(&right),
        (DelayImportTarget::Ordinal(_), DelayImportTarget::Name { .. }) => Ordering::Less,
        (DelayImportTarget::Name { .. }, DelayImportTarget::Ordinal(_)) => Ordering::Greater,
        (
            DelayImportTarget::Name {
                name: left,
                hint: left_hint,
            },
            DelayImportTarget::Name {
                name: right,
                hint: right_hint,
            },
        ) => left.cmp(right).then_with(|| left_hint.cmp(&right_hint)),
    }
}

fn owned(target: DelayImportTarget<'_>) -> OwnedDelayImportTarget {
    match target {
        DelayImportTarget::Name { name, hint } => OwnedDelayImportTarget::Name {
            name: name.to_vec(),
            hint,
        },
        DelayImportTarget::Ordinal(ordinal) => OwnedDelayImportTarget::Ordinal(ordinal),
    }
}

fn append_thunks(output: &mut Vec<u8>, values: &[u64]) -> Result<usize> {
    ensure!(
        output.len().is_multiple_of(THUNK_SIZE),
        "internal delay thunk alignment error"
    );
    let offset = output.len();
    for value in values {
        output.extend_from_slice(&value.to_le_bytes());
    }
    output.extend_from_slice(&0_u64.to_le_bytes());
    Ok(offset)
}

fn thunk_array_len(entries: usize) -> Result<usize> {
    entries
        .checked_add(1)
        .and_then(|count| count.checked_mul(THUNK_SIZE))
        .context("delay thunk array size overflow")
}

fn align_vec(data: &mut Vec<u8>, alignment: usize) -> Result<()> {
    let aligned = data
        .len()
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .context("delay-import alignment overflow")?;
    data.resize(aligned, 0);
    Ok(())
}

fn rva_at(layout: DelayImportLayout, offset: usize, size: usize, what: &str) -> Result<u32> {
    let offset = u32::try_from(offset).with_context(|| format!("{what} offset exceeds 4 GiB"))?;
    let size = u32::try_from(size).with_context(|| format!("{what} size exceeds 4 GiB"))?;
    let rva = layout
        .metadata_rva
        .checked_add(offset)
        .with_context(|| format!("{what} RVA overflow"))?;
    validate_range(rva, size, layout.size_of_image, what)?;
    Ok(rva)
}

fn validate_range(rva: u32, size: u32, image_size: u32, what: &str) -> Result<()> {
    let end = rva
        .checked_add(size)
        .with_context(|| format!("{what} RVA range overflow"))?;
    ensure!(end <= image_size, "{what} extends past image size");
    Ok(())
}

fn optional_add(base: Option<u32>, offset: u32, what: &str) -> Result<Option<u32>> {
    base.map(|base| {
        base.checked_add(offset)
            .with_context(|| format!("{what} overflow"))
    })
    .transpose()
}

fn offset_of(base: u32, rva: u32, data_len: usize, what: &str) -> Result<usize> {
    let offset = rva
        .checked_sub(base)
        .with_context(|| format!("{what} RVA precedes metadata"))?;
    let offset =
        usize::try_from(offset).with_context(|| format!("{what} offset does not fit usize"))?;
    ensure!(offset < data_len, "{what} RVA lies outside metadata");
    Ok(offset)
}

fn read_thunks(data: &[u8], base: u32, rva: u32, what: &str) -> Result<Vec<u64>> {
    let mut offset = offset_of(base, rva, data.len(), what)?;
    ensure!(
        offset.is_multiple_of(THUNK_SIZE),
        "{what} is not 8-byte aligned"
    );
    let mut values = Vec::new();
    loop {
        let value = read_u64_checked(data, offset, what)?;
        offset = offset
            .checked_add(THUNK_SIZE)
            .context("delay thunk cursor overflow")?;
        if value == 0 {
            return Ok(values);
        }
        values.push(value);
    }
}

fn parse_lookup_values(
    data: &[u8],
    base: u32,
    values: &[u64],
) -> Result<Vec<OwnedDelayImportTarget>> {
    values
        .iter()
        .map(|value| {
            if value & ORDINAL_FLAG64 != 0 {
                ensure!(
                    value & !(ORDINAL_FLAG64 | 0xffff) == 0,
                    "delay ordinal thunk has reserved bits set"
                );
                let ordinal = u16::try_from(value & 0xffff).unwrap();
                ensure!(ordinal != 0, "delay import ordinal must not be zero");
                Ok(OwnedDelayImportTarget::Ordinal(ordinal))
            } else {
                let name_rva =
                    u32::try_from(*value).context("delay hint/name RVA exceeds 32 bits")?;
                let offset = offset_of(base, name_rva, data.len(), "delay hint/name record")?;
                ensure!(
                    offset % 2 == 0,
                    "delay hint/name record is not 2-byte aligned"
                );
                let hint_end = offset
                    .checked_add(2)
                    .context("delay hint/name offset overflow")?;
                ensure!(
                    hint_end <= data.len(),
                    "delay hint/name record is truncated"
                );
                let hint = read_u16(data, offset);
                let name = read_c_string(data, hint_end, "delay-import symbol name")?.to_vec();
                validate_name(&name, "delay-import symbol name")?;
                Ok(OwnedDelayImportTarget::Name { name, hint })
            }
        })
        .collect()
}

fn ensure_strict_targets(targets: &[OwnedDelayImportTarget]) -> Result<()> {
    for pair in targets.windows(2) {
        ensure!(
            compare_owned(&pair[0], &pair[1]) == Ordering::Less
                && !same_owned_target(&pair[0], &pair[1]),
            "delay-import targets are not strictly sorted"
        );
    }
    Ok(())
}

fn same_owned_target(left: &OwnedDelayImportTarget, right: &OwnedDelayImportTarget) -> bool {
    match (left, right) {
        (OwnedDelayImportTarget::Ordinal(left), OwnedDelayImportTarget::Ordinal(right)) => {
            left == right
        }
        (
            OwnedDelayImportTarget::Name { name: left, .. },
            OwnedDelayImportTarget::Name { name: right, .. },
        ) => left == right,
        _ => false,
    }
}

fn compare_owned(left: &OwnedDelayImportTarget, right: &OwnedDelayImportTarget) -> Ordering {
    match (left, right) {
        (OwnedDelayImportTarget::Ordinal(left), OwnedDelayImportTarget::Ordinal(right)) => {
            left.cmp(right)
        }
        (OwnedDelayImportTarget::Ordinal(_), OwnedDelayImportTarget::Name { .. }) => Ordering::Less,
        (OwnedDelayImportTarget::Name { .. }, OwnedDelayImportTarget::Ordinal(_)) => {
            Ordering::Greater
        }
        (
            OwnedDelayImportTarget::Name {
                name: left,
                hint: left_hint,
            },
            OwnedDelayImportTarget::Name {
                name: right,
                hint: right_hint,
            },
        ) => left.cmp(right).then_with(|| left_hint.cmp(right_hint)),
    }
}

fn validate_name(name: &[u8], what: &str) -> Result<()> {
    ensure!(!name.is_empty(), "{what} is empty");
    ensure!(!name.contains(&0), "{what} contains an embedded NUL");
    Ok(())
}

fn read_c_string<'data>(data: &'data [u8], offset: usize, what: &str) -> Result<&'data [u8]> {
    let tail = data
        .get(offset..)
        .with_context(|| format!("{what} offset lies outside metadata"))?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .with_context(|| format!("{what} is not NUL terminated"))?;
    Ok(&tail[..end])
}

fn nonzero(value: u32) -> Option<u32> {
    (value != 0).then_some(value)
}
fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}
fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}
fn read_u64_checked(data: &[u8], offset: usize, what: &str) -> Result<u64> {
    let end = offset.checked_add(8).context("delay thunk end overflow")?;
    ensure!(
        end <= data.len(),
        "{what} is not NUL terminated before the metadata ends"
    );
    Ok(u64::from_le_bytes(data[offset..end].try_into().unwrap()))
}
fn put_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn display_bytes(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> DelayImportLayout {
        DelayImportLayout {
            metadata_rva: 0x3000,
            size_of_image: 0x8000,
        }
    }

    #[test]
    fn deterministic_roundtrip_with_names_ordinals_bound_and_unload() {
        let kernel_imports = [
            DelayImportTarget::Name {
                name: b"Sleep",
                hint: 7,
            },
            DelayImportTarget::Ordinal(12),
        ];
        let user_imports = [DelayImportTarget::Name {
            name: b"MessageBoxW",
            hint: 1,
        }];
        let bound = [0x1800_0010_u64, 0x1800_0020];
        let reverse_kernel_imports = [
            DelayImportTarget::Ordinal(12),
            DelayImportTarget::Name {
                name: b"Sleep",
                hint: 7,
            },
        ];
        let reverse_bound = [0x1800_0020_u64, 0x1800_0010];
        let forward = [
            DelayImportDll {
                name: b"USER32.dll",
                imports: &user_imports,
                timestamp: 0,
                bound_iat: None,
                emit_unload_iat: false,
            },
            DelayImportDll {
                name: b"KERNEL32.dll",
                imports: &kernel_imports,
                timestamp: 42,
                bound_iat: Some(&bound),
                emit_unload_iat: true,
            },
        ];
        let reverse = [
            DelayImportDll {
                name: b"KERNEL32.dll",
                imports: &reverse_kernel_imports,
                timestamp: 42,
                bound_iat: Some(&reverse_bound),
                emit_unload_iat: true,
            },
            forward[0],
        ];
        let first = build_amd64_delay_imports(layout(), &forward).unwrap();
        let second = build_amd64_delay_imports(layout(), &reverse).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.data_directory.rva, 0x3000);
        assert_eq!(first.data_directory.size, 96);
        let parsed =
            parse_amd64_delay_imports(&first.bytes, 0x3000, first.data_directory, 0x8000).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, b"KERNEL32.dll");
        assert_eq!(
            parsed[0].imports,
            vec![
                OwnedDelayImportTarget::Ordinal(12),
                OwnedDelayImportTarget::Name {
                    name: b"Sleep".to_vec(),
                    hint: 7
                }
            ]
        );
        assert_eq!(parsed[0].bound_iat, Some(vec![0x1800_0020, 0x1800_0010]));
        assert!(parsed[0].has_unload_iat);
        assert_eq!(first.helper_thunk_relocations.len(), 3);
        assert_eq!(
            first.helper_thunk_relocations[0].relocations[0].target,
            Amd64DelayThunkRelocationTarget::DelayLoadHelper
        );
        assert_eq!(
            first.helper_thunk_relocations[0].relocations[0].kind,
            Amd64DelayThunkRelocationKind::Rel32
        );
    }

    #[test]
    fn empty_input_has_no_directory() {
        let image = build_amd64_delay_imports(layout(), &[]).unwrap();
        assert!(image.bytes.is_empty());
        assert_eq!(
            image.data_directory,
            DelayImportDataDirectory { rva: 0, size: 0 }
        );
        assert!(
            parse_amd64_delay_imports(&[], 0, image.data_directory, 0)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn rejects_invalid_inputs_and_bounds() {
        let imports = [DelayImportTarget::Ordinal(1)];
        let duplicate = [DelayImportDll {
            name: b"a.dll",
            imports: &imports,
            timestamp: 0,
            bound_iat: None,
            emit_unload_iat: false,
        }; 2];
        assert!(
            build_amd64_delay_imports(layout(), &duplicate)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
        let case_duplicate = [
            DelayImportDll {
                name: b"A.dll",
                imports: &imports,
                timestamp: 0,
                bound_iat: None,
                emit_unload_iat: false,
            },
            DelayImportDll {
                name: b"a.DLL",
                imports: &imports,
                timestamp: 0,
                bound_iat: None,
                emit_unload_iat: false,
            },
        ];
        assert!(build_amd64_delay_imports(layout(), &case_duplicate).is_err());
        let empty = [DelayImportDll {
            name: b"a.dll",
            imports: &[],
            timestamp: 0,
            bound_iat: None,
            emit_unload_iat: false,
        }];
        assert!(build_amd64_delay_imports(layout(), &empty).is_err());
        let bad_name = [DelayImportDll {
            name: b"a\0.dll",
            imports: &imports,
            timestamp: 0,
            bound_iat: None,
            emit_unload_iat: false,
        }];
        assert!(build_amd64_delay_imports(layout(), &bad_name).is_err());
        let ordinal_zero = [DelayImportTarget::Ordinal(0)];
        let bad_ordinal = [DelayImportDll {
            name: b"a.dll",
            imports: &ordinal_zero,
            timestamp: 0,
            bound_iat: None,
            emit_unload_iat: false,
        }];
        assert!(build_amd64_delay_imports(layout(), &bad_ordinal).is_err());
        let timestamp = [DelayImportDll {
            name: b"a.dll",
            imports: &imports,
            timestamp: 1,
            bound_iat: None,
            emit_unload_iat: false,
        }];
        assert!(build_amd64_delay_imports(layout(), &timestamp).is_err());
        assert!(
            build_amd64_delay_imports(
                DelayImportLayout {
                    metadata_rva: 0x3000,
                    size_of_image: 0x3010
                },
                &timestamp
            )
            .is_err()
        );
        assert!(
            build_amd64_delay_imports(
                DelayImportLayout {
                    metadata_rva: 0x3001,
                    size_of_image: 0x8000
                },
                &[DelayImportDll {
                    name: b"a.dll",
                    imports: &imports,
                    timestamp: 0,
                    bound_iat: None,
                    emit_unload_iat: false,
                }]
            )
            .is_err()
        );
    }

    #[test]
    fn parser_rejects_corrupt_descriptors_and_arrays() {
        let imports = [DelayImportTarget::Name {
            name: b"ExitProcess",
            hint: 0,
        }];
        let dlls = [DelayImportDll {
            name: b"kernel32.dll",
            imports: &imports,
            timestamp: 0,
            bound_iat: None,
            emit_unload_iat: true,
        }];
        let image = build_amd64_delay_imports(layout(), &dlls).unwrap();

        let mut bad_attrs = image.bytes.clone();
        put_u32(&mut bad_attrs, 0, 0);
        assert!(
            parse_amd64_delay_imports(&bad_attrs, 0x3000, image.data_directory, 0x8000)
                .unwrap_err()
                .to_string()
                .contains("attributes")
        );

        let mut missing_terminator = image.bytes.clone();
        put_u32(
            &mut missing_terminator,
            IMAGE_DELAY_IMPORT_DESCRIPTOR_SIZE as usize,
            1,
        );
        assert!(
            parse_amd64_delay_imports(&missing_terminator, 0x3000, image.data_directory, 0x8000)
                .is_err()
        );

        let mut wrong_iat = image.bytes.clone();
        let iat_offset = usize::try_from(image.dlls[0].iat_rva - 0x3000).unwrap();
        wrong_iat[iat_offset] ^= 1;
        assert!(
            parse_amd64_delay_imports(&wrong_iat, 0x3000, image.data_directory, 0x8000)
                .unwrap_err()
                .to_string()
                .contains("IAT")
        );

        let mut unterminated = image.bytes.clone();
        let int_offset = usize::try_from(image.dlls[0].int_rva - 0x3000).unwrap();
        for byte in &mut unterminated[int_offset..] {
            *byte = 0xff;
        }
        assert!(
            parse_amd64_delay_imports(&unterminated, 0x3000, image.data_directory, 0x8000).is_err()
        );
    }
}
