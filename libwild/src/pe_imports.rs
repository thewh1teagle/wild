//! Construction of the PE import directory and AMD64 import thunks.

use crate::ensure;
use crate::error::Context;
use crate::error::Result;
#[cfg(test)]
use linker_utils::coff_imports::ImportLibrary;
#[cfg(test)]
use linker_utils::coff_imports::ImportLibraryMember;
use linker_utils::coff_imports::ImportTarget;
use linker_utils::coff_imports::ImportType;
use linker_utils::coff_imports::ShortImportObject;
use linker_utils::pe_delay_imports::DelayImportDll;
use linker_utils::pe_delay_imports::DelayImportLayout;
use linker_utils::pe_delay_imports::DelayImportTarget;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;

const ORDINAL_FLAG64: u64 = 1 << 63;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum OwnedTarget {
    Ordinal(u16),
    Name { name: Vec<u8>, hint: u16 },
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct Import {
    dll: Vec<u8>,
    symbol: Vec<u8>,
    target: OwnedTarget,
    import_type: u8,
    needs_thunk: bool,
}

/// The generated sections and symbol addresses for all selected imports.
#[derive(Debug, Default)]
pub(super) struct EmittedImports {
    pub(super) idata: Vec<u8>,
    pub(super) thunks: Vec<u8>,
    /// Symbol name to RVA. Includes `__imp_foo` and, for code imports, `foo`.
    pub(super) symbols: HashMap<Vec<u8>, u32>,
    pub(super) import_directory: Option<(u32, u32)>,
    pub(super) iat_directory: Option<(u32, u32)>,
}

/// Generated delay-load metadata, IAT entry points, and AMD64 resolver stubs.
#[derive(Debug, Default)]
pub(super) struct EmittedDelayImports {
    pub(super) didat: Vec<u8>,
    pub(super) thunks: Vec<u8>,
    pub(super) symbols: HashMap<Vec<u8>, u32>,
    pub(super) directory: Option<(u32, u32)>,
    /// Absolute-pointer delay-IAT entries, which require DIR64 base relocations.
    pub(super) iat_slots: Vec<u32>,
}

/// Exception metadata for the generated non-leaf delay resolver thunks.
#[derive(Debug, Default)]
pub(super) struct DelayUnwindInfo {
    /// One shareable `UNWIND_INFO` record describing `sub rsp, 0x88`.
    pub(super) xdata: Vec<u8>,
    /// One `RUNTIME_FUNCTION` record per resolver thunk. Public import thunks are leaves.
    pub(super) pdata: Vec<u8>,
}

pub(super) fn partition_delay_imports(
    imports: Vec<Import>,
    delayed_dlls: &[String],
) -> (Vec<Import>, Vec<Import>) {
    let mut eager = Vec::new();
    let mut delayed = Vec::new();
    for import in imports {
        if delayed_dlls
            .iter()
            .any(|dll| import.dll.eq_ignore_ascii_case(dll.as_bytes()))
        {
            delayed.push(import);
        } else {
            eager.push(import);
        }
    }
    (eager, delayed)
}

/// All symbols that the generated import machinery can define for resolution purposes.
pub(super) fn definition_names(imports: &[Import]) -> HashSet<Vec<u8>> {
    let mut definitions = HashSet::new();
    for import in imports {
        let mut imp_symbol = b"__imp_".to_vec();
        imp_symbol.extend_from_slice(&import.symbol);
        definitions.insert(imp_symbol);
        if import.import_type == 0 {
            definitions.insert(import.symbol.clone());
        }
    }
    definitions
}

/// Drop imports that are referenced only by sections removed by `/OPT:REF`.
///
/// Recompute direct-thunk demand at the same time: an `__imp_foo`-only reference needs an IAT
/// slot but not the public `foo` jump thunk.
pub(super) fn retain_referenced(imports: &mut Vec<Import>, references: &HashSet<Vec<u8>>) {
    imports.retain_mut(|import| {
        let mut imp_symbol = b"__imp_".to_vec();
        imp_symbol.extend_from_slice(&import.symbol);
        let direct = import.import_type == 0 && references.contains(&import.symbol);
        let indirect = references.contains(&imp_symbol);
        import.needs_thunk = direct;
        direct || indirect
    });
}

/// Materialize the short-import records already selected by archive resolution.
pub(super) fn select_from_records(
    records: &[ShortImportObject<'_>],
    undefined: &HashSet<Vec<u8>>,
) -> Vec<Import> {
    let mut selected = Vec::new();
    let mut selected_symbols = HashSet::new();
    for &import in records {
        let symbol = import.symbol();
        let mut imp_symbol = b"__imp_".to_vec();
        imp_symbol.extend_from_slice(symbol);
        if !undefined.contains(symbol) && !undefined.contains(&imp_symbol) {
            continue;
        }
        if !selected_symbols.insert(symbol.to_vec()) {
            continue;
        }
        let target = match import.target() {
            ImportTarget::Ordinal(ordinal) => OwnedTarget::Ordinal(ordinal),
            ImportTarget::Name { name, hint } => OwnedTarget::Name {
                name: name.to_vec(),
                hint,
            },
        };
        selected.push(Import {
            dll: import.dll().to_vec(),
            symbol: symbol.to_vec(),
            target,
            import_type: match import.import_type() {
                ImportType::Code => 0,
                ImportType::Data => 1,
                ImportType::Const => 2,
            },
            needs_thunk: undefined.contains(symbol),
        });
    }
    selected.sort();
    selected
}

#[cfg(test)]
fn select_from_libraries(libraries: &[&[u8]], undefined: &HashSet<Vec<u8>>) -> Result<Vec<Import>> {
    let mut records = Vec::new();
    for bytes in libraries {
        let library = ImportLibrary::parse(bytes)?;
        for member in library.members() {
            if let ImportLibraryMember::ShortImport { import, .. } = member? {
                records.push(import);
            }
        }
    }
    Ok(select_from_records(&records, undefined))
}

/// Compute the generated section sizes without requiring their eventual RVAs.
pub(super) fn section_sizes(imports: &[Import]) -> Result<(usize, usize)> {
    let layout = Layout::new(imports)?;
    Ok((layout.idata_size, layout.code_imports * 6))
}

/// Emit `.idata` and jump thunks after section RVAs have been assigned.
pub(super) fn emit(imports: &[Import], idata_rva: u32, thunk_rva: u32) -> Result<EmittedImports> {
    if imports.is_empty() {
        return Ok(EmittedImports::default());
    }
    let layout = Layout::new(imports)?;
    let mut result = EmittedImports {
        idata: vec![0; layout.idata_size],
        thunks: Vec::with_capacity(layout.code_imports * 6),
        symbols: HashMap::new(),
        import_directory: Some((idata_rva, ((layout.groups.len() + 1) * 20) as u32)),
        iat_directory: Some((
            idata_rva
                .checked_add(layout.first_iat as u32)
                .context("PE IAT RVA overflow")?,
            layout.iat_size as u32,
        )),
    };

    let mut thunk_index = 0_u32;
    for (group_index, group) in layout.groups.iter().enumerate() {
        let descriptor = group_index * 20;
        put_u32(&mut result.idata, descriptor, rva(idata_rva, group.ilt)?);
        put_u32(
            &mut result.idata,
            descriptor + 12,
            rva(idata_rva, group.dll_name)?,
        );
        put_u32(
            &mut result.idata,
            descriptor + 16,
            rva(idata_rva, group.iat)?,
        );

        for (index, import_index) in group.imports.iter().copied().enumerate() {
            let import = &imports[import_index];
            let lookup = match import.target {
                OwnedTarget::Ordinal(ordinal) => ORDINAL_FLAG64 | u64::from(ordinal),
                OwnedTarget::Name { .. } => {
                    u64::from(rva(idata_rva, layout.hint_names[import_index])?)
                }
            };
            put_u64(&mut result.idata, group.ilt + index * 8, lookup);
            put_u64(&mut result.idata, group.iat + index * 8, lookup);

            let iat_rva = rva(idata_rva, group.iat + index * 8)?;
            let mut imp_name = b"__imp_".to_vec();
            imp_name.extend_from_slice(&import.symbol);
            insert_symbol(&mut result.symbols, &imp_name, iat_rva)?;

            if import.import_type == 0 && import.needs_thunk {
                let current_rva = thunk_rva
                    .checked_add(thunk_index * 6)
                    .context("PE import thunk RVA overflow")?;
                let displacement = i64::from(iat_rva) - i64::from(current_rva + 6);
                let displacement = i32::try_from(displacement)
                    .context("AMD64 import thunk is too far from the IAT")?;
                result.thunks.extend_from_slice(&[0xff, 0x25]);
                result.thunks.extend_from_slice(&displacement.to_le_bytes());
                insert_symbol(&mut result.symbols, &import.symbol, current_rva)?;
                thunk_index += 1;
            }
        }

        result.idata[group.dll_name..group.dll_name + group.dll.len()].copy_from_slice(&group.dll);
    }

    for (index, import) in imports.iter().enumerate() {
        if let OwnedTarget::Name { ref name, hint } = import.target {
            let at = layout.hint_names[index];
            put_u16(&mut result.idata, at, hint);
            result.idata[at + 2..at + 2 + name.len()].copy_from_slice(name);
        }
    }
    Ok(result)
}

pub(super) fn delay_section_sizes(imports: &[Import]) -> Result<(usize, usize)> {
    if imports.is_empty() {
        return Ok((0, 0));
    }
    let image = build_delay_metadata(imports, 0x1000, u32::MAX)?;
    Ok((image.bytes.len(), delay_thunk_bytes(imports)?))
}

pub(super) fn delay_unwind_sizes(imports: &[Import]) -> Result<(usize, usize)> {
    if imports.is_empty() {
        return Ok((0, 0));
    }
    let pdata = imports
        .len()
        .checked_mul(12)
        .context("delay runtime-function table size overflow")?;
    Ok((pdata, DELAY_UNWIND_INFO.len()))
}

pub(super) fn emit_delay_unwind(
    imports: &[Import],
    thunk_rva: u32,
    unwind_info_rva: u32,
) -> Result<DelayUnwindInfo> {
    if imports.is_empty() {
        return Ok(DelayUnwindInfo::default());
    }
    let public_bytes = imports
        .iter()
        .filter(|import| import.needs_thunk)
        .count()
        .checked_mul(DELAY_PUBLIC_THUNK_SIZE)
        .and_then(|size| u32::try_from(size).ok())
        .context("delay public thunk size exceeds 4 GiB")?;
    let resolver_base = thunk_rva
        .checked_add(public_bytes)
        .context("delay resolver RVA overflow")?;
    let pdata_capacity = imports
        .len()
        .checked_mul(12)
        .context("delay runtime-function table size overflow")?;
    let mut pdata = Vec::with_capacity(pdata_capacity);
    for index in 0..imports.len() {
        let offset = index
            .checked_mul(DELAY_RESOLVER_THUNK_SIZE)
            .and_then(|offset| u32::try_from(offset).ok())
            .context("delay resolver offset exceeds 4 GiB")?;
        let begin = resolver_base
            .checked_add(offset)
            .context("delay resolver begin RVA overflow")?;
        let end = begin
            .checked_add(DELAY_RESOLVER_THUNK_SIZE as u32)
            .context("delay resolver end RVA overflow")?;
        pdata.extend_from_slice(&begin.to_le_bytes());
        pdata.extend_from_slice(&end.to_le_bytes());
        pdata.extend_from_slice(&unwind_info_rva.to_le_bytes());
    }
    Ok(DelayUnwindInfo {
        xdata: DELAY_UNWIND_INFO.to_vec(),
        pdata,
    })
}

/// Emits MSVC-compatible delay metadata, public IAT thunks, and ABI-preserving resolver stubs.
/// `helper_rva` may be zero during the layout/definition pass; call again with the resolved
/// `__delayLoadHelper2` RVA before serializing the final image. The delay IAT initially points at
/// the resolver stubs. Public function symbols always jump through that IAT, so subsequent calls
/// use the target installed by the helper without entering the resolver again.
pub(super) fn emit_delay(
    imports: &[Import],
    didat_rva: u32,
    thunk_rva: u32,
    image_size: u32,
    image_base: u64,
    helper_rva: u32,
) -> Result<EmittedDelayImports> {
    if imports.is_empty() {
        return Ok(EmittedDelayImports::default());
    }
    ensure!(
        imports.iter().all(|import| import.import_type == 0),
        "delay-loading imported data is not supported"
    );
    let metadata = build_delay_metadata(imports, didat_rva, image_size)?;
    let public_thunk_count = imports.iter().filter(|import| import.needs_thunk).count();
    let public_thunk_bytes = public_thunk_count
        .checked_mul(DELAY_PUBLIC_THUNK_SIZE)
        .context("delay public thunk size overflow")?;
    let resolver_base_rva = thunk_rva
        .checked_add(u32::try_from(public_thunk_bytes).context("delay public thunks exceed 4 GiB")?)
        .context("delay resolver thunk RVA overflow")?;
    let mut result = EmittedDelayImports {
        didat: metadata.bytes,
        thunks: Vec::with_capacity(delay_thunk_bytes(imports)?),
        symbols: HashMap::new(),
        directory: Some((metadata.data_directory.rva, metadata.data_directory.size)),
        iat_slots: Vec::new(),
    };
    let mut placements = HashMap::new();
    for dll in &metadata.dlls {
        for placement in &dll.imports {
            placements.insert(
                (dll.name.clone(), placement.target.clone()),
                (dll.descriptor_rva, placement.iat_slot_rva),
            );
        }
    }
    let mut public_index = 0_u32;
    for import in imports {
        if !import.needs_thunk {
            continue;
        }
        let target = delay_target_owned(import);
        let (_, iat_rva) = placements
            .get(&(import.dll.clone(), target))
            .copied()
            .context("missing delay-import placement")?;
        let public_rva = thunk_rva
            .checked_add(
                public_index
                    .checked_mul(DELAY_PUBLIC_THUNK_SIZE as u32)
                    .context("delay public thunk offset overflow")?,
            )
            .context("delay public thunk RVA overflow")?;
        emit_delay_public_thunk(&mut result.thunks, public_rva, iat_rva)?;
        insert_symbol(&mut result.symbols, &import.symbol, public_rva)?;
        public_index += 1;
    }
    ensure!(
        result.thunks.len() == public_thunk_bytes,
        "invalid delay public thunk region size"
    );
    for (index, import) in imports.iter().enumerate() {
        let target = delay_target_owned(import);
        let (descriptor_rva, iat_rva) = placements
            .get(&(import.dll.clone(), target))
            .copied()
            .context("missing delay-import placement")?;
        let resolver_rva = resolver_base_rva
            .checked_add(
                u32::try_from(
                    index
                        .checked_mul(DELAY_RESOLVER_THUNK_SIZE)
                        .context("delay resolver thunk offset overflow")?,
                )
                .context("delay resolver thunk offset exceeds 4 GiB")?,
            )
            .context("delay resolver thunk RVA overflow")?;
        emit_delay_resolver_thunk(
            &mut result.thunks,
            resolver_rva,
            descriptor_rva,
            iat_rva,
            helper_rva,
        )?;
        let iat_offset = usize::try_from(
            iat_rva
                .checked_sub(didat_rva)
                .context("delay IAT precedes metadata")?,
        )
        .context("delay IAT offset exceeds usize")?;
        let resolver_va = image_base
            .checked_add(u64::from(resolver_rva))
            .context("delay resolver thunk VA overflow")?;
        result.didat[iat_offset..iat_offset + 8].copy_from_slice(&resolver_va.to_le_bytes());
        result.iat_slots.push(iat_rva);
        let mut imp_name = b"__imp_".to_vec();
        imp_name.extend_from_slice(&import.symbol);
        insert_symbol(&mut result.symbols, &imp_name, iat_rva)?;
    }
    ensure!(
        result.thunks.len() == delay_thunk_bytes(imports)?,
        "invalid delay thunk region size"
    );
    Ok(result)
}

const DELAY_PUBLIC_THUNK_SIZE: usize = 6;
const DELAY_RESOLVER_THUNK_SIZE: usize = 127;
// Version 1, seven-byte prologue, two unwind-code slots, no frame register.
// UWOP_ALLOC_LARGE(info=0) at prologue offset 7 consumes the second slot, whose value is
// 0x88 / 8 = 17. All generated resolver thunks have this exact prologue.
const DELAY_UNWIND_INFO: [u8; 8] = [1, 7, 2, 0, 7, 1, 17, 0];

fn delay_thunk_bytes(imports: &[Import]) -> Result<usize> {
    let public = imports
        .iter()
        .filter(|import| import.needs_thunk)
        .count()
        .checked_mul(DELAY_PUBLIC_THUNK_SIZE)
        .context("delay public thunk size overflow")?;
    let resolvers = imports
        .len()
        .checked_mul(DELAY_RESOLVER_THUNK_SIZE)
        .context("delay resolver thunk size overflow")?;
    public
        .checked_add(resolvers)
        .context("delay thunk size overflow")
}

fn emit_delay_public_thunk(output: &mut Vec<u8>, thunk_rva: u32, iat_rva: u32) -> Result<()> {
    let start = output.len();
    // jmp qword ptr [rip + delay-IAT slot]
    output.extend_from_slice(&[0xff, 0x25]);
    emit_rel32(output, start, thunk_rva, iat_rva, "delay IAT")?;
    ensure!(
        output.len() - start == DELAY_PUBLIC_THUNK_SIZE,
        "invalid delay public thunk size"
    );
    Ok(())
}

fn emit_delay_resolver_thunk(
    output: &mut Vec<u8>,
    thunk_rva: u32,
    descriptor_rva: u32,
    iat_rva: u32,
    helper_rva: u32,
) -> Result<()> {
    let start = output.len();
    // At a Win64 function entry RSP is 8 mod 16. Reserve 32 bytes of helper shadow space, slots
    // for RCX/RDX/R8/R9 and XMM0-3, plus eight bytes to align RSP before the helper call.
    output.extend_from_slice(&[0x48, 0x81, 0xec, 0x88, 0x00, 0x00, 0x00]); // sub rsp, 0x88
    output.extend_from_slice(&[0x48, 0x89, 0x4c, 0x24, 0x20]); // mov [rsp+0x20], rcx
    output.extend_from_slice(&[0x48, 0x89, 0x54, 0x24, 0x28]); // mov [rsp+0x28], rdx
    output.extend_from_slice(&[0x4c, 0x89, 0x44, 0x24, 0x30]); // mov [rsp+0x30], r8
    output.extend_from_slice(&[0x4c, 0x89, 0x4c, 0x24, 0x38]); // mov [rsp+0x38], r9
    output.extend_from_slice(&[0xf3, 0x0f, 0x7f, 0x44, 0x24, 0x40]); // movdqu [rsp+0x40], xmm0
    output.extend_from_slice(&[0xf3, 0x0f, 0x7f, 0x4c, 0x24, 0x50]); // movdqu [rsp+0x50], xmm1
    output.extend_from_slice(&[0xf3, 0x0f, 0x7f, 0x54, 0x24, 0x60]); // movdqu [rsp+0x60], xmm2
    output.extend_from_slice(&[0xf3, 0x0f, 0x7f, 0x5c, 0x24, 0x70]); // movdqu [rsp+0x70], xmm3

    output.extend_from_slice(&[0x48, 0x8d, 0x0d]); // lea rcx, [rip + descriptor]
    emit_rel32(output, start, thunk_rva, descriptor_rva, "delay descriptor")?;
    output.extend_from_slice(&[0x48, 0x8d, 0x15]); // lea rdx, [rip + delay-IAT slot]
    emit_rel32(output, start, thunk_rva, iat_rva, "delay IAT")?;
    output.push(0xe8); // call __delayLoadHelper2
    emit_rel32(output, start, thunk_rva, helper_rva, "delay helper")?;
    output.extend_from_slice(&[0x49, 0x89, 0xc3]); // mov r11, rax

    output.extend_from_slice(&[0xf3, 0x0f, 0x6f, 0x44, 0x24, 0x40]); // movdqu xmm0, [rsp+0x40]
    output.extend_from_slice(&[0xf3, 0x0f, 0x6f, 0x4c, 0x24, 0x50]); // movdqu xmm1, [rsp+0x50]
    output.extend_from_slice(&[0xf3, 0x0f, 0x6f, 0x54, 0x24, 0x60]); // movdqu xmm2, [rsp+0x60]
    output.extend_from_slice(&[0xf3, 0x0f, 0x6f, 0x5c, 0x24, 0x70]); // movdqu xmm3, [rsp+0x70]
    output.extend_from_slice(&[0x48, 0x8b, 0x4c, 0x24, 0x20]); // mov rcx, [rsp+0x20]
    output.extend_from_slice(&[0x48, 0x8b, 0x54, 0x24, 0x28]); // mov rdx, [rsp+0x28]
    output.extend_from_slice(&[0x4c, 0x8b, 0x44, 0x24, 0x30]); // mov r8, [rsp+0x30]
    output.extend_from_slice(&[0x4c, 0x8b, 0x4c, 0x24, 0x38]); // mov r9, [rsp+0x38]
    output.extend_from_slice(&[0x48, 0x81, 0xc4, 0x88, 0x00, 0x00, 0x00]); // add rsp, 0x88
    output.extend_from_slice(&[0x41, 0xff, 0xe3]); // jmp r11
    ensure!(
        output.len() - start == DELAY_RESOLVER_THUNK_SIZE,
        "invalid delay resolver thunk size"
    );
    Ok(())
}

fn emit_rel32(
    output: &mut Vec<u8>,
    thunk_start: usize,
    thunk_rva: u32,
    target_rva: u32,
    target_name: &str,
) -> Result<()> {
    let field_end = output
        .len()
        .checked_sub(thunk_start)
        .and_then(|offset| offset.checked_add(4))
        .context("delay thunk offset overflow")?;
    let next_rva = thunk_rva
        .checked_add(u32::try_from(field_end).context("delay thunk offset exceeds 4 GiB")?)
        .context("delay thunk address overflow")?;
    let displacement = i32::try_from(i64::from(target_rva) - i64::from(next_rva))
        .with_context(|| format!("{target_name} is too far from its delay thunk"))?;
    output.extend_from_slice(&displacement.to_le_bytes());
    Ok(())
}

fn build_delay_metadata(
    imports: &[Import],
    metadata_rva: u32,
    size_of_image: u32,
) -> Result<linker_utils::pe_delay_imports::DelayImportImage> {
    let mut groups: BTreeMap<Vec<u8>, Vec<DelayImportTarget<'_>>> = BTreeMap::new();
    for import in imports {
        groups
            .entry(import.dll.clone())
            .or_default()
            .push(delay_target(import));
    }
    let dlls = groups
        .iter()
        .map(|(name, imports)| DelayImportDll {
            name,
            imports,
            timestamp: 0,
            bound_iat: None,
            emit_unload_iat: false,
        })
        .collect::<Vec<_>>();
    linker_utils::pe_delay_imports::build_amd64_delay_imports(
        DelayImportLayout {
            metadata_rva,
            size_of_image,
        },
        &dlls,
    )
    .map_err(Into::into)
}

fn delay_target(import: &Import) -> DelayImportTarget<'_> {
    match import.target {
        OwnedTarget::Ordinal(ordinal) => DelayImportTarget::Ordinal(ordinal),
        OwnedTarget::Name { ref name, hint } => DelayImportTarget::Name { name, hint },
    }
}

fn delay_target_owned(import: &Import) -> linker_utils::pe_delay_imports::OwnedDelayImportTarget {
    match delay_target(import) {
        DelayImportTarget::Ordinal(ordinal) => {
            linker_utils::pe_delay_imports::OwnedDelayImportTarget::Ordinal(ordinal)
        }
        DelayImportTarget::Name { name, hint } => {
            linker_utils::pe_delay_imports::OwnedDelayImportTarget::Name {
                name: name.to_vec(),
                hint,
            }
        }
    }
}

fn insert_symbol(symbols: &mut HashMap<Vec<u8>, u32>, name: &[u8], rva: u32) -> Result {
    if let Some(previous) = symbols.insert(name.to_owned(), rva) {
        ensure!(
            previous == rva,
            "conflicting import definition for `{}`",
            String::from_utf8_lossy(name)
        );
    }
    Ok(())
}

#[derive(Debug)]
struct Group {
    dll: Vec<u8>,
    imports: Vec<usize>,
    ilt: usize,
    iat: usize,
    dll_name: usize,
}

#[derive(Debug)]
struct Layout {
    groups: Vec<Group>,
    hint_names: Vec<usize>,
    first_iat: usize,
    iat_size: usize,
    idata_size: usize,
    code_imports: usize,
}

impl Layout {
    fn new(imports: &[Import]) -> Result<Self> {
        let mut by_dll: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
        for (index, import) in imports.iter().enumerate() {
            by_dll.entry(import.dll.clone()).or_default().push(index);
        }
        let mut cursor = (by_dll.len() + 1)
            .checked_mul(20)
            .context("PE import descriptor size overflow")?;
        let mut groups = Vec::new();
        for (dll, import_indices) in by_dll {
            let bytes = (import_indices.len() + 1)
                .checked_mul(8)
                .context("PE import lookup table size overflow")?;
            let ilt = cursor;
            cursor = cursor
                .checked_add(bytes)
                .context("PE import size overflow")?;
            groups.push(Group {
                dll,
                imports: import_indices,
                ilt,
                iat: 0,
                dll_name: 0,
            });
        }
        let first_iat = cursor;
        for group in &mut groups {
            group.iat = cursor;
            cursor = cursor
                .checked_add((group.imports.len() + 1) * 8)
                .context("PE IAT size overflow")?;
        }
        let iat_size = cursor - first_iat;
        let mut hint_names = vec![0; imports.len()];
        for (index, import) in imports.iter().enumerate() {
            if let OwnedTarget::Name { ref name, .. } = import.target {
                cursor = align(cursor, 2)?;
                hint_names[index] = cursor;
                cursor = cursor
                    .checked_add(2 + name.len() + 1)
                    .context("PE import name size overflow")?;
            }
        }
        for group in &mut groups {
            group.dll_name = cursor;
            cursor = cursor
                .checked_add(group.dll.len() + 1)
                .context("PE DLL name size overflow")?;
        }
        ensure!(
            u32::try_from(cursor).is_ok(),
            "PE import section is too large"
        );
        Ok(Self {
            groups,
            hint_names,
            first_iat,
            iat_size,
            idata_size: cursor,
            code_imports: imports
                .iter()
                .filter(|import| import.import_type == 0 && import.needs_thunk)
                .count(),
        })
    }
}

fn align(value: usize, alignment: usize) -> Result<usize> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .context("PE import size overflow")
}

fn rva(section_rva: u32, offset: usize) -> Result<u32> {
    section_rva
        .checked_add(u32::try_from(offset).context("PE import offset overflow")?)
        .context("PE import RVA overflow")
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_valid_named_import_and_amd64_thunk() {
        let imports = vec![Import {
            dll: b"KERNEL32.dll".to_vec(),
            symbol: b"ExitProcess".to_vec(),
            target: OwnedTarget::Name {
                name: b"ExitProcess".to_vec(),
                hint: 9,
            },
            import_type: 0,
            needs_thunk: true,
        }];
        let emitted = emit(&imports, 0x2000, 0x1000).unwrap();
        assert_eq!(emitted.import_directory, Some((0x2000, 40)));
        assert_eq!(emitted.symbols[b"__imp_ExitProcess".as_slice()], 0x2038);
        assert_eq!(emitted.symbols[b"ExitProcess".as_slice()], 0x1000);
        assert_eq!(&emitted.thunks[..2], &[0xff, 0x25]);
        assert_eq!(
            i32::from_le_bytes(emitted.thunks[2..6].try_into().unwrap()),
            0x2038 - 0x1006
        );
        assert_eq!(
            u32::from_le_bytes(emitted.idata[..4].try_into().unwrap()),
            0x2028
        );
        assert_eq!(
            u32::from_le_bytes(emitted.idata[16..20].try_into().unwrap()),
            0x2038
        );
        assert_eq!(
            u16::from_le_bytes(emitted.idata[72..74].try_into().unwrap()),
            9
        );
        assert_eq!(&emitted.idata[74..85], b"ExitProcess");
    }

    #[test]
    fn partitions_and_emits_delay_loaded_code_imports() {
        let imports = vec![Import {
            dll: b"KERNEL32.dll".to_vec(),
            symbol: b"Sleep".to_vec(),
            target: OwnedTarget::Name {
                name: b"Sleep".to_vec(),
                hint: 0,
            },
            import_type: 0,
            needs_thunk: true,
        }];
        let (eager, delayed) = partition_delay_imports(imports, &["kernel32.DLL".into()]);
        assert!(eager.is_empty());
        assert_eq!(delayed.len(), 1);
        let emitted = emit_delay(&delayed, 0x3000, 0x1000, 0x8000, 0x140000000, 0x1100).unwrap();
        assert_eq!(emitted.directory, Some((0x3000, 64)));
        assert_eq!(emitted.symbols[b"__imp_Sleep".as_slice()], 0x3068);
        assert_eq!(emitted.symbols[b"Sleep".as_slice()], 0x1000);
        assert_eq!(emitted.thunks.len(), 6 + 127);
        assert_eq!(&emitted.thunks[..2], &[0xff, 0x25]);
        assert_eq!(
            i32::from_le_bytes(emitted.thunks[2..6].try_into().unwrap()),
            0x3068 - 0x1006,
            "the public function thunk jumps through the delay IAT"
        );

        let resolver = &emitted.thunks[6..];
        assert_eq!(&resolver[..7], &[0x48, 0x81, 0xec, 0x88, 0, 0, 0]);
        assert_eq!(
            &resolver[7..27],
            &[
                0x48, 0x89, 0x4c, 0x24, 0x20, // save rcx
                0x48, 0x89, 0x54, 0x24, 0x28, // save rdx
                0x4c, 0x89, 0x44, 0x24, 0x30, // save r8
                0x4c, 0x89, 0x4c, 0x24, 0x38, // save r9
            ]
        );
        assert_eq!(&resolver[27..33], &[0xf3, 0x0f, 0x7f, 0x44, 0x24, 0x40]);
        assert_eq!(&resolver[73..79], &[0xf3, 0x0f, 0x6f, 0x44, 0x24, 0x40]);
        assert_eq!(&resolver[117..124], &[0x48, 0x81, 0xc4, 0x88, 0, 0, 0]);
        assert_eq!(&resolver[124..], &[0x41, 0xff, 0xe3]);
        assert_eq!(
            i32::from_le_bytes(resolver[54..58].try_into().unwrap()),
            0x3000 - (0x1006 + 58),
            "resolver loads its delay descriptor"
        );
        assert_eq!(
            i32::from_le_bytes(resolver[61..65].try_into().unwrap()),
            0x3068 - (0x1006 + 65),
            "resolver passes the address of its delay-IAT slot"
        );
        assert_eq!(
            i32::from_le_bytes(resolver[66..70].try_into().unwrap()),
            0x1100 - (0x1006 + 70),
            "resolver calls __delayLoadHelper2"
        );
        assert_eq!(emitted.iat_slots, [0x3068]);
        assert_eq!(
            u64::from_le_bytes(emitted.didat[0x68..0x70].try_into().unwrap()),
            0x140001006,
            "the initial delay-IAT target is the resolver, not the public thunk"
        );

        let unwind = emit_delay_unwind(&delayed, 0x1000, 0x4000).unwrap();
        assert_eq!(delay_unwind_sizes(&delayed).unwrap(), (12, 8));
        assert_eq!(unwind.xdata, [1, 7, 2, 0, 7, 1, 17, 0]);
        let table = linker_utils::pe_unwind::build_amd64_exception_table(
            &unwind.pdata,
            0x5000,
            &unwind.xdata,
            0x4000,
            0x8000,
        )
        .unwrap();
        assert_eq!(
            table.functions,
            [linker_utils::pe_unwind::RuntimeFunction {
                begin_rva: 0x1006,
                end_rva: 0x1085,
                unwind_info_rva: 0x4000,
            }]
        );

        let mut malformed = unwind.xdata;
        malformed[4] = 8;
        assert!(
            linker_utils::pe_unwind::build_amd64_exception_table(
                &unwind.pdata,
                0x5000,
                &malformed,
                0x4000,
                0x8000,
            )
            .is_err()
        );
    }

    #[test]
    fn delay_imp_only_reference_uses_a_resolver_without_a_public_thunk() {
        let imports = [Import {
            dll: b"KERNEL32.dll".to_vec(),
            symbol: b"Sleep".to_vec(),
            target: OwnedTarget::Name {
                name: b"Sleep".to_vec(),
                hint: 0,
            },
            import_type: 0,
            needs_thunk: false,
        }];

        assert_eq!(delay_section_sizes(&imports).unwrap().1, 127);
        let emitted = emit_delay(&imports, 0x3000, 0x1000, 0x8000, 0x140000000, 0x1100).unwrap();

        assert_eq!(emitted.thunks.len(), 127);
        assert!(!emitted.symbols.contains_key(b"Sleep".as_slice()));
        assert_eq!(emitted.symbols[b"__imp_Sleep".as_slice()], 0x3068);
        assert_eq!(
            u64::from_le_bytes(emitted.didat[0x68..0x70].try_into().unwrap()),
            0x140001000
        );
    }

    #[test]
    fn missing_delay_imports_have_no_exception_metadata() {
        assert_eq!(delay_unwind_sizes(&[]).unwrap(), (0, 0));
        let unwind = emit_delay_unwind(&[], 0, 0).unwrap();
        assert!(unwind.pdata.is_empty());
        assert!(unwind.xdata.is_empty());
    }

    #[test]
    fn selects_only_referenced_short_imports() {
        let exit = short_import(b"ExitProcess", b"KERNEL32.dll");
        let sleep = short_import(b"Sleep", b"KERNEL32.dll");
        let archive = archive(&[("exit.obj", &exit), ("sleep.obj", &sleep)]);
        let undefined = HashSet::from([b"__imp_ExitProcess".to_vec()]);
        let imports = select_from_libraries(&[&archive], &undefined).unwrap();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].symbol, b"ExitProcess");
        assert!(!imports[0].needs_thunk);
        assert_eq!(section_sizes(&imports).unwrap().1, 0);
    }

    #[test]
    fn selected_records_keep_first_duplicate_and_sort_output() {
        let first = short_import(b"Zulu", b"FIRST.dll");
        let duplicate = short_import(b"Zulu", b"SECOND.dll");
        let alpha = short_import(b"Alpha", b"FIRST.dll");
        let records =
            [&first, &duplicate, &alpha].map(|bytes| ShortImportObject::parse(bytes).unwrap());
        let undefined = HashSet::from([b"Zulu".to_vec(), b"Alpha".to_vec()]);

        let imports = select_from_records(&records, &undefined);

        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].symbol, b"Alpha");
        assert_eq!(imports[1].symbol, b"Zulu");
        assert_eq!(imports[1].dll, b"FIRST.dll");
    }

    #[test]
    fn selected_records_preserve_ordinal_and_delay_partition() {
        let mut ordinal = short_import(b"OrdinalApi", b"DELAY.dll");
        ordinal[16..18].copy_from_slice(&7u16.to_le_bytes());
        ordinal[18..20].copy_from_slice(
            &(object::pe::IMPORT_OBJECT_CODE.0
                | (object::pe::IMPORT_OBJECT_ORDINAL.0 << object::pe::IMPORT_OBJECT_NAME_SHIFT))
                .to_le_bytes(),
        );
        let eager = short_import(b"NamedApi", b"EAGER.dll");
        let records = [&ordinal, &eager].map(|bytes| ShortImportObject::parse(bytes).unwrap());
        let undefined = HashSet::from([b"OrdinalApi".to_vec(), b"NamedApi".to_vec()]);

        let imports = select_from_records(&records, &undefined);
        let (eager, delayed) = partition_delay_imports(imports, &["delay.DLL".into()]);

        assert_eq!(eager.len(), 1);
        assert_eq!(eager[0].symbol, b"NamedApi");
        assert_eq!(delayed.len(), 1);
        assert_eq!(delayed[0].symbol, b"OrdinalApi");
        assert_eq!(delayed[0].target, OwnedTarget::Ordinal(7));
    }

    #[test]
    fn opt_ref_prunes_dead_imports_and_recomputes_thunk_demand() {
        let mut imports = vec![
            Import {
                dll: b"KERNEL32.dll".to_vec(),
                symbol: b"ExitProcess".to_vec(),
                target: OwnedTarget::Name {
                    name: b"ExitProcess".to_vec(),
                    hint: 0,
                },
                import_type: 0,
                needs_thunk: true,
            },
            Import {
                dll: b"KERNEL32.dll".to_vec(),
                symbol: b"Sleep".to_vec(),
                target: OwnedTarget::Name {
                    name: b"Sleep".to_vec(),
                    hint: 0,
                },
                import_type: 0,
                needs_thunk: true,
            },
        ];
        let references = HashSet::from([b"__imp_ExitProcess".to_vec()]);

        retain_referenced(&mut imports, &references);

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].symbol, b"ExitProcess");
        assert!(!imports[0].needs_thunk);
        assert_eq!(definition_names(&imports).len(), 2);
    }

    fn short_import(symbol: &[u8], dll: &[u8]) -> Vec<u8> {
        let size = symbol.len() + 1 + dll.len() + 1;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&object::pe::IMPORT_OBJECT_HDR_SIG2.to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&object::pe::IMAGE_FILE_MACHINE_AMD64.0.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&(size as u32).to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(
            &(object::pe::IMPORT_OBJECT_CODE.0
                | (object::pe::IMPORT_OBJECT_NAME.0 << object::pe::IMPORT_OBJECT_NAME_SHIFT))
                .to_le_bytes(),
        );
        bytes.extend_from_slice(symbol);
        bytes.push(0);
        bytes.extend_from_slice(dll);
        bytes.push(0);
        bytes
    }

    fn archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut bytes = object::archive::MAGIC.to_vec();
        for (name, data) in members {
            let name = format!("{name}/");
            bytes.extend_from_slice(
                format!(
                    "{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                    0,
                    0,
                    0,
                    0,
                    data.len()
                )
                .as_bytes(),
            );
            bytes.extend_from_slice(data);
            if data.len() % 2 != 0 {
                bytes.push(b'\n');
            }
        }
        bytes
    }
}
