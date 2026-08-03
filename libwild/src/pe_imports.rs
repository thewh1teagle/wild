//! Construction of the PE import directory and AMD64 import thunks.

use crate::ensure;
use crate::error::Context;
use crate::error::Result;
use linker_utils::coff_imports::ImportLibrary;
use linker_utils::coff_imports::ImportLibraryMember;
use linker_utils::coff_imports::ImportTarget;
use linker_utils::coff_imports::ImportType;
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

/// Select short import objects that satisfy an undefined symbol.
pub(super) fn select_from_libraries(
    libraries: &[&[u8]],
    undefined: &HashSet<Vec<u8>>,
) -> Result<Vec<Import>> {
    let mut selected = Vec::new();
    let mut selected_symbols = HashSet::new();
    for bytes in libraries {
        // General static COFF archives are handled by the object resolver. Avoid interpreting
        // every regular archive as an import library merely because both use the `ar` container.
        if !bytes.windows(8).any(|window| {
            window
                == [
                    0,
                    0,
                    0xff,
                    0xff,
                    0,
                    0,
                    object::pe::IMAGE_FILE_MACHINE_AMD64.0 as u8,
                    (object::pe::IMAGE_FILE_MACHINE_AMD64.0 >> 8) as u8,
                ]
        }) {
            continue;
        }
        let library = ImportLibrary::parse(bytes)?;
        for member in library.members() {
            let ImportLibraryMember::ShortImport { import, .. } = member? else {
                continue;
            };
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
    }
    selected.sort();
    Ok(selected)
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
