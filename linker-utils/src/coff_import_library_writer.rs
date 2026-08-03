//! Deterministic AMD64 COFF import-library construction.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use object::pe;

const ARCHIVE_MAGIC: &[u8] = b"!<arch>\n";
const ARCHIVE_HEADER_SIZE: usize = 60;

/// Import representation requested by references to an exported symbol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportLibrarySymbolType {
    Code,
    Data,
    Const,
}

/// One public symbol represented in an import library.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportLibraryExport<'data> {
    /// Symbol made available to the static linker.
    pub symbol: &'data [u8],
    /// Name looked up in the DLL. It may differ from `symbol` for an alias.
    pub export_name: &'data [u8],
    pub ordinal: u16,
    pub noname: bool,
    pub symbol_type: ImportLibrarySymbolType,
}

struct Member {
    name: Vec<u8>,
    data: Vec<u8>,
    symbols: Vec<Vec<u8>>,
}

/// Builds an MSVC-style archive containing AMD64 short import objects.
///
/// Both linker members are emitted. All timestamps and ownership fields are
/// zero, member order is bytewise by public symbol, and archive symbol indexes
/// contain both the direct and `__imp_` spellings.
pub fn build_amd64_import_library(
    dll_name: &[u8],
    exports: &[ImportLibraryExport<'_>],
) -> Result<Vec<u8>> {
    validate_string(dll_name, "DLL name")?;
    ensure!(
        !exports.is_empty(),
        "an import library requires at least one export"
    );
    ensure!(
        u16::try_from(exports.len()).is_ok(),
        "too many import-library members"
    );

    let mut sorted = exports.to_vec();
    sorted.sort_by(|left, right| left.symbol.cmp(right.symbol));
    let mut public_symbols = BTreeSet::new();
    for export in &sorted {
        validate_string(export.symbol, "import symbol")?;
        validate_string(export.export_name, "DLL export name")?;
        ensure!(
            export.ordinal != 0,
            "import symbol {:?} uses reserved ordinal zero",
            display(export.symbol)
        );
        ensure!(
            public_symbols.insert(export.symbol),
            "duplicate import symbol {:?}",
            display(export.symbol)
        );
    }

    let named_order = sorted
        .iter()
        .filter(|export| !export.noname)
        .map(|export| export.export_name)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .enumerate()
        .map(|(hint, name)| {
            Ok((
                name,
                u16::try_from(hint).context("import hint exceeds u16")?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;

    let mut indexed_names = BTreeSet::<Vec<u8>>::new();
    let mut members = Vec::with_capacity(sorted.len());
    for (index, export) in sorted.iter().enumerate() {
        let imported = prefixed(b"__imp_", export.symbol)?;
        ensure!(
            indexed_names.insert(export.symbol.to_vec()),
            "duplicate archive symbol"
        );
        ensure!(
            indexed_names.insert(imported.clone()),
            "archive symbol collision for {:?}",
            display(export.symbol)
        );
        let ordinal_or_hint = if export.noname {
            export.ordinal
        } else {
            named_order[export.export_name]
        };
        let data = short_import_object(dll_name, export, ordinal_or_hint)?;
        members.push(Member {
            name: format!("e{index:05}.obj/").into_bytes(),
            data,
            symbols: vec![export.symbol.to_vec(), imported],
        });
    }

    build_archive(&members)
}

fn short_import_object(
    dll_name: &[u8],
    export: &ImportLibraryExport<'_>,
    ordinal_or_hint: u16,
) -> Result<Vec<u8>> {
    let import_type = match export.symbol_type {
        ImportLibrarySymbolType::Code => pe::IMPORT_OBJECT_CODE.0,
        ImportLibrarySymbolType::Data => pe::IMPORT_OBJECT_DATA.0,
        ImportLibrarySymbolType::Const => pe::IMPORT_OBJECT_CONST.0,
    };
    let name_type = if export.noname {
        pe::IMPORT_OBJECT_ORDINAL.0
    } else if export.symbol == export.export_name {
        pe::IMPORT_OBJECT_NAME.0
    } else {
        pe::IMPORT_OBJECT_NAME_EXPORTAS.0
    };
    let mut payload = Vec::new();
    append_c_string(&mut payload, export.symbol);
    append_c_string(&mut payload, dll_name);
    if name_type == pe::IMPORT_OBJECT_NAME_EXPORTAS.0 {
        append_c_string(&mut payload, export.export_name);
    }
    let payload_size =
        u32::try_from(payload.len()).context("short import object payload exceeds u32")?;

    let mut bytes = Vec::with_capacity(20 + payload.len());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&pe::IMPORT_OBJECT_HDR_SIG2.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&pe::IMAGE_FILE_MACHINE_AMD64.0.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&payload_size.to_le_bytes());
    bytes.extend_from_slice(&ordinal_or_hint.to_le_bytes());
    bytes.extend_from_slice(
        &(import_type | (name_type << pe::IMPORT_OBJECT_NAME_SHIFT)).to_le_bytes(),
    );
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn build_archive(members: &[Member]) -> Result<Vec<u8>> {
    let mut index = Vec::<(Vec<u8>, usize)>::new();
    for (member_index, member) in members.iter().enumerate() {
        for symbol in &member.symbols {
            index.push((symbol.clone(), member_index));
        }
    }
    index.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    let names_size = index.iter().try_fold(0usize, |size, (name, _)| {
        size.checked_add(name.len() + 1)
            .context("archive symbol table size overflow")
    })?;
    let first_size = 4usize
        .checked_add(
            index
                .len()
                .checked_mul(4)
                .context("first linker member size overflow")?,
        )
        .and_then(|size| size.checked_add(names_size))
        .context("first linker member size overflow")?;
    let second_size = 4usize
        .checked_add(
            members
                .len()
                .checked_mul(4)
                .context("second linker member size overflow")?,
        )
        .and_then(|size| size.checked_add(4))
        .and_then(|size| size.checked_add(index.len().checked_mul(2)?))
        .and_then(|size| size.checked_add(names_size))
        .context("second linker member size overflow")?;

    let members_start = ARCHIVE_MAGIC
        .len()
        .checked_add(record_size(first_size)?)
        .and_then(|size| size.checked_add(record_size(second_size).ok()?))
        .context("archive header size overflow")?;
    let mut member_offsets = Vec::with_capacity(members.len());
    let mut offset = members_start;
    for member in members {
        member_offsets.push(u32::try_from(offset).context("archive member offset exceeds u32")?);
        offset = offset
            .checked_add(record_size(member.data.len())?)
            .context("archive size overflow")?;
    }

    let symbol_count = u32::try_from(index.len()).context("archive symbol count exceeds u32")?;
    let mut first = Vec::with_capacity(first_size);
    first.extend_from_slice(&symbol_count.to_be_bytes());
    for (_, member_index) in &index {
        first.extend_from_slice(&member_offsets[*member_index].to_be_bytes());
    }
    append_index_names(&mut first, &index);

    let mut second = Vec::with_capacity(second_size);
    second.extend_from_slice(
        &u32::try_from(members.len())
            .context("archive member count exceeds u32")?
            .to_le_bytes(),
    );
    for offset in &member_offsets {
        second.extend_from_slice(&offset.to_le_bytes());
    }
    second.extend_from_slice(&symbol_count.to_le_bytes());
    for (_, member_index) in &index {
        second.extend_from_slice(
            &u16::try_from(member_index + 1)
                .context("archive member index exceeds u16")?
                .to_le_bytes(),
        );
    }
    append_index_names(&mut second, &index);

    let mut archive = Vec::with_capacity(offset);
    archive.extend_from_slice(ARCHIVE_MAGIC);
    push_record(&mut archive, b"/", &first)?;
    push_record(&mut archive, b"/", &second)?;
    for member in members {
        push_record(&mut archive, &member.name, &member.data)?;
    }
    Ok(archive)
}

fn append_index_names(output: &mut Vec<u8>, index: &[(Vec<u8>, usize)]) {
    for (name, _) in index {
        append_c_string(output, name);
    }
}

fn record_size(data_size: usize) -> Result<usize> {
    ARCHIVE_HEADER_SIZE
        .checked_add(data_size)
        .and_then(|size| size.checked_add(data_size & 1))
        .context("archive record size overflow")
}

fn push_record(output: &mut Vec<u8>, name: &[u8], data: &[u8]) -> Result<()> {
    ensure!(name.len() <= 16, "archive member name is too long");
    let mut header = [b' '; ARCHIVE_HEADER_SIZE];
    header[..name.len()].copy_from_slice(name);
    let size = data.len().to_string();
    ensure!(
        size.len() <= 10,
        "archive member exceeds decimal size field"
    );
    header[48..48 + size.len()].copy_from_slice(size.as_bytes());
    header[58..60].copy_from_slice(b"`\n");
    output.extend_from_slice(&header);
    output.extend_from_slice(data);
    if data.len() & 1 != 0 {
        output.push(b'\n');
    }
    Ok(())
}

fn prefixed(prefix: &[u8], suffix: &[u8]) -> Result<Vec<u8>> {
    let capacity = prefix
        .len()
        .checked_add(suffix.len())
        .context("import symbol length overflow")?;
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(prefix);
    output.extend_from_slice(suffix);
    Ok(output)
}

fn append_c_string(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(value);
    output.push(0);
}

fn validate_string(value: &[u8], description: &str) -> Result<()> {
    ensure!(!value.is_empty(), "{description} must not be empty");
    ensure!(
        !value.contains(&0),
        "{description} contains an embedded NUL byte"
    );
    Ok(())
}

fn display(value: &[u8]) -> String {
    String::from_utf8_lossy(value).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coff_imports::{
        ImportLibrary, ImportLibraryMember, ImportNameType, ImportTarget, ImportType,
    };

    #[test]
    fn round_trips_named_ordinal_alias_and_data_imports() {
        let archive = build_amd64_import_library(
            b"sample.dll",
            &[
                ImportLibraryExport {
                    symbol: b"Zulu",
                    export_name: b"Zulu",
                    ordinal: 9,
                    noname: false,
                    symbol_type: ImportLibrarySymbolType::Data,
                },
                ImportLibraryExport {
                    symbol: b"OrdinalOnly",
                    export_name: b"OrdinalOnly",
                    ordinal: 7,
                    noname: true,
                    symbol_type: ImportLibrarySymbolType::Code,
                },
                ImportLibraryExport {
                    symbol: b"Alias",
                    export_name: b"RealName",
                    ordinal: 3,
                    noname: false,
                    symbol_type: ImportLibrarySymbolType::Const,
                },
            ],
        )
        .unwrap();

        let imports = ImportLibrary::parse(&archive)
            .unwrap()
            .members()
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(imports.len(), 3);
        let mut parsed = BTreeMap::new();
        for member in imports {
            let ImportLibraryMember::ShortImport { import, .. } = member else {
                panic!("unexpected regular object")
            };
            parsed.insert(import.symbol().to_vec(), import);
        }
        assert_eq!(
            parsed[b"OrdinalOnly".as_slice()].target(),
            ImportTarget::Ordinal(7)
        );
        assert_eq!(parsed[b"Zulu".as_slice()].import_type(), ImportType::Data);
        assert_eq!(parsed[b"Zulu".as_slice()].name_type(), ImportNameType::Name);
        assert_eq!(
            parsed[b"Zulu".as_slice()].target(),
            ImportTarget::Name {
                name: b"Zulu",
                hint: 1
            }
        );
        assert_eq!(parsed[b"Alias".as_slice()].import_type(), ImportType::Const);
        assert_eq!(
            parsed[b"Alias".as_slice()].name_type(),
            ImportNameType::ExportAs
        );
        assert_eq!(
            parsed[b"Alias".as_slice()].target(),
            ImportTarget::Name {
                name: b"RealName",
                hint: 0
            }
        );
    }

    #[test]
    fn output_is_deterministic_and_rejects_collisions() {
        let a = ImportLibraryExport {
            symbol: b"a",
            export_name: b"a",
            ordinal: 1,
            noname: false,
            symbol_type: ImportLibrarySymbolType::Code,
        };
        let b = ImportLibraryExport {
            symbol: b"b",
            export_name: b"b",
            ordinal: 2,
            noname: false,
            symbol_type: ImportLibrarySymbolType::Code,
        };
        assert_eq!(
            build_amd64_import_library(b"x.dll", &[a, b]).unwrap(),
            build_amd64_import_library(b"x.dll", &[b, a]).unwrap()
        );
        assert!(build_amd64_import_library(b"x.dll", &[a, a]).is_err());
        let collision = ImportLibraryExport {
            symbol: b"__imp_a",
            export_name: b"__imp_a",
            ordinal: 2,
            noname: false,
            symbol_type: ImportLibrarySymbolType::Code,
        };
        assert!(build_amd64_import_library(b"x.dll", &[a, collision]).is_err());
    }
}
