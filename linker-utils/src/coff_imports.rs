//! Reading MSVC-style COFF import libraries and short import objects.
//!
//! Import libraries are ordinary archives whose members are either regular
//! COFF objects or the compact `IMPORT_OBJECT_HEADER` representation. This
//! module keeps all strings borrowed because COFF names are byte strings, not
//! necessarily UTF-8.

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use object::Architecture;
use object::FileKind;
use object::Object as _;
use object::pe;
use object::read::archive::ArchiveFile;
use object::read::archive::ArchiveMemberIterator;

const IMPORT_HEADER_SIZE: usize = 20;
const IMPORT_FLAGS_MASK: u16 = 0x1f;

/// The kind of entity imported from a DLL.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ImportType {
    Code,
    Data,
    Const,
}

/// The rule used to derive the name looked up in the DLL.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ImportNameType {
    Ordinal,
    Name,
    NameNoPrefix,
    NameUndecorate,
    ExportAs,
}

/// The DLL lookup encoded by a short import object.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ImportTarget<'data> {
    Ordinal(u16),
    Name { name: &'data [u8], hint: u16 },
}

/// A validated AMD64 short import-object record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShortImportObject<'data> {
    symbol: &'data [u8],
    dll: &'data [u8],
    import_name: Option<&'data [u8]>,
    ordinal_or_hint: u16,
    import_type: ImportType,
    name_type: ImportNameType,
}

impl<'data> ShortImportObject<'data> {
    /// Parses one complete `IMPORT_OBJECT_HEADER` record.
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        ensure!(
            data.len() >= IMPORT_HEADER_SIZE,
            "short import object header is truncated: expected {IMPORT_HEADER_SIZE} bytes, got {}",
            data.len()
        );

        let sig1 = u16_at(data, 0);
        let sig2 = u16_at(data, 2);
        ensure!(
            sig1 == 0 && sig2 == pe::IMPORT_OBJECT_HDR_SIG2,
            "invalid short import object signature: expected 0000/ffff, got {sig1:04x}/{sig2:04x}"
        );
        let version = u16_at(data, 4);
        ensure!(
            version == 0,
            "unsupported short import object version {version}"
        );
        let machine = u16_at(data, 6);
        ensure!(
            machine == pe::IMAGE_FILE_MACHINE_AMD64.0,
            "unsupported short import object machine 0x{machine:04x}; only AMD64 is supported"
        );

        let data_size = usize::try_from(u32_at(data, 12))
            .context("short import object data size does not fit in usize")?;
        let expected_size = IMPORT_HEADER_SIZE
            .checked_add(data_size)
            .context("short import object data size overflows address space")?;
        ensure!(
            data.len() == expected_size,
            "short import object size mismatch: header declares {data_size} data bytes, file has {}",
            data.len() - IMPORT_HEADER_SIZE
        );

        let ordinal_or_hint = u16_at(data, 16);
        let flags = u16_at(data, 18);
        ensure!(
            flags & !IMPORT_FLAGS_MASK == 0,
            "short import object has non-zero reserved flags 0x{:04x}",
            flags & !IMPORT_FLAGS_MASK
        );
        let import_type = match flags & pe::IMPORT_OBJECT_TYPE_MASK {
            value if value == pe::IMPORT_OBJECT_CODE.0 => ImportType::Code,
            value if value == pe::IMPORT_OBJECT_DATA.0 => ImportType::Data,
            value if value == pe::IMPORT_OBJECT_CONST.0 => ImportType::Const,
            value => bail!("unsupported short import object import type {value}"),
        };
        let name_type = match (flags >> pe::IMPORT_OBJECT_NAME_SHIFT) & pe::IMPORT_OBJECT_NAME_MASK
        {
            value if value == pe::IMPORT_OBJECT_ORDINAL.0 => ImportNameType::Ordinal,
            value if value == pe::IMPORT_OBJECT_NAME.0 => ImportNameType::Name,
            value if value == pe::IMPORT_OBJECT_NAME_NO_PREFIX.0 => ImportNameType::NameNoPrefix,
            value if value == pe::IMPORT_OBJECT_NAME_UNDECORATE.0 => ImportNameType::NameUndecorate,
            value if value == pe::IMPORT_OBJECT_NAME_EXPORTAS.0 => ImportNameType::ExportAs,
            value => bail!("unsupported short import object name type {value}"),
        };

        let mut strings = &data[IMPORT_HEADER_SIZE..];
        let symbol = take_c_string(&mut strings, "public symbol")?;
        ensure!(!symbol.is_empty(), "short import object symbol is empty");
        let dll = take_c_string(&mut strings, "DLL name")?;
        ensure!(!dll.is_empty(), "short import object DLL name is empty");
        let import_name = if name_type == ImportNameType::ExportAs {
            let name = take_c_string(&mut strings, "export-as name")?;
            ensure!(
                !name.is_empty(),
                "short import object export-as name is empty"
            );
            Some(name)
        } else {
            None
        };
        ensure!(
            strings.is_empty(),
            "short import object contains {} trailing data bytes",
            strings.len()
        );

        Ok(Self {
            symbol,
            dll,
            import_name,
            ordinal_or_hint,
            import_type,
            name_type,
        })
    }

    #[must_use]
    pub fn symbol(self) -> &'data [u8] {
        self.symbol
    }

    #[must_use]
    pub fn dll(self) -> &'data [u8] {
        self.dll
    }

    #[must_use]
    pub fn ordinal_or_hint(self) -> u16 {
        self.ordinal_or_hint
    }

    #[must_use]
    pub fn import_type(self) -> ImportType {
        self.import_type
    }

    #[must_use]
    pub fn name_type(self) -> ImportNameType {
        self.name_type
    }

    /// Returns the ordinal or the transformed name and hint used in the IAT.
    #[must_use]
    pub fn target(self) -> ImportTarget<'data> {
        match self.name_type {
            ImportNameType::Ordinal => ImportTarget::Ordinal(self.ordinal_or_hint),
            ImportNameType::Name => self.named_target(self.symbol),
            ImportNameType::NameNoPrefix => self.named_target(strip_prefix(self.symbol)),
            ImportNameType::NameUndecorate => {
                let name = strip_prefix(self.symbol);
                let name = name.split(|byte| *byte == b'@').next().unwrap_or(name);
                self.named_target(name)
            }
            ImportNameType::ExportAs => self.named_target(self.import_name.unwrap()),
        }
    }

    fn named_target(self, name: &'data [u8]) -> ImportTarget<'data> {
        ImportTarget::Name {
            name,
            hint: self.ordinal_or_hint,
        }
    }
}

/// A regular AMD64 COFF member in an import library.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoffObjectMember<'data> {
    pub name: &'data [u8],
    pub data: &'data [u8],
    pub is_bigobj: bool,
}

/// A parsed member of an MSVC import library.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportLibraryMember<'data> {
    CoffObject(CoffObjectMember<'data>),
    ShortImport {
        name: &'data [u8],
        import: ShortImportObject<'data>,
    },
}

/// A validated archive containing COFF import-library members.
#[derive(Clone, Copy, Debug)]
pub struct ImportLibrary<'data> {
    data: &'data [u8],
    archive: ArchiveFile<'data>,
}

impl<'data> ImportLibrary<'data> {
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        let archive = ArchiveFile::parse(data).context("invalid COFF import-library archive")?;
        ensure!(
            !archive.is_thin(),
            "thin archives are not supported as COFF import libraries"
        );
        Ok(Self { data, archive })
    }

    #[must_use]
    pub fn members(self) -> ImportLibraryMembers<'data> {
        ImportLibraryMembers {
            data: self.data,
            members: self.archive.members(),
        }
    }
}

/// Iterator over validated import-library members.
pub struct ImportLibraryMembers<'data> {
    data: &'data [u8],
    members: ArchiveMemberIterator<'data>,
}

impl<'data> Iterator for ImportLibraryMembers<'data> {
    type Item = Result<ImportLibraryMember<'data>>;

    fn next(&mut self) -> Option<Self::Item> {
        let member = match self.members.next()? {
            Ok(member) => member,
            Err(error) => return Some(Err(error).context("invalid import-library member header")),
        };
        let name = member.name();
        let data = match member.data(self.data) {
            Ok(data) => data,
            Err(error) => {
                return Some(Err(error).with_context(|| {
                    format!("cannot read import-library member {}", display_bytes(name))
                }));
            }
        };
        Some(
            parse_member(name, data)
                .with_context(|| format!("invalid import-library member {}", display_bytes(name))),
        )
    }
}

fn parse_member<'data>(name: &'data [u8], data: &'data [u8]) -> Result<ImportLibraryMember<'data>> {
    match FileKind::parse(data) {
        Ok(FileKind::CoffImport) => Ok(ImportLibraryMember::ShortImport {
            name,
            import: ShortImportObject::parse(data)?,
        }),
        Ok(kind @ (FileKind::Coff | FileKind::CoffBig)) => {
            let file = object::File::parse(data).context("malformed COFF object")?;
            ensure!(
                file.architecture() == Architecture::X86_64,
                "unsupported COFF object architecture {:?}; only AMD64 is supported",
                file.architecture()
            );
            Ok(ImportLibraryMember::CoffObject(CoffObjectMember {
                name,
                data,
                is_bigobj: kind == FileKind::CoffBig,
            }))
        }
        Ok(kind) => bail!(
            "unsupported member format {kind:?}; expected AMD64 COFF object or short import object"
        ),
        Err(error) => Err(error).context(
            "unrecognized member format; expected AMD64 COFF object or short import object",
        ),
    }
}

fn strip_prefix(name: &[u8]) -> &[u8] {
    match name.split_first() {
        Some((b'?' | b'@' | b'_', rest)) => rest,
        _ => name,
    }
}

fn take_c_string<'data>(data: &mut &'data [u8], description: &str) -> Result<&'data [u8]> {
    let Some(end) = data.iter().position(|byte| *byte == 0) else {
        bail!("short import object {description} is not NUL-terminated");
    };
    let value = &data[..end];
    *data = &data[end + 1..];
    Ok(value)
}

fn display_bytes(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn u16_at(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}

fn u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn short_import(
        symbol: &[u8],
        dll: &[u8],
        extra_name: Option<&[u8]>,
        ordinal_or_hint: u16,
        import_type: pe::ImportObjectType,
        name_type: pe::ImportObjectNameType,
    ) -> Vec<u8> {
        let mut strings = Vec::new();
        strings.extend_from_slice(symbol);
        strings.push(0);
        strings.extend_from_slice(dll);
        strings.push(0);
        if let Some(extra_name) = extra_name {
            strings.extend_from_slice(extra_name);
            strings.push(0);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&pe::IMPORT_OBJECT_HDR_SIG2.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&pe::IMAGE_FILE_MACHINE_AMD64.0.to_le_bytes());
        out.extend_from_slice(&0_u32.to_le_bytes());
        out.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        out.extend_from_slice(&ordinal_or_hint.to_le_bytes());
        out.extend_from_slice(&(import_type.0 | (name_type.0 << 2)).to_le_bytes());
        out.extend_from_slice(&strings);
        out
    }

    fn minimal_coff(machine: u16) -> Vec<u8> {
        let mut out = vec![0; 20];
        out[..2].copy_from_slice(&machine.to_le_bytes());
        out
    }

    fn archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = object::archive::MAGIC.to_vec();
        for (name, data) in members {
            let archive_name = format!("{name}/");
            assert!(archive_name.len() <= 16);
            out.extend_from_slice(
                format!(
                    "{archive_name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                    0,
                    0,
                    0,
                    0,
                    data.len()
                )
                .as_bytes(),
            );
            assert_eq!(out.len() % 2, 0);
            out.extend_from_slice(data);
            if data.len() % 2 != 0 {
                out.push(b'\n');
            }
        }
        out
    }

    #[test]
    fn parses_name_and_ordinal_imports() {
        let named = short_import(
            b"MessageBoxA",
            b"USER32.dll",
            None,
            7,
            pe::IMPORT_OBJECT_CODE,
            pe::IMPORT_OBJECT_NAME,
        );
        let parsed = ShortImportObject::parse(&named).unwrap();
        assert_eq!(parsed.symbol(), b"MessageBoxA");
        assert_eq!(parsed.dll(), b"USER32.dll");
        assert_eq!(parsed.ordinal_or_hint(), 7);
        assert_eq!(parsed.import_type(), ImportType::Code);
        assert_eq!(parsed.name_type(), ImportNameType::Name);
        assert_eq!(
            parsed.target(),
            ImportTarget::Name {
                name: b"MessageBoxA",
                hint: 7
            }
        );

        let ordinal = short_import(
            b"public_name",
            b"ordinal.dll",
            None,
            42,
            pe::IMPORT_OBJECT_DATA,
            pe::IMPORT_OBJECT_ORDINAL,
        );
        let parsed = ShortImportObject::parse(&ordinal).unwrap();
        assert_eq!(parsed.import_type(), ImportType::Data);
        assert_eq!(parsed.target(), ImportTarget::Ordinal(42));
    }

    #[test]
    fn applies_all_name_transformations() {
        for (symbol, export, name_type, expected) in [
            (&b"_plain"[..], None, pe::IMPORT_OBJECT_NAME, &b"_plain"[..]),
            (
                b"_prefixed",
                None,
                pe::IMPORT_OBJECT_NAME_NO_PREFIX,
                b"prefixed",
            ),
            (
                b"?method@8",
                None,
                pe::IMPORT_OBJECT_NAME_UNDECORATE,
                b"method",
            ),
            (
                b"public",
                Some(&b"actual"[..]),
                pe::IMPORT_OBJECT_NAME_EXPORTAS,
                b"actual",
            ),
        ] {
            let bytes = short_import(
                symbol,
                b"a.dll",
                export,
                11,
                pe::IMPORT_OBJECT_CONST,
                name_type,
            );
            let import = ShortImportObject::parse(&bytes).unwrap();
            assert_eq!(import.import_type(), ImportType::Const);
            assert_eq!(
                import.target(),
                ImportTarget::Name {
                    name: expected,
                    hint: 11
                }
            );
        }
    }

    #[test]
    fn iterates_mixed_archive_members() {
        let object = minimal_coff(pe::IMAGE_FILE_MACHINE_AMD64.0);
        let import = short_import(
            b"puts",
            b"ucrtbase.dll",
            None,
            0,
            pe::IMPORT_OBJECT_CODE,
            pe::IMPORT_OBJECT_NAME,
        );
        let bytes = archive(&[("descriptor.obj", &object), ("puts.obj", &import)]);
        let members = ImportLibrary::parse(&bytes)
            .unwrap()
            .members()
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(members.len(), 2);
        assert!(
            matches!(members[0], ImportLibraryMember::CoffObject(member) if member.name == b"descriptor.obj" && !member.is_bigobj)
        );
        assert!(
            matches!(members[1], ImportLibraryMember::ShortImport { name: b"puts.obj", import } if import.dll() == b"ucrtbase.dll")
        );
    }

    #[test]
    fn rejects_truncation_sizes_and_unterminated_strings() {
        let bytes = short_import(
            b"f",
            b"x.dll",
            None,
            0,
            pe::IMPORT_OBJECT_CODE,
            pe::IMPORT_OBJECT_NAME,
        );
        assert!(
            ShortImportObject::parse(&bytes[..19])
                .unwrap_err()
                .to_string()
                .contains("header is truncated")
        );
        assert!(
            ShortImportObject::parse(&bytes[..bytes.len() - 1])
                .unwrap_err()
                .to_string()
                .contains("size mismatch")
        );

        let mut missing_nul = bytes;
        *missing_nul.last_mut().unwrap() = b'x';
        assert!(
            ShortImportObject::parse(&missing_nul)
                .unwrap_err()
                .to_string()
                .contains("DLL name is not NUL-terminated")
        );
    }

    #[test]
    fn rejects_wrong_signature_version_machine_and_flags() {
        let bytes = short_import(
            b"f",
            b"x.dll",
            None,
            0,
            pe::IMPORT_OBJECT_CODE,
            pe::IMPORT_OBJECT_NAME,
        );
        let mut bad = bytes.clone();
        bad[2] = 0;
        assert!(
            ShortImportObject::parse(&bad)
                .unwrap_err()
                .to_string()
                .contains("invalid short import object signature")
        );
        let mut bad = bytes.clone();
        bad[4] = 1;
        assert!(
            ShortImportObject::parse(&bad)
                .unwrap_err()
                .to_string()
                .contains("version 1")
        );
        let mut bad = bytes.clone();
        bad[6..8].copy_from_slice(&pe::IMAGE_FILE_MACHINE_I386.0.to_le_bytes());
        assert!(
            ShortImportObject::parse(&bad)
                .unwrap_err()
                .to_string()
                .contains("only AMD64")
        );
        let mut bad = bytes;
        bad[19] = 0x80;
        assert!(
            ShortImportObject::parse(&bad)
                .unwrap_err()
                .to_string()
                .contains("reserved flags")
        );
    }

    #[test]
    fn rejects_unknown_types_empty_names_and_extra_strings() {
        let mut bad_type = short_import(
            b"f",
            b"x.dll",
            None,
            0,
            pe::IMPORT_OBJECT_CODE,
            pe::IMPORT_OBJECT_NAME,
        );
        bad_type[18] = 3;
        assert!(
            ShortImportObject::parse(&bad_type)
                .unwrap_err()
                .to_string()
                .contains("import type 3")
        );

        let mut bad_name_type = bad_type;
        bad_name_type[18] = 5 << pe::IMPORT_OBJECT_NAME_SHIFT;
        assert!(
            ShortImportObject::parse(&bad_name_type)
                .unwrap_err()
                .to_string()
                .contains("name type 5")
        );

        let empty_symbol = short_import(
            b"",
            b"x.dll",
            None,
            0,
            pe::IMPORT_OBJECT_CODE,
            pe::IMPORT_OBJECT_NAME,
        );
        assert!(
            ShortImportObject::parse(&empty_symbol)
                .unwrap_err()
                .to_string()
                .contains("symbol is empty")
        );

        let extra = short_import(
            b"f",
            b"x.dll",
            Some(b"unexpected"),
            0,
            pe::IMPORT_OBJECT_CODE,
            pe::IMPORT_OBJECT_NAME,
        );
        assert!(
            ShortImportObject::parse(&extra)
                .unwrap_err()
                .to_string()
                .contains("trailing data bytes")
        );
    }

    #[test]
    fn rejects_non_amd64_regular_members_and_malformed_archives() {
        let i386 = minimal_coff(pe::IMAGE_FILE_MACHINE_I386.0);
        let bytes = archive(&[("wrong.obj", &i386)]);
        let error = ImportLibrary::parse(&bytes)
            .unwrap()
            .members()
            .next()
            .unwrap()
            .unwrap_err();
        assert!(format!("{error:#}").contains("only AMD64"));

        let error = ImportLibrary::parse(b"not an archive").unwrap_err();
        assert!(format!("{error:#}").contains("invalid COFF import-library archive"));
    }
}
