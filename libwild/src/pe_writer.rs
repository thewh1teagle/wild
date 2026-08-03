//! Shared PE32+ writer configuration.
//!
//! Output construction is intentionally introduced separately from COFF input parsing. The next
//! vertical slice can build a minimal image around this validated configuration without baking
//! alignment policy into the generic layout code.

#![allow(dead_code)]

use crate::ensure;
use crate::error;
use crate::error::Context;
use crate::error::Result;
use crate::fs::{FileReplacementMode, FileSystem, InputFileData, OutputFileData, OutputOptions};
use object::{Object, ObjectSection, ObjectSymbol, RelocationKind, RelocationTarget, SectionFlags};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeWriterConfig {
    pub(crate) image_base: u64,
    pub(crate) section_alignment: u32,
    pub(crate) file_alignment: u32,
}

impl Default for PeWriterConfig {
    fn default() -> Self {
        Self {
            image_base: crate::coff_x86_64::CoffX86_64::IMAGE_BASE,
            section_alignment: 0x1000,
            file_alignment: 0x200,
        }
    }
}

impl PeWriterConfig {
    pub(crate) fn validate(self) -> Result<Self> {
        ensure!(
            self.image_base.is_multiple_of(0x1_0000),
            "PE image base must be 64 KiB aligned"
        );
        ensure!(
            self.section_alignment.is_power_of_two(),
            "PE section alignment must be a power of two"
        );
        ensure!(
            self.file_alignment.is_power_of_two()
                && (0x200..=0x1_0000).contains(&self.file_alignment),
            "PE file alignment must be a power of two between 512 B and 64 KiB"
        );
        ensure!(
            self.section_alignment >= self.file_alignment,
            "PE section alignment must not be smaller than file alignment"
        );
        Ok(self)
    }
}

#[derive(Debug)]
struct InputSection {
    object: usize,
    index: object::SectionIndex,
    name: [u8; 8],
    data: Vec<u8>,
    virtual_size: u32,
    characteristics: u32,
    rva: u32,
    file_offset: u32,
}

/// Link the deliberately small first PE/COFF vertical slice.
///
/// Keeping this path separate from the ELF-oriented generic layout makes the constraints explicit
/// while the COFF resolver grows. Archives, COMDAT selection and imports are rejected rather than
/// silently producing a corrupt image.
pub(crate) fn link<F: FileSystem>(
    fs: &F,
    args: &crate::args::coff::CoffArgs,
) -> Result<crate::LinkerOutput<'static>> {
    ensure!(
        !args.is_dll,
        "DLL output is not supported by the minimal PE writer yet"
    );
    let entry_name = args
        .entry
        .as_deref()
        .ok_or_else(|| error!("PE output currently requires /ENTRY:<symbol>"))?;
    ensure!(!args.common.inputs.is_empty(), "no COFF input files");

    let mut inputs = Vec::new();
    for input in &args.common.inputs {
        let path = match &input.spec {
            crate::args::InputSpec::File(path) => path.as_ref(),
            _ => {
                return Err(error!(
                    "library search inputs are not supported by the minimal PE writer"
                ));
            }
        };
        let (data, _) = fs
            .open_input(path, args.common.prepopulate_maps)
            .with_context(|| format!("Failed to open COFF input `{}`", path.display()))?;
        inputs.push((path.to_path_buf(), data));
    }

    let objects = inputs
        .iter()
        .map(|(path, data)| {
            crate::coff::CoffObject::parse(data.bytes())
                .with_context(|| format!("while reading `{}`", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    let config = PeWriterConfig::default().validate()?;
    let image = build_image(&objects, entry_name, args, config)?;

    let mut output = fs.create_output(
        args.common.output.clone(),
        OutputOptions {
            size: image.len() as u64,
            file_replacement_mode: args
                .common
                .file_replacement_mode
                .unwrap_or(FileReplacementMode::UnlinkAndReplace),
            write_mode: args.common.file_write_mode,
        },
    )?;
    output.bytes_mut().copy_from_slice(&image);
    output.finish()?;
    Ok(crate::LinkerOutput { layout: None })
}

fn build_image(
    objects: &[crate::coff::CoffObject<'_>],
    entry_name: &str,
    args: &crate::args::coff::CoffArgs,
    config: PeWriterConfig,
) -> Result<Vec<u8>> {
    let mut sections = Vec::new();
    for (object_index, input) in objects.iter().enumerate() {
        for section in input.file().sections() {
            let characteristics = match section.flags() {
                SectionFlags::Coff { characteristics } => characteristics.0,
                _ => 0,
            };
            if characteristics & object::pe::IMAGE_SCN_LNK_REMOVE.0 != 0
                || characteristics
                    & (object::pe::IMAGE_SCN_CNT_CODE
                        | object::pe::IMAGE_SCN_CNT_INITIALIZED_DATA
                        | object::pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA)
                        .0
                    == 0
            {
                continue;
            }
            let source_name = section.name_bytes().context("invalid COFF section name")?;
            let mut name = [0; 8];
            let base_name = source_name
                .split(|byte| *byte == b'$')
                .next()
                .unwrap_or(source_name);
            ensure!(
                base_name.len() <= name.len(),
                "PE section name `{}` is longer than 8 bytes",
                String::from_utf8_lossy(base_name)
            );
            name[..base_name.len()].copy_from_slice(base_name);
            let data = section
                .data()
                .context("invalid COFF section contents")?
                .to_vec();
            let virtual_size =
                u32::try_from(section.size()).context("COFF section is too large")?;
            if virtual_size == 0 && data.is_empty() {
                continue;
            }
            sections.push(InputSection {
                object: object_index,
                index: section.index(),
                name,
                data,
                virtual_size,
                characteristics: output_characteristics(characteristics),
                rva: 0,
                file_offset: 0,
            });
        }
    }
    ensure!(
        !sections.is_empty(),
        "COFF inputs contain no allocatable sections"
    );
    ensure!(
        u16::try_from(sections.len()).is_ok(),
        "too many PE sections"
    );

    let headers_size = align_up(
        0x80 + 4 + 20 + 240 + sections.len() as u32 * 40,
        config.file_alignment,
    )?;
    let mut next_rva = config.section_alignment;
    let mut next_file = headers_size;
    for section in &mut sections {
        section.rva = next_rva;
        section.file_offset = next_file;
        next_rva = align_up(
            next_rva
                .checked_add(section.virtual_size.max(section.data.len() as u32))
                .context("PE image is too large")?,
            config.section_alignment,
        )?;
        if !section.data.is_empty() {
            next_file = align_up(
                next_file
                    .checked_add(section.data.len() as u32)
                    .context("PE file is too large")?,
                config.file_alignment,
            )?;
        }
    }
    let size_of_image = next_rva;

    let section_locations: HashMap<_, _> = sections
        .iter()
        .enumerate()
        .map(|(i, section)| ((section.object, section.index), i))
        .collect();
    let mut definitions: HashMap<Vec<u8>, u64> = HashMap::new();
    for (object_index, input) in objects.iter().enumerate() {
        for symbol in input.file().symbols() {
            let Some(section_index) = symbol.section_index() else {
                continue;
            };
            let Some(&output_index) = section_locations.get(&(object_index, section_index)) else {
                continue;
            };
            let address =
                config.image_base + u64::from(sections[output_index].rva) + symbol.address();
            let name = symbol.name_bytes().context("invalid COFF symbol name")?;
            if symbol.is_global()
                && let Some(old) = definitions.insert(name.to_vec(), address)
            {
                ensure!(
                    old == address,
                    "duplicate symbol `{}`",
                    String::from_utf8_lossy(name)
                );
            }
        }
    }

    let entry_va = definitions
        .get(entry_name.as_bytes())
        .copied()
        .or_else(|| {
            find_local_symbol(
                objects,
                &sections,
                &section_locations,
                entry_name.as_bytes(),
                config.image_base,
            )
            .ok()
            .flatten()
        })
        .ok_or_else(|| error!("entry symbol `{entry_name}` is undefined"))?;
    let entry_rva = u32::try_from(entry_va - config.image_base)
        .context("entry point lies outside the image")?;

    apply_relocations(
        objects,
        &mut sections,
        &section_locations,
        &definitions,
        config.image_base,
    )?;
    let mut image = vec![0; next_file as usize];
    write_headers(
        &mut image,
        &sections,
        args,
        config,
        headers_size,
        size_of_image,
        entry_rva,
    );
    for section in &sections {
        if !section.data.is_empty() {
            let start = section.file_offset as usize;
            image[start..start + section.data.len()].copy_from_slice(&section.data);
        }
    }
    Ok(image)
}

fn find_local_symbol(
    objects: &[crate::coff::CoffObject<'_>],
    sections: &[InputSection],
    locations: &HashMap<(usize, object::SectionIndex), usize>,
    name: &[u8],
    image_base: u64,
) -> Result<Option<u64>> {
    for (object_index, input) in objects.iter().enumerate() {
        for symbol in input.file().symbols() {
            if symbol.name_bytes()? != name {
                continue;
            }
            if let Some(section_index) = symbol.section_index()
                && let Some(&output_index) = locations.get(&(object_index, section_index))
            {
                return Ok(Some(
                    image_base + u64::from(sections[output_index].rva) + symbol.address(),
                ));
            }
        }
    }
    Ok(None)
}

fn apply_relocations(
    objects: &[crate::coff::CoffObject<'_>],
    sections: &mut [InputSection],
    locations: &HashMap<(usize, object::SectionIndex), usize>,
    definitions: &HashMap<Vec<u8>, u64>,
    image_base: u64,
) -> Result {
    for (object_index, input) in objects.iter().enumerate() {
        for source in input.file().sections() {
            let Some(&output_index) = locations.get(&(object_index, source.index())) else {
                continue;
            };
            for (offset, relocation) in source.relocations() {
                let target = match relocation.target() {
                    RelocationTarget::Symbol(index) => {
                        let symbol = input
                            .file()
                            .symbol_by_index(index)
                            .context("invalid relocation symbol")?;
                        if let Some(section_index) = symbol.section_index() {
                            let &target_index = locations
                                .get(&(object_index, section_index))
                                .ok_or_else(|| error!("relocation targets a discarded section"))?;
                            image_base + u64::from(sections[target_index].rva) + symbol.address()
                        } else {
                            let name = symbol.name_bytes()?;
                            *definitions.get(name).ok_or_else(|| {
                                error!("undefined symbol `{}`", String::from_utf8_lossy(name))
                            })?
                        }
                    }
                    RelocationTarget::Section(index) => {
                        let &target_index = locations
                            .get(&(object_index, index))
                            .ok_or_else(|| error!("relocation targets a discarded section"))?;
                        image_base + u64::from(sections[target_index].rva)
                    }
                    _ => return Err(error!("unsupported absolute COFF relocation target")),
                };
                let place = image_base + u64::from(sections[output_index].rva) + offset;
                let kind = relocation.kind();
                let value = match kind {
                    RelocationKind::Relative | RelocationKind::PltRelative => {
                        i128::from(target) + i128::from(relocation.addend()) - i128::from(place)
                    }
                    RelocationKind::Absolute => {
                        i128::from(target) + i128::from(relocation.addend())
                    }
                    RelocationKind::ImageOffset => {
                        i128::from(target) + i128::from(relocation.addend())
                            - i128::from(image_base)
                    }
                    kind => return Err(error!("unsupported AMD64 COFF relocation {kind:?}")),
                };
                let size = relocation.size();
                let start = usize::try_from(offset).context("relocation offset is too large")?;
                let data = &mut sections[output_index].data;
                match size {
                    32 => {
                        ensure!(
                            start + 4 <= data.len(),
                            "relocation extends past section data"
                        );
                        if matches!(kind, RelocationKind::Relative | RelocationKind::PltRelative) {
                            let value = i32::try_from(value)
                                .context("32-bit relative relocation overflow")?;
                            data[start..start + 4].copy_from_slice(&value.to_le_bytes());
                        } else {
                            let value =
                                u32::try_from(value).context("32-bit relocation overflow")?;
                            data[start..start + 4].copy_from_slice(&value.to_le_bytes());
                        }
                    }
                    64 => {
                        ensure!(
                            start + 8 <= data.len(),
                            "relocation extends past section data"
                        );
                        let value = u64::try_from(value).context("64-bit relocation overflow")?;
                        data[start..start + 8].copy_from_slice(&value.to_le_bytes());
                    }
                    _ => return Err(error!("unsupported {size}-bit AMD64 COFF relocation")),
                }
            }
        }
    }
    Ok(())
}

fn output_characteristics(input: u32) -> u32 {
    let content = input
        & (object::pe::IMAGE_SCN_CNT_CODE
            | object::pe::IMAGE_SCN_CNT_INITIALIZED_DATA
            | object::pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA)
            .0;
    let memory = input
        & (object::pe::IMAGE_SCN_MEM_EXECUTE
            | object::pe::IMAGE_SCN_MEM_READ
            | object::pe::IMAGE_SCN_MEM_WRITE)
            .0;
    content | memory
}

fn write_headers(
    image: &mut [u8],
    sections: &[InputSection],
    args: &crate::args::coff::CoffArgs,
    config: PeWriterConfig,
    headers_size: u32,
    image_size: u32,
    entry_rva: u32,
) {
    image[..2].copy_from_slice(b"MZ");
    put_u32(image, 0x3c, 0x80);
    image[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    put_u16(image, coff, crate::coff_x86_64::CoffX86_64::MACHINE);
    put_u16(image, coff + 2, sections.len() as u16);
    put_u16(image, coff + 16, 240);
    put_u16(
        image,
        coff + 18,
        (object::pe::IMAGE_FILE_EXECUTABLE_IMAGE
            | object::pe::IMAGE_FILE_LARGE_ADDRESS_AWARE
            | object::pe::IMAGE_FILE_RELOCS_STRIPPED)
            .0,
    );
    let opt = coff + 20;
    put_u16(image, opt, 0x20b);
    image[opt + 2] = 0;
    let code_size: u32 = sections
        .iter()
        .filter(|s| s.characteristics & object::pe::IMAGE_SCN_CNT_CODE.0 != 0)
        .map(|s| align_plain(s.data.len() as u32, config.file_alignment))
        .sum();
    let data_size: u32 = sections
        .iter()
        .filter(|s| s.characteristics & object::pe::IMAGE_SCN_CNT_INITIALIZED_DATA.0 != 0)
        .map(|s| align_plain(s.data.len() as u32, config.file_alignment))
        .sum();
    let bss_size: u32 = sections
        .iter()
        .filter(|s| s.characteristics & object::pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA.0 != 0)
        .map(|s| s.virtual_size)
        .sum();
    put_u32(image, opt + 4, code_size);
    put_u32(image, opt + 8, data_size);
    put_u32(image, opt + 12, bss_size);
    put_u32(image, opt + 16, entry_rva);
    put_u32(
        image,
        opt + 20,
        sections
            .iter()
            .find(|s| s.characteristics & object::pe::IMAGE_SCN_CNT_CODE.0 != 0)
            .map_or(0, |s| s.rva),
    );
    put_u64(image, opt + 24, config.image_base);
    put_u32(image, opt + 32, config.section_alignment);
    put_u32(image, opt + 36, config.file_alignment);
    put_u16(image, opt + 40, 6);
    put_u16(
        image,
        opt + 48,
        args.subsystem
            .as_ref()
            .and_then(|s| s.version)
            .map_or(6, |v| v.0),
    );
    put_u16(
        image,
        opt + 50,
        args.subsystem
            .as_ref()
            .and_then(|s| s.version)
            .map_or(0, |v| v.1),
    );
    put_u32(image, opt + 56, image_size);
    put_u32(image, opt + 60, headers_size);
    put_u16(image, opt + 68, subsystem_value(args));
    put_u16(
        image,
        opt + 70,
        object::pe::IMAGE_DLLCHARACTERISTICS_NX_COMPAT.0,
    );
    put_u64(image, opt + 72, 0x10_0000);
    put_u64(image, opt + 80, 0x1000);
    put_u64(image, opt + 88, 0x10_0000);
    put_u64(image, opt + 96, 0x1000);
    put_u32(image, opt + 108, 16);
    let table = opt + 240;
    for (index, section) in sections.iter().enumerate() {
        let at = table + index * 40;
        image[at..at + 8].copy_from_slice(&section.name);
        put_u32(image, at + 8, section.virtual_size);
        put_u32(image, at + 12, section.rva);
        put_u32(
            image,
            at + 16,
            if section.data.is_empty() {
                0
            } else {
                align_plain(section.data.len() as u32, config.file_alignment)
            },
        );
        put_u32(
            image,
            at + 20,
            if section.data.is_empty() {
                0
            } else {
                section.file_offset
            },
        );
        put_u32(image, at + 36, section.characteristics);
    }
}

fn subsystem_value(args: &crate::args::coff::CoffArgs) -> u16 {
    use crate::args::coff::Subsystem;
    match args.subsystem.as_ref().map(|s| &s.kind) {
        Some(Subsystem::Windows) => 2,
        Some(Subsystem::Native) => 1,
        Some(Subsystem::Posix) => 7,
        Some(Subsystem::EfiApplication) => 10,
        Some(Subsystem::EfiBootServiceDriver) => 11,
        Some(Subsystem::EfiRuntimeDriver) => 12,
        Some(Subsystem::EfiRom) => 13,
        Some(Subsystem::Console) | None => 3,
    }
}

fn align_up(value: u32, alignment: u32) -> Result<u32> {
    value
        .checked_add(alignment - 1)
        .map(|v| v & !(alignment - 1))
        .context("PE size overflow")
}
fn align_plain(value: u32, alignment: u32) -> u32 {
    (value + alignment - 1) & !(alignment - 1)
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

    fn minimal_object() -> Vec<u8> {
        use object::write::{Object, Symbol, SymbolSection};
        let mut object = Object::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let text = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
        object.append_section_data(text, &[0xb8, 42, 0, 0, 0, 0xc3], 1);
        object.add_symbol(Symbol {
            name: b"entry".to_vec(),
            value: 0,
            size: 6,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(text),
            flags: object::SymbolFlags::None,
        });
        object.write().unwrap()
    }

    #[test]
    fn default_configuration_is_valid() {
        assert_eq!(
            PeWriterConfig::default().validate().unwrap(),
            PeWriterConfig::default()
        );
    }

    #[test]
    fn rejects_invalid_alignment() {
        let config = PeWriterConfig {
            file_alignment: 3,
            ..PeWriterConfig::default()
        };
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("file alignment")
        );
    }

    #[test]
    fn emits_deterministic_parseable_pe32_plus() {
        let input = minimal_object();
        let object = crate::coff::CoffObject::parse(&input).unwrap();
        let args = crate::args::coff::CoffArgs {
            entry: Some("entry".into()),
            ..Default::default()
        };
        let first = build_image(&[object], "entry", &args, PeWriterConfig::default()).unwrap();

        let object = crate::coff::CoffObject::parse(&input).unwrap();
        let second = build_image(&[object], "entry", &args, PeWriterConfig::default()).unwrap();
        assert_eq!(first, second);
        assert_eq!(&first[..2], b"MZ");
        assert_eq!(&first[0x80..0x84], b"PE\0\0");
        assert_eq!(u32::from_le_bytes(first[0x88..0x8c].try_into().unwrap()), 0);
        assert_eq!(
            u16::from_le_bytes(first[0x98..0x9a].try_into().unwrap()),
            0x20b
        );

        let parsed = object::File::parse(first.as_slice()).unwrap();
        assert_eq!(parsed.format(), object::BinaryFormat::Pe);
        assert_eq!(parsed.architecture(), object::Architecture::X86_64);
        assert_eq!(parsed.kind(), object::ObjectKind::Executable);
        let text = parsed.section_by_name(".text").unwrap();
        assert_eq!(text.address(), 0x1_4000_1000);
        assert_eq!(&text.data().unwrap()[..6], &[0xb8, 42, 0, 0, 0, 0xc3]);
    }
}
