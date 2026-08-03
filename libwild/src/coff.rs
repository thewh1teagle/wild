//! PE/COFF input primitives.
//!
//! This module deliberately starts with the standard COFF reader from `object`. Wild will add its
//! own allocation-friendly representation once the resolution and layout phases consume COFF.

#![allow(dead_code)]

use crate::ensure;
use crate::error::Context;
use crate::error::Result;
use foldhash::HashMap;
use foldhash::HashMapExt;
use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use std::ops::Range;
use std::sync::OnceLock;

/// Marker type for the PE/COFF platform.
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct Pe;

/// A validated x86-64 COFF relocatable object.
#[derive(Debug)]
pub(crate) struct CoffObject<'data> {
    file: object::File<'data>,
    bytes: &'data [u8],
    relocation_index: OnceLock<CoffRelocationIndex>,
}

#[derive(Debug)]
pub(crate) struct CoffRelocationIndex {
    sections: Box<[CoffSectionRecord]>,
    relocations: Box<[CoffRelocationRecord]>,
    symbols: Box<[CoffRelocationSymbolCache]>,
}

#[derive(Debug)]
pub(crate) struct CoffSectionRecord {
    index: object::SectionIndex,
    size: u64,
    align: u64,
    kind: object::SectionKind,
    characteristics: Option<u32>,
    data_range: Option<Range<u64>>,
    relocations: Range<usize>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CoffRelocationRecord {
    offset: u32,
    typ: u16,
    symbol: CoffRelocationSymbolId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CoffRelocationSymbolId(u32);

#[derive(Debug)]
pub(crate) struct CoffRelocationSymbolCache {
    raw_index: object::SymbolIndex,
    shape: OnceLock<CoffRelocationSymbolShape>,
    name: OnceLock<Box<[u8]>>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CoffRelocationSymbolShape {
    pub(crate) section: Option<object::SectionIndex>,
    pub(crate) address: u64,
    pub(crate) is_global: bool,
    pub(crate) is_common: bool,
    pub(crate) is_weak: bool,
}

impl<'data> CoffObject<'data> {
    pub(crate) fn parse(bytes: &'data [u8]) -> Result<Self> {
        let kind = object::FileKind::parse(bytes).context("Invalid x86-64 COFF object")?;
        ensure!(
            matches!(kind, object::FileKind::Coff | object::FileKind::CoffBig),
            "Only standard and bigobj COFF objects are currently supported"
        );
        let file = object::File::parse(bytes).context("Invalid x86-64 COFF object")?;
        ensure!(
            file.architecture() == object::Architecture::X86_64,
            "Unsupported COFF architecture {:?}; only x86-64 COFF is currently supported",
            file.architecture()
        );
        ensure!(
            file.kind() == object::ObjectKind::Relocatable,
            "Only relocatable COFF objects are currently supported"
        );
        Ok(Self {
            file,
            bytes,
            relocation_index: OnceLock::new(),
        })
    }

    pub(crate) fn section_count(&self) -> usize {
        self.file.sections().count()
    }

    pub(crate) fn symbol_count(&self) -> usize {
        self.file.symbols().count()
    }

    pub(crate) fn file(&self) -> &object::File<'data> {
        &self.file
    }

    pub(crate) fn bytes(&self) -> &'data [u8] {
        self.bytes
    }

    pub(crate) fn relocation_index(&self) -> &CoffRelocationIndex {
        self.relocation_index
            .get_or_init(|| CoffRelocationIndex::new(&self.file))
    }

    #[cfg(test)]
    pub(crate) fn relocation_index_initialized(&self) -> bool {
        self.relocation_index.get().is_some()
    }
}

impl CoffRelocationIndex {
    fn new(file: &object::File<'_>) -> Self {
        let mut sections = Vec::with_capacity(file.sections().count());
        let mut relocations = Vec::new();
        let mut symbols = Vec::new();
        let mut symbol_ids = HashMap::<object::SymbolIndex, CoffRelocationSymbolId>::new();
        for section in file.sections() {
            let relocation_start = relocations.len();
            for (offset, relocation) in section.relocations() {
                // Both standard and bigobj COFF readers always expose a raw COFF relocation as a
                // symbol target with COFF flags. CoffObject::parse has already excluded every
                // other format, so retaining these compact raw fields performs no policy or kind
                // validation.
                let object::RelocationTarget::Symbol(raw_index) = relocation.target() else {
                    unreachable!("the object COFF reader always emits symbol relocation targets")
                };
                let object::RelocationFlags::Coff { typ } = relocation.flags() else {
                    unreachable!("the object COFF reader always emits COFF relocation flags")
                };
                let next = CoffRelocationSymbolId(
                    u32::try_from(symbols.len()).expect("COFF symbol count fits in u32"),
                );
                let symbol = *symbol_ids.entry(raw_index).or_insert_with(|| {
                    symbols.push(CoffRelocationSymbolCache {
                        raw_index,
                        shape: OnceLock::new(),
                        name: OnceLock::new(),
                    });
                    next
                });
                relocations.push(CoffRelocationRecord {
                    offset: u32::try_from(offset).expect("COFF relocation offset fits in u32"),
                    typ: typ.0,
                    symbol,
                });
            }
            let data_range = section
                .file_range()
                .map(|(offset, size)| offset..offset + size);
            let characteristics = match section.flags() {
                object::SectionFlags::Coff { characteristics } => Some(characteristics.0),
                _ => None,
            };
            sections.push(CoffSectionRecord {
                index: section.index(),
                size: section.size(),
                align: section.align(),
                kind: section.kind(),
                characteristics,
                data_range,
                relocations: relocation_start..relocations.len(),
            });
        }
        Self {
            sections: sections.into_boxed_slice(),
            relocations: relocations.into_boxed_slice(),
            symbols: symbols.into_boxed_slice(),
        }
    }

    pub(crate) fn sections(&self) -> &[CoffSectionRecord] {
        &self.sections
    }

    pub(crate) fn relocations(&self, section: &CoffSectionRecord) -> &[CoffRelocationRecord] {
        &self.relocations[section.relocations.clone()]
    }

    pub(crate) fn symbol(&self, id: CoffRelocationSymbolId) -> &CoffRelocationSymbolCache {
        &self.symbols[id.0 as usize]
    }
}

impl CoffSectionRecord {
    pub(crate) fn index(&self) -> object::SectionIndex {
        self.index
    }
}

impl CoffRelocationRecord {
    pub(crate) fn symbol(&self) -> CoffRelocationSymbolId {
        self.symbol
    }
}

impl CoffRelocationSymbolCache {
    pub(crate) fn shape<'object>(
        &'object self,
        object: &CoffObject<'_>,
    ) -> Result<&'object CoffRelocationSymbolShape> {
        if self.shape.get().is_none() {
            let symbol = object.file.symbol_by_index(self.raw_index)?;
            let shape = CoffRelocationSymbolShape {
                section: symbol.section_index(),
                address: symbol.address(),
                is_global: symbol.is_global(),
                is_common: symbol.is_common(),
                is_weak: symbol.is_weak(),
            };
            let _ = self.shape.set(shape);
        }
        Ok(self.shape.get().unwrap())
    }

    pub(crate) fn name<'object>(&'object self, object: &CoffObject<'_>) -> Result<&'object [u8]> {
        if self.name.get().is_none() {
            let name = object
                .file
                .symbol_by_index(self.raw_index)?
                .name_bytes()?
                .into();
            let _ = self.name.set(name);
        }
        Ok(self.name.get().unwrap())
    }
}

/// Fast prefix check used before invoking the complete COFF parser.
pub(crate) fn has_amd64_machine(bytes: &[u8]) -> bool {
    const BIGOBJ_PREFIX: [u8; 4] = [0, 0, 0xff, 0xff];

    bytes.starts_with(&crate::coff_x86_64::CoffX86_64::MACHINE.to_le_bytes())
        || (bytes.starts_with(&BIGOBJ_PREFIX)
            && bytes.get(6..8).is_some_and(|machine| {
                machine == crate::coff_x86_64::CoffX86_64::MACHINE.to_le_bytes()
            }))
}

pub(crate) fn validate_x86_64_object(bytes: &[u8]) -> Result {
    CoffObject::parse(bytes).map(|_| ())
}

#[cfg(test)]
pub(crate) fn test_object() -> Vec<u8> {
    use object::write::Object;

    Object::new(
        object::BinaryFormat::Coff,
        object::Architecture::X86_64,
        object::Endianness::Little,
    )
    .write()
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::ObjectSection;
    use object::ObjectSymbol;
    use object::write::Object as WritableObject;
    use object::write::Relocation;
    use object::write::Symbol;
    use object::write::SymbolSection;

    fn bigobj_with_text_symbol() -> Vec<u8> {
        const HEADER_SIZE: usize = 56;
        const SECTION_SIZE: usize = 40;
        const SYMBOL_SIZE: usize = 20;
        const BIGOBJ_CLASS_ID: [u8; 16] = [
            0xc7, 0xa1, 0xba, 0xd1, 0xee, 0xba, 0xa9, 0x4b, 0xaf, 0x20, 0xfa, 0xf6, 0x6a, 0xa4,
            0xdc, 0xb8,
        ];

        let raw_data = HEADER_SIZE + SECTION_SIZE;
        let relocations = raw_data + 1;
        let symbol_table = relocations + 10;
        let mut bytes = vec![0; symbol_table + SYMBOL_SIZE + 4];

        bytes[2..4].copy_from_slice(&0xffffu16.to_le_bytes());
        bytes[4..6].copy_from_slice(&2u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&crate::coff_x86_64::CoffX86_64::MACHINE.to_le_bytes());
        bytes[12..28].copy_from_slice(&BIGOBJ_CLASS_ID);
        bytes[44..48].copy_from_slice(&1u32.to_le_bytes());
        bytes[48..52].copy_from_slice(&(symbol_table as u32).to_le_bytes());
        bytes[52..56].copy_from_slice(&1u32.to_le_bytes());

        let section = HEADER_SIZE;
        bytes[section..section + 5].copy_from_slice(b".text");
        bytes[section + 16..section + 20].copy_from_slice(&1u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&(raw_data as u32).to_le_bytes());
        bytes[section + 24..section + 28].copy_from_slice(&(relocations as u32).to_le_bytes());
        bytes[section + 32..section + 34].copy_from_slice(&1u16.to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        bytes[raw_data] = 0xc3;

        bytes[relocations + 4..relocations + 8].copy_from_slice(&0u32.to_le_bytes());
        bytes[relocations + 8..relocations + 10]
            .copy_from_slice(&object::pe::IMAGE_REL_AMD64_REL32.0.to_le_bytes());

        bytes[symbol_table..symbol_table + 7].copy_from_slice(b"big_sym");
        bytes[symbol_table + 12..symbol_table + 16].copy_from_slice(&1i32.to_le_bytes());
        bytes[symbol_table + 18] = 2; // IMAGE_SYM_CLASS_EXTERNAL
        bytes[symbol_table + SYMBOL_SIZE..].copy_from_slice(&4u32.to_le_bytes());
        bytes
    }

    fn standard_object_with_repeated_relocations() -> Vec<u8> {
        let mut object = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let text = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
        object.append_section_data(text, &[0; 8], 1);
        let target = object.add_symbol(Symbol {
            name: b"target".to_vec(),
            value: 0,
            size: 0,
            kind: object::SymbolKind::Unknown,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Undefined,
            flags: object::SymbolFlags::None,
        });
        for offset in [0, 4] {
            object
                .add_relocation(
                    text,
                    Relocation {
                        offset,
                        symbol: target,
                        addend: 0,
                        flags: object::RelocationFlags::Coff {
                            typ: object::pe::IMAGE_REL_AMD64_REL32,
                        },
                    },
                )
                .unwrap();
        }
        object.write().unwrap()
    }

    fn assert_send_sync<T: Send + Sync>() {}

    fn first_standard_relocation_offset(bytes: &[u8]) -> usize {
        u32::from_le_bytes(bytes[44..48].try_into().unwrap()) as usize
    }

    #[test]
    fn relocation_index_is_stable_ordered_and_interns_symbols() {
        assert_send_sync::<CoffRelocationIndex>();
        assert_eq!(std::mem::size_of::<CoffRelocationRecord>(), 12);
        assert!(std::mem::size_of::<CoffSectionRecord>() <= 80);
        assert!(std::mem::size_of::<CoffRelocationSymbolCache>() <= 96);
        let bytes = standard_object_with_repeated_relocations();
        let object = CoffObject::parse(&bytes).unwrap();
        let index = object.relocation_index();
        assert!(std::ptr::eq(index, object.relocation_index()));
        assert_eq!(index.sections.len(), 1);
        assert_eq!(index.symbols.len(), 1);
        let section = &index.sections[0];
        let raw_section = object.file().section_by_index(section.index).unwrap();
        assert_eq!(section.size, 8);
        assert_eq!(section.align, raw_section.align());
        assert_eq!(section.kind, object::SectionKind::Text);
        assert_eq!(
            section.data_range,
            raw_section.file_range().map(|(o, s)| o..o + s)
        );
        let relocations = index.relocations(section);
        assert_eq!(relocations.len(), 2);
        assert_eq!([relocations[0].offset, relocations[1].offset], [0, 4]);
        assert_eq!(
            [relocations[0].typ, relocations[1].typ],
            [
                object::pe::IMAGE_REL_AMD64_REL32.0,
                object::pe::IMAGE_REL_AMD64_REL32.0,
            ]
        );
        let (first, second) = (relocations[0].symbol, relocations[1].symbol);
        assert_eq!(first, second);
        let symbol = index.symbol(first);
        assert!(symbol.shape.get().is_none());
        assert!(symbol.name.get().is_none());
        assert!(symbol.shape(&object).unwrap().is_global);
        assert!(symbol.name.get().is_none());
        assert_eq!(symbol.name(&object).unwrap(), b"target");
    }

    #[test]
    fn bigobj_uses_the_same_relocation_index() {
        let bytes = bigobj_with_text_symbol();
        let object = CoffObject::parse(&bytes).unwrap();
        let index = object.relocation_index();
        assert_eq!(index.sections.len(), 1);
        let relocations = index.relocations(&index.sections[0]);
        assert_eq!(relocations.len(), 1);
        assert_eq!(relocations[0].offset, 0);
        assert_eq!(relocations[0].typ, object::pe::IMAGE_REL_AMD64_REL32.0);
        let symbol = relocations[0].symbol;
        let shape = index.symbol(symbol).shape(&object).unwrap();
        assert_eq!(shape.section, Some(object::SectionIndex(1)));
        assert_eq!(index.symbol(symbol).name(&object).unwrap(), b"big_sym");
    }

    #[test]
    fn invalid_relocation_symbol_stays_lazy_until_target_resolution() {
        let mut bytes = standard_object_with_repeated_relocations();
        let relocation = first_standard_relocation_offset(&bytes);
        bytes[relocation + 4..relocation + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        let object = CoffObject::parse(&bytes).unwrap();
        let index = object.relocation_index();
        let relocation = &index.relocations(&index.sections[0])[0];
        let symbol = relocation.symbol;
        assert!(index.symbol(symbol).shape.get().is_none());
        assert!(index.symbol(symbol).shape(&object).is_err());
    }

    #[test]
    fn unsupported_relocation_type_is_cached_without_validation() {
        let mut bytes = standard_object_with_repeated_relocations();
        let relocation = first_standard_relocation_offset(&bytes);
        bytes[relocation + 8..relocation + 10].copy_from_slice(&u16::MAX.to_le_bytes());
        let object = CoffObject::parse(&bytes).unwrap();
        let index = object.relocation_index();
        assert_eq!(index.relocations(&index.sections[0])[0].typ, u16::MAX);
    }

    #[test]
    fn parses_object_generated_by_object_crate() {
        let bytes = test_object();
        let object = CoffObject::parse(&bytes).unwrap();
        assert_eq!(object.section_count(), 0);
        assert_eq!(object.symbol_count(), 0);
        assert_eq!(object.file().architecture(), object::Architecture::X86_64);
    }

    #[test]
    fn machine_check_is_cheap_and_exact() {
        assert!(has_amd64_machine(&[0x64, 0x86]));
        assert!(!has_amd64_machine(&[0x4c, 0x01]));
        assert!(!has_amd64_machine(&[0x64]));
    }

    #[test]
    fn parses_amd64_bigobj_with_unified_object_access() {
        let bytes = bigobj_with_text_symbol();
        assert_eq!(
            object::FileKind::parse(bytes.as_slice()).unwrap(),
            object::FileKind::CoffBig
        );
        assert!(has_amd64_machine(&bytes));

        let object = CoffObject::parse(&bytes).unwrap();
        assert_eq!(object.section_count(), 1);
        assert_eq!(object.symbol_count(), 1);
        assert_eq!(
            object
                .file()
                .section_by_name(".text")
                .unwrap()
                .data()
                .unwrap(),
            [0xc3]
        );
        assert_eq!(
            object.file().symbols().next().unwrap().name().unwrap(),
            "big_sym"
        );
    }
}
