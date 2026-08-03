//! PE/COFF input primitives.
//!
//! This module deliberately starts with the standard COFF reader from `object`. Wild will add its
//! own allocation-friendly representation once the resolution and layout phases consume COFF.

#![allow(dead_code)]

use crate::ensure;
use crate::error::Context;
use crate::error::Result;
use object::Object as _;

/// Marker type for the PE/COFF platform.
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct Pe;

/// A validated x86-64 COFF relocatable object.
#[derive(Debug)]
pub(crate) struct CoffObject<'data> {
    file: object::File<'data>,
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
        Ok(Self { file })
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

    fn bigobj_with_text_symbol() -> Vec<u8> {
        const HEADER_SIZE: usize = 56;
        const SECTION_SIZE: usize = 40;
        const SYMBOL_SIZE: usize = 20;
        const BIGOBJ_CLASS_ID: [u8; 16] = [
            0xc7, 0xa1, 0xba, 0xd1, 0xee, 0xba, 0xa9, 0x4b, 0xaf, 0x20, 0xfa, 0xf6, 0x6a, 0xa4,
            0xdc, 0xb8,
        ];

        let raw_data = HEADER_SIZE + SECTION_SIZE;
        let symbol_table = raw_data + 1;
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
        bytes[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        bytes[raw_data] = 0xc3;

        bytes[symbol_table..symbol_table + 7].copy_from_slice(b"big_sym");
        bytes[symbol_table + 12..symbol_table + 16].copy_from_slice(&1i32.to_le_bytes());
        bytes[symbol_table + 18] = 2; // IMAGE_SYM_CLASS_EXTERNAL
        bytes[symbol_table + SYMBOL_SIZE..].copy_from_slice(&4u32.to_le_bytes());
        bytes
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
