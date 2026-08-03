//! PE/COFF input primitives.
//!
//! This module deliberately starts with the standard COFF reader from `object`. Wild will add its
//! own allocation-friendly representation once the resolution and layout phases consume COFF.

#![allow(dead_code)]

use crate::ensure;
use crate::error::Context;
use crate::error::Result;
use object::Object as _;
use object::read::coff::CoffFile;

/// Marker type for the PE/COFF platform.
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct Pe;

/// A validated x86-64 COFF relocatable object.
#[derive(Debug)]
pub(crate) struct CoffObject<'data> {
    file: CoffFile<'data>,
}

impl<'data> CoffObject<'data> {
    pub(crate) fn parse(bytes: &'data [u8]) -> Result<Self> {
        let file = CoffFile::parse(bytes).context("Invalid x86-64 COFF object")?;
        ensure!(
            file.architecture() == object::Architecture::X86_64,
            "Unsupported COFF machine {:#06x}; only x86-64 COFF is currently supported",
            u16::from_le_bytes(bytes[..2].try_into().unwrap())
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

    pub(crate) fn file(&self) -> &CoffFile<'data> {
        &self.file
    }
}

/// Fast prefix check used before invoking the complete COFF parser.
pub(crate) fn has_amd64_machine(bytes: &[u8]) -> bool {
    bytes.starts_with(&crate::coff_x86_64::CoffX86_64::MACHINE.to_le_bytes())
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
}
