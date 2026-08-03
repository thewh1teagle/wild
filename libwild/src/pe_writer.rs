//! Shared PE32+ writer configuration.
//!
//! Output construction is intentionally introduced separately from COFF input parsing. The next
//! vertical slice can build a minimal image around this validated configuration without baking
//! alignment policy into the generic layout code.

#![allow(dead_code)]

use crate::ensure;
use crate::error::Result;

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
            self.image_base % 0x1_0000 == 0,
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
