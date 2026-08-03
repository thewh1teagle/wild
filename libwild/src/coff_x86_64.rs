//! x86-64 COFF architecture definitions shared by parsing and PE emission.

#![allow(dead_code)]

/// Marker for the AMD64 COFF architecture.
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct CoffX86_64;

impl CoffX86_64 {
    pub(crate) const MACHINE: u16 = object::pe::IMAGE_FILE_MACHINE_AMD64.0;
    pub(crate) const POINTER_SIZE: u8 = 8;
    pub(crate) const IMAGE_BASE: u64 = 0x0000_0001_4000_0000;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architecture_constants_match_pe32_plus() {
        assert_eq!(CoffX86_64::MACHINE, 0x8664);
        assert_eq!(CoffX86_64::POINTER_SIZE, 8);
        assert_eq!(CoffX86_64::IMAGE_BASE, 0x1_4000_0000);
    }
}
