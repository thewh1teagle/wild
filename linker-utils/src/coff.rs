//! Utilities for applying relocations found in AMD64 COFF object files.
//!
//! COFF relocations carry their addend in the bytes being relocated. The
//! helpers in this module deliberately use RVAs for locations in the output
//! image, adding the image base only for relocations that require a VA.

use anyhow::{Result, bail, ensure};
use object::pe;

/// The preferred load address of a PE image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageBase(pub u64);

/// An address relative to the image base.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rva(pub u32);

/// A one-based PE section-table index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SectionIndex(pub u16);

/// Addresses needed to evaluate an AMD64 COFF relocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Amd64RelocationInputs {
    pub image_base: ImageBase,
    /// RVA of the first byte of the relocation field.
    pub place: Rva,
    pub target: Rva,
    /// RVA of the start of the output section containing `target`.
    pub target_section: Rva,
    pub target_section_index: SectionIndex,
}

/// A supported `IMAGE_REL_AMD64_*` relocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Amd64RelocationKind {
    Absolute,
    Address64,
    Address32,
    Address32NoBase,
    Relative { extra_offset: u8 },
    Section,
    SectionRelative,
}

impl Amd64RelocationKind {
    /// Classifies a typed COFF relocation constant.
    pub fn from_type(relocation_type: pe::RelocationType) -> Result<Self> {
        Ok(match relocation_type {
            pe::IMAGE_REL_AMD64_ABSOLUTE => Self::Absolute,
            pe::IMAGE_REL_AMD64_ADDR64 => Self::Address64,
            pe::IMAGE_REL_AMD64_ADDR32 => Self::Address32,
            pe::IMAGE_REL_AMD64_ADDR32NB => Self::Address32NoBase,
            pe::IMAGE_REL_AMD64_REL32 => Self::Relative { extra_offset: 0 },
            pe::IMAGE_REL_AMD64_REL32_1 => Self::Relative { extra_offset: 1 },
            pe::IMAGE_REL_AMD64_REL32_2 => Self::Relative { extra_offset: 2 },
            pe::IMAGE_REL_AMD64_REL32_3 => Self::Relative { extra_offset: 3 },
            pe::IMAGE_REL_AMD64_REL32_4 => Self::Relative { extra_offset: 4 },
            pe::IMAGE_REL_AMD64_REL32_5 => Self::Relative { extra_offset: 5 },
            pe::IMAGE_REL_AMD64_SECTION => Self::Section,
            pe::IMAGE_REL_AMD64_SECREL => Self::SectionRelative,
            _ => bail!(
                "unsupported AMD64 COFF relocation type 0x{:04x}",
                relocation_type.0
            ),
        })
    }

    #[must_use]
    pub fn field_size(self) -> usize {
        match self {
            Self::Absolute => 0,
            Self::Address64 => 8,
            Self::Section => 2,
            Self::Address32
            | Self::Address32NoBase
            | Self::Relative { .. }
            | Self::SectionRelative => 4,
        }
    }
}

/// The checked value produced for a relocation field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Amd64RelocationValue {
    None,
    U16(u16),
    U32(u32),
    U64(u64),
    I32(i32),
}

/// Calculates a relocation value from a signed implicit addend.
pub fn calculate_amd64_relocation(
    kind: Amd64RelocationKind,
    addend: i64,
    inputs: Amd64RelocationInputs,
) -> Result<Amd64RelocationValue> {
    let addend = i128::from(addend);
    let target = i128::from(inputs.target.0);
    let value = match kind {
        Amd64RelocationKind::Absolute => Amd64RelocationValue::None,
        Amd64RelocationKind::Address64 => {
            let value = i128::from(inputs.image_base.0) + target + addend;
            Amd64RelocationValue::U64(checked_u64(value, "ADDR64")?)
        }
        Amd64RelocationKind::Address32 => {
            let value = i128::from(inputs.image_base.0) + target + addend;
            Amd64RelocationValue::U32(checked_u32(value, "ADDR32")?)
        }
        Amd64RelocationKind::Address32NoBase => {
            Amd64RelocationValue::U32(checked_u32(target + addend, "ADDR32NB")?)
        }
        Amd64RelocationKind::Relative { extra_offset } => {
            let next_instruction = i128::from(inputs.place.0) + 4 + i128::from(extra_offset);
            let value = target + addend - next_instruction;
            let value = i32::try_from(value).map_err(|_| {
                anyhow::anyhow!("REL32 relocation value {value} does not fit in i32")
            })?;
            Amd64RelocationValue::I32(value)
        }
        Amd64RelocationKind::Section => {
            let value = i128::from(inputs.target_section_index.0) + addend;
            let value = u16::try_from(value).map_err(|_| {
                anyhow::anyhow!("SECTION relocation value {value} does not fit in u16")
            })?;
            Amd64RelocationValue::U16(value)
        }
        Amd64RelocationKind::SectionRelative => {
            ensure!(
                inputs.target.0 >= inputs.target_section.0,
                "SECREL target RVA {:#x} precedes section RVA {:#x}",
                inputs.target.0,
                inputs.target_section.0
            );
            let offset = i128::from(inputs.target.0 - inputs.target_section.0);
            Amd64RelocationValue::U32(checked_u32(offset + addend, "SECREL")?)
        }
    };
    Ok(value)
}

/// Reads the implicit addend, evaluates the relocation, and writes it back.
///
/// `field` may contain trailing bytes; only [`Amd64RelocationKind::field_size`]
/// bytes are read and modified. On error, it is left unchanged.
pub fn apply_amd64_relocation(
    kind: Amd64RelocationKind,
    field: &mut [u8],
    inputs: Amd64RelocationInputs,
) -> Result<()> {
    ensure!(
        field.len() >= kind.field_size(),
        "{kind:?} relocation requires {} bytes, only {} available",
        kind.field_size(),
        field.len()
    );

    let addend = match kind {
        Amd64RelocationKind::Absolute => 0,
        Amd64RelocationKind::Address64 => i64::from_le_bytes(field[..8].try_into().unwrap()),
        Amd64RelocationKind::Section => {
            i64::from(i16::from_le_bytes(field[..2].try_into().unwrap()))
        }
        _ => i64::from(i32::from_le_bytes(field[..4].try_into().unwrap())),
    };
    let value = calculate_amd64_relocation(kind, addend, inputs)?;
    match value {
        Amd64RelocationValue::None => {}
        Amd64RelocationValue::U16(value) => field[..2].copy_from_slice(&value.to_le_bytes()),
        Amd64RelocationValue::U32(value) => field[..4].copy_from_slice(&value.to_le_bytes()),
        Amd64RelocationValue::U64(value) => field[..8].copy_from_slice(&value.to_le_bytes()),
        Amd64RelocationValue::I32(value) => field[..4].copy_from_slice(&value.to_le_bytes()),
    }
    Ok(())
}

fn checked_u32(value: i128, name: &str) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| anyhow::anyhow!("{name} relocation value {value} does not fit in u32"))
}

fn checked_u64(value: i128, name: &str) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| anyhow::anyhow!("{name} relocation value {value} does not fit in u64"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> Amd64RelocationInputs {
        Amd64RelocationInputs {
            image_base: ImageBase(0x1_4000_0000),
            place: Rva(0x1010),
            target: Rva(0x2020),
            target_section: Rva(0x2000),
            target_section_index: SectionIndex(3),
        }
    }

    #[test]
    fn classifies_all_common_relocations() {
        assert_eq!(
            Amd64RelocationKind::from_type(pe::IMAGE_REL_AMD64_ABSOLUTE).unwrap(),
            Amd64RelocationKind::Absolute
        );
        assert_eq!(
            Amd64RelocationKind::from_type(pe::IMAGE_REL_AMD64_ADDR64).unwrap(),
            Amd64RelocationKind::Address64
        );
        assert_eq!(
            Amd64RelocationKind::from_type(pe::IMAGE_REL_AMD64_ADDR32).unwrap(),
            Amd64RelocationKind::Address32
        );
        assert_eq!(
            Amd64RelocationKind::from_type(pe::IMAGE_REL_AMD64_ADDR32NB).unwrap(),
            Amd64RelocationKind::Address32NoBase
        );
        for (relocation_type, extra) in [
            pe::IMAGE_REL_AMD64_REL32,
            pe::IMAGE_REL_AMD64_REL32_1,
            pe::IMAGE_REL_AMD64_REL32_2,
            pe::IMAGE_REL_AMD64_REL32_3,
            pe::IMAGE_REL_AMD64_REL32_4,
            pe::IMAGE_REL_AMD64_REL32_5,
        ]
        .into_iter()
        .zip(0..=5)
        {
            assert_eq!(
                Amd64RelocationKind::from_type(relocation_type).unwrap(),
                Amd64RelocationKind::Relative {
                    extra_offset: extra
                }
            );
        }
        assert_eq!(
            Amd64RelocationKind::from_type(pe::IMAGE_REL_AMD64_SECTION).unwrap(),
            Amd64RelocationKind::Section
        );
        assert_eq!(
            Amd64RelocationKind::from_type(pe::IMAGE_REL_AMD64_SECREL).unwrap(),
            Amd64RelocationKind::SectionRelative
        );
        assert_eq!(
            Amd64RelocationKind::from_type(pe::IMAGE_REL_AMD64_SECREL7)
                .unwrap_err()
                .to_string(),
            "unsupported AMD64 COFF relocation type 0x000c"
        );
    }

    #[test]
    fn calculates_address_relocations_with_negative_addends() {
        assert_eq!(
            calculate_amd64_relocation(Amd64RelocationKind::Address64, -0x20, inputs()).unwrap(),
            Amd64RelocationValue::U64(0x1_4000_2000)
        );
        assert_eq!(
            calculate_amd64_relocation(Amd64RelocationKind::Address32NoBase, -0x20, inputs())
                .unwrap(),
            Amd64RelocationValue::U32(0x2000)
        );

        let mut low_base = inputs();
        low_base.image_base = ImageBase(0x400000);
        assert_eq!(
            calculate_amd64_relocation(Amd64RelocationKind::Address32, -0x20, low_base).unwrap(),
            Amd64RelocationValue::U32(0x402000)
        );
        assert_eq!(
            calculate_amd64_relocation(Amd64RelocationKind::Absolute, i64::MAX, inputs()).unwrap(),
            Amd64RelocationValue::None
        );
    }

    #[test]
    fn calculates_every_relative_variant() {
        for extra in 0..=5 {
            let value = calculate_amd64_relocation(
                Amd64RelocationKind::Relative {
                    extra_offset: extra,
                },
                -4,
                inputs(),
            )
            .unwrap();
            assert_eq!(
                value,
                Amd64RelocationValue::I32(0x2020 - 4 - (0x1010 + 4 + i32::from(extra)))
            );
        }
    }

    #[test]
    fn calculates_section_relocations() {
        assert_eq!(
            calculate_amd64_relocation(Amd64RelocationKind::Section, -1, inputs()).unwrap(),
            Amd64RelocationValue::U16(2)
        );
        assert_eq!(
            calculate_amd64_relocation(Amd64RelocationKind::SectionRelative, -0x10, inputs())
                .unwrap(),
            Amd64RelocationValue::U32(0x10)
        );
    }

    #[test]
    fn applies_implicit_addends_and_preserves_trailing_data() {
        let mut field = [0xf0, 0xff, 0xff, 0xff, 0xaa]; // -16i32, then sentinel
        apply_amd64_relocation(Amd64RelocationKind::Address32NoBase, &mut field, inputs()).unwrap();
        assert_eq!(&field[..4], &0x2010_u32.to_le_bytes());
        assert_eq!(field[4], 0xaa);

        let mut absolute = [];
        apply_amd64_relocation(Amd64RelocationKind::Absolute, &mut absolute, inputs()).unwrap();
    }

    #[test]
    fn rejects_short_fields_without_modifying_them() {
        let mut field = [1, 2, 3];
        let before = field;
        let error = apply_amd64_relocation(Amd64RelocationKind::Address32, &mut field, inputs())
            .unwrap_err();
        assert!(error.to_string().contains("requires 4 bytes"));
        assert_eq!(field, before);
    }

    #[test]
    fn detects_unsigned_and_relative_overflow() {
        let mut values = inputs();
        values.image_base = ImageBase(u64::MAX);
        assert!(
            calculate_amd64_relocation(Amd64RelocationKind::Address64, 1, values)
                .unwrap_err()
                .to_string()
                .contains("ADDR64")
        );
        assert!(
            calculate_amd64_relocation(Amd64RelocationKind::Address32NoBase, i64::MAX, inputs())
                .unwrap_err()
                .to_string()
                .contains("ADDR32NB")
        );
        assert!(
            calculate_amd64_relocation(Amd64RelocationKind::Address32NoBase, -0x2021, inputs())
                .unwrap_err()
                .to_string()
                .contains("ADDR32NB")
        );
        assert!(
            calculate_amd64_relocation(Amd64RelocationKind::Address32, 0, inputs())
                .unwrap_err()
                .to_string()
                .contains("ADDR32")
        );

        let mut values = inputs();
        values.target = Rva(u32::MAX);
        values.place = Rva(0);
        assert!(
            calculate_amd64_relocation(
                Amd64RelocationKind::Relative { extra_offset: 0 },
                0,
                values
            )
            .unwrap_err()
            .to_string()
            .contains("REL32")
        );

        values.target = Rva(0);
        values.place = Rva(u32::MAX);
        assert!(
            calculate_amd64_relocation(
                Amd64RelocationKind::Relative { extra_offset: 5 },
                i64::from(i32::MIN),
                values
            )
            .unwrap_err()
            .to_string()
            .contains("REL32")
        );
    }

    #[test]
    fn detects_invalid_section_values() {
        let mut values = inputs();
        values.target_section = Rva(0x3000);
        assert!(
            calculate_amd64_relocation(Amd64RelocationKind::SectionRelative, 0, values)
                .unwrap_err()
                .to_string()
                .contains("precedes section")
        );
        assert!(
            calculate_amd64_relocation(Amd64RelocationKind::Section, -4, inputs())
                .unwrap_err()
                .to_string()
                .contains("SECTION")
        );

        values = inputs();
        values.target_section_index = SectionIndex(u16::MAX);
        assert!(
            calculate_amd64_relocation(Amd64RelocationKind::Section, 1, values)
                .unwrap_err()
                .to_string()
                .contains("SECTION")
        );

        values = inputs();
        values.target = Rva(u32::MAX);
        values.target_section = Rva(0);
        assert!(
            calculate_amd64_relocation(Amd64RelocationKind::SectionRelative, 1, values)
                .unwrap_err()
                .to_string()
                .contains("SECREL")
        );
    }
}
