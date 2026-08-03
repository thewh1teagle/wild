//! Policy-free building blocks for resolving AMD64 COFF symbols.
//!
//! This module deliberately does not own a global symbol table.  It validates
//! the compact metadata found in COFF records and turns it into typed values
//! that a linker can use without repeatedly interpreting magic numbers.

use std::error::Error;
use std::fmt;

use object::pe;

const SECTION_NUMBER_UNDEFINED: i32 = 0;
const SECTION_NUMBER_ABSOLUTE: i32 = -1;
const SECTION_NUMBER_DEBUG: i32 = -2;
const AUXILIARY_SYMBOL_SIZE: usize = 18;

/// A malformed or contradictory COFF symbol-table construct.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoffSymbolError {
    message: String,
}

impl CoffSymbolError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for CoffSymbolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for CoffSymbolError {}

pub type Result<T> = std::result::Result<T, CoffSymbolError>;

/// The resolution-relevant meaning of a COFF symbol record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolClass {
    /// A translation-unit-local definition.
    LocalDefinition { section: u32 },
    /// A definition visible to the global symbol table.
    ExternalDefinition { section: u32 },
    /// A strong undefined external.
    UndefinedExternal,
    /// A tentative definition. `size` is the allocation size in bytes.
    Common { size: u64 },
    /// An absolute value that is not relocated with the image.
    Absolute { value: u64 },
    /// A debugging symbol that does not participate in normal resolution.
    Debug,
    /// An undefined external whose auxiliary record supplies fallback policy.
    WeakExternal,
}

/// Classifies one symbol after validating its section index and storage class.
pub fn classify_symbol(
    storage_class: u8,
    section_number: i32,
    value: u64,
    section_count: u32,
) -> Result<SymbolClass> {
    match section_number {
        SECTION_NUMBER_UNDEFINED => match storage_class {
            value_class if value_class == pe::IMAGE_SYM_CLASS_EXTERNAL.0 && value == 0 => {
                Ok(SymbolClass::UndefinedExternal)
            }
            value_class if value_class == pe::IMAGE_SYM_CLASS_EXTERNAL.0 => {
                Ok(SymbolClass::Common { size: value })
            }
            value_class if value_class == pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL.0 && value == 0 => {
                Ok(SymbolClass::WeakExternal)
            }
            value_class if value_class == pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL.0 => {
                Err(CoffSymbolError::new(
                    "weak external has a non-zero value; common weak externals are invalid",
                ))
            }
            other => Err(CoffSymbolError::new(format!(
                "undefined symbol has unsupported storage class 0x{other:02x}"
            ))),
        },
        SECTION_NUMBER_ABSOLUTE => match storage_class {
            value_class
                if value_class == pe::IMAGE_SYM_CLASS_EXTERNAL.0
                    || value_class == pe::IMAGE_SYM_CLASS_STATIC.0 =>
            {
                Ok(SymbolClass::Absolute { value })
            }
            other => Err(CoffSymbolError::new(format!(
                "absolute symbol has unsupported storage class 0x{other:02x}"
            ))),
        },
        SECTION_NUMBER_DEBUG => Ok(SymbolClass::Debug),
        number if number > 0 => {
            let section = u32::try_from(number).expect("positive i32 fits in u32");
            if section > section_count {
                return Err(CoffSymbolError::new(format!(
                    "symbol section {section} is outside the object section range 1..={section_count}"
                )));
            }
            match storage_class {
                value_class
                    if value_class == pe::IMAGE_SYM_CLASS_EXTERNAL.0
                        || value_class == pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL.0 =>
                {
                    Ok(SymbolClass::ExternalDefinition { section })
                }
                value_class
                    if value_class == pe::IMAGE_SYM_CLASS_STATIC.0
                        || value_class == pe::IMAGE_SYM_CLASS_LABEL.0
                        || value_class == pe::IMAGE_SYM_CLASS_SECTION.0 =>
                {
                    Ok(SymbolClass::LocalDefinition { section })
                }
                other => Err(CoffSymbolError::new(format!(
                    "defined symbol has unsupported storage class 0x{other:02x}"
                ))),
            }
        }
        other => Err(CoffSymbolError::new(format!(
            "symbol has invalid reserved section number {other}"
        ))),
    }
}

/// The kind and memory permissions encoded in section characteristics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SectionClass {
    pub contents: SectionContents,
    pub comdat: bool,
    pub discardable: bool,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SectionContents {
    Code,
    InitializedData,
    UninitializedData,
    Metadata,
}

/// Validates the mutually exclusive section-content bits and exposes flags.
pub fn classify_section(characteristics: u32) -> Result<SectionClass> {
    let content_bits = characteristics
        & (pe::IMAGE_SCN_CNT_CODE.0
            | pe::IMAGE_SCN_CNT_INITIALIZED_DATA.0
            | pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA.0);
    let contents = match content_bits {
        value if value == pe::IMAGE_SCN_CNT_CODE.0 => SectionContents::Code,
        value if value == pe::IMAGE_SCN_CNT_INITIALIZED_DATA.0 => SectionContents::InitializedData,
        value if value == pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA.0 => {
            SectionContents::UninitializedData
        }
        0 => SectionContents::Metadata,
        _ => {
            return Err(CoffSymbolError::new(format!(
                "section has contradictory content flags 0x{content_bits:08x}"
            )));
        }
    };
    Ok(SectionClass {
        contents,
        comdat: characteristics & pe::IMAGE_SCN_LNK_COMDAT.0 != 0,
        discardable: characteristics & pe::IMAGE_SCN_MEM_DISCARDABLE.0 != 0,
        readable: characteristics & pe::IMAGE_SCN_MEM_READ.0 != 0,
        writable: characteristics & pe::IMAGE_SCN_MEM_WRITE.0 != 0,
        executable: characteristics & pe::IMAGE_SCN_MEM_EXECUTE.0 != 0,
    })
}

/// Selection policy from a section-definition auxiliary symbol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComdatSelection {
    NoDuplicates,
    Any,
    SameSize,
    ExactMatch,
    Associative { parent_section: u32 },
    Largest,
    Newest,
}

/// Validated fields from a section-definition auxiliary record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SectionDefinition {
    pub length: u32,
    pub relocation_count: u16,
    pub checksum: u32,
    pub selection: Option<ComdatSelection>,
}

/// Parses the standard 18-byte section-definition auxiliary record.
///
/// `is_comdat` must come from `IMAGE_SCN_LNK_COMDAT`. The high 16 bits of the
/// associative section number are accepted for bigobj producers as specified
/// by Microsoft's extended auxiliary record layout.
pub fn parse_section_definition(
    auxiliary: &[u8],
    is_comdat: bool,
    section_count: u32,
) -> Result<SectionDefinition> {
    require_aux_size(auxiliary, "section-definition")?;
    let length = u32::from_le_bytes(auxiliary[0..4].try_into().unwrap());
    let relocation_count = u16::from_le_bytes(auxiliary[4..6].try_into().unwrap());
    if auxiliary[6..8] != [0, 0] || auxiliary[15] != 0 {
        return Err(CoffSymbolError::new(
            "section-definition auxiliary record has non-zero reserved bytes",
        ));
    }
    let checksum = u32::from_le_bytes(auxiliary[8..12].try_into().unwrap());
    let low = u16::from_le_bytes(auxiliary[12..14].try_into().unwrap());
    let selection_byte = auxiliary[14];
    let high = u16::from_le_bytes(auxiliary[16..18].try_into().unwrap());
    let associated = u32::from(low) | (u32::from(high) << 16);

    let selection = if is_comdat {
        Some(parse_comdat_selection(
            selection_byte,
            associated,
            section_count,
        )?)
    } else {
        if selection_byte != 0 || associated != 0 {
            return Err(CoffSymbolError::new(
                "non-COMDAT section has COMDAT selection metadata",
            ));
        }
        None
    };
    Ok(SectionDefinition {
        length,
        relocation_count,
        checksum,
        selection,
    })
}

pub fn parse_comdat_selection(
    selection: u8,
    associated_section: u32,
    section_count: u32,
) -> Result<ComdatSelection> {
    let ordinary = |value| {
        if associated_section == 0 {
            Ok(value)
        } else {
            Err(CoffSymbolError::new(format!(
                "non-associative COMDAT has unexpected associated section {associated_section}"
            )))
        }
    };
    match selection {
        value if value == pe::IMAGE_COMDAT_SELECT_NODUPLICATES.0 => {
            ordinary(ComdatSelection::NoDuplicates)
        }
        value if value == pe::IMAGE_COMDAT_SELECT_ANY.0 => ordinary(ComdatSelection::Any),
        value if value == pe::IMAGE_COMDAT_SELECT_SAME_SIZE.0 => {
            ordinary(ComdatSelection::SameSize)
        }
        value if value == pe::IMAGE_COMDAT_SELECT_EXACT_MATCH.0 => {
            ordinary(ComdatSelection::ExactMatch)
        }
        value if value == pe::IMAGE_COMDAT_SELECT_LARGEST.0 => ordinary(ComdatSelection::Largest),
        value if value == pe::IMAGE_COMDAT_SELECT_NEWEST.0 => ordinary(ComdatSelection::Newest),
        value if value == pe::IMAGE_COMDAT_SELECT_ASSOCIATIVE.0 => {
            if associated_section == 0 || associated_section > section_count {
                Err(CoffSymbolError::new(format!(
                    "associative COMDAT parent {associated_section} is outside the section range 1..={section_count}"
                )))
            } else {
                Ok(ComdatSelection::Associative {
                    parent_section: associated_section,
                })
            }
        }
        other => Err(CoffSymbolError::new(format!(
            "unsupported COMDAT selection {other}"
        ))),
    }
}

/// Input needed to compare two non-associative COMDAT definitions.
#[derive(Clone, Copy, Debug)]
pub struct ComdatCandidate<'a> {
    pub contents: &'a [u8],
    /// A stable encoding of relocation offsets, types, addends and targets.
    pub relocation_signature: &'a [u8],
    /// COFF header timestamp, used only by `NEWEST`.
    pub timestamp: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComdatDecision {
    KeepExisting,
    ReplaceExisting,
}

/// Applies a COMDAT duplicate-selection rule.
pub fn select_comdat(
    selection: ComdatSelection,
    existing: ComdatCandidate<'_>,
    incoming: ComdatCandidate<'_>,
) -> Result<ComdatDecision> {
    match selection {
        ComdatSelection::NoDuplicates => Err(CoffSymbolError::new(
            "duplicate COMDAT violates NODUPLICATES selection",
        )),
        ComdatSelection::Any => Ok(ComdatDecision::KeepExisting),
        ComdatSelection::SameSize => {
            if existing.contents.len() == incoming.contents.len() {
                Ok(ComdatDecision::KeepExisting)
            } else {
                Err(CoffSymbolError::new(format!(
                    "SAME_SIZE COMDAT mismatch: existing size {}, incoming size {}",
                    existing.contents.len(),
                    incoming.contents.len()
                )))
            }
        }
        ComdatSelection::ExactMatch => {
            if existing.contents == incoming.contents
                && existing.relocation_signature == incoming.relocation_signature
            {
                Ok(ComdatDecision::KeepExisting)
            } else {
                Err(CoffSymbolError::new(
                    "EXACT_MATCH COMDAT differs in contents or relocations",
                ))
            }
        }
        ComdatSelection::Largest => {
            if incoming.contents.len() > existing.contents.len() {
                Ok(ComdatDecision::ReplaceExisting)
            } else {
                Ok(ComdatDecision::KeepExisting)
            }
        }
        ComdatSelection::Newest => {
            if incoming.timestamp > existing.timestamp {
                Ok(ComdatDecision::ReplaceExisting)
            } else {
                Ok(ComdatDecision::KeepExisting)
            }
        }
        ComdatSelection::Associative { .. } => Err(CoffSymbolError::new(
            "associative COMDAT liveness is determined by its parent, not duplicate selection",
        )),
    }
}

/// Search policy from a weak-external auxiliary record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WeakSearch {
    NoLibrary,
    Library,
    Alias,
    AntiDependency,
}

/// A weak external and the symbol-table index of its fallback definition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WeakExternal {
    pub fallback_symbol: u32,
    pub search: WeakSearch,
}

/// Parses and bounds-checks an 18-byte weak-external auxiliary record.
pub fn parse_weak_external(
    auxiliary: &[u8],
    symbol_index: u32,
    symbol_count: u32,
) -> Result<WeakExternal> {
    require_aux_size(auxiliary, "weak-external")?;
    let fallback_symbol = u32::from_le_bytes(auxiliary[0..4].try_into().unwrap());
    if fallback_symbol >= symbol_count {
        return Err(CoffSymbolError::new(format!(
            "weak external fallback index {fallback_symbol} is outside symbol table of {symbol_count} records"
        )));
    }
    if fallback_symbol == symbol_index {
        return Err(CoffSymbolError::new(
            "weak external cannot fall back to itself",
        ));
    }
    let characteristic = u32::from_le_bytes(auxiliary[4..8].try_into().unwrap());
    if auxiliary[8..].iter().any(|byte| *byte != 0) {
        return Err(CoffSymbolError::new(
            "weak-external auxiliary record has non-zero reserved bytes",
        ));
    }
    let search = match characteristic {
        value if value == pe::IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY.0 => WeakSearch::NoLibrary,
        value if value == pe::IMAGE_WEAK_EXTERN_SEARCH_LIBRARY.0 => WeakSearch::Library,
        value if value == pe::IMAGE_WEAK_EXTERN_SEARCH_ALIAS.0 => WeakSearch::Alias,
        value if value == pe::IMAGE_WEAK_EXTERN_ANTI_DEPENDENCY.0 => WeakSearch::AntiDependency,
        other => {
            return Err(CoffSymbolError::new(format!(
                "unsupported weak external search characteristic {other}"
            )));
        }
    };
    Ok(WeakExternal {
        fallback_symbol,
        search,
    })
}

/// Why an unresolved name may cause an archive member to be extracted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveDemandKind {
    Strong,
    WeakLibrary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveDemand<'a> {
    pub name: &'a [u8],
    pub kind: ArchiveDemandKind,
}

/// Converts a resolution state into an archive lookup demand.
///
/// Commons and non-library weak externals intentionally do not extract an
/// archive member. A later strong object definition can still replace a
/// common during normal object processing.
pub fn archive_demand<'a>(
    name: &'a [u8],
    class: SymbolClass,
    weak: Option<WeakExternal>,
) -> Result<Option<ArchiveDemand<'a>>> {
    match class {
        SymbolClass::UndefinedExternal if weak.is_none() => Ok(Some(ArchiveDemand {
            name,
            kind: ArchiveDemandKind::Strong,
        })),
        SymbolClass::WeakExternal => {
            let weak = weak.ok_or_else(|| {
                CoffSymbolError::new("weak external is missing its auxiliary metadata")
            })?;
            if weak.search == WeakSearch::Library {
                Ok(Some(ArchiveDemand {
                    name,
                    kind: ArchiveDemandKind::WeakLibrary,
                }))
            } else {
                Ok(None)
            }
        }
        _ if weak.is_some() => Err(CoffSymbolError::new(
            "non-weak symbol was supplied weak-external metadata",
        )),
        _ => Ok(None),
    }
}

/// Returns whether an associative COMDAT follows a retained parent section.
///
/// Keeping this operation explicit prevents associative children from being
/// entered into ordinary duplicate selection by accident.
#[must_use]
pub const fn associative_comdat_is_live(selection: ComdatSelection, parent_is_live: bool) -> bool {
    match selection {
        ComdatSelection::Associative { .. } => parent_is_live,
        _ => false,
    }
}

/// Returns the first demand satisfied by a member's public definitions.
#[must_use]
pub fn archive_member_needed<'a, 'name>(
    demands: &'a [ArchiveDemand<'name>],
    definitions: &[&[u8]],
) -> Option<&'a ArchiveDemand<'name>> {
    demands
        .iter()
        .find(|demand| definitions.contains(&demand.name))
}

fn require_aux_size(auxiliary: &[u8], kind: &str) -> Result<()> {
    if auxiliary.len() == AUXILIARY_SYMBOL_SIZE {
        Ok(())
    } else {
        Err(CoffSymbolError::new(format!(
            "{kind} auxiliary record must be exactly {AUXILIARY_SYMBOL_SIZE} bytes, got {}",
            auxiliary.len()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_resolution_relevant_symbols() {
        assert_eq!(
            classify_symbol(pe::IMAGE_SYM_CLASS_EXTERNAL.0, 0, 0, 2).unwrap(),
            SymbolClass::UndefinedExternal
        );
        assert_eq!(
            classify_symbol(pe::IMAGE_SYM_CLASS_EXTERNAL.0, 0, 64, 2).unwrap(),
            SymbolClass::Common { size: 64 }
        );
        assert_eq!(
            classify_symbol(pe::IMAGE_SYM_CLASS_EXTERNAL.0, 2, 7, 2).unwrap(),
            SymbolClass::ExternalDefinition { section: 2 }
        );
        assert_eq!(
            classify_symbol(pe::IMAGE_SYM_CLASS_STATIC.0, 1, 0, 2).unwrap(),
            SymbolClass::LocalDefinition { section: 1 }
        );
        assert_eq!(
            classify_symbol(pe::IMAGE_SYM_CLASS_EXTERNAL.0, -1, 42, 2).unwrap(),
            SymbolClass::Absolute { value: 42 }
        );
        assert_eq!(
            classify_symbol(pe::IMAGE_SYM_CLASS_FILE.0, -2, 0, 2).unwrap(),
            SymbolClass::Debug
        );
        assert_eq!(
            classify_symbol(pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL.0, 0, 0, 2).unwrap(),
            SymbolClass::WeakExternal
        );
    }

    #[test]
    fn rejects_invalid_symbol_shapes() {
        assert!(classify_symbol(pe::IMAGE_SYM_CLASS_STATIC.0, 0, 0, 1).is_err());
        assert!(classify_symbol(pe::IMAGE_SYM_CLASS_EXTERNAL.0, 2, 0, 1).is_err());
        assert!(classify_symbol(pe::IMAGE_SYM_CLASS_EXTERNAL.0, -3, 0, 1).is_err());
        assert!(classify_symbol(pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL.0, 0, 1, 1).is_err());
    }

    #[test]
    fn classifies_and_validates_sections() {
        let section = classify_section(
            pe::IMAGE_SCN_CNT_CODE.0
                | pe::IMAGE_SCN_LNK_COMDAT.0
                | pe::IMAGE_SCN_MEM_READ.0
                | pe::IMAGE_SCN_MEM_EXECUTE.0,
        )
        .unwrap();
        assert_eq!(section.contents, SectionContents::Code);
        assert!(section.comdat && section.readable && section.executable);
        assert!(!section.writable);
        assert!(
            classify_section(pe::IMAGE_SCN_CNT_CODE.0 | pe::IMAGE_SCN_CNT_INITIALIZED_DATA.0)
                .is_err()
        );
    }

    fn section_aux(selection: u8, associated: u32) -> [u8; 18] {
        let mut aux = [0; 18];
        aux[0..4].copy_from_slice(&123u32.to_le_bytes());
        aux[4..6].copy_from_slice(&7u16.to_le_bytes());
        aux[8..12].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        aux[12..14].copy_from_slice(&(associated as u16).to_le_bytes());
        aux[14] = selection;
        aux[16..18].copy_from_slice(&((associated >> 16) as u16).to_le_bytes());
        aux
    }

    #[test]
    fn parses_section_definition_and_associative_parent() {
        let parsed = parse_section_definition(
            &section_aux(pe::IMAGE_COMDAT_SELECT_ASSOCIATIVE.0, 70_000),
            true,
            80_000,
        )
        .unwrap();
        assert_eq!(parsed.length, 123);
        assert_eq!(parsed.relocation_count, 7);
        assert_eq!(parsed.checksum, 0x1234_5678);
        assert_eq!(
            parsed.selection,
            Some(ComdatSelection::Associative {
                parent_section: 70_000
            })
        );
        assert!(
            parse_section_definition(&section_aux(pe::IMAGE_COMDAT_SELECT_ANY.0, 1), true, 2)
                .is_err()
        );
        assert!(parse_section_definition(&[0; 17], false, 1).is_err());
        assert!(
            parse_section_definition(
                &section_aux(pe::IMAGE_COMDAT_SELECT_ASSOCIATIVE.0, 3),
                true,
                2
            )
            .is_err()
        );
    }

    fn candidate<'a>(
        contents: &'a [u8],
        relocations: &'a [u8],
        timestamp: u32,
    ) -> ComdatCandidate<'a> {
        ComdatCandidate {
            contents,
            relocation_signature: relocations,
            timestamp,
        }
    }

    #[test]
    fn applies_comdat_duplicate_rules() {
        let old = candidate(b"abc", b"reloc", 10);
        assert_eq!(
            select_comdat(ComdatSelection::Any, old, candidate(b"xyz", b"x", 20)).unwrap(),
            ComdatDecision::KeepExisting
        );
        assert!(select_comdat(ComdatSelection::NoDuplicates, old, old).is_err());
        assert!(select_comdat(ComdatSelection::SameSize, old, candidate(b"xx", b"", 0)).is_err());
        assert_eq!(
            select_comdat(ComdatSelection::SameSize, old, candidate(b"xyz", b"", 0)).unwrap(),
            ComdatDecision::KeepExisting
        );
        assert_eq!(
            select_comdat(ComdatSelection::ExactMatch, old, old).unwrap(),
            ComdatDecision::KeepExisting
        );
        assert!(
            select_comdat(
                ComdatSelection::ExactMatch,
                old,
                candidate(b"abc", b"other", 10)
            )
            .is_err()
        );
        assert_eq!(
            select_comdat(ComdatSelection::Largest, old, candidate(b"abcd", b"", 0)).unwrap(),
            ComdatDecision::ReplaceExisting
        );
        assert_eq!(
            select_comdat(ComdatSelection::Newest, old, candidate(b"", b"", 11)).unwrap(),
            ComdatDecision::ReplaceExisting
        );
        assert!(
            select_comdat(ComdatSelection::Associative { parent_section: 1 }, old, old).is_err()
        );
    }

    fn weak_aux(fallback: u32, search: u32) -> [u8; 18] {
        let mut aux = [0; 18];
        aux[0..4].copy_from_slice(&fallback.to_le_bytes());
        aux[4..8].copy_from_slice(&search.to_le_bytes());
        aux
    }

    #[test]
    fn parses_weak_external_and_rejects_bad_indices() {
        assert_eq!(
            parse_weak_external(&weak_aux(4, pe::IMAGE_WEAK_EXTERN_SEARCH_ALIAS.0), 2, 5).unwrap(),
            WeakExternal {
                fallback_symbol: 4,
                search: WeakSearch::Alias
            }
        );
        assert!(
            parse_weak_external(&weak_aux(5, pe::IMAGE_WEAK_EXTERN_SEARCH_LIBRARY.0), 2, 5)
                .is_err()
        );
        assert!(
            parse_weak_external(&weak_aux(2, pe::IMAGE_WEAK_EXTERN_SEARCH_LIBRARY.0), 2, 5)
                .is_err()
        );
        assert!(parse_weak_external(&weak_aux(1, 99), 0, 2).is_err());
    }

    #[test]
    fn archive_extraction_respects_weak_policy_and_commons() {
        let weak_library = WeakExternal {
            fallback_symbol: 3,
            search: WeakSearch::Library,
        };
        let demands = [
            archive_demand(b"strong", SymbolClass::UndefinedExternal, None)
                .unwrap()
                .unwrap(),
            archive_demand(b"weak", SymbolClass::WeakExternal, Some(weak_library))
                .unwrap()
                .unwrap(),
        ];
        assert_eq!(
            archive_member_needed(&demands, &[b"unrelated", b"weak"]),
            Some(&demands[1])
        );
        assert!(
            archive_demand(b"common", SymbolClass::Common { size: 4 }, None)
                .unwrap()
                .is_none()
        );
        assert!(
            archive_demand(
                b"alias",
                SymbolClass::WeakExternal,
                Some(WeakExternal {
                    fallback_symbol: 1,
                    search: WeakSearch::Alias,
                })
            )
            .unwrap()
            .is_none()
        );
        assert!(archive_demand(b"weak", SymbolClass::WeakExternal, None).is_err());
        assert!(
            archive_demand(
                b"strong",
                SymbolClass::UndefinedExternal,
                Some(weak_library)
            )
            .is_err()
        );
    }

    #[test]
    fn associative_comdat_follows_parent_only() {
        let associative = ComdatSelection::Associative { parent_section: 2 };
        assert!(associative_comdat_is_live(associative, true));
        assert!(!associative_comdat_is_live(associative, false));
        assert!(!associative_comdat_is_live(ComdatSelection::Any, true));
    }
}
