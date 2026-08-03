//! Packed symbol/provider contract for the final PE architecture.

#![allow(dead_code)]

use super::pe_ir::ArchiveId;
use super::pe_ir::ArchiveMemberId;
use super::pe_ir::ImportId;
use super::pe_ir::ImportLibraryId;
use super::pe_ir::NameId;
use super::pe_ir::ObjectId;
use super::pe_ir::ProviderId;
use super::pe_ir::SectionId;
use super::pe_ir::SymbolId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum ProviderKind {
    ObjectSymbol,
    ArchiveMember,
    Import,
    Absolute,
    LinkerDefined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum BindingStrength {
    Weak,
    Common,
    Strong,
}

/// Fixed-width provider payload. `owner` and `subject` are interpreted by `kind`.
///
/// - ObjectSymbol: ObjectId, SymbolId
/// - ArchiveMember: ArchiveId, ArchiveMemberId
/// - Import: ImportLibraryId, ImportId
/// - Absolute/LinkerDefined: zero, value-table index
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct ProviderRecord {
    pub(super) owner: u32,
    pub(super) subject: u32,
    pub(super) kind: ProviderKind,
    pub(super) strength: BindingStrength,
    pub(super) flags: u16,
}

impl ProviderRecord {
    pub(super) const fn object(
        object: ObjectId,
        symbol: SymbolId,
        strength: BindingStrength,
    ) -> Self {
        Self {
            owner: object.get(),
            subject: symbol.get(),
            kind: ProviderKind::ObjectSymbol,
            strength,
            flags: 0,
        }
    }

    pub(super) const fn archive(
        archive: ArchiveId,
        member: ArchiveMemberId,
        strength: BindingStrength,
    ) -> Self {
        Self {
            owner: archive.get(),
            subject: member.get(),
            kind: ProviderKind::ArchiveMember,
            strength,
            flags: 0,
        }
    }

    pub(super) const fn import(import_library: ImportLibraryId, import: ImportId) -> Self {
        Self {
            owner: import_library.get(),
            subject: import.get(),
            kind: ProviderKind::Import,
            strength: BindingStrength::Strong,
            flags: 0,
        }
    }

    pub(super) const fn kind(self) -> ProviderKind {
        self.kind
    }

    pub(super) const fn absolute(value_index: u32, linker_defined: bool) -> Self {
        Self {
            owner: 0,
            subject: value_index,
            kind: if linker_defined {
                ProviderKind::LinkerDefined
            } else {
                ProviderKind::Absolute
            },
            strength: BindingStrength::Strong,
            flags: 0,
        }
    }
}

/// `u32::MAX` is the unresolved provider sentinel, keeping every resolution eight bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct Resolution {
    pub(super) provider: u32,
    pub(super) state: ResolutionState,
    pub(super) binding: BindingStrength,
    pub(super) flags: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum ResolutionState {
    Unresolved,
    Resolved,
    Ambiguous,
    Discarded,
}

impl Resolution {
    pub(super) const UNRESOLVED: Self = Self {
        provider: u32::MAX,
        state: ResolutionState::Unresolved,
        binding: BindingStrength::Weak,
        flags: 0,
    };

    pub(super) const fn resolved(provider: ProviderId, binding: BindingStrength) -> Self {
        Self {
            provider: provider.get(),
            state: ResolutionState::Resolved,
            binding,
            flags: 0,
        }
    }

    pub(super) const fn provider(self) -> Option<ProviderId> {
        if self.provider == u32::MAX {
            None
        } else {
            Some(ProviderId::from_u32(self.provider))
        }
    }

    pub(super) const fn state(self) -> ResolutionState {
        self.state
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct SymbolEntry {
    pub(super) resolution: Resolution,
    pub(super) provider_start: u32,
    pub(super) provider_len: u32,
    pub(super) weak_fallback: u32,
}

impl SymbolEntry {
    pub(super) const NO_FALLBACK: u32 = u32::MAX;

    pub(super) const fn weak_fallback(self) -> Option<NameId> {
        if self.weak_fallback == Self::NO_FALLBACK {
            None
        } else {
            Some(NameId::from_u32(self.weak_fallback))
        }
    }
}

/// One canonical entry per NameId. SymbolId identifies a per-object occurrence and only appears in
/// object-provider payloads; global resolution and fallback relationships use NameId.
#[derive(Debug)]
pub(super) struct SymbolDb {
    pub(super) entries: Box<[SymbolEntry]>,
    pub(super) providers: Box<[ProviderRecord]>,
    pub(super) absolute_values: Box<[u64]>,
}

impl SymbolDb {
    pub(super) fn entry(&self, name: NameId) -> Option<&SymbolEntry> {
        self.entries.get(name.index())
    }

    pub(super) fn provider(&self, provider: ProviderId) -> Option<&ProviderRecord> {
        self.providers.get(provider.index())
    }

    pub(super) fn providers_for(&self, name: NameId) -> Option<&[ProviderRecord]> {
        let entry = self.entry(name)?;
        let start = entry.provider_start as usize;
        let end = start.checked_add(entry.provider_len as usize)?;
        self.providers.get(start..end)
    }
}

/// Builder boundary for M1. Parsing/archives emit providers; one resolver owns final decisions.
pub(super) trait BuildSymbolDb {
    type Error;

    fn build_symbol_db(
        &self,
        names: &[NameId],
        object_sections: &[Option<SectionId>],
        providers: &[ProviderRecord],
    ) -> std::result::Result<SymbolDb, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_and_resolution_records_remain_packed() {
        assert_eq!(std::mem::size_of::<ProviderRecord>(), 12);
        assert_eq!(std::mem::size_of::<Resolution>(), 8);
        assert_eq!(Resolution::UNRESOLVED.provider(), None);
        let resolution = Resolution::resolved(ProviderId::from_u32(7), BindingStrength::Strong);
        assert_eq!(resolution.provider(), Some(ProviderId::from_u32(7)));
        let entry = SymbolEntry {
            resolution,
            provider_start: 0,
            provider_len: 0,
            weak_fallback: NameId::from_u32(2).get(),
        };
        assert_eq!(entry.weak_fallback(), Some(NameId::from_u32(2)));

        let database = SymbolDb {
            entries: vec![entry].into_boxed_slice(),
            providers: Box::new([]),
            absolute_values: Box::new([]),
        };
        assert_eq!(database.entry(NameId::from_u32(0)), Some(&entry));
        assert_eq!(database.providers_for(NameId::from_u32(0)), Some(&[][..]));
    }
}
