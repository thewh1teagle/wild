//! Event-driven section-GC boundary for the final PE architecture.

#![allow(dead_code)]

use super::pe_ir::NameId;
use super::pe_ir::RelocationCsr;
use super::pe_ir::SectionId;
use super::pe_ir::SymbolId;
use super::pe_symbol_db::SymbolDb;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum RootReason {
    CommandLine,
    Entry,
    Export,
    RuntimeDirective,
    NonComdat,
    LoaderMetadata,
}

/// Ordered events are the only way roots and newly-live edges enter the collector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GcEvent {
    RootSymbol {
        name: NameId,
        reason: RootReason,
    },
    RootSection {
        section: SectionId,
        reason: RootReason,
    },
    RelocationEdge {
        source: SectionId,
        /// Per-object occurrence; its SymbolRecord maps the edge to a canonical NameId.
        target: SymbolId,
    },
    AssociativeEdge {
        parent: SectionId,
        child: SectionId,
    },
    Redirect {
        from: SectionId,
        to: SectionId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct SectionGroup {
    pub(super) leader: SectionId,
    pub(super) member_start: u32,
    pub(super) member_len: u32,
}

/// Immutable M2 input. Event order is source order and therefore diagnostic order.
#[derive(Debug)]
pub(super) struct GcInput<'a> {
    pub(super) section_count: u32,
    pub(super) events: &'a [GcEvent],
    pub(super) groups: &'a [SectionGroup],
    pub(super) group_members: &'a [SectionId],
    pub(super) relocations: &'a RelocationCsr,
    pub(super) symbols: &'a SymbolDb,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct SectionRedirect {
    pub(super) from: SectionId,
    pub(super) to: SectionId,
}

/// Dense output consumed by layout. Canonical IDs replace hash lookups and redirect chasing.
#[derive(Debug)]
pub(super) struct GcOutput {
    pub(super) live_bits: Box<[u64]>,
    pub(super) canonical_sections: Box<[SectionId]>,
    pub(super) redirects: Box<[SectionRedirect]>,
    pub(super) visitation_order: Box<[SectionId]>,
}

impl GcOutput {
    pub(super) fn is_live(&self, section: SectionId) -> bool {
        let word = section.index() / 64;
        let bit = section.index() % 64;
        self.live_bits
            .get(word)
            .is_some_and(|bits| bits & (1u64 << bit) != 0)
    }

    pub(super) fn canonical(&self, section: SectionId) -> Option<SectionId> {
        self.canonical_sections.get(section.index()).copied()
    }
}

/// M2 implementation seam. The concrete collector may be serial or sharded but must consume and
/// publish events in deterministic input order.
pub(super) trait EventDrivenGc {
    type Error;

    fn collect(&mut self, input: GcInput<'_>) -> std::result::Result<GcOutput, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dense_gc_output_uses_bit_and_canonical_arrays() {
        let root = GcEvent::RootSymbol {
            name: NameId::from_u32(7),
            reason: RootReason::Entry,
        };
        assert!(matches!(
            root,
            GcEvent::RootSymbol { name, .. } if name == NameId::from_u32(7)
        ));

        let output = GcOutput {
            live_bits: vec![1u64 << 3].into_boxed_slice(),
            canonical_sections: (0..4)
                .map(SectionId::from_u32)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            redirects: Box::new([]),
            visitation_order: vec![SectionId::from_u32(3)].into_boxed_slice(),
        };
        assert!(output.is_live(SectionId::from_u32(3)));
        assert!(!output.is_live(SectionId::from_u32(2)));
        assert_eq!(
            output.canonical(SectionId::from_u32(3)),
            Some(SectionId::from_u32(3))
        );
        assert!(output.canonical(SectionId::from_u32(4)).is_none());
    }
}
