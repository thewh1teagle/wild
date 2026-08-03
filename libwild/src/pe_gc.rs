//! Event-driven section-GC boundary for the final PE architecture.

#![allow(dead_code)]

use super::pe_ir::NameId;
use super::pe_ir::PeIr;
use super::pe_ir::RelocationCsr;
use super::pe_ir::RelocationRecord;
use super::pe_ir::SectionId;
use super::pe_ir::SymbolId;
use super::pe_symbol_db::ProviderKind;
use super::pe_symbol_db::ResolutionState;
use super::pe_symbol_db::SymbolDb;
use crate::ensure;
use crate::error;
use crate::error::Context;
use crate::error::Result;
use std::collections::BTreeSet;
use std::collections::VecDeque;

#[inline]
fn count_hot_allocations(count: u64) {
    #[cfg(not(test))]
    crate::perf::removal_counters::add_hot_phase_allocations(count);
    #[cfg(test)]
    let _ = count;
}

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

/// A live AMD64 DIR64 site. Layout turns this section-relative offset into an RVA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct Dir64Need {
    pub(super) section: SectionId,
    pub(super) offset: u32,
}

/// Dense output consumed by layout. Canonical IDs replace hash lookups and redirect chasing.
#[derive(Debug)]
pub(super) struct GcOutput {
    pub(super) live_bits: Box<[u64]>,
    pub(super) canonical_sections: Box<[SectionId]>,
    pub(super) redirects: Box<[SectionRedirect]>,
    pub(super) visitation_order: Box<[SectionId]>,
    pub(super) referenced_imports: Box<[super::pe_ir::ImportId]>,
    pub(super) dir64_needs: Box<[Dir64Need]>,
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

/// Concrete dense collector. Relocation edges are read from CSR only when their source becomes
/// live; unlike the legacy collector, this never materializes a whole-program relocation graph.
pub(super) struct DenseEventGc<'ir, 'data> {
    ir: &'ir PeIr<'data>,
}

impl<'ir, 'data> DenseEventGc<'ir, 'data> {
    pub(super) fn new(ir: &'ir PeIr<'data>) -> Self {
        Self { ir }
    }

    fn resolve_name(&self, symbols: &SymbolDb, mut name: NameId) -> Result<ResolvedTarget> {
        for _ in 0..=symbols.entries.len() {
            let entry = symbols
                .entry(name)
                .context("symbol name is outside the symbol DB")?;
            if entry.resolution.state() == ResolutionState::Resolved {
                let provider = entry
                    .resolution
                    .provider()
                    .and_then(|provider| symbols.provider(provider))
                    .context("resolved symbol refers to an invalid provider")?;
                return match provider.kind() {
                    ProviderKind::ObjectSymbol => {
                        let occurrence = SymbolId::from_u32(provider.subject);
                        let symbol = self
                            .ir
                            .symbols
                            .get(occurrence.index())
                            .context("object provider refers to an invalid symbol")?;
                        Ok(ResolvedTarget {
                            section: symbol.section.get(),
                            import: None,
                            absolute: false,
                        })
                    }
                    ProviderKind::Import => Ok(ResolvedTarget {
                        section: None,
                        import: Some(super::pe_ir::ImportId::from_u32(provider.subject)),
                        absolute: false,
                    }),
                    ProviderKind::Absolute | ProviderKind::LinkerDefined => Ok(ResolvedTarget {
                        section: None,
                        import: None,
                        absolute: true,
                    }),
                    ProviderKind::ArchiveMember => Err(error!(
                        "selected relocation target still resolves to an archive member"
                    )),
                };
            }
            let Some(fallback) = entry.weak_fallback() else {
                return Ok(ResolvedTarget::default());
            };
            name = fallback;
        }
        Err(error!("cycle in weak symbol fallbacks"))
    }

    fn resolve_occurrence(
        &self,
        symbols: &SymbolDb,
        relocation: RelocationRecord,
    ) -> Result<ResolvedTarget> {
        // Keep target validation at the live-edge boundary. In particular, malformed targets in
        // discarded sections never cross `relocation_target` and remain non-diagnostic.
        let symbol = self.ir.relocation_target(relocation)?;
        if let Some(section) = symbol.section.get() {
            return Ok(ResolvedTarget {
                section: Some(section),
                import: None,
                absolute: false,
            });
        }
        self.resolve_name(symbols, symbol.name)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ResolvedTarget {
    section: Option<SectionId>,
    import: Option<super::pe_ir::ImportId>,
    absolute: bool,
}

impl EventDrivenGc for DenseEventGc<'_, '_> {
    type Error = crate::error::Error;

    fn collect(&mut self, input: GcInput<'_>) -> Result<GcOutput> {
        let section_count = usize::try_from(input.section_count)
            .context("PE section count does not fit in usize")?;
        ensure!(
            section_count == self.ir.sections.len(),
            "GC section count differs from dense IR"
        );
        ensure!(
            std::ptr::eq(input.relocations, &raw const self.ir.relocations),
            "GC relocation CSR differs from dense IR"
        );
        ensure!(
            input.relocations.is_well_formed(section_count),
            "invalid relocation CSR"
        );

        count_hot_allocations(7);
        let mut redirect_targets = (0..input.section_count)
            .map(SectionId::from_u32)
            .collect::<Vec<_>>();
        let mut redirects = Vec::new();
        let mut associative_heads = vec![u32::MAX; section_count];
        let mut associative_tails = vec![u32::MAX; section_count];
        let mut associative_targets = Vec::new();
        let mut associative_next = Vec::new();
        for event in input.events {
            match *event {
                GcEvent::Redirect { from, to } => {
                    ensure!(
                        from.index() < section_count && to.index() < section_count,
                        "COMDAT redirect section is outside dense IR"
                    );
                    let old = redirect_targets[from.index()];
                    ensure!(
                        old == from || old == to,
                        "conflicting COMDAT section redirects"
                    );
                    if old == from {
                        redirect_targets[from.index()] = to;
                        redirects.push(SectionRedirect { from, to });
                    }
                }
                GcEvent::AssociativeEdge { parent, child } => {
                    ensure!(
                        parent.index() < section_count && child.index() < section_count,
                        "associative COMDAT section is outside dense IR"
                    );
                    let edge = u32::try_from(associative_targets.len())
                        .context("too many associative COMDAT edges")?;
                    associative_targets.push(child);
                    associative_next.push(u32::MAX);
                    let tail = &mut associative_tails[parent.index()];
                    if *tail == u32::MAX {
                        associative_heads[parent.index()] = edge;
                    } else {
                        associative_next[*tail as usize] = edge;
                    }
                    *tail = edge;
                }
                _ => {}
            }
        }

        // Resolve redirect chains once. Later consumers perform one dense lookup, not hash-table
        // lookup plus repeated redirect chasing.
        for start in 0..section_count {
            let mut node = SectionId::from_u32(start as u32);
            for _ in 0..=redirects.len() {
                let next = redirect_targets[node.index()];
                if next == node {
                    redirect_targets[start] = node;
                    break;
                }
                node = next;
            }
            ensure!(
                redirect_targets[node.index()] == node,
                "cycle in COMDAT section redirects"
            );
        }

        let mut group_by_section = vec![u32::MAX; section_count];
        for (group_index, group) in input.groups.iter().enumerate() {
            ensure!(
                group.leader.index() < section_count,
                "invalid COMDAT group leader"
            );
            let start = group.member_start as usize;
            let end = start
                .checked_add(group.member_len as usize)
                .context("COMDAT member range overflow")?;
            let members = input
                .group_members
                .get(start..end)
                .context("COMDAT member range is out of bounds")?;
            for &member in members {
                ensure!(
                    member.index() < section_count,
                    "invalid COMDAT group member"
                );
                let slot = &mut group_by_section[member.index()];
                ensure!(
                    *slot == u32::MAX || *slot == group_index as u32,
                    "section belongs to multiple COMDAT groups"
                );
                *slot = group_index as u32;
            }
        }

        let mut live_bits = vec![0u64; section_count.div_ceil(64)];
        let mut visitation_order = Vec::new();
        let mut pending = VecDeque::new();
        let mark = |section: SectionId,
                    live_bits: &mut [u64],
                    pending: &mut VecDeque<SectionId>,
                    visitation_order: &mut Vec<SectionId>|
         -> Result<()> {
            let canonical = *redirect_targets
                .get(section.index())
                .context("live section is outside dense IR")?;
            let word = canonical.index() / 64;
            let mask = 1u64 << (canonical.index() % 64);
            if live_bits[word] & mask == 0 {
                live_bits[word] |= mask;
                pending.push_back(canonical);
                visitation_order.push(canonical);
            }
            Ok(())
        };

        for event in input.events {
            match *event {
                GcEvent::RootSection { section, .. } => {
                    mark(section, &mut live_bits, &mut pending, &mut visitation_order)?;
                }
                GcEvent::RootSymbol { name, .. } => {
                    if let Some(section) = self.resolve_name(input.symbols, name)?.section {
                        mark(section, &mut live_bits, &mut pending, &mut visitation_order)?;
                    }
                }
                // Dense CSR is authoritative. RelocationEdge remains in the frozen event enum so
                // producers can preserve diagnostic event logs without building another graph.
                GcEvent::RelocationEdge { .. }
                | GcEvent::AssociativeEdge { .. }
                | GcEvent::Redirect { .. } => {}
            }
        }

        let mut referenced_imports = BTreeSet::new();
        let mut dir64_needs = Vec::new();
        while let Some(section) = pending.pop_front() {
            let group = group_by_section[section.index()];
            if group != u32::MAX {
                let group = &input.groups[group as usize];
                let start = group.member_start as usize;
                let end = start + group.member_len as usize;
                for &member in &input.group_members[start..end] {
                    mark(member, &mut live_bits, &mut pending, &mut visitation_order)?;
                }
            }

            let mut edge = associative_heads[section.index()];
            while edge != u32::MAX {
                mark(
                    associative_targets[edge as usize],
                    &mut live_bits,
                    &mut pending,
                    &mut visitation_order,
                )?;
                edge = associative_next[edge as usize];
            }

            let relocations = input
                .relocations
                .for_section(section)
                .context("live section has no relocation CSR row")?;
            for relocation in relocations {
                let target = self.resolve_occurrence(input.symbols, *relocation)?;
                if relocation.typ == 1 && !target.absolute {
                    dir64_needs.push(Dir64Need {
                        section,
                        offset: relocation.offset,
                    });
                }
                if let Some(import) = target.import {
                    referenced_imports.insert(import);
                }
                if let Some(target) = target.section {
                    mark(target, &mut live_bits, &mut pending, &mut visitation_order)?;
                }
            }
        }

        Ok(GcOutput {
            live_bits: live_bits.into_boxed_slice(),
            canonical_sections: redirect_targets.into_boxed_slice(),
            redirects: redirects.into_boxed_slice(),
            visitation_order: visitation_order.into_boxed_slice(),
            referenced_imports: referenced_imports.into_iter().collect(),
            dir64_needs: dir64_needs.into_boxed_slice(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::pe_ir::*;
    use super::super::pe_symbol_db::*;
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
            referenced_imports: Box::new([]),
            dir64_needs: Box::new([]),
        };
        assert!(output.is_live(SectionId::from_u32(3)));
        assert!(!output.is_live(SectionId::from_u32(2)));
        assert_eq!(
            output.canonical(SectionId::from_u32(3)),
            Some(SectionId::from_u32(3))
        );
        assert!(output.canonical(SectionId::from_u32(4)).is_none());
    }

    #[test]
    fn dense_gc_walks_csr_groups_imports_dir64_and_redirects() {
        let sections = (0..4)
            .map(|index| SectionRecord {
                object: ObjectId::from_u32(0),
                raw_index: index + 1,
                name: NameId::from_u32(0),
                data: None,
                size: 8,
                alignment: 1,
                characteristics: 0,
                contents: if index == 0 {
                    SectionContents::Code
                } else {
                    SectionContents::Data
                },
                comdat_selection: 0,
                associative_section: OptionalSectionId::NONE,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let symbols = vec![
            SymbolRecord {
                object: ObjectId::from_u32(0),
                raw_index: 0,
                name: NameId::from_u32(0),
                section: OptionalSectionId::some(SectionId::from_u32(1)),
                value: 0,
                size: 0,
                flags: 0,
                storage_class: 0,
                typ: 0,
                weak_default: OptionalSymbolId::NONE,
                diagnostic: SymbolDiagnostic::None,
            },
            SymbolRecord {
                object: ObjectId::from_u32(0),
                raw_index: 1,
                name: NameId::from_u32(1),
                section: OptionalSectionId::NONE,
                value: 0,
                size: 0,
                flags: 0,
                storage_class: 0,
                typ: 0,
                weak_default: OptionalSymbolId::NONE,
                diagnostic: SymbolDiagnostic::None,
            },
            SymbolRecord {
                object: ObjectId::from_u32(0),
                raw_index: 2,
                name: NameId::from_u32(2),
                section: OptionalSectionId::NONE,
                value: 0,
                size: 0,
                flags: 0,
                storage_class: 0,
                typ: 0,
                weak_default: OptionalSymbolId::NONE,
                diagnostic: SymbolDiagnostic::None,
            },
        ]
        .into_boxed_slice();
        let relocations = RelocationCsr {
            starts: vec![0, 3, 3, 3, 3].into_boxed_slice(),
            records: vec![
                RelocationRecord {
                    offset: 0,
                    target: SymbolId::from_u32(0),
                    typ: 4,
                    flags: 0,
                },
                RelocationRecord {
                    offset: 4,
                    target: SymbolId::from_u32(1),
                    typ: 1,
                    flags: 0,
                },
                RelocationRecord {
                    offset: 6,
                    target: SymbolId::from_u32(2),
                    typ: 1,
                    flags: 0,
                },
            ]
            .into_boxed_slice(),
        };
        let ir = PeIr {
            sources: SourceFiles::new(vec![b""]),
            names: (0..3)
                .map(|_| NameRecord {
                    source: Some(SourceRange {
                        file: FileId::from_u32(0),
                        start: 0,
                        len: 0,
                    }),
                    hash: 0,
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            objects: vec![ObjectRecord {
                file: FileId::from_u32(0),
                sections: DenseRange::new(0, 4),
                symbols: DenseRange::new(0, 3),
                input_ordinal: 0,
            }]
            .into_boxed_slice(),
            sections,
            symbols,
            relocations,
        };
        let database = SymbolDb {
            entries: vec![
                SymbolEntry {
                    resolution: Resolution::UNRESOLVED,
                    provider_start: 0,
                    provider_len: 0,
                    weak_fallback: SymbolEntry::NO_FALLBACK,
                },
                SymbolEntry {
                    resolution: Resolution::resolved(
                        ProviderId::from_u32(0),
                        BindingStrength::Strong,
                    ),
                    provider_start: 0,
                    provider_len: 1,
                    weak_fallback: SymbolEntry::NO_FALLBACK,
                },
                SymbolEntry {
                    resolution: Resolution::resolved(
                        ProviderId::from_u32(1),
                        BindingStrength::Strong,
                    ),
                    provider_start: 1,
                    provider_len: 1,
                    weak_fallback: SymbolEntry::NO_FALLBACK,
                },
            ]
            .into_boxed_slice(),
            providers: vec![
                ProviderRecord::import(ImportLibraryId::from_u32(0), ImportId::from_u32(4)),
                ProviderRecord::absolute(0, false),
            ]
            .into_boxed_slice(),
            absolute_values: vec![0].into_boxed_slice(),
        };
        let events = [
            GcEvent::Redirect {
                from: SectionId::from_u32(3),
                to: SectionId::from_u32(1),
            },
            GcEvent::AssociativeEdge {
                parent: SectionId::from_u32(1),
                child: SectionId::from_u32(2),
            },
            GcEvent::RootSection {
                section: SectionId::from_u32(0),
                reason: RootReason::NonComdat,
            },
        ];
        let groups = [SectionGroup {
            leader: SectionId::from_u32(1),
            member_start: 0,
            member_len: 2,
        }];
        let members = [SectionId::from_u32(1), SectionId::from_u32(2)];
        let mut collector = DenseEventGc::new(&ir);
        let output = collector
            .collect(GcInput {
                section_count: 4,
                events: &events,
                groups: &groups,
                group_members: &members,
                relocations: &ir.relocations,
                symbols: &database,
            })
            .unwrap();

        assert!(output.is_live(SectionId::from_u32(0)));
        assert!(output.is_live(SectionId::from_u32(1)));
        assert!(output.is_live(SectionId::from_u32(2)));
        assert!(!output.is_live(SectionId::from_u32(3)));
        assert_eq!(
            output.canonical(SectionId::from_u32(3)),
            Some(SectionId::from_u32(1))
        );
        assert_eq!(&*output.referenced_imports, &[ImportId::from_u32(4)]);
        assert_eq!(
            &*output.dir64_needs,
            &[Dir64Need {
                section: SectionId::from_u32(0),
                offset: 4,
            }]
        );
        assert_eq!(
            &*output.visitation_order,
            &[
                SectionId::from_u32(0),
                SectionId::from_u32(1),
                SectionId::from_u32(2)
            ]
        );
    }

    #[test]
    fn associative_children_preserve_event_order() {
        let sections = (0..4)
            .map(|index| SectionRecord {
                object: ObjectId::from_u32(0),
                raw_index: index + 1,
                name: NameId::from_u32(0),
                data: None,
                size: 1,
                alignment: 1,
                characteristics: 0,
                contents: SectionContents::Data,
                comdat_selection: 0,
                associative_section: OptionalSectionId::NONE,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let ir = PeIr {
            sources: SourceFiles::new(vec![b""]),
            names: vec![NameRecord {
                source: Some(SourceRange {
                    file: FileId::from_u32(0),
                    start: 0,
                    len: 0,
                }),
                hash: 0,
            }]
            .into_boxed_slice(),
            objects: vec![ObjectRecord {
                file: FileId::from_u32(0),
                sections: DenseRange::new(0, 4),
                symbols: DenseRange::new(0, 0),
                input_ordinal: 0,
            }]
            .into_boxed_slice(),
            sections,
            symbols: Box::new([]),
            relocations: RelocationCsr {
                starts: vec![0, 0, 0, 0, 0].into_boxed_slice(),
                records: Box::new([]),
            },
        };
        let database = SymbolDb {
            entries: Box::new([]),
            providers: Box::new([]),
            absolute_values: Box::new([]),
        };
        let events = [
            GcEvent::AssociativeEdge {
                parent: SectionId::from_u32(0),
                child: SectionId::from_u32(1),
            },
            GcEvent::AssociativeEdge {
                parent: SectionId::from_u32(0),
                child: SectionId::from_u32(2),
            },
            GcEvent::AssociativeEdge {
                parent: SectionId::from_u32(0),
                child: SectionId::from_u32(3),
            },
            GcEvent::RootSection {
                section: SectionId::from_u32(0),
                reason: RootReason::NonComdat,
            },
        ];
        let mut collector = DenseEventGc::new(&ir);
        let output = collector
            .collect(GcInput {
                section_count: 4,
                events: &events,
                groups: &[],
                group_members: &[],
                relocations: &ir.relocations,
                symbols: &database,
            })
            .unwrap();

        assert_eq!(
            &*output.visitation_order,
            &[
                SectionId::from_u32(0),
                SectionId::from_u32(1),
                SectionId::from_u32(2),
                SectionId::from_u32(3),
            ]
        );
    }

    #[test]
    fn malformed_relocation_target_is_diagnostic_only_when_source_is_live() {
        let sections = (0..2)
            .map(|index| SectionRecord {
                object: ObjectId::from_u32(0),
                raw_index: index + 1,
                name: NameId::from_u32(0),
                data: None,
                size: 1,
                alignment: 1,
                characteristics: 0,
                contents: SectionContents::Data,
                comdat_selection: 0,
                associative_section: OptionalSectionId::NONE,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let ir = PeIr {
            sources: SourceFiles::new(vec![b""]),
            names: vec![NameRecord {
                source: Some(SourceRange {
                    file: FileId::from_u32(0),
                    start: 0,
                    len: 0,
                }),
                hash: 0,
            }]
            .into_boxed_slice(),
            objects: vec![ObjectRecord {
                file: FileId::from_u32(0),
                sections: DenseRange::new(0, 2),
                symbols: DenseRange::new(0, 1),
                input_ordinal: 0,
            }]
            .into_boxed_slice(),
            sections,
            symbols: vec![SymbolRecord {
                object: ObjectId::from_u32(0),
                raw_index: 17,
                name: NameId::from_u32(0),
                section: OptionalSectionId::NONE,
                value: 0,
                size: 0,
                flags: 0,
                storage_class: 0,
                typ: 0,
                weak_default: OptionalSymbolId::NONE,
                diagnostic: SymbolDiagnostic::InvalidRelocationTarget,
            }]
            .into_boxed_slice(),
            relocations: RelocationCsr {
                // Section 0 has no edges; section 1 owns the malformed edge.
                starts: vec![0, 0, 1].into_boxed_slice(),
                records: vec![RelocationRecord {
                    offset: 0,
                    target: SymbolId::from_u32(0),
                    typ: 4,
                    flags: 0,
                }]
                .into_boxed_slice(),
            },
        };
        let database = SymbolDb {
            entries: Box::new([]),
            providers: Box::new([]),
            absolute_values: Box::new([]),
        };
        let discarded_events = [GcEvent::RootSection {
            section: SectionId::from_u32(0),
            reason: RootReason::NonComdat,
        }];
        DenseEventGc::new(&ir)
            .collect(GcInput {
                section_count: 2,
                events: &discarded_events,
                groups: &[],
                group_members: &[],
                relocations: &ir.relocations,
                symbols: &database,
            })
            .unwrap();

        let live_events = [GcEvent::RootSection {
            section: SectionId::from_u32(1),
            reason: RootReason::NonComdat,
        }];
        let error = DenseEventGc::new(&ir)
            .collect(GcInput {
                section_count: 2,
                events: &live_events,
                groups: &[],
                group_members: &[],
                relocations: &ir.relocations,
                symbols: &database,
            })
            .unwrap_err();
        assert!(format!("{error:?}").contains("Invalid COFF relocation symbol 17"));
    }
}
