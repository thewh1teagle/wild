//! Event-driven section-GC boundary for the final PE architecture.

#![allow(dead_code)]

use super::pe_ir::NameId;
use super::pe_ir::PeIr;
use super::pe_ir::RelocationCsr;
use super::pe_ir::RelocationRecord;
use super::pe_ir::ResolvedSymbolTargets;
use super::pe_ir::ResolvedTargetKind;
use super::pe_ir::SectionId;
use super::pe_ir::SymbolId;
use super::pe_symbol_db::ProviderKind;
use super::pe_symbol_db::ResolutionState;
use super::pe_symbol_db::SymbolDb;
use crate::ensure;
use crate::error;
use crate::error::Context;
use crate::error::Result;
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::collections::VecDeque;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

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
    Discard {
        section: SectionId,
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
    pub(super) referenced_import_names: Box<[NameId]>,
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
    alternate_targets: &'ir [u32],
    resolved: Option<&'ir ResolvedSymbolTargets>,
}

pub(super) struct ProductionGcInput<'a> {
    pub(super) redirect_targets: Vec<SectionId>,
    pub(super) discarded: Vec<bool>,
    pub(super) is_comdat: &'a [bool],
    pub(super) root_names: &'a [NameId],
    /// Authoritative `CompactComdatAnalysis` CSR. Every dense section belongs to exactly one
    /// group, and associative descendants are already coalesced with their ultimate leader.
    pub(super) group_starts: &'a [u32],
    pub(super) group_members: &'a [usize],
    pub(super) group_by_section: &'a [usize],
}

impl<'ir, 'data> DenseEventGc<'ir, 'data> {
    const PREDECODE_RELOCATIONS_MIN: usize = 500_000;
    const PREDECODE_KIND_SHIFT: u32 = 29;
    const PREDECODE_TARGET_MASK: u32 = (1 << Self::PREDECODE_KIND_SHIFT) - 1;
    const PREDECODE_IMPORT: u32 = 1 << Self::PREDECODE_KIND_SHIFT;
    const PREDECODE_NONE: u32 = 2 << Self::PREDECODE_KIND_SHIFT;
    const PREDECODE_DIAGNOSTIC: u32 = 3 << Self::PREDECODE_KIND_SHIFT;

    pub(super) fn new(ir: &'ir PeIr<'data>, alternate_targets: &'ir [u32]) -> Self {
        Self {
            ir,
            alternate_targets,
            resolved: None,
        }
    }

    pub(super) fn new_resolved(
        ir: &'ir PeIr<'data>,
        alternate_targets: &'ir [u32],
        resolved: &'ir ResolvedSymbolTargets,
    ) -> Self {
        Self {
            ir,
            alternate_targets,
            resolved: Some(resolved),
        }
    }

    fn unpack_target(target: super::pe_ir::ResolvedTarget) -> Result<ResolvedTarget> {
        Ok(match target.kind {
            ResolvedTargetKind::Section => ResolvedTarget {
                section: Some(SectionId::from_u32(target.target)),
                import: None,
                import_name: None,
                absolute: false,
            },
            ResolvedTargetKind::Import => ResolvedTarget {
                section: None,
                import: Some(super::pe_ir::ImportId::from_u32(target.value)),
                import_name: Some(NameId::from_u32(target.target)),
                absolute: false,
            },
            ResolvedTargetKind::Absolute => ResolvedTarget {
                section: None,
                import: None,
                import_name: None,
                absolute: true,
            },
            ResolvedTargetKind::Name => ResolvedTarget::default(),
            ResolvedTargetKind::Diagnostic => {
                return Err(error!("Invalid COFF relocation symbol {}", target.target));
            }
        })
    }

    #[inline(always)]
    fn unpack_symbol_target(
        resolved: &ResolvedSymbolTargets,
        relocation: RelocationRecord,
    ) -> Result<ResolvedTarget> {
        if relocation.has_invalid_target() {
            return Err(error!(
                "Invalid COFF relocation symbol {}",
                relocation.target.get()
            ));
        }
        // Section GC never consumes a symbol's section-relative value. Read only the kind and
        // target columns here; relocation application retains the full three-column lookup.
        let (kind, target) = resolved
            .kind_target(relocation.target)
            .context("relocation target is outside resolved symbol table")?;
        Ok(match kind {
            ResolvedTargetKind::Section => ResolvedTarget {
                section: Some(SectionId::from_u32(target)),
                import: None,
                import_name: None,
                absolute: false,
            },
            ResolvedTargetKind::Import => ResolvedTarget {
                section: None,
                // Load the value column only for the rare import edge. Section edges, which
                // dominate production GC, avoid that extra random access entirely.
                import: Some(super::pe_ir::ImportId::from_u32(
                    resolved
                        .value(relocation.target)
                        .context("import target is outside resolved symbol table")?,
                )),
                import_name: Some(NameId::from_u32(target)),
                absolute: false,
            },
            ResolvedTargetKind::Absolute => ResolvedTarget {
                section: None,
                import: None,
                import_name: None,
                absolute: true,
            },
            ResolvedTargetKind::Name => ResolvedTarget::default(),
            ResolvedTargetKind::Diagnostic => {
                return Err(error!("Invalid COFF relocation symbol {}", target));
            }
        })
    }

    #[inline(always)]
    fn predecode_relocation_target(
        resolved: &ResolvedSymbolTargets,
        relocation: RelocationRecord,
    ) -> u32 {
        if relocation.has_invalid_target() {
            return Self::PREDECODE_DIAGNOSTIC;
        }
        match resolved.kind_target(relocation.target) {
            Some((ResolvedTargetKind::Section, target)) => target,
            Some((ResolvedTargetKind::Import, name)) => Self::PREDECODE_IMPORT | name,
            Some((ResolvedTargetKind::Absolute | ResolvedTargetKind::Name, _)) => {
                Self::PREDECODE_NONE
            }
            Some((ResolvedTargetKind::Diagnostic, _)) | None => Self::PREDECODE_DIAGNOSTIC,
        }
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
                            import_name: None,
                            absolute: false,
                        })
                    }
                    ProviderKind::Import => Ok(ResolvedTarget {
                        section: None,
                        import: Some(super::pe_ir::ImportId::from_u32(provider.subject)),
                        import_name: Some(name),
                        absolute: false,
                    }),
                    ProviderKind::Absolute | ProviderKind::LinkerDefined => Ok(ResolvedTarget {
                        section: None,
                        import: None,
                        import_name: None,
                        absolute: true,
                    }),
                    ProviderKind::ArchiveMember => Err(error!(
                        "selected relocation target still resolves to an archive member"
                    )),
                };
            }
            if let Some(fallback) = entry.weak_fallback() {
                name = fallback;
                continue;
            }
            let alternate = self
                .alternate_targets
                .get(name.index())
                .copied()
                .unwrap_or(u32::MAX);
            if alternate == u32::MAX {
                return Ok(ResolvedTarget::default());
            }
            name = NameId::from_u32(alternate);
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
                import_name: None,
                absolute: false,
            });
        }
        self.resolve_name(symbols, symbol.name)
    }

    pub(super) fn collect_production(&self, mut input: ProductionGcInput<'_>) -> Result<GcOutput> {
        let mut collect_phase = crate::pe_timing_guard!("PE dense GC: Direct collect");
        let resolved = self
            .resolved
            .context("production GC requires resolved relocations")?;
        let section_count = self.ir.sections.len();
        collect_phase
            .0
            .add(crate::timing::PeMetric::Sections, section_count);
        collect_phase.0.add(
            crate::timing::PeMetric::Relocations,
            self.ir.relocations.records.len(),
        );
        collect_phase.0.add(
            crate::timing::PeMetric::Groups,
            input.group_starts.len().saturating_sub(1),
        );
        ensure!(
            input.redirect_targets.len() == section_count
                && input.discarded.len() == section_count
                && input.is_comdat.len() == section_count
                && input.group_by_section.len() == section_count,
            "production GC dense array cardinality mismatch"
        );
        let mut redirects = Vec::new();
        for (index, &target) in input.redirect_targets.iter().enumerate() {
            let from = SectionId::from_u32(index as u32);
            ensure!(
                target.index() < section_count,
                "invalid production GC redirect"
            );
            if from != target {
                redirects.push(SectionRedirect { from, to: target });
            }
        }
        for start in 0..section_count {
            let mut node = SectionId::from_u32(start as u32);
            for _ in 0..=redirects.len() {
                let next = input.redirect_targets[node.index()];
                if next == node {
                    input.redirect_targets[start] = node;
                    break;
                }
                node = next;
            }
            ensure!(
                input.redirect_targets[node.index()] == node,
                "cycle in COMDAT section redirects"
            );
        }

        ensure!(
            input
                .group_starts
                .last()
                .is_some_and(|&end| end as usize == input.group_members.len()),
            "production GC group CSR is malformed"
        );

        let mut live_bits = vec![0u64; section_count.div_ceil(64)];
        let mut pending = VecDeque::new();
        let mut visited_sections = 0usize;
        let mark = |section: SectionId,
                    live_bits: &mut [u64],
                    pending: &mut VecDeque<SectionId>,
                    visited_sections: &mut usize|
         -> Result<()> {
            let canonical = *input
                .redirect_targets
                .get(section.index())
                .context("live section is outside dense IR")?;
            if input.discarded[canonical.index()] {
                return Ok(());
            }
            let word = canonical.index() / 64;
            let mask = 1u64 << (canonical.index() % 64);
            if live_bits[word] & mask == 0 {
                live_bits[word] |= mask;
                pending.push_back(canonical);
                *visited_sections += 1;
            }
            Ok(())
        };
        let mut referenced_import_bits = vec![0u64; resolved.names.len().div_ceil(64)];
        let mark_import = |name: NameId, bits: &mut [u64]| -> Result<()> {
            let word = bits
                .get_mut(name.index() / 64)
                .context("import name is outside resolved namespace")?;
            *word |= 1u64 << (name.index() % 64);
            Ok(())
        };
        for (index, &is_comdat) in input.is_comdat.iter().enumerate() {
            if !is_comdat {
                mark(
                    SectionId::from_u32(index as u32),
                    &mut live_bits,
                    &mut pending,
                    &mut visited_sections,
                )?;
            }
        }
        for &name in input.root_names {
            let target = Self::unpack_target(
                resolved
                    .name(name)
                    .context("GC root name is outside resolved namespace")?,
            )?;
            if let Some(name) = target.import_name {
                mark_import(name, &mut referenced_import_bits)?;
            }
            if let Some(section) = target.section {
                mark(section, &mut live_bits, &mut pending, &mut visited_sections)?;
            }
        }

        let mut traversal_phase = crate::pe_timing_guard!("PE dense GC: Traverse resolved CSR");
        let instrumentation_enabled = traversal_phase.0.enabled();
        let mut relocation_count = 0usize;
        // Large Rust links revisit enough scattered symbol-target entries during GC that one
        // parallel, linear pass is cheaper than resolving each live relocation in queue order.
        // The compact stream has the same CSR offsets as `records`; diagnostics remain deferred
        // until their source section becomes live. Small links retain the lower-overhead path.
        let predecoded_targets = (self.ir.relocations.records.len()
            >= Self::PREDECODE_RELOCATIONS_MIN
            && rayon::current_num_threads() > 1)
            .then(|| {
                self.ir
                    .relocations
                    .records
                    .par_iter()
                    .map(|&relocation| Self::predecode_relocation_target(resolved, relocation))
                    .collect::<Vec<_>>()
            });
        const PARALLEL_FRONTIER_MIN: usize = 8192;
        while !pending.is_empty() {
            if rayon::current_num_threads() > 1 && pending.len() >= PARALLEL_FRONTIER_MIN {
                let frontier = pending.drain(..).collect::<Vec<_>>();
                let chunk_size = frontier
                    .len()
                    .div_ceil(rayon::current_num_threads().saturating_mul(2))
                    .max(1024);
                let parallel_live = live_bits
                    .iter()
                    .copied()
                    .map(AtomicU64::new)
                    .collect::<Vec<_>>();
                let parallel_imports = referenced_import_bits
                    .iter()
                    .copied()
                    .map(AtomicU64::new)
                    .collect::<Vec<_>>();
                let mark_parallel = |section: SectionId| -> Result<()> {
                    let canonical = *input
                        .redirect_targets
                        .get(section.index())
                        .context("live section is outside dense IR")?;
                    if input.discarded[canonical.index()] {
                        return Ok(());
                    }
                    let word = parallel_live
                        .get(canonical.index() / 64)
                        .context("canonical live section is outside dense IR")?;
                    word.fetch_or(1u64 << (canonical.index() % 64), Ordering::Relaxed);
                    Ok(())
                };
                let mark_import_parallel = |name: NameId| -> Result<()> {
                    let word = parallel_imports
                        .get(name.index() / 64)
                        .context("import name is outside resolved namespace")?;
                    word.fetch_or(1u64 << (name.index() % 64), Ordering::Relaxed);
                    Ok(())
                };
                let chunks = frontier
                    .par_chunks(chunk_size)
                    .map(|sections| {
                        let mut scanned_relocations = 0usize;
                        for &section in sections {
                            let group = input.group_by_section[section.index()];
                            let start = input.group_starts[group] as usize;
                            let end = input.group_starts[group + 1] as usize;
                            for &member in &input.group_members[start..end] {
                                mark_parallel(SectionId::from_u32(member as u32))?;
                            }
                            let relocations = self
                                .ir
                                .relocations
                                .for_section(section)
                                .context("live section has no relocation CSR row")?;
                            scanned_relocations += relocations.len();
                            if let Some(predecoded_targets) = predecoded_targets.as_deref() {
                                let range = self
                                    .ir
                                    .relocations
                                    .range(section)
                                    .context("live section has no relocation CSR row")?;
                                for (relocation, &target) in
                                    relocations.iter().zip(&predecoded_targets[range])
                                {
                                    match target >> Self::PREDECODE_KIND_SHIFT {
                                        0 => mark_parallel(SectionId::from_u32(target))?,
                                        1 => mark_import_parallel(NameId::from_u32(
                                            target & Self::PREDECODE_TARGET_MASK,
                                        ))?,
                                        2 => {}
                                        _ => {
                                            Self::unpack_symbol_target(resolved, *relocation)?;
                                        }
                                    }
                                }
                            } else {
                                for relocation in relocations {
                                    let target = Self::unpack_symbol_target(resolved, *relocation)?;
                                    if let Some(name) = target.import_name {
                                        mark_import_parallel(name)?;
                                    }
                                    if let Some(section) = target.section {
                                        mark_parallel(section)?;
                                    }
                                }
                            }
                        }
                        Ok(scanned_relocations)
                    })
                    .collect::<Vec<Result<_>>>();
                for chunk in chunks {
                    let scanned_relocations = chunk?;
                    if instrumentation_enabled {
                        relocation_count += scanned_relocations;
                    }
                }
                for (bits, parallel) in referenced_import_bits.iter_mut().zip(&parallel_imports) {
                    *bits = parallel.load(Ordering::Relaxed);
                }
                for (word_index, (bits, parallel)) in
                    live_bits.iter_mut().zip(&parallel_live).enumerate()
                {
                    let updated = parallel.load(Ordering::Relaxed);
                    let mut added = updated & !*bits;
                    *bits = updated;
                    while added != 0 {
                        let bit = added.trailing_zeros() as usize;
                        pending.push_back(SectionId::from_u32(
                            (word_index * 64 + bit) as u32,
                        ));
                        visited_sections += 1;
                        added &= added - 1;
                    }
                }
                continue;
            }

            let section = pending
                .pop_front()
                .expect("non-empty PE GC frontier has a section");
            let group = input.group_by_section[section.index()];
            let start = input.group_starts[group] as usize;
            let end = input.group_starts[group + 1] as usize;
            for &member in &input.group_members[start..end] {
                mark(
                    SectionId::from_u32(member as u32),
                    &mut live_bits,
                    &mut pending,
                    &mut visited_sections,
                )?;
            }
            let relocations = self
                .ir
                .relocations
                .for_section(section)
                .context("live section has no relocation CSR row")?;
            if instrumentation_enabled {
                relocation_count += relocations.len();
            }
            if let Some(predecoded_targets) = predecoded_targets.as_deref() {
                let range = self
                    .ir
                    .relocations
                    .range(section)
                    .context("live section has no relocation CSR row")?;
                for (relocation, &target) in relocations.iter().zip(&predecoded_targets[range]) {
                    match target >> Self::PREDECODE_KIND_SHIFT {
                        0 => mark(
                            SectionId::from_u32(target),
                            &mut live_bits,
                            &mut pending,
                            &mut visited_sections,
                        )?,
                        1 => {
                            mark_import(
                                NameId::from_u32(target & Self::PREDECODE_TARGET_MASK),
                                &mut referenced_import_bits,
                            )?;
                        }
                        2 => {}
                        _ => {
                            Self::unpack_symbol_target(resolved, *relocation)?;
                        }
                    }
                }
            } else {
                for relocation in relocations {
                    let target = Self::unpack_symbol_target(resolved, *relocation)?;
                    if let Some(name) = target.import_name {
                        mark_import(name, &mut referenced_import_bits)?;
                    }
                    if let Some(target) = target.section {
                        mark(target, &mut live_bits, &mut pending, &mut visited_sections)?;
                    }
                }
            }
        }
        let mut referenced_import_names = Vec::new();
        for (word_index, &bits) in referenced_import_bits.iter().enumerate() {
            let mut bits = bits;
            while bits != 0 {
                let bit = bits.trailing_zeros() as usize;
                referenced_import_names.push(NameId::from_u32((word_index * 64 + bit) as u32));
                bits &= bits - 1;
            }
        }
        if instrumentation_enabled {
            traversal_phase
                .0
                .add(crate::timing::PeMetric::Sections, visited_sections);
            traversal_phase
                .0
                .add(crate::timing::PeMetric::Relocations, relocation_count);
            traversal_phase
                .0
                .add(crate::timing::PeMetric::QueuePushes, visited_sections);
            traversal_phase.0.add(
                crate::timing::PeMetric::Imports,
                referenced_import_names.len(),
            );
        }
        Ok(GcOutput {
            live_bits: live_bits.into_boxed_slice(),
            canonical_sections: input.redirect_targets.into_boxed_slice(),
            redirects: redirects.into_boxed_slice(),
            // Production consumers use only dense liveness and canonical import names. These
            // compatibility snapshots remain populated by the general event collector below.
            visitation_order: Box::new([]),
            referenced_imports: Box::new([]),
            referenced_import_names: referenced_import_names.into_boxed_slice(),
            dir64_needs: Box::new([]),
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ResolvedTarget {
    section: Option<SectionId>,
    import: Option<super::pe_ir::ImportId>,
    import_name: Option<NameId>,
    absolute: bool,
}

impl EventDrivenGc for DenseEventGc<'_, '_> {
    type Error = crate::error::Error;

    fn collect(&mut self, input: GcInput<'_>) -> Result<GcOutput> {
        let mut collect_phase = crate::pe_timing_guard!("PE dense GC: Collect");
        collect_phase.0.add(
            crate::timing::PeMetric::Sections,
            input.section_count as usize,
        );
        collect_phase
            .0
            .add(crate::timing::PeMetric::Events, input.events.len());
        collect_phase
            .0
            .add(crate::timing::PeMetric::Groups, input.groups.len());
        collect_phase.0.add(
            crate::timing::PeMetric::Relocations,
            input.relocations.records.len(),
        );
        collect_phase
            .0
            .add(crate::timing::PeMetric::Names, input.symbols.entries.len());
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

        count_hot_allocations(8);
        let mut redirect_phase =
            crate::pe_timing_guard!("PE dense GC: Build redirects and associations");
        redirect_phase
            .0
            .add(crate::timing::PeMetric::Events, input.events.len());
        redirect_phase
            .0
            .add(crate::timing::PeMetric::Sections, section_count);
        let mut redirect_targets = (0..input.section_count)
            .map(SectionId::from_u32)
            .collect::<Vec<_>>();
        let mut redirects = Vec::new();
        let mut associative_heads = vec![u32::MAX; section_count];
        let mut associative_tails = vec![u32::MAX; section_count];
        let mut associative_targets = Vec::new();
        let mut associative_next = Vec::new();
        let mut discarded = vec![false; section_count];
        let mut referenced_imports = BTreeSet::new();
        let mut referenced_import_names = BTreeSet::new();
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
                GcEvent::Discard { section } => {
                    let slot = discarded
                        .get_mut(section.index())
                        .context("discarded COMDAT section is outside dense IR")?;
                    *slot = true;
                }
                _ => {}
            }
        }
        redirect_phase
            .0
            .add(crate::timing::PeMetric::Events, redirects.len());
        drop(redirect_phase);

        // Resolve redirect chains once. Later consumers perform one dense lookup, not hash-table
        // lookup plus repeated redirect chasing.
        let mut compression_phase = crate::pe_timing_guard!("PE dense GC: Compress redirects");
        compression_phase
            .0
            .add(crate::timing::PeMetric::Sections, section_count);
        compression_phase
            .0
            .add(crate::timing::PeMetric::Events, redirects.len());
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
        drop(compression_phase);

        let mut groups_phase = crate::pe_timing_guard!("PE dense GC: Build groups");
        groups_phase
            .0
            .add(crate::timing::PeMetric::Groups, input.groups.len());
        groups_phase
            .0
            .add(crate::timing::PeMetric::Sections, input.group_members.len());
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
        drop(groups_phase);

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
            if discarded[canonical.index()] {
                return Ok(());
            }
            let word = canonical.index() / 64;
            let mask = 1u64 << (canonical.index() % 64);
            if live_bits[word] & mask == 0 {
                live_bits[word] |= mask;
                pending.push_back(canonical);
                visitation_order.push(canonical);
            }
            Ok(())
        };

        let mut roots_phase = crate::pe_timing_guard!("PE dense GC: Seed roots");
        if roots_phase.0.enabled() {
            let root_events = input
                .events
                .iter()
                .filter(|event| {
                    matches!(
                        event,
                        GcEvent::RootSection { .. } | GcEvent::RootSymbol { .. }
                    )
                })
                .count();
            let root_lookups = input
                .events
                .iter()
                .filter(|event| matches!(event, GcEvent::RootSymbol { .. }))
                .count();
            roots_phase
                .0
                .add(crate::timing::PeMetric::Events, root_events);
            roots_phase
                .0
                .add(crate::timing::PeMetric::Lookups, root_lookups);
        }
        for event in input.events {
            match *event {
                GcEvent::RootSection { section, .. } => {
                    mark(section, &mut live_bits, &mut pending, &mut visitation_order)?;
                }
                GcEvent::RootSymbol { name, .. } => {
                    let target = if let Some(resolved) = self.resolved {
                        Self::unpack_target(
                            resolved
                                .name(name)
                                .context("GC root name is outside resolved namespace")?,
                        )?
                    } else {
                        self.resolve_name(input.symbols, name)?
                    };
                    if let Some(import) = target.import {
                        referenced_imports.insert(import);
                    }
                    if let Some(name) = target.import_name {
                        referenced_import_names.insert(name);
                    }
                    if let Some(section) = target.section {
                        mark(section, &mut live_bits, &mut pending, &mut visitation_order)?;
                    }
                }
                // Dense CSR is authoritative. RelocationEdge remains in the frozen event enum so
                // producers can preserve diagnostic event logs without building another graph.
                GcEvent::RelocationEdge { .. }
                | GcEvent::AssociativeEdge { .. }
                | GcEvent::Redirect { .. }
                | GcEvent::Discard { .. } => {}
            }
        }
        drop(roots_phase);

        let mut traversal_phase = crate::pe_timing_guard!("PE dense GC: Traverse live graph");
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

            if let Some(resolved) = self.resolved {
                let relocations = self
                    .ir
                    .relocations
                    .for_section(section)
                    .context("live section has no relocation CSR row")?;
                for relocation in relocations {
                    let target = Self::unpack_symbol_target(resolved, *relocation)?;
                    if relocation.typ == 1 && !target.absolute {
                        dir64_needs.push(Dir64Need {
                            section,
                            offset: relocation.offset,
                        });
                    }
                    if let Some(import) = target.import {
                        referenced_imports.insert(import);
                    }
                    if let Some(name) = target.import_name {
                        referenced_import_names.insert(name);
                    }
                    if let Some(target) = target.section {
                        mark(target, &mut live_bits, &mut pending, &mut visitation_order)?;
                    }
                }
            } else {
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
                    if let Some(name) = target.import_name {
                        referenced_import_names.insert(name);
                    }
                    if let Some(target) = target.section {
                        mark(target, &mut live_bits, &mut pending, &mut visitation_order)?;
                    }
                }
            }
        }
        if traversal_phase.0.enabled() {
            let visited_relocations = visitation_order
                .iter()
                .filter_map(|&section| input.relocations.range(section))
                .map(|range| range.len())
                .sum();
            traversal_phase
                .0
                .add(crate::timing::PeMetric::Sections, visitation_order.len());
            traversal_phase
                .0
                .add(crate::timing::PeMetric::Relocations, visited_relocations);
            traversal_phase
                .0
                .add(crate::timing::PeMetric::Lookups, visited_relocations);
            traversal_phase
                .0
                .add(crate::timing::PeMetric::QueuePushes, visitation_order.len());
        }
        traversal_phase.0.add(
            crate::timing::PeMetric::Imports,
            referenced_import_names.len(),
        );
        drop(traversal_phase);

        let mut result_phase = crate::pe_timing_guard!("PE dense GC: Materialize result");
        result_phase
            .0
            .add(crate::timing::PeMetric::Sections, visitation_order.len());
        result_phase
            .0
            .add(crate::timing::PeMetric::Events, redirects.len());
        result_phase.0.add(
            crate::timing::PeMetric::Imports,
            referenced_import_names.len(),
        );
        Ok(GcOutput {
            live_bits: live_bits.into_boxed_slice(),
            canonical_sections: redirect_targets.into_boxed_slice(),
            redirects: redirects.into_boxed_slice(),
            visitation_order: visitation_order.into_boxed_slice(),
            referenced_imports: referenced_imports.into_iter().collect(),
            referenced_import_names: referenced_import_names.into_iter().collect(),
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
            referenced_import_names: Box::new([]),
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
    fn production_gc_parallel_frontier_matches_dense_root_set() {
        const SECTION_COUNT: usize = 9000;
        let sections = (0..SECTION_COUNT)
            .map(|index| SectionRecord {
                object: ObjectId::from_u32(0),
                raw_index: u32::try_from(index).unwrap() + 1,
                name: NameId::from_u32(0),
                data: None,
                size: 1,
                alignment: 1,
                characteristics: 0,
                contents: SectionContents::Data,
                comdat_selection: 0,
                associative_section: OptionalSectionId::NONE,
                comdat_leader: OptionalSymbolId::NONE,
                comdat_order: u32::MAX,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let symbols = (0..SECTION_COUNT)
            .map(|index| SymbolRecord {
                object: ObjectId::from_u32(0),
                raw_index: u32::try_from(index).unwrap(),
                name: NameId::from_u32(0),
                section: OptionalSectionId::some(SectionId::from_u32(
                    u32::try_from((index + 1) % SECTION_COUNT).unwrap(),
                )),
                value: 0,
                size: 0,
                flags: 0,
                storage_class: 0,
                typ: 0,
                weak_default: OptionalSymbolId::NONE,
                diagnostic: SymbolDiagnostic::None,
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
                sections: DenseRange::new(0, u32::try_from(SECTION_COUNT).unwrap()),
                symbols: DenseRange::new(0, u32::try_from(SECTION_COUNT).unwrap()),
                input_ordinal: 0,
            }]
            .into_boxed_slice(),
            sections,
            symbols,
            global_symbols: Box::new([]),
            relocations: RelocationCsr {
                starts: (0..=u32::try_from(SECTION_COUNT).unwrap())
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                records: (0..SECTION_COUNT)
                    .map(|index| RelocationRecord {
                        offset: 0,
                        target: SymbolId::from_u32(u32::try_from(index).unwrap()),
                        typ: 4,
                        flags: 0,
                    })
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            },
        };
        let database = SymbolDb {
            entries: Box::new([]),
            providers: Box::new([]),
            absolute_values: Box::new([]),
        };
        let resolved = ir.resolve_symbol_targets(&database, &[]).unwrap();
        let collector = DenseEventGc::new_resolved(&ir, &[], &resolved);
        let is_comdat = vec![false; SECTION_COUNT];
        let group_starts = (0..=u32::try_from(SECTION_COUNT).unwrap()).collect::<Vec<_>>();
        let group_members = (0..SECTION_COUNT).collect::<Vec<_>>();
        let group_by_section = group_members.clone();
        let output = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap()
            .install(|| {
                collector.collect_production(ProductionGcInput {
                    redirect_targets: (0..u32::try_from(SECTION_COUNT).unwrap())
                        .map(SectionId::from_u32)
                        .collect(),
                    discarded: vec![false; SECTION_COUNT],
                    is_comdat: &is_comdat,
                    root_names: &[],
                    group_starts: &group_starts,
                    group_members: &group_members,
                    group_by_section: &group_by_section,
                })
            })
            .unwrap();
        assert_eq!(
            output
                .live_bits
                .iter()
                .map(|word| word.count_ones() as usize)
                .sum::<usize>(),
            SECTION_COUNT
        );
        assert!(output.referenced_import_names.is_empty());
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
                comdat_leader: OptionalSymbolId::NONE,
                comdat_order: u32::MAX,
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
            global_symbols: Box::new([]),
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
        let mut collector = DenseEventGc::new(&ir, &[]);
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
        assert_eq!(&*output.referenced_import_names, &[NameId::from_u32(1)]);
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
                comdat_leader: OptionalSymbolId::NONE,
                comdat_order: u32::MAX,
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
            global_symbols: Box::new([]),
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
        let mut collector = DenseEventGc::new(&ir, &[]);
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
                comdat_leader: OptionalSymbolId::NONE,
                comdat_order: u32::MAX,
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
            global_symbols: Box::new([]),
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
        DenseEventGc::new(&ir, &[])
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
        let error = DenseEventGc::new(&ir, &[])
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
