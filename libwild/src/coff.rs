//! PE/COFF input primitives.
//!
//! `CoffObject::parse` only validates the container. Once archive selection has reached its
//! fixpoint, selected objects build compact prefix/name plans in parallel, then raw standard or
//! bigobj records are written directly into the final dense PE IR. Malformed symbol-name offsets
//! and relocation symbol indices are recorded, not diagnosed: the consumer that first needs a
//! live name or target remains the final diagnostic boundary. The older full local index remains
//! available for isolated legacy/test consumers but is not materialized by production linking.

#![allow(dead_code)]

use crate::ensure;
use crate::error::Context;
use crate::error::Result;
use object::LittleEndian as LE;
use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use object::read::coff::CoffHeader;
use object::read::coff::Symbol as _;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

/// Marker type for the PE/COFF platform.
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct Pe;

/// A validated x86-64 COFF relocatable object.
#[derive(Debug)]
pub(crate) struct CoffObject<'data> {
    file: object::File<'data>,
    bytes: &'data [u8],
    index: OnceLock<CoffRelocationIndex>,
    dense_plan: OnceLock<CoffDensePlan>,
    resolver_summary: OnceLock<CoffResolverSummary>,
    legacy_relocation_index_accessed: AtomicBool,
}

/// The complete object-local index. The historical name is retained until writer consumers move
/// to `PeIr`; it no longer means that only relocation-referenced symbols are indexed.
#[derive(Debug)]
pub(crate) struct CoffRelocationIndex {
    sections: Box<[CoffSectionRecord]>,
    relocations: Box<[CoffRelocationRecord]>,
    symbols: Box<[CoffSymbolRecord]>,
    names: Box<[CoffNameOccurrence]>,
}

/// Compact validation and prefix plan for production dense-IR construction. Full section,
/// symbol and relocation records are written directly into `PeIr`; only data needed to assign
/// deterministic global IDs before that parallel fill is retained here.
#[derive(Debug)]
pub(crate) struct CoffDensePlan {
    names: Box<[CoffNameOccurrence]>,
    raw_to_dense_symbol: Box<[u32]>,
    section_comdats: Box<[CoffDenseComdat]>,
    primary_symbol_count: u32,
    symbol_count: u32,
    relocation_count: u32,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CoffDenseComdat {
    pub(super) selection: u8,
    pub(super) associative_section: u32,
    pub(super) leader: u32,
    pub(super) order: u32,
}

/// The resolution-facing subset of a COFF symbol table. It is populated directly from the raw
/// table on first selection and retained for the dense-index pass, avoiding a second generic
/// `object::Symbol` traversal and a second hash of every externally visible name.
#[derive(Debug)]
pub(crate) struct CoffResolverSummary {
    globals: Box<[CoffGlobalSymbolSummary]>,
    weak_externals: Box<[CoffWeakExternalSummary]>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CoffGlobalSymbolSummary {
    pub(super) hash: u64,
    pub(super) symbol_occurrence: u32,
    pub(super) raw_index: u32,
    name_start: u32,
    name_len: u32,
    section: u32,
    pub(super) address: u32,
    pub(super) size: u32,
    flags: u8,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CoffWeakExternalSummary {
    pub(super) symbol: CoffSourceRange,
    pub(super) symbol_hash: u64,
    pub(super) target: CoffSourceRange,
    pub(super) target_hash: u64,
    pub(super) search: linker_utils::coff_symbols::WeakSearch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CoffSourceRange {
    pub(super) start: u32,
    pub(super) len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CoffNameId(pub(super) u32);

impl CoffNameId {
    pub(super) const NONE: Self = Self(u32::MAX);

    pub(super) const fn get(self) -> Option<usize> {
        if self.0 == u32::MAX {
            None
        } else {
            Some(self.0 as usize)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CoffDeferredNameError {
    InvalidNameOffset,
    InvalidRelocationSymbol,
}

/// One occurrence, in primary-symbol then section/relocation input order. Equal byte strings
/// intentionally remain separate here so global NameId assignment can be finalized
/// deterministically across objects.
#[derive(Debug, Clone, Copy)]
pub(super) struct CoffNameOccurrence {
    pub(super) source: Option<CoffSourceRange>,
    /// Global symbol names were already hashed by archive resolution. Their canonical NameIds are
    /// reused during dense finalization, so the full index deliberately leaves the hash absent.
    pub(super) hash: Option<u64>,
    error: Option<CoffDeferredNameError>,
}

#[derive(Debug)]
pub(crate) struct CoffSectionRecord {
    pub(super) index: object::SectionIndex,
    pub(super) name: CoffNameId,
    pub(super) size: u64,
    pub(super) align: u64,
    pub(super) kind: object::SectionKind,
    pub(super) characteristics: Option<u32>,
    pub(super) data_range: Option<CoffSourceRange>,
    pub(super) relocation_start: u32,
    pub(super) relocation_len: u32,
    pub(super) comdat_selection: u8,
    pub(super) associative_section: u32,
    pub(super) comdat_leader: u32,
    pub(super) comdat_order: u32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CoffRelocationRecord {
    pub(super) offset: u32,
    pub(super) typ: u16,
    pub(super) symbol: CoffRelocationSymbolId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CoffRelocationSymbolId(pub(super) u32);

#[derive(Debug)]
pub(crate) struct CoffSymbolRecord {
    pub(super) raw_index: u32,
    pub(super) name: CoffNameId,
    pub(super) shape: Option<CoffRelocationSymbolShape>,
    pub(super) value: u32,
    pub(super) size: u32,
    pub(super) typ: u16,
    pub(super) storage_class: u8,
    pub(super) weak_default: Option<CoffRelocationSymbolId>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CoffRelocationSymbolShape {
    pub(crate) section: Option<object::SectionIndex>,
    pub(crate) address: u64,
    pub(crate) is_global: bool,
    pub(crate) is_common: bool,
    pub(crate) is_weak: bool,
    pub(crate) is_definition: bool,
    pub(crate) is_undefined: bool,
    pub(crate) is_absolute: bool,
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
        Ok(Self {
            file,
            bytes,
            index: OnceLock::new(),
            dense_plan: OnceLock::new(),
            resolver_summary: OnceLock::new(),
            legacy_relocation_index_accessed: AtomicBool::new(false),
        })
    }

    pub(crate) fn section_count(&self) -> usize {
        self.index().sections.len()
    }

    pub(crate) fn symbol_count(&self) -> usize {
        self.index().symbols.len()
    }

    pub(crate) fn file(&self) -> &object::File<'data> {
        &self.file
    }

    pub(crate) fn bytes(&self) -> &'data [u8] {
        self.bytes
    }

    pub(crate) fn relocation_index(&self) -> &CoffRelocationIndex {
        self.legacy_relocation_index_accessed
            .store(true, Ordering::Relaxed);
        self.index()
    }

    pub(super) fn index(&self) -> &CoffRelocationIndex {
        self.materialize_full_index()
            .expect("valid selected COFF object must have a materializable index")
    }

    pub(crate) fn resolver_summary(&self) -> Result<&CoffResolverSummary> {
        if let Some(summary) = self.resolver_summary.get() {
            return Ok(summary);
        }
        let summary = CoffResolverSummary::new(&self.file, self.bytes)?;
        let _ = self.resolver_summary.set(summary);
        Ok(self
            .resolver_summary
            .get()
            .expect("COFF resolver summary was just initialized"))
    }

    /// Build the full section/symbol/relocation index on demand. Archive extraction deliberately
    /// uses `file()` instead, so unselected members never pay this cost. The writer calls this for
    /// every selected object in parallel before dense finalization, which also keeps construction
    /// errors on the normal `Result` path rather than the infallible accessor above.
    pub(crate) fn materialize_full_index(&self) -> Result<&CoffRelocationIndex> {
        if let Some(index) = self.index.get() {
            return Ok(index);
        }
        let index = CoffRelocationIndex::new(&self.file, self.bytes, self.resolver_summary()?)?;
        // Each selected object occupies one deterministic parallel slot. Retain correctness if a
        // future caller races on the same object: either identical immutable index may win.
        let _ = self.index.set(index);
        Ok(self.index.get().expect("COFF index was just initialized"))
    }

    pub(crate) fn materialize_dense_plan(&self) -> Result<&CoffDensePlan> {
        if let Some(plan) = self.dense_plan.get() {
            return Ok(plan);
        }
        let plan = CoffDensePlan::new(&self.file, self.bytes, self.resolver_summary()?)?;
        let _ = self.dense_plan.set(plan);
        Ok(self
            .dense_plan
            .get()
            .expect("COFF dense plan was just initialized"))
    }

    pub(super) fn dense_plan(&self) -> &CoffDensePlan {
        self.materialize_dense_plan()
            .expect("valid selected COFF object must have a dense plan")
    }

    #[cfg(test)]
    pub(crate) fn relocation_index_initialized(&self) -> bool {
        self.legacy_relocation_index_accessed
            .load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn full_index_initialized(&self) -> bool {
        self.index.get().is_some()
    }
}

impl CoffResolverSummary {
    fn new(file: &object::File<'_>, bytes: &[u8]) -> Result<Self> {
        match file {
            object::File::Coff(file) => Self::new_typed(file, bytes),
            object::File::CoffBig(file) => Self::new_typed(file, bytes),
            _ => Err(crate::error!(
                "Internal non-COFF file reached resolver summarization"
            )),
        }
    }

    fn new_typed<'data, Coff>(
        file: &object::read::coff::CoffFile<'data, &'data [u8], Coff>,
        bytes: &[u8],
    ) -> Result<Self>
    where
        Coff: CoffHeader,
    {
        let mut globals = Vec::new();
        let mut weak_externals = Vec::new();
        for (symbol_occurrence, (raw_index, symbol)) in file.coff_symbol_table().iter().enumerate()
        {
            let storage_class = symbol.storage_class();
            if !matches!(
                storage_class,
                object::pe::IMAGE_SYM_CLASS_EXTERNAL | object::pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
            ) {
                continue;
            }
            let name_result = symbol.name(file.coff_symbol_table().strings());
            if symbol.has_aux_weak_external() {
                let weak_name = name_result
                    .as_ref()
                    .map_err(|error| crate::error!("invalid weak symbol name: {error}"))?;
                let auxiliary = file
                    .coff_symbol_table()
                    .aux_weak_external(raw_index)
                    .context("invalid weak-external auxiliary record")?;
                let target = file
                    .coff_symbol_table()
                    .symbol(auxiliary.default_symbol())
                    .context("invalid weak-external target index")?;
                let target_name = target
                    .name(file.coff_symbol_table().strings())
                    .context("invalid weak fallback name")?;
                let search = match auxiliary.weak_search_type.get(LE) {
                    value if value == object::pe::IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY => {
                        linker_utils::coff_symbols::WeakSearch::NoLibrary
                    }
                    value if value == object::pe::IMAGE_WEAK_EXTERN_SEARCH_LIBRARY => {
                        linker_utils::coff_symbols::WeakSearch::Library
                    }
                    value if value == object::pe::IMAGE_WEAK_EXTERN_SEARCH_ALIAS => {
                        linker_utils::coff_symbols::WeakSearch::Alias
                    }
                    value if value == object::pe::IMAGE_WEAK_EXTERN_ANTI_DEPENDENCY => {
                        linker_utils::coff_symbols::WeakSearch::AntiDependency
                    }
                    value => {
                        return Err(crate::error!(
                            "unsupported weak-external search characteristic {}",
                            value.0
                        ));
                    }
                };
                crate::ensure!(
                    !weak_name.is_empty() && !target_name.is_empty() && *weak_name != target_name,
                    "weak external has an empty or self-referential fallback"
                );
                weak_externals.push(CoffWeakExternalSummary {
                    symbol: source_range(bytes, weak_name)
                        .context("invalid weak COFF symbol name range")?,
                    symbol_hash: hash_name_once(weak_name),
                    target: source_range(bytes, target_name)
                        .context("invalid weak COFF fallback name range")?,
                    target_hash: hash_name_once(target_name),
                    search,
                });
            }
            let section_number = symbol.section_number();
            let parsed = file.symbol_by_index(raw_index).ok();
            let name = make_name_occurrence(bytes, name_result, true);
            let source = name.source.unwrap_or(CoffSourceRange {
                start: u32::MAX,
                len: 0,
            });
            let flags = u8::from(
                storage_class == object::pe::IMAGE_SYM_CLASS_EXTERNAL
                    && section_number == object::pe::IMAGE_SYM_UNDEFINED
                    && symbol.value() != 0,
            ) | (u8::from(storage_class == object::pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL)
                << 1)
                | (u8::from(symbol.is_definition()) << 2)
                | (u8::from(
                    storage_class == object::pe::IMAGE_SYM_CLASS_EXTERNAL
                        && section_number == object::pe::IMAGE_SYM_UNDEFINED
                        && symbol.value() == 0,
                ) << 3)
                | (u8::from(section_number == object::pe::IMAGE_SYM_ABSOLUTE) << 4);
            globals.push(CoffGlobalSymbolSummary {
                hash: name.hash.unwrap_or(0),
                symbol_occurrence: dense_u32(symbol_occurrence, "COFF symbol occurrence")?,
                raw_index: dense_u32(raw_index.0, "raw COFF symbol index")?,
                name_start: source.start,
                name_len: source.len,
                section: symbol.section().map_or(0, |section| section.0 as u32),
                address: symbol.value(),
                size: parsed
                    .as_ref()
                    .and_then(|symbol| u32::try_from(symbol.size()).ok())
                    .unwrap_or(0),
                flags,
            });
        }
        weak_externals.sort_unstable_by(|left, right| {
            source_bytes(bytes, left.symbol).cmp(source_bytes(bytes, right.symbol))
        });
        Ok(Self {
            globals: globals.into_boxed_slice(),
            weak_externals: weak_externals.into_boxed_slice(),
        })
    }

    pub(crate) fn globals(&self) -> &[CoffGlobalSymbolSummary] {
        &self.globals
    }

    pub(crate) fn weak_externals(&self) -> &[CoffWeakExternalSummary] {
        &self.weak_externals
    }
}

impl CoffGlobalSymbolSummary {
    const COMMON: u8 = 1 << 0;
    const WEAK: u8 = 1 << 1;
    const DEFINITION: u8 = 1 << 2;
    const UNDEFINED: u8 = 1 << 3;
    const ABSOLUTE: u8 = 1 << 4;

    pub(super) fn name(self) -> CoffNameOccurrence {
        if self.name_start == u32::MAX {
            CoffNameOccurrence {
                source: None,
                hash: None,
                error: Some(CoffDeferredNameError::InvalidNameOffset),
            }
        } else {
            CoffNameOccurrence {
                source: Some(CoffSourceRange {
                    start: self.name_start,
                    len: self.name_len,
                }),
                hash: Some(self.hash),
                error: None,
            }
        }
    }

    pub(super) fn section(self) -> Option<object::SectionIndex> {
        (self.section != 0).then_some(object::SectionIndex(self.section as usize))
    }

    pub(super) fn section_kind(self) -> object::SymbolSection {
        if self.flags & Self::ABSOLUTE != 0 {
            object::SymbolSection::Absolute
        } else if self.flags & Self::COMMON != 0 {
            object::SymbolSection::Common
        } else if self.flags & Self::UNDEFINED != 0 {
            object::SymbolSection::Undefined
        } else if let Some(section) = self.section() {
            object::SymbolSection::Section(section)
        } else {
            object::SymbolSection::Unknown
        }
    }

    pub(super) const fn is_common(self) -> bool {
        self.flags & Self::COMMON != 0
    }

    pub(super) const fn is_weak(self) -> bool {
        self.flags & Self::WEAK != 0
    }

    pub(super) const fn is_definition(self) -> bool {
        self.flags & Self::DEFINITION != 0
    }

    pub(super) const fn is_undefined(self) -> bool {
        self.flags & Self::UNDEFINED != 0
    }

    pub(super) const fn is_absolute(self) -> bool {
        self.flags & Self::ABSOLUTE != 0
    }
}

impl CoffWeakExternalSummary {
    pub(crate) fn symbol(self, bytes: &[u8]) -> &[u8] {
        source_bytes(bytes, self.symbol)
    }

    pub(crate) fn target(self, bytes: &[u8]) -> &[u8] {
        source_bytes(bytes, self.target)
    }
}

fn source_bytes(bytes: &[u8], source: CoffSourceRange) -> &[u8] {
    &bytes[source.start as usize..source.start as usize + source.len as usize]
}

fn hash_name_once(name: &[u8]) -> u64 {
    count_name_hash();
    crate::hash::hash_bytes(name)
}

impl CoffDensePlan {
    fn new(file: &object::File<'_>, bytes: &[u8], resolver: &CoffResolverSummary) -> Result<Self> {
        count_object_parse();
        match file {
            object::File::Coff(file) => Self::new_typed(file, bytes, resolver),
            object::File::CoffBig(file) => Self::new_typed(file, bytes, resolver),
            _ => Err(crate::error!(
                "Internal non-COFF file reached dense COFF planning"
            )),
        }
    }

    fn new_typed<'data, Coff>(
        file: &object::read::coff::CoffFile<'data, &'data [u8], Coff>,
        bytes: &[u8],
        resolver: &CoffResolverSummary,
    ) -> Result<Self>
    where
        Coff: CoffHeader,
    {
        let section_count = file.coff_header().number_of_sections() as usize;
        let mut names = Vec::with_capacity(resolver.globals.len().saturating_add(section_count));
        let mut raw_to_dense_symbol = vec![u32::MAX; file.coff_symbol_table().len()];
        let mut section_comdats = vec![
            CoffDenseComdat {
                selection: 0,
                associative_section: u32::MAX,
                leader: u32::MAX,
                order: u32::MAX,
            };
            section_count
        ];

        let mut next_global = 0usize;
        let mut primary_symbol_count = 0u32;
        for (symbol_occurrence, (raw_index, raw_symbol)) in
            file.coff_symbol_table().iter().enumerate()
        {
            let dense = primary_symbol_count;
            primary_symbol_count = primary_symbol_count
                .checked_add(1)
                .ok_or_else(|| crate::error!("COFF symbol count exceeds u32"))?;
            raw_to_dense_symbol[raw_index.0] = dense;
            let storage_class = raw_symbol.storage_class();
            let is_global = matches!(
                storage_class,
                object::pe::IMAGE_SYM_CLASS_EXTERNAL | object::pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
            );
            let global = if is_global {
                let global = resolver.globals.get(next_global).ok_or_else(|| {
                    crate::error!("COFF resolver summary is missing a global symbol")
                })?;
                crate::ensure!(
                    global.symbol_occurrence as usize == symbol_occurrence
                        && global.raw_index as usize == raw_index.0,
                    "COFF resolver summary does not match the raw symbol table"
                );
                next_global += 1;
                Some(global)
            } else {
                None
            };
            if let Some(global) = global {
                push_existing_name_occurrence(&mut names, global.name())?;
            }

            if let Ok(symbol) = file.symbol_by_index(raw_index)
                && let object::SymbolFlags::CoffSection {
                    selection,
                    associative_section,
                    ..
                } = symbol.flags()
                && let Some(section) = symbol.section_index()
                && let Some(slot) = section
                    .0
                    .checked_sub(1)
                    .and_then(|index| section_comdats.get_mut(index))
            {
                slot.selection = selection.0;
                slot.associative_section = associative_section
                    .map(|section| dense_u32(section.0, "associative COMDAT parent"))
                    .transpose()?
                    .unwrap_or(u32::MAX);
                slot.order = dense_u32(raw_index.0, "COFF COMDAT auxiliary order")?;
            }

            let section = global.map_or_else(|| raw_symbol.section(), |global| global.section());
            if let Some(section) = section
                && let Some(slot) = section
                    .0
                    .checked_sub(1)
                    .and_then(|index| section_comdats.get_mut(index))
                && slot.selection != 0
                && slot.selection != object::pe::IMAGE_COMDAT_SELECT_ASSOCIATIVE.0
                && slot.leader == u32::MAX
                && dense_u32(raw_index.0, "raw COFF symbol index")? > slot.order
            {
                slot.leader = dense;
            }
        }
        crate::ensure!(
            next_global == resolver.globals.len(),
            "COFF resolver summary has excess global symbols"
        );

        let mut relocation_count = 0u32;
        for section in file.sections() {
            push_name_occurrence(&mut names, bytes, section.name_bytes(), true)?;
            let relocations = section.coff_relocations().unwrap_or(&[]);
            relocation_count = relocation_count
                .checked_add(dense_u32(relocations.len(), "COFF relocation")?)
                .ok_or_else(|| crate::error!("COFF relocation count exceeds u32"))?;
        }

        Ok(Self {
            names: names.into_boxed_slice(),
            raw_to_dense_symbol: raw_to_dense_symbol.into_boxed_slice(),
            section_comdats: section_comdats.into_boxed_slice(),
            primary_symbol_count,
            symbol_count: primary_symbol_count,
            relocation_count,
        })
    }

    pub(super) fn names(&self) -> &[CoffNameOccurrence] {
        &self.names
    }

    pub(super) fn raw_to_dense_symbol(&self) -> &[u32] {
        &self.raw_to_dense_symbol
    }

    pub(super) fn section_comdats(&self) -> &[CoffDenseComdat] {
        &self.section_comdats
    }

    pub(super) const fn primary_symbol_count(&self) -> u32 {
        self.primary_symbol_count
    }

    pub(super) const fn symbol_count(&self) -> u32 {
        self.symbol_count
    }

    pub(super) const fn relocation_count(&self) -> u32 {
        self.relocation_count
    }

    pub(super) fn section_count(&self) -> usize {
        self.section_comdats.len()
    }
}

impl CoffRelocationIndex {
    fn new(file: &object::File<'_>, bytes: &[u8], resolver: &CoffResolverSummary) -> Result<Self> {
        count_object_parse();
        match file {
            object::File::Coff(file) => Self::new_typed(file, bytes, resolver),
            object::File::CoffBig(file) => Self::new_typed(file, bytes, resolver),
            _ => Err(crate::error!(
                "Internal non-COFF file reached COFF indexing"
            )),
        }
    }

    fn new_typed<'data, Coff>(
        file: &object::read::coff::CoffFile<'data, &'data [u8], Coff>,
        bytes: &[u8],
        resolver: &CoffResolverSummary,
    ) -> Result<Self>
    where
        Coff: CoffHeader,
    {
        let section_count = file.coff_header().number_of_sections() as usize;
        let mut sections = Vec::with_capacity(section_count);
        let mut relocations = Vec::new();
        let mut symbols = Vec::new();
        let mut names = Vec::new();
        let mut raw_to_dense = vec![None; file.coff_symbol_table().len()];
        let mut weak_defaults = Vec::new();
        let mut section_comdats = vec![(0, None, None, u32::MAX); section_count];

        let mut next_global = 0usize;
        for (symbol_occurrence, (raw_index, raw_symbol)) in
            file.coff_symbol_table().iter().enumerate()
        {
            let storage_class = raw_symbol.storage_class();
            let section_number = raw_symbol.section_number();
            let parsed_symbol = file.symbol_by_index(raw_index).ok();
            let is_global = matches!(
                storage_class,
                object::pe::IMAGE_SYM_CLASS_EXTERNAL | object::pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
            );
            let global = if is_global {
                let global = resolver.globals.get(next_global).ok_or_else(|| {
                    crate::error!("COFF resolver summary is missing a global symbol")
                })?;
                crate::ensure!(
                    global.symbol_occurrence as usize == symbol_occurrence
                        && global.raw_index as usize == raw_index.0,
                    "COFF resolver summary does not match the raw symbol table"
                );
                next_global += 1;
                Some(global)
            } else {
                None
            };
            // Local symbols resolve directly to a section/value pair. Their names have no
            // semantic consumer and therefore never enter the global canonical namespace.
            let name = global.map_or(Ok(CoffNameId::NONE), |global| {
                push_existing_name_occurrence(&mut names, global.name())
            })?;
            let symbol_id = CoffRelocationSymbolId(dense_u32(symbols.len(), "COFF symbol")?);
            raw_to_dense[raw_index.0] = Some(symbol_id);
            symbols.push(CoffSymbolRecord {
                raw_index: dense_u32(raw_index.0, "raw COFF symbol index")?,
                name,
                shape: Some(CoffRelocationSymbolShape {
                    section: global.map_or_else(|| raw_symbol.section(), |global| global.section()),
                    address: global.map_or_else(
                        || u64::from(raw_symbol.value()),
                        |global| u64::from(global.address),
                    ),
                    is_global,
                    is_common: global.map_or_else(
                        || {
                            storage_class == object::pe::IMAGE_SYM_CLASS_EXTERNAL
                                && section_number == object::pe::IMAGE_SYM_UNDEFINED
                                && raw_symbol.value() != 0
                        },
                        |global| global.is_common(),
                    ),
                    is_weak: global.map_or(
                        storage_class == object::pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL,
                        |global| global.is_weak(),
                    ),
                    is_definition: global.map_or_else(
                        || {
                            parsed_symbol
                                .as_ref()
                                .is_some_and(|symbol| symbol.is_definition())
                        },
                        |global| global.is_definition(),
                    ),
                    is_undefined: global.map_or_else(
                        || {
                            parsed_symbol
                                .as_ref()
                                .is_some_and(|symbol| symbol.is_undefined())
                        },
                        |global| global.is_undefined(),
                    ),
                    is_absolute: global.map_or_else(
                        || {
                            parsed_symbol.as_ref().is_some_and(|symbol| {
                                symbol.section() == object::SymbolSection::Absolute
                            })
                        },
                        |global| global.is_absolute(),
                    ),
                }),
                value: raw_symbol.value(),
                size: global.map_or_else(
                    || {
                        parsed_symbol
                            .as_ref()
                            .and_then(|symbol| u32::try_from(symbol.size()).ok())
                            .unwrap_or(0)
                    },
                    |global| global.size,
                ),
                typ: raw_symbol.typ().0,
                storage_class: storage_class.0,
                weak_default: None,
            });
            if raw_symbol.has_aux_weak_external()
                && let Ok(aux) = file.coff_symbol_table().aux_weak_external(raw_index)
            {
                weak_defaults.push((symbol_id, aux.default_symbol()));
            }
            if let Ok(symbol) = file.symbol_by_index(raw_index)
                && let object::SymbolFlags::CoffSection {
                    selection,
                    associative_section,
                    ..
                } = symbol.flags()
                && let Some(section) = symbol.section_index()
                && let Some(slot) = section
                    .0
                    .checked_sub(1)
                    .and_then(|index| section_comdats.get_mut(index))
            {
                *slot = (
                    selection.0,
                    associative_section,
                    None,
                    dense_u32(raw_index.0, "COFF COMDAT auxiliary order")?,
                );
            }
        }
        crate::ensure!(
            next_global == resolver.globals.len(),
            "COFF resolver summary has excess global symbols"
        );

        // Auxiliary weak records refer to raw table indices; translate them after the single
        // primary-symbol pass has assigned every dense ID.
        for (symbol, raw_default) in weak_defaults {
            symbols[symbol.0 as usize].weak_default =
                raw_to_dense.get(raw_default.0).copied().flatten();
        }

        // A COFF COMDAT key is the first primary symbol after its section-definition auxiliary
        // record that refers to the same section. Cache that dense symbol ID once so later COMDAT
        // selection never scans the raw symbol table or constructs object::Comdat iterators.
        for (symbol_index, symbol) in symbols.iter().enumerate() {
            let Some(shape) = symbol.shape else {
                continue;
            };
            let Some(section) = shape.section else {
                continue;
            };
            let Some(slot) = section
                .0
                .checked_sub(1)
                .and_then(|index| section_comdats.get_mut(index))
            else {
                continue;
            };
            if slot.0 == 0
                || slot.0 == object::pe::IMAGE_COMDAT_SELECT_ASSOCIATIVE.0
                || slot.2.is_some()
                || symbol.raw_index <= slot.3
            {
                continue;
            }
            slot.2 = Some(CoffRelocationSymbolId(dense_u32(
                symbol_index,
                "COFF COMDAT leader",
            )?));
        }

        for (section_ordinal, section) in file.sections().enumerate() {
            let name = push_name_occurrence(&mut names, bytes, section.name_bytes(), true)?;
            let relocation_start = dense_u32(relocations.len(), "COFF relocation")?;
            for relocation in section.coff_relocations().unwrap_or(&[]) {
                // The input was already restricted to standard/bigobj COFF. Decode the compact
                // raw record directly instead of constructing an architecture-neutral object::
                // Relocation for every edge; overflow relocation tables are normalized by
                // `coff_relocations` before this slice is returned.
                let raw_index = object::SymbolIndex(relocation.symbol_table_index.get(LE) as usize);
                count_relocation_decode();
                let symbol = if let Some(symbol) = raw_to_dense.get(raw_index.0).copied().flatten()
                {
                    symbol
                } else {
                    let id = CoffRelocationSymbolId(dense_u32(
                        symbols.len(),
                        "invalid COFF relocation symbol",
                    )?);
                    symbols.push(CoffSymbolRecord {
                        raw_index: dense_u32(raw_index.0, "invalid raw COFF symbol index")?,
                        name: CoffNameId::NONE,
                        shape: None,
                        value: 0,
                        size: 0,
                        typ: 0,
                        storage_class: 0,
                        weak_default: None,
                    });
                    id
                };
                relocations.push(CoffRelocationRecord {
                    offset: relocation.virtual_address.get(LE),
                    typ: relocation.typ.get(LE).0,
                    symbol,
                });
            }
            let data_range = section
                .file_range()
                .map(|(offset, size)| {
                    Ok::<_, crate::error::Error>(CoffSourceRange {
                        start: u32::try_from(offset).map_err(|_| {
                            crate::error!("COFF section payload offset exceeds u32")
                        })?,
                        len: u32::try_from(size)
                            .map_err(|_| crate::error!("COFF section payload size exceeds u32"))?,
                    })
                })
                .transpose()?;
            let characteristics = match section.flags() {
                object::SectionFlags::Coff { characteristics } => Some(characteristics.0),
                _ => None,
            };
            let (comdat_selection, associative_section, comdat_leader, comdat_order) =
                section_comdats[section_ordinal];
            sections.push(CoffSectionRecord {
                index: section.index(),
                name,
                size: section.size(),
                align: section.align(),
                kind: section.kind(),
                characteristics,
                data_range,
                relocation_start,
                relocation_len: dense_u32(relocations.len(), "COFF relocation")? - relocation_start,
                comdat_selection,
                associative_section: associative_section
                    .map(|section| dense_u32(section.0, "associative COMDAT parent"))
                    .transpose()?
                    .unwrap_or(u32::MAX),
                comdat_leader: comdat_leader.map_or(u32::MAX, |symbol| symbol.0),
                comdat_order,
            });
        }
        Ok(Self {
            sections: sections.into_boxed_slice(),
            relocations: relocations.into_boxed_slice(),
            symbols: symbols.into_boxed_slice(),
            names: names.into_boxed_slice(),
        })
    }

    pub(crate) fn sections(&self) -> &[CoffSectionRecord] {
        &self.sections
    }

    pub(crate) fn relocations(&self, section: &CoffSectionRecord) -> &[CoffRelocationRecord] {
        let start = section.relocation_start as usize;
        let end = start + section.relocation_len as usize;
        &self.relocations[start..end]
    }

    pub(crate) fn symbol(&self, id: CoffRelocationSymbolId) -> &CoffSymbolRecord {
        &self.symbols[id.0 as usize]
    }

    pub(super) fn names(&self) -> &[CoffNameOccurrence] {
        &self.names
    }

    pub(super) fn symbols(&self) -> &[CoffSymbolRecord] {
        &self.symbols
    }
}

impl CoffSectionRecord {
    pub(crate) fn index(&self) -> object::SectionIndex {
        self.index
    }
}

impl CoffRelocationRecord {
    pub(crate) fn symbol(&self) -> CoffRelocationSymbolId {
        self.symbol
    }
}

impl CoffSymbolRecord {
    pub(crate) fn shape<'object>(
        &'object self,
        _object: &CoffObject<'_>,
    ) -> Result<&'object CoffRelocationSymbolShape> {
        self.shape
            .as_ref()
            .ok_or_else(|| crate::error!("Invalid COFF symbol index {}", self.raw_index))
    }

    pub(crate) fn name<'data>(&self, object: &'data CoffObject<'data>) -> Result<&'data [u8]> {
        object.index().name_bytes(object.bytes, self.name)
    }
}

impl CoffNameOccurrence {
    pub(super) fn source(self) -> Option<CoffSourceRange> {
        self.source
    }

    pub(super) fn hash(self) -> Option<u64> {
        self.hash
    }

    pub(super) fn hash_or_compute(self, bytes: &[u8]) -> u64 {
        self.hash.unwrap_or_else(|| {
            count_name_hash();
            crate::hash::hash_bytes(bytes)
        })
    }

    pub(super) fn deferred_error(self) -> Option<CoffDeferredNameError> {
        self.error
    }
}

fn push_name_occurrence(
    names: &mut Vec<CoffNameOccurrence>,
    bytes: &[u8],
    name: object::read::Result<&[u8]>,
    prehash: bool,
) -> Result<CoffNameId> {
    let occurrence = make_name_occurrence(bytes, name, prehash);
    push_existing_name_occurrence(names, occurrence)
}

fn make_name_occurrence(
    bytes: &[u8],
    name: object::read::Result<&[u8]>,
    prehash: bool,
) -> CoffNameOccurrence {
    name.ok()
        .and_then(|name| source_range(bytes, name).map(|source| (source, name)))
        .map_or(
            CoffNameOccurrence {
                source: None,
                hash: None,
                error: Some(CoffDeferredNameError::InvalidNameOffset),
            },
            |(source, name)| CoffNameOccurrence {
                source: Some(source),
                hash: prehash.then(|| hash_name_once(name)),
                error: None,
            },
        )
}

fn push_existing_name_occurrence(
    names: &mut Vec<CoffNameOccurrence>,
    occurrence: CoffNameOccurrence,
) -> Result<CoffNameId> {
    let id = CoffNameId(dense_u32(names.len(), "COFF name occurrence")?);
    names.push(occurrence);
    Ok(id)
}

fn push_invalid_name(
    names: &mut Vec<CoffNameOccurrence>,
    error: CoffDeferredNameError,
) -> Result<CoffNameId> {
    let id = CoffNameId(dense_u32(names.len(), "COFF name occurrence")?);
    names.push(CoffNameOccurrence {
        source: None,
        hash: None,
        error: Some(error),
    });
    Ok(id)
}

fn source_range(bytes: &[u8], source: &[u8]) -> Option<CoffSourceRange> {
    let start = (source.as_ptr() as usize).checked_sub(bytes.as_ptr() as usize)?;
    let end = start.checked_add(source.len())?;
    (end <= bytes.len()).then_some(CoffSourceRange {
        start: u32::try_from(start).ok()?,
        len: u32::try_from(source.len()).ok()?,
    })
}

// Unit tests execute independent links concurrently, while removal counters are intentionally
// process-global. Instrument real `wip` binaries at the exact boundaries without making unrelated
// unit tests race the counter API's reset tests.
#[inline]
fn count_object_parse() {
    #[cfg(all(feature = "wip", not(test)))]
    crate::perf::removal_counters::increment_object_full_parse_passes();
}

#[inline]
fn count_relocation_decode() {
    #[cfg(all(feature = "wip", not(test)))]
    crate::perf::removal_counters::increment_relocation_decodes();
}

#[inline]
fn count_name_hash() {
    #[cfg(all(feature = "wip", not(test)))]
    crate::perf::removal_counters::increment_name_hash_ops();
}

fn dense_u32(value: usize, what: &str) -> Result<u32> {
    u32::try_from(value).map_err(|_| crate::error!("{what} count exceeds u32"))
}

impl CoffRelocationIndex {
    fn name_bytes<'data>(&self, bytes: &'data [u8], name: CoffNameId) -> Result<&'data [u8]> {
        let occurrence = self
            .names
            .get(name.0 as usize)
            .ok_or_else(|| crate::error!("Invalid dense COFF name ID {}", name.0))?;
        if let Some(source) = occurrence.source {
            let start = source.start as usize;
            let end = start + source.len as usize;
            return bytes
                .get(start..end)
                .ok_or_else(|| crate::error!("Invalid source-backed COFF name range"));
        }
        match occurrence.error {
            Some(CoffDeferredNameError::InvalidRelocationSymbol) => {
                Err(crate::error!("Invalid COFF relocation symbol"))
            }
            _ => Err(crate::error!("Invalid COFF name offset")),
        }
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
    use object::write::Object as WritableObject;
    use object::write::Relocation;
    use object::write::Symbol;
    use object::write::SymbolSection;

    fn bigobj_with_text_symbol() -> Vec<u8> {
        const HEADER_SIZE: usize = 56;
        const SECTION_SIZE: usize = 40;
        const SYMBOL_SIZE: usize = 20;
        const BIGOBJ_CLASS_ID: [u8; 16] = [
            0xc7, 0xa1, 0xba, 0xd1, 0xee, 0xba, 0xa9, 0x4b, 0xaf, 0x20, 0xfa, 0xf6, 0x6a, 0xa4,
            0xdc, 0xb8,
        ];

        let raw_data = HEADER_SIZE + SECTION_SIZE;
        let relocations = raw_data + 1;
        let symbol_table = relocations + 10;
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
        bytes[section + 24..section + 28].copy_from_slice(&(relocations as u32).to_le_bytes());
        bytes[section + 32..section + 34].copy_from_slice(&1u16.to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        bytes[raw_data] = 0xc3;

        bytes[relocations + 4..relocations + 8].copy_from_slice(&0u32.to_le_bytes());
        bytes[relocations + 8..relocations + 10]
            .copy_from_slice(&object::pe::IMAGE_REL_AMD64_REL32.0.to_le_bytes());

        bytes[symbol_table..symbol_table + 7].copy_from_slice(b"big_sym");
        bytes[symbol_table + 12..symbol_table + 16].copy_from_slice(&1i32.to_le_bytes());
        bytes[symbol_table + 18] = 2; // IMAGE_SYM_CLASS_EXTERNAL
        bytes[symbol_table + SYMBOL_SIZE..].copy_from_slice(&4u32.to_le_bytes());
        bytes
    }

    fn standard_object_with_repeated_relocations() -> Vec<u8> {
        let mut object = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let text = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
        object.append_section_data(text, &[0; 8], 1);
        let target = object.add_symbol(Symbol {
            name: b"target".to_vec(),
            value: 0,
            size: 0,
            kind: object::SymbolKind::Unknown,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Undefined,
            flags: object::SymbolFlags::None,
        });
        for offset in [0, 4] {
            object
                .add_relocation(
                    text,
                    Relocation {
                        offset,
                        symbol: target,
                        addend: 0,
                        flags: object::RelocationFlags::Coff {
                            typ: object::pe::IMAGE_REL_AMD64_REL32,
                        },
                    },
                )
                .unwrap();
        }
        object.write().unwrap()
    }

    fn rich_comdat_object() -> Vec<u8> {
        let mut object = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let leader_name = b".text$very_long_comdat_leader";
        let leader =
            object.add_section(Vec::new(), leader_name.to_vec(), object::SectionKind::Text);
        object.append_section_data(leader, &[0; 8], 4);
        object.section_symbol(leader);
        let child = object.add_section(
            Vec::new(),
            b".rdata$very_long_associative_child".to_vec(),
            object::SectionKind::ReadOnlyData,
        );
        object.append_section_data(child, b"child", 1);
        object.section_symbol(child);
        let leader_symbol = object.add_symbol(Symbol {
            name: b"very_long_comdat_definition_name".to_vec(),
            value: 0,
            size: 8,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(leader),
            flags: object::SymbolFlags::None,
        });
        object.add_symbol(Symbol {
            name: b"weak_occurrence".to_vec(),
            value: 4,
            size: 1,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage,
            weak: true,
            section: SymbolSection::Section(leader),
            flags: object::SymbolFlags::None,
        });
        let target = object.add_symbol(Symbol {
            name: b"very_long_undefined_relocation_target".to_vec(),
            value: 0,
            size: 0,
            kind: object::SymbolKind::Unknown,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Undefined,
            flags: object::SymbolFlags::None,
        });
        object.add_comdat(object::write::Comdat {
            kind: object::ComdatKind::Any,
            symbol: leader_symbol,
            sections: vec![leader, child],
        });
        for offset in [0, 4] {
            object
                .add_relocation(
                    leader,
                    Relocation {
                        offset,
                        symbol: target,
                        addend: 0,
                        flags: object::RelocationFlags::Coff {
                            typ: object::pe::IMAGE_REL_AMD64_REL32,
                        },
                    },
                )
                .unwrap();
        }
        object.write().unwrap()
    }

    fn weak_external_object() -> Vec<u8> {
        let mut bytes = vec![0; 20 + 40];
        bytes[0..2].copy_from_slice(&object::pe::IMAGE_FILE_MACHINE_AMD64.0.to_le_bytes());
        bytes[2..4].copy_from_slice(&1u16.to_le_bytes());
        bytes[8..12].copy_from_slice(&60u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&3u32.to_le_bytes());
        bytes[20..25].copy_from_slice(b".text");
        bytes[56..60].copy_from_slice(
            &(object::pe::IMAGE_SCN_CNT_CODE.0 | object::pe::IMAGE_SCN_MEM_READ.0).to_le_bytes(),
        );
        let mut fallback = [0; 18];
        fallback[..8].copy_from_slice(b"fallback");
        fallback[12..14].copy_from_slice(&1i16.to_le_bytes());
        fallback[16] = object::pe::IMAGE_SYM_CLASS_EXTERNAL.0;
        bytes.extend_from_slice(&fallback);
        let mut weak = [0; 18];
        weak[..7].copy_from_slice(b"primary");
        weak[16] = object::pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL.0;
        weak[17] = 1;
        bytes.extend_from_slice(&weak);
        let mut auxiliary = [0; 18];
        auxiliary[..4].copy_from_slice(&0u32.to_le_bytes());
        auxiliary[4..8]
            .copy_from_slice(&object::pe::IMAGE_WEAK_EXTERN_SEARCH_ALIAS.0.to_le_bytes());
        bytes.extend_from_slice(&auxiliary);
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes
    }

    fn assert_send_sync<T: Send + Sync>() {}

    fn first_standard_relocation_offset(bytes: &[u8]) -> usize {
        u32::from_le_bytes(bytes[44..48].try_into().unwrap()) as usize
    }

    #[test]
    fn deferred_index_is_stable_ordered_and_interns_relocation_targets() {
        assert_send_sync::<CoffRelocationIndex>();
        assert!(std::mem::size_of::<CoffGlobalSymbolSummary>() <= 40);
        assert_eq!(std::mem::size_of::<CoffRelocationRecord>(), 12);
        assert!(std::mem::size_of::<CoffSectionRecord>() <= 80);
        assert!(std::mem::size_of::<CoffSymbolRecord>() <= 64);
        let bytes = standard_object_with_repeated_relocations();
        let object = CoffObject::parse(&bytes).unwrap();
        assert!(!object.full_index_initialized());
        let index = object.relocation_index();
        assert!(object.full_index_initialized());
        assert!(std::ptr::eq(index, object.relocation_index()));
        assert_eq!(index.sections.len(), 1);
        assert_eq!(index.symbols.len(), 1);
        let section = &index.sections[0];
        let raw_section = object.file().section_by_index(section.index).unwrap();
        assert_eq!(section.size, 8);
        assert_eq!(section.align, raw_section.align());
        assert_eq!(section.kind, object::SectionKind::Text);
        assert_eq!(
            section.data_range,
            raw_section
                .file_range()
                .map(|(start, len)| CoffSourceRange {
                    start: start as u32,
                    len: len as u32,
                })
        );
        let relocations = index.relocations(section);
        assert_eq!(relocations.len(), 2);
        assert_eq!([relocations[0].offset, relocations[1].offset], [0, 4]);
        assert_eq!(
            [relocations[0].typ, relocations[1].typ],
            [
                object::pe::IMAGE_REL_AMD64_REL32.0,
                object::pe::IMAGE_REL_AMD64_REL32.0,
            ]
        );
        let (first, second) = (relocations[0].symbol, relocations[1].symbol);
        assert_eq!(first, second);
        let symbol = index.symbol(first);
        assert!(symbol.shape.is_some());
        let occurrence = index.names[symbol.name.0 as usize];
        assert!(occurrence.source.is_some());
        assert!(symbol.shape(&object).unwrap().is_global);
        assert_eq!(symbol.name(&object).unwrap(), b"target");
        assert_eq!(occurrence.hash(), Some(crate::hash::hash_bytes(b"target")));
    }

    #[test]
    fn eager_records_differentially_match_object_for_long_comdat_fixture() {
        let bytes = rich_comdat_object();
        let object = CoffObject::parse(&bytes).unwrap();
        let raw_sections = object.file().sections().collect::<Vec<_>>();
        let raw_symbols = object.file().symbols().collect::<Vec<_>>();
        let index = object.index();
        assert_eq!(index.sections.len(), raw_sections.len());
        assert_eq!(index.symbols.len(), raw_symbols.len());

        for (record, raw) in index.sections.iter().zip(&raw_sections) {
            assert_eq!(
                index.name_bytes(&bytes, record.name).unwrap(),
                raw.name_bytes().unwrap()
            );
            assert_eq!(record.size, raw.size());
            assert_eq!(record.align, raw.align());
            assert_eq!(record.kind, raw.kind());
            assert_eq!(
                record.characteristics,
                match raw.flags() {
                    object::SectionFlags::Coff { characteristics } => Some(characteristics.0),
                    _ => None,
                }
            );
            let raw_relocations = raw.relocations().collect::<Vec<_>>();
            let dense_relocations = index.relocations(record);
            assert_eq!(dense_relocations.len(), raw_relocations.len());
            for (dense, (offset, raw)) in dense_relocations.iter().zip(raw_relocations) {
                assert_eq!(u64::from(dense.offset), offset);
                assert_eq!(
                    dense.typ,
                    match raw.flags() {
                        object::RelocationFlags::Coff { typ } => typ.0,
                        _ => unreachable!(),
                    }
                );
            }
        }
        for (record, raw) in index.symbols.iter().zip(raw_symbols) {
            assert_eq!(record.raw_index as usize, raw.index().0);
            if raw.is_global() {
                assert_eq!(record.name(&object).unwrap(), raw.name_bytes().unwrap());
            } else {
                assert_eq!(record.name, CoffNameId::NONE);
            }
            assert_eq!(u64::from(record.value), raw.address());
            assert_eq!(u64::from(record.size), raw.size());
            let shape = record.shape(&object).unwrap();
            assert_eq!(shape.section, raw.section_index());
            assert_eq!(shape.is_global, raw.is_global());
            assert_eq!(shape.is_common, raw.is_common());
            assert_eq!(shape.is_weak, raw.is_weak());
        }
        assert_eq!(
            index.sections[0].comdat_selection,
            object::pe::IMAGE_COMDAT_SELECT_ANY.0
        );
        assert_eq!(
            index.sections[1].comdat_selection,
            object::pe::IMAGE_COMDAT_SELECT_ASSOCIATIVE.0
        );
        assert_eq!(index.sections[1].associative_section, 1);
        assert_ne!(index.sections[0].comdat_leader, u32::MAX);
        let relocations = index.relocations(&index.sections[0]);
        assert_eq!(relocations[0].symbol, relocations[1].symbol);
    }

    #[test]
    fn weak_external_auxiliary_maps_to_dense_fallback() {
        let bytes = weak_external_object();
        let object = CoffObject::parse(&bytes).unwrap();
        let index = object.index();
        assert_eq!(index.symbols.len(), 2);
        assert_eq!(index.symbols[1].name(&object).unwrap(), b"primary");
        assert!(index.symbols[1].shape(&object).unwrap().is_weak);
        assert_eq!(
            index.symbols[1].weak_default,
            Some(CoffRelocationSymbolId(0))
        );
        assert_eq!(index.symbols[0].name(&object).unwrap(), b"fallback");
    }

    #[test]
    fn malformed_name_is_recorded_until_a_consumer_requests_it() {
        let mut bytes = standard_object_with_repeated_relocations();
        let symbol_table = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        bytes[symbol_table..symbol_table + 4].fill(0);
        bytes[symbol_table + 4..symbol_table + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        let object = CoffObject::parse(&bytes).unwrap();
        let symbol = &object.index().symbols[0];
        assert!(symbol.shape(&object).is_ok());
        assert!(symbol.name(&object).is_err());
    }

    #[test]
    fn bigobj_uses_the_same_relocation_index() {
        let bytes = bigobj_with_text_symbol();
        let object = CoffObject::parse(&bytes).unwrap();
        let index = object.relocation_index();
        assert_eq!(index.sections.len(), 1);
        let relocations = index.relocations(&index.sections[0]);
        assert_eq!(relocations.len(), 1);
        assert_eq!(relocations[0].offset, 0);
        assert_eq!(relocations[0].typ, object::pe::IMAGE_REL_AMD64_REL32.0);
        let symbol = relocations[0].symbol;
        let shape = index.symbol(symbol).shape(&object).unwrap();
        assert_eq!(shape.section, Some(object::SectionIndex(1)));
        assert_eq!(index.symbol(symbol).name(&object).unwrap(), b"big_sym");
    }

    #[test]
    fn invalid_relocation_symbol_stays_lazy_until_target_resolution() {
        let mut bytes = standard_object_with_repeated_relocations();
        let relocation = first_standard_relocation_offset(&bytes);
        bytes[relocation + 4..relocation + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        let object = CoffObject::parse(&bytes).unwrap();
        let index = object.relocation_index();
        let relocation = &index.relocations(&index.sections[0])[0];
        let symbol = relocation.symbol;
        assert!(index.symbol(symbol).shape.is_none());
        assert!(index.symbol(symbol).shape(&object).is_err());
    }

    #[test]
    fn unsupported_relocation_type_is_cached_without_validation() {
        let mut bytes = standard_object_with_repeated_relocations();
        let relocation = first_standard_relocation_offset(&bytes);
        bytes[relocation + 8..relocation + 10].copy_from_slice(&u16::MAX.to_le_bytes());
        let object = CoffObject::parse(&bytes).unwrap();
        let index = object.relocation_index();
        assert_eq!(index.relocations(&index.sections[0])[0].typ, u16::MAX);
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
