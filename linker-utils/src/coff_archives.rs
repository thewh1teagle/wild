//! Deterministic, policy-light planning for AMD64 COFF archive extraction.
//!
//! The planner parses the archive container once and records both public
//! definitions and archive-relevant undefined symbols. Unsupported members
//! remain opaque until selected, so legacy members that are irrelevant to a
//! link do not make an otherwise usable MSVC library fail eagerly.

use crate::coff_imports::ShortImportObject;
use crate::coff_symbols::ArchiveDemand;
use crate::coff_symbols::ArchiveDemandKind;
use foldhash::HashMap;
use foldhash::HashMapExt;
use foldhash::HashSet;
use foldhash::HashSetExt;
use object::Architecture;
use object::FileKind;
use object::LittleEndian as LE;
use object::Object as _;
use object::ObjectSymbol as _;
use object::pe;
use object::read::archive::ArchiveFile;
use object::read::archive::ArchiveKind;
use object::read::coff::CoffHeader;
use object::read::coff::Symbol as _;
use std::borrow::Cow;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::OnceLock;

/// The broad category of an archive parsing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoffArchiveErrorKind {
    InvalidArchive,
    UnsupportedArchive,
    ThinArchive,
    InvalidMember,
    UnsupportedMember,
    InvalidSymbolIndex,
}

/// A typed archive error with optional member context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoffArchiveError {
    kind: CoffArchiveErrorKind,
    member: Option<Vec<u8>>,
    message: String,
}

impl CoffArchiveError {
    fn archive(kind: CoffArchiveErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            member: None,
            message: message.into(),
        }
    }

    fn member(kind: CoffArchiveErrorKind, name: &[u8], message: impl Into<String>) -> Self {
        Self {
            kind,
            member: Some(name.to_vec()),
            message: message.into(),
        }
    }

    #[must_use]
    pub fn kind(&self) -> CoffArchiveErrorKind {
        self.kind
    }

    #[must_use]
    pub fn member_name(&self) -> Option<&[u8]> {
        self.member.as_deref()
    }
}

impl fmt::Display for CoffArchiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(member) = &self.member {
            write!(
                formatter,
                "archive member {}: {}",
                String::from_utf8_lossy(member),
                self.message
            )
        } else {
            formatter.write_str(&self.message)
        }
    }
}

impl Error for CoffArchiveError {}

pub type Result<T> = std::result::Result<T, CoffArchiveError>;

/// The representation used by one archive member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoffArchiveMemberKind<'data> {
    CoffObject {
        is_bigobj: bool,
    },
    ShortImport(ShortImportObject<'data>),
    /// A member whose payload is not a supported AMD64 COFF object.
    ///
    /// Archive symbol indices can still associate definitions with an opaque
    /// member. Consumers must report [`CoffArchiveMember::opaque_error`] if
    /// such a member is selected, including in whole-archive mode.
    Opaque,
}

/// One validated member, in archive order.
#[derive(Clone, Debug)]
pub struct CoffArchiveMember<'data> {
    index: usize,
    name: &'data [u8],
    data: &'data [u8],
    kind: CoffArchiveMemberKind<'data>,
    opaque_error: Option<CoffArchiveError>,
    definitions: MemberDefinitions<'data>,
    demands: OnceLock<Result<Vec<OwnedArchiveDemand>>>,
}

#[derive(Clone, Debug)]
struct MemberDefinitions<'data> {
    values: Arc<Vec<Cow<'data, [u8]>>>,
    start: u32,
    end: u32,
}

impl<'data> MemberDefinitions<'data> {
    fn as_slice(&self) -> &[Cow<'data, [u8]>] {
        &self.values[self.start as usize..self.end as usize]
    }
}

struct PendingArchiveMember<'data> {
    index: usize,
    name: &'data [u8],
    data: &'data [u8],
    kind: CoffArchiveMemberKind<'data>,
    opaque_error: Option<CoffArchiveError>,
    definitions: Vec<Cow<'data, [u8]>>,
    demands: OnceLock<Result<Vec<OwnedArchiveDemand>>>,
}

impl<'data> CoffArchiveMember<'data> {
    #[must_use]
    pub fn index(&self) -> usize {
        self.index
    }

    #[must_use]
    pub fn name(&self) -> &'data [u8] {
        self.name
    }

    #[must_use]
    pub fn data(&self) -> &'data [u8] {
        self.data
    }

    #[must_use]
    pub fn kind(&self) -> CoffArchiveMemberKind<'data> {
        self.kind
    }

    /// Returns the deferred error for an opaque member.
    #[must_use]
    pub fn opaque_error(&self) -> Option<&CoffArchiveError> {
        self.opaque_error.as_ref()
    }

    #[must_use]
    pub fn definitions(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.definitions.as_slice().iter().map(AsRef::as_ref)
    }

    fn demands(&self) -> &[OwnedArchiveDemand] {
        self.demands
            .get_or_init(|| parse_member(self.name, self.data).map(|(_, _, demands)| demands))
            .as_deref()
            .unwrap_or_default()
    }
}

/// An owned demand, suitable for retaining after archive parsing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedArchiveDemand {
    name: Vec<u8>,
    kind: ArchiveDemandKind,
}

impl OwnedArchiveDemand {
    fn new(name: &[u8], kind: ArchiveDemandKind) -> Self {
        Self {
            name: name.to_vec(),
            kind,
        }
    }

    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    #[must_use]
    pub fn kind(&self) -> ArchiveDemandKind {
        self.kind
    }
}

/// Why a member was selected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArchiveSelectionReason {
    WholeArchive,
    Symbol(OwnedArchiveDemand),
}

/// A selected member plus the demand that first caused extraction.
#[derive(Clone, Debug)]
pub struct SelectedArchiveMember<'archive, 'data> {
    member: &'archive CoffArchiveMember<'data>,
    reason: ArchiveSelectionReason,
}

impl<'archive, 'data> SelectedArchiveMember<'archive, 'data> {
    #[must_use]
    pub fn member(&self) -> &'archive CoffArchiveMember<'data> {
        self.member
    }

    #[must_use]
    pub fn reason(&self) -> &ArchiveSelectionReason {
        &self.reason
    }
}

/// The deterministic result of archive extraction.
#[derive(Clone, Debug)]
pub struct CoffArchivePlan<'archive, 'data> {
    selected: Vec<SelectedArchiveMember<'archive, 'data>>,
    unresolved: Vec<OwnedArchiveDemand>,
}

impl<'archive, 'data> CoffArchivePlan<'archive, 'data> {
    #[must_use]
    pub fn selected(&self) -> &[SelectedArchiveMember<'archive, 'data>] {
        &self.selected
    }

    #[must_use]
    pub fn unresolved(&self) -> &[OwnedArchiveDemand] {
        &self.unresolved
    }
}

/// A parsed regular GNU or MSVC archive containing AMD64 COFF members.
#[derive(Clone, Debug)]
pub struct CoffArchive<'data> {
    members: Vec<CoffArchiveMember<'data>>,
    definition_members: HashMap<Cow<'data, [u8]>, DefinitionMember>,
}

#[derive(Clone, Copy, Debug)]
struct DefinitionMember {
    first: usize,
    has_object: bool,
}

impl<'data> CoffArchive<'data> {
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        let archive = ArchiveFile::parse(data).map_err(|error| {
            CoffArchiveError::archive(
                CoffArchiveErrorKind::InvalidArchive,
                format!("invalid archive: {error}"),
            )
        })?;
        if archive.is_thin() {
            return Err(CoffArchiveError::archive(
                CoffArchiveErrorKind::ThinArchive,
                "thin COFF archives are not self-contained and are unsupported",
            ));
        }
        match archive.kind() {
            ArchiveKind::Unknown | ArchiveKind::Gnu | ArchiveKind::Gnu64 | ArchiveKind::Coff => {}
            kind => {
                return Err(CoffArchiveError::archive(
                    CoffArchiveErrorKind::UnsupportedArchive,
                    format!("unsupported archive format {kind:?}; expected GNU or MSVC COFF"),
                ));
            }
        }

        let symbols = archive.symbols().map_err(|error| {
            CoffArchiveError::archive(
                CoffArchiveErrorKind::InvalidSymbolIndex,
                format!("invalid archive symbol index: {error}"),
            )
        })?;
        let has_symbol_index = symbols.is_some();
        let mut members = Vec::new();
        let mut member_indices_by_offset = HashMap::new();
        for raw_member in archive.members() {
            let raw_member = raw_member.map_err(|error| {
                CoffArchiveError::archive(
                    CoffArchiveErrorKind::InvalidArchive,
                    format!("invalid archive member header: {error}"),
                )
            })?;
            let name = raw_member.name();
            let member_data = raw_member.data(data).map_err(|error| {
                CoffArchiveError::member(
                    CoffArchiveErrorKind::InvalidMember,
                    name,
                    format!("cannot read data: {error}"),
                )
            })?;
            let parsed = if has_symbol_index {
                classify_member(name, member_data)
            } else {
                eagerly_parse_member(name, member_data)?
            };
            let demands = OnceLock::new();
            if let Some(parsed_demands) = parsed.demands {
                demands
                    .set(Ok(parsed_demands))
                    .expect("new archive-member demand cell is empty");
            }
            let member_index = members.len();
            members.push(PendingArchiveMember {
                index: member_index,
                name,
                data: member_data,
                kind: parsed.kind,
                opaque_error: parsed.opaque_error,
                definitions: parsed.definitions,
                demands,
            });
            if let Some(header) = raw_member.header() {
                let header_offset =
                    std::ptr::from_ref(header).cast::<u8>() as usize - data.as_ptr() as usize;
                member_indices_by_offset.insert(header_offset as u64, member_index);
            }
        }

        let mut indexed_definitions = Vec::new();
        if let Some(symbols) = symbols {
            for symbol in symbols {
                let symbol = symbol.map_err(|error| {
                    CoffArchiveError::archive(
                        CoffArchiveErrorKind::InvalidSymbolIndex,
                        format!("invalid archive symbol entry: {error}"),
                    )
                })?;
                let Some(member_index) = member_indices_by_offset.get(&symbol.offset().0).copied()
                else {
                    return Err(CoffArchiveError::archive(
                        CoffArchiveErrorKind::InvalidSymbolIndex,
                        "archive symbol points outside the ordinary member list",
                    ));
                };
                indexed_definitions.push((member_index, Cow::Borrowed(symbol.name())));
            }
        }
        let members = finalize_members(members, indexed_definitions)?;

        let mut definition_members = HashMap::<Cow<'data, [u8]>, DefinitionMember>::new();
        for member in &members {
            for definition in member.definitions.as_slice() {
                definition_members
                    .entry(definition.clone())
                    .and_modify(|entry| {
                        entry.has_object |=
                            matches!(member.kind, CoffArchiveMemberKind::CoffObject { .. });
                    })
                    .or_insert(DefinitionMember {
                        first: member.index,
                        has_object: matches!(member.kind, CoffArchiveMemberKind::CoffObject { .. }),
                    });
            }
        }

        Ok(Self {
            members,
            definition_members,
        })
    }

    /// Reports whether this archive has a linker symbol index without parsing ordinary members.
    pub fn has_symbol_index(data: &'data [u8]) -> Result<bool> {
        let archive = ArchiveFile::parse(data).map_err(|error| {
            CoffArchiveError::archive(
                CoffArchiveErrorKind::InvalidArchive,
                format!("invalid archive: {error}"),
            )
        })?;
        archive
            .symbols()
            .map(|symbols| symbols.is_some())
            .map_err(|error| {
                CoffArchiveError::archive(
                    CoffArchiveErrorKind::InvalidSymbolIndex,
                    format!("invalid archive symbol index: {error}"),
                )
            })
    }

    #[must_use]
    pub fn members(&self) -> &[CoffArchiveMember<'data>] {
        &self.members
    }

    /// Returns whether the archive index associates `name` with a regular COFF object.
    #[must_use]
    pub fn has_object_definition(&self, name: &[u8]) -> bool {
        self.definition_members
            .get(name)
            .is_some_and(|entry| entry.has_object)
    }

    /// Returns the first member associated with `name` by this archive's definition index.
    ///
    /// This is the same member lookup used by shallow extraction planning. Callers that cache
    /// providers across archives can use it without walking every archive for every resolution
    /// pass.
    #[must_use]
    pub fn first_definition_member_index(&self, name: &[u8]) -> Option<usize> {
        self.definition_members.get(name).map(|entry| entry.first)
    }

    /// Selects members to a fixpoint.
    ///
    /// `defined` contains definitions supplied by objects seen before this
    /// archive. Strong demands dominate weak-library demands with the same
    /// name. In normal mode the earliest unresolved demand selects the first
    /// matching member in archive order. Whole-archive mode preserves member
    /// order and selects each member exactly once.
    #[must_use]
    pub fn plan<'archive, 'name>(
        &'archive self,
        demands: &[ArchiveDemand<'name>],
        defined: &[&[u8]],
        whole_archive: bool,
    ) -> CoffArchivePlan<'archive, 'data> {
        let definitions = defined.iter().copied().collect::<HashSet<_>>();
        self.plan_with_defined_lookup(demands, whole_archive, |name| definitions.contains(name))
    }

    /// Plans extraction while querying the caller's existing symbol state in place.
    ///
    /// This avoids copying and re-hashing a large global definition set for every
    /// archive pass. Definitions introduced by selected members remain local to
    /// this plan and are consulted before the caller-provided lookup.
    pub fn plan_with_defined_lookup<'archive, 'name>(
        &'archive self,
        demands: &[ArchiveDemand<'name>],
        whole_archive: bool,
        mut is_defined: impl FnMut(&[u8]) -> bool,
    ) -> CoffArchivePlan<'archive, 'data> {
        self.plan_impl(demands, whole_archive, &mut is_defined, true)
    }

    /// Select members for the caller's current demand set without decoding newly selected COFF
    /// symbol tables. The caller must absorb selected objects and invoke this method again for
    /// any demands they introduce. This is useful for linkers that already parse selected objects
    /// into their own symbol database and avoids doing that work twice.
    pub fn plan_shallow_with_defined_lookup<'archive, 'name>(
        &'archive self,
        demands: &[ArchiveDemand<'name>],
        whole_archive: bool,
        mut is_defined: impl FnMut(&[u8]) -> bool,
    ) -> CoffArchivePlan<'archive, 'data> {
        self.plan_impl(demands, whole_archive, &mut is_defined, false)
    }

    /// Selects shallow archive members without materializing the unresolved-demand result.
    ///
    /// This is equivalent to [`Self::plan_shallow_with_defined_lookup`] for callers that only
    /// consume the selected members. It first discards demands that this archive cannot satisfy,
    /// then retains borrowed demand and definition names while planning. Large links commonly
    /// have many archives but only a handful of relevant demands per archive, so avoiding an
    /// owned copy of every global demand for every archive substantially reduces resolver work.
    pub fn select_shallow_members_with_defined_lookup<'archive, 'name>(
        &'archive self,
        demands: &[ArchiveDemand<'name>],
        whole_archive: bool,
        mut is_defined: impl FnMut(&[u8]) -> bool,
    ) -> Vec<&'archive CoffArchiveMember<'data>> {
        if whole_archive {
            return self.members.iter().collect();
        }

        let mut local_definitions = HashSet::<&[u8]>::new();
        let mut selected_indices = HashSet::new();
        let mut selected = Vec::new();
        // Selection and local-definition sets only grow. A candidate skipped because its demand
        // was defined or its member was already selected can therefore never become eligible on
        // a later restart. Walk demand-ordered candidates once instead of rescanning the prefix
        // after every extraction. Keep the lookup linearized here rather than materializing a
        // second candidate Vec; NameId-based callers already retain the provider row externally.
        for demand in demands {
            let name = demand.name;
            let Some(member_index) = self
                .definition_members
                .get(name)
                .filter(|_| !is_defined(name))
                .map(|entry| entry.first)
            else {
                continue;
            };
            if local_definitions.contains(name) || !selected_indices.insert(member_index) {
                continue;
            }
            let member = &self.members[member_index];
            local_definitions.extend(member.definitions.as_slice().iter().map(AsRef::as_ref));
            selected.push(member);
        }
        selected
    }

    /// Selects shallow members from provider rows already resolved by the caller.
    ///
    /// `candidates` is in canonical demand order and contains the first member associated with
    /// each demand in this archive. This is the NameId/CSR fast path: it preserves the same
    /// linear shallow-selection algorithm without hashing raw names through
    /// `definition_members` again.
    #[must_use]
    pub fn select_shallow_members_from_provider_indices<'archive>(
        &'archive self,
        candidates: &[(&[u8], usize)],
        whole_archive: bool,
    ) -> Vec<&'archive CoffArchiveMember<'data>> {
        if whole_archive {
            return self.members.iter().collect();
        }

        let mut local_definitions = HashSet::<&[u8]>::new();
        let mut selected_indices = HashSet::new();
        let mut selected = Vec::new();
        for &(name, member_index) in candidates {
            if local_definitions.contains(name) || !selected_indices.insert(member_index) {
                continue;
            }
            let Some(member) = self.members.get(member_index) else {
                debug_assert!(false, "cached archive provider member is out of range");
                continue;
            };
            local_definitions.extend(member.definitions.as_slice().iter().map(AsRef::as_ref));
            selected.push(member);
        }
        selected
    }

    fn plan_impl<'archive, 'name>(
        &'archive self,
        demands: &[ArchiveDemand<'name>],
        whole_archive: bool,
        is_defined: &mut impl FnMut(&[u8]) -> bool,
        expand_demands: bool,
    ) -> CoffArchivePlan<'archive, 'data> {
        let mut definitions = HashSet::<Vec<u8>>::new();
        let mut unresolved = Vec::new();
        for demand in demands {
            add_demand_with_lookup(
                &mut unresolved,
                &definitions,
                is_defined,
                demand.name,
                demand.kind,
            );
        }

        let mut selected = Vec::new();
        let mut was_selected = vec![false; self.members.len()];
        if whole_archive {
            for member in &self.members {
                was_selected[member.index] = true;
                absorb_member_with_lookup(
                    member,
                    &mut definitions,
                    &mut unresolved,
                    is_defined,
                    expand_demands,
                );
                selected.push(SelectedArchiveMember {
                    member,
                    reason: ArchiveSelectionReason::WholeArchive,
                });
            }
        } else {
            loop {
                let candidate = unresolved.iter().find_map(|demand| {
                    self.definition_members
                        .get(demand.name())
                        .map(|entry| entry.first)
                        .filter(|index| !was_selected[*index])
                        .map(|index| &self.members[index])
                        .map(|member| (member, demand.clone()))
                });
                let Some((member, trigger)) = candidate else {
                    break;
                };
                was_selected[member.index] = true;
                absorb_member_with_lookup(
                    member,
                    &mut definitions,
                    &mut unresolved,
                    is_defined,
                    expand_demands,
                );
                selected.push(SelectedArchiveMember {
                    member,
                    reason: ArchiveSelectionReason::Symbol(trigger),
                });
            }
        }

        CoffArchivePlan {
            selected,
            unresolved,
        }
    }
}

fn finalize_members<'data>(
    mut members: Vec<PendingArchiveMember<'data>>,
    indexed_definitions: Vec<(usize, Cow<'data, [u8]>)>,
) -> Result<Vec<CoffArchiveMember<'data>>> {
    let mut counts = vec![0usize; members.len()];
    for member in &members {
        counts[member.index] += member.definitions.len();
    }
    for (member_index, _) in &indexed_definitions {
        counts[*member_index] += 1;
    }

    let definition_count = counts.iter().sum();
    let mut starts = Vec::with_capacity(members.len());
    let mut next_start = 0;
    for &count in &counts {
        starts.push(next_start);
        next_start += count;
    }
    let mut cursors = starts.clone();
    let mut grouped_definitions: Vec<Cow<'data, [u8]>> = vec![Cow::Borrowed(&[]); definition_count];
    for member in &mut members {
        for definition in std::mem::take(&mut member.definitions) {
            grouped_definitions[cursors[member.index]] = definition;
            cursors[member.index] += 1;
        }
    }
    for (member_index, definition) in indexed_definitions {
        grouped_definitions[cursors[member_index]] = definition;
        cursors[member_index] += 1;
    }
    debug_assert!(
        cursors
            .iter()
            .zip(&starts)
            .zip(&counts)
            .all(|((&cursor, &start), &count)| cursor == start + count)
    );

    let mut definitions = Vec::with_capacity(definition_count);
    let mut ranges = Vec::with_capacity(members.len());
    let mut grouped = grouped_definitions.into_iter();
    let mut large_seen = HashSet::new();
    const LINEAR_DEDUP_LIMIT: usize = 8;
    for count in counts {
        let start = definitions.len();
        if count <= LINEAR_DEDUP_LIMIT {
            for definition in grouped.by_ref().take(count) {
                if !contains_name(&definitions[start..], definition.as_ref()) {
                    definitions.push(definition);
                }
            }
        } else {
            large_seen.clear();
            large_seen.reserve(count);
            for definition in grouped.by_ref().take(count) {
                if large_seen.insert(definition.clone()) {
                    definitions.push(definition);
                }
            }
        }
        ranges.push((
            u32::try_from(start).map_err(|_| {
                CoffArchiveError::archive(
                    CoffArchiveErrorKind::InvalidSymbolIndex,
                    "archive definition count exceeds 32-bit range",
                )
            })?,
            u32::try_from(definitions.len()).map_err(|_| {
                CoffArchiveError::archive(
                    CoffArchiveErrorKind::InvalidSymbolIndex,
                    "archive definition count exceeds 32-bit range",
                )
            })?,
        ));
    }
    debug_assert!(grouped.next().is_none());

    let definitions = Arc::new(definitions);
    Ok(members
        .into_iter()
        .zip(ranges)
        .map(|(member, (start, end))| CoffArchiveMember {
            index: member.index,
            name: member.name,
            data: member.data,
            kind: member.kind,
            opaque_error: member.opaque_error,
            definitions: MemberDefinitions {
                values: Arc::clone(&definitions),
                start,
                end,
            },
            demands: member.demands,
        })
        .collect())
}

struct ParsedMember<'data> {
    kind: CoffArchiveMemberKind<'data>,
    definitions: Vec<Cow<'data, [u8]>>,
    demands: Option<Vec<OwnedArchiveDemand>>,
    opaque_error: Option<CoffArchiveError>,
}

type ParsedMemberParts<'data> = (
    CoffArchiveMemberKind<'data>,
    Vec<Cow<'data, [u8]>>,
    Vec<OwnedArchiveDemand>,
);

fn eagerly_parse_member<'data>(name: &[u8], data: &'data [u8]) -> Result<ParsedMember<'data>> {
    match parse_member(name, data) {
        Ok((kind, definitions, demands)) => Ok(ParsedMember {
            kind,
            definitions,
            demands: Some(demands),
            opaque_error: None,
        }),
        Err(error) if error.kind() == CoffArchiveErrorKind::UnsupportedMember => Ok(ParsedMember {
            kind: CoffArchiveMemberKind::Opaque,
            definitions: Vec::new(),
            demands: Some(Vec::new()),
            opaque_error: Some(error),
        }),
        Err(error) => Err(error),
    }
}

/// Classify indexed members without walking their symbol tables. The archive linker index is
/// sufficient for extraction; undefined symbols are decoded only if the member is selected.
fn classify_member<'data>(name: &[u8], data: &'data [u8]) -> ParsedMember<'data> {
    let kind = match FileKind::parse(data) {
        Ok(FileKind::Coff) => Some(CoffArchiveMemberKind::CoffObject { is_bigobj: false }),
        Ok(FileKind::CoffBig) => Some(CoffArchiveMemberKind::CoffObject { is_bigobj: true }),
        Ok(FileKind::CoffImport) => match ShortImportObject::parse(data) {
            Ok(import) => Some(CoffArchiveMemberKind::ShortImport(import)),
            Err(error) => {
                return ParsedMember {
                    kind: CoffArchiveMemberKind::Opaque,
                    definitions: Vec::new(),
                    demands: Some(Vec::new()),
                    opaque_error: Some(CoffArchiveError::member(
                        CoffArchiveErrorKind::InvalidMember,
                        name,
                        error.to_string(),
                    )),
                };
            }
        },
        _ => None,
    };
    match kind {
        Some(kind) => ParsedMember {
            kind,
            definitions: Vec::new(),
            demands: (!matches!(kind, CoffArchiveMemberKind::CoffObject { .. })).then(Vec::new),
            opaque_error: None,
        },
        None => ParsedMember {
            kind: CoffArchiveMemberKind::Opaque,
            definitions: Vec::new(),
            demands: Some(Vec::new()),
            opaque_error: Some(CoffArchiveError::member(
                CoffArchiveErrorKind::UnsupportedMember,
                name,
                "unrecognized or unsupported archive member format",
            )),
        },
    }
}

fn parse_member<'data>(name: &[u8], data: &'data [u8]) -> Result<ParsedMemberParts<'data>> {
    let kind = FileKind::parse(data).map_err(|error| {
        CoffArchiveError::member(
            CoffArchiveErrorKind::UnsupportedMember,
            name,
            format!("unrecognized member format: {error}"),
        )
    })?;
    match kind {
        FileKind::CoffImport => {
            let import = ShortImportObject::parse(data).map_err(|error| {
                CoffArchiveError::member(
                    CoffArchiveErrorKind::InvalidMember,
                    name,
                    error.to_string(),
                )
            })?;
            Ok((
                CoffArchiveMemberKind::ShortImport(import),
                vec![Cow::Owned(import.symbol().to_vec())],
                Vec::new(),
            ))
        }
        FileKind::Coff => parse_coff::<pe::ImageFileHeader>(name, data, false),
        FileKind::CoffBig => parse_coff::<pe::AnonObjectHeaderBigobj>(name, data, true),
        other => Err(CoffArchiveError::member(
            CoffArchiveErrorKind::UnsupportedMember,
            name,
            format!("unsupported member format {other:?}; expected AMD64 COFF"),
        )),
    }
}

fn parse_coff<'data, Coff: CoffHeader>(
    name: &[u8],
    data: &'data [u8],
    is_bigobj: bool,
) -> Result<ParsedMemberParts<'data>> {
    let file = object::read::coff::CoffFile::<_, Coff>::parse(data).map_err(|error| {
        CoffArchiveError::member(
            CoffArchiveErrorKind::InvalidMember,
            name,
            format!("malformed COFF object: {error}"),
        )
    })?;
    if file.architecture() != Architecture::X86_64 {
        return Err(CoffArchiveError::member(
            CoffArchiveErrorKind::UnsupportedMember,
            name,
            format!(
                "unsupported COFF architecture {:?}; only AMD64 is supported",
                file.architecture()
            ),
        ));
    }

    let mut definitions = Vec::new();
    let mut demands = Vec::new();
    for symbol in file.symbols() {
        let symbol_name = symbol.name_bytes().map_err(|error| {
            CoffArchiveError::member(
                CoffArchiveErrorKind::InvalidMember,
                name,
                format!("invalid COFF symbol name: {error}"),
            )
        })?;
        if symbol_name.is_empty() {
            continue;
        }
        if symbol.is_definition() && symbol.is_global() {
            add_unique(&mut definitions, symbol_name);
        } else if symbol.is_undefined() && !symbol.is_common() && symbol.is_global() {
            let kind = if symbol.is_weak() {
                ArchiveDemandKind::WeakLibrary
            } else {
                ArchiveDemandKind::Strong
            };
            add_owned_demand(&mut demands, symbol_name, kind);
        }
    }

    // The unified API identifies all undefined COFF weak externals as weak.
    // Refine that to SEARCH_LIBRARY: aliases and anti-dependencies must not
    // pull archive members.
    let table = file.coff_symbol_table();
    let strings = table.strings();
    for (index, raw) in table.iter() {
        if !raw.has_aux_weak_external() {
            continue;
        }
        let raw_name = raw.name(strings).map_err(|error| {
            CoffArchiveError::member(
                CoffArchiveErrorKind::InvalidMember,
                name,
                format!("invalid weak external name: {error}"),
            )
        })?;
        let auxiliary = table.aux_weak_external(index).map_err(|error| {
            CoffArchiveError::member(
                CoffArchiveErrorKind::InvalidMember,
                name,
                format!("invalid weak external auxiliary record: {error}"),
            )
        })?;
        if auxiliary.weak_search_type.get(LE) != pe::IMAGE_WEAK_EXTERN_SEARCH_LIBRARY {
            demands.retain(|demand| {
                demand.name() != raw_name || demand.kind() != ArchiveDemandKind::WeakLibrary
            });
        }
    }

    Ok((
        CoffArchiveMemberKind::CoffObject { is_bigobj },
        definitions,
        demands,
    ))
}

fn absorb_member_with_lookup(
    member: &CoffArchiveMember<'_>,
    definitions: &mut HashSet<Vec<u8>>,
    unresolved: &mut Vec<OwnedArchiveDemand>,
    is_defined: &mut impl FnMut(&[u8]) -> bool,
    expand_demands: bool,
) {
    for definition in member.definitions.as_slice() {
        definitions.insert(definition.as_ref().to_vec());
    }
    unresolved.retain(|demand| !definitions.contains(demand.name()) && !is_defined(demand.name()));
    if !expand_demands {
        return;
    }
    for demand in member.demands() {
        add_demand_with_lookup(
            unresolved,
            definitions,
            is_defined,
            demand.name(),
            demand.kind(),
        );
    }
}

fn add_demand_with_lookup(
    demands: &mut Vec<OwnedArchiveDemand>,
    definitions: &HashSet<Vec<u8>>,
    is_defined: &mut impl FnMut(&[u8]) -> bool,
    name: &[u8],
    kind: ArchiveDemandKind,
) {
    if definitions.contains(name) || is_defined(name) {
        return;
    }
    add_owned_demand(demands, name, kind);
}

fn add_owned_demand(demands: &mut Vec<OwnedArchiveDemand>, name: &[u8], kind: ArchiveDemandKind) {
    if let Some(existing) = demands.iter_mut().find(|demand| demand.name() == name) {
        if kind == ArchiveDemandKind::Strong {
            existing.kind = ArchiveDemandKind::Strong;
        }
    } else {
        demands.push(OwnedArchiveDemand::new(name, kind));
    }
}

fn add_unique(names: &mut Vec<Cow<'_, [u8]>>, name: &[u8]) {
    if !contains_name(names, name) {
        names.push(Cow::Owned(name.to_vec()));
    }
}

fn contains_name(names: &[Cow<'_, [u8]>], needle: &[u8]) -> bool {
    names.iter().any(|name| name.as_ref() == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    enum TestArchiveKind {
        Gnu,
        Coff,
    }

    struct TestMember<'a> {
        name: &'a str,
        data: Vec<u8>,
        symbols: &'a [&'a str],
    }

    #[test]
    fn extracts_to_a_fixpoint_in_demand_order() {
        let archive = test_archive(
            TestArchiveKind::Gnu,
            &[
                TestMember {
                    name: "bar.obj",
                    data: coff_object(&["bar"], &[]),
                    symbols: &["bar"],
                },
                TestMember {
                    name: "foo.obj",
                    data: coff_object(&["foo"], &["bar"]),
                    symbols: &["foo"],
                },
                TestMember {
                    name: "unused.obj",
                    data: coff_object(&["unused"], &[]),
                    symbols: &["unused"],
                },
            ],
            false,
        );
        let parsed = CoffArchive::parse(&archive).unwrap();
        let plan = parsed.plan(
            &[ArchiveDemand {
                name: b"foo",
                kind: ArchiveDemandKind::Strong,
            }],
            &[],
            false,
        );
        let names: Vec<_> = plan
            .selected()
            .iter()
            .map(|selected| selected.member().name())
            .collect();
        assert_eq!(names, [b"foo.obj".as_slice(), b"bar.obj".as_slice()]);
        assert!(plan.unresolved().is_empty());
    }

    #[test]
    fn parses_msvc_index_and_long_member_names() {
        let long_name = "a_very_long_member_name_for_coff.obj";
        let archive = test_archive(
            TestArchiveKind::Coff,
            &[TestMember {
                name: long_name,
                data: coff_object(&["entry"], &[]),
                symbols: &["entry"],
            }],
            true,
        );
        let parsed = CoffArchive::parse(&archive).unwrap();
        assert_eq!(parsed.members()[0].name(), long_name.as_bytes());
        assert_eq!(parsed.first_definition_member_index(b"entry"), Some(0));
        assert_eq!(parsed.first_definition_member_index(b"missing"), None);
        let plan = parsed.plan(
            &[ArchiveDemand {
                name: b"entry",
                kind: ArchiveDemandKind::Strong,
            }],
            &[],
            false,
        );
        assert_eq!(plan.selected().len(), 1);
    }

    #[test]
    fn large_indexed_member_definition_lists_are_stably_deduplicated() {
        let symbols = [
            "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "three",
            "nine", "zero",
        ];
        let archive = test_archive(
            TestArchiveKind::Gnu,
            &[TestMember {
                name: "many.obj",
                data: coff_object(&symbols[..10], &[]),
                symbols: &symbols,
            }],
            false,
        );
        let parsed = CoffArchive::parse(&archive).unwrap();
        let definitions = parsed.members()[0]
            .definitions()
            .map(String::from_utf8_lossy)
            .collect::<Vec<_>>();
        assert_eq!(
            definitions,
            [
                "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"
            ]
        );
    }

    #[test]
    fn parses_gnu_long_member_names() {
        let long_name = "another_very_long_member_name_for_gnu.obj";
        let archive = test_archive(
            TestArchiveKind::Gnu,
            &[TestMember {
                name: long_name,
                data: coff_object(&["entry"], &[]),
                symbols: &["entry"],
            }],
            true,
        );
        let parsed = CoffArchive::parse(&archive).unwrap();
        assert_eq!(parsed.members()[0].name(), long_name.as_bytes());
        assert_eq!(
            parsed
                .plan(
                    &[ArchiveDemand {
                        name: b"entry",
                        kind: ArchiveDemandKind::Strong,
                    }],
                    &[],
                    false,
                )
                .selected()
                .len(),
            1
        );
    }

    #[test]
    fn honors_definitions_weak_demands_and_whole_archive() {
        let archive = test_archive(
            TestArchiveKind::Gnu,
            &[
                TestMember {
                    name: "weak.obj",
                    data: coff_object(&["weak"], &[]),
                    symbols: &["weak"],
                },
                TestMember {
                    name: "other.obj",
                    data: coff_object(&["other"], &[]),
                    symbols: &["other"],
                },
            ],
            false,
        );
        let parsed = CoffArchive::parse(&archive).unwrap();
        let weak = ArchiveDemand {
            name: b"weak",
            kind: ArchiveDemandKind::WeakLibrary,
        };
        assert!(
            parsed
                .plan(&[weak], &[b"weak"], false)
                .selected()
                .is_empty()
        );
        let mut lookups = 0;
        let lookup_plan = parsed.plan_with_defined_lookup(&[weak], false, |name| {
            lookups += 1;
            name == b"weak"
        });
        assert!(lookup_plan.selected().is_empty());
        assert_eq!(lookups, 1);

        let plan = parsed.plan(&[weak], &[], false);
        assert_eq!(plan.selected()[0].member().name(), b"weak.obj");
        assert!(matches!(
            plan.selected()[0].reason(),
            ArchiveSelectionReason::Symbol(demand)
                if demand.kind() == ArchiveDemandKind::WeakLibrary
        ));

        let whole = parsed.plan(&[], &[], true);
        assert_eq!(whole.selected().len(), 2);
        assert!(
            whole
                .selected()
                .iter()
                .all(|member| member.reason() == &ArchiveSelectionReason::WholeArchive)
        );
    }

    #[test]
    fn handles_mixed_regular_and_short_import_members() {
        let archive = test_archive(
            TestArchiveKind::Coff,
            &[
                TestMember {
                    name: "helper.obj",
                    data: coff_object(&["helper"], &[]),
                    symbols: &["helper"],
                },
                TestMember {
                    name: "exit.obj",
                    data: short_import("ExitProcess", "KERNEL32.dll"),
                    symbols: &["ExitProcess", "__imp_ExitProcess"],
                },
            ],
            false,
        );
        let parsed = CoffArchive::parse(&archive).unwrap();
        let plan = parsed.plan(
            &[ArchiveDemand {
                name: b"__imp_ExitProcess",
                kind: ArchiveDemandKind::Strong,
            }],
            &[],
            false,
        );
        assert_eq!(plan.selected().len(), 1);
        assert!(matches!(
            plan.selected()[0].member().kind(),
            CoffArchiveMemberKind::ShortImport(import) if import.symbol() == b"ExitProcess"
        ));
    }

    #[test]
    fn never_extracts_the_same_member_twice_and_reports_unresolved() {
        let archive = test_archive(
            TestArchiveKind::Gnu,
            &[TestMember {
                name: "both.obj",
                data: coff_object(&["one", "two"], &["missing"]),
                symbols: &["one", "two"],
            }],
            false,
        );
        let parsed = CoffArchive::parse(&archive).unwrap();
        let plan = parsed.plan(
            &[
                ArchiveDemand {
                    name: b"one",
                    kind: ArchiveDemandKind::Strong,
                },
                ArchiveDemand {
                    name: b"two",
                    kind: ArchiveDemandKind::Strong,
                },
            ],
            &[],
            false,
        );
        assert_eq!(plan.selected().len(), 1);
        assert_eq!(plan.unresolved()[0].name(), b"missing");
    }

    #[test]
    fn rejects_thin_archives_and_defers_non_coff_member_errors() {
        let thin = b"!<thin>\n";
        let error = CoffArchive::parse(thin).unwrap_err();
        assert_eq!(error.kind(), CoffArchiveErrorKind::ThinArchive);

        let archive = test_archive(
            TestArchiveKind::Gnu,
            &[TestMember {
                name: "bad.txt",
                data: b"not an object".to_vec(),
                symbols: &[],
            }],
            false,
        );
        let parsed = CoffArchive::parse(&archive).unwrap();
        let member = &parsed.members()[0];
        assert_eq!(member.kind(), CoffArchiveMemberKind::Opaque);
        let error = member.opaque_error().unwrap();
        assert_eq!(error.kind(), CoffArchiveErrorKind::UnsupportedMember);
        assert_eq!(error.member_name(), Some(b"bad.txt".as_slice()));
        assert!(parsed.plan(&[], &[], false).selected().is_empty());
        assert_eq!(parsed.plan(&[], &[], true).selected().len(), 1);

        let mut malformed_import = short_import("ExitProcess", "KERNEL32.dll");
        malformed_import.pop();
        let archive = test_archive(
            TestArchiveKind::Coff,
            &[TestMember {
                name: "broken.obj",
                data: malformed_import,
                symbols: &["ExitProcess"],
            }],
            false,
        );
        let parsed = CoffArchive::parse(&archive).unwrap();
        let broken = &parsed.members()[0];
        assert_eq!(broken.kind(), CoffArchiveMemberKind::Opaque);
        assert_eq!(
            broken.opaque_error().unwrap().kind(),
            CoffArchiveErrorKind::InvalidMember
        );
        assert_eq!(
            parsed
                .plan(
                    &[ArchiveDemand {
                        name: b"ExitProcess",
                        kind: ArchiveDemandKind::Strong,
                    }],
                    &[],
                    false,
                )
                .selected()
                .len(),
            1
        );
    }

    #[test]
    fn indexed_members_decode_demands_only_when_full_planning_needs_them() {
        let archive = test_archive(
            TestArchiveKind::Gnu,
            &[
                TestMember {
                    name: "bar.obj",
                    data: coff_object(&["bar"], &[]),
                    symbols: &["bar"],
                },
                TestMember {
                    name: "foo.obj",
                    data: coff_object(&["foo"], &["bar"]),
                    symbols: &["foo"],
                },
            ],
            false,
        );
        let parsed = CoffArchive::parse(&archive).unwrap();
        assert!(
            parsed
                .members()
                .iter()
                .all(|member| member.demands.get().is_none())
        );
        let demand = ArchiveDemand {
            name: b"foo",
            kind: ArchiveDemandKind::Strong,
        };
        let shallow = parsed.plan_shallow_with_defined_lookup(&[demand], false, |_| false);
        assert_eq!(shallow.selected().len(), 1);
        assert!(
            parsed
                .members()
                .iter()
                .all(|member| member.demands.get().is_none())
        );

        let full = parsed.plan(&[demand], &[], false);
        assert_eq!(full.selected().len(), 2);
        assert!(parsed.members()[1].demands.get().is_some());
    }

    #[test]
    fn borrowed_shallow_selection_matches_shallow_plan() {
        let archive = test_archive(
            TestArchiveKind::Gnu,
            &[
                TestMember {
                    name: "first.obj",
                    data: coff_object(&["first", "alias"], &[]),
                    symbols: &["first", "alias"],
                },
                TestMember {
                    name: "second.obj",
                    data: coff_object(&["second"], &[]),
                    symbols: &["second"],
                },
            ],
            false,
        );
        let parsed = CoffArchive::parse(&archive).unwrap();
        let demands = [
            ArchiveDemand {
                name: b"missing",
                kind: ArchiveDemandKind::Strong,
            },
            ArchiveDemand {
                name: b"alias",
                kind: ArchiveDemandKind::Strong,
            },
            ArchiveDemand {
                name: b"first",
                kind: ArchiveDemandKind::WeakLibrary,
            },
            ArchiveDemand {
                name: b"second",
                kind: ArchiveDemandKind::Strong,
            },
        ];
        let planned = parsed.plan_shallow_with_defined_lookup(&demands, false, |_| false);
        let borrowed =
            parsed.select_shallow_members_with_defined_lookup(&demands, false, |_| false);
        assert_eq!(
            borrowed
                .iter()
                .map(|member| member.index())
                .collect::<Vec<_>>(),
            planned
                .selected()
                .iter()
                .map(|selected| selected.member().index())
                .collect::<Vec<_>>()
        );
        let provider_rows = [
            (b"alias".as_slice(), 0),
            (b"first".as_slice(), 0),
            (b"second".as_slice(), 1),
        ];
        let from_provider_rows =
            parsed.select_shallow_members_from_provider_indices(&provider_rows, false);
        assert_eq!(
            from_provider_rows
                .iter()
                .map(|member| member.index())
                .collect::<Vec<_>>(),
            borrowed
                .iter()
                .map(|member| member.index())
                .collect::<Vec<_>>()
        );

        let planned =
            parsed.plan_shallow_with_defined_lookup(&demands, false, |name| name == b"second");
        let borrowed = parsed
            .select_shallow_members_with_defined_lookup(&demands, false, |name| name == b"second");
        assert_eq!(borrowed.len(), planned.selected().len());
        assert_eq!(borrowed[0].index(), planned.selected()[0].member().index());

        let borrowed = parsed.select_shallow_members_with_defined_lookup(&[], true, |_| false);
        assert_eq!(borrowed.len(), parsed.members().len());
        assert_eq!(
            parsed
                .select_shallow_members_from_provider_indices(&[], true)
                .len(),
            parsed.members().len()
        );
    }

    #[test]
    fn linear_shallow_selection_preserves_order_duplicates_and_demand_kinds() {
        let archive = test_archive(
            TestArchiveKind::Gnu,
            &[
                TestMember {
                    name: "many.obj",
                    data: coff_object(&["alias", "first", "later"], &[]),
                    symbols: &["alias", "first", "later"],
                },
                TestMember {
                    name: "next.obj",
                    data: coff_object(&["next"], &[]),
                    symbols: &["next"],
                },
                TestMember {
                    name: "global.obj",
                    data: coff_object(&["global"], &[]),
                    symbols: &["global"],
                },
            ],
            false,
        );
        let parsed = CoffArchive::parse(&archive).unwrap();
        let demands = [
            ArchiveDemand {
                name: b"alias",
                kind: ArchiveDemandKind::WeakLibrary,
            },
            ArchiveDemand {
                name: b"first",
                kind: ArchiveDemandKind::Strong,
            },
            ArchiveDemand {
                name: b"next",
                kind: ArchiveDemandKind::WeakLibrary,
            },
            ArchiveDemand {
                name: b"later",
                kind: ArchiveDemandKind::Strong,
            },
            ArchiveDemand {
                name: b"alias",
                kind: ArchiveDemandKind::Strong,
            },
            ArchiveDemand {
                name: b"global",
                kind: ArchiveDemandKind::Strong,
            },
        ];

        let selected = parsed
            .select_shallow_members_with_defined_lookup(&demands, false, |name| name == b"global");
        let selected_indices = selected
            .iter()
            .map(|member| member.index())
            .collect::<Vec<_>>();
        assert_eq!(selected_indices, [0, 1]);

        let shallow =
            parsed.plan_shallow_with_defined_lookup(&demands, false, |name| name == b"global");
        assert_eq!(
            selected_indices,
            shallow
                .selected()
                .iter()
                .map(|selection| selection.member().index())
                .collect::<Vec<_>>()
        );

        // These members introduce no new demands, so full and shallow planning coincide.
        let full = parsed.plan(&demands, &[b"global"], false);
        assert_eq!(
            selected_indices,
            full.selected()
                .iter()
                .map(|selection| selection.member().index())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn linear_shallow_selection_honors_local_definition_suppression() {
        let archive = test_archive(
            TestArchiveKind::Gnu,
            &[
                TestMember {
                    name: "first.obj",
                    data: coff_object(&["trigger", "local"], &[]),
                    symbols: &["trigger", "local"],
                },
                TestMember {
                    name: "later.obj",
                    data: coff_object(&["local"], &[]),
                    symbols: &["local"],
                },
            ],
            false,
        );
        let mut parsed = CoffArchive::parse(&archive).unwrap();

        // Model an index candidate later than a definition already carried by the first member.
        // Selecting `trigger` must suppress the later `local` candidate before member 1 is read.
        parsed
            .definition_members
            .get_mut(b"local".as_slice())
            .unwrap()
            .first = 1;
        let demands = [
            ArchiveDemand {
                name: b"trigger",
                kind: ArchiveDemandKind::Strong,
            },
            ArchiveDemand {
                name: b"local",
                kind: ArchiveDemandKind::Strong,
            },
        ];

        let selected =
            parsed.select_shallow_members_with_defined_lookup(&demands, false, |_| false);
        assert_eq!(
            selected
                .iter()
                .map(|member| member.index())
                .collect::<Vec<_>>(),
            [0]
        );
        assert_eq!(parsed.plan(&demands, &[], false).selected().len(), 1);
    }

    #[test]
    fn indexless_archives_keep_eager_symbol_fallback() {
        let data = coff_object(&["foo"], &["bar"]);
        let mut archive = object::archive::MAGIC.to_vec();
        push_archive_record(&mut archive, b"foo.obj/", &data);
        let parsed = CoffArchive::parse(&archive).unwrap();
        assert!(parsed.members()[0].demands.get().is_some());
        assert!(parsed.definition_members.contains_key(b"foo".as_slice()));
        let plan = parsed.plan(
            &[ArchiveDemand {
                name: b"foo",
                kind: ArchiveDemandKind::Strong,
            }],
            &[],
            false,
        );
        assert_eq!(plan.selected().len(), 1);
        assert_eq!(plan.unresolved()[0].name(), b"bar");
    }

    #[test]
    fn ignores_unselected_unknown_machine_member_in_msvc_archive() {
        let mut legacy_alias = coff_object(&[], &["legacy"]);
        legacy_alias[0..2].copy_from_slice(&pe::IMAGE_FILE_MACHINE_UNKNOWN.0.to_le_bytes());
        let archive = test_archive(
            TestArchiveKind::Coff,
            &[
                TestMember {
                    name: r"sdknames\_argc.obj",
                    data: legacy_alias,
                    symbols: &["_argc"],
                },
                TestMember {
                    name: "exit.obj",
                    data: short_import("ExitProcess", "KERNEL32.dll"),
                    symbols: &["ExitProcess", "__imp_ExitProcess"],
                },
            ],
            true,
        );

        let parsed = CoffArchive::parse(&archive).unwrap();
        assert_eq!(parsed.members().len(), 2);
        assert_eq!(parsed.members()[0].kind(), CoffArchiveMemberKind::Opaque);
        assert_eq!(
            parsed.members()[0].opaque_error().unwrap().kind(),
            CoffArchiveErrorKind::UnsupportedMember
        );

        let import_plan = parsed.plan(
            &[ArchiveDemand {
                name: b"__imp_ExitProcess",
                kind: ArchiveDemandKind::Strong,
            }],
            &[],
            false,
        );
        assert_eq!(import_plan.selected().len(), 1);
        assert_eq!(import_plan.selected()[0].member().name(), b"exit.obj");

        let legacy_plan = parsed.plan(
            &[ArchiveDemand {
                name: b"_argc",
                kind: ArchiveDemandKind::Strong,
            }],
            &[],
            false,
        );
        assert_eq!(legacy_plan.selected().len(), 1);
        let selected = legacy_plan.selected()[0].member();
        assert_eq!(selected.kind(), CoffArchiveMemberKind::Opaque);
        assert!(selected.opaque_error().is_some());
    }

    #[test]
    #[ignore = "requires the local xwin MSVC CRT"]
    fn probes_local_xwin_msvcrt_archive() {
        let xwin_root = std::env::var_os("XWIN_ROOT")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".xwin"))
            })
            .expect("set XWIN_ROOT or HOME");
        let path = xwin_root.join("crt/lib/x86_64/msvcrt.lib");
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let parsed = CoffArchive::parse(&bytes).unwrap();
        assert!(
            parsed
                .members()
                .iter()
                .any(|member| member.kind() == CoffArchiveMemberKind::Opaque),
            "the probe fixture no longer contains legacy opaque members"
        );
        let plan = parsed.plan(
            &[
                ArchiveDemand {
                    name: b"mainCRTStartup",
                    kind: ArchiveDemandKind::Strong,
                },
                ArchiveDemand {
                    name: b"printf",
                    kind: ArchiveDemandKind::Strong,
                },
            ],
            &[],
            false,
        );
        assert!(plan.selected().iter().any(|selected| {
            selected
                .member()
                .definitions()
                .any(|definition| definition == b"mainCRTStartup")
        }));
    }

    fn coff_object(definitions: &[&str], undefined: &[&str]) -> Vec<u8> {
        let symbol_count = definitions.len() + undefined.len();
        let mut bytes = vec![0; 20 + 40];
        bytes[0..2].copy_from_slice(&pe::IMAGE_FILE_MACHINE_AMD64.0.to_le_bytes());
        bytes[2..4].copy_from_slice(&1u16.to_le_bytes());
        bytes[8..12].copy_from_slice(&60u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&(symbol_count as u32).to_le_bytes());
        bytes[20..25].copy_from_slice(b".text");
        bytes[56..60]
            .copy_from_slice(&(pe::IMAGE_SCN_CNT_CODE.0 | pe::IMAGE_SCN_MEM_READ.0).to_le_bytes());
        for name in definitions {
            push_symbol(&mut bytes, name, 1);
        }
        for name in undefined {
            push_symbol(&mut bytes, name, 0);
        }
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes
    }

    fn push_symbol(bytes: &mut Vec<u8>, name: &str, section: i16) {
        assert!(name.len() <= 8);
        let mut symbol = [0; 18];
        symbol[..name.len()].copy_from_slice(name.as_bytes());
        symbol[12..14].copy_from_slice(&section.to_le_bytes());
        symbol[16] = pe::IMAGE_SYM_CLASS_EXTERNAL.0;
        bytes.extend_from_slice(&symbol);
    }

    fn short_import(symbol: &str, dll: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(symbol.as_bytes());
        payload.push(0);
        payload.extend_from_slice(dll.as_bytes());
        payload.push(0);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&pe::IMPORT_OBJECT_HDR_SIG2.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&pe::IMAGE_FILE_MACHINE_AMD64.0.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        let flags = pe::IMPORT_OBJECT_CODE.0 | (pe::IMPORT_OBJECT_NAME.0 << 2);
        bytes.extend_from_slice(&flags.to_le_bytes());
        bytes.extend_from_slice(&payload);
        bytes
    }

    fn test_archive(
        kind: TestArchiveKind,
        members: &[TestMember<'_>],
        long_names: bool,
    ) -> Vec<u8> {
        let names: Vec<_> = members
            .iter()
            .flat_map(|member| member.symbols.iter().copied())
            .collect();
        let first_index_size =
            4 + names.len() * 4 + names.iter().map(|name| name.len() + 1).sum::<usize>();
        let second_index_size = match kind {
            TestArchiveKind::Gnu => 0,
            TestArchiveKind::Coff => {
                4 + members.len() * 4
                    + 4
                    + names.len() * 2
                    + names.iter().map(|name| name.len() + 1).sum::<usize>()
            }
        };
        let mut long_name_data = Vec::new();
        if long_names {
            for member in members {
                long_name_data.extend_from_slice(member.name.as_bytes());
                long_name_data.extend_from_slice(b"/\n");
            }
        }
        let mut members_start = 8 + record_size(first_index_size);
        if matches!(kind, TestArchiveKind::Coff) {
            members_start += record_size(second_index_size);
        }
        if long_names {
            members_start += record_size(long_name_data.len());
        }
        let mut offsets = Vec::new();
        let mut offset = members_start;
        for member in members {
            offsets.push(offset as u32);
            offset += record_size(member.data.len());
        }

        let mut first = Vec::new();
        first.extend_from_slice(&(names.len() as u32).to_be_bytes());
        for (member_index, member) in members.iter().enumerate() {
            for _ in member.symbols {
                first.extend_from_slice(&offsets[member_index].to_be_bytes());
            }
        }
        for name in &names {
            first.extend_from_slice(name.as_bytes());
            first.push(0);
        }

        let mut archive = b"!<arch>\n".to_vec();
        push_archive_record(&mut archive, b"/", &first);
        if matches!(kind, TestArchiveKind::Coff) {
            let mut second = Vec::new();
            second.extend_from_slice(&(members.len() as u32).to_le_bytes());
            for offset in &offsets {
                second.extend_from_slice(&offset.to_le_bytes());
            }
            second.extend_from_slice(&(names.len() as u32).to_le_bytes());
            for (member_index, member) in members.iter().enumerate() {
                for _ in member.symbols {
                    second.extend_from_slice(&((member_index + 1) as u16).to_le_bytes());
                }
            }
            for name in &names {
                second.extend_from_slice(name.as_bytes());
                second.push(0);
            }
            push_archive_record(&mut archive, b"/", &second);
        }
        if long_names {
            push_archive_record(&mut archive, b"//", &long_name_data);
        }
        let mut name_offset = 0;
        for member in members {
            let header_name = if long_names {
                let value = format!("/{name_offset}");
                name_offset += member.name.len() + 2;
                value.into_bytes()
            } else {
                member.name.as_bytes().to_vec()
            };
            push_archive_record(&mut archive, &header_name, &member.data);
        }
        archive
    }

    fn record_size(data_size: usize) -> usize {
        60 + data_size + (data_size & 1)
    }

    fn push_archive_record(archive: &mut Vec<u8>, name: &[u8], data: &[u8]) {
        assert!(name.len() <= 16);
        let mut header = [b' '; 60];
        header[..name.len()].copy_from_slice(name);
        let size = data.len().to_string();
        header[48..48 + size.len()].copy_from_slice(size.as_bytes());
        header[58..60].copy_from_slice(b"`\n");
        archive.extend_from_slice(&header);
        archive.extend_from_slice(data);
        if data.len() & 1 != 0 {
            archive.push(b'\n');
        }
    }
}
