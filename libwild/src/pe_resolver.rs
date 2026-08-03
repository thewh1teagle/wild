//! COFF archive extraction used by the PE writer.

#[cfg(test)]
use crate::ensure;
use crate::error;
use crate::error::Context;
use crate::error::Result;
use linker_utils::coff_archives::CoffArchive;
use linker_utils::coff_archives::CoffArchiveMemberKind;
use linker_utils::coff_runtime::RuntimeResolution;
use linker_utils::coff_runtime::WeakExternalResolution;
use linker_utils::coff_runtime::parse_legacy_alias_object;
use linker_utils::coff_symbols::ArchiveDemand;
use linker_utils::coff_symbols::ArchiveDemandKind;
use object::Object;
use object::ObjectSymbol;
use std::collections::BTreeSet;
use std::collections::HashSet;

#[cfg(test)]
type SymbolState = (BTreeSet<Vec<u8>>, BTreeSet<Vec<u8>>);

struct IncrementalSymbolState {
    defined: BTreeSet<Vec<u8>>,
    unresolved: BTreeSet<Vec<u8>>,
    weak_resolution: WeakExternalResolution,
    absorbed_objects: usize,
}

impl IncrementalSymbolState {
    fn new() -> Self {
        Self {
            defined: BTreeSet::new(),
            unresolved: BTreeSet::new(),
            weak_resolution: WeakExternalResolution::default(),
            absorbed_objects: 0,
        }
    }

    fn add_roots(&mut self, roots: &[Vec<u8>]) {
        self.unresolved.extend(roots.iter().cloned());
        self.unresolved.retain(|name| !self.defined.contains(name));
    }

    fn absorb_object(&mut self, object: &crate::coff::CoffObject<'_>, index: usize) -> Result<()> {
        self.absorbed_objects += 1;
        for record in linker_utils::coff_runtime::parse_weak_externals(object.bytes())? {
            self.weak_resolution
                .apply(record, &format!("selected COFF object #{index}"))?;
        }
        for symbol in object.file().symbols() {
            let name = symbol.name_bytes().context("invalid COFF symbol name")?;
            if name.is_empty() || !symbol.is_global() {
                continue;
            }
            if symbol.is_undefined() && !symbol.is_common() && !symbol.is_weak() {
                self.unresolved.insert(name.to_vec());
            } else if symbol.is_definition() || symbol.is_common() {
                self.defined.insert(name.to_vec());
            }
        }
        self.unresolved.retain(|name| !self.defined.contains(name));
        Ok(())
    }

    fn define(&mut self, name: &[u8]) -> bool {
        let changed = self.defined.insert(name.to_vec());
        self.unresolved.remove(name);
        changed
    }
}

/// Incremental archive extraction state retained while default libraries are discovered.
pub(super) struct ResolverSession<'data> {
    archives: Vec<CoffArchive<'data>>,
    whole_archive: Vec<bool>,
    extracted: HashSet<(usize, usize)>,
    import_definitions: BTreeSet<Vec<u8>>,
    symbol_state: IncrementalSymbolState,
    scanned_objects: usize,
    selected_aliases: Vec<(usize, usize)>,
}

impl<'data> ResolverSession<'data> {
    pub(super) fn new() -> Self {
        Self {
            archives: Vec::new(),
            whole_archive: Vec::new(),
            extracted: HashSet::new(),
            import_definitions: BTreeSet::new(),
            symbol_state: IncrementalSymbolState::new(),
            scanned_objects: 0,
            selected_aliases: Vec::new(),
        }
    }

    pub(super) fn add_archive(&mut self, bytes: &'data [u8], whole_archive: bool) -> Result<()> {
        self.archives
            .push(CoffArchive::parse(bytes).context("invalid AMD64 COFF archive")?);
        self.whole_archive.push(whole_archive);
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn object_scan_count(&self) -> usize {
        self.symbol_state.absorbed_objects
    }

    pub(super) fn resolve(
        &mut self,
        objects: &mut Vec<crate::coff::CoffObject<'data>>,
        roots: &[Vec<u8>],
        runtime_resolution: &mut RuntimeResolution,
    ) -> Result<BTreeSet<Vec<u8>>> {
        self.symbol_state.add_roots(roots);
        for (index, object) in objects.iter().enumerate().skip(self.scanned_objects) {
            self.symbol_state.absorb_object(object, index)?;
        }
        self.scanned_objects = objects.len();

        // Legacy alias members are not retained as ordinary objects. Reapply their directives
        // because the caller rebuilds runtime directives whenever newly selected objects add
        // another `.drectve` wave.
        for &(archive_index, member_index) in &self.selected_aliases {
            let member = &self.archives[archive_index].members()[member_index];
            let aliases = parse_legacy_alias_object(member.data())?
                .expect("selected legacy alias member remains a legacy alias");
            for directive in aliases.directives()? {
                runtime_resolution.apply(directive, &String::from_utf8_lossy(member.name()))?;
            }
        }

        loop {
            let mut changed = false;
            changed |= extract_pass(
                &self.archives,
                objects,
                &self.whole_archive,
                runtime_resolution,
                &mut self.extracted,
                &mut self.import_definitions,
                &mut self.symbol_state,
                &mut self.selected_aliases,
                false,
            )?;
            self.scanned_objects = objects.len();
            if changed {
                continue;
            }
            changed |= extract_pass(
                &self.archives,
                objects,
                &self.whole_archive,
                runtime_resolution,
                &mut self.extracted,
                &mut self.import_definitions,
                &mut self.symbol_state,
                &mut self.selected_aliases,
                true,
            )?;
            self.scanned_objects = objects.len();
            if !changed {
                return Ok(self.import_definitions.clone());
            }
        }
    }
}

/// Extract regular COFF members from all archives until no archive can satisfy
/// another unresolved external. Short import objects remain owned by the
/// import-directory builder.
#[cfg(test)]
fn extract<'data>(
    objects: &mut Vec<crate::coff::CoffObject<'data>>,
    archive_bytes: &[&'data [u8]],
    whole_archive: &[bool],
    roots: &[Vec<u8>],
    runtime_resolution: &mut RuntimeResolution,
) -> Result<BTreeSet<Vec<u8>>> {
    ensure!(
        archive_bytes.len() == whole_archive.len(),
        "internal archive policy mismatch"
    );
    let mut session = ResolverSession::new();
    for (&bytes, &whole_archive) in archive_bytes.iter().zip(whole_archive) {
        session.add_archive(bytes, whole_archive)?;
    }
    session.resolve(objects, roots, runtime_resolution)
}

#[allow(clippy::too_many_arguments)]
fn extract_pass<'data>(
    archives: &[CoffArchive<'data>],
    objects: &mut Vec<crate::coff::CoffObject<'data>>,
    whole_archive: &[bool],
    runtime_resolution: &mut RuntimeResolution,
    extracted: &mut HashSet<(usize, usize)>,
    import_definitions: &mut BTreeSet<Vec<u8>>,
    symbol_state: &mut IncrementalSymbolState,
    selected_aliases: &mut Vec<(usize, usize)>,
    use_alternates: bool,
) -> Result<bool> {
    let mut changed = false;
    for (archive_index, archive) in archives.iter().enumerate() {
        // Archive order is significant. In particular, a definition selected from an
        // earlier library must suppress a competing definition in a later one during this
        // same pass. Keep the outer loop because a later library may introduce a new demand
        // that can be satisfied by an earlier library on the next pass.
        let fallback_names;
        let demands = if use_alternates {
            fallback_names = fallback_demands(
                symbol_state.unresolved.clone(),
                &symbol_state.defined,
                runtime_resolution,
                &symbol_state.weak_resolution,
            )?;
            fallback_names
                .iter()
                .map(|name| ArchiveDemand {
                    name,
                    kind: ArchiveDemandKind::Strong,
                })
                .collect::<Vec<_>>()
        } else {
            let mut demands = symbol_state
                .unresolved
                .iter()
                .map(|name| ArchiveDemand {
                    name: name.as_slice(),
                    kind: ArchiveDemandKind::Strong,
                })
                .collect::<Vec<_>>();
            demands.extend(
                symbol_state
                    .weak_resolution
                    .records()
                    .filter(|(symbol, _, search)| {
                        *search == linker_utils::coff_symbols::WeakSearch::Library
                            && !symbol_state.defined.contains(*symbol)
                    })
                    .map(|(symbol, _, _)| ArchiveDemand {
                        name: symbol,
                        kind: ArchiveDemandKind::WeakLibrary,
                    }),
            );
            demands
        };
        let plan =
            archive.plan_with_defined_lookup(&demands, whole_archive[archive_index], |name| {
                symbol_state.defined.contains(name)
            });
        for selected in plan.selected() {
            let member = selected.member();
            if !extracted.insert((archive_index, member.index())) {
                continue;
            }
            match member.kind() {
                CoffArchiveMemberKind::CoffObject { .. } => {
                    let object =
                        crate::coff::CoffObject::parse(member.data()).with_context(|| {
                            format!(
                                "invalid COFF archive member `{}`",
                                String::from_utf8_lossy(member.name())
                            )
                        })?;
                    symbol_state.absorb_object(&object, objects.len())?;
                    objects.push(object);
                    changed = true;
                }
                CoffArchiveMemberKind::ShortImport(_) => {
                    // The PE import builder consumes selected import symbols from
                    // the original archive. Do not parse these as ordinary objects, but do
                    // retain their definitions for subsequent archive decisions.
                    for definition in member.definitions() {
                        if import_definitions.insert(definition.to_vec()) {
                            symbol_state.define(definition);
                            changed = true;
                        }
                    }
                }
                CoffArchiveMemberKind::Opaque => {
                    if let Some(aliases) = parse_legacy_alias_object(member.data())
                        .context("invalid legacy COFF alias member")?
                    {
                        for directive in aliases.directives()? {
                            runtime_resolution
                                .apply(directive, &String::from_utf8_lossy(member.name()))?;
                        }
                        selected_aliases.push((archive_index, member.index()));
                        changed = true;
                    } else {
                        return Err(error!(
                            "unsupported selected COFF archive member `{}`: {}",
                            String::from_utf8_lossy(member.name()),
                            member
                                .opaque_error()
                                .expect("opaque archive members retain their parse error")
                        ));
                    }
                }
            }
        }
    }
    Ok(changed)
}

fn fallback_demands(
    unresolved: BTreeSet<Vec<u8>>,
    defined: &BTreeSet<Vec<u8>>,
    runtime_resolution: &RuntimeResolution,
    weak_resolution: &WeakExternalResolution,
) -> Result<BTreeSet<Vec<u8>>> {
    let mut names = unresolved
        .into_iter()
        .map(|name| {
            let Ok(text) = std::str::from_utf8(&name) else {
                return Ok(name);
            };
            runtime_resolution
                .resolve_alternate_name(text, |candidate| defined.contains(candidate.as_bytes()))
                .map(|resolved| resolved.as_bytes().to_vec())
                .map_err(Into::into)
        })
        .collect::<Result<BTreeSet<_>>>()?;
    for (symbol, _, _) in weak_resolution.records() {
        if defined.contains(symbol) {
            continue;
        }
        let target = weak_resolution.resolve(symbol, |name| defined.contains(name))?;
        if !defined.contains(target) {
            names.insert(target.to_vec());
        }
    }
    Ok(names)
}

#[cfg(test)]
fn symbol_state(objects: &[crate::coff::CoffObject<'_>], roots: &[Vec<u8>]) -> Result<SymbolState> {
    let mut state = IncrementalSymbolState::new();
    state.add_roots(roots);
    for (index, object) in objects.iter().enumerate() {
        state.absorb_object(object, index)?;
    }
    Ok((state.defined, state.unresolved))
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::pe;

    #[test]
    fn later_archive_observes_definitions_and_demands_from_earlier_archive() {
        let root = coff_object(&[], &["foo"]);
        let first = archive(&[("first.obj", coff_object(&["foo"], &["bar"]))]);
        let second = archive(&[
            ("duplicate.obj", coff_object(&["foo"], &[])),
            ("bar.obj", coff_object(&["bar"], &[])),
        ]);
        let mut objects = vec![crate::coff::CoffObject::parse(&root).unwrap()];

        extract(
            &mut objects,
            &[&first, &second],
            &[false, false],
            &[],
            &mut RuntimeResolution::new(),
        )
        .unwrap();

        assert_eq!(
            objects.len(),
            3,
            "the competing foo definition was extracted"
        );
        let (defined, unresolved) = symbol_state(&objects, &[]).unwrap();
        assert!(defined.contains(b"foo".as_slice()));
        assert!(defined.contains(b"bar".as_slice()));
        assert!(unresolved.is_empty());
    }

    #[test]
    fn later_archive_demands_can_revisit_an_earlier_archive() {
        let root = coff_object(&[], &["foo"]);
        let first = archive(&[("bar.obj", coff_object(&["bar"], &[]))]);
        let second = archive(&[("foo.obj", coff_object(&["foo"], &["bar"]))]);
        let mut objects = vec![crate::coff::CoffObject::parse(&root).unwrap()];

        extract(
            &mut objects,
            &[&first, &second],
            &[false, false],
            &[],
            &mut RuntimeResolution::new(),
        )
        .unwrap();

        assert_eq!(objects.len(), 3);
        let (_, unresolved) = symbol_state(&objects, &[]).unwrap();
        assert!(unresolved.is_empty());
    }

    #[test]
    fn short_import_definition_suppresses_later_regular_member() {
        let root = coff_object(&[], &["foo"]);
        let imports = archive(&[("foo.obj", short_import("foo", "example.dll"))]);
        let fallback = archive(&[("fallback.obj", coff_object(&["foo"], &[]))]);
        let mut objects = vec![crate::coff::CoffObject::parse(&root).unwrap()];

        extract(
            &mut objects,
            &[&imports, &fallback],
            &[false, false],
            &[],
            &mut RuntimeResolution::new(),
        )
        .unwrap();

        assert_eq!(objects.len(), 1, "the fallback definition was extracted");
    }

    #[test]
    fn alternatename_extracts_fallback_only_after_primary_search_fails() {
        let root = coff_object(&[], &["primary"]);
        let fallback = archive(&[("fallback.obj", coff_object(&["fallback"], &[]))]);
        let mut objects = vec![crate::coff::CoffObject::parse(&root).unwrap()];
        let mut runtime = RuntimeResolution::new();
        runtime
            .parse_and_apply("/alternatename:primary=fallback", "root.obj")
            .unwrap();

        extract(&mut objects, &[&fallback], &[false], &[], &mut runtime).unwrap();

        assert_eq!(objects.len(), 2);
        let (defined, _) = symbol_state(&objects, &[]).unwrap();
        assert!(defined.contains(b"fallback".as_slice()));
    }

    #[test]
    fn strong_archive_definition_beats_alternatename_fallback() {
        let root = coff_object(&[], &["primary"]);
        let library = archive(&[
            ("fallback.obj", coff_object(&["fallback"], &[])),
            ("primary.obj", coff_object(&["primary"], &[])),
        ]);
        let mut objects = vec![crate::coff::CoffObject::parse(&root).unwrap()];
        let mut runtime = RuntimeResolution::new();
        runtime
            .parse_and_apply("/alternatename:primary=fallback", "root.obj")
            .unwrap();

        extract(&mut objects, &[&library], &[false], &[], &mut runtime).unwrap();

        assert_eq!(objects.len(), 2, "fallback was extracted beside primary");
        let (defined, _) = symbol_state(&objects, &[]).unwrap();
        assert!(defined.contains(b"primary".as_slice()));
        assert!(!defined.contains(b"fallback".as_slice()));
    }

    #[test]
    fn weak_search_policy_controls_primary_archive_extraction() {
        for (search, extracts_primary) in [
            (pe::IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY.0, false),
            (pe::IMAGE_WEAK_EXTERN_SEARCH_ALIAS.0, false),
            (pe::IMAGE_WEAK_EXTERN_SEARCH_LIBRARY.0, true),
            (pe::IMAGE_WEAK_EXTERN_ANTI_DEPENDENCY.0, false),
        ] {
            let root = weak_object(search);
            let library = archive(&[("primary.obj", coff_object(&["primary"], &[]))]);
            let mut objects = vec![crate::coff::CoffObject::parse(&root).unwrap()];

            extract(
                &mut objects,
                &[&library],
                &[false],
                &[],
                &mut RuntimeResolution::new(),
            )
            .unwrap();

            assert_eq!(objects.len() == 2, extracts_primary, "search type {search}");
        }
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

    fn weak_object(search: u32) -> Vec<u8> {
        let mut bytes = vec![0; 20 + 40];
        bytes[0..2].copy_from_slice(&pe::IMAGE_FILE_MACHINE_AMD64.0.to_le_bytes());
        bytes[2..4].copy_from_slice(&1u16.to_le_bytes());
        bytes[8..12].copy_from_slice(&60u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&3u32.to_le_bytes());
        bytes[20..25].copy_from_slice(b".text");
        bytes[56..60]
            .copy_from_slice(&(pe::IMAGE_SCN_CNT_CODE.0 | pe::IMAGE_SCN_MEM_READ.0).to_le_bytes());
        push_symbol(&mut bytes, "fallback", 1);
        let mut weak = [0; 18];
        weak[..7].copy_from_slice(b"primary");
        weak[16] = pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL.0;
        weak[17] = 1;
        bytes.extend_from_slice(&weak);
        let mut auxiliary = [0; 18];
        auxiliary[..4].copy_from_slice(&0u32.to_le_bytes());
        auxiliary[4..8].copy_from_slice(&search.to_le_bytes());
        bytes.extend_from_slice(&auxiliary);
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes
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
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&payload);
        bytes
    }

    fn archive(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut bytes = object::archive::MAGIC.to_vec();
        for (name, data) in members {
            let identifier = format!("{name}/");
            let header = format!(
                "{identifier:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                0,
                0,
                0,
                0,
                data.len()
            );
            assert_eq!(header.len(), 60);
            bytes.extend_from_slice(header.as_bytes());
            bytes.extend_from_slice(data);
            if data.len() % 2 != 0 {
                bytes.push(b'\n');
            }
        }
        bytes
    }
}
