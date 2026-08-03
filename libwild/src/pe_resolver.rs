//! COFF archive extraction used by the PE writer.

use crate::ensure;
use crate::error;
use crate::error::Context;
use crate::error::Result;
use linker_utils::coff_archives::CoffArchive;
use linker_utils::coff_archives::CoffArchiveMemberKind;
use linker_utils::coff_runtime::RuntimeResolution;
use linker_utils::coff_runtime::parse_legacy_alias_object;
use linker_utils::coff_symbols::ArchiveDemand;
use linker_utils::coff_symbols::ArchiveDemandKind;
use object::Object;
use object::ObjectSymbol;
use std::collections::BTreeSet;
use std::collections::HashSet;

type SymbolState = (BTreeSet<Vec<u8>>, BTreeSet<Vec<u8>>);

/// Extract regular COFF members from all archives until no archive can satisfy
/// another unresolved external. Short import objects remain owned by the
/// import-directory builder.
pub(super) fn extract<'data>(
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
    let archives = archive_bytes
        .iter()
        .map(|bytes| CoffArchive::parse(bytes).context("invalid AMD64 COFF archive"))
        .collect::<Result<Vec<_>>>()?;
    let mut extracted = HashSet::<(usize, usize)>::new();
    let mut import_definitions = BTreeSet::<Vec<u8>>::new();

    loop {
        let mut changed = false;

        // First give ordinary strong demands a complete pass over every archive.
        // Only after that reaches a global fixpoint may weak fallback targets pull
        // members. This ensures a real definition (including a short import) of
        // the primary name always wins over /alternatename.
        changed |= extract_pass(
            &archives,
            objects,
            whole_archive,
            roots,
            runtime_resolution,
            &mut extracted,
            &mut import_definitions,
            false,
        )?;
        if changed {
            continue;
        }
        changed |= extract_pass(
            &archives,
            objects,
            whole_archive,
            roots,
            runtime_resolution,
            &mut extracted,
            &mut import_definitions,
            true,
        )?;
        if !changed {
            return Ok(import_definitions);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn extract_pass<'data>(
    archives: &[CoffArchive<'data>],
    objects: &mut Vec<crate::coff::CoffObject<'data>>,
    whole_archive: &[bool],
    roots: &[Vec<u8>],
    runtime_resolution: &mut RuntimeResolution,
    extracted: &mut HashSet<(usize, usize)>,
    import_definitions: &mut BTreeSet<Vec<u8>>,
    use_alternates: bool,
) -> Result<bool> {
    let mut changed = false;
    for (archive_index, archive) in archives.iter().enumerate() {
        // Archive order is significant. In particular, a definition selected from an
        // earlier library must suppress a competing definition in a later one during this
        // same pass. Keep the outer loop because a later library may introduce a new demand
        // that can be satisfied by an earlier library on the next pass.
        let (mut defined, mut unresolved) = symbol_state(objects, roots)?;
        defined.extend(import_definitions.iter().cloned());
        unresolved.retain(|name| !defined.contains(name));
        let unresolved = if use_alternates {
            resolve_alternate_demands(unresolved, &defined, runtime_resolution)?
        } else {
            unresolved
        };
        let demands = unresolved
            .iter()
            .map(|name| ArchiveDemand {
                name,
                kind: ArchiveDemandKind::Strong,
            })
            .collect::<Vec<_>>();
        let defined_refs = defined.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let plan = archive.plan(&demands, &defined_refs, whole_archive[archive_index]);
        for selected in plan.selected() {
            let member = selected.member();
            if !extracted.insert((archive_index, member.index())) {
                continue;
            }
            match member.kind() {
                CoffArchiveMemberKind::CoffObject { .. } => {
                    objects.push(crate::coff::CoffObject::parse(member.data()).with_context(
                        || {
                            format!(
                                "invalid COFF archive member `{}`",
                                String::from_utf8_lossy(member.name())
                            )
                        },
                    )?);
                    changed = true;
                }
                CoffArchiveMemberKind::ShortImport(_) => {
                    // The PE import builder consumes selected import symbols from
                    // the original archive. Do not parse these as ordinary objects, but do
                    // retain their definitions for subsequent archive decisions.
                    for definition in member.definitions() {
                        changed |= import_definitions.insert(definition.to_vec());
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

fn resolve_alternate_demands(
    unresolved: BTreeSet<Vec<u8>>,
    defined: &BTreeSet<Vec<u8>>,
    runtime_resolution: &RuntimeResolution,
) -> Result<BTreeSet<Vec<u8>>> {
    unresolved
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
        .collect()
}

fn symbol_state(objects: &[crate::coff::CoffObject<'_>], roots: &[Vec<u8>]) -> Result<SymbolState> {
    let mut defined = BTreeSet::new();
    let mut unresolved = roots.iter().cloned().collect::<BTreeSet<_>>();
    for object in objects {
        for symbol in object.file().symbols() {
            let name = symbol.name_bytes().context("invalid COFF symbol name")?;
            if name.is_empty() || !symbol.is_global() {
                continue;
            }
            if symbol.is_undefined() && !symbol.is_common() {
                unresolved.insert(name.to_vec());
            } else if symbol.is_definition() || symbol.is_common() {
                defined.insert(name.to_vec());
            }
        }
    }
    unresolved.retain(|name| !defined.contains(name));
    Ok((defined, unresolved))
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
