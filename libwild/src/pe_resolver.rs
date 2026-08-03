//! COFF archive extraction used by the PE writer.

use crate::error::{Context, Result};
use crate::{ensure, error};
use linker_utils::coff_archives::{CoffArchive, CoffArchiveMemberKind};
use linker_utils::coff_symbols::{ArchiveDemand, ArchiveDemandKind};
use object::{Object, ObjectSymbol};
use std::collections::HashSet;

type SymbolState = (HashSet<Vec<u8>>, HashSet<Vec<u8>>);

/// Extract regular COFF members from all archives until no archive can satisfy
/// another unresolved external. Short import objects remain owned by the
/// import-directory builder.
pub(super) fn extract<'data>(
    objects: &mut Vec<crate::coff::CoffObject<'data>>,
    archive_bytes: &[&'data [u8]],
    whole_archive: &[bool],
    roots: &[Vec<u8>],
) -> Result<()> {
    ensure!(
        archive_bytes.len() == whole_archive.len(),
        "internal archive policy mismatch"
    );
    let archives = archive_bytes
        .iter()
        .map(|bytes| CoffArchive::parse(bytes).context("invalid AMD64 COFF archive"))
        .collect::<Result<Vec<_>>>()?;
    let mut extracted = HashSet::<(usize, usize)>::new();

    loop {
        let (defined, unresolved) = symbol_state(objects, roots)?;
        let demands = unresolved
            .iter()
            .map(|name| ArchiveDemand {
                name,
                kind: ArchiveDemandKind::Strong,
            })
            .collect::<Vec<_>>();
        let defined_refs = defined.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let mut changed = false;

        for (archive_index, archive) in archives.iter().enumerate() {
            let plan = archive.plan(&demands, &defined_refs, whole_archive[archive_index]);
            for selected in plan.selected() {
                let member = selected.member();
                if !extracted.insert((archive_index, member.index())) {
                    continue;
                }
                match member.kind() {
                    CoffArchiveMemberKind::CoffObject { is_bigobj: false } => {
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
                    CoffArchiveMemberKind::CoffObject { is_bigobj: true } => {
                        return Err(error!(
                            "bigobj archive member `{}` is not supported yet",
                            String::from_utf8_lossy(member.name())
                        ));
                    }
                    CoffArchiveMemberKind::ShortImport(_) => {
                        // The PE import builder consumes selected import symbols from
                        // the original archive. Do not parse these as ordinary objects.
                    }
                    CoffArchiveMemberKind::Opaque => {
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
        if !changed {
            return Ok(());
        }
    }
}

fn symbol_state(objects: &[crate::coff::CoffObject<'_>], roots: &[Vec<u8>]) -> Result<SymbolState> {
    let mut defined = HashSet::new();
    let mut unresolved = roots.iter().cloned().collect::<HashSet<_>>();
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
