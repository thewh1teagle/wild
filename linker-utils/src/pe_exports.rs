//! Construction of deterministic PE export directories.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};

const EXPORT_DIRECTORY_SIZE: usize = 40;

/// The address exported from a PE image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportTarget<'data> {
    /// RVA of code or data in the image.
    Rva(u32),
    /// A `DLL.symbol` or `DLL.#ordinal` forwarding string.
    Forwarder(&'data [u8]),
}

/// One public DLL export before ordinal assignment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Export<'data> {
    /// Public name used by clients and import libraries.
    pub name: &'data [u8],
    /// Explicit ordinal, or `None` to assign the lowest available ordinal.
    pub ordinal: Option<u16>,
    /// Omit the export from the name tables, making it importable by ordinal only.
    pub noname: bool,
    /// The target is data rather than code.
    pub data: bool,
    pub target: ExportTarget<'data>,
}

/// Target after a forwarder string has been placed in the directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolvedExportTarget {
    Rva(u32),
    ForwarderRva(u32),
}

/// Canonical export metadata corresponding to the emitted directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedExport {
    pub name: Vec<u8>,
    pub ordinal: u16,
    pub noname: bool,
    pub data: bool,
    pub target: ResolvedExportTarget,
}

/// Complete contents and metadata for a `.edata` contribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportDirectory {
    pub bytes: Vec<u8>,
    pub rva: u32,
    pub size: u32,
    pub ordinal_base: u32,
    /// Sorted by ordinal, then name.
    pub exports: Vec<ResolvedExport>,
}

/// Builds one PE32+ export directory at `section_rva`.
///
/// Explicit ordinals are preserved. Remaining ordinals are assigned by public
/// name, starting at one and skipping explicit ordinals. The PE name table is
/// sorted bytewise as required by the loader's binary search.
pub fn build_export_directory(
    dll_name: &[u8],
    section_rva: u32,
    exports: &[Export<'_>],
) -> Result<ExportDirectory> {
    validate_string(dll_name, "DLL name")?;
    ensure!(section_rva != 0, "export directory RVA must not be zero");
    ensure!(
        !exports.is_empty(),
        "an export directory requires at least one export"
    );
    ensure!(u16::try_from(exports.len()).is_ok(), "too many PE exports");

    let mut names = BTreeSet::new();
    let mut explicit_ordinals = BTreeSet::new();
    let mut explicit_targets = BTreeMap::new();
    for export in exports {
        validate_string(export.name, "export name")?;
        ensure!(
            names.insert(export.name),
            "duplicate export name {:?}",
            display(export.name)
        );
        if let Some(ordinal) = export.ordinal {
            ensure!(
                ordinal != 0,
                "export {:?} uses reserved ordinal zero",
                display(export.name)
            );
            explicit_ordinals.insert(ordinal);
            if let Some((target, data)) =
                explicit_targets.insert(ordinal, (export.target, export.data))
            {
                ensure!(
                    target == export.target && data == export.data,
                    "export ordinal {ordinal} is assigned to incompatible targets"
                );
            }
        }
        match export.target {
            ExportTarget::Rva(rva) => ensure!(
                rva != 0,
                "export {:?} has a zero target RVA",
                display(export.name)
            ),
            ExportTarget::Forwarder(value) => validate_string(value, "forwarder")?,
        }
    }

    let mut by_name = (0..exports.len()).collect::<Vec<_>>();
    by_name.sort_by(|&left, &right| exports[left].name.cmp(exports[right].name));
    let mut assigned = BTreeMap::<usize, u16>::new();
    let mut next = 1u32;
    for index in by_name.iter().copied() {
        let ordinal = if let Some(ordinal) = exports[index].ordinal {
            ordinal
        } else {
            let ordinal = loop {
                let candidate = u16::try_from(next).context("no PE export ordinals remain")?;
                if !explicit_ordinals.contains(&candidate) {
                    break candidate;
                }
                next += 1;
            };
            explicit_ordinals.insert(ordinal);
            next += 1;
            ordinal
        };
        assigned.insert(index, ordinal);
    }

    let ordinal_base = u32::from(*assigned.values().min().context("missing export ordinal")?);
    let maximum_ordinal = u32::from(*assigned.values().max().context("missing export ordinal")?);
    let function_count = maximum_ordinal
        .checked_sub(ordinal_base)
        .and_then(|value| value.checked_add(1))
        .context("export address table size overflow")?;
    let function_count_usize =
        usize::try_from(function_count).context("export count does not fit usize")?;

    let named = by_name
        .iter()
        .copied()
        .filter(|index| !exports[*index].noname)
        .collect::<Vec<_>>();
    ensure!(
        u16::try_from(named.len()).is_ok(),
        "too many named PE exports"
    );

    let eat_offset = EXPORT_DIRECTORY_SIZE;
    let name_pointer_offset =
        checked_table_end(eat_offset, function_count_usize, 4, "export address table")?;
    let ordinal_table_offset = checked_table_end(
        name_pointer_offset,
        named.len(),
        4,
        "export name pointer table",
    )?;
    let strings_offset =
        checked_table_end(ordinal_table_offset, named.len(), 2, "export ordinal table")?;
    let mut bytes = vec![0; strings_offset];

    let dll_name_rva = append_string(&mut bytes, section_rva, dll_name)?;
    let mut name_rvas = BTreeMap::new();
    for index in named.iter().copied() {
        name_rvas.insert(
            index,
            append_string(&mut bytes, section_rva, exports[index].name)?,
        );
    }
    let mut forwarder_rvas = BTreeMap::new();
    let mut forwarder_values = BTreeMap::<&[u8], u32>::new();
    for index in by_name.iter().copied() {
        if let ExportTarget::Forwarder(value) = exports[index].target {
            let rva = if let Some(rva) = forwarder_values.get(value).copied() {
                rva
            } else {
                let rva = append_string(&mut bytes, section_rva, value)?;
                forwarder_values.insert(value, rva);
                rva
            };
            forwarder_rvas.insert(index, rva);
        }
    }

    let size = u32::try_from(bytes.len()).context("export directory exceeds 4 GiB")?;
    let directory_end = section_rva
        .checked_add(size)
        .context("export directory RVA range overflow")?;
    let mut resolved = Vec::with_capacity(exports.len());
    for index in by_name.iter().copied() {
        let export = exports[index];
        let ordinal = assigned[&index];
        let target = match export.target {
            ExportTarget::Rva(rva) => {
                ensure!(
                    rva < section_rva || rva >= directory_end,
                    "export {:?} target RVA {rva:#x} lies inside the export directory and would be interpreted as a forwarder",
                    display(export.name)
                );
                ResolvedExportTarget::Rva(rva)
            }
            ExportTarget::Forwarder(_) => {
                ResolvedExportTarget::ForwarderRva(forwarder_rvas[&index])
            }
        };
        let eat_index = usize::try_from(u32::from(ordinal) - ordinal_base).unwrap();
        write_u32(&mut bytes, eat_offset + eat_index * 4, target_rva(target));
        resolved.push(ResolvedExport {
            name: export.name.to_vec(),
            ordinal,
            noname: export.noname,
            data: export.data,
            target,
        });
    }
    resolved.sort_by(|left, right| {
        left.ordinal
            .cmp(&right.ordinal)
            .then_with(|| left.name.cmp(&right.name))
    });

    for (table_index, index) in named.iter().copied().enumerate() {
        write_u32(
            &mut bytes,
            name_pointer_offset + table_index * 4,
            name_rvas[&index],
        );
        let ordinal_index = u32::from(assigned[&index]) - ordinal_base;
        let ordinal_index =
            u16::try_from(ordinal_index).context("export ordinal table index exceeds u16")?;
        write_u16(
            &mut bytes,
            ordinal_table_offset + table_index * 2,
            ordinal_index,
        );
    }

    write_u32(&mut bytes, 12, dll_name_rva);
    write_u32(&mut bytes, 16, ordinal_base);
    write_u32(&mut bytes, 20, function_count);
    write_u32(&mut bytes, 24, u32::try_from(named.len()).unwrap());
    write_u32(&mut bytes, 28, rva_at(section_rva, eat_offset)?);
    write_u32(&mut bytes, 32, rva_at(section_rva, name_pointer_offset)?);
    write_u32(&mut bytes, 36, rva_at(section_rva, ordinal_table_offset)?);

    Ok(ExportDirectory {
        bytes,
        rva: section_rva,
        size,
        ordinal_base,
        exports: resolved,
    })
}

fn checked_table_end(start: usize, count: usize, width: usize, description: &str) -> Result<usize> {
    start
        .checked_add(
            count
                .checked_mul(width)
                .with_context(|| format!("{description} size overflow"))?,
        )
        .with_context(|| format!("{description} end overflow"))
}

fn append_string(bytes: &mut Vec<u8>, section_rva: u32, value: &[u8]) -> Result<u32> {
    let rva = rva_at(section_rva, bytes.len())?;
    bytes.extend_from_slice(value);
    bytes.push(0);
    Ok(rva)
}

fn rva_at(section_rva: u32, offset: usize) -> Result<u32> {
    let offset = u32::try_from(offset).context("export directory offset exceeds u32")?;
    section_rva
        .checked_add(offset)
        .context("export directory RVA overflow")
}

fn validate_string(value: &[u8], description: &str) -> Result<()> {
    ensure!(!value.is_empty(), "{description} must not be empty");
    ensure!(
        !value.contains(&0),
        "{description} contains an embedded NUL byte"
    );
    Ok(())
}

fn target_rva(target: ResolvedExportTarget) -> u32 {
    match target {
        ResolvedExportTarget::Rva(rva) | ResolvedExportTarget::ForwarderRva(rva) => rva,
    }
}

fn display(value: &[u8]) -> String {
    String::from_utf8_lossy(value).into_owned()
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16_at(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
    }

    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    #[test]
    fn builds_sorted_named_noname_data_and_forwarder_exports() {
        let directory = build_export_directory(
            b"sample.dll",
            0x5000,
            &[
                Export {
                    name: b"Zulu",
                    ordinal: None,
                    noname: false,
                    data: true,
                    target: ExportTarget::Rva(0x3010),
                },
                Export {
                    name: b"ByOrdinal",
                    ordinal: Some(7),
                    noname: true,
                    data: false,
                    target: ExportTarget::Rva(0x1020),
                },
                Export {
                    name: b"Alpha",
                    ordinal: Some(3),
                    noname: false,
                    data: false,
                    target: ExportTarget::Forwarder(b"KERNEL32.Sleep"),
                },
            ],
        )
        .unwrap();

        assert_eq!(directory.ordinal_base, 1);
        assert_eq!(u32_at(&directory.bytes, 16), 1);
        assert_eq!(u32_at(&directory.bytes, 20), 7);
        assert_eq!(u32_at(&directory.bytes, 24), 2);
        let eat = (u32_at(&directory.bytes, 28) - directory.rva) as usize;
        assert_eq!(u32_at(&directory.bytes, eat), 0x3010);
        assert_eq!(u32_at(&directory.bytes, eat + 6 * 4), 0x1020);
        let names = (u32_at(&directory.bytes, 32) - directory.rva) as usize;
        let alpha = (u32_at(&directory.bytes, names) - directory.rva) as usize;
        let zulu = (u32_at(&directory.bytes, names + 4) - directory.rva) as usize;
        assert_eq!(&directory.bytes[alpha..alpha + 6], b"Alpha\0");
        assert_eq!(&directory.bytes[zulu..zulu + 5], b"Zulu\0");
        let ordinals = (u32_at(&directory.bytes, 36) - directory.rva) as usize;
        assert_eq!(
            (
                u16_at(&directory.bytes, ordinals),
                u16_at(&directory.bytes, ordinals + 2)
            ),
            (2, 0)
        );
        let forwarder = u32_at(&directory.bytes, eat + 2 * 4);
        assert!((directory.rva..directory.rva + directory.size).contains(&forwarder));
    }

    #[test]
    fn output_is_independent_of_input_order() {
        let a = Export {
            name: b"a",
            ordinal: None,
            noname: false,
            data: false,
            target: ExportTarget::Rva(0x1000),
        };
        let b = Export {
            name: b"b",
            ordinal: None,
            noname: false,
            data: false,
            target: ExportTarget::Rva(0x2000),
        };
        let first = build_export_directory(b"x.dll", 0x4000, &[a, b]).unwrap();
        let second = build_export_directory(b"x.dll", 0x4000, &[b, a]).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn permits_named_aliases_for_the_same_ordinal_and_target() {
        let first = Export {
            name: b"first",
            ordinal: Some(4),
            noname: false,
            data: false,
            target: ExportTarget::Forwarder(b"OTHER.target"),
        };
        let second = Export {
            name: b"second",
            ordinal: Some(4),
            noname: false,
            data: false,
            target: ExportTarget::Forwarder(b"OTHER.target"),
        };
        let directory = build_export_directory(b"x.dll", 0x4000, &[second, first]).unwrap();
        assert_eq!(directory.ordinal_base, 4);
        assert_eq!(u32_at(&directory.bytes, 20), 1);
        assert_eq!(u32_at(&directory.bytes, 24), 2);
        assert_eq!(directory.exports[0].ordinal, directory.exports[1].ordinal);
        assert_eq!(directory.exports[0].target, directory.exports[1].target);
    }

    #[test]
    fn rejects_ambiguous_or_overflowing_inputs() {
        let duplicate = Export {
            name: b"same",
            ordinal: None,
            noname: false,
            data: false,
            target: ExportTarget::Rva(1),
        };
        assert!(build_export_directory(b"x.dll", 0x1000, &[duplicate, duplicate]).is_err());
        let inside = Export {
            name: b"inside",
            ordinal: None,
            noname: false,
            data: false,
            target: ExportTarget::Rva(u32::MAX),
        };
        assert!(build_export_directory(b"x.dll", u32::MAX - 20, &[inside]).is_err());
    }
}
