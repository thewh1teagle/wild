//! Experimental AMD64 PE/COFF linker.

use crate::ensure;
use crate::error;
use crate::error::{Context, Result};
use crate::fs::{FileReplacementMode, FileSystem, InputFileData, OutputFileData, OutputOptions};
use linker_utils::pe_base_relocs::build_amd64_base_relocation_table;
use linker_utils::pe_exports::{Export, ExportTarget, ResolvedExport};
use linker_utils::pe_sections::{
    ContributionId, ContributionKind, DataDirectoryKind, SectionContribution, SectionLayout,
    SectionLayoutOptions, directory_range_for_section, layout_sections,
};
use object::{
    Object, ObjectComdat, ObjectSection, ObjectSymbol, RelocationKind, RelocationTarget,
    SectionFlags,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

#[path = "pe_imports.rs"]
mod pe_imports;
#[path = "pe_resolver.rs"]
mod pe_resolver;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeWriterConfig {
    pub(crate) image_base: u64,
    pub(crate) section_alignment: u32,
    pub(crate) file_alignment: u32,
}

impl Default for PeWriterConfig {
    fn default() -> Self {
        Self {
            image_base: crate::coff_x86_64::CoffX86_64::IMAGE_BASE,
            section_alignment: 0x1000,
            file_alignment: 0x200,
        }
    }
}

impl PeWriterConfig {
    fn from_args(args: &crate::args::coff::CoffArgs) -> Result<Self> {
        Self {
            image_base: args
                .image_base
                .map_or(Self::default().image_base, |v| v.address),
            section_alignment: args.section_alignment.unwrap_or(0x1000),
            file_alignment: args.file_alignment.unwrap_or(0x200),
        }
        .validate()
    }

    pub(crate) fn validate(self) -> Result<Self> {
        ensure!(
            self.image_base.is_multiple_of(0x1_0000),
            "PE image base must be 64 KiB aligned"
        );
        ensure!(
            self.section_alignment.is_power_of_two(),
            "PE section alignment must be a power of two"
        );
        ensure!(
            self.file_alignment.is_power_of_two()
                && (0x200..=0x1_0000).contains(&self.file_alignment),
            "PE file alignment must be a power of two between 512 B and 64 KiB"
        );
        ensure!(
            self.section_alignment >= self.file_alignment,
            "PE section alignment must not be smaller than file alignment"
        );
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy)]
enum Source {
    Object {
        object: usize,
        section: object::SectionIndex,
    },
    Synthetic,
}

#[derive(Debug)]
struct Contribution {
    source: Source,
    spec: SectionContribution,
    data: Vec<u8>,
}

struct BuiltImage {
    bytes: Vec<u8>,
    exports: Vec<ResolvedExport>,
}

pub(crate) fn link<F: FileSystem>(
    fs: &F,
    args: &crate::args::coff::CoffArgs,
) -> Result<crate::LinkerOutput<'static>> {
    ensure!(!args.common.inputs.is_empty(), "no COFF input files");
    let entry_name = (!args.no_entry).then_some(args.entry.as_deref()).flatten();
    ensure!(
        args.is_dll || args.no_entry || entry_name.is_some(),
        "PE executable output requires /ENTRY:<symbol>"
    );
    ensure!(
        !(args.no_entry && args.entry.is_some()),
        "/ENTRY and /NOENTRY cannot be used together"
    );
    ensure!(
        !args.no_entry || args.is_dll,
        "/NOENTRY is only valid with /DLL"
    );

    let mut requested = Vec::new();
    for input in &args.common.inputs {
        match &input.spec {
            crate::args::InputSpec::File(path) => requested.push(path.to_path_buf()),
            _ => return Err(error!("unsupported COFF library input form")),
        }
    }
    if !args.no_default_libraries {
        for library in &args.default_libraries {
            if !is_excluded(library, args) {
                requested.push(PathBuf::from(library));
            }
        }
    }

    let mut inputs = Vec::new();
    for request in requested {
        open_input(fs, &request, args, &mut inputs)?;
    }
    add_directive_libraries(fs, args, &mut inputs)?;

    let mut objects = Vec::new();
    let mut archive_bytes = Vec::new();
    let mut archive_whole = Vec::new();
    for (path, data) in &inputs {
        match object::FileKind::parse(data.bytes())
            .with_context(|| format!("cannot identify COFF input `{}`", path.display()))?
        {
            object::FileKind::Coff => objects.push(
                crate::coff::CoffObject::parse(data.bytes())
                    .with_context(|| format!("while reading `{}`", path.display()))?,
            ),
            object::FileKind::Archive => {
                archive_bytes.push(data.bytes());
                archive_whole.push(
                    args.whole_archive
                        || args
                            .whole_archive_libraries
                            .iter()
                            .any(|name| path_matches(path, name)),
                );
            }
            kind => {
                return Err(error!(
                    "unsupported PE input kind {kind:?} in `{}`",
                    path.display()
                ));
            }
        }
    }
    let initial_directive_exports = directive_exports(&objects)?;
    let mut exports = args.exports.clone();
    exports.extend(initial_directive_exports.iter().cloned());
    let mut roots = args
        .force_undefined
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect::<Vec<_>>();
    if let Some(entry) = entry_name {
        roots.push(entry.as_bytes().to_vec());
    }
    roots.extend(
        exports
            .iter()
            .map(|export| export.target.as_bytes().to_vec()),
    );
    pe_resolver::extract(&mut objects, &archive_bytes, &archive_whole, &roots)?;
    ensure!(!objects.is_empty(), "no COFF object files selected");

    for export in directive_exports(&objects)? {
        if !exports.contains(&export) {
            exports.push(export);
        }
    }

    let undefined = undefined_symbols(&objects, &roots)?;
    let imports = pe_imports::select_from_libraries(&archive_bytes, &undefined)?;
    let dll_name = args
        .common
        .output
        .file_name()
        .and_then(|name| name.to_str())
        .context("PE output file name is not valid UTF-8")?;
    let image = build_image(
        &objects,
        &imports,
        &exports,
        dll_name.as_bytes(),
        entry_name,
        args,
        PeWriterConfig::from_args(args)?,
    )?;
    let mut output = fs.create_output(
        args.common.output.clone(),
        OutputOptions {
            size: image.bytes.len() as u64,
            file_replacement_mode: args
                .common
                .file_replacement_mode
                .unwrap_or(FileReplacementMode::UnlinkAndReplace),
            write_mode: args.common.file_write_mode,
        },
    )?;
    output.bytes_mut().copy_from_slice(&image.bytes);
    output.finish()?;
    if !image.exports.is_empty() {
        write_import_library(fs, args, dll_name.as_bytes(), &exports, &image.exports)?;
    }
    Ok(crate::LinkerOutput { layout: None })
}

fn directive_exports(
    objects: &[crate::coff::CoffObject<'_>],
) -> Result<Vec<crate::args::coff::ExportSpec>> {
    let mut exports = Vec::new();
    for object in objects {
        let Some(section) = object.file().section_by_name(".drectve") else {
            continue;
        };
        let text = std::str::from_utf8(section.data().context("invalid COFF .drectve")?)
            .context("non-UTF-8 COFF .drectve")?
            .trim_end_matches('\0');
        let mut parsed = crate::args::coff::CoffArgs::default();
        crate::args::coff::parse_directives(&mut parsed, text)?;
        exports.extend(parsed.exports);
    }
    Ok(exports)
}

fn write_import_library<F: FileSystem>(
    fs: &F,
    args: &crate::args::coff::CoffArgs,
    dll_name: &[u8],
    specs: &[crate::args::coff::ExportSpec],
    resolved: &[ResolvedExport],
) -> Result<()> {
    use linker_utils::coff_import_library_writer::{
        ImportLibraryExport, ImportLibrarySymbolType, build_amd64_import_library,
    };

    let private = specs
        .iter()
        .filter(|spec| spec.private)
        .map(|spec| spec.name.as_bytes())
        .collect::<HashSet<_>>();
    let exports = resolved
        .iter()
        .filter(|export| !private.contains(export.name.as_slice()))
        .map(|export| ImportLibraryExport {
            symbol: export.name.as_slice(),
            export_name: export.name.as_slice(),
            ordinal: export.ordinal,
            noname: export.noname,
            symbol_type: if export.data {
                ImportLibrarySymbolType::Data
            } else {
                ImportLibrarySymbolType::Code
            },
        })
        .collect::<Vec<_>>();
    if exports.is_empty() {
        return Ok(());
    }
    let bytes = build_amd64_import_library(dll_name, &exports)
        .context("failed to build COFF import library")?;
    let path = args.import_library.as_deref().map_or_else(
        || {
            let mut path = args.common.output.to_path_buf();
            path.set_extension("lib");
            path
        },
        Path::to_path_buf,
    );
    fs.write_auxiliary(&path, &bytes)
        .with_context(|| format!("failed to write import library `{}`", path.display()))
}

fn path_matches(path: &Path, requested: &str) -> bool {
    path.to_string_lossy().eq_ignore_ascii_case(requested)
        || path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case(requested))
}

fn is_excluded(library: &str, args: &crate::args::coff::CoffArgs) -> bool {
    args.excluded_default_libraries
        .iter()
        .any(|excluded| excluded.eq_ignore_ascii_case(library))
}

fn open_input<F: FileSystem>(
    fs: &F,
    request: &Path,
    args: &crate::args::coff::CoffArgs,
    inputs: &mut Vec<(PathBuf, F::Input)>,
) -> Result<()> {
    let path = find_input(fs, request, args)?;
    if inputs.iter().any(|(existing, _)| existing == &path) {
        return Ok(());
    }
    let (data, _) = fs
        .open_input(&path, args.common.prepopulate_maps)
        .with_context(|| format!("Failed to open COFF input `{}`", path.display()))?;
    inputs.push((path, data));
    Ok(())
}

fn add_directive_libraries<F: FileSystem>(
    fs: &F,
    args: &crate::args::coff::CoffArgs,
    inputs: &mut Vec<(PathBuf, F::Input)>,
) -> Result<()> {
    if args.no_default_libraries {
        return Ok(());
    }
    let mut libraries = Vec::new();
    for (path, data) in inputs.iter() {
        if object::FileKind::parse(data.bytes()).ok() != Some(object::FileKind::Coff) {
            continue;
        }
        let file = crate::coff::CoffObject::parse(data.bytes())?;
        let Some(section) = file.file().section_by_name(".drectve") else {
            continue;
        };
        let text = std::str::from_utf8(
            section
                .data()
                .with_context(|| format!("invalid .drectve in `{}`", path.display()))?,
        )
        .with_context(|| format!("non-UTF-8 .drectve in `{}`", path.display()))?
        .trim_end_matches('\0');
        let mut parsed = crate::args::coff::CoffArgs::default();
        crate::args::coff::parse_directives(&mut parsed, text)?;
        if !parsed.no_default_libraries {
            libraries.extend(parsed.default_libraries.into_iter().filter(|lib| {
                !is_excluded(lib, args)
                    && !parsed
                        .excluded_default_libraries
                        .iter()
                        .any(|x| x.eq_ignore_ascii_case(lib))
            }));
        }
    }
    for library in libraries {
        open_input(fs, Path::new(&library), args, inputs)?;
    }
    Ok(())
}

fn find_input<F: FileSystem>(
    fs: &F,
    requested: &Path,
    args: &crate::args::coff::CoffArgs,
) -> Result<PathBuf> {
    if matches!(fs.file_type(requested), Ok(crate::fs::FileType::File)) {
        return Ok(requested.to_path_buf());
    }
    let environment_paths = std::env::var_os("LIB")
        .map(|v| std::env::split_paths(&v).collect::<Vec<_>>())
        .unwrap_or_default();
    for directory in args
        .lib_search_path
        .iter()
        .map(AsRef::as_ref)
        .chain(environment_paths.iter().map(PathBuf::as_path))
    {
        let candidate = directory.join(requested);
        if matches!(fs.file_type(&candidate), Ok(crate::fs::FileType::File)) {
            return Ok(candidate);
        }
    }
    Err(error!("cannot find COFF input `{}`", requested.display()))
}

fn undefined_symbols(
    objects: &[crate::coff::CoffObject<'_>],
    roots: &[Vec<u8>],
) -> Result<HashSet<Vec<u8>>> {
    let mut undefined = roots.iter().cloned().collect::<HashSet<_>>();
    let mut defined = HashSet::new();
    for input in objects {
        for symbol in input.file().symbols() {
            let name = symbol.name_bytes().context("invalid COFF symbol name")?;
            if name.is_empty() || !symbol.is_global() {
                continue;
            }
            if symbol.is_undefined() && !symbol.is_common() {
                undefined.insert(name.to_vec());
            } else if symbol.is_definition() || symbol.is_common() {
                defined.insert(name.to_vec());
            }
        }
    }
    undefined.retain(|name| !defined.contains(name));
    Ok(undefined)
}

fn build_image(
    objects: &[crate::coff::CoffObject<'_>],
    imports: &[pe_imports::Import],
    exports: &[crate::args::coff::ExportSpec],
    dll_name: &[u8],
    entry_name: Option<&str>,
    args: &crate::args::coff::CoffArgs,
    config: PeWriterConfig,
) -> Result<BuiltImage> {
    let mut contributions = collect_contributions(objects, args)?;
    let common_offsets = add_common_symbols(objects, &mut contributions)?;
    let (idata_size, thunk_size) = if imports.is_empty() {
        (0, 0)
    } else {
        pe_imports::section_sizes(imports)?
    };
    let thunk_id = add_synthetic(
        &mut contributions,
        b".text$wild_imports",
        thunk_size,
        text_characteristics(),
    )?;
    let idata_id = add_synthetic(
        &mut contributions,
        b".idata",
        idata_size,
        data_characteristics(),
    )?;
    let edata_size = estimated_export_size(dll_name, exports)?;
    let edata_id = add_synthetic(
        &mut contributions,
        b".edata",
        edata_size,
        readonly_data_characteristics(),
    )?;

    let dynamic_base = args.dynamic_base && !args.fixed;
    let mut reloc_id = None;
    let mut reloc_data = Vec::new();
    let mut layout = make_layout(&contributions, config)?;
    if dynamic_base {
        for _ in 0..3 {
            let dir64 = dir64_rvas(objects, &contributions, &layout)?;
            let next = build_amd64_base_relocation_table(dir64, layout.size_of_image)
                .context("failed to build PE base relocation table")?;
            if next.is_empty() {
                break;
            }
            match reloc_id {
                None => {
                    reloc_id = add_synthetic(
                        &mut contributions,
                        b".reloc",
                        next.len(),
                        reloc_characteristics(),
                    )?;
                }
                Some(id) => {
                    let contribution = contributions.iter_mut().find(|c| c.spec.id == id).unwrap();
                    contribution.spec.size =
                        u32::try_from(next.len()).context("base relocation table too large")?;
                    contribution.data.resize(next.len(), 0);
                }
            }
            let next_layout = make_layout(&contributions, config)?;
            if next == reloc_data && next_layout == layout {
                layout = next_layout;
                break;
            }
            reloc_data = next;
            layout = next_layout;
        }
        if let Some(id) = reloc_id {
            let dir64 = dir64_rvas(objects, &contributions, &layout)?;
            reloc_data = build_amd64_base_relocation_table(dir64, layout.size_of_image)?;
            let contribution = contributions.iter_mut().find(|c| c.spec.id == id).unwrap();
            contribution.spec.size = reloc_data.len() as u32;
            contribution.data = reloc_data.clone();
            layout = make_layout(&contributions, config)?;
        }
    }
    if let Some(max_size) = args.image_base.and_then(|base| base.max_size) {
        ensure!(
            u64::from(layout.size_of_image) <= max_size,
            "PE image size {:#x} exceeds /BASE maximum size {max_size:#x}",
            layout.size_of_image
        );
    }
    config
        .image_base
        .checked_add(u64::from(layout.size_of_image))
        .context("PE virtual address space overflows u64")?;

    let emitted_imports = match (idata_id, thunk_id) {
        (Some(idata), thunk) => pe_imports::emit(
            imports,
            layout.placements[&idata].rva,
            thunk.map_or(0, |id| layout.placements[&id].rva),
        )?,
        _ => pe_imports::EmittedImports::default(),
    };
    if let Some(id) = idata_id {
        contributions
            .iter_mut()
            .find(|c| c.spec.id == id)
            .unwrap()
            .data = emitted_imports.idata.clone();
    }
    if let Some(id) = thunk_id {
        contributions
            .iter_mut()
            .find(|c| c.spec.id == id)
            .unwrap()
            .data = emitted_imports.thunks.clone();
    }

    let (locations, mut definitions) = definitions(
        objects,
        &contributions,
        &layout,
        config.image_base,
        args.force.multiple,
    )?;
    for (name, (offset, id)) in common_offsets {
        definitions
            .entry(name)
            .or_insert(config.image_base + u64::from(layout.placements[&id].rva + offset));
    }
    for (name, rva) in &emitted_imports.symbols {
        definitions
            .entry(name.clone())
            .or_insert(config.image_base + u64::from(*rva));
    }
    let entry_rva = match entry_name {
        Some(name) => {
            let va = definitions
                .get(name.as_bytes())
                .copied()
                .or_else(|| {
                    find_local_symbol(
                        objects,
                        &locations,
                        &layout,
                        name.as_bytes(),
                        config.image_base,
                    )
                    .ok()
                    .flatten()
                })
                .ok_or_else(|| error!("entry symbol `{name}` is undefined"))?;
            u32::try_from(
                va.checked_sub(config.image_base)
                    .context("entry point precedes image base")?,
            )
            .context("entry point outside image")?
        }
        None => 0,
    };

    let export_directory = if let Some(id) = edata_id {
        let section_rva = layout.placements[&id].rva;
        let values = exports
            .iter()
            .map(|export| {
                let target = resolve_export_target(
                    export,
                    objects,
                    &locations,
                    &layout,
                    &definitions,
                    config.image_base,
                )?;
                Ok(Export {
                    name: export.name.as_bytes(),
                    ordinal: export.ordinal,
                    noname: export.noname,
                    data: export.data,
                    target,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let directory =
            linker_utils::pe_exports::build_export_directory(dll_name, section_rva, &values)
                .context("failed to build PE export directory")?;
        let contribution = contributions.iter_mut().find(|c| c.spec.id == id).unwrap();
        ensure!(
            directory.bytes.len() <= contribution.data.len(),
            "PE export directory exceeded its reserved size"
        );
        contribution.data[..directory.bytes.len()].copy_from_slice(&directory.bytes);
        Some(directory)
    } else {
        None
    };

    let mut image = vec![0; layout.file_size as usize];
    for contribution in &contributions {
        let placement = &layout.placements[&contribution.spec.id];
        if let Some(file_offset) = placement.file_offset {
            let start = file_offset as usize;
            image[start..start + contribution.data.len()].copy_from_slice(&contribution.data);
        }
    }
    apply_relocations(
        objects,
        &layout,
        &locations,
        &definitions,
        config.image_base,
        &mut image,
    )?;
    write_headers(
        &mut image,
        &layout,
        args,
        config,
        entry_rva,
        emitted_imports.import_directory,
        emitted_imports.iat_directory,
        reloc_id.is_some() && !reloc_data.is_empty(),
        export_directory
            .as_ref()
            .map(|directory| (directory.rva, directory.size)),
    );
    Ok(BuiltImage {
        bytes: image,
        exports: export_directory.map_or_else(Vec::new, |directory| directory.exports),
    })
}

fn estimated_export_size(
    dll_name: &[u8],
    exports: &[crate::args::coff::ExportSpec],
) -> Result<usize> {
    if exports.is_empty() {
        return Ok(0);
    }
    let values = exports
        .iter()
        .map(|export| Export {
            name: export.name.as_bytes(),
            ordinal: export.ordinal,
            noname: export.noname,
            data: export.data,
            target: if looks_like_forwarder(export) {
                ExportTarget::Forwarder(export.target.as_bytes())
            } else {
                ExportTarget::Rva(1)
            },
        })
        .collect::<Vec<_>>();
    Ok(
        linker_utils::pe_exports::build_export_directory(dll_name, 0x7000_0000, &values)
            .context("invalid PE exports")?
            .bytes
            .len(),
    )
}

fn looks_like_forwarder(export: &crate::args::coff::ExportSpec) -> bool {
    export.target != export.name
        && export
            .target
            .split_once('.')
            .is_some_and(|(dll, symbol)| !dll.is_empty() && !symbol.is_empty())
}

fn resolve_export_target<'a>(
    export: &'a crate::args::coff::ExportSpec,
    objects: &[crate::coff::CoffObject<'_>],
    locations: &LocationMap,
    layout: &SectionLayout,
    definitions: &HashMap<Vec<u8>, u64>,
    image_base: u64,
) -> Result<ExportTarget<'a>> {
    let name = export.target.as_bytes();
    let address = if let Some(address) = definitions.get(name).copied() {
        Some(address)
    } else {
        find_local_symbol(objects, locations, layout, name, image_base)?
    };
    if let Some(address) = address {
        let rva = u32::try_from(
            address
                .checked_sub(image_base)
                .context("export target precedes image base")?,
        )
        .context("export target RVA exceeds u32")?;
        return Ok(ExportTarget::Rva(rva));
    }
    if looks_like_forwarder(export) {
        return Ok(ExportTarget::Forwarder(name));
    }
    Err(error!(
        "export `{}` targets undefined symbol `{}`",
        export.name, export.target
    ))
}

fn collect_contributions(
    objects: &[crate::coff::CoffObject<'_>],
    args: &crate::args::coff::CoffArgs,
) -> Result<Vec<Contribution>> {
    let mut output = Vec::new();
    let discarded_comdats = discarded_comdat_sections(objects)?;
    for (object_index, input) in objects.iter().enumerate() {
        for section in input.file().sections() {
            let flags = match section.flags() {
                SectionFlags::Coff { characteristics } => characteristics.0,
                _ => 0,
            };
            let class = linker_utils::coff_symbols::classify_section(flags)
                .context("invalid COFF section flags")?;
            if class.discardable
                || flags & object::pe::IMAGE_SCN_LNK_REMOVE.0 != 0
                || matches!(
                    class.contents,
                    linker_utils::coff_symbols::SectionContents::Metadata
                )
            {
                continue;
            }
            if discarded_comdats.contains(&(object_index, section.index())) {
                continue;
            }
            let raw_name = section.name_bytes().context("invalid COFF section name")?;
            let name = merged_name(raw_name, args)?;
            let size = u32::try_from(section.size()).context("COFF section too large")?;
            if size == 0 {
                continue;
            }
            let kind = if matches!(
                class.contents,
                linker_utils::coff_symbols::SectionContents::UninitializedData
            ) {
                ContributionKind::Bss
            } else {
                ContributionKind::Data
            };
            let data = if kind == ContributionKind::Bss {
                Vec::new()
            } else {
                section
                    .data()
                    .context("invalid COFF section contents")?
                    .to_vec()
            };
            let alignment = u32::try_from(section.align().max(1))
                .context("COFF section alignment too large")?;
            output.push(Contribution {
                source: Source::Object {
                    object: object_index,
                    section: section.index(),
                },
                spec: SectionContribution {
                    id: ContributionId(output.len() as u32),
                    name,
                    characteristics: output_characteristics(flags),
                    alignment,
                    size,
                    kind,
                },
                data,
            });
        }
    }
    Ok(output)
}

#[derive(Debug)]
struct SelectedComdat {
    object: usize,
    sections: Vec<object::SectionIndex>,
    contents: Vec<u8>,
    relocation_signature: Vec<u8>,
}

fn discarded_comdat_sections(
    objects: &[crate::coff::CoffObject<'_>],
) -> Result<HashSet<(usize, object::SectionIndex)>> {
    use linker_utils::coff_symbols::{
        ComdatCandidate, ComdatDecision, ComdatSelection, select_comdat,
    };

    let mut selected = HashMap::<Vec<u8>, SelectedComdat>::new();
    let mut discarded = HashSet::new();
    for (object_index, input) in objects.iter().enumerate() {
        for comdat in input.file().comdats() {
            let name = comdat
                .name_bytes()
                .context("invalid COFF COMDAT name")?
                .to_vec();
            // object includes the primary section and all associative children.
            let sections = comdat.sections().collect::<Vec<_>>();
            let Some(primary) = sections.first().copied() else {
                continue;
            };
            let section = input
                .file()
                .section_by_index(primary)
                .context("invalid primary COMDAT section")?;
            let contents = section.data().context("invalid COMDAT contents")?.to_vec();
            let relocation_signature =
                format!("{:?}", section.relocations().collect::<Vec<_>>()).into_bytes();
            let selection = match comdat.kind() {
                object::read::ComdatKind::NoDuplicates => ComdatSelection::NoDuplicates,
                object::read::ComdatKind::Any => ComdatSelection::Any,
                object::read::ComdatKind::SameSize => ComdatSelection::SameSize,
                object::read::ComdatKind::ExactMatch => ComdatSelection::ExactMatch,
                object::read::ComdatKind::Largest => ComdatSelection::Largest,
                object::read::ComdatKind::Newest => ComdatSelection::Newest,
                _ => {
                    return Err(error!(
                        "COMDAT `{}` has an unsupported selection",
                        String::from_utf8_lossy(&name)
                    ));
                }
            };
            if let Some(existing) = selected.get(&name) {
                let decision = select_comdat(
                    selection,
                    ComdatCandidate {
                        contents: &existing.contents,
                        relocation_signature: &existing.relocation_signature,
                        timestamp: existing.object as u32,
                    },
                    ComdatCandidate {
                        contents: &contents,
                        relocation_signature: &relocation_signature,
                        timestamp: object_index as u32,
                    },
                )
                .with_context(|| {
                    format!(
                        "while selecting COMDAT `{}`",
                        String::from_utf8_lossy(&name)
                    )
                })?;
                match decision {
                    ComdatDecision::KeepExisting => {
                        discarded.extend(sections.iter().map(|section| (object_index, *section)));
                    }
                    ComdatDecision::ReplaceExisting => {
                        discarded.extend(
                            existing
                                .sections
                                .iter()
                                .map(|section| (existing.object, *section)),
                        );
                        selected.insert(
                            name,
                            SelectedComdat {
                                object: object_index,
                                sections,
                                contents,
                                relocation_signature,
                            },
                        );
                    }
                }
            } else {
                selected.insert(
                    name,
                    SelectedComdat {
                        object: object_index,
                        sections,
                        contents,
                        relocation_signature,
                    },
                );
            }
        }
    }
    Ok(discarded)
}

fn merged_name(input: &[u8], args: &crate::args::coff::CoffArgs) -> Result<Vec<u8>> {
    let (base, suffix) = input
        .iter()
        .position(|byte| *byte == b'$')
        .map_or((input, &[][..]), |at| (&input[..at], &input[at + 1..]));
    let mut name = String::from_utf8(base.to_vec()).context("non-UTF-8 COFF section name")?;
    // Windows unwind payload is conventionally folded into read-only data.
    // `.pdata` stays separate because it is named by the exception directory.
    if name.eq_ignore_ascii_case(".xdata") {
        name = ".rdata".to_owned();
    }
    for _ in 0..args.merges.len().saturating_add(1) {
        let Some(merge) = args
            .merges
            .iter()
            .find(|m| m.from.eq_ignore_ascii_case(&name))
        else {
            break;
        };
        ensure!(
            !merge.to.eq_ignore_ascii_case(&name),
            "self-referential /MERGE for `{name}`"
        );
        name.clone_from(&merge.to);
    }
    ensure!(name.len() <= 8, "PE section name `{name}` exceeds 8 bytes");
    if suffix.is_empty() {
        Ok(name.into_bytes())
    } else {
        let mut bytes = name.into_bytes();
        bytes.push(b'$');
        bytes.extend_from_slice(suffix);
        Ok(bytes)
    }
}

fn add_common_symbols(
    objects: &[crate::coff::CoffObject<'_>],
    contributions: &mut Vec<Contribution>,
) -> Result<HashMap<Vec<u8>, (u32, ContributionId)>> {
    let mut commons = BTreeMap::<Vec<u8>, u64>::new();
    for object in objects {
        for symbol in object.file().symbols() {
            if symbol.is_common() && symbol.is_global() {
                commons
                    .entry(symbol.name_bytes()?.to_vec())
                    .and_modify(|size| *size = (*size).max(symbol.size()))
                    .or_insert(symbol.size());
            }
        }
    }
    if commons.is_empty() {
        return Ok(HashMap::new());
    }
    let id = ContributionId(contributions.len() as u32);
    let mut offsets = HashMap::new();
    let mut cursor = 0u32;
    for (name, size) in commons {
        cursor = align_plain(cursor, 16);
        offsets.insert(name, (cursor, id));
        cursor = cursor
            .checked_add(u32::try_from(size).context("common symbol too large")?)
            .context("common BSS overflow")?;
    }
    contributions.push(Contribution {
        source: Source::Synthetic,
        spec: SectionContribution {
            id,
            name: b".bss$common".to_vec(),
            characteristics: bss_characteristics(),
            alignment: 16,
            size: cursor,
            kind: ContributionKind::Bss,
        },
        data: Vec::new(),
    });
    Ok(offsets)
}

fn add_synthetic(
    contributions: &mut Vec<Contribution>,
    name: &[u8],
    size: usize,
    characteristics: u32,
) -> Result<Option<ContributionId>> {
    if size == 0 {
        return Ok(None);
    }
    let id = ContributionId(contributions.len() as u32);
    let size = u32::try_from(size).context("synthetic PE section too large")?;
    contributions.push(Contribution {
        source: Source::Synthetic,
        spec: SectionContribution {
            id,
            name: name.to_vec(),
            characteristics,
            alignment: if name.starts_with(b".text") { 16 } else { 8 },
            size,
            kind: ContributionKind::Data,
        },
        data: vec![0; size as usize],
    });
    Ok(Some(id))
}

fn make_layout(contributions: &[Contribution], config: PeWriterConfig) -> Result<SectionLayout> {
    let section_count = contributions
        .iter()
        .map(|c| c.spec.name.split(|b| *b == b'$').next().unwrap().to_vec())
        .collect::<HashSet<_>>()
        .len();
    ensure!(u16::try_from(section_count).is_ok(), "too many PE sections");
    let headers = 0x80 + 4 + 20 + 240 + u32::try_from(section_count).unwrap() * 40;
    let layout = layout_sections(
        &contributions
            .iter()
            .map(|c| c.spec.clone())
            .collect::<Vec<_>>(),
        SectionLayoutOptions {
            headers_size: headers,
            section_alignment: config.section_alignment,
            file_alignment: config.file_alignment,
        },
    )
    .context("failed to lay out PE sections")?;
    Ok(layout)
}

fn source_locations(
    contributions: &[Contribution],
) -> HashMap<(usize, object::SectionIndex), ContributionId> {
    contributions
        .iter()
        .filter_map(|c| match c.source {
            Source::Object { object, section } => Some(((object, section), c.spec.id)),
            Source::Synthetic => None,
        })
        .collect()
}

fn dir64_rvas(
    objects: &[crate::coff::CoffObject<'_>],
    contributions: &[Contribution],
    layout: &SectionLayout,
) -> Result<Vec<u32>> {
    let locations = source_locations(contributions);
    let mut rvas = Vec::new();
    for (object_index, input) in objects.iter().enumerate() {
        for section in input.file().sections() {
            let Some(id) = locations.get(&(object_index, section.index())) else {
                continue;
            };
            for (offset, relocation) in section.relocations() {
                if relocation.kind() == RelocationKind::Absolute && relocation.size() == 64 {
                    rvas.push(
                        layout.placements[id]
                            .rva
                            .checked_add(
                                u32::try_from(offset).context("relocation offset too large")?,
                            )
                            .context("relocation RVA overflow")?,
                    );
                }
            }
        }
    }
    Ok(rvas)
}

type LocationMap = HashMap<(usize, object::SectionIndex), ContributionId>;

fn definitions(
    objects: &[crate::coff::CoffObject<'_>],
    contributions: &[Contribution],
    layout: &SectionLayout,
    image_base: u64,
    allow_multiple: bool,
) -> Result<(LocationMap, HashMap<Vec<u8>, u64>)> {
    let locations = source_locations(contributions);
    let mut definitions = HashMap::new();
    for (object_index, input) in objects.iter().enumerate() {
        for symbol in input.file().symbols() {
            if !symbol.is_global() || symbol.is_common() {
                continue;
            }
            let name = symbol.name_bytes()?.to_vec();
            let address = if let Some(section) = symbol.section_index() {
                let Some(id) = locations.get(&(object_index, section)) else {
                    continue;
                };
                image_base + u64::from(layout.placements[id].rva) + symbol.address()
            } else if symbol.is_definition() {
                symbol.address()
            } else {
                continue;
            };
            if let Some(old) = definitions.insert(name.clone(), address) {
                ensure!(
                    allow_multiple || old == address,
                    "duplicate symbol `{}`",
                    String::from_utf8_lossy(&name)
                );
                if allow_multiple {
                    definitions.insert(name, old);
                }
            }
        }
    }
    Ok((locations, definitions))
}

fn find_local_symbol(
    objects: &[crate::coff::CoffObject<'_>],
    locations: &LocationMap,
    layout: &SectionLayout,
    name: &[u8],
    image_base: u64,
) -> Result<Option<u64>> {
    for (object_index, input) in objects.iter().enumerate() {
        for symbol in input.file().symbols() {
            if symbol.name_bytes()? != name {
                continue;
            }
            if let Some(section) = symbol.section_index()
                && let Some(id) = locations.get(&(object_index, section))
            {
                return Ok(Some(
                    image_base + u64::from(layout.placements[id].rva) + symbol.address(),
                ));
            }
        }
    }
    Ok(None)
}

fn apply_relocations(
    objects: &[crate::coff::CoffObject<'_>],
    layout: &SectionLayout,
    locations: &LocationMap,
    definitions: &HashMap<Vec<u8>, u64>,
    image_base: u64,
    image: &mut [u8],
) -> Result<()> {
    for (object_index, input) in objects.iter().enumerate() {
        for source in input.file().sections() {
            let Some(source_id) = locations.get(&(object_index, source.index())) else {
                continue;
            };
            let placement = &layout.placements[source_id];
            for (offset, relocation) in source.relocations() {
                use linker_utils::coff::{
                    Amd64RelocationInputs, Amd64RelocationKind, ImageBase, Rva, SectionIndex,
                    apply_amd64_relocation,
                };
                let source_file = placement
                    .file_offset
                    .ok_or_else(|| error!("relocation in uninitialized section"))?;
                let (target, target_section, target_section_index) = match relocation.target() {
                    RelocationTarget::Symbol(index) => {
                        let symbol = input
                            .file()
                            .symbol_by_index(index)
                            .context("invalid relocation symbol")?;
                        let name = symbol.name_bytes()?;
                        if symbol.is_global()
                            && let Some(address) = definitions.get(name)
                        {
                            target_location(layout, image_base, *address)?
                        } else if let Some(section) = symbol.section_index() {
                            let id = locations
                                .get(&(object_index, section))
                                .ok_or_else(|| error!("relocation targets discarded section"))?;
                            let target_placement = &layout.placements[id];
                            let target = target_placement
                                .rva
                                .checked_add(
                                    u32::try_from(symbol.address())
                                        .context("COFF symbol offset exceeds u32")?,
                                )
                                .context("COFF symbol RVA overflow")?;
                            (
                                target,
                                layout.sections[target_placement.output_section].rva,
                                u16::try_from(target_placement.output_section + 1)
                                    .context("PE section index exceeds u16")?,
                            )
                        } else {
                            let address = *definitions.get(name).ok_or_else(|| {
                                error!("undefined symbol `{}`", String::from_utf8_lossy(name))
                            })?;
                            target_location(layout, image_base, address)?
                        }
                    }
                    RelocationTarget::Section(section) => {
                        let id = locations
                            .get(&(object_index, section))
                            .ok_or_else(|| error!("relocation targets discarded section"))?;
                        let target_placement = &layout.placements[id];
                        (
                            target_placement.rva,
                            layout.sections[target_placement.output_section].rva,
                            u16::try_from(target_placement.output_section + 1)
                                .context("PE section index exceeds u16")?,
                        )
                    }
                    _ => return Err(error!("unsupported COFF relocation target")),
                };
                let typ = match relocation.flags() {
                    object::RelocationFlags::Coff { typ } => typ,
                    flags => return Err(error!("expected COFF relocation flags, got {flags:?}")),
                };
                let kind = Amd64RelocationKind::from_type(typ)
                    .context("unsupported AMD64 COFF relocation")?;
                let at = usize::try_from(u64::from(source_file) + offset)
                    .context("relocation file offset too large")?;
                let field = image.get_mut(at..).context("relocation past file data")?;
                apply_amd64_relocation(
                    kind,
                    field,
                    Amd64RelocationInputs {
                        image_base: ImageBase(image_base),
                        place: Rva(placement
                            .rva
                            .checked_add(
                                u32::try_from(offset).context("relocation offset exceeds u32")?,
                            )
                            .context("relocation place RVA overflow")?),
                        target: Rva(target),
                        target_section: Rva(target_section),
                        target_section_index: SectionIndex(target_section_index),
                    },
                )
                .context("failed to apply AMD64 COFF relocation")?;
            }
        }
    }
    Ok(())
}

fn target_location(
    layout: &SectionLayout,
    image_base: u64,
    address: u64,
) -> Result<(u32, u32, u16)> {
    let rva = u32::try_from(
        address
            .checked_sub(image_base)
            .context("relocation target precedes image base")?,
    )
    .context("relocation target RVA exceeds u32")?;
    let (index, section) = layout
        .sections
        .iter()
        .enumerate()
        .find(|(_, section)| {
            rva >= section.rva && rva < section.rva.saturating_add(section.virtual_size)
        })
        .ok_or_else(|| error!("relocation target RVA {rva:#x} is outside the image"))?;
    Ok((
        rva,
        section.rva,
        u16::try_from(index + 1).context("PE section index exceeds u16")?,
    ))
}

fn write_headers(
    image: &mut [u8],
    layout: &SectionLayout,
    args: &crate::args::coff::CoffArgs,
    config: PeWriterConfig,
    entry_rva: u32,
    import_directory: Option<(u32, u32)>,
    iat_directory: Option<(u32, u32)>,
    has_relocs: bool,
    export_directory: Option<(u32, u32)>,
) {
    image[..2].copy_from_slice(b"MZ");
    put_u32(image, 0x3c, 0x80);
    image[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    put_u16(image, coff, crate::coff_x86_64::CoffX86_64::MACHINE);
    put_u16(image, coff + 2, layout.sections.len() as u16);
    put_u16(image, coff + 16, 240);
    let mut file_chars =
        object::pe::IMAGE_FILE_EXECUTABLE_IMAGE.0 | object::pe::IMAGE_FILE_LARGE_ADDRESS_AWARE.0;
    if args.is_dll {
        file_chars |= object::pe::IMAGE_FILE_DLL.0;
    }
    if args.fixed {
        file_chars |= object::pe::IMAGE_FILE_RELOCS_STRIPPED.0;
    }
    put_u16(image, coff + 18, file_chars);
    let opt = coff + 20;
    put_u16(image, opt, 0x20b);
    put_u32(
        image,
        opt + 4,
        layout
            .sections
            .iter()
            .filter(|s| s.characteristics & object::pe::IMAGE_SCN_CNT_CODE.0 != 0)
            .map(|s| s.raw_size)
            .sum(),
    );
    put_u32(
        image,
        opt + 8,
        layout
            .sections
            .iter()
            .filter(|s| s.characteristics & object::pe::IMAGE_SCN_CNT_INITIALIZED_DATA.0 != 0)
            .map(|s| s.raw_size)
            .sum(),
    );
    put_u32(
        image,
        opt + 12,
        layout
            .sections
            .iter()
            .filter(|s| s.characteristics & object::pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA.0 != 0)
            .map(|s| s.virtual_size)
            .sum(),
    );
    put_u32(image, opt + 16, entry_rva);
    put_u32(
        image,
        opt + 20,
        layout
            .sections
            .iter()
            .find(|s| s.characteristics & object::pe::IMAGE_SCN_CNT_CODE.0 != 0)
            .map_or(0, |s| s.rva),
    );
    put_u64(image, opt + 24, config.image_base);
    put_u32(image, opt + 32, config.section_alignment);
    put_u32(image, opt + 36, config.file_alignment);
    put_u16(image, opt + 40, 6);
    if let Some((major, minor)) = args.image_version {
        put_u16(image, opt + 44, major);
        put_u16(image, opt + 46, minor);
    }
    put_u16(
        image,
        opt + 48,
        args.subsystem
            .as_ref()
            .and_then(|s| s.version)
            .map_or(6, |v| v.0),
    );
    put_u16(
        image,
        opt + 50,
        args.subsystem
            .as_ref()
            .and_then(|s| s.version)
            .map_or(0, |v| v.1),
    );
    put_u32(image, opt + 56, layout.size_of_image);
    put_u32(
        image,
        opt + 60,
        align_plain(
            0x80 + 4 + 20 + 240 + layout.sections.len() as u32 * 40,
            config.file_alignment,
        ),
    );
    put_u16(image, opt + 68, subsystem_value(args));
    let mut dll_chars = 0;
    if args.nx_compat {
        dll_chars |= object::pe::IMAGE_DLLCHARACTERISTICS_NX_COMPAT.0;
    }
    if args.dynamic_base && !args.fixed {
        dll_chars |= object::pe::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE.0
            | object::pe::IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA.0;
    }
    dll_chars |= object::pe::IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE.0;
    put_u16(image, opt + 70, dll_chars);
    let stack = args.stack.unwrap_or(crate::args::coff::ReserveCommit {
        reserve: 0x10_0000,
        commit: Some(0x1000),
    });
    let heap = args.heap.unwrap_or(crate::args::coff::ReserveCommit {
        reserve: 0x10_0000,
        commit: Some(0x1000),
    });
    put_u64(image, opt + 72, stack.reserve);
    put_u64(image, opt + 80, stack.commit.unwrap_or(0x1000));
    put_u64(image, opt + 88, heap.reserve);
    put_u64(image, opt + 96, heap.commit.unwrap_or(0x1000));
    put_u32(image, opt + 108, 16);
    if let Some((rva, size)) = export_directory {
        put_u32(image, opt + 112, rva);
        put_u32(image, opt + 116, size);
    }
    if let Some((rva, size)) = import_directory {
        put_u32(image, opt + 120, rva);
        put_u32(image, opt + 124, size);
    }
    set_directory_from_section(image, opt + 136, layout, DataDirectoryKind::Exception);
    if has_relocs {
        set_directory_from_section(image, opt + 152, layout, DataDirectoryKind::BaseRelocation);
    }
    if let Some((rva, size)) = iat_directory {
        put_u32(image, opt + 208, rva);
        put_u32(image, opt + 212, size);
    }
    let table = opt + 240;
    for (index, section) in layout.sections.iter().enumerate() {
        let at = table + index * 40;
        image[at..at + section.name.len()].copy_from_slice(&section.name);
        put_u32(image, at + 8, section.virtual_size);
        put_u32(image, at + 12, section.rva);
        put_u32(image, at + 16, section.raw_size);
        put_u32(image, at + 20, section.file_offset.unwrap_or(0));
        put_u32(image, at + 36, section_attributes(section, args));
    }
}

fn set_directory_from_section(
    image: &mut [u8],
    at: usize,
    layout: &SectionLayout,
    kind: DataDirectoryKind,
) {
    if let Some(range) = directory_range_for_section(layout, kind) {
        put_u32(image, at, range.rva);
        put_u32(image, at + 4, range.size);
    }
}

fn section_attributes(
    section: &linker_utils::pe_sections::OutputSection,
    args: &crate::args::coff::CoffArgs,
) -> u32 {
    let mut flags = section.characteristics;
    let name = String::from_utf8_lossy(&section.name);
    if let Some(spec) = args
        .section_attributes
        .iter()
        .find(|s| s.name.eq_ignore_ascii_case(&name))
    {
        for attr in spec.attributes.bytes() {
            match attr {
                b'E' => flags |= object::pe::IMAGE_SCN_MEM_EXECUTE.0,
                b'R' => flags |= object::pe::IMAGE_SCN_MEM_READ.0,
                b'W' => flags |= object::pe::IMAGE_SCN_MEM_WRITE.0,
                b'S' => flags |= object::pe::IMAGE_SCN_MEM_SHARED.0,
                b'D' => flags |= object::pe::IMAGE_SCN_MEM_DISCARDABLE.0,
                b'K' => flags &= !object::pe::IMAGE_SCN_MEM_READ.0,
                b'P' => flags &= !object::pe::IMAGE_SCN_MEM_WRITE.0,
                _ => {}
            }
        }
    }
    flags
}

fn subsystem_value(args: &crate::args::coff::CoffArgs) -> u16 {
    use crate::args::coff::Subsystem;
    match args.subsystem.as_ref().map(|s| &s.kind) {
        Some(Subsystem::Windows) => 2,
        Some(Subsystem::Native) => 1,
        Some(Subsystem::Posix) => 7,
        Some(Subsystem::EfiApplication) => 10,
        Some(Subsystem::EfiBootServiceDriver) => 11,
        Some(Subsystem::EfiRuntimeDriver) => 12,
        Some(Subsystem::EfiRom) => 13,
        Some(Subsystem::Console) | None => 3,
    }
}
fn output_characteristics(input: u32) -> u32 {
    input
        & (object::pe::IMAGE_SCN_CNT_CODE
            | object::pe::IMAGE_SCN_CNT_INITIALIZED_DATA
            | object::pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA
            | object::pe::IMAGE_SCN_MEM_EXECUTE
            | object::pe::IMAGE_SCN_MEM_READ
            | object::pe::IMAGE_SCN_MEM_WRITE
            | object::pe::IMAGE_SCN_MEM_SHARED
            | object::pe::IMAGE_SCN_MEM_DISCARDABLE)
            .0
}
fn text_characteristics() -> u32 {
    (object::pe::IMAGE_SCN_CNT_CODE
        | object::pe::IMAGE_SCN_MEM_EXECUTE
        | object::pe::IMAGE_SCN_MEM_READ)
        .0
}
fn data_characteristics() -> u32 {
    (object::pe::IMAGE_SCN_CNT_INITIALIZED_DATA
        | object::pe::IMAGE_SCN_MEM_READ
        | object::pe::IMAGE_SCN_MEM_WRITE)
        .0
}
fn readonly_data_characteristics() -> u32 {
    (object::pe::IMAGE_SCN_CNT_INITIALIZED_DATA | object::pe::IMAGE_SCN_MEM_READ).0
}
fn bss_characteristics() -> u32 {
    (object::pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA
        | object::pe::IMAGE_SCN_MEM_READ
        | object::pe::IMAGE_SCN_MEM_WRITE)
        .0
}
fn reloc_characteristics() -> u32 {
    (object::pe::IMAGE_SCN_CNT_INITIALIZED_DATA
        | object::pe::IMAGE_SCN_MEM_READ
        | object::pe::IMAGE_SCN_MEM_DISCARDABLE)
        .0
}
fn align_plain(value: u32, alignment: u32) -> u32 {
    (value + alignment - 1) & !(alignment - 1)
}
fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::write::{Object as WritableObject, Symbol, SymbolSection};

    fn export_test_object(directives: Option<&[u8]>) -> Vec<u8> {
        let mut object = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let text = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
        object.append_section_data(text, &[0xc3], 1);
        object.add_symbol(Symbol {
            name: b"function".to_vec(),
            value: 0,
            size: 1,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(text),
            flags: object::SymbolFlags::None,
        });
        let data = object.add_section(Vec::new(), b".data".to_vec(), object::SectionKind::Data);
        object.append_section_data(data, &17u32.to_le_bytes(), 4);
        object.add_symbol(Symbol {
            name: b"value".to_vec(),
            value: 0,
            size: 4,
            kind: object::SymbolKind::Data,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(data),
            flags: object::SymbolFlags::None,
        });
        if let Some(directives) = directives {
            let section = object.add_section(
                Vec::new(),
                b".drectve".to_vec(),
                object::SectionKind::ReadOnlyData,
            );
            object.append_section_data(section, directives, 1);
        }
        object.write().unwrap()
    }

    #[test]
    fn args_drive_writer_configuration() {
        let args = crate::args::coff::CoffArgs {
            section_alignment: Some(0x2000),
            file_alignment: Some(0x400),
            image_base: Some(crate::args::coff::ImageBase {
                address: 0x180000000,
                max_size: None,
            }),
            ..Default::default()
        };
        let config = PeWriterConfig::from_args(&args).unwrap();
        assert_eq!(config.section_alignment, 0x2000);
        assert_eq!(config.file_alignment, 0x400);
        assert_eq!(config.image_base, 0x180000000);
    }
    #[test]
    fn applies_merge_to_subsection() {
        let args = crate::args::coff::CoffArgs {
            merges: vec![crate::args::coff::SectionMerge {
                from: ".foo".into(),
                to: ".data".into(),
            }],
            ..Default::default()
        };
        assert_eq!(merged_name(b".foo$z", &args).unwrap(), b".data$z");
    }

    #[test]
    fn builds_dll_exports_at_final_rvas() {
        let bytes = export_test_object(None);
        let object = crate::coff::CoffObject::parse(&bytes).unwrap();
        let args = crate::args::coff::CoffArgs {
            is_dll: true,
            no_entry: true,
            ..Default::default()
        };
        let exports = vec![
            crate::args::coff::ExportSpec {
                name: "function".into(),
                target: "function".into(),
                ordinal: None,
                noname: false,
                data: false,
                private: false,
            },
            crate::args::coff::ExportSpec {
                name: "value".into(),
                target: "value".into(),
                ordinal: Some(9),
                noname: false,
                data: true,
                private: false,
            },
        ];
        let image = build_image(
            &[object],
            &[],
            &exports,
            b"sample.dll",
            None,
            &args,
            PeWriterConfig::default(),
        )
        .unwrap();
        assert_eq!(
            image
                .exports
                .iter()
                .map(|export| (export.name.as_slice(), export.ordinal, export.data))
                .collect::<Vec<_>>(),
            [
                (b"function".as_slice(), 1, false),
                (b"value".as_slice(), 9, true)
            ]
        );
        assert_ne!(
            u32::from_le_bytes(image.bytes[0x108..0x10c].try_into().unwrap()),
            0
        );
        assert_ne!(
            u32::from_le_bytes(image.bytes[0x10c..0x110].try_into().unwrap()),
            0
        );
    }

    #[test]
    fn reads_compiler_generated_export_directives() {
        let bytes = export_test_object(Some(b" /EXPORT:function /EXPORT:value,DATA"));
        let object = crate::coff::CoffObject::parse(&bytes).unwrap();
        let exports = directive_exports(&[object]).unwrap();
        assert_eq!(exports.len(), 2);
        assert_eq!(exports[0].name, "function");
        assert!(!exports[0].data);
        assert_eq!(exports[1].name, "value");
        assert!(exports[1].data);
    }
}
