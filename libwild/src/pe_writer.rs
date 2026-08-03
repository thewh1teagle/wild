//! Experimental AMD64 PE/COFF linker.

use crate::ensure;
use crate::error;
use crate::error::Context;
use crate::error::Result;
use crate::fs::FileReplacementMode;
use crate::fs::FileSystem;
use crate::fs::InputFileData;
use crate::fs::OutputFileData;
use crate::fs::OutputOptions;
use linker_utils::pe_base_relocs::build_amd64_base_relocation_table;
use linker_utils::pe_exports::Export;
use linker_utils::pe_exports::ExportTarget;
use linker_utils::pe_exports::ResolvedExport;
use linker_utils::pe_resources::ResourceRecord;
use linker_utils::pe_sections::ContributionId;
use linker_utils::pe_sections::ContributionKind;
use linker_utils::pe_sections::DataDirectoryKind;
use linker_utils::pe_sections::SectionContribution;
use linker_utils::pe_sections::SectionLayout;
use linker_utils::pe_sections::SectionLayoutOptions;
use linker_utils::pe_sections::directory_range_for_section;
use linker_utils::pe_sections::layout_sections;
use object::Object;
use object::ObjectComdat;
use object::ObjectSection;
use object::ObjectSymbol;
use object::RelocationKind;
use object::RelocationTarget;
use object::SectionFlags;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;
use std::path::PathBuf;

const LOAD_CONFIG_SECURITY_COOKIE_OFFSET: u32 = 88;

#[path = "pe_entry.rs"]
mod pe_entry;
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

    let mut inputs = Vec::new();
    for request in requested {
        open_input(fs, &request, args, &mut inputs, false)?;
    }
    let selected = select_inputs_to_fixpoint(fs, args, &mut inputs)?;
    let objects = selected.objects;
    let resources = selected.resources;
    let archive_bytes = selected.archive_bytes;
    let entry_name = selected.entry_name;
    let exports = selected.exports;
    let archive_definitions = selected.archive_definitions;
    let runtime_resolution = selected.runtime_resolution;
    let mut roots = selected.roots;
    // Preserve the accumulated runtime state through final resolution. Includes already took
    // part in extraction, and keeping this merge here makes that downstream contract explicit.
    roots.extend(
        runtime_resolution
            .include_roots()
            .map(|symbol| symbol.as_bytes().to_vec()),
    );
    roots.sort();
    roots.dedup();
    ensure!(!objects.is_empty(), "no COFF object files selected");

    let undefined =
        resolved_undefined_symbols(&objects, &roots, &archive_definitions, &runtime_resolution)?;
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
        entry_name.as_deref(),
        args,
        PeWriterConfig::from_args(args)?,
        &resources,
        &runtime_resolution,
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

#[cfg(test)]
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

struct SelectedInputs<'data> {
    objects: Vec<crate::coff::CoffObject<'data>>,
    resources: Vec<ResourceRecord>,
    archive_bytes: Vec<&'data [u8]>,
    entry_name: Option<String>,
    exports: Vec<crate::args::coff::ExportSpec>,
    roots: Vec<Vec<u8>>,
    runtime_resolution: linker_utils::coff_runtime::RuntimeResolution,
    archive_definitions: BTreeSet<Vec<u8>>,
}

/// Rebuilds borrowed COFF state after every newly discovered default library.
///
/// This deliberately keeps the `inputs` growth outside the scope holding `CoffObject` and
/// archive borrows. Besides satisfying Rust's ownership rules, rebuilding is important for
/// correctness: an archive member selected in one round can carry another `/DEFAULTLIB`,
/// `/INCLUDE`, or `/EXPORT` that changes the next archive-extraction fixpoint.
fn select_inputs_to_fixpoint<'data, F: FileSystem>(
    fs: &F,
    args: &crate::args::coff::CoffArgs,
    inputs: &'data mut Vec<(PathBuf, F::Input, bool)>,
) -> Result<SelectedInputs<'data>> {
    let mut no_default_libraries = args.no_default_libraries;
    let mut excluded_default_libraries = args.excluded_default_libraries.clone();
    loop {
        let missing = {
            let selection = select_opened_inputs::<F>(
                args,
                inputs,
                no_default_libraries,
                &excluded_default_libraries,
            )?;
            let old_policy = (no_default_libraries, excluded_default_libraries.len());
            no_default_libraries |= selection.directives.no_default_libraries;
            for excluded in &selection.directives.excluded_default_libraries {
                if !excluded_default_libraries
                    .iter()
                    .any(|existing| same_library_name(existing, excluded))
                {
                    excluded_default_libraries.push(excluded.clone());
                }
            }
            if old_policy == (no_default_libraries, excluded_default_libraries.len()) {
                let mut libraries = Vec::new();
                if !no_default_libraries {
                    libraries.extend(args.default_libraries.iter().cloned());
                    libraries.extend(selection.directives.default_libraries.iter().cloned());
                }
                libraries.retain(|library| {
                    !excluded_default_libraries
                        .iter()
                        .any(|excluded| same_library_name(excluded, library))
                });
                deduplicate_case_insensitive(&mut libraries);

                let disallowed = args
                    .disallowed_libraries
                    .iter()
                    .chain(selection.directives.disallowed_libraries.iter())
                    .collect::<Vec<_>>();
                for (path, _, is_default) in inputs.iter() {
                    if *is_default
                        && (no_default_libraries
                            || excluded_default_libraries
                                .iter()
                                .any(|name| path_matches(path, name)))
                    {
                        continue;
                    }
                    if !disallowed.iter().any(|name| path_matches(path, name)) {
                        continue;
                    }
                    return Err(error!(
                        "COFF library `{}` is forbidden by /DISALLOWLIB",
                        path.display()
                    ));
                }
                if let Some(library) = libraries.iter().find(|library| {
                    disallowed
                        .iter()
                        .any(|name| same_library_name(name, library))
                }) {
                    return Err(error!(
                        "COFF library `{library}` is forbidden by /DISALLOWLIB"
                    ));
                }

                Some(
                    libraries
                        .into_iter()
                        .filter(|library| {
                            !inputs
                                .iter()
                                .any(|(path, _, _)| path_matches(path, library))
                        })
                        .collect::<Vec<_>>(),
                )
            } else {
                // Re-select before discovering more libraries so a newly observed
                // /NODEFAULTLIB can deactivate an archive opened in an earlier round.
                None
            }
        };
        let Some(missing) = missing else {
            continue;
        };
        if missing.is_empty() {
            break;
        }

        // Every borrow into `inputs` ended with the discovery scope above. The next iteration
        // reparses direct objects and deterministically re-extracts archive members.
        let old_len = inputs.len();
        for library in missing {
            open_input(fs, Path::new(&library), args, inputs, true)?;
        }
        ensure!(
            inputs.len() != old_len,
            "default-library discovery made no progress"
        );
    }
    Ok(select_opened_inputs::<F>(
        args,
        inputs,
        no_default_libraries,
        &excluded_default_libraries,
    )?
    .finish())
}

struct OpenSelection<'data> {
    objects: Vec<crate::coff::CoffObject<'data>>,
    resources: Vec<ResourceRecord>,
    archive_bytes: Vec<&'data [u8]>,
    entry_name: Option<String>,
    exports: Vec<crate::args::coff::ExportSpec>,
    roots: Vec<Vec<u8>>,
    directives: crate::args::coff::CoffArgs,
    archive_definitions: BTreeSet<Vec<u8>>,
}

impl<'data> OpenSelection<'data> {
    fn finish(self) -> SelectedInputs<'data> {
        SelectedInputs {
            objects: self.objects,
            resources: self.resources,
            archive_bytes: self.archive_bytes,
            entry_name: self.entry_name,
            exports: self.exports,
            roots: self.roots,
            runtime_resolution: self.directives.runtime_resolution,
            archive_definitions: self.archive_definitions,
        }
    }
}

fn select_opened_inputs<'data, F: FileSystem>(
    args: &crate::args::coff::CoffArgs,
    inputs: &'data [(PathBuf, F::Input, bool)],
    no_default_libraries: bool,
    excluded_default_libraries: &[String],
) -> Result<OpenSelection<'data>> {
    let mut objects = Vec::new();
    let mut resources = Vec::new();
    let mut archive_bytes = Vec::new();
    let mut archive_whole = Vec::new();
    for (path, data, is_default) in inputs {
        if *is_default
            && (no_default_libraries
                || excluded_default_libraries
                    .iter()
                    .any(|name| path_matches(path, name)))
        {
            continue;
        }
        if path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("res"))
        {
            resources.extend(
                linker_utils::pe_resources::parse_res(data.bytes())
                    .with_context(|| format!("while reading `{}`", path.display()))?,
            );
            continue;
        }
        match object::FileKind::parse(data.bytes())
            .with_context(|| format!("cannot identify COFF input `{}`", path.display()))?
        {
            object::FileKind::Coff | object::FileKind::CoffBig => objects.push(
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

    let entry_name = pe_entry::select(args, &objects)?;
    loop {
        let mut directives = directive_args(args, &objects)?;
        let mut exports = args.exports.clone();
        for export in &directives.exports {
            if !exports.contains(export) {
                exports.push(export.clone());
            }
        }
        let mut roots = args
            .force_undefined
            .iter()
            .chain(directives.force_undefined.iter())
            .map(|symbol| symbol.as_bytes().to_vec())
            .collect::<Vec<_>>();
        roots.extend(
            directives
                .runtime_resolution
                .include_roots()
                .map(|symbol| symbol.as_bytes().to_vec()),
        );
        if let Some(entry) = entry_name.as_deref() {
            roots.push(entry.as_bytes().to_vec());
        }
        roots.extend(
            exports
                .iter()
                .map(|export| export.target.as_bytes().to_vec()),
        );
        roots.sort();
        roots.dedup();

        let old_len = objects.len();
        let archive_definitions = pe_resolver::extract(
            &mut objects,
            &archive_bytes,
            &archive_whole,
            &roots,
            &mut directives.runtime_resolution,
        )?;
        if objects.len() == old_len {
            return Ok(OpenSelection {
                objects,
                resources,
                archive_bytes,
                entry_name,
                exports,
                roots,
                directives,
                archive_definitions,
            });
        }
    }
}

fn directive_args(
    args: &crate::args::coff::CoffArgs,
    objects: &[crate::coff::CoffObject<'_>],
) -> Result<crate::args::coff::CoffArgs> {
    let mut parsed = crate::args::coff::CoffArgs {
        runtime_resolution: args.runtime_resolution.clone(),
        ..Default::default()
    };
    for (index, object) in objects.iter().enumerate() {
        let Some(section) = object.file().section_by_name(".drectve") else {
            continue;
        };
        let text = std::str::from_utf8(section.data().context("invalid COFF .drectve")?)
            .with_context(|| format!("non-UTF-8 .drectve in selected COFF object #{index}"))?
            .trim_end_matches('\0');
        crate::args::coff::parse_directives(&mut parsed, text)
            .with_context(|| format!("in selected COFF object #{index}"))?;
    }
    Ok(parsed)
}

fn deduplicate_case_insensitive(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.to_ascii_lowercase()));
}

fn write_import_library<F: FileSystem>(
    fs: &F,
    args: &crate::args::coff::CoffArgs,
    dll_name: &[u8],
    specs: &[crate::args::coff::ExportSpec],
    resolved: &[ResolvedExport],
) -> Result<()> {
    use linker_utils::coff_import_library_writer::ImportLibraryExport;
    use linker_utils::coff_import_library_writer::ImportLibrarySymbolType;
    use linker_utils::coff_import_library_writer::build_amd64_import_library;

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
            .is_some_and(|name| same_library_name(&name.to_string_lossy(), requested))
}

fn same_library_name(left: &str, right: &str) -> bool {
    fn canonical(name: &str) -> String {
        let file_name = Path::new(name)
            .file_name()
            .map_or(name, |value| value.to_str().unwrap_or(name));
        let mut canonical = file_name.to_ascii_lowercase();
        if Path::new(&canonical)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("lib"))
        {
            canonical.truncate(canonical.len() - 4);
        }
        canonical
    }
    canonical(left) == canonical(right)
}

fn open_input<F: FileSystem>(
    fs: &F,
    request: &Path,
    args: &crate::args::coff::CoffArgs,
    inputs: &mut Vec<(PathBuf, F::Input, bool)>,
    is_default: bool,
) -> Result<()> {
    let path = find_input(fs, request, args)?;
    if inputs.iter().any(|(existing, _, _)| existing == &path) {
        return Ok(());
    }
    let (data, _) = fs
        .open_input(&path, args.common.prepopulate_maps)
        .with_context(|| format!("Failed to open COFF input `{}`", path.display()))?;
    inputs.push((path, data, is_default));
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

fn resolved_undefined_symbols(
    objects: &[crate::coff::CoffObject<'_>],
    roots: &[Vec<u8>],
    archive_definitions: &BTreeSet<Vec<u8>>,
    runtime_resolution: &linker_utils::coff_runtime::RuntimeResolution,
) -> Result<HashSet<Vec<u8>>> {
    let undefined = undefined_symbols(objects, roots)?;
    let object_definitions = object_definition_names(objects)?;
    undefined
        .into_iter()
        .map(|name| {
            // A selected short import of the primary name is a real definition and
            // must be emitted rather than replaced by its weak fallback.
            if archive_definitions.contains(&name) {
                return Ok(name);
            }
            let Ok(text) = std::str::from_utf8(&name) else {
                return Ok(name);
            };
            runtime_resolution
                .resolve_alternate_name(text, |candidate| {
                    object_definitions.contains(candidate.as_bytes())
                        || archive_definitions.contains(candidate.as_bytes())
                })
                .map(|resolved| resolved.as_bytes().to_vec())
                .map_err(Into::into)
        })
        .collect()
}

fn object_definition_names(objects: &[crate::coff::CoffObject<'_>]) -> Result<HashSet<Vec<u8>>> {
    let mut definitions = HashSet::new();
    for input in objects {
        for symbol in input.file().symbols() {
            if symbol.is_global() && (symbol.is_definition() || symbol.is_common()) {
                definitions.insert(symbol.name_bytes()?.to_vec());
            }
        }
    }
    Ok(definitions)
}

fn build_image(
    objects: &[crate::coff::CoffObject<'_>],
    imports: &[pe_imports::Import],
    exports: &[crate::args::coff::ExportSpec],
    dll_name: &[u8],
    entry_name: Option<&str>,
    args: &crate::args::coff::CoffArgs,
    config: PeWriterConfig,
    resources: &[ResourceRecord],
    runtime_resolution: &linker_utils::coff_runtime::RuntimeResolution,
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
    let resource_size = if resources.is_empty() {
        0
    } else {
        linker_utils::pe_resources::build_resource_section(resources, 1)
            .context("failed to size PE resources")?
            .bytes
            .len()
    };
    let resource_id = add_synthetic(
        &mut contributions,
        b".rsrc",
        resource_size,
        readonly_data_characteristics(),
    )?;
    let debug_id = add_synthetic(
        &mut contributions,
        b".debug",
        if args.debug {
            linker_utils::pe_debug::IMAGE_DEBUG_DIRECTORY_SIZE
                + linker_utils::pe_debug::REPRO_BUILD_ID_SIZE
        } else {
            0
        },
        debug_characteristics(),
    )?;
    let has_security_cookie =
        has_live_defined_symbol(objects, &contributions, b"__security_cookie")?;
    let load_config_id = add_synthetic(
        &mut contributions,
        b".loadcfg",
        if has_security_cookie {
            linker_utils::pe_load_config::IMAGE_LOAD_CONFIG_DIRECTORY64_COMPAT_SIZE as usize
        } else {
            0
        },
        readonly_data_characteristics(),
    )?;

    let dynamic_base = args.dynamic_base && !args.fixed;
    let mut reloc_id = None;
    let mut reloc_data = Vec::new();
    let mut layout = make_layout(&contributions, config)?;
    if dynamic_base {
        for _ in 0..3 {
            let mut dir64 = dir64_rvas(objects, &contributions, &layout)?;
            add_load_config_relocation(&mut dir64, load_config_id, &layout)?;
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
            let mut dir64 = dir64_rvas(objects, &contributions, &layout)?;
            add_load_config_relocation(&mut dir64, load_config_id, &layout)?;
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
    let resource_directory = if let Some(id) = resource_id {
        let section = linker_utils::pe_resources::build_resource_section(
            resources,
            layout.placements[&id].rva,
        )
        .context("failed to build PE resource directory")?;
        let contribution = contributions.iter_mut().find(|c| c.spec.id == id).unwrap();
        ensure!(
            section.bytes.len() == contribution.data.len(),
            "PE resource section changed size after layout"
        );
        contribution.data.copy_from_slice(&section.bytes);
        Some((section.data_directory.rva, section.data_directory.size))
    } else {
        None
    };

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
    add_image_base_symbol(&mut definitions, config.image_base);
    bind_alternate_names(&mut definitions, runtime_resolution)?;
    let load_config_directory = if let Some(id) = load_config_id {
        let cookie_va = definitions
            .get(b"__security_cookie".as_slice())
            .copied()
            .context("__security_cookie disappeared during PE symbol resolution")?;
        let cookie_rva = u32::try_from(
            cookie_va
                .checked_sub(config.image_base)
                .context("__security_cookie precedes the image base")?,
        )
        .context("__security_cookie RVA exceeds u32")?;
        let placement = &layout.placements[&id];
        let encoded = linker_utils::pe_load_config::encode_pe_load_config64(
            &linker_utils::pe_load_config::PeLoadConfig64 {
                image_base: config.image_base,
                directory_rva: placement.rva,
                size_of_image: layout.size_of_image,
                security_cookie_rva: Some(cookie_rva),
                guard_cf_check_function_pointer_rva: None,
                guard_cf_dispatch_function_pointer_rva: None,
                guard_cf_function_rvas: Vec::new(),
                guard_eh_continuation_rvas: Vec::new(),
                guard_flags: 0,
            },
        )
        .context("failed to build PE load-config directory")?;
        let contribution = contributions.iter_mut().find(|c| c.spec.id == id).unwrap();
        ensure!(
            encoded.bytes.len() == contribution.data.len(),
            "PE load-config section changed size after layout"
        );
        contribution.data.copy_from_slice(&encoded.bytes);
        Some((encoded.data_directory_rva, encoded.data_directory_size))
    } else {
        None
    };
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
    let exception_directory = canonicalize_exception_directory(&mut image, &layout, args)?;
    let debug_directory = if let Some(id) = debug_id {
        let placement = &layout.placements[&id];
        let file_offset = placement
            .file_offset
            .context("synthetic debug directory has no file contents")?;
        let encoded = linker_utils::pe_debug::encode_debug_directory(
            &[linker_utils::pe_debug::DebugRecord::Repro { build_id: [0; 32] }],
            placement.rva,
            file_offset,
        )
        .context("failed to create reproducible PE debug directory")?;
        let start = usize::try_from(file_offset).context("debug file offset exceeds usize")?;
        image[start..start + encoded.bytes.len()].copy_from_slice(&encoded.bytes);
        Some((placement.rva, encoded.directory_size))
    } else {
        None
    };
    write_headers(
        &mut image,
        &layout,
        args,
        config,
        entry_rva,
        entry_name,
        emitted_imports.import_directory,
        emitted_imports.iat_directory,
        reloc_id.is_some() && !reloc_data.is_empty(),
        export_directory
            .as_ref()
            .map(|directory| (directory.rva, directory.size)),
        resource_directory,
        exception_directory,
        None,
        debug_directory,
        load_config_directory,
    );
    if let Some(id) = debug_id {
        let placement = &layout.placements[&id];
        let file_offset = placement.file_offset.unwrap();
        let start = usize::try_from(file_offset).context("debug file offset exceeds usize")?;
        let payload_start = start + linker_utils::pe_debug::IMAGE_DEBUG_DIRECTORY_SIZE;
        let payload_end = payload_start + linker_utils::pe_debug::REPRO_BUILD_ID_SIZE;
        let excluded_build_id = payload_start..payload_end;
        let build_id = linker_utils::pe_debug::stable_build_id(
            &image,
            Some(0x80 + 4 + 20 + 64),
            std::slice::from_ref(&excluded_build_id),
        )
        .context("failed to compute reproducible PE build id")?;
        let encoded = linker_utils::pe_debug::encode_debug_directory(
            &[linker_utils::pe_debug::DebugRecord::Repro { build_id }],
            placement.rva,
            file_offset,
        )?;
        image[start..start + encoded.bytes.len()].copy_from_slice(&encoded.bytes);
    }
    Ok(BuiltImage {
        bytes: image,
        exports: export_directory.map_or_else(Vec::new, |directory| directory.exports),
    })
}

fn add_image_base_symbol(definitions: &mut HashMap<Vec<u8>, u64>, image_base: u64) {
    use linker_utils::coff_runtime::LinkerDefinedValue;
    use linker_utils::coff_runtime::linker_defined_symbol;

    // lld-link and link.exe let an ordinary selected definition win. Otherwise
    // the canonical symbol denotes the first byte of the loaded PE image.
    let Some(LinkerDefinedValue::VirtualAddress(address)) =
        linker_defined_symbol("__ImageBase", image_base, &[])
    else {
        unreachable!("the PE runtime policy always defines __ImageBase")
    };
    definitions
        .entry(b"__ImageBase".to_vec())
        .or_insert(address);
}

fn bind_alternate_names(
    definitions: &mut HashMap<Vec<u8>, u64>,
    runtime_resolution: &linker_utils::coff_runtime::RuntimeResolution,
) -> Result<()> {
    // Resolve every chain against the immutable set of real definitions. Alias
    // bindings added earlier in this loop must never become strong definitions.
    let strong = definitions.keys().cloned().collect::<HashSet<_>>();
    for (symbol, _) in runtime_resolution.alternate_names() {
        if strong.contains(symbol.as_bytes()) {
            continue;
        }
        let target = runtime_resolution
            .resolve_alternate_name(symbol, |candidate| strong.contains(candidate.as_bytes()))?;
        if let Some(address) = definitions.get(target.as_bytes()).copied() {
            definitions.insert(symbol.as_bytes().to_vec(), address);
        }
    }
    Ok(())
}

fn canonicalize_exception_directory(
    image: &mut [u8],
    layout: &SectionLayout,
    args: &crate::args::coff::CoffArgs,
) -> Result<Option<(u32, u32)>> {
    let Some(pdata) = layout
        .sections
        .iter()
        .find(|section| section.name == b".pdata")
    else {
        return Ok(None);
    };
    let canonical_pdata_name = merged_name(b".pdata", args)?;
    ensure!(
        canonical_pdata_name == b".pdata",
        "/MERGE of .pdata is not yet supported because the exception directory requires an exact range"
    );
    let xdata_name = merged_name(b".xdata", args)?;
    let xdata_base = xdata_name
        .split(|byte| *byte == b'$')
        .next()
        .unwrap_or(&xdata_name);
    let xdata = layout
        .sections
        .iter()
        .find(|section| section.name == xdata_base)
        .context(".pdata is present but its merged .xdata output section is missing")?;
    let pdata_file = pdata
        .file_offset
        .context(".pdata unexpectedly has no file contents")? as usize;
    let pdata_size = usize::try_from(pdata.virtual_size).context(".pdata size exceeds usize")?;
    let xdata_file = xdata
        .file_offset
        .context(".xdata unexpectedly has no file contents")? as usize;
    let xdata_size = usize::try_from(xdata.virtual_size).context(".xdata size exceeds usize")?;
    let pdata_bytes = image
        .get(pdata_file..pdata_file + pdata_size)
        .context(".pdata lies outside the PE file")?
        .to_vec();
    let xdata_bytes = image
        .get(xdata_file..xdata_file + xdata_size)
        .context(".xdata lies outside the PE file")?;
    let table = linker_utils::pe_unwind::build_amd64_exception_table(
        &pdata_bytes,
        pdata.rva,
        xdata_bytes,
        xdata.rva,
        layout.size_of_image,
    )
    .context("invalid AMD64 exception metadata")?;
    let output = image
        .get_mut(pdata_file..pdata_file + pdata_size)
        .context(".pdata lies outside the PE file")?;
    output.fill(0);
    output[..table.pdata.len()].copy_from_slice(&table.pdata);
    Ok(Some((table.directory.rva, table.directory.size)))
}

fn has_live_defined_symbol(
    objects: &[crate::coff::CoffObject<'_>],
    contributions: &[Contribution],
    name: &[u8],
) -> Result<bool> {
    let locations = source_locations(contributions);
    for (object_index, object) in objects.iter().enumerate() {
        for symbol in object.file().symbols() {
            if symbol.name_bytes()? == name
                && (symbol.is_common()
                    || symbol
                        .section_index()
                        .is_some_and(|section| locations.contains_key(&(object_index, section))))
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn add_load_config_relocation(
    rvas: &mut Vec<u32>,
    load_config_id: Option<ContributionId>,
    layout: &SectionLayout,
) -> Result<()> {
    if let Some(id) = load_config_id {
        rvas.push(
            layout.placements[&id]
                .rva
                .checked_add(LOAD_CONFIG_SECURITY_COOKIE_OFFSET)
                .context("load-config relocation RVA overflow")?,
        );
    }
    Ok(())
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
    if args.guard.control_flow == crate::args::coff::OptSetting::Enabled {
        return Err(error!(
            "explicit /GUARD:CF is not yet supported; refusing to emit incomplete CFG/load-config metadata"
        ));
    }
    let mut output = Vec::new();
    let discarded_comdats = discarded_comdat_sections(objects)?;
    for (object_index, input) in objects.iter().enumerate() {
        for section in input.file().sections() {
            let raw_name = section.name_bytes().context("invalid COFF section name")?;
            let flags = match section.flags() {
                SectionFlags::Coff { characteristics } => characteristics.0,
                _ => 0,
            };
            let class = linker_utils::coff_symbols::classify_section(flags)
                .context("invalid COFF section flags")?;
            if guard_metadata_policy(raw_name, args.guard.control_flow)?
                == GuardMetadataPolicy::Discard
            {
                continue;
            }
            reject_unsupported_metadata_section(raw_name)?;
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

fn reject_unsupported_metadata_section(name: &[u8]) -> Result<()> {
    if name == b".tls" || name.starts_with(b".tls$") {
        return Err(error!(
            "TLS input section `{}` is not yet supported: emitting the TLS directory requires resolver-owned synthetic symbols",
            String::from_utf8_lossy(name)
        ));
    }
    if name.starts_with(b".CRT$XL") {
        return Err(error!(
            "TLS callback section `{}` is not yet supported: callback targets must be resolved before PE TLS emission",
            String::from_utf8_lossy(name)
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuardMetadataPolicy {
    Keep,
    Discard,
}

fn guard_metadata_policy(
    name: &[u8],
    control_flow: crate::args::coff::OptSetting,
) -> Result<GuardMetadataPolicy> {
    let is_guard_metadata = [b".gfids".as_slice(), b".giats", b".gljmp", b".gehcont"]
        .iter()
        .any(|prefix| {
            name == *prefix
                || name
                    .strip_prefix(*prefix)
                    .is_some_and(|tail| tail.starts_with(b"$"))
        });
    if !is_guard_metadata {
        return Ok(GuardMetadataPolicy::Keep);
    }

    match control_flow {
        crate::args::coff::OptSetting::Default | crate::args::coff::OptSetting::Disabled => {
            Ok(GuardMetadataPolicy::Discard)
        }
        crate::args::coff::OptSetting::Enabled => Err(error!(
            "Guard metadata section `{}` is not yet supported; refusing to emit an incomplete load-config directory for explicit /GUARD:CF",
            String::from_utf8_lossy(name)
        )),
    }
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
    use linker_utils::coff_symbols::ComdatCandidate;
    use linker_utils::coff_symbols::ComdatDecision;
    use linker_utils::coff_symbols::ComdatSelection;
    use linker_utils::coff_symbols::select_comdat;

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
                use linker_utils::coff::Amd64RelocationInputs;
                use linker_utils::coff::Amd64RelocationKind;
                use linker_utils::coff::ImageBase;
                use linker_utils::coff::Rva;
                use linker_utils::coff::SectionIndex;
                use linker_utils::coff::apply_amd64_relocation;
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
    if rva == 0 {
        // `__ImageBase` names the PE headers rather than a section. Relocation
        // kinds that use section metadata therefore observe section zero.
        return Ok((0, 0, 0));
    }
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
    entry_name: Option<&str>,
    import_directory: Option<(u32, u32)>,
    iat_directory: Option<(u32, u32)>,
    has_relocs: bool,
    export_directory: Option<(u32, u32)>,
    resource_directory: Option<(u32, u32)>,
    exception_directory: Option<(u32, u32)>,
    tls_directory: Option<(u32, u32)>,
    debug_directory: Option<(u32, u32)>,
    load_config_directory: Option<(u32, u32)>,
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
    put_u16(image, opt + 68, subsystem_value(args, entry_name));
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
    if let Some((rva, size)) = resource_directory {
        put_u32(image, opt + 128, rva);
        put_u32(image, opt + 132, size);
    }
    if let Some((rva, size)) = exception_directory {
        put_u32(image, opt + 136, rva);
        put_u32(image, opt + 140, size);
    }
    if has_relocs {
        set_directory_from_section(image, opt + 152, layout, DataDirectoryKind::BaseRelocation);
    }
    if let Some((rva, size)) = iat_directory {
        put_u32(image, opt + 208, rva);
        put_u32(image, opt + 212, size);
    }
    if let Some((rva, size)) = tls_directory {
        put_u32(image, opt + 184, rva);
        put_u32(image, opt + 188, size);
    }
    if let Some((rva, size)) = debug_directory {
        put_u32(image, opt + 160, rva);
        put_u32(image, opt + 164, size);
    }
    if let Some((rva, size)) = load_config_directory {
        put_u32(image, opt + 200, rva);
        put_u32(image, opt + 204, size);
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

fn subsystem_value(args: &crate::args::coff::CoffArgs, entry_name: Option<&str>) -> u16 {
    use crate::args::coff::Subsystem;
    match args.subsystem.as_ref().map(|s| &s.kind) {
        Some(Subsystem::Windows) => 2,
        Some(Subsystem::Native) => 1,
        Some(Subsystem::Posix) => 7,
        Some(Subsystem::EfiApplication) => 10,
        Some(Subsystem::EfiBootServiceDriver) => 11,
        Some(Subsystem::EfiRuntimeDriver) => 12,
        Some(Subsystem::EfiRom) => 13,
        Some(Subsystem::Console) => 3,
        None if matches!(entry_name, Some("WinMainCRTStartup" | "wWinMainCRTStartup")) => 2,
        None => 3,
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
fn debug_characteristics() -> u32 {
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
    use object::write::Object as WritableObject;
    use object::write::Relocation;
    use object::write::Symbol;
    use object::write::SymbolSection;

    fn directive_object(
        definition: Option<&[u8]>,
        undefined: Option<&[u8]>,
        directives: &[u8],
    ) -> Vec<u8> {
        let mut object = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        if let Some(name) = definition {
            let text = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
            object.append_section_data(text, &[0xc3], 1);
            object.add_symbol(Symbol {
                name: name.to_vec(),
                value: 0,
                size: 1,
                kind: object::SymbolKind::Text,
                scope: object::SymbolScope::Linkage,
                weak: false,
                section: SymbolSection::Section(text),
                flags: object::SymbolFlags::None,
            });
        }
        if let Some(name) = undefined {
            object.add_symbol(Symbol {
                name: name.to_vec(),
                value: 0,
                size: 0,
                kind: object::SymbolKind::Unknown,
                scope: object::SymbolScope::Linkage,
                weak: false,
                section: SymbolSection::Undefined,
                flags: object::SymbolFlags::None,
            });
        }
        if !directives.is_empty() {
            let section = object.add_section(
                Vec::new(),
                b".drectve".to_vec(),
                object::SectionKind::ReadOnlyData,
            );
            object.append_section_data(section, directives, 1);
        }
        object.write().unwrap()
    }

    fn single_member_archive(name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        {
            let mut builder = ar::Builder::new(&mut bytes);
            let header = ar::Header::new(name.to_vec(), data.len() as u64);
            builder.append(&header, data).unwrap();
        }
        bytes
    }

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

    fn security_cookie_object() -> Vec<u8> {
        let mut object = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let data = object.add_section(Vec::new(), b".data".to_vec(), object::SectionKind::Data);
        object.append_section_data(data, &0x2b99_2ddf_a232u64.to_le_bytes(), 8);
        object.add_symbol(Symbol {
            name: b"__security_cookie".to_vec(),
            value: 0,
            size: 8,
            kind: object::SymbolKind::Data,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(data),
            flags: object::SymbolFlags::None,
        });
        object.write().unwrap()
    }

    fn relocation_object(source: &[u8], target: &[u8]) -> Vec<u8> {
        let mut object = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let text = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
        object.append_section_data(text, &[0, 0, 0, 0, 0xc3], 1);
        object.add_symbol(Symbol {
            name: source.to_vec(),
            value: 0,
            size: 5,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(text),
            flags: object::SymbolFlags::None,
        });
        let target = object.add_symbol(Symbol {
            name: target.to_vec(),
            value: 0,
            size: 0,
            kind: object::SymbolKind::Unknown,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Undefined,
            flags: object::SymbolFlags::None,
        });
        object
            .add_relocation(
                text,
                Relocation {
                    offset: 0,
                    symbol: target,
                    addend: 0,
                    flags: object::RelocationFlags::Coff {
                        typ: object::pe::IMAGE_REL_AMD64_REL32,
                    },
                },
            )
            .unwrap();
        object.write().unwrap()
    }

    fn guard_metadata_object() -> Vec<u8> {
        let mut object = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let text = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
        object.append_section_data(text, &[0xc3], 1);
        for name in [
            b".gfids$y".as_slice(),
            b".giats$y",
            b".gljmp$y",
            b".gehcont$y",
        ] {
            let section =
                object.add_section(Vec::new(), name.to_vec(), object::SectionKind::ReadOnlyData);
            object.append_section_data(section, &0u32.to_le_bytes(), 4);
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
    fn alternate_chain_binds_original_relocation_to_fallback_address() {
        let caller = relocation_object(b"caller", b"primary");
        let fallback = directive_object(Some(b"fallback"), None, b"");
        let objects = [
            crate::coff::CoffObject::parse(&caller).unwrap(),
            crate::coff::CoffObject::parse(&fallback).unwrap(),
        ];
        let mut runtime = linker_utils::coff_runtime::RuntimeResolution::new();
        runtime
            .parse_and_apply(
                "/alternatename:primary=middle /alternatename:middle=fallback",
                "caller.obj",
            )
            .unwrap();

        build_image(
            &objects,
            &[],
            &[],
            b"alias.exe",
            Some("caller"),
            &crate::args::coff::CoffArgs::default(),
            PeWriterConfig::default(),
            &[],
            &runtime,
        )
        .unwrap();
    }

    #[test]
    fn alternate_binding_never_overrides_a_strong_definition() {
        let mut definitions = HashMap::from([
            (b"primary".to_vec(), 0x1111),
            (b"fallback".to_vec(), 0x2222),
        ]);
        let mut runtime = linker_utils::coff_runtime::RuntimeResolution::new();
        runtime
            .parse_and_apply("/alternatename:primary=fallback", "directives.obj")
            .unwrap();

        bind_alternate_names(&mut definitions, &runtime).unwrap();

        assert_eq!(definitions[b"primary".as_slice()], 0x1111);
    }

    #[test]
    fn image_base_symbol_resolves_relocation_to_rva_zero() {
        let caller = relocation_object(b"caller", b"__ImageBase");
        let object = crate::coff::CoffObject::parse(&caller).unwrap();
        let implicit_addend = i32::from_le_bytes(
            object
                .file()
                .section_by_name(".text")
                .unwrap()
                .data()
                .unwrap()[..4]
                .try_into()
                .unwrap(),
        );
        let image = build_image(
            &[object],
            &[],
            &[],
            b"image-base.exe",
            Some("caller"),
            &crate::args::coff::CoffArgs::default(),
            PeWriterConfig::default(),
            &[],
            &Default::default(),
        )
        .unwrap();

        let file = object::File::parse(image.bytes.as_slice()).unwrap();
        let text = file.section_by_name(".text").unwrap();
        let displacement = i32::from_le_bytes(text.data().unwrap()[..4].try_into().unwrap());
        assert_eq!(
            i64::try_from(text.address()).unwrap() + 4 + i64::from(displacement)
                - i64::from(implicit_addend),
            i64::try_from(PeWriterConfig::default().image_base).unwrap()
        );
    }

    #[test]
    fn strong_image_base_definition_wins_over_linker_default() {
        let mut definitions = HashMap::from([(b"__ImageBase".to_vec(), 0x1_4000_2000)]);

        add_image_base_symbol(&mut definitions, 0x1_4000_0000);

        assert_eq!(definitions[b"__ImageBase".as_slice()], 0x1_4000_2000);
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
    fn inferred_windows_entry_selects_gui_subsystem() {
        let args = crate::args::coff::CoffArgs::default();
        assert_eq!(subsystem_value(&args, Some("mainCRTStartup")), 3);
        assert_eq!(subsystem_value(&args, Some("WinMainCRTStartup")), 2);
        assert_eq!(subsystem_value(&args, Some("wWinMainCRTStartup")), 2);
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
            &[],
            &Default::default(),
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

    #[test]
    fn discovers_default_libraries_from_extracted_members_to_a_fixpoint() {
        let directory = tempfile::tempdir().unwrap();
        let direct_path = directory.path().join("direct.obj");
        let first_path = directory.path().join("first.lib");
        let second_path = directory.path().join("second.lib");
        std::fs::write(
            &direct_path,
            directive_object(
                None,
                Some(b"first"),
                b" /DEFAULTLIB:first.lib /INCLUDE:first",
            ),
        )
        .unwrap();
        std::fs::write(
            &first_path,
            single_member_archive(
                b"first.obj",
                &directive_object(
                    Some(b"first"),
                    Some(b"second"),
                    b" /DEFAULTLIB:second.lib /FAILIFMISMATCH:RuntimeLibrary=MD",
                ),
            ),
        )
        .unwrap();
        std::fs::write(
            &second_path,
            single_member_archive(
                b"second.obj",
                &directive_object(Some(b"second"), None, b" /FAILIFMISMATCH:RuntimeLibrary=MD"),
            ),
        )
        .unwrap();

        let args = crate::args::coff::CoffArgs {
            no_entry: true,
            is_dll: true,
            lib_search_path: vec![directory.path().into()],
            ..Default::default()
        };
        let fs = crate::fs::OsFileSystem;
        let mut inputs = Vec::new();
        open_input(&fs, &direct_path, &args, &mut inputs, false).unwrap();
        let selected = select_inputs_to_fixpoint(&fs, &args, &mut inputs).unwrap();

        assert_eq!(selected.archive_bytes.len(), 2);
        assert_eq!(selected.objects.len(), 3);
        assert_eq!(
            selected.runtime_resolution.mismatch_value("RuntimeLibrary"),
            Some("MD")
        );
        assert!(
            undefined_symbols(&selected.objects, &selected.roots)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn emits_resources_and_repro_debug_directory_deterministically() {
        use linker_utils::pe_resources::ResourceId;
        use linker_utils::pe_resources::ResourceRecord;

        let args = crate::args::coff::CoffArgs {
            debug: true,
            ..Default::default()
        };
        let resources = [ResourceRecord {
            resource_type: ResourceId::Id(24),
            name: ResourceId::Id(1),
            language: 0x409,
            data_version: 0,
            memory_flags: 0x1030,
            version: 0,
            characteristics: 0,
            data: b"<assembly/>".to_vec(),
        }];
        let build = || {
            build_image(
                &[],
                &[],
                &[],
                b"metadata.exe",
                None,
                &args,
                PeWriterConfig::default(),
                &resources,
                &Default::default(),
            )
            .unwrap()
            .bytes
        };
        let first = build();
        let second = build();
        assert_eq!(first, second);
        assert_ne!(
            u32::from_le_bytes(first[0x118..0x11c].try_into().unwrap()),
            0
        );
        assert_ne!(
            u32::from_le_bytes(first[0x11c..0x120].try_into().unwrap()),
            0
        );
        assert_ne!(
            u32::from_le_bytes(first[0x138..0x13c].try_into().unwrap()),
            0
        );
        assert_eq!(
            u32::from_le_bytes(first[0x13c..0x140].try_into().unwrap()),
            linker_utils::pe_debug::IMAGE_DEBUG_DIRECTORY_SIZE as u32
        );
        let file = object::File::parse(first.as_slice()).unwrap();
        let debug = file.section_by_name(".debug").unwrap();
        let (offset, _) = debug.file_range().unwrap();
        let records = linker_utils::pe_debug::parse_debug_directory(
            &first,
            offset as usize,
            linker_utils::pe_debug::IMAGE_DEBUG_DIRECTORY_SIZE,
        )
        .unwrap();
        assert!(matches!(
            records.as_slice(),
            [linker_utils::pe_debug::DebugRecord::Repro { .. }]
        ));
    }

    #[test]
    fn rejects_tls_metadata_until_resolver_support_exists() {
        assert!(
            reject_unsupported_metadata_section(b".tls$AAA")
                .unwrap_err()
                .to_string()
                .contains("TLS input section")
        );
        assert!(
            reject_unsupported_metadata_section(b".CRT$XLB")
                .unwrap_err()
                .to_string()
                .contains("TLS callback")
        );
    }

    #[test]
    fn default_guard_policy_discards_guard_metadata_only() {
        let bytes = guard_metadata_object();
        let object = crate::coff::CoffObject::parse(&bytes).unwrap();
        let contributions =
            collect_contributions(&[object], &crate::args::coff::CoffArgs::default()).unwrap();
        assert_eq!(
            contributions
                .iter()
                .map(|contribution| contribution.spec.name.as_slice())
                .collect::<Vec<_>>(),
            [b".text".as_slice()]
        );
    }

    #[test]
    fn disabled_guard_policy_discards_guard_metadata_only() {
        let bytes = guard_metadata_object();
        let object = crate::coff::CoffObject::parse(&bytes).unwrap();
        let args = crate::args::coff::CoffArgs {
            guard: crate::args::coff::GuardOptions {
                control_flow: crate::args::coff::OptSetting::Disabled,
                no_long_jump: false,
            },
            ..Default::default()
        };
        let contributions = collect_contributions(&[object], &args).unwrap();
        assert_eq!(
            contributions
                .iter()
                .map(|contribution| contribution.spec.name.as_slice())
                .collect::<Vec<_>>(),
            [b".text".as_slice()]
        );
    }

    #[test]
    fn enabled_guard_policy_refuses_to_silently_weaken_cfg() {
        let bytes = guard_metadata_object();
        let object = crate::coff::CoffObject::parse(&bytes).unwrap();
        let args = crate::args::coff::CoffArgs {
            guard: crate::args::coff::GuardOptions {
                control_flow: crate::args::coff::OptSetting::Enabled,
                no_long_jump: false,
            },
            ..Default::default()
        };
        let error = collect_contributions(&[object], &args).unwrap_err();
        assert!(error.to_string().contains("explicit /GUARD:CF"));
    }

    #[test]
    fn emits_security_cookie_load_config_and_relocation() {
        let bytes = security_cookie_object();
        let object = crate::coff::CoffObject::parse(&bytes).unwrap();
        let image = build_image(
            &[object],
            &[],
            &[],
            b"cookie.exe",
            None,
            &crate::args::coff::CoffArgs::default(),
            PeWriterConfig::default(),
            &[],
            &Default::default(),
        )
        .unwrap()
        .bytes;
        let directory_rva = u32::from_le_bytes(image[0x160..0x164].try_into().unwrap());
        assert_ne!(directory_rva, 0);
        assert_eq!(
            u32::from_le_bytes(image[0x164..0x168].try_into().unwrap()),
            linker_utils::pe_load_config::IMAGE_LOAD_CONFIG_DIRECTORY64_COMPAT_SIZE
        );
        assert_ne!(
            u32::from_le_bytes(image[0x130..0x134].try_into().unwrap()),
            0
        );
        let file = object::File::parse(image.as_slice()).unwrap();
        let section = file.section_by_name(".loadcfg").unwrap();
        let parsed = linker_utils::pe_load_config::parse_pe_load_config64(
            section.data().unwrap(),
            directory_rva,
            PeWriterConfig::default().image_base,
            u32::from_le_bytes(image[0xd0..0xd4].try_into().unwrap()),
        )
        .unwrap();
        assert!(parsed.security_cookie_rva.is_some());
    }

    #[test]
    fn validates_and_publishes_exact_exception_directory() {
        use linker_utils::pe_sections::OutputSection;
        use linker_utils::pe_sections::SectionLayout;

        let mut image = vec![0; 0x600];
        image[0x200..0x204].copy_from_slice(&[1, 0, 0, 0]);
        let pdata = [0x1000u32, 0x1010, 0x2000]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        image[0x400..0x40c].copy_from_slice(&pdata);
        let layout = SectionLayout {
            sections: vec![
                OutputSection {
                    name: b".rdata".to_vec(),
                    characteristics: readonly_data_characteristics(),
                    rva: 0x2000,
                    virtual_size: 4,
                    file_offset: Some(0x200),
                    raw_size: 0x200,
                    contributions: Vec::new(),
                },
                OutputSection {
                    name: b".pdata".to_vec(),
                    characteristics: readonly_data_characteristics(),
                    rva: 0x3000,
                    virtual_size: 12,
                    file_offset: Some(0x400),
                    raw_size: 0x200,
                    contributions: Vec::new(),
                },
            ],
            placements: BTreeMap::new(),
            file_size: 0x600,
            size_of_image: 0x4000,
        };
        assert_eq!(
            canonicalize_exception_directory(
                &mut image,
                &layout,
                &crate::args::coff::CoffArgs::default()
            )
            .unwrap(),
            Some((0x3000, 12))
        );
    }
}
