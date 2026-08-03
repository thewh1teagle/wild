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

    let definition = load_definition_file(fs, args)?;

    let mut requested = Vec::new();
    for input in &args.common.inputs {
        match &input.spec {
            crate::args::InputSpec::File(path) => requested.push(path.to_path_buf()),
            _ => return Err(error!("unsupported COFF library input form")),
        }
    }

    let mut inputs = Vec::new();
    // The arena owns every opened input until linking finishes. Its stable allocations let the
    // resolver retain borrowed COFF/archive views while later default-library waves are appended.
    let input_storage = colosseum::sync::Arena::new();
    for request in requested {
        open_input(fs, &request, args, &input_storage, &mut inputs, false)?;
    }
    let selected =
        select_inputs_to_fixpoint(fs, args, &definition.exports, &input_storage, &mut inputs)?;
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
    let dll_name = if let Some(name) = definition.module_name.as_deref() {
        name
    } else {
        args.common
            .output
            .file_name()
            .and_then(|name| name.to_str())
            .context("PE output file name is not valid UTF-8")?
    };
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

#[derive(Debug)]
struct LoadedDefinitionFile {
    exports: Vec<crate::args::coff::ExportSpec>,
    module_name: Option<String>,
}

fn load_definition_file<F: FileSystem>(
    fs: &F,
    args: &crate::args::coff::CoffArgs,
) -> Result<LoadedDefinitionFile> {
    let mut exports = args.exports.clone();
    let mut module_name = None;
    for path in &args.definition_files {
        let (input, _) = fs
            .open_input(path, args.common.prepopulate_maps)
            .with_context(|| {
                format!("failed to open module-definition file `{}`", path.display())
            })?;
        let text = std::str::from_utf8(input.bytes())
            .with_context(|| format!("module-definition file `{}` is not UTF-8", path.display()))?;
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let definition =
            linker_utils::coff_def::parse_definition_file(text).with_context(|| {
                format!("while parsing module-definition file `{}`", path.display())
            })?;
        if let Some(image) = definition.image {
            ensure!(
                image.kind == linker_utils::coff_def::ImageKind::Library,
                "NAME directives in module-definition files are not supported"
            );
            ensure!(
                args.is_dll,
                "a LIBRARY module-definition file requires /DLL"
            );
            ensure!(
                image.base.is_none(),
                "LIBRARY BASE in module-definition files is not supported; use /BASE instead"
            );
            module_name = image.name;
        }
        ensure!(
            definition.heap_size.is_none(),
            "HEAPSIZE in module-definition files is not supported; use /HEAP instead"
        );
        ensure!(
            definition.stack_size.is_none(),
            "STACKSIZE in module-definition files is not supported; use /STACK instead"
        );
        ensure!(
            definition.version.is_none(),
            "VERSION in module-definition files is not supported; use /VERSION instead"
        );
        ensure!(
            definition.sections.is_empty(),
            "SECTIONS/SEGMENTS in module-definition files are not supported; use /SECTION instead"
        );
        for export in definition.exports {
            let target = export.target.unwrap_or_else(|| export.name.clone());
            merge_export(
                &mut exports,
                crate::args::coff::ExportSpec {
                    name: export.name,
                    target,
                    ordinal: export.ordinal,
                    noname: export.flags.noname,
                    data: export.flags.data,
                    private: export.flags.private,
                },
                &format!("module-definition file `{}`", path.display()),
            )?;
        }
    }
    Ok(LoadedDefinitionFile {
        exports,
        module_name,
    })
}

fn merge_export(
    exports: &mut Vec<crate::args::coff::ExportSpec>,
    candidate: crate::args::coff::ExportSpec,
    source: &str,
) -> Result<()> {
    if let Some(existing) = exports.iter().find(|export| export.name == candidate.name) {
        ensure!(
            existing == &candidate,
            "conflicting export `{}` in {source}",
            candidate.name
        );
        return Ok(());
    }
    if let Some(ordinal) = candidate.ordinal
        && let Some(existing) = exports
            .iter()
            .find(|export| export.ordinal == Some(ordinal))
    {
        ensure!(
            existing.target == candidate.target && existing.data == candidate.data,
            "export ordinal {ordinal} in {source} conflicts with export `{}`",
            existing.name
        );
    }
    exports.push(candidate);
    Ok(())
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
    #[cfg(test)]
    resolver_object_scans: usize,
}

type OpenedInput<'data, F> = (PathBuf, &'data <F as FileSystem>::Input, bool);

fn select_inputs_to_fixpoint<'data, F: FileSystem>(
    fs: &F,
    args: &crate::args::coff::CoffArgs,
    command_exports: &[crate::args::coff::ExportSpec],
    input_storage: &'data colosseum::sync::Arena<F::Input>,
    inputs: &mut Vec<OpenedInput<'data, F>>,
) -> Result<SelectedInputs<'data>> {
    crate::timing_phase!("Select PE inputs");
    let mut no_default_libraries = args.no_default_libraries;
    let mut excluded_default_libraries = args.excluded_default_libraries.clone();
    let mut selection = select_opened_inputs::<F>(
        args,
        command_exports,
        inputs,
        no_default_libraries,
        &excluded_default_libraries,
    )?;
    loop {
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
        if old_policy != (no_default_libraries, excluded_default_libraries.len()) {
            // Policy changes can remove previously active default libraries, so only this
            // non-monotonic case invalidates the incremental resolver cache.
            selection = select_opened_inputs::<F>(
                args,
                command_exports,
                inputs,
                no_default_libraries,
                &excluded_default_libraries,
            )?;
            continue;
        }

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
            if disallowed.iter().any(|name| path_matches(path, name)) {
                return Err(error!(
                    "COFF library `{}` is forbidden by /DISALLOWLIB",
                    path.display()
                ));
            }
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

        let missing = libraries
            .into_iter()
            .filter(|library| {
                !inputs
                    .iter()
                    .any(|(path, _, _)| path_matches(path, library))
            })
            .collect::<Vec<_>>();
        if missing.is_empty() {
            return Ok(selection.finish());
        }

        let old_len = inputs.len();
        for library in missing {
            open_input(fs, Path::new(&library), args, input_storage, inputs, true)?;
        }
        ensure!(
            inputs.len() != old_len,
            "default-library discovery made no progress"
        );
        selection.extend::<F>(args, command_exports, &inputs[old_len..])?;
    }
}

struct OpenSelection<'data> {
    objects: Vec<crate::coff::CoffObject<'data>>,
    direct_object_indices: Vec<usize>,
    resources: Vec<ResourceRecord>,
    archive_bytes: Vec<&'data [u8]>,
    entry_name: Option<String>,
    exports: Vec<crate::args::coff::ExportSpec>,
    roots: Vec<Vec<u8>>,
    directives: crate::args::coff::CoffArgs,
    archive_definitions: BTreeSet<Vec<u8>>,
    resolver: pe_resolver::ResolverSession<'data>,
}

impl<'data> OpenSelection<'data> {
    fn finish(self) -> SelectedInputs<'data> {
        #[cfg(test)]
        let resolver_object_scans = self.resolver.object_scan_count();
        SelectedInputs {
            objects: self.objects,
            resources: self.resources,
            archive_bytes: self.archive_bytes,
            entry_name: self.entry_name,
            exports: self.exports,
            roots: self.roots,
            runtime_resolution: self.directives.runtime_resolution,
            archive_definitions: self.archive_definitions,
            #[cfg(test)]
            resolver_object_scans,
        }
    }

    fn extend<F: FileSystem>(
        &mut self,
        args: &crate::args::coff::CoffArgs,
        command_exports: &[crate::args::coff::ExportSpec],
        inputs: &[OpenedInput<'data, F>],
    ) -> Result<()> {
        add_opened_inputs::<F>(args, inputs, self)?;
        resolve_open_selection(args, command_exports, self)
    }
}

fn select_opened_inputs<'data, F: FileSystem>(
    args: &crate::args::coff::CoffArgs,
    command_exports: &[crate::args::coff::ExportSpec],
    inputs: &[OpenedInput<'data, F>],
    no_default_libraries: bool,
    excluded_default_libraries: &[String],
) -> Result<OpenSelection<'data>> {
    let mut selection = OpenSelection {
        objects: Vec::new(),
        direct_object_indices: Vec::new(),
        resources: Vec::new(),
        archive_bytes: Vec::new(),
        entry_name: None,
        exports: Vec::new(),
        roots: Vec::new(),
        directives: Default::default(),
        archive_definitions: BTreeSet::new(),
        resolver: pe_resolver::ResolverSession::new(),
    };
    let active = inputs.iter().filter(|(path, _, is_default)| {
        !*is_default
            || (!no_default_libraries
                && !excluded_default_libraries
                    .iter()
                    .any(|name| path_matches(path, name)))
    });
    let active = active.cloned().collect::<Vec<_>>();
    add_opened_inputs::<F>(args, &active, &mut selection)?;
    resolve_open_selection(args, command_exports, &mut selection)?;
    Ok(selection)
}

fn add_opened_inputs<'data, F: FileSystem>(
    args: &crate::args::coff::CoffArgs,
    inputs: &[OpenedInput<'data, F>],
    selection: &mut OpenSelection<'data>,
) -> Result<()> {
    for (path, data, _is_default) in inputs {
        match object::FileKind::parse(data.bytes()) {
            Ok(object::FileKind::Coff | object::FileKind::CoffBig) => {
                selection
                    .direct_object_indices
                    .push(selection.objects.len());
                selection.objects.push(
                    crate::coff::CoffObject::parse(data.bytes())
                        .with_context(|| format!("while reading `{}`", path.display()))?,
                );
            }
            Ok(object::FileKind::Archive) => {
                let whole_archive = args.whole_archive
                    || args
                        .whole_archive_libraries
                        .iter()
                        .any(|name| path_matches(path, name));
                selection.archive_bytes.push(data.bytes());
                selection
                    .resolver
                    .add_archive(data.bytes(), whole_archive)?;
            }
            Ok(kind) => {
                return Err(error!(
                    "unsupported PE input kind {kind:?} in `{}`",
                    path.display()
                ));
            }
            Err(_error)
                if path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("res"))
                    || linker_utils::pe_resources::has_res_null_header(data.bytes()) =>
            {
                selection.resources.extend(
                    linker_utils::pe_resources::parse_res(data.bytes())
                        .with_context(|| format!("while reading resource `{}`", path.display()))?,
                );
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("cannot identify COFF input `{}`", path.display()));
            }
        }
    }
    Ok(())
}

fn resolve_open_selection(
    args: &crate::args::coff::CoffArgs,
    command_exports: &[crate::args::coff::ExportSpec],
    selection: &mut OpenSelection<'_>,
) -> Result<()> {
    crate::verbose_timing_phase!("Resolve PE archives");
    selection.entry_name = pe_entry::select_from_objects(
        args,
        selection
            .direct_object_indices
            .iter()
            .map(|&index| &selection.objects[index]),
    )?;
    loop {
        let mut directives = directive_args(args, &selection.objects)?;
        let mut exports = command_exports.to_vec();
        for export in &directives.exports {
            merge_export(
                &mut exports,
                export.clone(),
                "selected COFF .drectve section",
            )?;
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
        if let Some(entry) = selection.entry_name.as_deref() {
            roots.push(entry.as_bytes().to_vec());
        }
        roots.extend(
            exports
                .iter()
                .filter(|export| !looks_like_forwarder(export))
                .map(|export| export.target.as_bytes().to_vec()),
        );
        roots.sort();
        roots.dedup();

        let old_len = selection.objects.len();
        let archive_definitions = selection.resolver.resolve(
            &mut selection.objects,
            &roots,
            &mut directives.runtime_resolution,
        )?;
        if selection.objects.len() == old_len {
            selection.exports = exports;
            selection.roots = roots;
            selection.directives = directives;
            selection.archive_definitions = archive_definitions;
            return Ok(());
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

fn open_input<'data, F: FileSystem>(
    fs: &F,
    request: &Path,
    args: &crate::args::coff::CoffArgs,
    input_storage: &'data colosseum::sync::Arena<F::Input>,
    inputs: &mut Vec<OpenedInput<'data, F>>,
    is_default: bool,
) -> Result<()> {
    let path = find_input(fs, request, args)?;
    if inputs.iter().any(|(existing, _, _)| existing == &path) {
        return Ok(());
    }
    let (data, _) = fs
        .open_input(&path, args.common.prepopulate_maps)
        .with_context(|| format!("Failed to open COFF input `{}`", path.display()))?;
    inputs.push((path, input_storage.alloc(data), is_default));
    Ok(())
}

fn find_input<F: FileSystem>(
    fs: &F,
    requested: &Path,
    args: &crate::args::coff::CoffArgs,
) -> Result<PathBuf> {
    let implicit_name = implicit_library_name(requested);
    if matches!(fs.file_type(requested), Ok(crate::fs::FileType::File)) {
        return Ok(requested.to_path_buf());
    }
    if let Some(implicit_name) = &implicit_name
        && matches!(fs.file_type(implicit_name), Ok(crate::fs::FileType::File))
    {
        return Ok(implicit_name.clone());
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
        if let Some(implicit_name) = &implicit_name {
            let candidate = directory.join(implicit_name);
            if matches!(fs.file_type(&candidate), Ok(crate::fs::FileType::File)) {
                return Ok(candidate);
            }
        }
    }
    Err(error!("cannot find COFF input `{}`", requested.display()))
}

fn implicit_library_name(requested: &Path) -> Option<PathBuf> {
    let text = requested.to_str()?;
    if requested.extension().is_some() || text.contains('/') || text.contains('\\') {
        return None;
    }
    let mut name = requested.to_path_buf();
    name.set_extension("lib");
    Some(name)
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
            if symbol.is_undefined() && !symbol.is_common() && !symbol.is_weak() {
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
    let mut undefined = undefined
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
        .collect::<Result<HashSet<_>>>()?;
    let weak = weak_external_resolution(objects)?;
    for (symbol, _, _) in weak.records() {
        if object_definitions.contains(symbol) {
            continue;
        }
        if archive_definitions.contains(symbol) {
            undefined.insert(symbol.to_vec());
            continue;
        }
        let target = weak.resolve(symbol, |candidate| {
            object_definitions.contains(candidate) || archive_definitions.contains(candidate)
        })?;
        if !object_definitions.contains(target) {
            undefined.insert(target.to_vec());
        }
    }
    Ok(undefined)
}

fn weak_external_resolution(
    objects: &[crate::coff::CoffObject<'_>],
) -> Result<linker_utils::coff_runtime::WeakExternalResolution> {
    let mut resolution = linker_utils::coff_runtime::WeakExternalResolution::default();
    for (index, object) in objects.iter().enumerate() {
        for record in linker_utils::coff_runtime::parse_weak_externals(object.bytes())? {
            resolution.apply(record, &format!("selected COFF object #{index}"))?;
        }
    }
    Ok(resolution)
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
    let (mut contributions, comdat_redirects) = collect_contributions(objects, args)?;
    let has_tls_inputs = has_tls_contributions(objects, &contributions)?;
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
    bind_weak_externals(objects, &mut definitions)?;
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
                        &comdat_redirects,
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
                    &comdat_redirects,
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
        &comdat_redirects,
        &definitions,
        config.image_base,
        &mut image,
    )?;
    let tls_directory = prepare_tls_directory(
        objects,
        &contributions,
        &layout,
        &definitions,
        config.image_base,
        dynamic_base,
        has_tls_inputs,
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
        tls_directory,
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

fn bind_weak_externals(
    objects: &[crate::coff::CoffObject<'_>],
    definitions: &mut HashMap<Vec<u8>, u64>,
) -> Result<()> {
    let weak = weak_external_resolution(objects)?;
    let strong = definitions.keys().cloned().collect::<HashSet<_>>();
    for (symbol, _, _) in weak.records() {
        if strong.contains(symbol) {
            continue;
        }
        let target = weak.resolve(symbol, |candidate| strong.contains(candidate))?;
        if let Some(address) = definitions.get(target).copied() {
            definitions.insert(symbol.to_vec(), address);
        }
    }
    Ok(())
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
    redirects: &SectionRedirects,
    layout: &SectionLayout,
    definitions: &HashMap<Vec<u8>, u64>,
    image_base: u64,
) -> Result<ExportTarget<'a>> {
    if looks_like_forwarder(export) {
        return Ok(ExportTarget::Forwarder(export.target.as_bytes()));
    }
    let name = export.target.as_bytes();
    let address = if let Some(address) = definitions.get(name).copied() {
        Some(address)
    } else {
        find_local_symbol(objects, locations, redirects, layout, name, image_base)?
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
    Err(error!(
        "export `{}` targets undefined symbol `{}`",
        export.name, export.target
    ))
}

fn collect_contributions(
    objects: &[crate::coff::CoffObject<'_>],
    args: &crate::args::coff::CoffArgs,
) -> Result<(Vec<Contribution>, SectionRedirects)> {
    if args.guard.control_flow == crate::args::coff::OptSetting::Enabled {
        return Err(error!(
            "explicit /GUARD:CF is not yet supported; refusing to emit incomplete CFG/load-config metadata"
        ));
    }
    let mut output = Vec::new();
    let comdats = discarded_comdat_sections(objects)?;
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
            if class.discardable
                || flags & object::pe::IMAGE_SCN_LNK_REMOVE.0 != 0
                || matches!(
                    class.contents,
                    linker_utils::coff_symbols::SectionContents::Metadata
                )
            {
                continue;
            }
            if comdats.discarded.contains(&(object_index, section.index())) {
                continue;
            }
            let name = merged_name(raw_name, args)?;
            let size = u32::try_from(section.size()).context("COFF section too large")?;
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
    // lld-link gives an empty input contribution a boundary location only when its merged
    // output section exists for some non-empty input. Entirely empty groups are omitted.
    let non_empty_groups = output
        .iter()
        .filter(|contribution| contribution.spec.size != 0)
        .map(|contribution| {
            contribution
                .spec
                .name
                .split(|byte| *byte == b'$')
                .next()
                .unwrap()
                .to_vec()
        })
        .collect::<HashSet<_>>();
    output.retain(|contribution| {
        contribution.spec.size != 0
            || non_empty_groups.contains(
                contribution
                    .spec
                    .name
                    .split(|byte| *byte == b'$')
                    .next()
                    .unwrap(),
            )
    });
    // Filtering an entirely empty output group can leave gaps in the IDs assigned above.
    // Synthetic contributions use the retained length for their IDs, so compact the live
    // object contributions before any synthetic sections are appended.
    for (index, contribution) in output.iter_mut().enumerate() {
        contribution.spec.id = ContributionId(index as u32);
    }
    Ok((output, comdats.redirects))
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
    primary: object::SectionIndex,
    sections: Vec<object::SectionIndex>,
    parents: HashMap<object::SectionIndex, Option<object::SectionIndex>>,
    selection: linker_utils::coff_symbols::ComdatSelection,
    timestamp: u32,
}

fn coff_timestamp(file: &object::File<'_>) -> u32 {
    match file {
        object::File::Coff(file) => file.coff_header().time_date_stamp.get(object::LittleEndian),
        object::File::CoffBig(file) => file.coff_header().time_date_stamp.get(object::LittleEndian),
        _ => 0,
    }
}

#[derive(Debug)]
struct CachedComdatGroup {
    sections: Vec<object::SectionIndex>,
    parents: HashMap<object::SectionIndex, Option<object::SectionIndex>>,
}

fn raw_comdat_sections<'data, Coff: object::read::coff::CoffHeader>(
    file: &object::read::coff::CoffFile<'data, &'data [u8], Coff>,
) -> Result<HashMap<object::SectionIndex, CachedComdatGroup>> {
    use object::read::coff::Symbol as _;

    let symbols = file.coff_symbol_table();
    let mut groups = HashMap::<object::SectionIndex, CachedComdatGroup>::new();
    let mut associations = Vec::<(object::SectionIndex, object::SectionIndex)>::new();
    let mut parent_by_child = HashMap::<object::SectionIndex, object::SectionIndex>::new();
    for (index, symbol) in symbols.iter() {
        if !symbol.has_aux_section() {
            continue;
        }
        let aux = symbols
            .aux_section(index)
            .context("invalid COFF section-definition symbol")?;
        if aux.selection == object::pe::ComdatSelection(0) {
            continue;
        }
        let section = symbol
            .section()
            .context("COMDAT has an invalid section number")?;
        if aux.selection == object::pe::IMAGE_COMDAT_SELECT_ASSOCIATIVE {
            let parent = u32::from(aux.number.get(object::LittleEndian))
                | if Coff::is_type_bigobj() {
                    u32::from(aux.high_number.get(object::LittleEndian)) << 16
                } else {
                    0
                };
            ensure!(parent != 0, "associative COMDAT has no parent section");
            let parent = object::SectionIndex(parent as usize);
            ensure!(
                parent_by_child.insert(section, parent).is_none(),
                "COMDAT section has multiple associative parents"
            );
            associations.push((section, parent));
        } else {
            groups.entry(section).or_insert_with(|| CachedComdatGroup {
                sections: vec![section],
                parents: HashMap::from([(section, None)]),
            });
        }
    }
    // Associative groups may be nested. Resolve each child to the ultimate non-associative
    // leader while retaining symbol-table order, matching object's iterator semantics.
    for (child, mut parent) in associations.iter().copied() {
        let mut depth = 0;
        while let Some(next) = parent_by_child.get(&parent) {
            parent = *next;
            depth += 1;
            ensure!(
                depth <= associations.len(),
                "cycle in associative COMDAT parent chain"
            );
        }
        let sections = groups
            .get_mut(&parent)
            .context("associative COMDAT refers to a missing parent")?;
        sections.sections.push(child);
        sections
            .parents
            .insert(child, Some(parent_by_child[&child]));
    }
    Ok(groups)
}

fn cached_comdat_sections(
    file: &object::File<'_>,
) -> Result<HashMap<object::SectionIndex, CachedComdatGroup>> {
    match file {
        object::File::Coff(file) => raw_comdat_sections(file),
        object::File::CoffBig(file) => raw_comdat_sections(file),
        _ => Ok(HashMap::new()),
    }
}

fn section_is_comdat(file: &object::File<'_>, index: object::SectionIndex) -> bool {
    file.section_by_index(index)
        .ok()
        .is_some_and(|section| match section.flags() {
            SectionFlags::Coff { characteristics } => {
                characteristics.0 & object::pe::IMAGE_SCN_LNK_COMDAT.0 != 0
            }
            _ => false,
        })
}

type ObjectSectionKey = (usize, object::SectionIndex);
type SectionRedirects = HashMap<ObjectSectionKey, ObjectSectionKey>;

#[derive(Debug, Default)]
struct ComdatResolution {
    discarded: HashSet<ObjectSectionKey>,
    redirects: SectionRedirects,
}

fn record_comdat_redirects(
    objects: &[crate::coff::CoffObject<'_>],
    loser_object: usize,
    loser_sections: &[object::SectionIndex],
    loser_parents: &HashMap<object::SectionIndex, Option<object::SectionIndex>>,
    winner_object: usize,
    winner_sections: &[object::SectionIndex],
    winner_parents: &HashMap<object::SectionIndex, Option<object::SectionIndex>>,
    redirects: &mut SectionRedirects,
) -> Result<()> {
    let Some((&loser_primary, loser_children)) = loser_sections.split_first() else {
        return Ok(());
    };
    let Some((&winner_primary, winner_children)) = winner_sections.split_first() else {
        return Ok(());
    };
    redirects.insert(
        (loser_object, loser_primary),
        (winner_object, winner_primary),
    );

    // Match children by both section name and direct association parent. This preserves nested
    // association topology even when two objects order same-named children differently.
    let mut winner_used = vec![false; winner_children.len()];
    let mut pending = loser_children.to_vec();
    while !pending.is_empty() {
        let before = pending.len();
        pending.retain(|loser| {
            let Some(Some(loser_parent)) = loser_parents.get(loser) else {
                return false;
            };
            let Some(&(mapped_parent_object, mapped_parent)) =
                redirects.get(&(loser_object, *loser_parent))
            else {
                return true;
            };
            if mapped_parent_object != winner_object {
                return true;
            }
            let loser_name = objects[loser_object]
                .file()
                .section_by_index(*loser)
                .ok()
                .and_then(|section| section.name_bytes().ok());
            let Some((position, winner)) =
                winner_children
                    .iter()
                    .enumerate()
                    .find(|(position, winner)| {
                        !winner_used[*position]
                            && winner_parents.get(winner) == Some(&Some(mapped_parent))
                            && objects[winner_object]
                                .file()
                                .section_by_index(**winner)
                                .ok()
                                .and_then(|section| section.name_bytes().ok())
                                == loser_name
                    })
            else {
                return false;
            };
            winner_used[position] = true;
            redirects.insert((loser_object, *loser), (winner_object, *winner));
            false
        });
        if pending.len() == before {
            break;
        }
    }
    ensure!(
        pending.is_empty() && winner_used.iter().all(|used| *used),
        "duplicate COMDAT associative structures do not match"
    );
    Ok(())
}

fn discarded_comdat_sections(objects: &[crate::coff::CoffObject<'_>]) -> Result<ComdatResolution> {
    use linker_utils::coff_symbols::ComdatCandidate;
    use linker_utils::coff_symbols::ComdatDecision;
    use linker_utils::coff_symbols::ComdatSelection;
    use linker_utils::coff_symbols::select_comdat;

    let mut strong_definitions = HashSet::<Vec<u8>>::new();
    for input in objects {
        for symbol in input.file().symbols() {
            if !symbol.is_global() || !symbol.is_definition() {
                continue;
            }
            if symbol
                .section_index()
                .is_some_and(|section| section_is_comdat(input.file(), section))
            {
                continue;
            }
            strong_definitions.insert(symbol.name_bytes()?.to_vec());
        }
    }

    let mut selected = HashMap::<Vec<u8>, SelectedComdat>::new();
    let mut resolution = ComdatResolution::default();
    for (object_index, input) in objects.iter().enumerate() {
        let timestamp = coff_timestamp(input.file());
        let mut section_groups = cached_comdat_sections(input.file())?;
        for comdat in input.file().comdats() {
            let leader = input
                .file()
                .symbol_by_index(comdat.symbol())
                .context("invalid COFF COMDAT leader")?;
            let primary = leader
                .section_index()
                .context("COMDAT leader has no section")?;
            // A static COMDAT leader has object-local identity. Rust intentionally emits the
            // same local NODUPLICATES name in several codegen units; link.exe and lld-link keep
            // each instance because none participates in global symbol resolution.
            if !leader.is_global() {
                section_groups.remove(&primary);
                continue;
            }
            let name = comdat
                .name_bytes()
                .context("invalid COFF COMDAT name")?
                .to_vec();
            // Cache this mapping with one symbol-table pass. object's per-COMDAT iterator scans
            // the complete symbol table to find associative children, which is quadratic for
            // compiler output containing thousands of COMDATs.
            let group = section_groups
                .remove(&primary)
                .unwrap_or_else(|| CachedComdatGroup {
                    sections: vec![primary],
                    parents: HashMap::from([(primary, None)]),
                });
            let sections = group.sections;
            let parents = group.parents;
            if strong_definitions.contains(&name) {
                resolution
                    .discarded
                    .extend(sections.iter().map(|section| (object_index, *section)));
                continue;
            }
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
                ensure!(
                    existing.selection == selection,
                    "COMDAT `{}` has conflicting selection kinds {:?} and {:?}",
                    String::from_utf8_lossy(&name),
                    existing.selection,
                    selection
                );
                // ANY is overwhelmingly common in compiler output. Do not read or clone COMDAT
                // payloads (and especially do not format relocation tables) unless the selection
                // policy actually compares them.
                let (existing_contents, contents) = match selection {
                    ComdatSelection::SameSize
                    | ComdatSelection::ExactMatch
                    | ComdatSelection::Largest => {
                        let existing_section = objects[existing.object]
                            .file()
                            .section_by_index(existing.primary)
                            .context("invalid selected primary COMDAT section")?;
                        let section = input
                            .file()
                            .section_by_index(primary)
                            .context("invalid primary COMDAT section")?;
                        (
                            existing_section
                                .data()
                                .context("invalid selected COMDAT contents")?,
                            section.data().context("invalid COMDAT contents")?,
                        )
                    }
                    _ => (&[][..], &[][..]),
                };
                let (existing_relocation_signature, relocation_signature) =
                    if selection == ComdatSelection::ExactMatch {
                        let existing_section = objects[existing.object]
                            .file()
                            .section_by_index(existing.primary)
                            .context("invalid selected primary COMDAT section")?;
                        let section = input
                            .file()
                            .section_by_index(primary)
                            .context("invalid primary COMDAT section")?;
                        (
                            format!("{:?}", existing_section.relocations().collect::<Vec<_>>())
                                .into_bytes(),
                            format!("{:?}", section.relocations().collect::<Vec<_>>()).into_bytes(),
                        )
                    } else {
                        (Vec::new(), Vec::new())
                    };
                let decision = select_comdat(
                    selection,
                    ComdatCandidate {
                        contents: existing_contents,
                        relocation_signature: &existing_relocation_signature,
                        timestamp: existing.timestamp,
                    },
                    ComdatCandidate {
                        contents,
                        relocation_signature: &relocation_signature,
                        timestamp,
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
                        resolution
                            .discarded
                            .extend(sections.iter().map(|section| (object_index, *section)));
                        record_comdat_redirects(
                            objects,
                            object_index,
                            &sections,
                            &parents,
                            existing.object,
                            &existing.sections,
                            &existing.parents,
                            &mut resolution.redirects,
                        )?;
                    }
                    ComdatDecision::ReplaceExisting => {
                        resolution.discarded.extend(
                            existing
                                .sections
                                .iter()
                                .map(|section| (existing.object, *section)),
                        );
                        record_comdat_redirects(
                            objects,
                            existing.object,
                            &existing.sections,
                            &existing.parents,
                            object_index,
                            &sections,
                            &parents,
                            &mut resolution.redirects,
                        )?;
                        selected.insert(
                            name,
                            SelectedComdat {
                                object: object_index,
                                primary,
                                sections,
                                parents,
                                selection,
                                timestamp,
                            },
                        );
                    }
                }
            } else {
                selected.insert(
                    name,
                    SelectedComdat {
                        object: object_index,
                        primary,
                        sections,
                        parents,
                        selection,
                        timestamp,
                    },
                );
            }
        }
        ensure!(
            section_groups.is_empty(),
            "COFF COMDAT section groups were not matched to leaders"
        );
    }
    Ok(resolution)
}

fn merged_name(input: &[u8], args: &crate::args::coff::CoffArgs) -> Result<Vec<u8>> {
    let separator = input.iter().position(|byte| *byte == b'$');
    let (base, suffix) = separator.map_or((input, &[][..]), |at| (&input[..at], &input[at + 1..]));
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
    if separator.is_none() {
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

fn redirected_location(
    locations: &LocationMap,
    redirects: &SectionRedirects,
    mut section: ObjectSectionKey,
) -> Result<Option<(ObjectSectionKey, ContributionId)>> {
    for _ in 0..=redirects.len() {
        if let Some(id) = locations.get(&section) {
            return Ok(Some((section, *id)));
        }
        let Some(next) = redirects.get(&section) else {
            return Ok(None);
        };
        section = *next;
    }
    Err(error!("cycle in COMDAT section redirects"))
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
    redirects: &SectionRedirects,
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
                && let Some((_, id)) =
                    redirected_location(locations, redirects, (object_index, section))?
            {
                return Ok(Some(
                    image_base + u64::from(layout.placements[&id].rva) + symbol.address(),
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
    redirects: &SectionRedirects,
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
                            let ((target_object, target_section_index), id) =
                                redirected_location(locations, redirects, (object_index, section))?
                                    .ok_or_else(|| {
                                        error!(
                                            "relocation targets discarded section {object_index}:{section:?} via symbol `{}`",
                                            String::from_utf8_lossy(name)
                                        )
                                    })?;
                            let target_section = objects[target_object]
                                .file()
                                .section_by_index(target_section_index)
                                .context("COMDAT redirect targets an invalid section")?;
                            ensure!(
                                symbol.address() <= target_section.size(),
                                "symbol offset exceeds selected COMDAT section"
                            );
                            let target_placement = &layout.placements[&id];
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
                        let (_, id) = redirected_location(
                            locations,
                            redirects,
                            (object_index, section),
                        )?
                        .ok_or_else(|| {
                            error!(
                                "relocation targets discarded section {object_index}:{section:?}"
                            )
                        })?;
                        let target_placement = &layout.placements[&id];
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

fn rva_file_offset(layout: &SectionLayout, rva: u32, size: u32) -> Result<usize> {
    let end = rva.checked_add(size).context("PE RVA range overflow")?;
    let section = layout
        .sections
        .iter()
        .find(|section| {
            rva >= section.rva
                && end <= section.rva.saturating_add(section.raw_size)
                && section.file_offset.is_some()
        })
        .context("PE RVA range has no file-backed section")?;
    let file = section
        .file_offset
        .context("PE RVA range lies in an uninitialized section")?
        .checked_add(rva - section.rva)
        .context("PE file offset overflow")?;
    let file_end = file.checked_add(size).context("PE file range overflow")?;
    ensure!(
        file_end <= layout.file_size,
        "PE RVA range extends past the file"
    );
    usize::try_from(file).context("PE file offset exceeds usize")
}

fn has_tls_contributions(
    objects: &[crate::coff::CoffObject<'_>],
    contributions: &[Contribution],
) -> Result<bool> {
    for contribution in contributions {
        let Source::Object { object, section } = contribution.source else {
            continue;
        };
        let name = objects[object]
            .file()
            .section_by_index(section)?
            .name_bytes()
            .context("invalid COFF TLS section name")?;
        if name == b".tls" || name.starts_with(b".tls$") || name.starts_with(b".CRT$XL") {
            return Ok(true);
        }
    }
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
fn prepare_tls_directory(
    objects: &[crate::coff::CoffObject<'_>],
    contributions: &[Contribution],
    layout: &SectionLayout,
    definitions: &HashMap<Vec<u8>, u64>,
    image_base: u64,
    dynamic_base: bool,
    has_tls_inputs: bool,
    image: &mut [u8],
) -> Result<Option<(u32, u32)>> {
    if !has_tls_inputs {
        return Ok(None);
    }

    let directory_rva = tls_definition_rva(definitions, b"_tls_used", image_base)
        .context("TLS input requires the `_tls_used` IMAGE_TLS_DIRECTORY64 symbol")?;
    let index_rva = tls_definition_rva(definitions, b"_tls_index", image_base)
        .context("TLS input requires the loader-written `_tls_index` symbol")?;
    let tls_start_rva = tls_definition_rva(definitions, b"_tls_start", image_base)
        .context("TLS input requires the CRT `_tls_start` symbol")?;
    let tls_end_rva = tls_definition_rva(definitions, b"_tls_end", image_base)
        .context("TLS input requires the CRT `_tls_end` symbol")?;
    ensure!(
        tls_start_rva <= tls_end_rva,
        "TLS `_tls_start` lies after `_tls_end`"
    );

    let directory_size = linker_utils::pe_tls::IMAGE_TLS_DIRECTORY64_SIZE;
    let directory_offset = rva_file_offset(layout, directory_rva, directory_size)
        .context("`_tls_used` is not backed by a complete IMAGE_TLS_DIRECTORY64")?;
    let original = image
        .get(directory_offset..directory_offset + directory_size as usize)
        .context("`_tls_used` extends past the PE file")?
        .to_vec();
    let raw_start = tls_rva_from_va(read_tls_u64(&original, 0), image_base, "raw-data start")?;
    let raw_end = tls_rva_from_va(read_tls_u64(&original, 8), image_base, "raw-data end")?;
    let encoded_index = tls_rva_from_va(read_tls_u64(&original, 16), image_base, "index")?;
    let callbacks_rva = tls_rva_from_va(read_tls_u64(&original, 24), image_base, "callbacks")?;
    ensure!(
        raw_start == tls_start_rva && raw_end == tls_end_rva,
        "`_tls_used` raw-data range does not match `_tls_start`/`_tls_end`"
    );
    ensure!(
        encoded_index == index_rva,
        "`_tls_used` AddressOfIndex does not reference `_tls_index`"
    );

    let template_size = raw_end
        .checked_sub(raw_start)
        .context("TLS raw-data start is after its end")?;
    let template_offset = rva_file_offset(layout, raw_start, template_size)
        .context("TLS template is not fully file-backed")?;
    let template = image
        .get(template_offset..template_offset + template_size as usize)
        .context("TLS template extends past the PE file")?;
    let alignment = tls_template_alignment(objects, contributions)?;
    let zero_fill = u32::from_le_bytes(original[32..36].try_into().unwrap());
    let template_virtual_end = raw_end
        .checked_add(zero_fill)
        .context("TLS zero-fill range overflow")?;
    ensure!(
        layout.sections.iter().any(|section| {
            raw_start >= section.rva
                && template_virtual_end <= section.rva.saturating_add(section.virtual_size)
        }),
        "TLS template and zero-fill range is not contained in one mapped section"
    );
    let tls = linker_utils::pe_tls::build_amd64_tls_image(
        linker_utils::pe_tls::TlsLayout {
            image_base,
            raw_data_rva: raw_start,
            index_rva,
            callbacks_rva,
            directory_rva,
            size_of_image: layout.size_of_image,
        },
        &[linker_utils::pe_tls::TlsContribution {
            section_name: b".tls",
            data: template,
            zero_fill,
            alignment,
            order: 0,
        }],
        &[],
    )
    .context("failed to construct AMD64 PE TLS metadata")?;
    ensure!(
        tls.raw_data_virtual_size
            == template_size
                .checked_add(zero_fill)
                .context("TLS template size overflow")?,
        "TLS template size changed during metadata construction"
    );

    let dir64 = dir64_rvas(objects, contributions, layout)?;
    if dynamic_base {
        for rva in &tls.dir64_relocation_rvas {
            ensure!(
                dir64.contains(rva),
                "TLS directory field at RVA {rva:#x} lacks an AMD64 DIR64 base relocation"
            );
        }
    }
    validate_tls_callbacks(
        image,
        layout,
        image_base,
        callbacks_rva,
        dynamic_base,
        &dir64,
    )?;

    image[directory_offset..directory_offset + directory_size as usize]
        .copy_from_slice(&tls.directory);
    linker_utils::pe_tls::parse_amd64_tls_directory(
        &image[directory_offset..directory_offset + directory_size as usize],
        image_base,
        layout.size_of_image,
    )
    .context("malformed `_tls_used` IMAGE_TLS_DIRECTORY64")?;
    Ok(Some((directory_rva, directory_size)))
}

fn tls_template_alignment(
    objects: &[crate::coff::CoffObject<'_>],
    contributions: &[Contribution],
) -> Result<u32> {
    let mut alignment = 1;
    for contribution in contributions {
        let Source::Object { object, section } = contribution.source else {
            continue;
        };
        let section = objects[object].file().section_by_index(section)?;
        let name = section
            .name_bytes()
            .context("invalid COFF TLS section name")?;
        if name == b".tls" || name.starts_with(b".tls$") {
            alignment = alignment.max(contribution.spec.alignment);
        }
    }
    Ok(alignment)
}

fn validate_tls_callbacks(
    image: &[u8],
    layout: &SectionLayout,
    image_base: u64,
    callbacks_rva: u32,
    dynamic_base: bool,
    dir64_rvas: &[u32],
) -> Result<()> {
    let mut field_rva = callbacks_rva;
    loop {
        let offset = rva_file_offset(layout, field_rva, 8)
            .context("TLS callback array is not null-terminated in file-backed image data")?;
        let callback = read_tls_u64(image, offset);
        if callback == 0 {
            return Ok(());
        }
        let callback_rva = tls_rva_from_va(callback, image_base, "callback target")?;
        ensure!(
            callback_rva < layout.size_of_image,
            "TLS callback target RVA {callback_rva:#x} lies outside the image"
        );
        if dynamic_base {
            ensure!(
                dir64_rvas.contains(&field_rva),
                "TLS callback pointer at RVA {field_rva:#x} lacks an AMD64 DIR64 base relocation"
            );
        }
        field_rva = field_rva
            .checked_add(8)
            .context("TLS callback array RVA overflow")?;
    }
}

fn tls_definition_rva(
    definitions: &HashMap<Vec<u8>, u64>,
    name: &[u8],
    image_base: u64,
) -> Result<u32> {
    let address = definitions
        .get(name)
        .copied()
        .with_context(|| format!("undefined TLS symbol `{}`", String::from_utf8_lossy(name)))?;
    let rva = address.checked_sub(image_base).with_context(|| {
        format!(
            "TLS symbol `{}` precedes the image base",
            String::from_utf8_lossy(name)
        )
    })?;
    u32::try_from(rva).with_context(|| {
        format!(
            "TLS symbol `{}` has an RVA wider than 32 bits",
            String::from_utf8_lossy(name)
        )
    })
}

fn tls_rva_from_va(value: u64, image_base: u64, description: &str) -> Result<u32> {
    let rva = value
        .checked_sub(image_base)
        .with_context(|| format!("TLS {description} VA lies below the image base"))?;
    u32::try_from(rva).with_context(|| format!("TLS {description} RVA exceeds 32 bits"))
}

fn read_tls_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
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

    #[test]
    fn loads_rustc_style_definition_exports_and_merges_command_line_exports() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lib.def");
        std::fs::write(
            &path,
            concat!(
                "\u{feff}LIBRARY \"displaydoc.dll\"\r\n",
                "EXPORTS\r\n",
                "    __rustc_proc_macro_decls_0123456789abcdef__ DATA\r\n",
                "    rust_metadata_displaydoc_0123456789abcdef DATA\r\n",
                "    public_alias=internal_symbol @42 NONAME PRIVATE\r\n",
                "    forwarded=KERNEL32.Sleep @43\r\n",
            ),
        )
        .unwrap();
        let mut args = crate::args::coff::CoffArgs {
            is_dll: true,
            ..Default::default()
        };
        crate::args::coff::parse(
            &mut args,
            [
                format!("/DEF:{}", path.display()),
                "/EXPORT:command_line_symbol,DATA".to_owned(),
            ]
            .iter(),
        )
        .unwrap();

        let definition = load_definition_file(&crate::fs::OsFileSystem::new(), &args).unwrap();
        assert_eq!(definition.module_name.as_deref(), Some("displaydoc.dll"));
        let exports = definition.exports;
        assert_eq!(exports.len(), 5);
        assert_eq!(exports[0].name, "command_line_symbol");
        assert!(exports[0].data);
        assert_eq!(
            exports[1].target,
            "__rustc_proc_macro_decls_0123456789abcdef__"
        );
        assert!(exports[1].data);
        assert_eq!(
            exports[2].target,
            "rust_metadata_displaydoc_0123456789abcdef"
        );
        assert!(exports[2].data);
        assert_eq!(exports[3].name, "public_alias");
        assert_eq!(exports[3].target, "internal_symbol");
        assert_eq!(exports[3].ordinal, Some(42));
        assert!(exports[3].noname);
        assert!(exports[3].private);
        assert_eq!(exports[4].target, "KERNEL32.Sleep");
    }

    #[test]
    fn rejects_conflicting_definition_and_command_line_exports() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lib.def");
        std::fs::write(&path, "LIBRARY x.dll\nEXPORTS\n symbol=other\n").unwrap();
        let mut args = crate::args::coff::CoffArgs {
            is_dll: true,
            ..Default::default()
        };
        crate::args::coff::parse(
            &mut args,
            [
                format!("/DEF:{}", path.display()),
                "/EXPORT:symbol".to_owned(),
            ]
            .iter(),
        )
        .unwrap();

        let error = load_definition_file(&crate::fs::OsFileSystem::new(), &args).unwrap_err();
        assert!(error.to_string().contains("conflicting export `symbol`"));
    }

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

    fn comdat_object(
        name: &[u8],
        scope: object::SymbolScope,
        kind: object::ComdatKind,
        contents: &[u8],
        timestamp: u32,
        associative_child: bool,
    ) -> Vec<u8> {
        let mut object = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let primary = object.add_subsection(object::write::StandardSection::Text, name);
        object.append_section_data(primary, contents, 1);
        object.section_symbol(primary);
        let symbol = object.add_symbol(Symbol {
            name: name.to_vec(),
            value: 0,
            size: contents.len() as u64,
            kind: object::SymbolKind::Text,
            scope,
            weak: false,
            section: SymbolSection::Section(primary),
            flags: object::SymbolFlags::None,
        });
        let mut sections = vec![primary];
        if associative_child {
            let child = object.add_subsection(object::write::StandardSection::ReadOnlyData, name);
            object.append_section_data(child, b"child", 1);
            object.section_symbol(child);
            sections.push(child);
        }
        object.add_comdat(object::write::Comdat {
            kind,
            symbol,
            sections,
        });
        let mut bytes = object.write().unwrap();
        bytes[4..8].copy_from_slice(&timestamp.to_le_bytes());
        bytes
    }

    fn comdat_object_with_section_relocations(include_references: bool) -> Vec<u8> {
        let mut object = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let primary = object.add_subsection(object::write::StandardSection::Text, b"redirect");
        object.append_section_data(primary, &[0x90; 16], 1);
        object.section_symbol(primary);
        let leader = object.add_symbol(Symbol {
            name: b"redirect".to_vec(),
            value: 0,
            size: 16,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(primary),
            flags: object::SymbolFlags::None,
        });
        let local = object.add_symbol(Symbol {
            name: b"redirect_local".to_vec(),
            value: 4,
            size: 1,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(primary),
            flags: object::SymbolFlags::None,
        });
        object.add_comdat(object::write::Comdat {
            kind: object::ComdatKind::Any,
            symbol: leader,
            sections: vec![primary],
        });
        if include_references {
            let data = object.add_section(Vec::new(), b".data".to_vec(), object::SectionKind::Data);
            object.append_section_data(data, &[0; 8], 4);
            for (offset, typ) in [
                (0, object::pe::IMAGE_REL_AMD64_SECREL),
                (4, object::pe::IMAGE_REL_AMD64_SECTION),
            ] {
                object
                    .add_relocation(
                        data,
                        Relocation {
                            offset,
                            symbol: local,
                            addend: 0,
                            flags: object::RelocationFlags::Coff { typ },
                        },
                    )
                    .unwrap();
            }
        }
        object.write().unwrap()
    }

    fn nested_associative_comdat_object() -> Vec<u8> {
        let mut object = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let primary = object.add_subsection(object::write::StandardSection::Text, b"nested");
        object.append_section_data(primary, b"primary", 1);
        object.section_symbol(primary);
        let symbol = object.add_symbol(Symbol {
            name: b"nested".to_vec(),
            value: 0,
            size: 7,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(primary),
            flags: object::SymbolFlags::None,
        });
        let child = object.add_subsection(object::write::StandardSection::ReadOnlyData, b"child");
        object.append_section_data(child, b"child", 1);
        object.section_symbol(child);
        let grandchild =
            object.add_subsection(object::write::StandardSection::ReadOnlyData, b"grandchild");
        object.append_section_data(grandchild, b"grandchild", 1);
        object.section_symbol(grandchild);
        object.add_comdat(object::write::Comdat {
            kind: object::ComdatKind::Any,
            symbol,
            sections: vec![primary, child, grandchild],
        });
        let mut bytes = object.write().unwrap();

        // object writes both children as direct associates. Point the grandchild at the child to
        // exercise a valid nested associative chain.
        let symbol_table = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let symbol_count = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
        let mut index = 0;
        let mut associative_aux = Vec::new();
        while index < symbol_count {
            let symbol_offset = symbol_table + index * 18;
            let aux_count = bytes[symbol_offset + 17] as usize;
            if aux_count != 0 {
                let aux_offset = symbol_offset + 18;
                if bytes[aux_offset + 14] == object::pe::IMAGE_COMDAT_SELECT_ASSOCIATIVE.0 {
                    associative_aux.push(aux_offset);
                }
            }
            index += 1 + aux_count;
        }
        assert_eq!(associative_aux.len(), 2);
        bytes[associative_aux[1] + 12..associative_aux[1] + 14]
            .copy_from_slice(&2_u16.to_le_bytes());
        bytes
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

    fn resource_stream() -> Vec<u8> {
        let mut bytes = vec![0; 32];
        bytes[4..8].copy_from_slice(&32_u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&[0xff, 0xff, 0, 0]);
        bytes[12..16].copy_from_slice(&[0xff, 0xff, 0, 0]);

        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&32_u32.to_le_bytes());
        bytes.extend_from_slice(&[0xff, 0xff, 24, 0]);
        bytes.extend_from_slice(&[0xff, 0xff, 1, 0]);
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0x30_u16.to_le_bytes());
        bytes.extend_from_slice(&0x409_u16.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.push(b'x');
        bytes.extend_from_slice(&[0; 3]);
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

    fn zero_sized_local_comdat_relocation_object() -> Vec<u8> {
        let mut object = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let text = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
        object.append_section_data(text, &[0; 13], 1);
        object.add_symbol(Symbol {
            name: b"entry".to_vec(),
            value: 0,
            size: 13,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(text),
            flags: object::SymbolFlags::None,
        });

        let prefix = object.add_subsection(object::write::StandardSection::ReadOnlyData, b"a");
        object.append_section_data(prefix, &[1, 2, 3], 1);
        let empty = object.add_subsection(object::write::StandardSection::ReadOnlyData, b"z");
        object.append_section_data(empty, &[], 8);
        object.section_symbol(empty);
        let target = object.add_symbol(Symbol {
            name: b"empty-local".to_vec(),
            value: 0,
            size: 0,
            kind: object::SymbolKind::Data,
            scope: object::SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(empty),
            flags: object::SymbolFlags::None,
        });
        object.add_comdat(object::write::Comdat {
            kind: object::ComdatKind::NoDuplicates,
            symbol: target,
            sections: vec![empty],
        });

        for (offset, typ) in [
            (0, object::pe::IMAGE_REL_AMD64_REL32),
            (4, object::pe::IMAGE_REL_AMD64_SECTION),
            (8, object::pe::IMAGE_REL_AMD64_SECREL),
        ] {
            object
                .add_relocation(
                    text,
                    Relocation {
                        offset,
                        symbol: target,
                        addend: 0,
                        flags: object::RelocationFlags::Coff { typ },
                    },
                )
                .unwrap();
        }
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
    fn zero_sized_local_comdat_has_a_real_section_boundary_location() {
        let bytes = zero_sized_local_comdat_relocation_object();
        let object = crate::coff::CoffObject::parse(&bytes).unwrap();
        let image = build_image(
            &[object],
            &[],
            &[],
            b"zero-sized-local.exe",
            Some("entry"),
            &crate::args::coff::CoffArgs::default(),
            PeWriterConfig::default(),
            &[],
            &Default::default(),
        )
        .unwrap();

        let file = object::File::parse(image.bytes.as_slice()).unwrap();
        let text = file.section_by_name(".text").unwrap();
        assert_eq!(
            &text.data().unwrap()[..12],
            &[
                0x08, 0x10, 0x00, 0x00, // REL32: `.rdata + 8`, including COFF's addend.
                0x02, 0x00, // SECTION: the second output section, `.rdata`.
                0x00, 0x00, // Padding between the two relocation fields.
                0x08, 0x00, 0x00, 0x00, // SECREL: byte 8 within `.rdata`.
            ]
        );
    }

    #[test]
    fn wholly_empty_output_section_is_still_omitted() {
        let mut object = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let empty = object.add_section(
            Vec::new(),
            b".rdata$z".to_vec(),
            object::SectionKind::ReadOnlyData,
        );
        object.append_section_data(empty, &[], 8);
        let bytes = object.write().unwrap();
        let object = crate::coff::CoffObject::parse(&bytes).unwrap();

        assert!(
            collect_contributions(&[object], &crate::args::coff::CoffArgs::default())
                .unwrap()
                .0
                .is_empty()
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
        assert_eq!(merged_name(b".foo$", &args).unwrap(), b".data$");
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
    fn local_noduplicates_comdats_have_object_local_identity() {
        let first = comdat_object(
            b"local",
            object::SymbolScope::Compilation,
            object::ComdatKind::NoDuplicates,
            b"first",
            0,
            true,
        );
        let second = comdat_object(
            b"local",
            object::SymbolScope::Compilation,
            object::ComdatKind::NoDuplicates,
            b"second",
            0,
            true,
        );
        let objects = [
            crate::coff::CoffObject::parse(&first).unwrap(),
            crate::coff::CoffObject::parse(&second).unwrap(),
        ];

        assert!(
            discarded_comdat_sections(&objects)
                .unwrap()
                .discarded
                .is_empty()
        );
    }

    #[test]
    fn global_noduplicates_comdats_still_reject_live_conflicts() {
        let first = comdat_object(
            b"global",
            object::SymbolScope::Linkage,
            object::ComdatKind::NoDuplicates,
            b"first",
            0,
            false,
        );
        let second = comdat_object(
            b"global",
            object::SymbolScope::Linkage,
            object::ComdatKind::NoDuplicates,
            b"second",
            0,
            false,
        );
        let objects = [
            crate::coff::CoffObject::parse(&first).unwrap(),
            crate::coff::CoffObject::parse(&second).unwrap(),
        ];

        let error = discarded_comdat_sections(&objects).unwrap_err().to_string();
        assert!(error.contains("NODUPLICATES"), "{error}");
    }

    #[test]
    fn global_comdat_selection_discards_associative_children_as_a_group() {
        let cases = [
            (
                object::ComdatKind::Any,
                b"old".as_slice(),
                b"new".as_slice(),
                0,
                0,
            ),
            (object::ComdatKind::SameSize, b"old", b"new", 0, 0),
            (object::ComdatKind::ExactMatch, b"same", b"same", 0, 0),
            (object::ComdatKind::Largest, b"x", b"larger", 0, 0),
            (object::ComdatKind::Newest, b"old", b"new", 1, 2),
        ];
        for (kind, old, new, old_timestamp, new_timestamp) in cases {
            let first = comdat_object(
                b"global",
                object::SymbolScope::Linkage,
                kind,
                old,
                old_timestamp,
                true,
            );
            let second = comdat_object(
                b"global",
                object::SymbolScope::Linkage,
                kind,
                new,
                new_timestamp,
                true,
            );
            let objects = [
                crate::coff::CoffObject::parse(&first).unwrap(),
                crate::coff::CoffObject::parse(&second).unwrap(),
            ];

            let discarded = discarded_comdat_sections(&objects).unwrap();
            assert_eq!(discarded.discarded.len(), 2, "selection {kind:?}");
            assert_eq!(discarded.redirects.len(), 2, "selection {kind:?}");
            let (loser, winner) = if matches!(
                kind,
                object::ComdatKind::Largest | object::ComdatKind::Newest
            ) {
                (0, 1)
            } else {
                (1, 0)
            };
            for section in [object::SectionIndex(1), object::SectionIndex(2)] {
                assert_eq!(
                    discarded.redirects[&(loser, section)],
                    (winner, section),
                    "selection {kind:?} section {section:?}"
                );
            }
        }
    }

    #[test]
    fn nested_associative_comdats_follow_the_ultimate_leader() {
        let first = nested_associative_comdat_object();
        let second = nested_associative_comdat_object();
        let objects = [
            crate::coff::CoffObject::parse(&first).unwrap(),
            crate::coff::CoffObject::parse(&second).unwrap(),
        ];

        let resolution = discarded_comdat_sections(&objects).unwrap();
        assert_eq!(resolution.discarded.len(), 3);
        assert_eq!(resolution.redirects.len(), 3);
    }

    #[test]
    fn section_relocations_to_discarded_comdat_use_selected_section() {
        let winner = comdat_object_with_section_relocations(false);
        let loser = comdat_object_with_section_relocations(true);
        let objects = [
            crate::coff::CoffObject::parse(&winner).unwrap(),
            crate::coff::CoffObject::parse(&loser).unwrap(),
        ];

        let image = build_image(
            &objects,
            &[],
            &[],
            b"redirect.exe",
            None,
            &crate::args::coff::CoffArgs::default(),
            PeWriterConfig::default(),
            &[],
            &Default::default(),
        )
        .unwrap();
        let pe = object::File::parse(image.bytes.as_slice()).unwrap();
        let data = pe.section_by_name(".data").unwrap().data().unwrap();
        assert_eq!(u32::from_le_bytes(data[0..4].try_into().unwrap()), 4);
        assert_eq!(u16::from_le_bytes(data[4..6].try_into().unwrap()), 1);
    }

    #[test]
    fn regular_strong_definition_precedes_global_comdat() {
        let strong = directive_object(Some(b"shared"), None, b"");
        let comdat = comdat_object(
            b"shared",
            object::SymbolScope::Linkage,
            object::ComdatKind::Any,
            b"comdat",
            0,
            true,
        );
        let objects = [
            crate::coff::CoffObject::parse(&comdat).unwrap(),
            crate::coff::CoffObject::parse(&strong).unwrap(),
        ];

        assert_eq!(
            discarded_comdat_sections(&objects).unwrap().discarded.len(),
            2
        );
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
        let input_storage = colosseum::sync::Arena::new();
        let mut inputs = Vec::new();
        open_input(&fs, &direct_path, &args, &input_storage, &mut inputs, false).unwrap();
        let selected =
            select_inputs_to_fixpoint(&fs, &args, &args.exports, &input_storage, &mut inputs)
                .unwrap();

        assert_eq!(selected.archive_bytes.len(), 2);
        assert_eq!(selected.objects.len(), 3);
        assert_eq!(selected.resolver_object_scans, selected.objects.len());
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
    fn definition_exports_extract_archive_members_but_forwarders_do_not() {
        let directory = tempfile::tempdir().unwrap();
        let direct_path = directory.path().join("direct.obj");
        let library_path = directory.path().join("exports.lib");
        let proc_macro = b"__rustc_proc_macro_decls_0123456789abcdef__";
        std::fs::write(
            &direct_path,
            directive_object(Some(b"unrelated"), None, b""),
        )
        .unwrap();
        std::fs::write(
            &library_path,
            single_member_archive(
                b"exports.obj",
                &directive_object(Some(proc_macro), Some(b"KERNEL32.Sleep"), b""),
            ),
        )
        .unwrap();
        let args = crate::args::coff::CoffArgs {
            no_entry: true,
            is_dll: true,
            ..Default::default()
        };
        let exports = vec![
            crate::args::coff::ExportSpec {
                name: std::str::from_utf8(proc_macro).unwrap().to_owned(),
                target: std::str::from_utf8(proc_macro).unwrap().to_owned(),
                ordinal: None,
                noname: false,
                data: true,
                private: false,
            },
            crate::args::coff::ExportSpec {
                name: "sleep".into(),
                target: "KERNEL32.Sleep".into(),
                ordinal: None,
                noname: false,
                data: false,
                private: false,
            },
        ];
        let fs = crate::fs::OsFileSystem;
        let input_storage = colosseum::sync::Arena::new();
        let mut inputs = Vec::new();
        open_input(&fs, &direct_path, &args, &input_storage, &mut inputs, false).unwrap();
        open_input(
            &fs,
            &library_path,
            &args,
            &input_storage,
            &mut inputs,
            false,
        )
        .unwrap();

        let selected =
            select_inputs_to_fixpoint(&fs, &args, &exports, &input_storage, &mut inputs).unwrap();
        assert_eq!(selected.objects.len(), 2);
        assert!(selected.roots.iter().any(|root| root == proc_macro));
        assert!(!selected.roots.iter().any(|root| root == b"KERNEL32.Sleep"));
    }

    #[test]
    fn bare_library_names_gain_lib_suffix_in_search_path_order() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let first_library = first.path().join("runtime.lib");
        let second_library = second.path().join("runtime.lib");
        std::fs::write(&first_library, b"first").unwrap();
        std::fs::write(&second_library, b"second").unwrap();
        let args = crate::args::coff::CoffArgs {
            lib_search_path: vec![first.path().into(), second.path().into()],
            ..Default::default()
        };

        assert_eq!(
            find_input(&crate::fs::OsFileSystem, Path::new("runtime"), &args).unwrap(),
            first_library
        );
    }

    #[test]
    fn exact_extensionless_library_wins_before_implicit_suffix() {
        let directory = tempfile::tempdir().unwrap();
        let exact = directory.path().join("runtime");
        std::fs::write(&exact, b"exact").unwrap();
        std::fs::write(directory.path().join("runtime.lib"), b"suffixed").unwrap();
        let args = crate::args::coff::CoffArgs {
            lib_search_path: vec![directory.path().into()],
            ..Default::default()
        };

        assert_eq!(
            find_input(&crate::fs::OsFileSystem, Path::new("runtime"), &args).unwrap(),
            exact
        );
    }

    #[test]
    fn explicit_extensions_and_paths_do_not_gain_lib_suffix() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("runtime.custom.lib"), b"library").unwrap();
        std::fs::write(directory.path().join("nested.lib"), b"library").unwrap();
        let args = crate::args::coff::CoffArgs {
            lib_search_path: vec![directory.path().into()],
            ..Default::default()
        };

        let extension_error =
            find_input(&crate::fs::OsFileSystem, Path::new("runtime.custom"), &args)
                .unwrap_err()
                .to_string();
        assert!(extension_error.contains("runtime.custom"));

        let explicit_path = directory.path().join("nested");
        let path_error = find_input(&crate::fs::OsFileSystem, &explicit_path, &args)
            .unwrap_err()
            .to_string();
        assert!(path_error.contains(&explicit_path.display().to_string()));
    }

    #[test]
    fn library_policy_names_remain_case_and_suffix_insensitive() {
        assert!(same_library_name("MSVCRT", "msvcrt.lib"));
        assert!(same_library_name("Runtime.LIB", "runtime"));
        assert!(path_matches(Path::new("sdk/Foo.LIB"), "FOO"));
        assert!(!same_library_name("foo.dll", "foo"));
    }

    #[test]
    fn extracted_nodefaultlib_invalidates_cached_default_library_selection() {
        let directory = tempfile::tempdir().unwrap();
        let direct_path = directory.path().join("direct.obj");
        let first_path = directory.path().join("first.lib");
        let excluded_path = directory.path().join("excluded.lib");
        std::fs::write(
            &direct_path,
            directive_object(
                None,
                Some(b"first"),
                b" /DEFAULTLIB:first.lib /DEFAULTLIB:excluded.lib /INCLUDE:first",
            ),
        )
        .unwrap();
        std::fs::write(
            &first_path,
            single_member_archive(
                b"first.obj",
                &directive_object(Some(b"first"), None, b" /NODEFAULTLIB:excluded.lib"),
            ),
        )
        .unwrap();
        std::fs::write(
            &excluded_path,
            single_member_archive(
                b"excluded.obj",
                &directive_object(Some(b"excluded"), None, b""),
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
        let input_storage = colosseum::sync::Arena::new();
        let mut inputs = Vec::new();
        open_input(&fs, &direct_path, &args, &input_storage, &mut inputs, false).unwrap();
        let selected =
            select_inputs_to_fixpoint(&fs, &args, &args.exports, &input_storage, &mut inputs)
                .unwrap();

        assert_eq!(
            inputs.len(),
            3,
            "excluded library is opened before its directive"
        );
        assert_eq!(selected.archive_bytes.len(), 1);
        assert_eq!(selected.objects.len(), 2);
        assert!(selected.objects.iter().all(|object| {
            object
                .file()
                .symbols()
                .filter_map(|symbol| symbol.name_bytes().ok())
                .all(|name| name != b"excluded")
        }));
    }

    #[test]
    fn recognizes_renamed_resource_stream_after_known_coff_formats() {
        let directory = tempfile::tempdir().unwrap();
        let resource_path = directory.path().join("resource.lib");
        let object_path = directory.path().join("named-resource.res");
        std::fs::write(&resource_path, resource_stream()).unwrap();
        std::fs::write(&object_path, crate::coff::test_object()).unwrap();

        let args = crate::args::coff::CoffArgs {
            is_dll: true,
            no_entry: true,
            ..Default::default()
        };
        let fs = crate::fs::OsFileSystem;
        let input_storage = colosseum::sync::Arena::new();
        let mut inputs = Vec::new();
        open_input(
            &fs,
            &resource_path,
            &args,
            &input_storage,
            &mut inputs,
            false,
        )
        .unwrap();
        open_input(&fs, &object_path, &args, &input_storage, &mut inputs, false).unwrap();
        let selected = select_opened_inputs::<crate::fs::OsFileSystem>(
            &args,
            &args.exports,
            &inputs,
            false,
            &[],
        )
        .unwrap();

        assert_eq!(selected.resources.len(), 1);
        assert_eq!(selected.resources[0].data, b"x");
        assert_eq!(selected.objects.len(), 1);
    }

    #[test]
    fn malformed_renamed_resource_has_resource_diagnostic() {
        let directory = tempfile::tempdir().unwrap();
        let resource_path = directory.path().join("malformed.lib");
        let mut malformed = resource_stream();
        malformed.truncate(malformed.len() - 2);
        std::fs::write(&resource_path, malformed).unwrap();

        let args = crate::args::coff::CoffArgs {
            is_dll: true,
            no_entry: true,
            ..Default::default()
        };
        let fs = crate::fs::OsFileSystem;
        let input_storage = colosseum::sync::Arena::new();
        let mut inputs = Vec::new();
        open_input(
            &fs,
            &resource_path,
            &args,
            &input_storage,
            &mut inputs,
            false,
        )
        .unwrap();
        let error = match select_opened_inputs::<crate::fs::OsFileSystem>(
            &args,
            &args.exports,
            &inputs,
            false,
            &[],
        ) {
            Ok(_) => panic!("accepted malformed renamed resource"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains("while reading resource"), "{error}");
        assert!(!error.contains("cannot identify COFF input"), "{error}");
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
    fn diagnoses_missing_tls_runtime_symbols() {
        let layout = SectionLayout {
            sections: Vec::new(),
            placements: BTreeMap::new(),
            file_size: 0,
            size_of_image: 0x1000,
        };
        let error = prepare_tls_directory(
            &[],
            &[],
            &layout,
            &HashMap::new(),
            PeWriterConfig::default().image_base,
            true,
            true,
            &mut [],
        )
        .unwrap_err();
        assert!(format!("{error:?}").contains("_tls_used"));
    }

    #[test]
    fn diagnoses_unterminated_tls_callback_array() {
        let image_base = PeWriterConfig::default().image_base;
        let layout = SectionLayout {
            sections: vec![linker_utils::pe_sections::OutputSection {
                name: b".CRT".to_vec(),
                characteristics: readonly_data_characteristics(),
                rva: 0x1000,
                virtual_size: 8,
                file_offset: Some(0),
                raw_size: 8,
                contributions: Vec::new(),
            }],
            placements: BTreeMap::new(),
            file_size: 8,
            size_of_image: 0x2000,
        };
        let image = (image_base + 0x1100).to_le_bytes();
        let error = validate_tls_callbacks(&image, &layout, image_base, 0x1000, true, &[0x1000])
            .unwrap_err();
        assert!(format!("{error:?}").contains("not null-terminated"));
    }

    #[test]
    fn default_guard_policy_discards_guard_metadata_only() {
        let bytes = guard_metadata_object();
        let object = crate::coff::CoffObject::parse(&bytes).unwrap();
        let (contributions, _) =
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
        let (contributions, _) = collect_contributions(&[object], &args).unwrap();
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
