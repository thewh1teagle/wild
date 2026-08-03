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
use hashbrown::HashMap;
use hashbrown::HashSet;
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
use linker_utils::pe_sections::layout_sections_borrowed;
use linker_utils::pe_sections::try_insert_relocation_section;
use object::Object;
use object::ObjectComdat;
use object::ObjectSection;
use object::ObjectSymbol;
use object::RelocationKind;
use object::RelocationTarget;
use object::SectionFlags;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ops::Range;
use std::path::Path;
use std::path::PathBuf;

const LOAD_CONFIG_SYMBOL: &[u8] = b"_load_config_used";
const PE_PHASE_LOAD_DEFINITION: &str = "PE: Load definition";
const PE_PHASE_OPEN_INPUTS: &str = "PE: Open inputs";
const PE_PHASE_SELECT_INPUTS: &str = "PE: Select inputs";
const PE_PHASE_PARSE_INPUTS: &str = "PE: Parse inputs";
const PE_PHASE_PARSE_DIRECTIVES: &str = "PE: Parse directives";
const PE_PHASE_RESOLVE_ARCHIVES: &str = "PE: Resolve archives";
const PE_PHASE_PREPARE_RESOURCES: &str = "PE: Prepare resources";
const PE_PHASE_RESOLVE_IMPORTS: &str = "PE: Resolve imports";
const PE_PHASE_SELECT_COMDATS: &str = "PE: Select COMDATs and OPT:REF";
const PE_PHASE_LAYOUT: &str = "PE: Build contributions and layout";
const PE_PHASE_BUILD_SYNTHETIC: &str = "PE: Build synthetic sections";
const PE_PHASE_DEFINE_SYMBOLS: &str = "PE: Build symbol definitions";
const PE_PHASE_COPY_IMAGE: &str = "PE: Copy image contributions";
const PE_PHASE_APPLY_RELOCATIONS: &str = "PE: Apply relocations";
const PE_PHASE_FINALIZE_IMAGE: &str = "PE: Finalize image metadata";
const PE_PHASE_WRITE_OUTPUT: &str = "PE: Write output";
const PE_DETAIL_BUILD_IMPORTS: &str = "PE detail: Build eager imports";
const PE_DETAIL_BUILD_DELAY_IMPORTS: &str = "PE detail: Build delay imports";
const PE_DETAIL_BUILD_RESOURCES: &str = "PE detail: Build resources";
const PE_DETAIL_COMDAT_CLASSIFY: &str = "PE detail: Classify COMDAT topology";
const PE_DETAIL_COMDAT_SELECT: &str = "PE detail: Select COMDAT winners";
const PE_DETAIL_CONTRIBUTIONS: &str = "PE detail: Materialize input contributions";
const PE_DETAIL_DEBUG_BUILD_ID: &str = "PE detail: Compute debug build ID";
const PE_DETAIL_DEBUG_DIRECTORY: &str = "PE detail: Build debug directory";
const PE_DETAIL_DIR64_SITES: &str = "PE detail: Discover DIR64 sites";
const PE_DETAIL_EXCEPTION_DIRECTORY: &str = "PE detail: Canonicalize exception directory";
const PE_DETAIL_IMAGE_ALLOCATE: &str = "PE detail: Allocate output image";
const PE_DETAIL_IMAGE_COPY: &str = "PE detail: Copy contribution payloads";
const PE_DETAIL_IMPORT_SELECTION: &str = "PE detail: Select live imports";
const PE_DETAIL_LAYOUT_INITIAL: &str = "PE detail: Initial section layout";
const PE_DETAIL_LAYOUT_PREPARE: &str = "PE detail: Prepare layout inputs";
const PE_DETAIL_LAYOUT_RELOCATIONS: &str = "PE detail: Converge relocation layout";
const PE_DETAIL_LAYOUT_RELAYOUT: &str = "PE detail: Re-layout relocation section";
const PE_DETAIL_PROBE_ARCHIVE_INDICES: &str = "PE detail: Probe archive indices";
const PE_DETAIL_ABSORB_SELECTED_SYMBOLS: &str = "PE detail: Absorb selected symbols";
const PE_DETAIL_REBUILD_SELECTION_ROOTS: &str = "PE detail: Rebuild selection roots";
const PE_DETAIL_EVALUATE_DEFAULT_LIBRARIES: &str = "PE detail: Evaluate default libraries";
const PE_DETAIL_SNAPSHOT_RESOLVER_OUTPUTS: &str = "PE detail: Snapshot resolver outputs";
const PE_DETAIL_MATERIALIZE_SELECTED_IMPORTS: &str = "PE detail: Materialize selected imports";
#[cfg(test)]
const PE_DETAIL_REF_CLASSIFY: &str = "PE detail: Classify unreachable COMDATs";
#[cfg(test)]
const PE_DETAIL_REF_DEFINITIONS: &str = "PE detail: Build REF definition graph";
#[cfg(test)]
const PE_DETAIL_REF_REACHABILITY: &str = "PE detail: Traverse REF relocations";
const MAX_RELOCATION_RELAYOUTS: usize = 4;
#[cfg(test)]
const PE_DETAIL_REF_ROOTS: &str = "PE detail: Mark REF roots";
#[cfg(test)]
const PE_DETAIL_REF_TOPOLOGY: &str = "PE detail: Build REF group topology";
const PE_DETAIL_ROOTS: &str = "PE detail: Prepare GC roots";
const PE_DETAIL_SOURCE_LOCATIONS: &str = "PE detail: Build source-location map";
const PE_DETAIL_TLS_DIRECTORY: &str = "PE detail: Build TLS directory";
const PE_DETAIL_WRITE_HEADERS: &str = "PE detail: Write PE headers";
const PE_CHECKSUM_OFFSET: usize = 0x80 + 4 + 20 + 64;
const DIR64_DISCOVERY_CHUNK_SIZE: usize = 256;
// Live contributions are generally small compiler-generated sections. Keep at least this many in
// each import-reference task so Rayon scheduling and per-task set allocation don't dominate, while
// still creating several tasks per worker to absorb relocation-count skew between sections.
#[cfg(test)]
const LIVE_IMPORT_MIN_CONTRIBUTIONS_PER_CHUNK: usize = 64;
#[cfg(test)]
const LIVE_IMPORT_CHUNKS_PER_THREAD: usize = 4;
const PARALLEL_REPRO_COPY_MIN_SIZE: usize = 1024 * 1024;

#[inline]
fn count_pe_relocation_decode() {
    #[cfg(not(test))]
    crate::perf::removal_counters::increment_relocation_decodes();
}

#[inline]
fn count_pe_bytes_copied(bytes: usize) {
    #[cfg(not(test))]
    crate::perf::removal_counters::add_bytes_copied(bytes as u64);
    #[cfg(test)]
    let _ = bytes;
}

#[inline]
fn count_pe_hot_allocation() {
    #[cfg(not(test))]
    crate::perf::removal_counters::increment_hot_phase_allocations();
}
const LINKER_ABSOLUTE_ZERO_SYMBOLS: &[&[u8]] = &[
    b"__guard_fids_count",
    b"__guard_fids_table",
    b"__guard_flags",
    b"__guard_iat_count",
    b"__guard_iat_table",
    b"__guard_longjmp_count",
    b"__guard_longjmp_table",
    b"__guard_eh_cont_count",
    b"__guard_eh_cont_table",
    b"__enclave_config",
];

#[path = "pe_entry.rs"]
mod pe_entry;
#[path = "pe_gc.rs"]
mod pe_gc;
#[path = "pe_imports.rs"]
mod pe_imports;
#[path = "pe_ir.rs"]
mod pe_ir;
#[path = "pe_layout.rs"]
mod pe_layout;
#[path = "pe_resolver.rs"]
mod pe_resolver;
#[path = "pe_symbol_db.rs"]
mod pe_symbol_db;

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
    /// Dense identity for real selected-object sections. Synthetic contributions have none.
    dense_section: Option<pe_ir::SectionId>,
    spec: SectionContribution,
    /// Owned bytes exist only for linker-synthesized sections. Real input sections remain
    /// source-backed until their final output slice is copied and relocated.
    synthetic_data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Dir64Site {
    contribution: ContributionId,
    offset: u32,
}

struct BuiltImage {
    bytes: Vec<u8>,
    exports: Vec<ResolvedExport>,
    pending_repro_build_id: Option<PendingReproBuildId>,
}

#[derive(Clone, Debug)]
struct PendingReproBuildId {
    payload: Range<usize>,
}

impl PendingReproBuildId {
    fn new(image: &[u8], payload: Range<usize>) -> Result<Self> {
        ensure!(
            payload.start <= payload.end,
            "invalid excluded REPRO build-id range"
        );
        ensure!(
            payload.end <= image.len(),
            "excluded REPRO build-id range lies outside the image"
        );
        ensure!(
            payload.len() == linker_utils::pe_debug::REPRO_BUILD_ID_SIZE,
            "invalid REPRO build-id payload size"
        );
        let checksum_end = PE_CHECKSUM_OFFSET
            .checked_add(4)
            .context("PE checksum range overflow")?;
        ensure!(
            checksum_end <= image.len(),
            "PE checksum range lies outside the image"
        );
        ensure!(
            checksum_end <= payload.start,
            "PE checksum and REPRO build-id ranges overlap"
        );
        Ok(Self { payload })
    }

    fn compute(&self, image: &[u8]) -> Result<[u8; linker_utils::pe_debug::REPRO_BUILD_ID_SIZE]> {
        linker_utils::pe_debug::stable_build_id(
            image,
            Some(PE_CHECKSUM_OFFSET),
            std::slice::from_ref(&self.payload),
        )
        .context("failed to compute reproducible PE build id")
    }

    fn patch(&self, image: &mut [u8], build_id: &[u8; 32]) {
        image[self.payload.clone()].copy_from_slice(build_id);
    }
}

impl BuiltImage {
    fn finalize_repro_build_id(&mut self) -> Result<()> {
        let Some(pending) = self.pending_repro_build_id.as_ref() else {
            return Ok(());
        };
        let build_id_phase = crate::timing_guard!(PE_DETAIL_DEBUG_BUILD_ID);
        let build_id = pending.compute(&self.bytes)?;
        pending.patch(&mut self.bytes, &build_id);
        drop(build_id_phase);
        self.pending_repro_build_id = None;
        Ok(())
    }

    fn copy_to(&mut self, output: &mut [u8]) -> Result<()> {
        ensure!(
            output.len() == self.bytes.len(),
            "PE output buffer has an unexpected size"
        );
        let Some(pending) = self.pending_repro_build_id.as_ref() else {
            output.copy_from_slice(&self.bytes);
            return Ok(());
        };
        if rayon::current_num_threads() == 1 || self.bytes.len() < PARALLEL_REPRO_COPY_MIN_SIZE {
            self.finalize_repro_build_id()?;
            output.copy_from_slice(&self.bytes);
            return Ok(());
        }

        let (build_id, ()) = rayon::join(
            || {
                let build_id_phase = crate::timing_guard!(PE_DETAIL_DEBUG_BUILD_ID);
                let result = pending.compute(&self.bytes);
                drop(build_id_phase);
                result
            },
            || output.copy_from_slice(&self.bytes),
        );
        pending.patch(output, &build_id?);
        Ok(())
    }
}

pub(crate) fn link<F: FileSystem>(
    fs: &F,
    args: &crate::args::coff::CoffArgs,
) -> Result<crate::LinkerOutput<'static>> {
    crate::timing_phase!("PE link");
    ensure!(!args.common.inputs.is_empty(), "no COFF input files");
    ensure!(
        !(args.no_entry && args.entry.is_some()),
        "/ENTRY and /NOENTRY cannot be used together"
    );
    ensure!(
        !args.no_entry || args.is_dll,
        "/NOENTRY is only valid with /DLL"
    );

    let definition = {
        crate::timing_phase!(PE_PHASE_LOAD_DEFINITION);
        load_definition_file(fs, args)?
    };

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
    {
        crate::timing_phase!(PE_PHASE_OPEN_INPUTS);
        for request in requested {
            open_input(fs, &request, args, &input_storage, &mut inputs, false)?;
        }
    }
    let selected =
        select_inputs_to_fixpoint(fs, args, &definition.exports, &input_storage, &mut inputs)?;
    // Preserve the historical diagnostic/side-effect boundary: validate every retained object's
    // full shape before manifest preparation can write an auxiliary file.
    materialize_selected_object_indices(&selected.objects)?;
    let mut resources = selected.resources;
    {
        crate::timing_phase!(PE_PHASE_PREPARE_RESOURCES);
        prepare_manifest(fs, args, &selected.directives, &mut resources)?;
    }
    let objects = selected.objects;
    let selected_imports = selected.selected_imports;
    let resolver_seed = selected.resolver_seed;
    let symbol_snapshot = selected.symbol_snapshot;
    let entry_name = selected.entry_name;
    let exports = selected.exports;
    let runtime_resolution = selected.directives.runtime_resolution;
    let mut delay_load_dlls = args.delay_load_dlls.clone();
    delay_load_dlls.extend(selected.directives.delay_load_dlls);
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

    let dense = DenseProductionState::finalize(&objects, resolver_seed, &symbol_snapshot)?;

    let (imports, symbol_metadata) = {
        crate::timing_phase!(PE_PHASE_RESOLVE_IMPORTS);
        let undefined = dense.import_demands()?;
        // Remaining legacy layout/COMDAT consumers still use this borrowed compatibility view.
        // Undefined/import discovery no longer rebuilds global names from it.
        let (symbol_metadata, _) =
            SelectedObjectMetadata::new_with_undefined(&symbol_snapshot, &[], Some(&dense));
        let materialize_imports_phase =
            crate::timing_guard!(PE_DETAIL_MATERIALIZE_SELECTED_IMPORTS);
        let imports = pe_imports::select_from_records(&selected_imports, &undefined);
        drop(materialize_imports_phase);
        (imports, symbol_metadata)
    };
    let dll_name = if let Some(name) = definition.module_name.as_deref() {
        name
    } else {
        args.common
            .output
            .file_name()
            .and_then(|name| name.to_str())
            .context("PE output file name is not valid UTF-8")?
    };
    let mut image = build_image_with_delay_loads(
        &objects,
        Some(&dense),
        &symbol_metadata,
        &imports,
        &exports,
        dll_name.as_bytes(),
        entry_name.as_deref(),
        args,
        PeWriterConfig::from_args(args)?,
        &resources,
        &runtime_resolution,
        &delay_load_dlls,
        &roots,
    )?;
    {
        let mut write_phase = crate::pe_timing_guard!(PE_PHASE_WRITE_OUTPUT);
        write_phase
            .0
            .add(crate::timing::PeMetric::Bytes, image.bytes.len());
        write_phase
            .0
            .add(crate::timing::PeMetric::Events, image.exports.len());
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
        image.copy_to(output.bytes_mut())?;
        output.finish()?;
        if !image.exports.is_empty() {
            write_import_library(fs, args, dll_name.as_bytes(), &exports, &image.exports)?;
        }
    }
    Ok(crate::LinkerOutput { layout: None })
}

/// Materialize only the objects retained by archive selection. Indexed collection preserves input
/// order (and therefore deterministic error selection) while each independent object does its
/// generic COFF traversal on the Rayon pool.
fn materialize_selected_object_indices(objects: &[crate::coff::CoffObject<'_>]) -> Result<()> {
    let mut phase = crate::pe_timing_guard!("PE index: Materialize full COFF indices");
    phase.0.add(crate::timing::PeMetric::Objects, objects.len());
    let results = objects
        .par_iter()
        .map(crate::coff::CoffObject::materialize_full_index)
        .collect::<Vec<_>>();
    for result in results {
        result?;
    }
    if phase.0.enabled() {
        phase.0.add(
            crate::timing::PeMetric::Sections,
            objects
                .iter()
                .map(|object| object.index().sections().len())
                .sum(),
        );
        phase.0.add(
            crate::timing::PeMetric::Relocations,
            objects
                .iter()
                .map(|object| {
                    object
                        .index()
                        .sections()
                        .iter()
                        .map(|section| object.index().relocations(section).len())
                        .sum::<usize>()
                })
                .sum(),
        );
    }
    Ok(())
}

fn prepare_manifest<F: FileSystem>(
    fs: &F,
    args: &crate::args::coff::CoffArgs,
    directives: &crate::args::coff::CoffArgs,
    resources: &mut Vec<ResourceRecord>,
) -> Result<()> {
    let requested = args.manifest_requested || directives.manifest_requested;
    let (enabled, embed) = if args.manifest_mode_requested {
        (args.manifest, args.manifest_embed)
    } else if directives.manifest_mode_requested {
        (directives.manifest, directives.manifest_embed)
    } else {
        (args.manifest, None)
    };
    if !requested || !enabled {
        return Ok(());
    }

    let manifest_inputs = directives
        .manifest_inputs
        .iter()
        .chain(&args.manifest_inputs)
        .collect::<Vec<_>>();
    ensure!(
        manifest_inputs.is_empty() || embed.is_some(),
        "/MANIFESTINPUT requires /MANIFEST:EMBED"
    );

    use linker_utils::pe_manifest::ExecutionLevel;
    let dependencies = directives
        .manifest_dependencies
        .iter()
        .chain(&args.manifest_dependencies)
        .map(|dependency| dependency.value.as_str())
        .collect::<Vec<_>>();
    let uac = if args.manifest_uac_requested {
        args.manifest_uac
    } else if directives.manifest_uac_requested {
        directives.manifest_uac
    } else if args.is_dll {
        None
    } else {
        Some(crate::args::coff::ManifestUac {
            level: crate::args::coff::ManifestExecutionLevel::AsInvoker,
            ui_access: false,
        })
    };
    let execution_level = uac.map(|uac| match uac.level {
        crate::args::coff::ManifestExecutionLevel::AsInvoker => ExecutionLevel::AsInvoker,
        crate::args::coff::ManifestExecutionLevel::HighestAvailable => {
            ExecutionLevel::HighestAvailable
        }
        crate::args::coff::ManifestExecutionLevel::RequireAdministrator => {
            ExecutionLevel::RequireAdministrator
        }
    });
    let generated = linker_utils::pe_manifest::GeneratedManifest {
        dependencies: &dependencies,
        execution_level,
        ui_access: uac.is_some_and(|uac| uac.ui_access),
    };
    let bytes = if manifest_inputs.is_empty() {
        linker_utils::pe_manifest::generate_manifest(&generated)
    } else {
        let mut inputs = Vec::with_capacity(manifest_inputs.len());
        for path in manifest_inputs {
            let (input, _) = fs
                .open_input(path, args.common.prepopulate_maps)
                .with_context(|| format!("failed to open manifest input `{}`", path.display()))?;
            inputs.push(input.bytes().to_vec());
        }
        linker_utils::pe_manifest::merge_manifest_documents(
            &inputs.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            &generated,
        )?
    };

    let manifest_file = args
        .manifest_file
        .as_deref()
        .or(directives.manifest_file.as_deref());
    if let Some(path) = manifest_file {
        fs.write_auxiliary(path, &bytes)
            .with_context(|| format!("failed to write manifest file `{}`", path.display()))?;
    } else if embed.is_none() {
        let mut path = args.common.output.as_os_str().to_owned();
        path.push(".manifest");
        let path = PathBuf::from(path);
        fs.write_auxiliary(&path, &bytes)
            .with_context(|| format!("failed to write manifest file `{}`", path.display()))?;
    }

    let Some(embed) = embed else {
        return Ok(());
    };
    let id = match embed {
        crate::args::coff::ManifestEmbed::DefaultId => {
            linker_utils::pe_manifest::default_manifest_id(args.is_dll)
        }
        crate::args::coff::ManifestEmbed::Id(id) => id,
    };
    ensure!(
        !resources.iter().any(|record| {
            record.resource_type
                == linker_utils::pe_resources::ResourceId::Id(
                    linker_utils::pe_manifest::RT_MANIFEST,
                )
                && record.name == linker_utils::pe_resources::ResourceId::Id(id)
                && record.language == linker_utils::pe_manifest::MANIFEST_LANGUAGE_NEUTRAL
        }),
        "manifest resource ID {id} conflicts with an input resource"
    );
    resources.push(
        linker_utils::pe_manifest::manifest_resource(
            id,
            linker_utils::pe_manifest::MANIFEST_LANGUAGE_NEUTRAL,
            bytes,
        )
        .context("failed to create embedded manifest resource")?,
    );
    Ok(())
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
    #[cfg(test)]
    archive_bytes: Vec<&'data [u8]>,
    selected_imports: Vec<linker_utils::coff_imports::ShortImportObject<'data>>,
    resolver_seed: pe_resolver::ResolverSeed<'data>,
    symbol_snapshot: pe_resolver::SelectedSymbolSnapshot,
    entry_name: Option<String>,
    exports: Vec<crate::args::coff::ExportSpec>,
    roots: Vec<Vec<u8>>,
    directives: crate::args::coff::CoffArgs,
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
    crate::timing_phase!(PE_PHASE_SELECT_INPUTS);
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
        let default_libraries_phase = crate::timing_guard!(PE_DETAIL_EVALUATE_DEFAULT_LIBRARIES);
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
            drop(default_libraries_phase);
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
        drop(default_libraries_phase);
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
        let snapshot_phase = crate::timing_guard!(PE_DETAIL_SNAPSHOT_RESOLVER_OUTPUTS);
        let resolver_output = self.resolver.finish();
        drop(snapshot_phase);
        SelectedInputs {
            objects: self.objects,
            resources: self.resources,
            #[cfg(test)]
            archive_bytes: self.archive_bytes,
            selected_imports: resolver_output.selected_imports,
            resolver_seed: resolver_output.seed,
            symbol_snapshot: resolver_output.symbols,
            entry_name: self.entry_name,
            exports: self.exports,
            roots: self.roots,
            directives: self.directives,
            #[cfg(test)]
            resolver_object_scans: resolver_output.object_scans,
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
    for symbol in LINKER_ABSOLUTE_ZERO_SYMBOLS {
        selection.resolver.define_linker_symbol(symbol);
    }
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
    let mut parse_phase = crate::pe_timing_guard!(PE_PHASE_PARSE_INPUTS);
    parse_phase
        .0
        .add(crate::timing::PeMetric::Events, inputs.len());
    if parse_phase.0.enabled() {
        parse_phase.0.add(
            crate::timing::PeMetric::Bytes,
            inputs.iter().map(|(_, data, _)| data.bytes().len()).sum(),
        );
    }
    let mut object_count = 0usize;
    let mut archive_count = 0usize;
    for (path, data, _is_default) in inputs {
        match object::FileKind::parse(data.bytes()) {
            Ok(object::FileKind::Coff | object::FileKind::CoffBig) => {
                object_count += 1;
                selection
                    .direct_object_indices
                    .push(selection.objects.len());
                selection.objects.push(
                    crate::coff::CoffObject::parse(data.bytes())
                        .with_context(|| format!("while reading `{}`", path.display()))?,
                );
            }
            Ok(object::FileKind::Archive) => {
                archive_count += 1;
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
    parse_phase
        .0
        .add(crate::timing::PeMetric::Objects, object_count);
    parse_phase
        .0
        .add(crate::timing::PeMetric::Archives, archive_count);
    Ok(())
}

fn resolve_open_selection(
    args: &crate::args::coff::CoffArgs,
    command_exports: &[crate::args::coff::ExportSpec],
    selection: &mut OpenSelection<'_>,
) -> Result<()> {
    selection.entry_name = pe_entry::select_from_objects(
        args,
        selection
            .direct_object_indices
            .iter()
            .map(|&index| &selection.objects[index]),
    )?;
    loop {
        let mut directives = {
            crate::timing_phase!(PE_PHASE_PARSE_DIRECTIVES);
            directive_args(args, &selection.objects)?
        };
        let selection_roots_phase = crate::timing_guard!(PE_DETAIL_REBUILD_SELECTION_ROOTS);
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
        // link.exe and lld-link retain the CRT load-configuration object when
        // an archive makes it available. It is loader metadata rather than an
        // ordinary program reference, so no input undefined symbol pulls it
        // out of libcmt/msvcrt by itself.
        if selection
            .resolver
            .has_archive_definition(LOAD_CONFIG_SYMBOL)
        {
            roots.push(LOAD_CONFIG_SYMBOL.to_vec());
        }
        // The delay helper is referenced by linker-generated thunks rather than an input
        // relocation, so explicitly root it before archive extraction can reach delayimp.lib.
        if (!args.delay_load_dlls.is_empty() || !directives.delay_load_dlls.is_empty())
            && selection
                .resolver
                .has_archive_definition(b"__delayLoadHelper2")
        {
            roots.push(b"__delayLoadHelper2".to_vec());
        }
        roots.sort();
        roots.dedup();
        drop(selection_roots_phase);

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

/// Cohesive dense state finalized once after archive selection. The selected `CoffObject`s remain
/// the owners of all borrowed bytes and therefore outlive this value in `link`.
struct DenseProductionState<'data> {
    ir: pe_ir::PeIr<'data>,
    names: pe_symbol_db::OrderedNameInterner<'data>,
    symbols: pe_symbol_db::SymbolDb,
    resolved_targets: pe_ir::ResolvedSymbolTargets,
    resolver_states: Box<[pe_resolver::ResolverNameState]>,
    alternate_targets: Box<[u32]>,
    has_import_providers: bool,
}

impl<'data> DenseProductionState<'data> {
    fn finalize(
        objects: &[crate::coff::CoffObject<'data>],
        seed: pe_resolver::ResolverSeed<'data>,
        symbol_snapshot: &pe_resolver::SelectedSymbolSnapshot,
    ) -> Result<Self> {
        let mut finalize_phase =
            crate::pe_timing_guard!("PE symbols: Finalize dense production state");
        finalize_phase
            .0
            .add(crate::timing::PeMetric::Objects, objects.len());
        let pe_resolver::ResolverSeedParts {
            names,
            states,
            weak_fallbacks,
            alternate_fallbacks,
            providers,
        } = seed.into_parts();
        finalize_phase
            .0
            .add(crate::timing::PeMetric::Names, names.len());
        finalize_phase
            .0
            .add(crate::timing::PeMetric::Events, providers.len());
        let seed_name_count = names.len();
        ensure!(
            states.len() == seed_name_count,
            "resolver name/state cardinality mismatch"
        );
        let pe_ir::SelectedObjectFinalization {
            ir,
            names,
            occurrence_names: _,
        } = pe_ir::PeIr::finalize_selected_objects_with_globals(
            objects,
            names,
            &symbol_snapshot.globals,
        )?;

        let mut resolver_states = states.into_vec();
        // Object-local names appended during finalization were never resolver demands. Their
        // canonical entries deliberately start unresolved without renumbering any seed NameId.
        resolver_states.resize(names.len(), pe_resolver::ResolverNameState::default());
        let mut alternate_targets = vec![u32::MAX; names.len()];
        for fallback in alternate_fallbacks {
            let slot = alternate_targets
                .get_mut(fallback.symbol.index())
                .context("alternate fallback name is outside the canonical namespace")?;
            *slot = fallback.target.get();
        }

        let mut providers_phase = crate::pe_timing_guard!("PE symbols: Add resolver providers");
        providers_phase
            .0
            .add(crate::timing::PeMetric::Events, providers.len());
        providers_phase
            .0
            .add(crate::timing::PeMetric::Names, weak_fallbacks.len());
        let mut builder = pe_symbol_db::SymbolDbBuilder::new(names);
        let mut has_import_providers = false;
        for provider in providers {
            let (name, record) = match provider {
                pe_resolver::ResolverProviderOccurrence::Object {
                    name,
                    object,
                    raw_symbol,
                    strength,
                } => {
                    let object = pe_ir::ObjectId::from_u32(object);
                    let symbol = ir.symbol_by_raw(object, raw_symbol).ok_or_else(|| {
                        error!(
                            "resolver object provider {object:?}:{raw_symbol} has no dense symbol"
                        )
                    })?;
                    (
                        name,
                        pe_symbol_db::ProviderRecord::object(object, symbol, strength),
                    )
                }
                pe_resolver::ResolverProviderOccurrence::Import {
                    name,
                    selected_import,
                    archive,
                    member: _,
                } => {
                    has_import_providers = true;
                    (
                        name,
                        pe_symbol_db::ProviderRecord::import(
                            pe_ir::ImportLibraryId::from_u32(archive.get()),
                            pe_ir::ImportId::from_u32(selected_import),
                        ),
                    )
                }
                pe_resolver::ResolverProviderOccurrence::Absolute {
                    name,
                    value,
                    linker_defined,
                } => {
                    let value = builder.add_absolute_value(value);
                    (
                        name,
                        pe_symbol_db::ProviderRecord::absolute(value, linker_defined),
                    )
                }
            };
            builder
                .add_provider(name, record)
                .map_err(|error| error!("failed to add resolver provider: {error:?}"))?;
        }
        for fallback in weak_fallbacks {
            builder
                .set_weak_fallback(fallback.symbol, fallback.target)
                .map_err(|error| error!("failed to add weak fallback: {error:?}"))?;
        }
        drop(providers_phase);
        let finalized = builder
            .finish()
            .map_err(|error| error!("failed to finalize PE symbol database: {error:?}"))?;
        ensure!(
            finalized.names.len() == resolver_states.len(),
            "canonical name and symbol-state cardinality mismatch"
        );
        let mut resolve_targets_phase =
            crate::pe_timing_guard!("PE symbols: Resolve symbol targets");
        resolve_targets_phase
            .0
            .add(crate::timing::PeMetric::Symbols, ir.symbols.len());
        resolve_targets_phase.0.add(
            crate::timing::PeMetric::Names,
            finalized.symbols.entries.len(),
        );
        let resolved_targets = ir.resolve_symbol_targets(&finalized.symbols, &alternate_targets);
        drop(resolve_targets_phase);
        Ok(Self {
            ir,
            names: finalized.names,
            symbols: finalized.symbols,
            resolved_targets,
            resolver_states: resolver_states.into_boxed_slice(),
            alternate_targets: alternate_targets.into_boxed_slice(),
            has_import_providers,
        })
    }

    /// Materialize only demanded import names for the still-legacy import emitter. All selection
    /// and fallback decisions come from dense IDs; byte copies remain solely at this API seam.
    fn import_demands(&self) -> Result<HashSet<Vec<u8>>> {
        let mut demands = HashSet::new();
        for (index, state) in self.resolver_states.iter().enumerate() {
            if !state.is_demanded() {
                continue;
            }
            let mut name = pe_ir::NameId::from_u32(index as u32);
            for _ in 0..=self.symbols.entries.len() {
                let entry = self
                    .symbols
                    .entry(name)
                    .context("demanded name is outside the symbol database")?;
                if let Some(provider) = entry
                    .resolution
                    .provider()
                    .and_then(|provider| self.symbols.provider(provider))
                    && provider.kind() == pe_symbol_db::ProviderKind::Import
                {
                    let bytes = self
                        .names
                        .bytes(name)
                        .context("demanded import has no valid canonical bytes")?;
                    demands.insert(bytes.to_vec());
                    break;
                }
                if let Some(fallback) = entry.weak_fallback() {
                    name = fallback;
                    continue;
                }
                let alternate = *self
                    .alternate_targets
                    .get(name.index())
                    .context("alternate fallback row is missing")?;
                if alternate != u32::MAX {
                    name = pe_ir::NameId::from_u32(alternate);
                    continue;
                }
                break;
            }
        }
        Ok(demands)
    }
}

struct SelectedObjectMetadata<'a, 'data> {
    globals: &'a [pe_resolver::SelectedGlobalSymbol],
    weak: &'a linker_utils::coff_runtime::WeakExternalResolution,
    definition_names: HashSet<&'a [u8]>,
    dense: Option<&'a DenseProductionState<'data>>,
}

impl<'a, 'data> SelectedObjectMetadata<'a, 'data> {
    fn new_with_undefined(
        snapshot: &'a pe_resolver::SelectedSymbolSnapshot,
        roots: &[Vec<u8>],
        dense: Option<&'a DenseProductionState<'data>>,
    ) -> (Self, HashSet<Vec<u8>>) {
        let mut undefined = roots.iter().cloned().collect::<HashSet<_>>();
        let mut definitions = HashSet::new();
        for symbol in &snapshot.globals {
            let name = match dense {
                Some(dense) => dense
                    .names
                    .bytes(symbol.name_id)
                    .expect("resolver global NameId remains canonical"),
                #[cfg(test)]
                None => symbol.name.as_slice(),
                #[cfg(not(test))]
                None => unreachable!("production metadata requires dense canonical names"),
            };
            if symbol.is_definition || symbol.is_common {
                // Keep empty global definitions, matching object_definition_names.
                definitions.insert(name);
            } else if !name.is_empty() && symbol.is_undefined && !symbol.is_weak {
                undefined.insert(name.to_vec());
            }
        }
        undefined.retain(|name| !definitions.contains(name.as_slice()));
        (
            Self {
                globals: &snapshot.globals,
                weak: &snapshot.weak_resolution,
                definition_names: definitions,
                dense,
            },
            undefined,
        )
    }

    fn definition_names(&self) -> &HashSet<&'a [u8]> {
        &self.definition_names
    }

    fn weak(&self) -> &linker_utils::coff_runtime::WeakExternalResolution {
        self.weak
    }

    fn symbol_name<'symbol>(
        &'symbol self,
        symbol: &'symbol pe_resolver::SelectedGlobalSymbol,
    ) -> &'symbol [u8] {
        match self.dense {
            Some(dense) => dense
                .names
                .bytes(symbol.name_id)
                .expect("resolver global NameId remains canonical"),
            #[cfg(test)]
            None => symbol.name.as_slice(),
            #[cfg(not(test))]
            None => unreachable!("production metadata requires dense canonical names"),
        }
    }
}

#[cfg(test)]
fn selected_symbol_snapshot(
    objects: &[crate::coff::CoffObject<'_>],
) -> Result<pe_resolver::SelectedSymbolSnapshot> {
    let mut globals = Vec::new();
    let mut weak_resolution = linker_utils::coff_runtime::WeakExternalResolution::default();
    for (object_index, object) in objects.iter().enumerate() {
        for record in linker_utils::coff_runtime::parse_weak_externals(object.bytes())? {
            weak_resolution.apply(record, &format!("selected COFF object #{object_index}"))?;
        }
        for symbol in object.file().symbols() {
            let name = symbol.name_bytes().context("invalid COFF symbol name")?;
            if !symbol.is_global() {
                continue;
            }
            globals.push(pe_resolver::SelectedGlobalSymbol {
                object: object_index,
                index: symbol.index(),
                section: symbol.section_index(),
                section_kind: symbol.section(),
                address: symbol.address(),
                size: symbol.size(),
                is_definition: symbol.is_definition(),
                is_common: symbol.is_common(),
                is_undefined: symbol.is_undefined(),
                is_weak: symbol.is_weak(),
                name_id: pe_ir::NameId::from_u32(u32::MAX),
                name: name.to_vec(),
            });
        }
    }
    Ok(pe_resolver::SelectedSymbolSnapshot {
        globals,
        weak_resolution,
    })
}

#[cfg(test)]
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

fn absolute_symbol_values(
    _objects: &[crate::coff::CoffObject<'_>],
    metadata: &SelectedObjectMetadata<'_, '_>,
    runtime_resolution: &linker_utils::coff_runtime::RuntimeResolution,
) -> Result<HashMap<Vec<u8>, u64>> {
    let definitions = metadata.definition_names();
    let mut absolute = HashMap::new();
    for symbol in metadata.globals {
        if symbol.section_kind == object::SymbolSection::Absolute {
            let name = metadata.symbol_name(symbol);
            if !name.is_empty() {
                absolute.insert(name.to_vec(), symbol.address);
            }
        }
    }
    for symbol in LINKER_ABSOLUTE_ZERO_SYMBOLS {
        if !definitions.contains(*symbol) {
            absolute.insert(symbol.to_vec(), 0);
        }
    }

    let weak = metadata.weak();
    for (symbol, _, _) in weak.records() {
        if definitions.contains(symbol) {
            continue;
        }
        let target = weak.resolve(symbol, |candidate| definitions.contains(candidate))?;
        if let Some(value) = absolute.get(target).copied() {
            absolute.insert(symbol.to_vec(), value);
        }
    }
    for (symbol, _) in runtime_resolution.alternate_names() {
        if definitions.contains(symbol.as_bytes()) {
            continue;
        }
        let target = runtime_resolution.resolve_alternate_name(symbol, |candidate| {
            definitions.contains(candidate.as_bytes())
        })?;
        if let Some(value) = absolute.get(target.as_bytes()).copied() {
            absolute.insert(symbol.as_bytes().to_vec(), value);
        }
    }
    Ok(absolute)
}

#[cfg(test)]
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
    // Exercise the production dense GC path in unit-level image tests as well. Re-parsing retains
    // the caller's borrowed bytes while giving the resolver the owned vector it needs for archive
    // extraction (there are no archives in this helper).
    let mut dense_objects = objects
        .iter()
        .map(|object| crate::coff::CoffObject::parse(object.bytes()))
        .collect::<Result<Vec<_>>>()?;
    let mut resolver = pe_resolver::ResolverSession::new();
    let mut resolver_runtime = runtime_resolution.clone();
    resolver.resolve(&mut dense_objects, &[], &mut resolver_runtime)?;
    let resolved = resolver.finish();
    materialize_selected_object_indices(&dense_objects)?;
    let dense = DenseProductionState::finalize(&dense_objects, resolved.seed, &resolved.symbols)?;
    let (symbol_metadata, _) =
        SelectedObjectMetadata::new_with_undefined(&resolved.symbols, &[], Some(&dense));
    let mut image = build_image_with_delay_loads(
        objects,
        Some(&dense),
        &symbol_metadata,
        imports,
        exports,
        dll_name,
        entry_name,
        args,
        config,
        resources,
        runtime_resolution,
        &args.delay_load_dlls,
        &[],
    )?;
    image.finalize_repro_build_id()?;
    Ok(image)
}

fn build_image_with_delay_loads(
    objects: &[crate::coff::CoffObject<'_>],
    dense: Option<&DenseProductionState<'_>>,
    symbol_metadata: &SelectedObjectMetadata,
    imports: &[pe_imports::Import],
    exports: &[crate::args::coff::ExportSpec],
    dll_name: &[u8],
    entry_name: Option<&str>,
    args: &crate::args::coff::CoffArgs,
    config: PeWriterConfig,
    resources: &[ResourceRecord],
    runtime_resolution: &linker_utils::coff_runtime::RuntimeResolution,
    delay_load_dlls: &[String],
    selected_roots: &[Vec<u8>],
) -> Result<BuiltImage> {
    let (mut imports, mut delay_imports) =
        pe_imports::partition_delay_imports(imports.to_vec(), delay_load_dlls);
    // Retained only for the cfg(test) legacy differential path; production import liveness comes
    // directly from DenseEventGc without rebuilding a byte-owned definition set.
    #[cfg(not(test))]
    #[allow(clippy::no_effect_underscore_binding)]
    let _legacy_definition_names = pe_imports::definition_names;
    let comdat_phase = crate::timing_guard!(PE_PHASE_SELECT_COMDATS);
    let roots_phase = crate::timing_guard!(PE_DETAIL_ROOTS);
    // Archive selection and section GC deliberately remain separate: resolution must see every
    // undefined reference in order to extract the right archive members, while /OPT:REF only
    // decides which already-selected COMDAT contributions reach the image.
    let mut gc_roots = args
        .force_undefined
        .iter()
        .map(|symbol| symbol.as_bytes().to_vec())
        .collect::<Vec<_>>();
    gc_roots.extend_from_slice(selected_roots);
    gc_roots.extend(
        runtime_resolution
            .include_roots()
            .map(|symbol| symbol.as_bytes().to_vec()),
    );
    // CRT load configuration is loader metadata, not an ordinary relocation target. Retain it
    // when present even in direct unit-level image construction that has no archive root list.
    gc_roots.push(LOAD_CONFIG_SYMBOL.to_vec());
    if let Some(entry) = entry_name {
        gc_roots.push(entry.as_bytes().to_vec());
    }
    gc_roots.extend(
        exports
            .iter()
            .filter(|export| !looks_like_forwarder(export))
            .map(|export| export.target.as_bytes().to_vec()),
    );
    if !delay_imports.is_empty() {
        // This target exists only in linker-generated thunks, so /OPT:REF cannot discover it
        // through an input-object relocation graph.
        gc_roots.push(b"__delayLoadHelper2".to_vec());
    }
    gc_roots.sort();
    gc_roots.dedup();
    drop(roots_phase);
    let (mut contributions, comdat_redirects, dense_gc) =
        collect_contributions_with_roots_metadata(
            objects,
            symbol_metadata,
            args,
            &gc_roots,
            runtime_resolution,
        )?;
    if opt_ref_enabled(args) {
        let import_selection_phase = crate::timing_guard!(PE_DETAIL_IMPORT_SELECTION);
        let live_imports = if let (Some(dense), Some(gc)) = (dense, dense_gc.as_ref())
            && (dense.has_import_providers || imports.is_empty() && delay_imports.is_empty())
        {
            gc.referenced_import_names
                .iter()
                .map(|&name| {
                    dense
                        .names
                        .bytes(name)
                        .context("live import NameId has no canonical bytes")
                        .map(<[u8]>::to_vec)
                })
                .collect::<Result<HashSet<_>>>()?
        } else {
            #[cfg(test)]
            {
                let mut import_definitions = pe_imports::definition_names(&imports);
                import_definitions.extend(pe_imports::definition_names(&delay_imports));
                live_import_references(
                    objects,
                    symbol_metadata,
                    &contributions,
                    &gc_roots,
                    &import_definitions,
                    runtime_resolution,
                )?
            }
            #[cfg(not(test))]
            {
                return Err(error!(
                    "production /OPT:REF import retention requires dense provider state"
                ));
            }
        };
        pe_imports::retain_referenced(&mut imports, &live_imports);
        pe_imports::retain_referenced(&mut delay_imports, &live_imports);
        drop(import_selection_phase);
    }
    drop(comdat_phase);

    let mut layout_phase = crate::pe_timing_guard!(PE_PHASE_LAYOUT);
    layout_phase
        .0
        .add(crate::timing::PeMetric::Objects, objects.len());
    layout_phase
        .0
        .add(crate::timing::PeMetric::Sections, contributions.len());
    let mut layout_prepare_phase = crate::pe_timing_guard!(PE_DETAIL_LAYOUT_PREPARE);
    layout_prepare_phase
        .0
        .add(crate::timing::PeMetric::Sections, contributions.len());
    layout_prepare_phase.0.add(
        crate::timing::PeMetric::Imports,
        imports.len() + delay_imports.len(),
    );
    let absolute_symbols = absolute_symbol_values(objects, symbol_metadata, runtime_resolution)?;
    let has_tls_inputs = has_tls_contributions(objects, &contributions)?;
    let common_offsets = add_common_symbols(objects, symbol_metadata, &mut contributions)?;
    let (idata_size, thunk_size) = if imports.is_empty() {
        (0, 0)
    } else {
        pe_imports::section_sizes(&imports)?
    };
    let (didat_size, delay_thunk_size) = pe_imports::delay_section_sizes(&delay_imports)?;
    let (delay_pdata_size, delay_xdata_size) = pe_imports::delay_unwind_sizes(&delay_imports)?;
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
    let delay_thunk_id = add_synthetic(
        &mut contributions,
        b".text$wild_delay_imports",
        delay_thunk_size,
        text_characteristics(),
    )?;
    let didat_id = add_synthetic(
        &mut contributions,
        b".didat",
        didat_size,
        data_characteristics(),
    )?;
    let delay_xdata_id = add_synthetic(
        &mut contributions,
        b".rdata$wild_delay_unwind",
        delay_xdata_size,
        readonly_data_characteristics(),
    )?;
    let delay_pdata_id = add_synthetic(
        &mut contributions,
        b".pdata$wild_delay_unwind",
        delay_pdata_size,
        readonly_data_characteristics(),
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
    let dynamic_base = args.dynamic_base && !args.fixed;
    drop(layout_prepare_phase);
    let mut initial_layout_phase = crate::pe_timing_guard!(PE_DETAIL_LAYOUT_INITIAL);
    initial_layout_phase
        .0
        .add(crate::timing::PeMetric::Sections, contributions.len());
    let mut layout = make_layout(&contributions, config)?;
    initial_layout_phase
        .0
        .add_u64(crate::timing::PeMetric::Bytes, u64::from(layout.file_size));
    drop(initial_layout_phase);
    let mut relocation_layout_phase = crate::pe_timing_guard!(PE_DETAIL_LAYOUT_RELOCATIONS);
    relocation_layout_phase
        .0
        .add(crate::timing::PeMetric::Sections, contributions.len());
    let dir64_sites = if dynamic_base {
        discover_dir64_sites(objects, &contributions, &absolute_symbols)?
    } else {
        Vec::new()
    };
    let (next_layout, reloc_id, has_base_relocations, relocation_relayouts) = if dynamic_base {
        converge_relocation_layout(&mut contributions, layout, config, |layout| {
            let delay_iat_slots = delay_iat_slots(
                &delay_imports,
                didat_id,
                delay_thunk_id,
                layout,
                config.image_base,
            )?;
            let mut dir64 = dir64_rvas(&dir64_sites, layout)?;
            dir64.extend_from_slice(&delay_iat_slots);
            Ok(dir64)
        })?
    } else {
        (layout, None, false, 0)
    };
    relocation_layout_phase
        .0
        .add(crate::timing::PeMetric::Waves, relocation_relayouts);
    relocation_layout_phase
        .0
        .add(crate::timing::PeMetric::Relocations, dir64_sites.len());
    layout = next_layout;
    debug_assert!(relocation_relayouts <= MAX_RELOCATION_RELAYOUTS);
    drop(relocation_layout_phase);
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
    drop(layout_phase);

    let assemble_synthetic_phase = crate::timing_guard!(PE_PHASE_BUILD_SYNTHETIC);
    let emitted_delay_unwind = match (delay_thunk_id, delay_xdata_id, delay_pdata_id) {
        (Some(thunks), Some(xdata), Some(_)) => pe_imports::emit_delay_unwind(
            &delay_imports,
            layout.placements[&thunks].rva,
            layout.placements[&xdata].rva,
        )?,
        _ => pe_imports::DelayUnwindInfo::default(),
    };
    if let Some(id) = delay_xdata_id {
        contributions
            .iter_mut()
            .find(|contribution| contribution.spec.id == id)
            .unwrap()
            .synthetic_data = emitted_delay_unwind.xdata;
    }
    if let Some(id) = delay_pdata_id {
        contributions
            .iter_mut()
            .find(|contribution| contribution.spec.id == id)
            .unwrap()
            .synthetic_data = emitted_delay_unwind.pdata;
    }

    let eager_imports_phase = crate::timing_guard!(PE_DETAIL_BUILD_IMPORTS);
    let emitted_imports = match (idata_id, thunk_id) {
        (Some(idata), thunk) => pe_imports::emit(
            &imports,
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
            .synthetic_data = emitted_imports.idata.clone();
    }
    if let Some(id) = thunk_id {
        contributions
            .iter_mut()
            .find(|c| c.spec.id == id)
            .unwrap()
            .synthetic_data = emitted_imports.thunks.clone();
    }
    drop(eager_imports_phase);
    // Produce a first deterministic delay image to publish its synthetic definitions before
    // ordinary COFF relocations are resolved. The helper call is patched after definitions are
    // known below.
    let delay_imports_phase = crate::timing_guard!(PE_DETAIL_BUILD_DELAY_IMPORTS);
    let mut emitted_delay_imports = match (didat_id, delay_thunk_id) {
        (Some(didat), Some(thunks)) => pe_imports::emit_delay(
            &delay_imports,
            layout.placements[&didat].rva,
            layout.placements[&thunks].rva,
            layout.size_of_image,
            config.image_base,
            0,
        )?,
        _ => pe_imports::EmittedDelayImports::default(),
    };
    if let Some(id) = didat_id {
        contributions
            .iter_mut()
            .find(|c| c.spec.id == id)
            .unwrap()
            .synthetic_data = emitted_delay_imports.didat.clone();
    }
    if let Some(id) = delay_thunk_id {
        contributions
            .iter_mut()
            .find(|c| c.spec.id == id)
            .unwrap()
            .synthetic_data = emitted_delay_imports.thunks.clone();
    }
    drop(delay_imports_phase);
    let resources_phase = crate::timing_guard!(PE_DETAIL_BUILD_RESOURCES);
    let resource_directory = if let Some(id) = resource_id {
        let section = linker_utils::pe_resources::build_resource_section(
            resources,
            layout.placements[&id].rva,
        )
        .context("failed to build PE resource directory")?;
        let contribution = contributions.iter_mut().find(|c| c.spec.id == id).unwrap();
        ensure!(
            section.bytes.len() == contribution.synthetic_data.len(),
            "PE resource section changed size after layout"
        );
        contribution.synthetic_data.copy_from_slice(&section.bytes);
        Some((section.data_directory.rva, section.data_directory.size))
    } else {
        None
    };
    drop(resources_phase);
    drop(assemble_synthetic_phase);

    let definitions_phase = crate::timing_guard!(PE_PHASE_DEFINE_SYMBOLS);
    let (locations, mut definitions) = definitions(
        objects,
        symbol_metadata,
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
    for (name, rva) in &emitted_delay_imports.symbols {
        definitions
            .entry(name.clone())
            .or_insert(config.image_base + u64::from(*rva));
    }
    add_image_base_symbol(&mut definitions, config.image_base);
    for (symbol, value) in &absolute_symbols {
        definitions.entry(symbol.clone()).or_insert(*value);
    }
    bind_weak_externals(objects, symbol_metadata, &mut definitions)?;
    bind_alternate_names(&mut definitions, runtime_resolution)?;
    if !delay_imports.is_empty() {
        let helper_va = definitions
            .get(b"__delayLoadHelper2".as_slice())
            .copied()
            .context("/DELAYLOAD requires __delayLoadHelper2 from delayimp.lib")?;
        let helper_rva = u32::try_from(
            helper_va
                .checked_sub(config.image_base)
                .context("__delayLoadHelper2 precedes image base")?,
        )
        .context("__delayLoadHelper2 lies outside image")?;
        let didat = didat_id.unwrap();
        let thunks = delay_thunk_id.unwrap();
        emitted_delay_imports = pe_imports::emit_delay(
            &delay_imports,
            layout.placements[&didat].rva,
            layout.placements[&thunks].rva,
            layout.size_of_image,
            config.image_base,
            helper_rva,
        )?;
        contributions
            .iter_mut()
            .find(|c| c.spec.id == didat)
            .unwrap()
            .synthetic_data = emitted_delay_imports.didat.clone();
        contributions
            .iter_mut()
            .find(|c| c.spec.id == thunks)
            .unwrap()
            .synthetic_data = emitted_delay_imports.thunks.clone();
    }
    let load_config_directory = load_config_directory(
        objects,
        &contributions,
        &locations,
        &layout,
        &definitions,
        config.image_base,
    )?;
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
            directory.bytes.len() <= contribution.synthetic_data.len(),
            "PE export directory exceeded its reserved size"
        );
        contribution.synthetic_data[..directory.bytes.len()].copy_from_slice(&directory.bytes);
        Some(directory)
    } else {
        None
    };
    drop(definitions_phase);

    let mut assemble_image_phase = crate::pe_timing_guard!(PE_PHASE_COPY_IMAGE);
    assemble_image_phase
        .0
        .add(crate::timing::PeMetric::Sections, contributions.len());
    assemble_image_phase
        .0
        .add_u64(crate::timing::PeMetric::Bytes, u64::from(layout.file_size));
    let mut image_allocate_phase = crate::pe_timing_guard!(PE_DETAIL_IMAGE_ALLOCATE);
    image_allocate_phase
        .0
        .add_u64(crate::timing::PeMetric::Bytes, u64::from(layout.file_size));
    count_pe_hot_allocation();
    let mut image = vec![0; layout.file_size as usize];
    drop(image_allocate_phase);
    let mut image_copy_phase = crate::pe_timing_guard!(PE_DETAIL_IMAGE_COPY);
    image_copy_phase
        .0
        .add(crate::timing::PeMetric::Sections, contributions.len());
    let mut synthetic_bytes = 0usize;
    for contribution in &contributions {
        if !matches!(contribution.source, Source::Synthetic) {
            continue;
        }
        let placement = &layout.placements[&contribution.spec.id];
        if let Some(file_offset) = placement.file_offset {
            let start = file_offset as usize;
            image[start..start + contribution.synthetic_data.len()]
                .copy_from_slice(&contribution.synthetic_data);
            synthetic_bytes += contribution.synthetic_data.len();
            count_pe_bytes_copied(contribution.synthetic_data.len());
        }
    }
    image_copy_phase
        .0
        .add(crate::timing::PeMetric::Bytes, synthetic_bytes);
    drop(image_copy_phase);
    drop(assemble_image_phase);

    let mut dense_targets_phase =
        crate::pe_timing_guard!("PE relocations: Build dense section targets");
    dense_targets_phase
        .0
        .add(crate::timing::PeMetric::Sections, contributions.len());
    let dense_targets = dense
        .map(|dense| {
            dense_section_targets(
                dense,
                &contributions,
                &layout,
                &comdat_redirects,
                dense_gc.as_ref(),
            )
        })
        .transpose()?;
    drop(dense_targets_phase);

    let mut relocations_phase = crate::pe_timing_guard!(PE_PHASE_APPLY_RELOCATIONS);
    relocations_phase
        .0
        .add(crate::timing::PeMetric::Sections, contributions.len());
    if relocations_phase.0.enabled() {
        relocations_phase.0.add(
            crate::timing::PeMetric::Relocations,
            dense.map_or(0, |dense| dense.ir.relocations.records.len()),
        );
    }
    copy_and_apply_relocations(
        objects,
        dense,
        &contributions,
        &layout,
        &locations,
        &comdat_redirects,
        dense_gc.as_ref(),
        dense_targets.as_deref(),
        &definitions,
        &absolute_symbols,
        config.image_base,
        &mut image,
    )?;
    drop(relocations_phase);

    let final_image_phase = crate::timing_guard!(PE_PHASE_FINALIZE_IMAGE);
    let tls_phase = crate::timing_guard!(PE_DETAIL_TLS_DIRECTORY);
    let tls_directory = prepare_tls_directory(
        objects,
        &contributions,
        &layout,
        &definitions,
        &dir64_rvas(&dir64_sites, &layout)?,
        config.image_base,
        dynamic_base,
        has_tls_inputs,
        &mut image,
    )?;
    drop(tls_phase);
    let exception_phase = crate::timing_guard!(PE_DETAIL_EXCEPTION_DIRECTORY);
    let exception_directory = canonicalize_exception_directory(&mut image, &layout, args)?;
    drop(exception_phase);
    let debug_directory_phase = crate::timing_guard!(PE_DETAIL_DEBUG_DIRECTORY);
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
    drop(debug_directory_phase);
    let headers_phase = crate::timing_guard!(PE_DETAIL_WRITE_HEADERS);
    write_headers(
        &mut image,
        &layout,
        args,
        config,
        entry_rva,
        entry_name,
        emitted_imports.import_directory,
        emitted_imports.iat_directory,
        emitted_delay_imports.directory,
        reloc_id.is_some() && has_base_relocations,
        export_directory
            .as_ref()
            .map(|directory| (directory.rva, directory.size)),
        resource_directory,
        exception_directory,
        tls_directory,
        debug_directory,
        load_config_directory,
    );
    drop(headers_phase);
    let pending_repro_build_id = if let Some(id) = debug_id {
        let placement = &layout.placements[&id];
        let file_offset = placement.file_offset.unwrap();
        let start = usize::try_from(file_offset).context("debug file offset exceeds usize")?;
        let payload_start = start
            .checked_add(linker_utils::pe_debug::IMAGE_DEBUG_DIRECTORY_SIZE)
            .context("REPRO build-id payload offset overflow")?;
        let payload_end = payload_start
            .checked_add(linker_utils::pe_debug::REPRO_BUILD_ID_SIZE)
            .context("REPRO build-id payload range overflow")?;
        Some(PendingReproBuildId::new(
            &image,
            payload_start..payload_end,
        )?)
    } else {
        None
    };
    drop(final_image_phase);
    Ok(BuiltImage {
        bytes: image,
        exports: export_directory.map_or_else(Vec::new, |directory| directory.exports),
        pending_repro_build_id,
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

fn delay_iat_slots(
    imports: &[pe_imports::Import],
    didat_id: Option<ContributionId>,
    thunk_id: Option<ContributionId>,
    layout: &SectionLayout,
    image_base: u64,
) -> Result<Vec<u32>> {
    match (didat_id, thunk_id) {
        (Some(didat), Some(thunks)) => Ok(pe_imports::emit_delay(
            imports,
            layout.placements[&didat].rva,
            layout.placements[&thunks].rva,
            layout.size_of_image,
            image_base,
            0,
        )?
        .iat_slots),
        _ => Ok(Vec::new()),
    }
}

fn bind_weak_externals(
    _objects: &[crate::coff::CoffObject<'_>],
    metadata: &SelectedObjectMetadata,
    definitions: &mut HashMap<Vec<u8>, u64>,
) -> Result<()> {
    let weak = metadata.weak();
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
    let pdata_file = pdata
        .file_offset
        .context(".pdata unexpectedly has no file contents")? as usize;
    let pdata_size = usize::try_from(pdata.virtual_size).context(".pdata size exceeds usize")?;
    let pdata_bytes = image
        .get(pdata_file..pdata_file + pdata_size)
        .context(".pdata lies outside the PE file")?
        .to_vec();
    let table = linker_utils::pe_unwind::sort_amd64_exception_table(
        &pdata_bytes,
        pdata.rva,
        layout.size_of_image,
    )
    .context("invalid AMD64 exception table")?;
    let output = image
        .get_mut(pdata_file..pdata_file + pdata_size)
        .context(".pdata lies outside the PE file")?;
    output.fill(0);
    output[..table.pdata.len()].copy_from_slice(&table.pdata);
    Ok(Some((table.directory.rva, table.directory.size)))
}

fn load_config_directory(
    objects: &[crate::coff::CoffObject<'_>],
    contributions: &[Contribution],
    locations: &LocationMap,
    layout: &SectionLayout,
    definitions: &HashMap<Vec<u8>, u64>,
    image_base: u64,
) -> Result<Option<(u32, u32)>> {
    let Some(&selected_va) = definitions.get(LOAD_CONFIG_SYMBOL) else {
        return Ok(None);
    };
    for (object_index, object) in objects.iter().enumerate() {
        for symbol in object.file().symbols() {
            if !symbol.is_global() || symbol.name_bytes()? != LOAD_CONFIG_SYMBOL {
                continue;
            }
            let Some(section_index) = symbol.section_index() else {
                continue;
            };
            let Some(id) = locations.get(&(object_index, section_index)) else {
                continue;
            };
            let placement = &layout.placements[id];
            let symbol_offset = u32::try_from(symbol.address())
                .context("`_load_config_used` section offset exceeds u32")?;
            let symbol_rva = placement
                .rva
                .checked_add(symbol_offset)
                .context("`_load_config_used` RVA overflow")?;
            if image_base + u64::from(symbol_rva) != selected_va {
                continue;
            }

            let contribution = contributions
                .iter()
                .find(|contribution| contribution.spec.id == *id)
                .context("`_load_config_used` contribution disappeared")?;
            ensure!(
                contribution.spec.kind == ContributionKind::Data,
                "`_load_config_used` points to uninitialized data"
            );
            let section = object
                .file()
                .section_by_index(section_index)
                .context("`_load_config_used` references an invalid section")?;
            let data = section
                .data()
                .context("`_load_config_used` points to uninitialized data")?;
            let offset = usize::try_from(symbol.address())
                .context("`_load_config_used` section offset exceeds usize")?;
            let size_field_end = offset
                .checked_add(4)
                .context("`_load_config_used` section offset overflow")?;
            let size_field = data
                .get(offset..size_field_end)
                .context("`_load_config_used` section is too small")?;
            let size = u32::from_le_bytes(size_field.try_into().unwrap());
            let end = symbol_offset
                .checked_add(size)
                .context("`_load_config_used` size overflow")?;
            ensure!(
                u64::from(end) <= section.size(),
                "`_load_config_used` declares size {size} beyond its containing section"
            );
            ensure!(
                symbol_rva
                    .checked_add(size)
                    .is_some_and(|end| end <= layout.size_of_image),
                "`_load_config_used` extends beyond the PE image"
            );
            return Ok(Some((symbol_rva, size)));
        }
    }
    Ok(None)
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

#[cfg(test)]
fn collect_contributions(
    objects: &[crate::coff::CoffObject<'_>],
    args: &crate::args::coff::CoffArgs,
) -> Result<(Vec<Contribution>, SectionRedirects)> {
    let snapshot = selected_symbol_snapshot(objects)?;
    let (metadata, _) = SelectedObjectMetadata::new_with_undefined(&snapshot, &[], None);
    let (contributions, redirects, _) = collect_contributions_with_roots_metadata(
        objects,
        &metadata,
        args,
        &[],
        &args.runtime_resolution,
    )?;
    Ok((contributions, redirects))
}

#[cfg(test)]
fn collect_contributions_with_roots(
    objects: &[crate::coff::CoffObject<'_>],
    args: &crate::args::coff::CoffArgs,
    roots: &[Vec<u8>],
    runtime_resolution: &linker_utils::coff_runtime::RuntimeResolution,
) -> Result<(Vec<Contribution>, SectionRedirects)> {
    let snapshot = selected_symbol_snapshot(objects)?;
    let (metadata, _) = SelectedObjectMetadata::new_with_undefined(&snapshot, &[], None);
    let (contributions, redirects, _) = collect_contributions_with_roots_metadata(
        objects,
        &metadata,
        args,
        roots,
        runtime_resolution,
    )?;
    Ok((contributions, redirects))
}

fn collect_contributions_with_roots_metadata(
    objects: &[crate::coff::CoffObject<'_>],
    metadata: &SelectedObjectMetadata,
    args: &crate::args::coff::CoffArgs,
    roots: &[Vec<u8>],
    _runtime_resolution: &linker_utils::coff_runtime::RuntimeResolution,
) -> Result<(Vec<Contribution>, SectionRedirects, Option<pe_gc::GcOutput>)> {
    if args.guard.control_flow == crate::args::coff::OptSetting::Enabled {
        return Err(error!(
            "explicit /GUARD:CF is not yet supported; refusing to emit incomplete CFG/load-config metadata"
        ));
    }
    let mut output = Vec::new();
    #[allow(unused_mut)]
    let mut comdats = discarded_comdat_sections_with_metadata(objects, metadata)?;
    let dense_gc = if opt_ref_enabled(args) {
        if let Some(dense) = metadata.dense {
            Some(collect_dense_gc(dense, &comdats, roots)?)
        } else {
            #[cfg(test)]
            comdats.discarded.extend(unreferenced_comdat_sections(
                objects,
                metadata,
                &comdats,
                roots,
                _runtime_resolution,
            )?);
            #[cfg(test)]
            {
                None
            }
            #[cfg(not(test))]
            {
                return Err(error!("production /OPT:REF requires dense PE state"));
            }
        }
    } else {
        None
    };
    let dense_view = metadata.dense.map(|dense| (&dense.ir, dense_gc.as_ref()));
    let mut contributions_phase = crate::pe_timing_guard!(PE_DETAIL_CONTRIBUTIONS);
    contributions_phase
        .0
        .add(crate::timing::PeMetric::Objects, objects.len());
    if rayon::current_num_threads() == 1 {
        // Avoid Rayon and retaining every per-object descriptor vector at once for the required
        // single-thread baseline. IDs are assigned authoritatively after empty-group filtering.
        for (object_index, input) in objects.iter().enumerate() {
            materialize_object_contributions_into(
                object_index,
                input,
                &comdats,
                args,
                dense_view,
                &mut output,
            )?;
        }
    } else {
        // Each object owns its input sections, payload copies and result vector. Indexed collection
        // keeps the slots in input order; unwrapping them serially preserves the first object-order
        // diagnostic, and ordered flattening restores the original object/section contribution
        // order exactly.
        let object_results = objects
            .par_iter()
            .enumerate()
            .map(|(object_index, input)| {
                materialize_object_contributions(object_index, input, &comdats, args, dense_view)
            })
            .collect::<Vec<_>>();
        let object_contributions = object_results
            .into_iter()
            .collect::<Result<Vec<Vec<Contribution>>>>()?;
        let contribution_count = object_contributions.iter().map(Vec::len).sum();
        output.reserve(contribution_count);
        for contributions in object_contributions {
            output.extend(contributions);
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
    contributions_phase
        .0
        .add(crate::timing::PeMetric::Sections, output.len());
    drop(contributions_phase);
    Ok((output, comdats.redirects, dense_gc))
}

fn materialize_object_contributions(
    object_index: usize,
    input: &crate::coff::CoffObject<'_>,
    comdats: &ComdatResolution,
    args: &crate::args::coff::CoffArgs,
    dense_view: Option<(&pe_ir::PeIr<'_>, Option<&pe_gc::GcOutput>)>,
) -> Result<Vec<Contribution>> {
    let mut output = Vec::new();
    materialize_object_contributions_into(
        object_index,
        input,
        comdats,
        args,
        dense_view,
        &mut output,
    )?;
    Ok(output)
}

fn materialize_object_contributions_into(
    object_index: usize,
    input: &crate::coff::CoffObject<'_>,
    comdats: &ComdatResolution,
    args: &crate::args::coff::CoffArgs,
    dense_view: Option<(&pe_ir::PeIr<'_>, Option<&pe_gc::GcOutput>)>,
    output: &mut Vec<Contribution>,
) -> Result<()> {
    for section in input.file().sections() {
        let raw_name = section.name_bytes().context("invalid COFF section name")?;
        let flags = match section.flags() {
            SectionFlags::Coff { characteristics } => characteristics.0,
            _ => 0,
        };
        let class = linker_utils::coff_symbols::classify_section(flags)
            .context("invalid COFF section flags")?;
        if guard_metadata_policy(raw_name, args.guard.control_flow)? == GuardMetadataPolicy::Discard
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
        let dense_section = if let Some((ir, gc)) = dense_view {
            let dense = ir
                .section_by_raw(
                    pe_ir::ObjectId::from_u32(
                        u32::try_from(object_index).context("PE object index exceeds u32")?,
                    ),
                    u32::try_from(section.index().0)
                        .context("raw COFF section index exceeds u32")?,
                )
                .context("COFF contribution has no dense section")?;
            if gc.is_some_and(|gc| !gc.is_live(dense)) {
                continue;
            }
            Some(dense)
        } else {
            None
        };
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
        if kind != ContributionKind::Bss {
            let data = section.data().context("invalid COFF section contents")?;
            ensure!(
                data.len() == size as usize,
                "COFF section contents differ from section size"
            );
        }
        let alignment =
            u32::try_from(section.align().max(1)).context("COFF section alignment too large")?;
        output.push(Contribution {
            source: Source::Object {
                object: object_index,
                section: section.index(),
            },
            dense_section,
            spec: SectionContribution {
                // This ID is provisional in parallel object-local vectors. Empty-output-group
                // filtering below assigns compact, globally ordered IDs before any downstream
                // consumer observes the contributions.
                id: ContributionId(output.len() as u32),
                name,
                characteristics: output_characteristics(flags),
                alignment,
                size,
                kind,
            },
            synthetic_data: Vec::new(),
        });
    }
    Ok(())
}

fn opt_ref_enabled(args: &crate::args::coff::CoffArgs) -> bool {
    match args.optimization.ref_ {
        crate::args::coff::OptSetting::Enabled => true,
        crate::args::coff::OptSetting::Disabled => false,
        // lld-link enables REF for ordinary release links and disables it when /DEBUG is
        // present. An explicit /OPT setting above always wins over that profile default.
        crate::args::coff::OptSetting::Default => !args.debug,
    }
}

#[cfg(test)]
fn live_import_references(
    objects: &[crate::coff::CoffObject<'_>],
    metadata: &SelectedObjectMetadata,
    contributions: &[Contribution],
    roots: &[Vec<u8>],
    import_definitions: &HashSet<Vec<u8>>,
    runtime_resolution: &linker_utils::coff_runtime::RuntimeResolution,
) -> Result<HashSet<Vec<u8>>> {
    let object_definitions = metadata.definition_names();
    let weak_resolution = metadata.weak();
    live_import_references_with_resolution(
        objects,
        contributions,
        roots,
        object_definitions,
        import_definitions,
        weak_resolution,
        runtime_resolution,
    )
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn retain_live_import_reference(
    name: &[u8],
    object_definitions: &HashSet<&[u8]>,
    import_definitions: &HashSet<Vec<u8>>,
    weak_resolution: &linker_utils::coff_runtime::WeakExternalResolution,
    runtime_resolution: &linker_utils::coff_runtime::RuntimeResolution,
    referenced: &mut HashSet<Vec<u8>>,
) -> Result<()> {
    let is_selected = |candidate: &[u8]| {
        object_definitions.contains(candidate) || import_definitions.contains(candidate)
    };
    let target = if is_selected(name) {
        name
    } else {
        let weak_target = weak_resolution.resolve(name, is_selected)?;
        if is_selected(weak_target) {
            weak_target
        } else {
            let Ok(name) = std::str::from_utf8(name) else {
                return Ok(());
            };
            runtime_resolution
                .resolve_alternate_name(name, |candidate| is_selected(candidate.as_bytes()))?
                .as_bytes()
        }
    };
    if import_definitions.contains(target) {
        referenced.insert(target.to_vec());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn collect_live_import_references(
    objects: &[crate::coff::CoffObject<'_>],
    contributions: &[Contribution],
    object_definitions: &HashSet<&[u8]>,
    import_definitions: &HashSet<Vec<u8>>,
    weak_resolution: &linker_utils::coff_runtime::WeakExternalResolution,
    runtime_resolution: &linker_utils::coff_runtime::RuntimeResolution,
) -> Result<HashSet<Vec<u8>>> {
    let mut referenced = HashSet::new();
    for contribution in contributions {
        let Source::Object { object, section } = contribution.source else {
            continue;
        };
        let section = objects[object]
            .file()
            .section_by_index(section)
            .context("live contribution has an invalid source section")?;
        for (_, relocation) in section.relocations() {
            count_pe_relocation_decode();
            let RelocationTarget::Symbol(symbol) = relocation.target() else {
                continue;
            };
            let symbol = objects[object]
                .file()
                .symbol_by_index(symbol)
                .context("live relocation has an invalid symbol")?;
            if symbol.is_global() && symbol.section_index().is_none() {
                retain_live_import_reference(
                    symbol.name_bytes()?,
                    object_definitions,
                    import_definitions,
                    weak_resolution,
                    runtime_resolution,
                    &mut referenced,
                )?;
            }
        }
    }
    Ok(referenced)
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn live_import_references_with_resolution(
    objects: &[crate::coff::CoffObject<'_>],
    contributions: &[Contribution],
    roots: &[Vec<u8>],
    object_definitions: &HashSet<&[u8]>,
    import_definitions: &HashSet<Vec<u8>>,
    weak_resolution: &linker_utils::coff_runtime::WeakExternalResolution,
    runtime_resolution: &linker_utils::coff_runtime::RuntimeResolution,
) -> Result<HashSet<Vec<u8>>> {
    // Roots are few, already ordered and independent of contribution work. Keep their processing
    // serial so fallback-cycle diagnostics retain their established order.
    let mut referenced = HashSet::new();
    for root in roots {
        retain_live_import_reference(
            root,
            object_definitions,
            import_definitions,
            weak_resolution,
            runtime_resolution,
            &mut referenced,
        )?;
    }

    let thread_count = rayon::current_num_threads();
    if thread_count == 1 || contributions.len() <= LIVE_IMPORT_MIN_CONTRIBUTIONS_PER_CHUNK {
        referenced.extend(collect_live_import_references(
            objects,
            contributions,
            object_definitions,
            import_definitions,
            weak_resolution,
            runtime_resolution,
        )?);
        return Ok(referenced);
    }

    let target_chunks = thread_count.saturating_mul(LIVE_IMPORT_CHUNKS_PER_THREAD);
    let chunk_size = contributions
        .len()
        .div_ceil(target_chunks)
        .max(LIVE_IMPORT_MIN_CONTRIBUTIONS_PER_CHUNK);
    // `par_chunks` is indexed. Each chunk preserves contribution and relocation order, and the
    // collected slots are unwrapped serially below. Thus malformed-input diagnostics still select
    // the first contribution-order error even though successful chunks run concurrently.
    let chunk_results = contributions
        .par_chunks(chunk_size)
        .map(|chunk| {
            collect_live_import_references(
                objects,
                chunk,
                object_definitions,
                import_definitions,
                weak_resolution,
                runtime_resolution,
            )
        })
        .collect::<Vec<_>>();
    for chunk in chunk_results {
        referenced.extend(chunk?);
    }
    Ok(referenced)
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

type ObjectSectionKey = (usize, object::SectionIndex);
type SectionRedirects = HashMap<ObjectSectionKey, ObjectSectionKey>;
type SectionNode = usize;
type ComdatGroupId = usize;

#[derive(Debug, Default)]
struct CompactComdatAnalysis {
    keys: Vec<ObjectSectionKey>,
    nodes_by_object: Vec<Vec<Option<SectionNode>>>,
    is_comdat: Vec<bool>,
    groups: Vec<Vec<SectionNode>>,
    group_by_node: Vec<ComdatGroupId>,
}

impl CompactComdatAnalysis {
    fn new(
        objects: &[crate::coff::CoffObject<'_>],
        section_groups: &[HashMap<object::SectionIndex, CachedComdatGroup>],
    ) -> Result<Self> {
        let mut analysis = Self {
            nodes_by_object: Vec::with_capacity(objects.len()),
            ..Self::default()
        };
        for (object_index, object) in objects.iter().enumerate() {
            let section_count = object.file().sections().count();
            let mut nodes = vec![None; section_count.saturating_add(1)];
            for section in object.file().sections() {
                let index = section.index();
                if index.0 >= nodes.len() {
                    nodes.resize(index.0 + 1, None);
                }
                let node = analysis.keys.len();
                nodes[index.0] = Some(node);
                analysis.keys.push((object_index, index));
                analysis.is_comdat.push(match section.flags() {
                    SectionFlags::Coff { characteristics } => {
                        characteristics.0 & object::pe::IMAGE_SCN_LNK_COMDAT.0 != 0
                    }
                    _ => false,
                });
            }
            analysis.nodes_by_object.push(nodes);
        }
        analysis.group_by_node = vec![usize::MAX; analysis.keys.len()];

        // Walk leaders in object section order. Group IDs therefore remain deterministic even
        // though the cached lookup itself is a HashMap.
        for (object_index, object) in objects.iter().enumerate() {
            for section in object.file().sections() {
                let Some(group) = section_groups[object_index].get(&section.index()) else {
                    continue;
                };
                let group_id = analysis.groups.len();
                let mut members = Vec::with_capacity(group.sections.len());
                for &member in &group.sections {
                    let node = analysis
                        .node((object_index, member))
                        .context("COMDAT group refers to an invalid section")?;
                    ensure!(
                        analysis.group_by_node[node] == usize::MAX,
                        "COFF section belongs to multiple COMDAT groups"
                    );
                    analysis.group_by_node[node] = group_id;
                    members.push(node);
                }
                analysis.groups.push(members);
            }
        }
        // Ordinary sections, and defensive fallback COMDATs without an auxiliary group, are
        // singleton reachability units.
        for node in 0..analysis.keys.len() {
            if analysis.group_by_node[node] != usize::MAX {
                continue;
            }
            let group_id = analysis.groups.len();
            analysis.group_by_node[node] = group_id;
            analysis.groups.push(vec![node]);
        }
        Ok(analysis)
    }

    fn node(&self, (object, section): ObjectSectionKey) -> Option<SectionNode> {
        self.nodes_by_object
            .get(object)?
            .get(section.0)
            .copied()
            .flatten()
    }
}

#[derive(Debug, Default)]
struct ComdatResolution {
    discarded: HashSet<ObjectSectionKey>,
    redirects: SectionRedirects,
    analysis: CompactComdatAnalysis,
}

/// Convert COMDAT analysis directly into dense arrays. CompactComdatAnalysis and PeIr are both
/// finalized in selected-object/raw-section order; validate that invariant before treating an
/// analysis node as its SectionId, so a future ordering change fails safely rather than mislinks.
fn collect_dense_gc(
    dense: &DenseProductionState<'_>,
    comdats: &ComdatResolution,
    roots: &[Vec<u8>],
) -> Result<pe_gc::GcOutput> {
    let mut input_phase = crate::pe_timing_guard!("PE dense GC: Construct direct input");
    input_phase
        .0
        .add(crate::timing::PeMetric::Sections, dense.ir.sections.len());
    input_phase.0.add(
        crate::timing::PeMetric::Groups,
        comdats.analysis.groups.len(),
    );
    input_phase
        .0
        .add(crate::timing::PeMetric::Names, dense.names.len());
    input_phase.0.add(
        crate::timing::PeMetric::Relocations,
        dense.ir.relocations.records.len(),
    );

    ensure!(
        comdats.analysis.keys.len() == dense.ir.sections.len(),
        "COMDAT analysis/dense section cardinality mismatch"
    );
    let mut redirect_targets = (0..dense.ir.sections.len())
        .map(|index| pe_ir::SectionId::from_u32(index as u32))
        .collect::<Vec<_>>();
    let mut discarded = vec![false; dense.ir.sections.len()];
    for (node, (&key, section)) in comdats
        .analysis
        .keys
        .iter()
        .zip(dense.ir.sections.iter())
        .enumerate()
    {
        ensure!(
            key.0 == section.object.index() && key.1.0 == section.raw_index as usize,
            "COMDAT analysis node order differs from dense SectionId order"
        );
        discarded[node] = comdats.discarded.contains(&key);
        if let Some(&target) = comdats.redirects.get(&key) {
            let target_node = comdats
                .analysis
                .node(target)
                .context("COMDAT redirect target has no analysis node")?;
            redirect_targets[node] = pe_ir::SectionId::from_u32(
                u32::try_from(target_node).context("redirect target exceeds dense ID range")?,
            );
        }
    }

    let mut root_names = Vec::with_capacity(roots.len());
    for root in roots {
        let hash = crate::hash::hash_bytes(root);
        if let Some(name) = dense.names.lookup_prehashed(root, hash) {
            root_names.push(name);
        }
    }

    let mut groups = Vec::with_capacity(comdats.analysis.groups.len());
    let mut group_members = Vec::new();
    for group in &comdats.analysis.groups {
        let start = u32::try_from(group_members.len()).context("too many COMDAT group members")?;
        for &node in group {
            group_members.push(pe_ir::SectionId::from_u32(
                u32::try_from(node).context("COMDAT node exceeds dense ID range")?,
            ));
        }
        let Some(&leader) = group_members.get(start as usize) else {
            return Err(error!("empty COMDAT reachability group"));
        };
        groups.push(pe_gc::SectionGroup {
            leader,
            member_start: start,
            member_len: u32::try_from(group.len()).context("COMDAT group is too large")?,
        });
    }
    let collector = pe_gc::DenseEventGc::new_resolved(
        &dense.ir,
        &dense.alternate_targets,
        &dense.resolved_targets,
    );
    input_phase
        .0
        .add(crate::timing::PeMetric::Events, comdats.redirects.len());
    collector.collect_production(pe_gc::ProductionGcInput {
        redirect_targets,
        discarded,
        is_comdat: &comdats.analysis.is_comdat,
        root_names: &root_names,
        groups: &groups,
        group_members: &group_members,
    })
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
) {
    let Some((&loser_primary, loser_children)) = loser_sections.split_first() else {
        return;
    };
    let Some((&winner_primary, winner_children)) = winner_sections.split_first() else {
        return;
    };
    redirects.insert(
        (loser_object, loser_primary),
        (winner_object, winner_primary),
    );

    // Match children by both section name and direct association parent. This preserves nested
    // association topology even when two objects order same-named children differently. The
    // sets of associates need not be identical: link.exe and lld-link discard all associates of
    // the losing leader, retain all associates of the winner, and only redirect losing sections
    // for which the winner has an equivalent. In particular, MSVC libraries can emit an extra
    // `.voltbl` associate in one copy of an otherwise duplicate inline function.
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
                            && winner_parents.get(*winner) == Some(&Some(mapped_parent))
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
}

#[cfg(test)]
fn discarded_comdat_sections(objects: &[crate::coff::CoffObject<'_>]) -> Result<ComdatResolution> {
    let snapshot = selected_symbol_snapshot(objects)?;
    let (metadata, _) = SelectedObjectMetadata::new_with_undefined(&snapshot, &[], None);
    discarded_comdat_sections_with_metadata(objects, &metadata)
}

fn discarded_comdat_sections_with_metadata(
    objects: &[crate::coff::CoffObject<'_>],
    metadata: &SelectedObjectMetadata,
) -> Result<ComdatResolution> {
    use linker_utils::coff_symbols::ComdatCandidate;
    use linker_utils::coff_symbols::ComdatDecision;
    use linker_utils::coff_symbols::ComdatSelection;
    use linker_utils::coff_symbols::select_comdat;

    let mut classify_phase = crate::pe_timing_guard!(PE_DETAIL_COMDAT_CLASSIFY);
    classify_phase
        .0
        .add(crate::timing::PeMetric::Objects, objects.len());
    // Classifying one object's COMDAT topology neither reads nor mutates another object's
    // state. Keep the indexed result slots in input order, then unwrap them serially so a
    // malformed input still reports the first object-order error regardless of thread count.
    let section_group_results = objects
        .par_iter()
        .map(|input| cached_comdat_sections(input.file()))
        .collect::<Vec<_>>();
    let section_groups = section_group_results
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    let analysis = CompactComdatAnalysis::new(objects, &section_groups)?;
    classify_phase
        .0
        .add(crate::timing::PeMetric::Sections, analysis.keys.len());
    classify_phase
        .0
        .add(crate::timing::PeMetric::Groups, analysis.groups.len());
    let mut strong_definitions = HashSet::<Vec<u8>>::new();
    for symbol in metadata.globals {
        if !symbol.is_definition {
            continue;
        }
        if symbol
            .section
            .and_then(|section| analysis.node((symbol.object, section)))
            .is_some_and(|node| analysis.is_comdat[node])
        {
            continue;
        }
        strong_definitions.insert(metadata.symbol_name(symbol).to_vec());
    }
    drop(classify_phase);

    let mut selection_phase = crate::pe_timing_guard!(PE_DETAIL_COMDAT_SELECT);
    selection_phase
        .0
        .add(crate::timing::PeMetric::Objects, objects.len());
    let mut selected = HashMap::<Vec<u8>, SelectedComdat>::new();
    let mut resolution = ComdatResolution {
        analysis,
        ..ComdatResolution::default()
    };
    for (object_index, (input, mut section_groups)) in
        objects.iter().zip(section_groups).enumerate()
    {
        let timestamp = coff_timestamp(input.file());
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
                        );
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
                        );
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
    selection_phase
        .0
        .add(crate::timing::PeMetric::Groups, selected.len());
    selection_phase.0.add(
        crate::timing::PeMetric::Sections,
        resolution.discarded.len(),
    );
    selection_phase
        .0
        .add(crate::timing::PeMetric::Events, resolution.redirects.len());
    drop(selection_phase);
    Ok(resolution)
}

/// Return the selected COMDAT sections which are not reachable from a linker root.
///
/// COFF's section GC unit is a COMDAT group, not an input object: an associative child (for
/// example a function's unwind record) follows its leader.  Non-COMDAT sections intentionally
/// start live.  They contain PE/CRT conventions such as `.CRT$XCU`, TLS state and loader
/// metadata that do not necessarily have a normal relocation edge from the entry point.
#[cfg(test)]
fn unreferenced_comdat_sections(
    objects: &[crate::coff::CoffObject<'_>],
    metadata: &SelectedObjectMetadata,
    comdats: &ComdatResolution,
    roots: &[Vec<u8>],
    runtime_resolution: &linker_utils::coff_runtime::RuntimeResolution,
) -> Result<HashSet<ObjectSectionKey>> {
    let topology_phase = crate::timing_guard!(PE_DETAIL_REF_TOPOLOGY);
    let mut resolved_groups = vec![None; comdats.analysis.keys.len()];
    for (start, resolved_group) in resolved_groups.iter_mut().enumerate() {
        let mut node = start;
        for _ in 0..=comdats.redirects.len() {
            let key = comdats.analysis.keys[node];
            if !comdats.discarded.contains(&key) {
                *resolved_group = Some(comdats.analysis.group_by_node[node]);
                break;
            }
            let Some(next) = comdats.redirects.get(&key) else {
                break;
            };
            node = comdats
                .analysis
                .node(*next)
                .context("COMDAT redirect targets an invalid section")?;
        }
        ensure!(
            resolved_group.is_some()
                || !comdats.redirects.contains_key(&comdats.analysis.keys[node]),
            "cycle in COMDAT section redirects"
        );
    }
    drop(topology_phase);

    // Relocations to external symbols have no section on their local symbol record. Resolve
    // them through the selected global definition, while direct/local relocations use the
    // symbol's own section below.
    let definitions_phase = crate::timing_guard!(PE_DETAIL_REF_DEFINITIONS);
    let mut definitions = HashMap::<Vec<u8>, ComdatGroupId>::new();
    for symbol in metadata.globals {
        if !symbol.is_definition {
            continue;
        }
        let Some(section) = symbol.section else {
            continue;
        };
        let node = comdats
            .analysis
            .node((symbol.object, section))
            .context("definition refers to an invalid COFF section")?;
        let Some(group) = resolved_groups[node] else {
            continue;
        };
        definitions
            .entry(metadata.symbol_name(symbol).to_vec())
            .or_insert(group);
    }
    let weak_resolution = metadata.weak();
    let resolve_definition = |name: &[u8]| -> Result<Option<ComdatGroupId>> {
        if let Some(&group) = definitions.get(name) {
            return Ok(Some(group));
        }

        // A weak external is undefined at the relocation site; its auxiliary symbol names
        // the selected fallback definition. Follow that chain before deciding the target
        // COMDAT is dead. A strong definition of any intermediate name stops the chain.
        let weak_target =
            weak_resolution.resolve(name, |candidate| definitions.contains_key(candidate))?;
        if let Some(&group) = definitions.get(weak_target) {
            return Ok(Some(group));
        }

        // `/alternatename` has the same selected-definition rule as weak externals. Keep the
        // source spelling strong when it exists, and otherwise retain its final selected
        // fallback. Non-UTF-8 COFF names cannot participate in this textual directive.
        let Ok(name) = std::str::from_utf8(name) else {
            return Ok(None);
        };
        let target = runtime_resolution.resolve_alternate_name(name, |candidate| {
            definitions.contains_key(candidate.as_bytes())
        })?;
        Ok(definitions.get(target.as_bytes()).copied())
    };
    drop(definitions_phase);

    let mut live = vec![false; comdats.analysis.groups.len()];
    let mut pending = Vec::<ComdatGroupId>::new();
    let mark_live = |group: ComdatGroupId, live: &mut [bool], pending: &mut Vec<ComdatGroupId>| {
        if !live[group] {
            live[group] = true;
            pending.push(group);
        }
    };

    // See the function comment above: all ordinary sections are roots.  This also makes REF
    // compatible with objects compiled without /Gy, where a whole .text section is indivisible.
    let roots_phase = crate::timing_guard!(PE_DETAIL_REF_ROOTS);
    for (node, resolved_group) in resolved_groups.iter().enumerate() {
        if !comdats.analysis.is_comdat[node]
            && let Some(group) = *resolved_group
        {
            mark_live(group, &mut live, &mut pending);
        }
    }
    for root in roots {
        if let Some(group) = resolve_definition(root)? {
            mark_live(group, &mut live, &mut pending);
        }
    }
    drop(roots_phase);

    let reachability_phase = crate::timing_guard!(PE_DETAIL_REF_REACHABILITY);
    let no_edge = usize::MAX;
    let mut edge_heads = vec![no_edge; comdats.analysis.groups.len()];
    let mut edge_targets = Vec::<ComdatGroupId>::new();
    let mut edge_next = Vec::<usize>::new();
    // Relocation decoding and target resolution are object-local and read-only. Discover edges
    // in parallel, but retain section/relocation order inside each object and merge object slots
    // serially. Besides deterministic diagnostics, the ordered merge preserves the linked-list
    // insertion order (and therefore the existing DFS visitation order) exactly.
    let object_edge_results = objects
        .par_iter()
        .enumerate()
        .map(|(object_index, object)| {
            let mut edges = Vec::<(ComdatGroupId, ComdatGroupId)>::new();
            let relocation_index = object.relocation_index();
            for section in relocation_index.sections() {
                let key = (object_index, section.index());
                if comdats.discarded.contains(&key) {
                    continue;
                }
                let source_node = comdats
                    .analysis
                    .node(key)
                    .context("relocation source has an invalid COFF section")?;
                let Some(source_group) = resolved_groups[source_node] else {
                    continue;
                };
                for relocation in relocation_index.relocations(section) {
                    count_pe_relocation_decode();
                    let symbol = relocation_index.symbol(relocation.symbol());
                    let shape = symbol
                        .shape(object)
                        .context("invalid COFF relocation symbol")?;
                    let target = if let Some(section) = shape.section {
                        let node = comdats
                            .analysis
                            .node((object_index, section))
                            .context("relocation targets an invalid COFF section")?;
                        resolved_groups[node]
                    } else if shape.is_global {
                        resolve_definition(symbol.name(object)?)?
                    } else {
                        None
                    };
                    if let Some(target) = target {
                        edges.push((source_group, target));
                    }
                }
            }
            Ok(edges)
        })
        .collect::<Vec<Result<Vec<_>>>>();
    for object_edges in object_edge_results {
        for (source_group, target) in object_edges? {
            let edge = edge_targets.len();
            edge_targets.push(target);
            edge_next.push(edge_heads[source_group]);
            edge_heads[source_group] = edge;
        }
    }
    while let Some(group) = pending.pop() {
        let mut edge = edge_heads[group];
        while edge != no_edge {
            mark_live(edge_targets[edge], &mut live, &mut pending);
            edge = edge_next[edge];
        }
    }
    drop(reachability_phase);

    let classification_phase = crate::timing_guard!(PE_DETAIL_REF_CLASSIFY);
    let mut discarded = HashSet::new();
    for node in 0..comdats.analysis.keys.len() {
        let key = comdats.analysis.keys[node];
        if comdats.analysis.is_comdat[node]
            && !comdats.discarded.contains(&key)
            && !live[comdats.analysis.group_by_node[node]]
        {
            discarded.insert(key);
        }
    }
    drop(classification_phase);
    Ok(discarded)
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
    _objects: &[crate::coff::CoffObject<'_>],
    metadata: &SelectedObjectMetadata,
    contributions: &mut Vec<Contribution>,
) -> Result<HashMap<Vec<u8>, (u32, ContributionId)>> {
    let mut commons = BTreeMap::<Vec<u8>, u64>::new();
    for symbol in metadata.globals.iter().filter(|symbol| symbol.is_common) {
        commons
            .entry(metadata.symbol_name(symbol).to_vec())
            .and_modify(|size| *size = (*size).max(symbol.size))
            .or_insert(symbol.size);
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
        dense_section: None,
        spec: SectionContribution {
            id,
            name: b".bss$common".to_vec(),
            characteristics: bss_characteristics(),
            alignment: 16,
            size: cursor,
            kind: ContributionKind::Bss,
        },
        synthetic_data: Vec::new(),
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
        dense_section: None,
        spec: SectionContribution {
            id,
            name: name.to_vec(),
            characteristics,
            alignment: if name.starts_with(b".text") {
                16
            } else if name.starts_with(b".pdata") {
                4
            } else {
                8
            },
            size,
            kind: ContributionKind::Data,
        },
        synthetic_data: vec![0; size as usize],
    });
    Ok(Some(id))
}

fn converge_relocation_layout(
    contributions: &mut Vec<Contribution>,
    mut layout: SectionLayout,
    config: PeWriterConfig,
    mut relocation_rvas: impl FnMut(&SectionLayout) -> Result<Vec<u32>>,
) -> Result<(SectionLayout, Option<ContributionId>, bool, usize)> {
    let mut initial_rvas = relocation_rvas(&layout)?;
    let initial =
        build_amd64_base_relocation_table(initial_rvas.iter().copied(), layout.size_of_image)
            .context("failed to build PE base relocation table")?;
    if initial.is_empty() {
        return Ok((layout, None, false, 0));
    }

    let initial_layout_options = section_layout_options(layout.sections.len(), config)?;
    let reloc_id = add_synthetic(
        contributions,
        b".reloc",
        initial.len(),
        reloc_characteristics(),
    )?
    .expect("non-empty relocation data creates a contribution");
    let mut expected_size = initial.len();
    let mut relayouts = 0;

    let relocation_spec = &contributions
        .iter()
        .find(|contribution| contribution.spec.id == reloc_id)
        .expect("synthetic relocation contribution remains present")
        .spec;
    if let Some(insertion) =
        try_insert_relocation_section(&mut layout, relocation_spec, initial_layout_options)?
    {
        for rva in &mut initial_rvas {
            if *rva >= insertion.first_shifted_rva {
                *rva = rva
                    .checked_add(insertion.rva_delta)
                    .context("relocation RVA overflow")?;
            }
        }
        let data = build_amd64_base_relocation_table(initial_rvas, layout.size_of_image)
            .context("failed to build PE base relocation table")?;
        if data.len() == expected_size {
            let contribution = contributions
                .iter_mut()
                .find(|contribution| contribution.spec.id == reloc_id)
                .expect("synthetic relocation contribution remains present");
            contribution.synthetic_data = data;
            return Ok((layout, Some(reloc_id), true, 0));
        }

        // This cannot happen when the helper's page-alignment predicates hold,
        // but retain the bounded full-layout convergence as a defensive path.
        expected_size = data.len();
        let contribution = contributions
            .iter_mut()
            .find(|contribution| contribution.spec.id == reloc_id)
            .expect("synthetic relocation contribution remains present");
        contribution.spec.size =
            u32::try_from(expected_size).context("base relocation table too large")?;
        contribution.synthetic_data.resize(expected_size, 0);
    }

    loop {
        let relayout_phase = crate::timing_guard!(PE_DETAIL_LAYOUT_RELAYOUT);
        layout = make_layout(contributions, config)?;
        drop(relayout_phase);
        relayouts += 1;

        let data =
            build_amd64_base_relocation_table(relocation_rvas(&layout)?, layout.size_of_image)
                .context("failed to build PE base relocation table")?;
        if data.len() == expected_size {
            let contribution = contributions
                .iter_mut()
                .find(|contribution| contribution.spec.id == reloc_id)
                .expect("synthetic relocation contribution remains present");
            contribution.synthetic_data = data;
            return Ok((layout, Some(reloc_id), true, relayouts));
        }

        ensure!(
            relayouts < MAX_RELOCATION_RELAYOUTS,
            "PE base-relocation section size did not converge after {MAX_RELOCATION_RELAYOUTS} layouts"
        );
        // Usually this is the only correction: once `.reloc` exists, changing its size shifts
        // later output sections by their section alignment and preserves the number of encoded
        // relocation entries. Keep a bounded fallback for `.reloc` input subsections and valid
        // low-alignment images, where a sub-page shift can change the number of page blocks.
        expected_size = data.len();
        let contribution = contributions
            .iter_mut()
            .find(|contribution| contribution.spec.id == reloc_id)
            .expect("synthetic relocation contribution remains present");
        contribution.spec.size =
            u32::try_from(expected_size).context("base relocation table too large")?;
        contribution.synthetic_data.resize(expected_size, 0);
    }
}

fn make_layout(contributions: &[Contribution], config: PeWriterConfig) -> Result<SectionLayout> {
    let section_count = contributions
        .iter()
        .map(|c| c.spec.name.split(|b| *b == b'$').next().unwrap())
        .collect::<HashSet<_>>()
        .len();
    let options = section_layout_options(section_count, config)?;
    let layout = layout_sections_borrowed(
        contributions.iter().map(|contribution| &contribution.spec),
        options,
    )
    .context("failed to lay out PE sections")?;
    Ok(layout)
}

fn section_layout_options(
    section_count: usize,
    config: PeWriterConfig,
) -> Result<SectionLayoutOptions> {
    ensure!(u16::try_from(section_count).is_ok(), "too many PE sections");
    let headers = 0x80 + 4 + 20 + 240 + u32::try_from(section_count).unwrap() * 40;
    Ok(SectionLayoutOptions {
        headers_size: headers,
        section_alignment: config.section_alignment,
        file_alignment: config.file_alignment,
    })
}

fn source_locations(
    contributions: &[Contribution],
) -> HashMap<(usize, object::SectionIndex), ContributionId> {
    let locations_phase = crate::timing_guard!(PE_DETAIL_SOURCE_LOCATIONS);
    let mut locations = HashMap::with_capacity(contributions.len());
    locations.extend(contributions.iter().filter_map(|c| match c.source {
        Source::Object { object, section } => Some(((object, section), c.spec.id)),
        Source::Synthetic => None,
    }));
    drop(locations_phase);
    locations
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

fn discover_dir64_sites(
    objects: &[crate::coff::CoffObject<'_>],
    contributions: &[Contribution],
    absolute_symbols: &HashMap<Vec<u8>, u64>,
) -> Result<Vec<Dir64Site>> {
    let dir64_phase = crate::timing_guard!(PE_DETAIL_DIR64_SITES);
    let chunk_results = if rayon::current_num_threads() > 1
        && contributions.len() > DIR64_DISCOVERY_CHUNK_SIZE
    {
        contributions
            .par_chunks(DIR64_DISCOVERY_CHUNK_SIZE)
            .map(|chunk| discover_dir64_sites_in_contributions(objects, chunk, absolute_symbols))
            .collect::<Vec<_>>()
    } else {
        vec![discover_dir64_sites_in_contributions(
            objects,
            contributions,
            absolute_symbols,
        )]
    };
    let mut sites = Vec::new();
    // Indexed parallel collection preserves contribution order. Checking chunk results in that
    // same order keeps both relocation-table bytes and the first reported error deterministic.
    for chunk in chunk_results {
        sites.extend(chunk?);
    }
    drop(dir64_phase);
    Ok(sites)
}

fn discover_dir64_sites_in_contributions(
    objects: &[crate::coff::CoffObject<'_>],
    contributions: &[Contribution],
    absolute_symbols: &HashMap<Vec<u8>, u64>,
) -> Result<Vec<Dir64Site>> {
    let mut sites = Vec::new();
    for contribution in contributions {
        let Source::Object {
            object: object_index,
            section: section_index,
        } = contribution.source
        else {
            continue;
        };
        let input = objects
            .get(object_index)
            .context("selected COFF contribution references an invalid object")?;
        let section = input
            .file()
            .section_by_index(section_index)
            .context("selected COFF contribution references an invalid section")?;
        for (offset, relocation) in section.relocations() {
            count_pe_relocation_decode();
            if relocation.kind() == RelocationKind::Absolute && relocation.size() == 64 {
                if let RelocationTarget::Symbol(index) = relocation.target() {
                    let symbol = input
                        .file()
                        .symbol_by_index(index)
                        .context("invalid relocation symbol")?;
                    let name = symbol.name_bytes()?;
                    if absolute_symbols.contains_key(name) {
                        continue;
                    }
                }
                sites.push(Dir64Site {
                    contribution: contribution.spec.id,
                    offset: u32::try_from(offset).context("relocation offset too large")?,
                });
            }
        }
    }
    Ok(sites)
}

fn dir64_rvas(sites: &[Dir64Site], layout: &SectionLayout) -> Result<Vec<u32>> {
    let mut rvas = Vec::with_capacity(sites.len());
    for site in sites {
        rvas.push(
            layout.placements[&site.contribution]
                .rva
                .checked_add(site.offset)
                .context("relocation RVA overflow")?,
        );
    }
    Ok(rvas)
}

type LocationMap = HashMap<(usize, object::SectionIndex), ContributionId>;

fn definitions(
    _objects: &[crate::coff::CoffObject<'_>],
    metadata: &SelectedObjectMetadata,
    contributions: &[Contribution],
    layout: &SectionLayout,
    image_base: u64,
    allow_multiple: bool,
) -> Result<(LocationMap, HashMap<Vec<u8>, u64>)> {
    let locations = source_locations(contributions);
    let mut definitions = HashMap::new();
    for symbol in metadata.globals.iter().filter(|symbol| !symbol.is_common) {
        let name = metadata.symbol_name(symbol).to_vec();
        let address = if let Some(section) = symbol.section {
            let Some(id) = locations.get(&(symbol.object, section)) else {
                continue;
            };
            image_base + u64::from(layout.placements[id].rva) + symbol.address
        } else if symbol.is_definition {
            symbol.address
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

fn dense_section_targets(
    dense: &DenseProductionState<'_>,
    contributions: &[Contribution],
    layout: &SectionLayout,
    redirects: &SectionRedirects,
    dense_gc: Option<&pe_gc::GcOutput>,
) -> Result<Vec<Option<DenseSectionTarget>>> {
    let mut output = vec![None; dense.ir.sections.len()];
    for contribution in contributions {
        let Some(section) = contribution.dense_section else {
            continue;
        };
        let record = dense
            .ir
            .sections
            .get(section.index())
            .context("contribution has an invalid dense section")?;
        let placement = &layout.placements[contribution.spec.id];
        let target = DenseSectionTarget {
            rva: placement.rva,
            output_section_rva: layout.sections[placement.output_section].rva,
            output_section_index: u16::try_from(placement.output_section + 1)
                .context("PE section index exceeds u16")?,
            size: record.size,
        };
        let slot = output
            .get_mut(section.index())
            .context("contribution dense section is outside target table")?;
        ensure!(slot.is_none(), "duplicate live dense section contribution");
        *slot = Some(target);
    }

    if let Some(gc) = dense_gc {
        for index in 0..output.len() {
            let section = pe_ir::SectionId::from_u32(index as u32);
            let canonical = gc
                .canonical(section)
                .context("dense GC has no canonical section target")?;
            if canonical != section {
                output[index] = output.get(canonical.index()).copied().flatten();
            }
        }
    } else if !redirects.is_empty() {
        let mut canonical = (0..output.len())
            .map(|index| pe_ir::SectionId::from_u32(index as u32))
            .collect::<Vec<_>>();
        for (&(from_object, from_raw), &(to_object, to_raw)) in redirects {
            let from = dense
                .ir
                .section_by_raw(
                    pe_ir::ObjectId::from_u32(from_object as u32),
                    u32::try_from(from_raw.0).context("redirect source section exceeds u32")?,
                )
                .context("COMDAT redirect source has no dense section")?;
            let to = dense
                .ir
                .section_by_raw(
                    pe_ir::ObjectId::from_u32(to_object as u32),
                    u32::try_from(to_raw.0).context("redirect target section exceeds u32")?,
                )
                .context("COMDAT redirect target has no dense section")?;
            canonical[from.index()] = to;
        }
        for start in 0..canonical.len() {
            let mut section = canonical[start];
            for _ in 0..=redirects.len() {
                let next = canonical[section.index()];
                if next == section {
                    canonical[start] = section;
                    break;
                }
                section = next;
            }
            ensure!(
                canonical[section.index()] == section,
                "cycle in dense COMDAT redirects"
            );
        }
        for index in 0..output.len() {
            let selected = canonical[index];
            if selected.index() != index {
                output[index] = output.get(selected.index()).copied().flatten();
            }
        }
    }
    Ok(output)
}

fn copy_and_apply_relocations(
    objects: &[crate::coff::CoffObject<'_>],
    dense: Option<&DenseProductionState<'_>>,
    contributions: &[Contribution],
    layout: &SectionLayout,
    locations: &LocationMap,
    redirects: &SectionRedirects,
    dense_gc: Option<&pe_gc::GcOutput>,
    dense_targets: Option<&[Option<DenseSectionTarget>]>,
    definitions: &HashMap<Vec<u8>, u64>,
    absolute_symbols: &HashMap<Vec<u8>, u64>,
    image_base: u64,
    image: &mut [u8],
) -> Result<()> {
    validate_object_output_ranges(contributions, layout, image.len())?;
    let parallel_image = pe_layout::DisjointOutput::new(image);
    let copy = |contribution: &Contribution| match dense {
        Some(dense) => copy_and_relocate_dense_contribution(
            dense,
            contribution,
            layout,
            locations,
            redirects,
            dense_gc,
            dense_targets,
            definitions,
            absolute_symbols,
            image_base,
            parallel_image,
        ),
        None => copy_and_relocate_contribution(
            objects,
            contribution,
            layout,
            locations,
            redirects,
            definitions,
            absolute_symbols,
            image_base,
            parallel_image,
        ),
    };
    if rayon::current_num_threads() > 1 {
        let results = contributions.par_iter().map(copy).collect::<Vec<_>>();
        // Indexed collection retains contribution order, so malformed-input diagnostics remain
        // deterministic even though every task owns a disjoint final output slice.
        for result in results {
            result?;
        }
    } else {
        for contribution in contributions {
            copy(contribution)?;
        }
    }
    Ok(())
}

/// Checks the complete safety invariant before `DisjointOutput` is shared with Rayon: every real
/// input contribution has exactly one placement and every initialized placement owns a unique,
/// in-bounds file range.
fn validate_object_output_ranges(
    contributions: &[Contribution],
    layout: &SectionLayout,
    image_len: usize,
) -> Result<()> {
    count_pe_hot_allocation();
    count_pe_hot_allocation();
    let object_count = contributions
        .iter()
        .filter(|contribution| matches!(contribution.source, Source::Object { .. }))
        .count();
    let mut ids = Vec::with_capacity(object_count);
    let mut ranges = Vec::with_capacity(object_count);
    for contribution in contributions {
        if !matches!(contribution.source, Source::Object { .. }) {
            continue;
        }
        let placement = layout
            .placements
            .get(&contribution.spec.id)
            .context("real PE contribution has no layout placement")?;
        ensure!(
            placement.size == contribution.spec.size,
            "real PE contribution placement has the wrong size"
        );
        ids.push(contribution.spec.id);
        match (placement.file_offset, contribution.spec.kind) {
            (Some(offset), ContributionKind::Data) => {
                let start = usize::try_from(offset).context("PE contribution offset too large")?;
                let end = start
                    .checked_add(
                        usize::try_from(placement.size)
                            .context("PE contribution size too large")?,
                    )
                    .context("PE contribution file range overflow")?;
                ensure!(end <= image_len, "PE contribution extends past file data");
                ranges.push((start, end, contribution.spec.id));
            }
            (None, ContributionKind::Bss) => {}
            (Some(_), ContributionKind::Bss) => {
                return Err(error!("uninitialized PE contribution has file data"));
            }
            (None, ContributionKind::Data) => {
                return Err(error!("initialized PE contribution has no file placement"));
            }
        }
    }

    ids.sort_unstable();
    ensure!(
        ids.windows(2).all(|pair| pair[0] != pair[1]),
        "real PE contributions reuse a layout identity"
    );
    ranges.sort_unstable();
    ensure!(
        ranges.windows(2).all(|pair| pair[0].1 <= pair[1].0),
        "real PE contribution file placements overlap"
    );
    Ok(())
}

#[derive(Clone, Copy)]
struct PreparedRelocation {
    at: usize,
    kind: linker_utils::coff::Amd64RelocationKind,
    inputs: linker_utils::coff::Amd64RelocationInputs,
    absolute_value: Option<u64>,
    contribution_rva: u32,
    offset: u64,
}

#[derive(Clone, Copy)]
struct DenseSectionTarget {
    rva: u32,
    output_section_rva: u32,
    output_section_index: u16,
    size: u32,
}

impl PreparedRelocation {
    #[inline(always)]
    fn apply(self, image: &mut [u8]) -> Result<()> {
        let field = image
            .get_mut(self.at..)
            .context("relocation past file data")?;
        if let Some(value) = self.absolute_value {
            return apply_absolute_amd64_relocation(
                self.kind,
                field,
                value,
                self.inputs.image_base.0,
                self.contribution_rva,
                self.offset,
            );
        }
        linker_utils::coff::apply_amd64_relocation(self.kind, field, self.inputs)
            .context("failed to apply AMD64 COFF relocation")
    }
}

fn copy_and_relocate_contribution(
    objects: &[crate::coff::CoffObject<'_>],
    contribution: &Contribution,
    layout: &SectionLayout,
    locations: &LocationMap,
    redirects: &SectionRedirects,
    definitions: &HashMap<Vec<u8>, u64>,
    absolute_symbols: &HashMap<Vec<u8>, u64>,
    image_base: u64,
    parallel_image: pe_layout::DisjointOutput<'_>,
) -> Result<()> {
    let Source::Object {
        object: object_index,
        section: section_index,
    } = contribution.source
    else {
        return Ok(());
    };
    let input = &objects[object_index];
    let source = indexed_coff_section(input, section_index)?;
    let placement = &layout.placements[&contribution.spec.id];
    let Some(file_offset) = placement.file_offset else {
        ensure!(
            input.index().relocations(source).is_empty(),
            "relocation in uninitialized section"
        );
        return Ok(());
    };
    let source_file = usize::try_from(file_offset).context("relocation file offset too large")?;
    // SAFETY: Every selected input section has its own contribution ID and layout assigns
    // contribution IDs disjoint file ranges. This task is the sole writer for this source.
    let contribution = unsafe {
        parallel_image.slice(
            source_file,
            usize::try_from(placement.size).context("PE contribution size too large")?,
        )?
    };
    let source_range = source
        .data_range
        .context("initialized COFF section has no indexed source range")?;
    let source_start = source_range.start as usize;
    let source_end = source_start
        .checked_add(source_range.len as usize)
        .context("COFF source range overflow")?;
    let source_data = input
        .bytes()
        .get(source_start..source_end)
        .context("invalid indexed COFF section source range")?;
    ensure!(
        source_data.len() == contribution.len(),
        "COFF source and output contribution sizes differ"
    );
    contribution.copy_from_slice(source_data);
    count_pe_bytes_copied(source_data.len());
    for relocation in input.index().relocations(source) {
        let mut prepared = prepare_relocation(
            objects,
            object_index,
            input,
            layout,
            locations,
            redirects,
            definitions,
            absolute_symbols,
            image_base,
            placement,
            relocation,
        )?;
        prepared.at = prepared
            .at
            .checked_sub(source_file)
            .context("relocation precedes contribution data")?;
        prepared.apply(contribution)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn copy_and_relocate_dense_contribution(
    dense: &DenseProductionState<'_>,
    contribution: &Contribution,
    layout: &SectionLayout,
    locations: &LocationMap,
    redirects: &SectionRedirects,
    dense_gc: Option<&pe_gc::GcOutput>,
    dense_targets: Option<&[Option<DenseSectionTarget>]>,
    definitions: &HashMap<Vec<u8>, u64>,
    absolute_symbols: &HashMap<Vec<u8>, u64>,
    image_base: u64,
    parallel_image: pe_layout::DisjointOutput<'_>,
) -> Result<()> {
    let Source::Object { .. } = contribution.source else {
        return Ok(());
    };
    let section = contribution
        .dense_section
        .context("real contribution has no dense PE section")?;
    let record = &dense.ir.sections[section.index()];
    let relocations = dense
        .ir
        .relocations
        .for_section(section)
        .context("dense PE section has no relocation row")?;
    let placement = &layout.placements[&contribution.spec.id];
    let Some(file_offset) = placement.file_offset else {
        ensure!(
            relocations.is_empty(),
            "relocation in uninitialized section"
        );
        return Ok(());
    };
    let source_file = usize::try_from(file_offset).context("relocation file offset too large")?;
    // SAFETY: `validate_object_output_ranges` checked all real contribution ranges immediately
    // before the shared output handle was created.
    let output = unsafe {
        parallel_image.slice(
            source_file,
            usize::try_from(placement.size).context("PE contribution size too large")?,
        )?
    };
    let source = record
        .data
        .and_then(|source| dense.ir.sources.bytes(source))
        .context("initialized dense PE section has no source bytes")?;
    ensure!(
        source.len() == output.len(),
        "dense PE source and output contribution sizes differ"
    );
    output.copy_from_slice(source);
    count_pe_bytes_copied(source.len());
    for relocation in relocations {
        let mut prepared = prepare_dense_relocation(
            dense,
            layout,
            locations,
            redirects,
            dense_gc,
            dense_targets,
            definitions,
            absolute_symbols,
            image_base,
            placement,
            *relocation,
        )?;
        prepared.at = prepared
            .at
            .checked_sub(source_file)
            .context("relocation precedes contribution data")?;
        prepared.apply(output)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn prepare_dense_relocation(
    dense: &DenseProductionState<'_>,
    layout: &SectionLayout,
    locations: &LocationMap,
    redirects: &SectionRedirects,
    dense_gc: Option<&pe_gc::GcOutput>,
    dense_targets: Option<&[Option<DenseSectionTarget>]>,
    definitions: &HashMap<Vec<u8>, u64>,
    absolute_symbols: &HashMap<Vec<u8>, u64>,
    image_base: u64,
    placement: &linker_utils::pe_sections::ContributionPlacement,
    relocation: pe_ir::RelocationRecord,
) -> Result<PreparedRelocation> {
    use linker_utils::coff::Amd64RelocationInputs;
    use linker_utils::coff::ImageBase;
    use linker_utils::coff::Rva;
    use linker_utils::coff::SectionIndex;

    let resolved_target = dense
        .resolved_targets
        .symbol(relocation.target)
        .context("relocation target is outside resolved symbol table")?;
    let (target, target_section, target_section_index, absolute_value) = if let Some(section) =
        resolved_target.section_id()
    {
        if let Some(targets) = dense_targets {
            let target = targets
                .get(section.index())
                .copied()
                .flatten()
                .context("relocation targets a discarded dense section")?;
            ensure!(
                resolved_target.value <= target.size,
                "symbol offset exceeds selected COMDAT section"
            );
            (
                target
                    .rva
                    .checked_add(resolved_target.value)
                    .context("COFF symbol RVA overflow")?,
                target.output_section_rva,
                target.output_section_index,
                None,
            )
        } else {
            let (selected, id) = if let Some(gc) = dense_gc {
                let canonical = gc
                    .canonical(section)
                    .context("dense GC has no canonical relocation target")?;
                let selected = dense
                    .ir
                    .sections
                    .get(canonical.index())
                    .context("canonical dense relocation target is invalid")?;
                let key = (
                    selected.object.index(),
                    object::SectionIndex(selected.raw_index as usize),
                );
                let id = *locations.get(&key).ok_or_else(|| {
                    error!(
                        "relocation targets discarded canonical section {}:{:?}",
                        key.0, key.1
                    )
                })?;
                (selected, id)
            } else {
                let target_record = dense
                    .ir
                    .sections
                    .get(section.index())
                    .context("dense relocation target section is invalid")?;
                let target_object = target_record.object.index();
                let target_raw = object::SectionIndex(target_record.raw_index as usize);
                let ((selected_object, selected_raw), id) = redirected_location(
                    locations,
                    redirects,
                    (target_object, target_raw),
                )?
                .ok_or_else(|| {
                    error!("relocation targets discarded section {target_object}:{target_raw:?}")
                })?;
                let selected = dense
                    .ir
                    .section_by_raw(
                        pe_ir::ObjectId::from_u32(
                            u32::try_from(selected_object)
                                .context("selected object exceeds u32")?,
                        ),
                        u32::try_from(selected_raw.0).context("selected section exceeds u32")?,
                    )
                    .and_then(|section| dense.ir.sections.get(section.index()))
                    .context("COMDAT redirect target has no dense section")?;
                (selected, id)
            };
            ensure!(
                u64::from(resolved_target.value) <= u64::from(selected.size),
                "symbol offset exceeds selected COMDAT section"
            );
            let target_placement = &layout.placements[&id];
            let target = target_placement
                .rva
                .checked_add(resolved_target.value)
                .context("COFF symbol RVA overflow")?;
            (
                target,
                layout.sections[target_placement.output_section].rva,
                u16::try_from(target_placement.output_section + 1)
                    .context("PE section index exceeds u16")?,
                None,
            )
        }
    } else {
        if resolved_target.kind == pe_ir::ResolvedTargetKind::Diagnostic {
            return Err(error!(
                "Invalid COFF relocation symbol {}",
                resolved_target.target
            ));
        }
        let name = resolved_target
            .name_id()
            .and_then(|name| dense.names.bytes(name))
            .context("relocation target has an invalid canonical name")?;
        let address = *definitions
            .get(name)
            .ok_or_else(|| error!("undefined symbol `{}`", String::from_utf8_lossy(name)))?;
        if let Some(value) = absolute_symbols.get(name) {
            (0, 0, 0, Some(*value))
        } else {
            let (target, section, index) = target_location(layout, image_base, address)?;
            (target, section, index, None)
        }
    };
    let kind = linker_utils::coff::Amd64RelocationKind::from_type(object::pe::RelocationType(
        relocation.typ,
    ))
    .context("unsupported AMD64 COFF relocation")?;
    let offset = u64::from(relocation.offset);
    let source_file = placement
        .file_offset
        .ok_or_else(|| error!("relocation in uninitialized section"))?;
    let at = usize::try_from(u64::from(source_file) + offset)
        .context("relocation file offset too large")?;
    let place = placement
        .rva
        .checked_add(relocation.offset)
        .context("relocation place RVA overflow")?;
    Ok(PreparedRelocation {
        at,
        kind,
        inputs: Amd64RelocationInputs {
            image_base: ImageBase(image_base),
            place: Rva(place),
            target: Rva(target),
            target_section: Rva(target_section),
            target_section_index: SectionIndex(target_section_index),
        },
        absolute_value,
        contribution_rva: placement.rva,
        offset,
    })
}

#[inline]
fn indexed_coff_section<'object>(
    input: &'object crate::coff::CoffObject<'_>,
    section: object::SectionIndex,
) -> Result<&'object crate::coff::CoffSectionRecord> {
    let ordinal = section
        .0
        .checked_sub(1)
        .context("invalid zero COFF section index")?;
    let record = input
        .index()
        .sections()
        .get(ordinal)
        .context("COFF section is absent from the eager index")?;
    ensure!(
        record.index() == section,
        "eager COFF section index/order mismatch"
    );
    Ok(record)
}

#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn prepare_relocation(
    objects: &[crate::coff::CoffObject<'_>],
    object_index: usize,
    input: &crate::coff::CoffObject<'_>,
    layout: &SectionLayout,
    locations: &LocationMap,
    redirects: &SectionRedirects,
    definitions: &HashMap<Vec<u8>, u64>,
    absolute_symbols: &HashMap<Vec<u8>, u64>,
    image_base: u64,
    placement: &linker_utils::pe_sections::ContributionPlacement,
    relocation: &crate::coff::CoffRelocationRecord,
) -> Result<PreparedRelocation> {
    use linker_utils::coff::Amd64RelocationInputs;
    use linker_utils::coff::Amd64RelocationKind;
    use linker_utils::coff::ImageBase;
    use linker_utils::coff::Rva;
    use linker_utils::coff::SectionIndex;

    let source_file = placement
        .file_offset
        .ok_or_else(|| error!("relocation in uninitialized section"))?;
    let symbol = input.index().symbol(relocation.symbol());
    let shape = symbol.shape(input)?;
    let name = symbol.name(input)?;
    let (target, target_section, target_section_index, absolute_value) = if shape.is_global
        && let Some(address) = definitions.get(name)
    {
        if let Some(value) = absolute_symbols.get(name) {
            (0, 0, 0, Some(*value))
        } else {
            let (target, section, index) = target_location(layout, image_base, *address)?;
            (target, section, index, None)
        }
    } else if let Some(section) = shape.section {
        let ((target_object, target_section_index), id) = redirected_location(
            locations,
            redirects,
            (object_index, section),
        )?
        .ok_or_else(|| {
            error!(
                "relocation targets discarded section {object_index}:{section:?} via symbol `{}`",
                String::from_utf8_lossy(name)
            )
        })?;
        let target_section = indexed_coff_section(&objects[target_object], target_section_index)?;
        ensure!(
            shape.address <= target_section.size,
            "symbol offset exceeds selected COMDAT section"
        );
        let target_placement = &layout.placements[&id];
        let target = target_placement
            .rva
            .checked_add(u32::try_from(shape.address).context("COFF symbol offset exceeds u32")?)
            .context("COFF symbol RVA overflow")?;
        (
            target,
            layout.sections[target_placement.output_section].rva,
            u16::try_from(target_placement.output_section + 1)
                .context("PE section index exceeds u16")?,
            None,
        )
    } else {
        let address = *definitions
            .get(name)
            .ok_or_else(|| error!("undefined symbol `{}`", String::from_utf8_lossy(name)))?;
        let (target, section, index) = target_location(layout, image_base, address)?;
        (target, section, index, None)
    };
    let kind = Amd64RelocationKind::from_type(object::pe::RelocationType(relocation.typ))
        .context("unsupported AMD64 COFF relocation")?;
    let offset = u64::from(relocation.offset);
    let at = usize::try_from(u64::from(source_file) + offset)
        .context("relocation file offset too large")?;
    let place = placement
        .rva
        .checked_add(u32::try_from(offset).context("relocation offset exceeds u32")?)
        .context("relocation place RVA overflow")?;
    Ok(PreparedRelocation {
        at,
        kind,
        inputs: Amd64RelocationInputs {
            image_base: ImageBase(image_base),
            place: Rva(place),
            target: Rva(target),
            target_section: Rva(target_section),
            target_section_index: SectionIndex(target_section_index),
        },
        absolute_value,
        contribution_rva: placement.rva,
        offset,
    })
}

fn apply_absolute_amd64_relocation(
    kind: linker_utils::coff::Amd64RelocationKind,
    field: &mut [u8],
    target: u64,
    image_base: u64,
    contribution_rva: u32,
    offset: u64,
) -> Result<()> {
    use linker_utils::coff::Amd64RelocationKind;

    ensure!(
        field.len() >= kind.field_size(),
        "{kind:?} relocation field is truncated"
    );
    let addend = match kind {
        Amd64RelocationKind::Absolute => return Ok(()),
        Amd64RelocationKind::Address64 => {
            i128::from(i64::from_le_bytes(field[..8].try_into().unwrap()))
        }
        Amd64RelocationKind::Section => {
            i128::from(i16::from_le_bytes(field[..2].try_into().unwrap()))
        }
        _ => i128::from(i32::from_le_bytes(field[..4].try_into().unwrap())),
    };
    let target = i128::from(target);
    match kind {
        Amd64RelocationKind::Absolute => unreachable!(),
        Amd64RelocationKind::Address64 => {
            let value = u64::try_from(target + addend)
                .context("absolute ADDR64 relocation value is outside u64")?;
            field[..8].copy_from_slice(&value.to_le_bytes());
        }
        Amd64RelocationKind::Address32 | Amd64RelocationKind::Address32NoBase => {
            let value = u32::try_from(target + addend)
                .context("absolute ADDR32 relocation value is outside u32")?;
            field[..4].copy_from_slice(&value.to_le_bytes());
        }
        Amd64RelocationKind::Relative { extra_offset } => {
            let place = i128::from(image_base)
                + i128::from(contribution_rva)
                + i128::from(offset)
                + 4
                + i128::from(extra_offset);
            let value = i32::try_from(target + addend - place)
                .context("absolute REL32 relocation value is outside i32")?;
            field[..4].copy_from_slice(&value.to_le_bytes());
        }
        Amd64RelocationKind::Section => {
            let value = u16::try_from(i128::from(u16::MAX) + addend)
                .context("absolute SECTION relocation value is outside u16")?;
            field[..2].copy_from_slice(&value.to_le_bytes());
        }
        Amd64RelocationKind::SectionRelative => {
            let value = u32::try_from(target + addend)
                .context("absolute SECREL relocation value is outside u32")?;
            field[..4].copy_from_slice(&value.to_le_bytes());
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
    dir64_rvas: &[u32],
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

    if dynamic_base {
        for rva in &tls.dir64_relocation_rvas {
            ensure!(
                dir64_rvas.contains(rva),
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
        dir64_rvas,
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
    delay_import_directory: Option<(u32, u32)>,
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
    if let Some((rva, size)) = delay_import_directory {
        // IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT (13).
        put_u32(image, opt + 216, rva);
        put_u32(image, opt + 220, size);
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
        put_u32(image, opt + 192, rva);
        put_u32(image, opt + 196, size);
    }
    let table = opt + 240;
    for (index, section) in layout.sections.iter().enumerate() {
        let at = table + index * 40;
        // PE image section headers have a fixed eight-byte name field and no
        // standard string-table indirection. link.exe and lld-link therefore
        // truncate long, mapped section names here. Keep the full logical name
        // in the layout so long-name collisions remain distinct sections.
        let header_name = &section.name[..section.name.len().min(8)];
        image[at..at + header_name.len()].copy_from_slice(header_name);
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
    fn snapshot_aggregation_preserves_root_common_weak_and_empty_name_semantics() {
        let symbol = |index, name: &[u8], definition, common, undefined, weak| {
            pe_resolver::SelectedGlobalSymbol {
                object: 0,
                index: object::SymbolIndex(index),
                section: None,
                section_kind: object::SymbolSection::Undefined,
                address: 0,
                size: 0,
                is_definition: definition,
                is_common: common,
                is_undefined: undefined,
                is_weak: weak,
                name_id: pe_ir::NameId::from_u32(u32::MAX),
                name: name.to_vec(),
            }
        };
        let snapshot = pe_resolver::SelectedSymbolSnapshot {
            globals: vec![
                symbol(0, b"defined", true, false, false, false),
                symbol(1, b"common", false, true, true, false),
                symbol(2, b"missing", false, false, true, false),
                symbol(3, b"weak", false, false, true, true),
                symbol(4, b"", true, false, false, false),
            ],
            weak_resolution: Default::default(),
        };

        let (metadata, undefined) = SelectedObjectMetadata::new_with_undefined(
            &snapshot,
            &[b"defined".to_vec(), b"root".to_vec()],
            None,
        );
        assert_eq!(
            undefined,
            [b"missing".to_vec(), b"root".to_vec()]
                .into_iter()
                .collect()
        );
        assert!(metadata.definition_names().contains(b"".as_slice()));
        assert!(metadata.definition_names().contains(b"common".as_slice()));
        assert!(metadata.definition_names().contains(b"defined".as_slice()));
        assert!(!metadata.definition_names().contains(b"weak".as_slice()));
    }

    fn synthetic_test_contribution(id: u32, name: &[u8], size: u32) -> Contribution {
        Contribution {
            source: Source::Synthetic,
            dense_section: None,
            spec: SectionContribution {
                id: ContributionId(id),
                name: name.to_vec(),
                characteristics: readonly_data_characteristics(),
                alignment: 1,
                size,
                kind: ContributionKind::Data,
            },
            synthetic_data: vec![0; size as usize],
        }
    }

    fn object_test_contribution(
        id: u32,
        object: usize,
        section: object::SectionIndex,
    ) -> Contribution {
        Contribution {
            source: Source::Object { object, section },
            dense_section: None,
            spec: SectionContribution {
                id: ContributionId(id),
                name: b".text".to_vec(),
                characteristics: text_characteristics(),
                alignment: 1,
                size: 5,
                kind: ContributionKind::Data,
            },
            synthetic_data: Vec::new(),
        }
    }

    #[test]
    fn relocation_layout_inserts_reloc_without_a_full_relayout() {
        let config = PeWriterConfig::default();
        let mut contributions = vec![
            synthetic_test_contribution(0, b".text", 8),
            synthetic_test_contribution(1, b".custom", 0x1000),
        ];
        let initial = make_layout(&contributions, config).unwrap();
        let sites = [
            Dir64Site {
                contribution: ContributionId(1),
                offset: 0,
            },
            Dir64Site {
                contribution: ContributionId(1),
                offset: 0xff8,
            },
        ];

        let (layout, reloc_id, has_relocations, relayouts) =
            converge_relocation_layout(&mut contributions, initial, config, |layout| {
                dir64_rvas(&sites, layout)
            })
            .unwrap();

        assert_eq!(relayouts, 0);
        assert_eq!(reloc_id, Some(ContributionId(2)));
        assert!(has_relocations);
        let data = &contributions[2].synthetic_data;
        assert_eq!(
            linker_utils::pe_base_relocs::parse_amd64_base_relocation_table(
                data,
                layout.size_of_image,
            )
            .unwrap(),
            dir64_rvas(&sites, &layout).unwrap()
        );
    }

    #[test]
    fn relocation_layout_corrects_page_split_from_reloc_subsection() {
        let config = PeWriterConfig::default();
        let mut contributions = vec![synthetic_test_contribution(0, b".reloc$input", 0x1000)];
        let initial = make_layout(&contributions, config).unwrap();
        let sites = [
            Dir64Site {
                contribution: ContributionId(0),
                offset: 0,
            },
            Dir64Site {
                contribution: ContributionId(0),
                offset: 0xff8,
            },
        ];

        let (layout, reloc_id, has_relocations, relayouts) =
            converge_relocation_layout(&mut contributions, initial, config, |layout| {
                dir64_rvas(&sites, layout)
            })
            .unwrap();

        assert_eq!(relayouts, 2);
        assert_eq!(reloc_id, Some(ContributionId(1)));
        assert!(has_relocations);
        let data = &contributions[1].synthetic_data;
        assert_eq!(data.len(), 24);
        assert_eq!(
            linker_utils::pe_base_relocs::parse_amd64_base_relocation_table(
                data,
                layout.size_of_image,
            )
            .unwrap(),
            dir64_rvas(&sites, &layout).unwrap()
        );
    }

    #[test]
    fn parallel_dir64_discovery_preserves_contribution_order() {
        let bytes = crt_load_config_object(312, 8);
        let object = crate::coff::CoffObject::parse(&bytes).unwrap();
        let section_index = object
            .file()
            .sections()
            .find(|section| section.relocations().next().is_some())
            .unwrap()
            .index();
        let contributions = (0..(DIR64_DISCOVERY_CHUNK_SIZE * 3))
            .map(|index| Contribution {
                source: Source::Object {
                    object: 0,
                    section: section_index,
                },
                dense_section: None,
                spec: SectionContribution {
                    id: ContributionId(index as u32),
                    name: b".rdata".to_vec(),
                    characteristics: readonly_data_characteristics(),
                    alignment: 8,
                    size: 8,
                    kind: ContributionKind::Data,
                },
                synthetic_data: Vec::new(),
            })
            .collect::<Vec<_>>();
        let objects = [object];
        let absolute_symbols = HashMap::new();
        let expected =
            discover_dir64_sites_in_contributions(&objects, &contributions, &absolute_symbols)
                .unwrap();
        let actual = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap()
            .install(|| discover_dir64_sites(&objects, &contributions, &absolute_symbols))
            .unwrap();

        assert_eq!(actual, expected);
        assert!(
            actual
                .windows(2)
                .all(|pair| pair[0].contribution <= pair[1].contribution)
        );
    }

    #[test]
    fn parallel_repro_hash_and_copy_matches_in_place_finalization() {
        let payload_start = 4096;
        let payload = payload_start..payload_start + linker_utils::pe_debug::REPRO_BUILD_ID_SIZE;
        let mut bytes = (0..PARALLEL_REPRO_COPY_MIN_SIZE + 4096)
            .map(|index| index as u8)
            .collect::<Vec<_>>();
        bytes[payload.clone()].fill(0);
        let pending = PendingReproBuildId::new(&bytes, payload).unwrap();
        let mut sequential = BuiltImage {
            bytes: bytes.clone(),
            exports: Vec::new(),
            pending_repro_build_id: Some(pending.clone()),
        };
        sequential.finalize_repro_build_id().unwrap();

        for threads in [1, 4] {
            let mut candidate = BuiltImage {
                bytes: bytes.clone(),
                exports: Vec::new(),
                pending_repro_build_id: Some(pending.clone()),
            };
            let mut output = vec![0; bytes.len()];
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| candidate.copy_to(&mut output))
                .unwrap();
            assert_eq!(output, sequential.bytes, "threads={threads}");
        }
    }

    #[test]
    fn pe_timing_phase_labels_are_stable_and_unique() {
        let phases = [
            PE_PHASE_LOAD_DEFINITION,
            PE_PHASE_OPEN_INPUTS,
            PE_PHASE_SELECT_INPUTS,
            PE_PHASE_PARSE_INPUTS,
            PE_PHASE_PARSE_DIRECTIVES,
            PE_PHASE_RESOLVE_ARCHIVES,
            PE_PHASE_PREPARE_RESOURCES,
            PE_PHASE_RESOLVE_IMPORTS,
            PE_PHASE_SELECT_COMDATS,
            PE_PHASE_LAYOUT,
            PE_PHASE_BUILD_SYNTHETIC,
            PE_PHASE_DEFINE_SYMBOLS,
            PE_PHASE_COPY_IMAGE,
            PE_PHASE_APPLY_RELOCATIONS,
            PE_PHASE_FINALIZE_IMAGE,
            PE_PHASE_WRITE_OUTPUT,
        ];
        let details = [
            PE_DETAIL_BUILD_IMPORTS,
            PE_DETAIL_BUILD_DELAY_IMPORTS,
            PE_DETAIL_BUILD_RESOURCES,
            PE_DETAIL_COMDAT_CLASSIFY,
            PE_DETAIL_COMDAT_SELECT,
            PE_DETAIL_CONTRIBUTIONS,
            PE_DETAIL_DEBUG_BUILD_ID,
            PE_DETAIL_DEBUG_DIRECTORY,
            PE_DETAIL_DIR64_SITES,
            PE_DETAIL_EXCEPTION_DIRECTORY,
            PE_DETAIL_IMAGE_ALLOCATE,
            PE_DETAIL_IMAGE_COPY,
            PE_DETAIL_IMPORT_SELECTION,
            PE_DETAIL_LAYOUT_INITIAL,
            PE_DETAIL_LAYOUT_PREPARE,
            PE_DETAIL_LAYOUT_RELOCATIONS,
            PE_DETAIL_LAYOUT_RELAYOUT,
            PE_DETAIL_PROBE_ARCHIVE_INDICES,
            PE_DETAIL_ABSORB_SELECTED_SYMBOLS,
            PE_DETAIL_REBUILD_SELECTION_ROOTS,
            PE_DETAIL_EVALUATE_DEFAULT_LIBRARIES,
            PE_DETAIL_SNAPSHOT_RESOLVER_OUTPUTS,
            PE_DETAIL_MATERIALIZE_SELECTED_IMPORTS,
            PE_DETAIL_REF_CLASSIFY,
            PE_DETAIL_REF_DEFINITIONS,
            PE_DETAIL_REF_REACHABILITY,
            PE_DETAIL_REF_ROOTS,
            PE_DETAIL_REF_TOPOLOGY,
            PE_DETAIL_ROOTS,
            PE_DETAIL_SOURCE_LOCATIONS,
            PE_DETAIL_TLS_DIRECTORY,
            PE_DETAIL_WRITE_HEADERS,
        ];
        assert!(phases.iter().all(|phase| phase.starts_with("PE: ")));
        assert!(details.iter().all(|phase| phase.starts_with("PE detail: ")));
        assert_eq!(
            phases
                .iter()
                .chain(details.iter())
                .copied()
                .collect::<BTreeSet<_>>()
                .len(),
            phases.len() + details.len()
        );
    }

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

    fn crt_load_config_object(declared_size: u32, symbol_offset: u64) -> Vec<u8> {
        let mut object = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let data = object.add_section(Vec::new(), b".data".to_vec(), object::SectionKind::Data);
        object.append_section_data(data, &0x2b99_2ddf_a232u64.to_le_bytes(), 8);
        let cookie = object.add_symbol(Symbol {
            name: b"__security_cookie".to_vec(),
            value: 0,
            size: 8,
            kind: object::SymbolKind::Data,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(data),
            flags: object::SymbolFlags::None,
        });
        let config = object.add_section(
            Vec::new(),
            b".rdata$loadcfg".to_vec(),
            object::SectionKind::ReadOnlyData,
        );
        let config_size = 312usize;
        let mut contents = vec![0xa5; usize::try_from(symbol_offset).unwrap()];
        contents.resize(contents.len() + config_size, 0);
        contents
            [usize::try_from(symbol_offset).unwrap()..usize::try_from(symbol_offset).unwrap() + 4]
            .copy_from_slice(&declared_size.to_le_bytes());
        object.append_section_data(config, &contents, 8);
        object.add_symbol(Symbol {
            name: LOAD_CONFIG_SYMBOL.to_vec(),
            value: symbol_offset,
            size: u64::from(declared_size),
            kind: object::SymbolKind::Data,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(config),
            flags: object::SymbolFlags::None,
        });
        object.section_symbol(config);
        let comdat_leader = object.add_symbol(Symbol {
            name: b"loadcfg_comdat".to_vec(),
            value: 0,
            size: u64::try_from(contents.len()).unwrap(),
            kind: object::SymbolKind::Data,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(config),
            flags: object::SymbolFlags::None,
        });
        object.add_comdat(object::write::Comdat {
            kind: object::ComdatKind::Any,
            symbol: comdat_leader,
            sections: vec![config],
        });
        object
            .add_relocation(
                config,
                Relocation {
                    offset: symbol_offset + 88,
                    symbol: cookie,
                    addend: 0,
                    flags: object::RelocationFlags::Coff {
                        typ: object::pe::IMAGE_REL_AMD64_ADDR64,
                    },
                },
            )
            .unwrap();
        object.write().unwrap()
    }

    fn guard_absolute_load_config_object() -> Vec<u8> {
        let mut object = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let config = object.add_section(
            Vec::new(),
            b".rdata$loadcfg".to_vec(),
            object::SectionKind::ReadOnlyData,
        );
        let mut contents = vec![0; 112];
        contents[..4].copy_from_slice(&112u32.to_le_bytes());
        object.append_section_data(config, &contents, 8);
        object.add_symbol(Symbol {
            name: LOAD_CONFIG_SYMBOL.to_vec(),
            value: 0,
            size: 112,
            kind: object::SymbolKind::Data,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(config),
            flags: object::SymbolFlags::None,
        });
        object.add_symbol(Symbol {
            name: b"__AbsoluteZero".to_vec(),
            value: 0,
            size: 0,
            kind: object::SymbolKind::Data,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Absolute,
            flags: object::SymbolFlags::None,
        });
        let count = object.add_symbol(Symbol {
            name: b"__volatile_metadata".to_vec(),
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
                config,
                Relocation {
                    offset: 104,
                    symbol: count,
                    addend: 0,
                    flags: object::RelocationFlags::Coff {
                        typ: object::pe::IMAGE_REL_AMD64_ADDR64,
                    },
                },
            )
            .unwrap();
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

    fn relocation_object_with_invalid_target() -> Vec<u8> {
        let mut bytes = relocation_object(b"source", b"target");
        let relocation = u32::from_le_bytes(bytes[44..48].try_into().unwrap()) as usize;
        bytes[relocation + 4..relocation + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes
    }

    fn comdat_relocation_object(source: &[u8], target: &[u8]) -> Vec<u8> {
        let mut object = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let text = object.add_subsection(object::write::StandardSection::Text, source);
        object.append_section_data(text, &[0, 0, 0, 0, 0xc3], 1);
        object.section_symbol(text);
        let source = object.add_symbol(Symbol {
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
        object.add_comdat(object::write::Comdat {
            kind: object::ComdatKind::Any,
            symbol: source,
            sections: vec![text],
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

    fn weak_comdat_object(alias: &[u8], fallback: &[u8]) -> Vec<u8> {
        let mut object = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let text = object.add_subsection(object::write::StandardSection::Text, fallback);
        object.append_section_data(text, &[0xc3], 1);
        object.section_symbol(text);
        let fallback_symbol = object.add_symbol(Symbol {
            name: fallback.to_vec(),
            value: 0,
            size: 1,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(text),
            flags: object::SymbolFlags::None,
        });
        object.add_symbol(Symbol {
            name: alias.to_vec(),
            value: 0,
            size: 1,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage,
            weak: true,
            section: SymbolSection::Section(text),
            flags: object::SymbolFlags::None,
        });
        object.add_comdat(object::write::Comdat {
            kind: object::ComdatKind::Any,
            symbol: fallback_symbol,
            sections: vec![text],
        });
        object.write().unwrap()
    }

    fn long_section_name_object() -> Vec<u8> {
        let mut object = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let text = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
        object.append_section_data(text, &[0xc3], 1);
        let entry = object.add_symbol(Symbol {
            name: b"entry".to_vec(),
            value: 0,
            size: 1,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(text),
            flags: object::SymbolFlags::None,
        });
        let eh_frame = object.add_section(
            Vec::new(),
            b".eh_frame".to_vec(),
            object::SectionKind::ReadOnlyData,
        );
        object.append_section_data(eh_frame, &[0; 8], 8);
        object
            .add_relocation(
                eh_frame,
                Relocation {
                    offset: 0,
                    symbol: entry,
                    addend: 0,
                    flags: object::RelocationFlags::Coff {
                        typ: object::pe::IMAGE_REL_AMD64_ADDR64,
                    },
                },
            )
            .unwrap();
        for (name, contents) in [
            (b".a_very_long_section".as_slice(), b"first".as_slice()),
            (b".a_very_long_section2".as_slice(), b"second".as_slice()),
        ] {
            let section =
                object.add_section(Vec::new(), name.to_vec(), object::SectionKind::ReadOnlyData);
            object.append_section_data(section, contents, 1);
        }
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

    fn mixed_contribution_object() -> Vec<u8> {
        let mut object = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let text = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
        object.append_section_data(text, &[0xc3], 1);
        object.add_symbol(Symbol {
            name: b"entry".to_vec(),
            value: 0,
            size: 1,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(text),
            flags: object::SymbolFlags::None,
        });

        let data = object.add_section(Vec::new(), b".data".to_vec(), object::SectionKind::Data);
        object.append_section_data(data, &[1, 2, 3], 4);
        let bss = object.add_section(
            Vec::new(),
            b".bss".to_vec(),
            object::SectionKind::UninitializedData,
        );
        object.append_section_bss(bss, 9, 8);
        let merged = object.add_section(Vec::new(), b".foo$x".to_vec(), object::SectionKind::Data);
        object.append_section_data(merged, &[4, 5], 2);

        let non_empty = object.add_section(
            Vec::new(),
            b".rdata$a".to_vec(),
            object::SectionKind::ReadOnlyData,
        );
        object.append_section_data(non_empty, &[6], 1);
        let mixed_empty = object.add_section(
            Vec::new(),
            b".rdata$z".to_vec(),
            object::SectionKind::ReadOnlyData,
        );
        object.append_section_data(mixed_empty, &[], 8);
        let wholly_empty = object.add_section(
            Vec::new(),
            b".empty$z".to_vec(),
            object::SectionKind::ReadOnlyData,
        );
        object.append_section_data(wholly_empty, &[], 8);

        let discardable =
            object.add_section(Vec::new(), b".debug$S".to_vec(), object::SectionKind::Debug);
        object.append_section_data(discardable, &[7], 1);
        let linker = object.add_section(
            Vec::new(),
            b".drectve".to_vec(),
            object::SectionKind::Linker,
        );
        object.append_section_data(linker, b" /DEFAULTLIB:none", 1);
        // `object::write` deliberately rejects COFF metadata sections, so emit an ordinary
        // section and clear its characteristics in the finished test object below.
        let metadata = object.add_section(
            Vec::new(),
            b".meta".to_vec(),
            object::SectionKind::ReadOnlyData,
        );
        object.append_section_data(metadata, &[8], 1);
        let guard = object.add_section(
            Vec::new(),
            b".gfids$y".to_vec(),
            object::SectionKind::ReadOnlyData,
        );
        object.append_section_data(guard, &[0; 4], 4);
        let mut bytes = object.write().unwrap();
        let section_count = usize::from(u16::from_le_bytes(bytes[2..4].try_into().unwrap()));
        let metadata_header = (0..section_count)
            .map(|index| 20 + index * 40)
            .find(|&offset| &bytes[offset..offset + 5] == b".meta")
            .unwrap();
        bytes[metadata_header + 36..metadata_header + 40].fill(0);
        bytes
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
    fn opt_ref_discards_unreachable_comdat_groups_and_keeps_rooted_ones() {
        let live = comdat_object(
            b"live",
            object::SymbolScope::Linkage,
            object::ComdatKind::Any,
            b"live",
            0,
            true,
        );
        let dead = comdat_object(
            b"dead",
            object::SymbolScope::Linkage,
            object::ComdatKind::Any,
            b"dead",
            0,
            true,
        );
        let objects = [
            crate::coff::CoffObject::parse(&live).unwrap(),
            crate::coff::CoffObject::parse(&dead).unwrap(),
        ];
        let args = crate::args::coff::CoffArgs {
            optimization: crate::args::coff::OptimizationOptions {
                ref_: crate::args::coff::OptSetting::Enabled,
                icf: crate::args::coff::OptSetting::Default,
            },
            ..Default::default()
        };

        let (contributions, _) = collect_contributions_with_roots(
            &objects,
            &args,
            &[b"live".to_vec()],
            &Default::default(),
        )
        .unwrap();

        assert_eq!(
            contributions.len(),
            2,
            "the live COMDAT and its associate remain"
        );
        assert!(
            contributions
                .iter()
                .all(|contribution| match contribution.source {
                    Source::Object { object, .. } => object == 0,
                    Source::Synthetic => false,
                })
        );
    }

    #[test]
    fn opt_noref_preserves_unreachable_comdats() {
        let live = comdat_object(
            b"live",
            object::SymbolScope::Linkage,
            object::ComdatKind::Any,
            b"live",
            0,
            false,
        );
        let dead = comdat_object(
            b"dead",
            object::SymbolScope::Linkage,
            object::ComdatKind::Any,
            b"dead",
            0,
            false,
        );
        let objects = [
            crate::coff::CoffObject::parse(&live).unwrap(),
            crate::coff::CoffObject::parse(&dead).unwrap(),
        ];
        let args = crate::args::coff::CoffArgs {
            optimization: crate::args::coff::OptimizationOptions {
                ref_: crate::args::coff::OptSetting::Disabled,
                icf: crate::args::coff::OptSetting::Default,
            },
            ..Default::default()
        };

        let (contributions, _) = collect_contributions_with_roots(
            &objects,
            &args,
            &[b"live".to_vec()],
            &Default::default(),
        )
        .unwrap();

        assert_eq!(contributions.len(), 2);
        assert!(
            objects
                .iter()
                .all(|object| !object.relocation_index_initialized()),
            "/OPT:NOREF must not allocate relocation indices"
        );
    }

    #[test]
    fn opt_ref_follows_relocations_into_comdats() {
        let caller = relocation_object(b"caller", b"target");
        let target = comdat_object(
            b"target",
            object::SymbolScope::Linkage,
            object::ComdatKind::Any,
            b"target",
            0,
            false,
        );
        let dead = comdat_object(
            b"dead",
            object::SymbolScope::Linkage,
            object::ComdatKind::Any,
            b"dead",
            0,
            false,
        );
        let objects = [
            crate::coff::CoffObject::parse(&caller).unwrap(),
            crate::coff::CoffObject::parse(&target).unwrap(),
            crate::coff::CoffObject::parse(&dead).unwrap(),
        ];
        let args = crate::args::coff::CoffArgs {
            optimization: crate::args::coff::OptimizationOptions {
                ref_: crate::args::coff::OptSetting::Enabled,
                icf: crate::args::coff::OptSetting::Default,
            },
            ..Default::default()
        };

        let (contributions, _) = collect_contributions_with_roots(
            &objects,
            &args,
            &[b"caller".to_vec()],
            &Default::default(),
        )
        .unwrap();

        assert_eq!(contributions.len(), 2);
        assert!(
            contributions
                .iter()
                .all(|contribution| match contribution.source {
                    Source::Object { object, .. } => object != 2,
                    Source::Synthetic => false,
                })
        );
    }

    #[test]
    fn ref_reports_invalid_live_targets_but_skips_discarded_sources() {
        let bytes = relocation_object_with_invalid_target();
        let objects = [crate::coff::CoffObject::parse(&bytes).unwrap()];
        let snapshot = selected_symbol_snapshot(&objects).unwrap();
        let (metadata, _) = SelectedObjectMetadata::new_with_undefined(&snapshot, &[], None);
        let section_groups = [HashMap::new()];
        let analysis = CompactComdatAnalysis::new(&objects, &section_groups).unwrap();
        let live = ComdatResolution {
            analysis,
            ..Default::default()
        };
        let error =
            unreferenced_comdat_sections(&objects, &metadata, &live, &[], &Default::default())
                .unwrap_err();
        assert!(
            format!("{error:?}").contains("invalid COFF relocation symbol"),
            "{error:?}"
        );

        let bytes = relocation_object_with_invalid_target();
        let objects = [crate::coff::CoffObject::parse(&bytes).unwrap()];
        let snapshot = selected_symbol_snapshot(&objects).unwrap();
        let (metadata, _) = SelectedObjectMetadata::new_with_undefined(&snapshot, &[], None);
        let section_groups = [HashMap::new()];
        let analysis = CompactComdatAnalysis::new(&objects, &section_groups).unwrap();
        let discarded = ComdatResolution {
            discarded: HashSet::from([(0, object::SectionIndex(1))]),
            analysis,
            ..Default::default()
        };
        unreferenced_comdat_sections(&objects, &metadata, &discarded, &[], &Default::default())
            .unwrap();
    }

    #[test]
    fn opt_ref_follows_transitive_compact_group_edges() {
        let caller = relocation_object(b"caller", b"middle");
        let middle = comdat_relocation_object(b"middle", b"target");
        let target = comdat_object(
            b"target",
            object::SymbolScope::Linkage,
            object::ComdatKind::Any,
            b"target",
            0,
            false,
        );
        let dead = comdat_object(
            b"dead",
            object::SymbolScope::Linkage,
            object::ComdatKind::Any,
            b"dead",
            0,
            false,
        );
        let objects = [
            crate::coff::CoffObject::parse(&caller).unwrap(),
            crate::coff::CoffObject::parse(&middle).unwrap(),
            crate::coff::CoffObject::parse(&target).unwrap(),
            crate::coff::CoffObject::parse(&dead).unwrap(),
        ];
        let args = crate::args::coff::CoffArgs {
            optimization: crate::args::coff::OptimizationOptions {
                ref_: crate::args::coff::OptSetting::Enabled,
                icf: crate::args::coff::OptSetting::Default,
            },
            ..Default::default()
        };

        let (contributions, _) = collect_contributions_with_roots(
            &objects,
            &args,
            &[b"caller".to_vec()],
            &Default::default(),
        )
        .unwrap();

        assert!(contributions.iter().any(|contribution| {
            matches!(contribution.source, Source::Object { object: 1, .. })
        }));
        assert!(contributions.iter().any(|contribution| {
            matches!(contribution.source, Source::Object { object: 2, .. })
        }));
        assert!(contributions.iter().all(|contribution| {
            !matches!(contribution.source, Source::Object { object: 3, .. })
        }));
    }

    #[test]
    fn parallel_comdat_classification_and_ref_edges_match_single_thread() {
        let caller = relocation_object(b"caller", b"middle");
        let middle = comdat_relocation_object(b"middle", b"target");
        let winner = comdat_object(
            b"target",
            object::SymbolScope::Linkage,
            object::ComdatKind::Any,
            b"winner",
            0,
            true,
        );
        let loser = comdat_object(
            b"target",
            object::SymbolScope::Linkage,
            object::ComdatKind::Any,
            b"loser",
            0,
            false,
        );
        let dead = comdat_object(
            b"dead",
            object::SymbolScope::Linkage,
            object::ComdatKind::Any,
            b"dead",
            0,
            false,
        );
        let objects = [
            crate::coff::CoffObject::parse(&caller).unwrap(),
            crate::coff::CoffObject::parse(&middle).unwrap(),
            crate::coff::CoffObject::parse(&winner).unwrap(),
            crate::coff::CoffObject::parse(&loser).unwrap(),
            crate::coff::CoffObject::parse(&dead).unwrap(),
        ];
        let args = crate::args::coff::CoffArgs {
            optimization: crate::args::coff::OptimizationOptions {
                ref_: crate::args::coff::OptSetting::Enabled,
                icf: crate::args::coff::OptSetting::Default,
            },
            ..Default::default()
        };
        let run = |threads| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| {
                    let resolution = discarded_comdat_sections(&objects).unwrap();
                    let (contributions, redirects) = collect_contributions_with_roots(
                        &objects,
                        &args,
                        &[b"caller".to_vec()],
                        &Default::default(),
                    )
                    .unwrap();
                    let sources = contributions
                        .iter()
                        .map(|contribution| match contribution.source {
                            Source::Object { object, section } => Some((object, section)),
                            Source::Synthetic => None,
                        })
                        .collect::<Vec<_>>();
                    (
                        resolution.discarded,
                        resolution.redirects,
                        sources,
                        redirects,
                    )
                })
        };

        assert_eq!(run(4), run(1));
    }

    #[test]
    fn parallel_live_import_references_match_single_thread() {
        let direct = relocation_object(b"direct_source", b"direct_import");
        let indirect = relocation_object(b"indirect_source", b"__imp_indirect_import");
        let weak = relocation_object(b"weak_source", b"weak_alias");
        let alternate = relocation_object(b"alternate_source", b"alternate_alias");
        let dead = relocation_object(b"dead_source", b"dead_import");
        let objects = [
            crate::coff::CoffObject::parse(&direct).unwrap(),
            crate::coff::CoffObject::parse(&indirect).unwrap(),
            crate::coff::CoffObject::parse(&weak).unwrap(),
            crate::coff::CoffObject::parse(&alternate).unwrap(),
            crate::coff::CoffObject::parse(&dead).unwrap(),
        ];
        let sections = objects
            .iter()
            .map(|object| object.file().section_by_name(".text").unwrap().index())
            .collect::<Vec<_>>();

        // Repeat live contributions enough times to cross the adaptive minimum chunk size at
        // every tested parallel width. The dead object's section is deliberately not present,
        // matching the production contract that this scan receives post-/OPT:REF contributions.
        let mut contributions = Vec::new();
        for _ in 0..80 {
            for (object, &section) in sections.iter().take(4).enumerate() {
                contributions.push(object_test_contribution(
                    contributions.len() as u32,
                    object,
                    section,
                ));
            }
        }
        contributions.push(synthetic_test_contribution(
            contributions.len() as u32,
            b".synthetic",
            1,
        ));

        let snapshot = selected_symbol_snapshot(&objects).unwrap();
        let (metadata, _) = SelectedObjectMetadata::new_with_undefined(&snapshot, &[], None);
        let object_definitions = metadata.definition_names();
        let import_definitions = [
            b"direct_import".to_vec(),
            b"__imp_indirect_import".to_vec(),
            b"weak_import".to_vec(),
            b"alternate_import".to_vec(),
            b"root_import".to_vec(),
            b"dead_import".to_vec(),
        ]
        .into_iter()
        .collect::<HashSet<_>>();
        let mut weak_resolution = linker_utils::coff_runtime::WeakExternalResolution::default();
        weak_resolution
            .apply(
                linker_utils::coff_runtime::WeakExternalRecord {
                    symbol: b"weak_alias",
                    target: b"weak_import",
                    search: linker_utils::coff_symbols::WeakSearch::Alias,
                },
                "weak.obj",
            )
            .unwrap();
        let mut runtime_resolution = linker_utils::coff_runtime::RuntimeResolution::new();
        runtime_resolution
            .parse_and_apply(
                "/alternatename:alternate_alias=alternate_import",
                "alternate.obj",
            )
            .unwrap();
        let roots = [b"root_import".to_vec()];
        let expected = [
            b"direct_import".to_vec(),
            b"__imp_indirect_import".to_vec(),
            b"weak_import".to_vec(),
            b"alternate_import".to_vec(),
            b"root_import".to_vec(),
        ]
        .into_iter()
        .collect::<HashSet<_>>();

        for threads in [1, 2, 4, 10] {
            let actual = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| {
                    live_import_references_with_resolution(
                        &objects,
                        &contributions,
                        &roots,
                        object_definitions,
                        &import_definitions,
                        &weak_resolution,
                        &runtime_resolution,
                    )
                    .unwrap()
                });
            assert_eq!(actual, expected, "thread count {threads}");
            assert!(!actual.contains(b"dead_import".as_slice()));
        }
    }

    #[test]
    fn parallel_contribution_materialization_matches_single_thread() {
        let mixed = mixed_contribution_object();
        let live = comdat_object(
            b"live",
            object::SymbolScope::Linkage,
            object::ComdatKind::Any,
            b"live",
            0,
            false,
        );
        let dead = comdat_object(
            b"dead",
            object::SymbolScope::Linkage,
            object::ComdatKind::Any,
            b"dead",
            0,
            false,
        );
        let objects = [
            crate::coff::CoffObject::parse(&mixed).unwrap(),
            crate::coff::CoffObject::parse(&live).unwrap(),
            crate::coff::CoffObject::parse(&dead).unwrap(),
        ];
        let args = crate::args::coff::CoffArgs {
            force_undefined: vec!["live".into()],
            merges: vec![crate::args::coff::SectionMerge {
                from: ".foo".into(),
                to: ".data".into(),
            }],
            ..Default::default()
        };

        let run = |threads| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| {
                    let (contributions, redirects) = collect_contributions_with_roots(
                        &objects,
                        &args,
                        &[b"entry".to_vec(), b"live".to_vec()],
                        &Default::default(),
                    )
                    .unwrap();
                    let signature = contributions
                        .iter()
                        .map(|contribution| {
                            let source = match contribution.source {
                                Source::Object { object, section } => Some((object, section.0)),
                                Source::Synthetic => None,
                            };
                            (
                                source,
                                contribution.spec.id,
                                contribution.spec.name.clone(),
                                contribution.spec.characteristics,
                                contribution.spec.alignment,
                                contribution.spec.size,
                                contribution.spec.kind,
                                contribution.synthetic_data.clone(),
                            )
                        })
                        .collect::<Vec<_>>();
                    let image = build_image(
                        &objects,
                        &[],
                        &[],
                        b"parallel-contributions.exe",
                        Some("entry"),
                        &args,
                        PeWriterConfig::default(),
                        &[],
                        &Default::default(),
                    )
                    .unwrap()
                    .bytes;
                    (signature, redirects, image)
                })
        };

        let baseline = run(1);
        for threads in [2, 4, 10] {
            assert_eq!(run(threads), baseline, "thread count {threads}");
        }

        let signature = &baseline.0;
        assert!(
            signature
                .iter()
                .enumerate()
                .all(|(index, contribution)| { contribution.1 == ContributionId(index as u32) })
        );
        assert!(signature.iter().any(|contribution| {
            contribution.2 == b".bss"
                && contribution.6 == ContributionKind::Bss
                && contribution.7.is_empty()
        }));
        assert!(
            signature
                .iter()
                .filter(|contribution| contribution.0.is_some())
                .all(|contribution| contribution.7.is_empty()),
            "real sections must remain source-backed until their final output slice"
        );
        assert!(
            signature
                .iter()
                .any(|contribution| contribution.2 == b".data$x")
        );
        assert!(
            signature
                .iter()
                .any(|contribution| contribution.2 == b".rdata$z" && contribution.5 == 0)
        );
        for omitted in [
            b".empty$z".as_slice(),
            b".debug$S",
            b".drectve",
            b".meta",
            b".gfids$y",
        ] {
            assert!(
                signature
                    .iter()
                    .all(|contribution| contribution.2 != omitted),
                "section {} must be filtered",
                String::from_utf8_lossy(omitted)
            );
        }
        assert!(
            signature
                .iter()
                .any(|contribution| { matches!(contribution.0, Some((1, _))) })
        );
        assert!(
            signature
                .iter()
                .all(|contribution| { !matches!(contribution.0, Some((2, _))) })
        );
    }

    #[test]
    fn opt_ref_follows_weak_external_fallback_into_comdat() {
        let caller = relocation_object(b"caller", b"weak_alias");
        let target = weak_comdat_object(b"weak_alias", b"fallback");
        let dead = comdat_object(
            b"dead",
            object::SymbolScope::Linkage,
            object::ComdatKind::Any,
            b"dead",
            0,
            false,
        );
        let objects = [
            crate::coff::CoffObject::parse(&caller).unwrap(),
            crate::coff::CoffObject::parse(&target).unwrap(),
            crate::coff::CoffObject::parse(&dead).unwrap(),
        ];
        let args = crate::args::coff::CoffArgs {
            optimization: crate::args::coff::OptimizationOptions {
                ref_: crate::args::coff::OptSetting::Enabled,
                icf: crate::args::coff::OptSetting::Default,
            },
            ..Default::default()
        };

        let (contributions, _) = collect_contributions_with_roots(
            &objects,
            &args,
            &[b"caller".to_vec()],
            &Default::default(),
        )
        .unwrap();

        assert!(contributions.iter().any(|contribution| {
            matches!(contribution.source, Source::Object { object: 1, .. })
        }));
        assert!(contributions.iter().all(|contribution| {
            !matches!(contribution.source, Source::Object { object: 2, .. })
        }));
    }

    #[test]
    fn opt_ref_follows_alternatename_fallback_into_comdat() {
        let caller = relocation_object(b"caller", b"alias");
        let target = comdat_object(
            b"fallback",
            object::SymbolScope::Linkage,
            object::ComdatKind::Any,
            b"fallback",
            0,
            false,
        );
        let dead = comdat_object(
            b"dead",
            object::SymbolScope::Linkage,
            object::ComdatKind::Any,
            b"dead",
            0,
            false,
        );
        let objects = [
            crate::coff::CoffObject::parse(&caller).unwrap(),
            crate::coff::CoffObject::parse(&target).unwrap(),
            crate::coff::CoffObject::parse(&dead).unwrap(),
        ];
        let args = crate::args::coff::CoffArgs {
            optimization: crate::args::coff::OptimizationOptions {
                ref_: crate::args::coff::OptSetting::Enabled,
                icf: crate::args::coff::OptSetting::Default,
            },
            ..Default::default()
        };
        let mut runtime_resolution = linker_utils::coff_runtime::RuntimeResolution::new();
        runtime_resolution
            .parse_and_apply("/alternatename:alias=fallback", "directives.obj")
            .unwrap();

        let (contributions, _) = collect_contributions_with_roots(
            &objects,
            &args,
            &[b"caller".to_vec()],
            &runtime_resolution,
        )
        .unwrap();

        assert!(contributions.iter().any(|contribution| {
            matches!(contribution.source, Source::Object { object: 1, .. })
        }));
        assert!(contributions.iter().all(|contribution| {
            !matches!(contribution.source, Source::Object { object: 2, .. })
        }));
    }

    #[test]
    fn opt_ref_default_matches_lld_release_and_debug_profiles() {
        let live = comdat_object(
            b"live",
            object::SymbolScope::Linkage,
            object::ComdatKind::Any,
            b"live",
            0,
            false,
        );
        let dead = comdat_object(
            b"dead",
            object::SymbolScope::Linkage,
            object::ComdatKind::Any,
            b"dead",
            0,
            false,
        );
        let objects = [
            crate::coff::CoffObject::parse(&live).unwrap(),
            crate::coff::CoffObject::parse(&dead).unwrap(),
        ];

        let (release, _) = collect_contributions_with_roots(
            &objects,
            &Default::default(),
            &[b"live".to_vec()],
            &Default::default(),
        )
        .unwrap();
        assert_eq!(release.len(), 1);

        let debug = crate::args::coff::CoffArgs {
            debug: true,
            ..Default::default()
        };
        let (debug, _) = collect_contributions_with_roots(
            &objects,
            &debug,
            &[b"live".to_vec()],
            &Default::default(),
        )
        .unwrap();
        assert_eq!(debug.len(), 2);
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
    fn long_section_names_survive_mapping_for_header_only_truncation() {
        let args = crate::args::coff::CoffArgs::default();
        assert_eq!(merged_name(b".eh_frame", &args).unwrap(), b".eh_frame");
        assert_eq!(
            merged_name(b".a_very_long_section$z", &args).unwrap(),
            b".a_very_long_section$z"
        );
    }

    #[test]
    fn emits_lld_compatible_truncated_headers_for_long_sections() {
        let bytes = long_section_name_object();
        let object = crate::coff::CoffObject::parse(&bytes).unwrap();
        let image = build_image(
            &[object],
            &[],
            &[],
            b"long-sections.exe",
            Some("entry"),
            &crate::args::coff::CoffArgs::default(),
            PeWriterConfig::default(),
            &[],
            &Default::default(),
        )
        .unwrap();

        let file = object::File::parse(image.bytes.as_slice()).unwrap();
        let eh_frame = file.section_by_name(".eh_fram").unwrap();
        assert_eq!(
            u64::from_le_bytes(eh_frame.data().unwrap()[..8].try_into().unwrap()),
            file.section_by_name(".text").unwrap().address()
        );
        assert_eq!(
            file.sections()
                .filter(|section| section.name().unwrap() == ".a_very_")
                .count(),
            2
        );
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
                (b"value".as_slice(), 9, true),
                (b"function".as_slice(), 10, false)
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
            for object in 0..2 {
                let primary = discarded
                    .analysis
                    .node((object, object::SectionIndex(1)))
                    .unwrap();
                let associate = discarded
                    .analysis
                    .node((object, object::SectionIndex(2)))
                    .unwrap();
                let group = discarded.analysis.group_by_node[primary];
                assert_eq!(discarded.analysis.group_by_node[associate], group);
                assert_eq!(discarded.analysis.groups[group], [primary, associate]);
            }
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
    fn duplicate_comdats_allow_different_associative_children() {
        for (winner_has_child, loser_has_child) in [(true, false), (false, true)] {
            let winner = comdat_object(
                b"different-associates",
                object::SymbolScope::Linkage,
                object::ComdatKind::Any,
                b"winner",
                0,
                winner_has_child,
            );
            let loser = comdat_object(
                b"different-associates",
                object::SymbolScope::Linkage,
                object::ComdatKind::Any,
                b"loser",
                0,
                loser_has_child,
            );
            let objects = [
                crate::coff::CoffObject::parse(&winner).unwrap(),
                crate::coff::CoffObject::parse(&loser).unwrap(),
            ];

            let resolution = discarded_comdat_sections(&objects).unwrap();
            assert_eq!(resolution.discarded.len(), 1 + usize::from(loser_has_child));
            assert_eq!(
                resolution.redirects[&(1, object::SectionIndex(1))],
                (0, object::SectionIndex(1))
            );
            assert_eq!(resolution.redirects.len(), 1);
            assert_eq!(
                resolution
                    .analysis
                    .groups
                    .iter()
                    .map(Vec::len)
                    .filter(|len| *len > 1)
                    .collect::<Vec<_>>(),
                if winner_has_child || loser_has_child {
                    vec![2]
                } else {
                    Vec::new()
                }
            );
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
            selected
                .directives
                .runtime_resolution
                .mismatch_value("RuntimeLibrary"),
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
    fn embeds_generated_manifest_with_requested_id_uac_and_dependencies() {
        let directory = tempfile::tempdir().unwrap();
        let sidecar = directory.path().join("app.manifest");
        let args = crate::args::coff::CoffArgs {
            manifest_requested: true,
            manifest_mode_requested: true,
            manifest_embed: Some(crate::args::coff::ManifestEmbed::Id(7)),
            manifest_file: Some(sidecar.clone().into_boxed_path()),
            manifest_dependencies: vec![crate::args::coff::ManifestDependency {
                value: "type='win32' name='Common-Controls' version='6.0.0.0'".into(),
            }],
            manifest_uac: Some(crate::args::coff::ManifestUac {
                level: crate::args::coff::ManifestExecutionLevel::RequireAdministrator,
                ui_access: true,
            }),
            manifest_uac_requested: true,
            ..Default::default()
        };
        let mut resources = Vec::new();

        prepare_manifest(
            &crate::fs::OsFileSystem,
            &args,
            &Default::default(),
            &mut resources,
        )
        .unwrap();

        assert_eq!(resources.len(), 1);
        let record = &resources[0];
        assert_eq!(
            record.resource_type,
            linker_utils::pe_resources::ResourceId::Id(linker_utils::pe_manifest::RT_MANIFEST)
        );
        assert_eq!(record.name, linker_utils::pe_resources::ResourceId::Id(7));
        let xml = std::str::from_utf8(&record.data).unwrap();
        assert!(xml.contains("Common-Controls"));
        assert!(xml.contains("requireAdministrator"));
        assert!(xml.contains("uiAccess=\"true\""));
        assert_eq!(std::fs::read(sidecar).unwrap(), record.data);

        let object_bytes = long_section_name_object();
        let object = crate::coff::CoffObject::parse(&object_bytes).unwrap();
        let image = build_image(
            &[object],
            &[],
            &[],
            b"manifest.exe",
            Some("entry"),
            &args,
            PeWriterConfig::default(),
            &resources,
            &Default::default(),
        )
        .unwrap();
        let file = object::File::parse(image.bytes.as_slice()).unwrap();
        let rsrc = file.section_by_name(".rsrc").unwrap();
        assert!(
            rsrc.data()
                .unwrap()
                .windows(b"requireAdministrator".len())
                .any(|window| window == b"requireAdministrator")
        );
    }

    #[test]
    fn manifest_embed_rejects_conflicting_resource_id() {
        let args = crate::args::coff::CoffArgs {
            manifest_requested: true,
            manifest_mode_requested: true,
            manifest_embed: Some(crate::args::coff::ManifestEmbed::Id(1)),
            ..Default::default()
        };
        let mut resources = vec![
            linker_utils::pe_manifest::manifest_resource(
                1,
                linker_utils::pe_manifest::MANIFEST_LANGUAGE_NEUTRAL,
                b"input".to_vec(),
            )
            .unwrap(),
        ];

        let error = prepare_manifest(
            &crate::fs::OsFileSystem,
            &args,
            &Default::default(),
            &mut resources,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("conflicts with an input resource"));
    }

    #[test]
    fn manifest_inputs_and_selected_directives_merge_into_dll_resource() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first.manifest");
        let second = directory.path().join("second.manifest");
        std::fs::write(
            &first,
            br#"<?xml version="1.0"?><assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><assemblyIdentity type="win32" name="app" version="1.0.0.0"/></assembly>"#,
        )
        .unwrap();
        std::fs::write(
            &second,
            br#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><description>second input</description></assembly>"#,
        )
        .unwrap();
        let args = crate::args::coff::CoffArgs {
            is_dll: true,
            manifest_requested: true,
            manifest_mode_requested: true,
            manifest_embed: Some(crate::args::coff::ManifestEmbed::DefaultId),
            manifest_inputs: vec![first.into_boxed_path(), second.into_boxed_path()],
            ..Default::default()
        };
        let directives = crate::args::coff::CoffArgs {
            manifest_requested: true,
            manifest_dependencies: vec![crate::args::coff::ManifestDependency {
                value: "type='win32' name='Directive.Dependency' version='1.2.3.4'".into(),
            }],
            ..Default::default()
        };
        let mut resources = Vec::new();

        prepare_manifest(&crate::fs::OsFileSystem, &args, &directives, &mut resources).unwrap();

        assert_eq!(resources.len(), 1);
        assert_eq!(
            resources[0].name,
            linker_utils::pe_resources::ResourceId::Id(linker_utils::pe_manifest::DLL_MANIFEST_ID)
        );
        let xml = std::str::from_utf8(&resources[0].data).unwrap();
        assert!(xml.contains("second input"));
        assert!(xml.contains("Directive.Dependency"));
        assert!(!xml.contains("requestedExecutionLevel"));
    }

    #[test]
    fn manifest_resource_conflict_is_language_specific() {
        let args = crate::args::coff::CoffArgs {
            manifest_requested: true,
            manifest_mode_requested: true,
            manifest_embed: Some(crate::args::coff::ManifestEmbed::Id(1)),
            ..Default::default()
        };
        let mut resources = vec![
            linker_utils::pe_manifest::manifest_resource(1, 0x409, b"<assembly/>".to_vec())
                .unwrap(),
        ];

        prepare_manifest(
            &crate::fs::OsFileSystem,
            &args,
            &Default::default(),
            &mut resources,
        )
        .unwrap();

        assert_eq!(resources.len(), 2);
        assert!(resources.iter().any(|record| record.language == 0));
        assert!(resources.iter().any(|record| record.language == 0x409));
    }

    #[test]
    fn manifest_input_requires_embedding_and_sidecar_uses_full_output_name() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.manifest");
        std::fs::write(&input, b"<assembly></assembly>").unwrap();
        let invalid = crate::args::coff::CoffArgs {
            manifest_requested: true,
            manifest_inputs: vec![input.into_boxed_path()],
            ..Default::default()
        };
        let error = prepare_manifest(
            &crate::fs::OsFileSystem,
            &invalid,
            &Default::default(),
            &mut Vec::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("requires /MANIFEST:EMBED"));

        let output = directory.path().join("sidecar.exe");
        let mut args = crate::args::coff::CoffArgs {
            manifest_requested: true,
            manifest_mode_requested: true,
            ..Default::default()
        };
        args.common.output = output.into();
        prepare_manifest(
            &crate::fs::OsFileSystem,
            &args,
            &Default::default(),
            &mut Vec::new(),
        )
        .unwrap();
        assert!(directory.path().join("sidecar.exe.manifest").is_file());
        assert!(!directory.path().join("sidecar.manifest").exists());
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
    fn rejects_llvm_bitcode_as_a_pe_input() {
        let directory = tempfile::tempdir().unwrap();
        let bitcode_path = directory.path().join("module.obj");
        // LLVM bitcode's stable four-byte magic makes this a representative IR
        // input without requiring an external compiler fixture.
        std::fs::write(&bitcode_path, b"BC\xc0\xde\0\0\0\0\0\0\0\0\0\0\0\0").unwrap();

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
            &bitcode_path,
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
            Ok(_) => panic!("accepted LLVM bitcode as a PE input"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains("cannot identify COFF input"), "{error}");
        assert!(error.contains("module.obj"), "{error}");
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
            placements: linker_utils::pe_sections::ContributionPlacements::default(),
            file_size: 0,
            size_of_image: 0x1000,
        };
        let error = prepare_tls_directory(
            &[],
            &[],
            &layout,
            &HashMap::new(),
            &[],
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
            placements: linker_utils::pe_sections::ContributionPlacements::default(),
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
    fn retains_crt_load_config_at_its_symbol_and_applies_relocations() {
        let bytes = crt_load_config_object(312, 8);
        let object = crate::coff::CoffObject::parse(&bytes).unwrap();
        let config = PeWriterConfig {
            image_base: 0x0000_0001_8000_0000,
            ..PeWriterConfig::default()
        };
        let image = build_image(
            &[object],
            &[],
            &[],
            b"cookie.exe",
            None,
            &crate::args::coff::CoffArgs::default(),
            config,
            &[],
            &Default::default(),
        )
        .unwrap()
        .bytes;
        let directory_rva = u32::from_le_bytes(image[0x158..0x15c].try_into().unwrap());
        assert_ne!(directory_rva, 0);
        assert_eq!(
            u32::from_le_bytes(image[0x15c..0x160].try_into().unwrap()),
            312
        );
        assert_eq!(
            u64::from_le_bytes(image[0x160..0x168].try_into().unwrap()),
            0
        );
        assert_ne!(
            u32::from_le_bytes(image[0x130..0x134].try_into().unwrap()),
            0
        );
        let reloc_size =
            usize::try_from(u32::from_le_bytes(image[0x134..0x138].try_into().unwrap())).unwrap();
        let file = object::File::parse(image.as_slice()).unwrap();
        assert!(file.section_by_name(".loadcfg").is_none());
        let rdata = file.section_by_name(".rdata").unwrap();
        let rdata_rva = u32::try_from(rdata.address() - config.image_base).unwrap();
        let directory_offset = usize::try_from(directory_rva - rdata_rva).unwrap();
        let directory = &rdata.data().unwrap()[directory_offset..directory_offset + 312];
        assert_eq!(u32::from_le_bytes(directory[..4].try_into().unwrap()), 312);
        let data_va = file.section_by_name(".data").unwrap().address();
        assert_eq!(
            u64::from_le_bytes(directory[88..96].try_into().unwrap()),
            data_va
        );
        let relocations = linker_utils::pe_base_relocs::parse_amd64_base_relocation_table(
            &file.section_by_name(".reloc").unwrap().data().unwrap()[..reloc_size],
            u32::from_le_bytes(image[0xd0..0xd4].try_into().unwrap()),
        )
        .unwrap();
        assert!(relocations.contains(&(directory_rva + 88)));

        let object = crate::coff::CoffObject::parse(&bytes).unwrap();
        let fixed_args = crate::args::coff::CoffArgs {
            fixed: true,
            ..Default::default()
        };
        let fixed = build_image(
            &[object],
            &[],
            &[],
            b"cookie-fixed.exe",
            None,
            &fixed_args,
            config,
            &[],
            &Default::default(),
        )
        .unwrap()
        .bytes;
        assert_eq!(
            u32::from_le_bytes(fixed[0x130..0x134].try_into().unwrap()),
            0
        );
    }

    #[test]
    fn absolute_zero_guard_load_config_fields_are_not_base_relocations() {
        let bytes = guard_absolute_load_config_object();
        let object = crate::coff::CoffObject::parse(&bytes).unwrap();
        let mut runtime = linker_utils::coff_runtime::RuntimeResolution::new();
        runtime
            .parse_and_apply(
                "/alternatename:__volatile_metadata=__AbsoluteZero",
                "loadcfg.obj",
            )
            .unwrap();
        let image = build_image(
            &[object],
            &[],
            &[],
            b"guard-zero.exe",
            None,
            &crate::args::coff::CoffArgs::default(),
            PeWriterConfig::default(),
            &[],
            &runtime,
        )
        .unwrap()
        .bytes;
        let directory_rva = u32::from_le_bytes(image[0x158..0x15c].try_into().unwrap());
        assert_ne!(directory_rva, 0);
        assert_eq!(
            u32::from_le_bytes(image[0x15c..0x160].try_into().unwrap()),
            112
        );
        assert_eq!(
            u32::from_le_bytes(image[0x130..0x134].try_into().unwrap()),
            0
        );
        let file = object::File::parse(image.as_slice()).unwrap();
        let rdata = file.section_by_name(".rdata").unwrap();
        let rdata_rva =
            u32::try_from(rdata.address() - PeWriterConfig::default().image_base).unwrap();
        let offset = usize::try_from(directory_rva - rdata_rva).unwrap();
        assert_eq!(
            u64::from_le_bytes(
                rdata.data().unwrap()[offset + 104..offset + 112]
                    .try_into()
                    .unwrap()
            ),
            0
        );
    }

    #[test]
    fn accepts_misaligned_crt_load_config_symbol_like_lld() {
        let bytes = crt_load_config_object(312, 4);
        let object = crate::coff::CoffObject::parse(&bytes).unwrap();
        let image = build_image(
            &[object],
            &[],
            &[],
            b"misaligned-load-config.exe",
            None,
            &crate::args::coff::CoffArgs::default(),
            PeWriterConfig::default(),
            &[],
            &Default::default(),
        )
        .unwrap()
        .bytes;
        assert_ne!(
            u32::from_le_bytes(image[0x158..0x15c].try_into().unwrap()),
            0
        );
        assert_eq!(
            u32::from_le_bytes(image[0x15c..0x160].try_into().unwrap()),
            312
        );
    }

    #[test]
    fn publishes_small_readable_crt_load_config_size_like_lld() {
        let bytes = crt_load_config_object(2, 8);
        let object = crate::coff::CoffObject::parse(&bytes).unwrap();
        let image = build_image(
            &[object],
            &[],
            &[],
            b"small-load-config.exe",
            None,
            &crate::args::coff::CoffArgs::default(),
            PeWriterConfig::default(),
            &[],
            &Default::default(),
        )
        .unwrap()
        .bytes;
        assert_ne!(
            u32::from_le_bytes(image[0x158..0x15c].try_into().unwrap()),
            0
        );
        assert_eq!(
            u32::from_le_bytes(image[0x15c..0x160].try_into().unwrap()),
            2
        );
    }

    #[test]
    fn ignores_absolute_load_config_symbol() {
        let mut input = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let data = input.add_section(Vec::new(), b".data".to_vec(), object::SectionKind::Data);
        input.append_section_data(data, &[1], 1);
        input.add_symbol(Symbol {
            name: LOAD_CONFIG_SYMBOL.to_vec(),
            value: 0,
            size: 0,
            kind: object::SymbolKind::Data,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Absolute,
            flags: object::SymbolFlags::None,
        });
        let bytes = input.write().unwrap();
        let object = crate::coff::CoffObject::parse(&bytes).unwrap();
        let image = build_image(
            &[object],
            &[],
            &[],
            b"absolute-load-config.exe",
            None,
            &crate::args::coff::CoffArgs::default(),
            PeWriterConfig::default(),
            &[],
            &Default::default(),
        )
        .unwrap()
        .bytes;
        assert_eq!(
            u64::from_le_bytes(image[0x158..0x160].try_into().unwrap()),
            0
        );
    }

    #[test]
    fn extracts_comdat_load_config_from_archive_and_publishes_index_ten() {
        let directory = tempfile::tempdir().unwrap();
        let archive_path = directory.path().join("loadcfg.lib");
        std::fs::write(
            &archive_path,
            single_member_archive(b"loadcfg.obj", &crt_load_config_object(312, 8)),
        )
        .unwrap();
        let args = crate::args::coff::CoffArgs {
            is_dll: true,
            no_entry: true,
            ..Default::default()
        };
        let fs = crate::fs::OsFileSystem;
        let storage = colosseum::sync::Arena::new();
        let mut inputs = Vec::new();
        open_input(&fs, &archive_path, &args, &storage, &mut inputs, false).unwrap();
        let selected = select_inputs_to_fixpoint(&fs, &args, &[], &storage, &mut inputs).unwrap();
        assert_eq!(selected.objects.len(), 1);
        let image = build_image(
            &selected.objects,
            &[],
            &[],
            b"loadcfg.dll",
            None,
            &args,
            PeWriterConfig::default(),
            &[],
            &selected.directives.runtime_resolution,
        )
        .unwrap()
        .bytes;
        assert_ne!(
            u32::from_le_bytes(image[0x158..0x15c].try_into().unwrap()),
            0
        );
        assert_eq!(
            u32::from_le_bytes(image[0x15c..0x160].try_into().unwrap()),
            312
        );
        assert_eq!(
            u64::from_le_bytes(image[0x160..0x168].try_into().unwrap()),
            0
        );
    }

    #[test]
    fn rejects_uninitialized_crt_load_config_symbol() {
        let mut input = WritableObject::new(
            object::BinaryFormat::Coff,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let bss = input.add_section(
            Vec::new(),
            b".bss".to_vec(),
            object::SectionKind::UninitializedData,
        );
        input.append_section_bss(bss, 320, 8);
        input.add_symbol(Symbol {
            name: LOAD_CONFIG_SYMBOL.to_vec(),
            value: 0,
            size: 320,
            kind: object::SymbolKind::Data,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(bss),
            flags: object::SymbolFlags::None,
        });
        let bytes = input.write().unwrap();
        let object = crate::coff::CoffObject::parse(&bytes).unwrap();
        let error = build_image(
            &[object],
            &[],
            &[],
            b"bss-load-config.exe",
            None,
            &crate::args::coff::CoffArgs::default(),
            PeWriterConfig::default(),
            &[],
            &Default::default(),
        )
        .err()
        .unwrap();
        assert!(format!("{error:?}").contains("uninitialized data"));
    }

    #[test]
    fn security_cookie_without_crt_load_config_does_not_synthesize_one() {
        let bytes = crt_load_config_object(312, 8);
        let file = object::File::parse(bytes.as_slice()).unwrap();
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
        assert!(
            file.symbols()
                .any(|symbol| symbol.name().unwrap() == "_load_config_used")
        );
        let bytes = object.write().unwrap();
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
        assert_eq!(
            u32::from_le_bytes(image[0x158..0x15c].try_into().unwrap()),
            0
        );
        assert_eq!(
            u32::from_le_bytes(image[0x15c..0x160].try_into().unwrap()),
            0
        );
        assert_eq!(
            u64::from_le_bytes(image[0x160..0x168].try_into().unwrap()),
            0
        );
    }

    #[test]
    fn rejects_out_of_bounds_crt_load_config_size() {
        let bytes = crt_load_config_object(313, 8);
        let object = crate::coff::CoffObject::parse(&bytes).unwrap();
        let error = build_image(
            &[object],
            &[],
            &[],
            b"bad-load-config.exe",
            None,
            &crate::args::coff::CoffArgs::default(),
            PeWriterConfig::default(),
            &[],
            &Default::default(),
        )
        .err()
        .unwrap();
        assert!(format!("{error:?}").contains("beyond its containing section"));
    }

    #[test]
    fn sorts_opaque_pdata_and_publishes_exact_exception_directory() {
        use linker_utils::pe_sections::OutputSection;
        use linker_utils::pe_sections::SectionLayout;

        let mut image = vec![0; 0x600];
        let later = [0x1000u32, 0, 0xdead_beef]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let earlier = [0x200u32, 1, 0xffff_fff1]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        image[0x400..0x418].copy_from_slice(&[later.as_slice(), earlier.as_slice()].concat());
        let layout = SectionLayout {
            sections: vec![OutputSection {
                name: b".pdata".to_vec(),
                characteristics: readonly_data_characteristics(),
                rva: 0x3000,
                virtual_size: 24,
                file_offset: Some(0x400),
                raw_size: 0x200,
                contributions: Vec::new(),
            }],
            placements: linker_utils::pe_sections::ContributionPlacements::default(),
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
            Some((0x3000, 24))
        );
        assert_eq!(
            &image[0x400..0x418],
            [earlier.as_slice(), later.as_slice()].concat()
        );
    }

    #[test]
    fn rejects_malformed_pdata_shape_before_publishing_directory() {
        use linker_utils::pe_sections::OutputSection;
        use linker_utils::pe_sections::SectionLayout;

        let mut image = vec![0; 0x600];
        let layout = SectionLayout {
            sections: vec![OutputSection {
                name: b".pdata".to_vec(),
                characteristics: readonly_data_characteristics(),
                rva: 0x3000,
                virtual_size: 13,
                file_offset: Some(0x400),
                raw_size: 0x200,
                contributions: Vec::new(),
            }],
            placements: linker_utils::pe_sections::ContributionPlacements::default(),
            file_size: 0x600,
            size_of_image: 0x4000,
        };

        let error = canonicalize_exception_directory(
            &mut image,
            &layout,
            &crate::args::coff::CoffArgs::default(),
        )
        .unwrap_err();
        assert!(format!("{error:?}").contains("not a multiple of 12"));
    }
}
