//! Command-line parsing for the MSVC-compatible (`link.exe`) driver.

use super::CommonArgs;
use super::Input;
use super::InputSpec;
use super::Modifiers;
use crate::alignment::Alignment;
use crate::bail;
use crate::ensure;
use crate::error::Context;
use crate::error::Result;
use crate::platform;
use linker_utils::coff_runtime::RuntimeDirective;
use linker_utils::coff_runtime::RuntimeResolution;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoffMachine {
    X86_64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Subsystem {
    Console,
    Windows,
    Native,
    EfiApplication,
    EfiBootServiceDriver,
    EfiRuntimeDriver,
    EfiRom,
    Posix,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SubsystemSpec {
    pub(crate) kind: Subsystem,
    /// Optional `major.minor` version, preserved for the PE optional header writer.
    pub(crate) version: Option<(u16, u16)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReserveCommit {
    pub(crate) reserve: u64,
    pub(crate) commit: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ImageBase {
    pub(crate) address: u64,
    pub(crate) max_size: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OptSetting {
    Default,
    Enabled,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OptimizationOptions {
    pub(crate) ref_: OptSetting,
    pub(crate) icf: OptSetting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ForceOptions {
    pub(crate) multiple: bool,
    pub(crate) unresolved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SectionMerge {
    pub(crate) from: String,
    pub(crate) to: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SectionAttributes {
    pub(crate) name: String,
    /// Canonical upper-case link.exe attribute letters.
    pub(crate) attributes: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GuardOptions {
    pub(crate) control_flow: OptSetting,
    pub(crate) no_long_jump: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct GuardSymbolFlags {
    /// The symbol is present in GFIDS but explicitly suppressed as a valid CFG target.
    pub(crate) suppressed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuardSymbol {
    pub(crate) symbol: String,
    pub(crate) flags: GuardSymbolFlags,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManifestDependency {
    /// The link.exe manifest dependency payload, preserving symbol and assembly-name case.
    pub(crate) value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManifestExecutionLevel {
    AsInvoker,
    HighestAvailable,
    RequireAdministrator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ManifestUac {
    pub(crate) level: ManifestExecutionLevel,
    pub(crate) ui_access: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManifestEmbed {
    DefaultId,
    Id(u16),
}

/// One `/EXPORT:` directive in its link.exe-compatible form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExportSpec {
    /// Public name placed in the PE export directory.
    pub(crate) name: String,
    /// Internal symbol name, or a forwarder such as `KERNEL32.Sleep`.
    pub(crate) target: String,
    pub(crate) ordinal: Option<u16>,
    pub(crate) noname: bool,
    pub(crate) data: bool,
    /// Export from the DLL but omit it from the generated import library.
    pub(crate) private: bool,
}

#[derive(Debug)]
pub struct CoffArgs {
    pub(crate) common: CommonArgs,
    pub(crate) entry: Option<String>,
    pub(crate) no_entry: bool,
    pub(crate) subsystem: Option<SubsystemSpec>,
    pub(crate) is_dll: bool,
    pub(crate) machine: CoffMachine,
    pub(crate) lib_search_path: Vec<Box<Path>>,
    pub(crate) default_libraries: Vec<String>,
    pub(crate) no_default_libraries: bool,
    pub(crate) excluded_default_libraries: Vec<String>,
    pub(crate) exports: Vec<ExportSpec>,
    /// Microsoft module-definition files supplied with `/DEF:path`.
    pub(crate) definition_files: Vec<Box<Path>>,
    pub(crate) force_undefined: Vec<String>,
    pub(crate) debug: bool,
    pub(crate) no_logo: bool,
    pub(crate) section_alignment: Option<u32>,
    pub(crate) file_alignment: Option<u32>,
    pub(crate) image_base: Option<ImageBase>,
    pub(crate) stack: Option<ReserveCommit>,
    pub(crate) heap: Option<ReserveCommit>,
    pub(crate) image_version: Option<(u16, u16)>,
    pub(crate) dynamic_base: bool,
    pub(crate) fixed: bool,
    pub(crate) nx_compat: bool,
    pub(crate) optimization: OptimizationOptions,
    pub(crate) whole_archive: bool,
    pub(crate) whole_archive_libraries: Vec<String>,
    pub(crate) force: ForceOptions,
    pub(crate) import_library: Option<Box<Path>>,
    pub(crate) pdb: Option<Box<Path>>,
    pub(crate) manifest: bool,
    /// Whether a manifest switch/directive was explicitly supplied.
    pub(crate) manifest_requested: bool,
    /// Whether `/MANIFEST` itself was supplied, as opposed to an option that
    /// merely contributes to the manifest.
    pub(crate) manifest_mode_requested: bool,
    /// Resource ID selected by `/MANIFEST:EMBED[,ID=n]`.
    pub(crate) manifest_embed: Option<ManifestEmbed>,
    pub(crate) manifest_inputs: Vec<Box<Path>>,
    pub(crate) manifest_file: Option<Box<Path>>,
    pub(crate) manifest_uac: Option<ManifestUac>,
    pub(crate) manifest_uac_requested: bool,
    pub(crate) manifest_dependencies: Vec<ManifestDependency>,
    /// DLL names selected for delay loading by `/DELAYLOAD:name`.
    pub(crate) delay_load_dlls: Vec<String>,
    pub(crate) runtime_resolution: RuntimeResolution,
    pub(crate) guard: GuardOptions,
    pub(crate) guard_symbols: Vec<GuardSymbol>,
    pub(crate) edit_and_continue: bool,
    pub(crate) disallowed_libraries: Vec<String>,
    pub(crate) merges: Vec<SectionMerge>,
    pub(crate) section_attributes: Vec<SectionAttributes>,
}

impl CoffArgs {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            common: CommonArgs::from_env()?,
            ..Default::default()
        })
    }
}

impl Default for CoffArgs {
    fn default() -> Self {
        Self {
            common: CommonArgs {
                output: Arc::from(Path::new("a.exe")),
                ..CommonArgs::default()
            },
            entry: None,
            no_entry: false,
            subsystem: None,
            is_dll: false,
            machine: CoffMachine::X86_64,
            lib_search_path: Vec::new(),
            default_libraries: Vec::new(),
            no_default_libraries: false,
            excluded_default_libraries: Vec::new(),
            exports: Vec::new(),
            definition_files: Vec::new(),
            force_undefined: Vec::new(),
            debug: false,
            no_logo: false,
            section_alignment: None,
            file_alignment: None,
            image_base: None,
            stack: None,
            heap: None,
            image_version: None,
            dynamic_base: true,
            fixed: false,
            nx_compat: true,
            optimization: OptimizationOptions {
                ref_: OptSetting::Default,
                icf: OptSetting::Default,
            },
            whole_archive: false,
            whole_archive_libraries: Vec::new(),
            force: ForceOptions {
                multiple: false,
                unresolved: false,
            },
            import_library: None,
            pdb: None,
            manifest: true,
            manifest_requested: false,
            manifest_mode_requested: false,
            manifest_embed: None,
            manifest_inputs: Vec::new(),
            manifest_file: None,
            manifest_uac: None,
            manifest_uac_requested: false,
            manifest_dependencies: Vec::new(),
            delay_load_dlls: Vec::new(),
            runtime_resolution: RuntimeResolution::new(),
            guard: GuardOptions {
                control_flow: OptSetting::Default,
                no_long_jump: false,
            },
            guard_symbols: Vec::new(),
            edit_and_continue: false,
            disallowed_libraries: Vec::new(),
            merges: Vec::new(),
            section_attributes: Vec::new(),
        }
    }
}

impl platform::Args for CoffArgs {
    fn parse<S, I>(&mut self, input: I) -> Result
    where
        S: AsRef<str>,
        I: Iterator<Item = S>,
    {
        parse(self, input)
    }

    fn should_strip_debug(&self) -> bool {
        false
    }

    fn should_strip_all(&self) -> bool {
        false
    }

    fn force_undefined_symbol_names(&self) -> &[String] {
        &self.force_undefined
    }

    fn entry_point<'a>(
        &'a self,
        _linker_script_entry: Option<&'a [u8]>,
    ) -> platform::EntryPoint<'a> {
        self.entry
            .as_deref()
            .map_or(platform::EntryPoint::None, |entry| {
                platform::EntryPoint::Symbol(entry.as_bytes())
            })
    }

    fn lib_search_path(&self) -> &[Box<Path>] {
        &self.lib_search_path
    }

    fn common(&self) -> &CommonArgs {
        &self.common
    }

    fn common_mut(&mut self) -> &mut CommonArgs {
        &mut self.common
    }

    fn should_export_all_dynamic_symbols(&self) -> bool {
        false
    }

    fn should_export_dynamic(&self, _lib_name: &[u8]) -> bool {
        false
    }

    fn loadable_segment_alignment(&self) -> Alignment {
        // The PE section alignment default is 4096 bytes.
        Alignment { exponent: 12 }
    }

    fn should_merge_sections(&self) -> bool {
        true
    }

    fn should_output_executable(&self) -> bool {
        true
    }

    fn is_ignored_flag(&self, _flag: &str) -> bool {
        false
    }
}

pub(crate) fn parse<S: AsRef<str>, I: Iterator<Item = S>>(args: &mut CoffArgs, input: I) -> Result {
    let expanded = expand_response_files(input)?;
    parse_tokens(args, expanded.iter().map(String::as_str), "command line")?;
    validate_alignments(args)?;
    args.common.report_unrecognized()
}

/// Parses the contents of a COFF `.drectve` section through the regular link.exe option parser.
///
/// MSVC emits these strings using the Windows command-line quoting rules rather than shell
/// quoting. Keeping this entry point shared prevents compiler-generated directives from subtly
/// differing from their command-line equivalents.
pub(crate) fn parse_directives(args: &mut CoffArgs, directives: &str) -> Result {
    let tokens = windows_command_line_args(directives);
    parse_tokens(args, tokens.iter().map(String::as_str), ".drectve section")?;
    validate_alignments(args)?;
    args.common.report_unrecognized()
}

fn parse_tokens<'a, I>(args: &mut CoffArgs, input: I, source: &str) -> Result
where
    I: Iterator<Item = &'a str>,
{
    let mut input = input.peekable();

    while let Some(arg) = input.next() {
        let Some((prefix, option)) = arg
            .strip_prefix('/')
            .map(|option| ('/', option))
            .or_else(|| arg.strip_prefix('-').map(|option| ('-', option)))
        else {
            add_input(args, arg);
            continue;
        };
        let (name, inline_value) = option
            .split_once(':')
            .map_or((option, None), |(name, value)| (name, Some(value)));
        let name = name.to_ascii_lowercase();

        match name.as_str() {
            "nologo" if inline_value.is_none() => args.no_logo = true,
            "out" => {
                let value = required_value("/OUT", inline_value, &mut input)?;
                args.common.output = Arc::from(Path::new(value));
            }
            "entry" => {
                args.entry = Some(required_value("/ENTRY", inline_value, &mut input)?.to_owned());
            }
            "noentry" if inline_value.is_none() => args.no_entry = true,
            "subsystem" => {
                let value = required_value("/SUBSYSTEM", inline_value, &mut input)?;
                args.subsystem = Some(parse_subsystem(value)?);
            }
            "dll" if inline_value.is_none() => args.is_dll = true,
            "defaultlib" => {
                let value = required_value("/DEFAULTLIB", inline_value, &mut input)?;
                args.default_libraries.push(value.to_owned());
            }
            "nodefaultlib" => match inline_value {
                Some(value) if !value.is_empty() => {
                    args.excluded_default_libraries.push(value.to_owned());
                }
                _ => args.no_default_libraries = true,
            },
            "libpath" => {
                let value = required_value("/LIBPATH", inline_value, &mut input)?;
                args.common.save_dir.handle_file(value);
                args.lib_search_path.push(Box::from(Path::new(value)));
            }
            "export" => {
                let value = required_value("/EXPORT", inline_value, &mut input)?;
                args.exports.push(parse_export(value)?);
            }
            "def" => {
                ensure!(
                    source == "command line",
                    "/DEF is only valid on the command line"
                );
                let value = required_value("/DEF", inline_value, &mut input)?;
                ensure!(
                    args.definition_files.is_empty(),
                    "multiple /DEF options are not supported"
                );
                args.common.save_dir.handle_file(value);
                args.definition_files.push(Box::from(Path::new(value)));
            }
            "include" => {
                let value = required_value("/INCLUDE", inline_value, &mut input)?;
                args.force_undefined.push(value.to_owned());
                args.runtime_resolution
                    .apply(RuntimeDirective::Include(value.to_owned()), source)?;
            }
            "alternatename" => {
                let value = required_value("/ALTERNATENAME", inline_value, &mut input)?;
                let (symbol, target) = parse_assignment("/ALTERNATENAME", value)?;
                if symbol == target {
                    bail!("/ALTERNATENAME `{symbol}` aliases a symbol to itself");
                }
                args.runtime_resolution.apply(
                    RuntimeDirective::AlternateName {
                        symbol: symbol.to_owned(),
                        target: target.to_owned(),
                    },
                    source,
                )?;
            }
            "failifmismatch" => {
                let value = required_value("/FAILIFMISMATCH", inline_value, &mut input)?;
                let (key, value) = parse_assignment("/FAILIFMISMATCH", value)?;
                args.runtime_resolution.apply(
                    RuntimeDirective::FailIfMismatch {
                        key: key.to_owned(),
                        value: value.to_owned(),
                    },
                    source,
                )?;
            }
            "guard" => parse_guard(
                &mut args.guard,
                required_value("/GUARD", inline_value, &mut input)?,
            )?,
            "guardsym" => args.guard_symbols.push(parse_guard_symbol(required_value(
                "/GUARDSYM",
                inline_value,
                &mut input,
            )?)?),
            "manifestdependency" => {
                args.manifest_requested = true;
                let value = required_value("/MANIFESTDEPENDENCY", inline_value, &mut input)?;
                args.manifest_dependencies.push(ManifestDependency {
                    value: value.to_owned(),
                });
            }
            "editandcontinue" if inline_value.is_none() => args.edit_and_continue = true,
            // MSVC emits this compatibility marker from its C++ runtime. Both
            // link.exe and lld-link accept it on the command line and in
            // `.drectve`, but it does not alter the linked image.
            "throwingnew" if inline_value.is_none() => {}
            "throwingnew" => bail!("/THROWINGNEW does not accept a value"),
            "disallowlib" => {
                let value = required_value("/DISALLOWLIB", inline_value, &mut input)?;
                args.disallowed_libraries.push(value.to_owned());
            }
            "machine" => {
                let value = required_value("/MACHINE", inline_value, &mut input)?;
                if !value.eq_ignore_ascii_case("x64") && !value.eq_ignore_ascii_case("amd64") {
                    bail!("unsupported /MACHINE value `{value}`; only X64 is supported");
                }
                args.machine = CoffMachine::X86_64;
            }
            "debug" => {
                // PDB generation is outside v1, but accepting this flag is important for compiler
                // driver compatibility. Debug sections remain in the linked image.
                match inline_value {
                    None => args.debug = true,
                    Some(value) if value.eq_ignore_ascii_case("full") => args.debug = true,
                    Some(value) if value.eq_ignore_ascii_case("none") => args.debug = false,
                    Some(value) => bail!(
                        "unsupported /DEBUG value `{value}`; PDB modes other than FULL are not supported"
                    ),
                }
            }
            "align" => {
                let value = required_value("/ALIGN", inline_value, &mut input)?;
                args.section_alignment = Some(parse_alignment("/ALIGN", value, 1, u32::MAX)?);
            }
            "filealign" => {
                let value = required_value("/FILEALIGN", inline_value, &mut input)?;
                args.file_alignment = Some(parse_alignment("/FILEALIGN", value, 512, 65_536)?);
            }
            "base" => {
                let value = required_value("/BASE", inline_value, &mut input)?;
                let parsed = parse_pair(value, "/BASE")?;
                if parsed.reserve & 0xffff != 0 {
                    bail!("/BASE address must be a multiple of 65536");
                }
                args.image_base = Some(ImageBase {
                    address: parsed.reserve,
                    max_size: parsed.commit,
                });
            }
            "stack" => {
                args.stack = Some(parse_pair(
                    required_value("/STACK", inline_value, &mut input)?,
                    "/STACK",
                )?);
            }
            "heap" => {
                args.heap = Some(parse_pair(
                    required_value("/HEAP", inline_value, &mut input)?,
                    "/HEAP",
                )?);
            }
            "version" => {
                args.image_version = Some(parse_optional_minor_version(required_value(
                    "/VERSION",
                    inline_value,
                    &mut input,
                )?)?);
            }
            "dynamicbase" => {
                args.dynamic_base = parse_yes_no("/DYNAMICBASE", inline_value)?;
            }
            "fixed" => args.fixed = parse_yes_no("/FIXED", inline_value)?,
            "nxcompat" => args.nx_compat = parse_yes_no("/NXCOMPAT", inline_value)?,
            "opt" => parse_opt(
                &mut args.optimization,
                required_value("/OPT", inline_value, &mut input)?,
            )?,
            "wholearchive" => match inline_value {
                None => args.whole_archive = true,
                Some("") => bail!("missing argument to /WHOLEARCHIVE"),
                Some(library) => {
                    args.whole_archive_libraries.push(library.to_owned());
                    add_input_with_modifiers(args, library, true);
                }
            },
            "force" => parse_force(&mut args.force, inline_value)?,
            "implib" => {
                let value = required_value("/IMPLIB", inline_value, &mut input)?;
                args.import_library = Some(Box::from(Path::new(value)));
            }
            "pdb" => {
                let value = required_value("/PDB", inline_value, &mut input)?;
                // Stored for compatibility and diagnostics; v1 intentionally does not emit PDBs.
                args.pdb = Some(Box::from(Path::new(value)));
            }
            "pdbaltpath" => {
                // rustc passes this in both debug and release builds. PDB emission is outside
                // the PE v1 scope, so accept a non-empty value without claiming to apply it.
                let _ = required_value("/PDBALTPATH", inline_value, &mut input)?;
            }
            "natvis" => {
                // rustc forwards debugger visualizers to the linker for inclusion in the PDB.
                // PDB emission is outside PE v1, so accept the path without treating it as a
                // link input.
                let _ = required_value("/NATVIS", inline_value, &mut input)?;
            }
            "manifest" => {
                args.manifest_requested = true;
                args.manifest_mode_requested = true;
                match inline_value {
                    Some(value) if value.eq_ignore_ascii_case("no") => {
                        args.manifest = false;
                        args.manifest_embed = None;
                    }
                    Some(value)
                        if value
                            .get(..5)
                            .is_some_and(|mode| mode.eq_ignore_ascii_case("embed")) =>
                    {
                        args.manifest = true;
                        args.manifest_embed = Some(parse_manifest_embed(value)?);
                    }
                    None => {
                        args.manifest = true;
                        args.manifest_embed = None;
                    }
                    Some(value) => bail!(
                        "unsupported /MANIFEST value `{value}`; expected /MANIFEST, /MANIFEST:NO, or /MANIFEST:EMBED[,ID=n]"
                    ),
                }
            }
            // These link.exe/lld-link switches affect diagnostics, manifests, or optional
            // loader policy that v1 does not emit. Parse their values so they never become
            // object-file inputs, but deliberately leave the image unchanged.
            "manifestuac" => {
                args.manifest_requested = true;
                args.manifest_uac_requested = true;
                args.manifest_uac = match inline_value {
                    Some(value) if value.eq_ignore_ascii_case("no") => None,
                    None => Some(ManifestUac {
                        level: ManifestExecutionLevel::AsInvoker,
                        ui_access: false,
                    }),
                    Some(value) => Some(parse_manifest_uac(value)?),
                };
            }
            "manifestfile" => {
                args.manifest_requested = true;
                args.manifest_file = Some(Box::from(Path::new(required_value(
                    "/MANIFESTFILE",
                    inline_value,
                    &mut input,
                )?)));
            }
            "manifestinput" => {
                args.manifest_requested = true;
                args.manifest_inputs
                    .push(Box::from(Path::new(required_value(
                        "/MANIFESTINPUT",
                        inline_value,
                        &mut input,
                    )?)));
            }
            "ignore" | "tlbid" | "order" | "stub" | "dependentloadflag" => {
                let _ = required_value("linker option", inline_value, &mut input)?;
            }
            // lld-link accepts both the bare spelling and `/FUNCTIONPADMIN:size`.
            // Function padding is not emitted yet, but a following object must not be
            // consumed as an optional value for the bare form.
            "functionpadmin" => {
                if let Some(value) = inline_value {
                    ensure!(
                        !value.is_empty(),
                        "/FUNCTIONPADMIN expects a non-empty size"
                    );
                    let _ = parse_integer("/FUNCTIONPADMIN", value)?;
                }
            }
            "errorreport" => {
                // link.exe accepts this both with and without a mode.
                let _ = inline_value;
            }
            "wx" => {
                let _ = parse_yes_no("/WX", inline_value)?;
            }
            "release" => {
                if inline_value.is_some() {
                    bail!("{arg} does not accept a value");
                }
            }
            "appcontainer" => {
                let _ = parse_yes_no("/APPCONTAINER", inline_value)?;
            }
            "swaprun" => match inline_value {
                None => {}
                Some(value)
                    if value.eq_ignore_ascii_case("cd") || value.eq_ignore_ascii_case("net") => {}
                Some(value) => bail!("unsupported /SWAPRUN value `{value}`; expected CD or NET"),
            },
            "map" => {
                // /MAP has an optional output path. Actual map output is deferred with PDBs.
                let _ = inline_value;
            }
            "largeaddressaware" | "highentropyva" => {
                let _ = parse_yes_no("linker option", inline_value)?;
            }
            "incremental" => match inline_value {
                Some(value) if value.eq_ignore_ascii_case("no") => {}
                _ => args.common.unrecognized_options.push(arg.to_owned()),
            },
            // These require linker stages that are deliberately deferred. Keep their existing
            // hard diagnostic rather than silently producing a partial implementation.
            "delayload" => {
                let value = required_value("/DELAYLOAD", inline_value, &mut input)?;
                args.delay_load_dlls.push(value.to_owned());
            }
            "ltcg" => args.common.unrecognized_options.push(arg.to_owned()),
            // Keep security features explicitly rejected until their corresponding PE metadata
            // is emitted; accepting them would create an image with misleading protection bits.
            "cetcompat" => match inline_value {
                Some(value) if value.eq_ignore_ascii_case("no") => {}
                _ => bail!("/CETCOMPAT is not supported; /CETCOMPAT:NO is accepted to disable it"),
            },
            "merge" => args.merges.push(parse_merge(required_value(
                "/MERGE",
                inline_value,
                &mut input,
            )?)?),
            "section" => args.section_attributes.push(parse_section(required_value(
                "/SECTION",
                inline_value,
                &mut input,
            )?)?),
            // On Unix hosts an absolute path also begins with '/'. Do not mistake it for an
            // option merely because the link.exe spelling uses the same prefix.
            _ if prefix == '/' && option.contains('/') => add_input(args, arg),
            _ => tracing::warn!("ignoring unrecognized linker option `{arg}`"),
        }
    }
    Ok(())
}

fn parse_export(value: &str) -> Result<ExportSpec> {
    let mut fields = value.split(',');
    let mapping = fields.next().unwrap_or_default();
    if mapping.is_empty() {
        bail!("/EXPORT expects a non-empty export name");
    }
    let (name, target) = mapping
        .split_once('=')
        .map_or((mapping, mapping), |(name, target)| (name, target));
    if name.is_empty() || target.is_empty() {
        bail!("/EXPORT expects name[=internal-name]");
    }

    let mut ordinal = None;
    let mut noname = false;
    let mut data = false;
    let mut private = false;
    for field in fields {
        if let Some(value) = field.strip_prefix('@') {
            if ordinal.is_some() || value.is_empty() {
                bail!("invalid ordinal in /EXPORT:{value}");
            }
            let parsed = value
                .parse::<u16>()
                .with_context(|| format!("invalid export ordinal `@{value}`"))?;
            if parsed == 0 {
                bail!("export ordinal zero is reserved");
            }
            ordinal = Some(parsed);
            continue;
        }
        match field.to_ascii_lowercase().as_str() {
            "noname" if !noname => noname = true,
            "data" if !data => data = true,
            "private" if !private => private = true,
            "noname" | "data" | "private" => {
                bail!("duplicate /EXPORT modifier `{field}`")
            }
            _ => bail!("unsupported /EXPORT modifier `{field}`"),
        }
    }
    if noname && ordinal.is_none() {
        bail!("/EXPORT NONAME requires an explicit ordinal");
    }
    Ok(ExportSpec {
        name: name.to_owned(),
        target: target.to_owned(),
        ordinal,
        noname,
        data,
        private,
    })
}

fn parse_assignment<'a>(option: &str, value: &'a str) -> Result<(&'a str, &'a str)> {
    let (left, right) = value
        .split_once('=')
        .with_context(|| format!("{option} expects name=value"))?;
    if left.is_empty() || right.is_empty() {
        bail!("{option} expects non-empty values in name=value");
    }
    Ok((left, right))
}

fn parse_guard(options: &mut GuardOptions, value: &str) -> Result {
    for setting in value.split(',') {
        match setting.to_ascii_lowercase().as_str() {
            "cf" => set_guard_control_flow(options, OptSetting::Enabled)?,
            "no" => set_guard_control_flow(options, OptSetting::Disabled)?,
            "nolongjmp" => options.no_long_jump = true,
            _ => bail!(
                "unsupported /GUARD value `{setting}`; supported values are CF, NO, and NOLONGJMP"
            ),
        }
    }
    Ok(())
}

fn set_guard_control_flow(options: &mut GuardOptions, setting: OptSetting) -> Result {
    if options.control_flow != OptSetting::Default && options.control_flow != setting {
        bail!("conflicting /GUARD control-flow settings: CF and NO");
    }
    options.control_flow = setting;
    Ok(())
}

fn parse_guard_symbol(value: &str) -> Result<GuardSymbol> {
    let mut fields = value.split(',');
    let symbol = fields.next().unwrap_or_default();
    if symbol.is_empty() {
        bail!("/GUARDSYM expects a non-empty symbol name");
    }

    let mut flags = GuardSymbolFlags::default();
    if let Some(raw_flags) = fields.next() {
        if raw_flags.is_empty() {
            bail!("/GUARDSYM flags must not be empty");
        }
        for flag in raw_flags.chars() {
            match flag.to_ascii_lowercase() {
                's' if !flags.suppressed => flags.suppressed = true,
                's' => bail!("duplicate /GUARDSYM flag `{flag}`"),
                _ => bail!("unsupported /GUARDSYM flag `{flag}`; supported flag is S"),
            }
        }
    }
    if fields.next().is_some() {
        bail!("/GUARDSYM expects symbol[,flags]");
    }

    Ok(GuardSymbol {
        symbol: symbol.to_owned(),
        flags,
    })
}

fn required_value<'a, I>(
    option: &str,
    inline: Option<&'a str>,
    input: &mut std::iter::Peekable<I>,
) -> Result<&'a str>
where
    I: Iterator<Item = &'a str>,
{
    match inline {
        Some(value) if !value.is_empty() => Ok(value),
        _ => input
            .next()
            .with_context(|| format!("missing argument to {option}")),
    }
}

fn add_input(args: &mut CoffArgs, value: &str) {
    add_input_with_modifiers(args, value, args.whole_archive);
}

fn add_input_with_modifiers(args: &mut CoffArgs, value: &str, whole_archive: bool) {
    args.common.save_dir.handle_file(value);
    args.common.inputs.push(Input {
        spec: InputSpec::File(Box::from(Path::new(value))),
        search_first: None,
        modifiers: Modifiers {
            whole_archive,
            ..Modifiers::default()
        },
    });
}

fn parse_integer(option: &str, value: &str) -> Result<u64> {
    let compact = value.replace(['_', ','], "");
    let result = compact
        .strip_prefix("0x")
        .or_else(|| compact.strip_prefix("0X"))
        .map_or_else(
            || compact.parse::<u64>(),
            |hex| u64::from_str_radix(hex, 16),
        );
    result.with_context(|| format!("invalid numeric value `{value}` for {option}"))
}

fn parse_alignment(option: &str, value: &str, min: u32, max: u32) -> Result<u32> {
    let value = parse_integer(option, value)?;
    let value = u32::try_from(value).with_context(|| format!("{option} value is too large"))?;
    if !value.is_power_of_two() || !(min..=max).contains(&value) {
        bail!("{option} value must be a power of two between {min} and {max}");
    }
    Ok(value)
}

fn validate_alignments(args: &CoffArgs) -> Result {
    if let (Some(section), Some(file)) = (args.section_alignment, args.file_alignment)
        && section < file
    {
        bail!("/ALIGN ({section}) must not be smaller than /FILEALIGN ({file})");
    }
    Ok(())
}

fn parse_pair(value: &str, option: &str) -> Result<ReserveCommit> {
    let (reserve, commit) = value
        .split_once(',')
        .map_or((value, None), |(reserve, commit)| (reserve, Some(commit)));
    if reserve.is_empty() || commit == Some("") {
        bail!("{option} expects reserve[,commit]");
    }
    let reserve = parse_integer(option, reserve)?;
    let commit = commit.map(|v| parse_integer(option, v)).transpose()?;
    if reserve == 0 {
        bail!("{option} reserve must be non-zero");
    }
    if commit.is_some_and(|commit| commit > reserve) {
        bail!("{option} commit must not exceed reserve");
    }
    Ok(ReserveCommit { reserve, commit })
}

fn parse_optional_minor_version(value: &str) -> Result<(u16, u16)> {
    let (major, minor) = value
        .split_once('.')
        .map_or((value, "0"), |(major, minor)| (major, minor));
    if major.is_empty() || minor.is_empty() {
        bail!("/VERSION must have the form major[.minor]");
    }
    Ok((major.parse()?, minor.parse()?))
}

fn parse_yes_no(option: &str, value: Option<&str>) -> Result<bool> {
    match value {
        None => Ok(true),
        Some(value) if value.eq_ignore_ascii_case("no") => Ok(false),
        Some(value) => {
            bail!("unsupported {option} value `{value}`; expected {option} or {option}:NO")
        }
    }
}

fn parse_manifest_embed(value: &str) -> Result<ManifestEmbed> {
    let mut fields = value.split(',');
    let mode = fields.next().unwrap_or_default();
    ensure!(
        mode.eq_ignore_ascii_case("embed"),
        "invalid /MANIFEST mode `{value}`"
    );
    let mut id = None;
    for field in fields {
        let (key, value) = field
            .split_once('=')
            .context("/MANIFEST:EMBED expects optional ID=n")?;
        ensure!(
            key.eq_ignore_ascii_case("id"),
            "unsupported /MANIFEST:EMBED option `{key}`"
        );
        ensure!(id.is_none(), "duplicate /MANIFEST:EMBED ID");
        let parsed = parse_integer("/MANIFEST:EMBED,ID", value)?;
        let parsed = u16::try_from(parsed).context("/MANIFEST:EMBED ID exceeds u16")?;
        ensure!(parsed != 0, "/MANIFEST:EMBED ID must not be zero");
        id = Some(parsed);
    }
    Ok(id.map_or(ManifestEmbed::DefaultId, ManifestEmbed::Id))
}

fn parse_manifest_uac(value: &str) -> Result<ManifestUac> {
    let value = value.trim_matches(['\'', '"']);
    let mut level = None;
    let mut ui_access = false;
    for field in value.split_whitespace() {
        let (key, value) = field
            .split_once('=')
            .context("/MANIFESTUAC expects level=name [uiAccess=true|false]")?;
        let value = value.trim_matches(['\'', '"']);
        if key.eq_ignore_ascii_case("level") {
            ensure!(level.is_none(), "duplicate /MANIFESTUAC level");
            level = Some(match value.to_ascii_lowercase().as_str() {
                "asinvoker" => ManifestExecutionLevel::AsInvoker,
                "highestavailable" => ManifestExecutionLevel::HighestAvailable,
                "requireadministrator" => ManifestExecutionLevel::RequireAdministrator,
                _ => bail!("unsupported /MANIFESTUAC level `{value}`"),
            });
        } else if key.eq_ignore_ascii_case("uiaccess") {
            ui_access = match value {
                value if value.eq_ignore_ascii_case("true") => true,
                value if value.eq_ignore_ascii_case("false") => false,
                _ => bail!("/MANIFESTUAC uiAccess must be true or false"),
            };
        } else {
            bail!("unsupported /MANIFESTUAC field `{key}`");
        }
    }
    Ok(ManifestUac {
        level: level.unwrap_or(ManifestExecutionLevel::AsInvoker),
        ui_access,
    })
}

fn parse_opt(options: &mut OptimizationOptions, value: &str) -> Result {
    for value in value.split(',') {
        let (setting, parameter) = value
            .split_once('=')
            .map_or((value, None), |(setting, parameter)| {
                (setting, Some(parameter))
            });
        match setting.to_ascii_lowercase().as_str() {
            "ref" => options.ref_ = OptSetting::Enabled,
            "noref" => options.ref_ = OptSetting::Disabled,
            // lld-link accepts /OPT:ICF=N. The iteration count only matters to an ICF
            // implementation, which is intentionally deferred, so preserve the enabled state.
            "icf" if parameter.is_none_or(|value| !value.is_empty()) => {
                options.icf = OptSetting::Enabled;
            }
            "noicf" => options.icf = OptSetting::Disabled,
            // lld-link recognizes this optimization but it has no PE-v1 implementation.
            "lbr" if parameter.is_none() => {}
            _ => bail!(
                "unsupported /OPT value `{value}`; supported values are REF, NOREF, ICF, NOICF, and LBR"
            ),
        }
    }
    Ok(())
}

fn parse_force(options: &mut ForceOptions, value: Option<&str>) -> Result {
    match value {
        None => {
            options.multiple = true;
            options.unresolved = true;
        }
        Some(value) if value.eq_ignore_ascii_case("multiple") => options.multiple = true,
        Some(value) if value.eq_ignore_ascii_case("unresolved") => options.unresolved = true,
        Some(value) => bail!(
            "unsupported /FORCE value `{value}`; supported values are MULTIPLE and UNRESOLVED"
        ),
    }
    Ok(())
}

fn parse_merge(value: &str) -> Result<SectionMerge> {
    let (from, to) = value.split_once('=').context("/MERGE expects from=to")?;
    if from.is_empty() || to.is_empty() {
        bail!("/MERGE expects non-empty section names in from=to");
    }
    Ok(SectionMerge {
        from: from.to_owned(),
        to: to.to_owned(),
    })
}

fn parse_section(value: &str) -> Result<SectionAttributes> {
    let (name, attributes) = value
        .split_once(',')
        .context("/SECTION expects name,attributes")?;
    if name.is_empty() || attributes.is_empty() {
        bail!("/SECTION expects a non-empty name and attributes");
    }
    let attributes = attributes.to_ascii_uppercase();
    let mut after_bang = false;
    for ch in attributes.chars() {
        if ch == '!' && !after_bang {
            after_bang = true;
        } else if !matches!(ch, 'D' | 'E' | 'K' | 'L' | 'P' | 'R' | 'S' | 'W') {
            bail!("unsupported /SECTION attribute `{ch}` in `{value}`");
        }
    }
    Ok(SectionAttributes {
        name: name.to_owned(),
        attributes,
    })
}

/// Implements the backslash-before-quote rules used by CommandLineToArgvW/link.exe response
/// parsing. Unlike a shell, backslashes are otherwise preserved (important for Windows paths).
fn windows_command_line_args(input: &str) -> Vec<String> {
    let chars: Vec<char> = input.chars().collect();
    let mut result = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        while index < chars.len() && chars[index].is_whitespace() {
            index += 1;
        }
        if index == chars.len() {
            break;
        }
        let mut value = String::new();
        let mut quoted = false;
        while index < chars.len() && (quoted || !chars[index].is_whitespace()) {
            if chars[index] == '\\' {
                let start = index;
                while index < chars.len() && chars[index] == '\\' {
                    index += 1;
                }
                let count = index - start;
                if index < chars.len() && chars[index] == '"' {
                    value.extend(std::iter::repeat_n('\\', count / 2));
                    if count % 2 == 0 {
                        if quoted && index + 1 < chars.len() && chars[index + 1] == '"' {
                            // Two consecutive quotes within a quoted portion represent one
                            // literal quote under the Windows command-line rules.
                            value.push('"');
                            index += 1;
                        } else {
                            quoted = !quoted;
                        }
                    } else {
                        value.push('"');
                    }
                    index += 1;
                } else {
                    value.extend(std::iter::repeat_n('\\', count));
                }
            } else if chars[index] == '"' {
                if quoted && index + 1 < chars.len() && chars[index + 1] == '"' {
                    value.push('"');
                    index += 2;
                } else {
                    quoted = !quoted;
                    index += 1;
                }
            } else {
                value.push(chars[index]);
                index += 1;
            }
        }
        // CommandLineToArgvW and lld-link both treat EOF as the end of an unmatched quoted
        // portion, so retain the token instead of rejecting an otherwise usable response file.
        result.push(value);
    }
    result
}

/// Decodes a link.exe response file.
///
/// MSVC tools (and rustc when targeting MSVC) commonly emit UTF-16LE response files with a byte
/// order mark. Plain UTF-8 remains the default when no BOM is present. UTF-16BE is accepted as
/// well, since the BOM makes its byte order unambiguous.
fn decode_response_file(contents: &[u8]) -> Result<String> {
    const UTF8_BOM: &[u8] = b"\xef\xbb\xbf";
    const UTF16_LE_BOM: &[u8] = b"\xff\xfe";
    const UTF16_BE_BOM: &[u8] = b"\xfe\xff";

    if let Some(contents) = contents.strip_prefix(UTF16_LE_BOM) {
        decode_utf16_response_file(contents, u16::from_le_bytes)
    } else if let Some(contents) = contents.strip_prefix(UTF16_BE_BOM) {
        decode_utf16_response_file(contents, u16::from_be_bytes)
    } else {
        let contents = contents.strip_prefix(UTF8_BOM).unwrap_or(contents);
        String::from_utf8(contents.to_owned()).context("response file is not valid UTF-8")
    }
}

fn decode_utf16_response_file(contents: &[u8], decode: fn([u8; 2]) -> u16) -> Result<String> {
    if !contents.len().is_multiple_of(2) {
        bail!("UTF-16 response file has an odd number of bytes after its BOM");
    }
    let words = contents
        .chunks_exact(2)
        .map(|bytes| decode([bytes[0], bytes[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&words).context("response file contains malformed UTF-16")
}

fn expand_response_files<S: AsRef<str>, I: Iterator<Item = S>>(input: I) -> Result<Vec<String>> {
    let current_dir = std::env::current_dir().context("failed to determine current directory")?;
    expand_response_files_from(input, &current_dir, &mut Vec::new())
}

fn expand_response_files_from<S: AsRef<str>, I: Iterator<Item = S>>(
    input: I,
    base_dir: &Path,
    active_files: &mut Vec<PathBuf>,
) -> Result<Vec<String>> {
    // This is primarily a guard against an adversarial but acyclic chain exhausting the call
    // stack. Cycles are diagnosed separately below with their actual path.
    const MAX_RESPONSE_FILE_DEPTH: usize = 128;

    let mut output = Vec::new();
    for arg in input {
        let arg = arg.as_ref();
        if let Some(path) = arg.strip_prefix('@') {
            let supplied_path = Path::new(path);
            let response_path = if supplied_path.is_absolute() {
                supplied_path.to_owned()
            } else {
                base_dir.join(supplied_path)
            };
            let canonical_path = std::fs::canonicalize(&response_path).with_context(|| {
                format!(
                    "failed to resolve response file `{}`",
                    response_path.display()
                )
            })?;
            if active_files.contains(&canonical_path) {
                bail!(
                    "recursive response file expansion of `{}`",
                    response_path.display()
                );
            }
            if active_files.len() >= MAX_RESPONSE_FILE_DEPTH {
                bail!(
                    "response file nesting exceeds the maximum depth of {MAX_RESPONSE_FILE_DEPTH} at `{}`",
                    response_path.display()
                );
            }

            let contents = std::fs::read(&response_path).with_context(|| {
                format!("failed to read response file `{}`", response_path.display())
            })?;
            let contents = decode_response_file(&contents).with_context(|| {
                format!(
                    "failed to decode response file `{}`",
                    response_path.display()
                )
            })?;
            let nested = windows_command_line_args(&contents);
            let nested_base = response_path.parent().unwrap_or(base_dir);
            active_files.push(canonical_path);
            let expanded =
                expand_response_files_from(nested.into_iter(), nested_base, active_files);
            active_files.pop();
            output.extend(expanded?);
        } else {
            output.push(arg.to_owned());
        }
    }
    Ok(output)
}

fn parse_subsystem(value: &str) -> Result<SubsystemSpec> {
    let (kind, version) = value
        .split_once(',')
        .map_or((value, None), |(kind, version)| (kind, Some(version)));
    let kind = match kind.to_ascii_lowercase().as_str() {
        "console" => Subsystem::Console,
        "windows" => Subsystem::Windows,
        "native" => Subsystem::Native,
        "efi_application" => Subsystem::EfiApplication,
        "efi_boot_service_driver" => Subsystem::EfiBootServiceDriver,
        "efi_runtime_driver" => Subsystem::EfiRuntimeDriver,
        "efi_rom" => Subsystem::EfiRom,
        "posix" => Subsystem::Posix,
        _ => bail!("unsupported /SUBSYSTEM value `{kind}`"),
    };
    let version = version.map(parse_version).transpose()?;
    Ok(SubsystemSpec { kind, version })
}

fn parse_version(value: &str) -> Result<(u16, u16)> {
    let (major, minor) = value
        .split_once('.')
        .context("/SUBSYSTEM version must have the form major.minor")?;
    Ok((major.parse()?, minor.parse()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_link_options_case_insensitively() {
        let mut args = CoffArgs::default();
        parse(
            &mut args,
            [
                "/OuT:hello.exe",
                "/ENTRY:custom_entry",
                "/SUBSYSTEM:CONSOLE,6.2",
                "/DLL",
                "/NOENTRY",
                "/DEFAULTLIB:ucrt.lib",
                "/NODEFAULTLIB:oldnames.lib",
                "/LIBPATH:sdk/lib",
                "/DEF:exports/lib.def",
                "/EXPORT:answer,@7",
                "/INCLUDE:forced_symbol",
                "/MACHINE:AMD64",
                "/DEBUG:FULL",
                "main.obj",
            ]
            .into_iter(),
        )
        .unwrap();

        assert_eq!(&*args.common.output, Path::new("hello.exe"));
        assert_eq!(args.entry.as_deref(), Some("custom_entry"));
        assert_eq!(
            args.subsystem,
            Some(SubsystemSpec {
                kind: Subsystem::Console,
                version: Some((6, 2)),
            })
        );
        assert!(args.is_dll);
        assert_eq!(args.default_libraries, ["ucrt.lib"]);
        assert_eq!(args.excluded_default_libraries, ["oldnames.lib"]);
        assert_eq!(args.lib_search_path[0].as_ref(), Path::new("sdk/lib"));
        assert_eq!(
            args.definition_files[0].as_ref(),
            Path::new("exports/lib.def")
        );
        assert!(args.no_entry);
        assert_eq!(
            args.exports,
            [ExportSpec {
                name: "answer".into(),
                target: "answer".into(),
                ordinal: Some(7),
                noname: false,
                data: false,
                private: false,
            }]
        );
        assert_eq!(args.force_undefined, ["forced_symbol"]);
        assert!(args.debug);
        assert!(matches!(
            args.common.inputs[0].spec,
            InputSpec::File(ref path) if &**path == Path::new("main.obj")
        ));
    }

    #[test]
    fn parses_typed_export_alias_and_modifiers() {
        let mut args = CoffArgs::default();
        parse(
            &mut args,
            ["/EXPORT:public_name=internal_name,@42,NONAME,DATA,PRIVATE"].into_iter(),
        )
        .unwrap();
        assert_eq!(
            args.exports,
            [ExportSpec {
                name: "public_name".into(),
                target: "internal_name".into(),
                ordinal: Some(42),
                noname: true,
                data: true,
                private: true,
            }]
        );
    }

    #[test]
    fn rejects_invalid_export_modifiers() {
        let mut args = CoffArgs::default();
        assert!(parse(&mut args, ["/EXPORT:answer,NONAME"].into_iter()).is_err());
        let mut args = CoffArgs::default();
        assert!(parse(&mut args, ["/EXPORT:answer,@0"].into_iter()).is_err());
    }

    #[test]
    fn rejects_missing_definition_file_path() {
        assert!(parse(&mut CoffArgs::default(), ["/DEF:"].into_iter()).is_err());
        assert!(
            parse(
                &mut CoffArgs::default(),
                ["/DEF:first.def", "/DEF:second.def"].into_iter()
            )
            .is_err()
        );
        assert!(parse_directives(&mut CoffArgs::default(), "/DEF:exports.def").is_err());
    }

    #[test]
    fn supports_separate_values_and_global_nodefaultlib() {
        let mut args = CoffArgs::default();
        parse(
            &mut args,
            ["/out", "separate.exe", "/nodefaultlib", "/machine", "x64"].into_iter(),
        )
        .unwrap();
        assert_eq!(&*args.common.output, Path::new("separate.exe"));
        assert!(args.no_default_libraries);
    }

    #[test]
    fn rejects_unsupported_machine_and_warns_for_unknown_options() {
        let mut args = CoffArgs::default();
        assert!(parse(&mut args, ["/machine:arm64"].into_iter()).is_err());
        parse(&mut args, ["/not-a-real-option"].into_iter()).unwrap();
        assert!(args.common.unrecognized_options.is_empty());
    }

    #[test]
    fn rejects_ltcg_and_enabled_incremental_linking_options() {
        for option in ["/LTCG", "/INCREMENTAL", "/INCREMENTAL:YES"] {
            let error = parse(&mut CoffArgs::default(), [option].into_iter())
                .unwrap_err()
                .to_string();
            assert!(error.contains("unrecognized option"), "{option}: {error}");
            assert!(error.contains(option), "{option}: {error}");

            let error = parse_directives(&mut CoffArgs::default(), option)
                .unwrap_err()
                .to_string();
            assert!(error.contains("unrecognized option"), "{option}: {error}");
            assert!(error.contains(option), "{option}: {error}");
        }

        parse(&mut CoffArgs::default(), ["/INCREMENTAL:NO"].into_iter()).unwrap();
        parse_directives(&mut CoffArgs::default(), "/INCREMENTAL:NO").unwrap();
    }

    #[test]
    fn accepts_common_msvc_compatibility_options_as_noops() {
        let mut args = CoffArgs::default();
        parse(
            &mut args,
            [
                "/IGNORE:4078",
                "/ERRORREPORT:NONE",
                "/TLBID:1",
                "/MANIFEST:EMBED,ID=1",
                "/MANIFESTUAC:\"level='asInvoker' uiAccess='false'\"",
                "/MANIFESTFILE:app.manifest",
                "/MANIFESTINPUT:input.manifest",
                "/WX",
                "/MAP:app.map",
                "/ORDER:@order.txt",
                "/STUB:stub.exe",
                "/RELEASE",
                "/APPCONTAINER:NO",
                "/LARGEADDRESSAWARE:NO",
                "/HIGHENTROPYVA",
                "/DEPENDENTLOADFLAG:0x800",
                "/FUNCTIONPADMIN",
                "/CETCOMPAT:NO",
                "/SWAPRUN:NET",
                "/OPT:LBR,ICF=3",
            ]
            .into_iter(),
        )
        .unwrap();
        assert!(args.manifest);
        assert_eq!(args.manifest_embed, Some(ManifestEmbed::Id(1)));
        assert_eq!(
            args.manifest_file.as_deref(),
            Some(Path::new("app.manifest"))
        );
        assert_eq!(
            args.manifest_inputs,
            [Box::from(Path::new("input.manifest"))]
        );
        assert_eq!(
            args.manifest_uac,
            Some(ManifestUac {
                level: ManifestExecutionLevel::AsInvoker,
                ui_access: false,
            })
        );
        assert_eq!(args.optimization.icf, OptSetting::Enabled);
        assert!(args.common.inputs.is_empty());
    }

    #[test]
    fn parses_stock_cmake_msbuild_release_link_line() {
        let mut args = CoffArgs::default();
        parse(
            &mut args,
            [
                "/nologo",
                "CMakeFiles\\app.dir\\main.cpp.obj",
                "/out:Release\\app.exe",
                "/implib:Release\\app.lib",
                "/pdb:Release\\app.pdb",
                "/version:0.0",
                "/machine:x64",
                "/INCREMENTAL:NO",
                "/subsystem:console",
                "/MANIFEST:EMBED,ID=1",
                "/MANIFESTUAC:level='asInvoker' uiAccess='false'",
                "/ERRORREPORT:QUEUE",
                "/TLBID:1",
                "/DYNAMICBASE",
                "/NXCOMPAT",
                "/HIGHENTROPYVA",
                "/LARGEADDRESSAWARE",
                "/OPT:REF,ICF",
                "/FUNCTIONPADMIN",
                "/APPCONTAINER:NO",
                "/CETCOMPAT:NO",
                "kernel32.lib",
                "user32.lib",
            ]
            .into_iter(),
        )
        .unwrap();

        assert_eq!(&*args.common.output, Path::new("Release\\app.exe"));
        assert_eq!(args.optimization.ref_, OptSetting::Enabled);
        assert_eq!(args.optimization.icf, OptSetting::Enabled);
        assert_eq!(args.manifest_embed, Some(ManifestEmbed::Id(1)));
        assert!(args.common.unrecognized_options.is_empty());
        assert_eq!(args.common.inputs.len(), 3);
        for (input, expected) in args.common.inputs.iter().zip([
            "CMakeFiles\\app.dir\\main.cpp.obj",
            "kernel32.lib",
            "user32.lib",
        ]) {
            assert!(matches!(
                input.spec,
                InputSpec::File(ref path) if &**path == Path::new(expected)
            ));
        }
    }

    #[test]
    fn parses_manifest_modes_and_last_uac_setting_wins() {
        let mut executable = CoffArgs::default();
        parse(
            &mut executable,
            [
                "/MANIFEST:EMBED",
                "/MANIFESTUAC:level='highestAvailable' uiAccess='true'",
                "/MANIFESTUAC:NO",
            ]
            .into_iter(),
        )
        .unwrap();
        assert_eq!(executable.manifest_embed, Some(ManifestEmbed::DefaultId));
        assert!(executable.manifest_uac_requested);
        assert_eq!(executable.manifest_uac, None);

        let mut explicit = CoffArgs::default();
        parse(
            &mut explicit,
            [
                "/MANIFEST:EMBED,ID=42",
                "/MANIFESTUAC",
                "/MANIFESTINPUT:first.manifest",
                "/MANIFESTINPUT:second.manifest",
            ]
            .into_iter(),
        )
        .unwrap();
        assert_eq!(explicit.manifest_embed, Some(ManifestEmbed::Id(42)));
        assert_eq!(
            explicit.manifest_uac,
            Some(ManifestUac {
                level: ManifestExecutionLevel::AsInvoker,
                ui_access: false,
            })
        );
        assert_eq!(explicit.manifest_inputs.len(), 2);

        let mut disabled = CoffArgs::default();
        parse(
            &mut disabled,
            ["/MANIFEST:EMBED", "/MANIFEST:NO"].into_iter(),
        )
        .unwrap();
        assert!(!disabled.manifest);
        assert_eq!(disabled.manifest_embed, None);
    }

    #[test]
    fn accepts_dash_prefixed_msvc_options() {
        let mut args = CoffArgs::default();
        parse(
            &mut args,
            [
                "-out:hello.exe",
                "-defaultlib:ucrt.lib",
                "-incremental:no",
                "-opt:icf=2",
            ]
            .into_iter(),
        )
        .unwrap();
        assert_eq!(&*args.common.output, Path::new("hello.exe"));
        assert_eq!(args.default_libraries, ["ucrt.lib"]);
        assert_eq!(args.optimization.icf, OptSetting::Enabled);
    }

    #[test]
    fn parses_delay_load_dlls_on_command_line_and_in_directives() {
        let mut args = CoffArgs::default();
        parse(
            &mut args,
            ["/DELAYLOAD:kernel32.dll", "-delayload:user32.dll"].into_iter(),
        )
        .unwrap();
        parse_directives(&mut args, "/DELAYLOAD:ole32.dll").unwrap();
        assert_eq!(
            args.delay_load_dlls,
            ["kernel32.dll", "user32.dll", "ole32.dll"]
        );
        assert!(parse(&mut CoffArgs::default(), ["/DELAYLOAD:"].into_iter()).is_err());
    }

    #[test]
    fn keeps_cetcompat_explicitly_unsupported() {
        parse(&mut CoffArgs::default(), ["/CETCOMPAT:NO"].into_iter()).unwrap();
        let error = parse(&mut CoffArgs::default(), ["/CETCOMPAT"].into_iter())
            .unwrap_err()
            .to_string();
        assert!(error.contains("CETCOMPAT"));
        assert!(parse(&mut CoffArgs::default(), ["/CETCOMPAT:YES"].into_iter()).is_err());
    }

    #[test]
    fn accepts_ignored_pdb_alt_path_without_changing_debug_policy() {
        let mut args = CoffArgs::default();
        parse(&mut args, ["/PDBALTPATH:%_PDB%"].into_iter()).unwrap();
        assert!(!args.debug);
        assert!(args.pdb.is_none());

        parse(
            &mut args,
            ["/DEBUG", "/PDBALTPATH", "symbols\\vibe.pdb"].into_iter(),
        )
        .unwrap();
        assert!(args.debug);

        parse(
            &mut args,
            ["/DEBUG:NONE", "/PDBALTPATH:ignored.pdb"].into_iter(),
        )
        .unwrap();
        assert!(!args.debug);

        assert!(parse(&mut CoffArgs::default(), ["/PDBALTPATH:"].into_iter()).is_err());
    }

    #[test]
    fn accepts_ignored_natvis_paths_without_treating_them_as_inputs() {
        let mut args = CoffArgs::default();
        parse(
            &mut args,
            [
                "/NATVIS:visualizers\\std.natvis",
                "/NATVIS",
                "custom.natvis",
            ]
            .into_iter(),
        )
        .unwrap();
        assert!(args.common.inputs.is_empty());
        assert!(parse(&mut CoffArgs::default(), ["/NATVIS:"].into_iter()).is_err());
    }

    #[test]
    fn accepts_throwing_new_compatibility_marker_without_a_value() {
        let mut command_line = CoffArgs::default();
        parse(&mut command_line, ["/ThrowingNew"].into_iter()).unwrap();

        let mut directives = CoffArgs::default();
        parse_directives(&mut directives, " /THROWINGNEW").unwrap();

        assert!(parse(&mut CoffArgs::default(), ["/ThrowingNew:yes"].into_iter()).is_err());
        assert!(parse_directives(&mut CoffArgs::default(), "/ThrowingNew:yes").is_err());
    }

    #[test]
    fn treats_unix_absolute_paths_as_inputs() {
        let mut args = CoffArgs::default();
        parse(&mut args, ["/tmp/main.obj"].into_iter()).unwrap();
        assert_eq!(args.common.inputs.len(), 1);
    }

    #[test]
    fn expands_response_files() {
        let directory = tempfile::tempdir().unwrap();
        let response = directory.path().join("options.rsp");
        std::fs::write(
            &response,
            "/OUT:from-response.exe \"object with spaces.obj\"",
        )
        .unwrap();

        let mut args = CoffArgs::default();
        parse(&mut args, [format!("@{}", response.display())].into_iter()).unwrap();
        assert_eq!(&*args.common.output, Path::new("from-response.exe"));
        assert!(matches!(
            args.common.inputs[0].spec,
            InputSpec::File(ref path) if &**path == Path::new("object with spaces.obj")
        ));
    }

    #[test]
    fn expands_utf16_response_files() {
        fn encoded_response(contents: &str, little_endian: bool) -> Vec<u8> {
            let mut encoded = if little_endian {
                vec![0xff, 0xfe]
            } else {
                vec![0xfe, 0xff]
            };
            for word in contents.encode_utf16() {
                encoded.extend(if little_endian {
                    word.to_le_bytes()
                } else {
                    word.to_be_bytes()
                });
            }
            encoded
        }

        let directory = tempfile::tempdir().unwrap();
        for (name, little_endian) in [("little.rsp", true), ("big.rsp", false)] {
            let response = directory.path().join(name);
            std::fs::write(
                &response,
                encoded_response(
                    "/OUT:unicode.exe \"object with spaces.obj\" caf\u{e9}.obj",
                    little_endian,
                ),
            )
            .unwrap();

            let mut args = CoffArgs::default();
            parse(&mut args, [format!("@{}", response.display())].into_iter()).unwrap();
            assert_eq!(&*args.common.output, Path::new("unicode.exe"));
            assert!(matches!(
                args.common.inputs[0].spec,
                InputSpec::File(ref path) if &**path == Path::new("object with spaces.obj")
            ));
            assert!(matches!(
                args.common.inputs[1].spec,
                InputSpec::File(ref path) if &**path == Path::new("caf\u{e9}.obj")
            ));
        }
    }

    #[test]
    fn resolves_nested_response_files_relative_to_the_including_file() {
        let directory = tempfile::tempdir().unwrap();
        let nested_directory = directory.path().join("responses");
        std::fs::create_dir(&nested_directory).unwrap();
        let outer = nested_directory.join("outer.rsp");
        let inner = nested_directory.join("inner.rsp");
        std::fs::write(&outer, "@inner.rsp").unwrap();
        std::fs::write(&inner, "/OUT:nested.exe \"nested object.obj\"").unwrap();

        let mut args = CoffArgs::default();
        parse(&mut args, [format!("@{}", outer.display())].into_iter()).unwrap();
        assert_eq!(&*args.common.output, Path::new("nested.exe"));
        assert!(matches!(
            args.common.inputs[0].spec,
            InputSpec::File(ref path) if &**path == Path::new("nested object.obj")
        ));
    }

    #[test]
    fn rejects_recursive_response_files_but_allows_sequential_reuse() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first.rsp");
        let second = directory.path().join("second.rsp");
        std::fs::write(&first, "@second.rsp").unwrap();
        std::fs::write(&second, "@first.rsp").unwrap();

        let error =
            expand_response_files([format!("@{}", first.display())].into_iter()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("recursive response file expansion")
        );

        let leaf = directory.path().join("leaf.rsp");
        let repeated = directory.path().join("repeated.rsp");
        std::fs::write(&leaf, "common.obj").unwrap();
        std::fs::write(&repeated, "@leaf.rsp @leaf.rsp").unwrap();
        assert_eq!(
            expand_response_files([format!("@{}", repeated.display())].into_iter()).unwrap(),
            ["common.obj", "common.obj"]
        );
    }

    #[test]
    fn limits_response_file_nesting_depth() {
        let directory = tempfile::tempdir().unwrap();
        for index in 0..=128 {
            let contents = if index == 128 {
                "too-deep.obj".to_owned()
            } else {
                format!("@{}.rsp", index + 1)
            };
            std::fs::write(directory.path().join(format!("{index}.rsp")), contents).unwrap();
        }

        let first = directory.path().join("0.rsp");
        let error =
            expand_response_files([format!("@{}", first.display())].into_iter()).unwrap_err();
        assert!(error.to_string().contains("maximum depth of 128"));
    }

    #[test]
    fn follows_windows_doubled_quote_and_unmatched_quote_rules() {
        assert_eq!(
            windows_command_line_args(r#""before""after" plain"#),
            [r#"before"after"#, "plain"]
        );
        assert_eq!(
            windows_command_line_args(r#""unterminated value"#),
            ["unterminated value"]
        );
    }

    #[test]
    fn rejects_malformed_utf16_response_files() {
        let directory = tempfile::tempdir().unwrap();
        let odd = directory.path().join("odd.rsp");
        std::fs::write(&odd, [0xff, 0xfe, b'A']).unwrap();
        let error = parse(
            &mut CoffArgs::default(),
            [format!("@{}", odd.display())].into_iter(),
        )
        .unwrap_err();
        let diagnostic = error.to_string();
        assert!(diagnostic.contains("failed to decode response file"));
        assert!(diagnostic.contains("odd number of bytes"));

        let unpaired_surrogate = directory.path().join("surrogate.rsp");
        std::fs::write(&unpaired_surrogate, [0xff, 0xfe, 0x00, 0xd8]).unwrap();
        let error = parse(
            &mut CoffArgs::default(),
            [format!("@{}", unpaired_surrogate.display())].into_iter(),
        )
        .unwrap_err();
        let diagnostic = error.to_string();
        assert!(diagnostic.contains("failed to decode response file"));
        assert!(diagnostic.contains("malformed UTF-16"));
    }

    #[test]
    fn parses_image_layout_and_mitigation_options() {
        let mut args = CoffArgs::default();
        parse(
            &mut args,
            [
                "/NOLOGO",
                "/ALIGN:8192",
                "/FILEALIGN:0x200",
                "/BASE:0x140000000,0x200000",
                "/STACK:1048576,4096",
                "/HEAP:0x200000,0x1000",
                "/VERSION:12.7",
                "/DYNAMICBASE:NO",
                "/FIXED",
                "/NXCOMPAT:NO",
            ]
            .into_iter(),
        )
        .unwrap();

        assert!(args.no_logo);
        assert_eq!(args.section_alignment, Some(8192));
        assert_eq!(args.file_alignment, Some(512));
        assert_eq!(
            args.image_base,
            Some(ImageBase {
                address: 0x140000000,
                max_size: Some(0x200000),
            })
        );
        assert_eq!(
            args.stack,
            Some(ReserveCommit {
                reserve: 1_048_576,
                commit: Some(4096),
            })
        );
        assert_eq!(args.image_version, Some((12, 7)));
        assert!(!args.dynamic_base);
        assert!(args.fixed);
        assert!(!args.nx_compat);
    }

    #[test]
    fn parses_optimization_force_and_output_metadata() {
        let mut args = CoffArgs::default();
        parse(
            &mut args,
            [
                "/OPT:REF,NOICF",
                "/FORCE:MULTIPLE",
                "/FORCE:UNRESOLVED",
                "/IMPLIB:answer.lib",
                "/PDB:answer.pdb",
                "/MANIFEST:NO",
                "/MERGE:.rdata=.text",
                "/SECTION:.shared,RWS",
            ]
            .into_iter(),
        )
        .unwrap();

        assert_eq!(args.optimization.ref_, OptSetting::Enabled);
        assert_eq!(args.optimization.icf, OptSetting::Disabled);
        assert!(args.force.multiple);
        assert!(args.force.unresolved);
        assert_eq!(
            args.import_library.as_deref(),
            Some(Path::new("answer.lib"))
        );
        assert_eq!(args.pdb.as_deref(), Some(Path::new("answer.pdb")));
        assert!(!args.manifest);
        assert_eq!(
            args.merges,
            [SectionMerge {
                from: ".rdata".to_owned(),
                to: ".text".to_owned(),
            }]
        );
        assert_eq!(
            args.section_attributes,
            [SectionAttributes {
                name: ".shared".to_owned(),
                attributes: "RWS".to_owned(),
            }]
        );
    }

    #[test]
    fn whole_archive_marks_global_and_specific_library_inputs() {
        let mut args = CoffArgs::default();
        parse(
            &mut args,
            ["/WHOLEARCHIVE:first.lib", "/WHOLEARCHIVE", "second.lib"].into_iter(),
        )
        .unwrap();
        assert_eq!(args.whole_archive_libraries, ["first.lib"]);
        assert!(args.whole_archive);
        assert_eq!(args.common.inputs.len(), 2);
        assert!(
            args.common
                .inputs
                .iter()
                .all(|input| input.modifiers.whole_archive)
        );
    }

    #[test]
    fn parses_directives_with_windows_quoting() {
        let mut args = CoffArgs::default();
        parse_directives(
            &mut args,
            r#"/DEFAULTLIB:"C:\Program Files\SDK\runtime.lib" /INCLUDE:"symbol\"quoted" /OPT:NOREF,ICF"#,
        )
        .unwrap();
        assert_eq!(
            args.default_libraries,
            [r"C:\Program Files\SDK\runtime.lib"]
        );
        assert_eq!(args.force_undefined, [r#"symbol"quoted"#]);
        assert_eq!(args.optimization.ref_, OptSetting::Disabled);
        assert_eq!(args.optimization.icf, OptSetting::Enabled);
    }

    #[test]
    fn parses_real_msvc_crt_directives_into_runtime_state() {
        let mut args = CoffArgs::default();
        parse_directives(
            &mut args,
            r#" /DEFAULTLIB:libcmt /alternatename:__pRawDllMain=__pDefaultRawDllMain /FAILIFMISMATCH:"RuntimeLibrary=MT_StaticRelease" /include:"forced symbol" /EDITANDCONTINUE /DISALLOWLIB:libcmtd"#,
        )
        .unwrap();

        assert_eq!(
            args.runtime_resolution.alternate_target("__pRawDllMain"),
            Some("__pDefaultRawDllMain")
        );
        assert_eq!(
            args.runtime_resolution.mismatch_value("RuntimeLibrary"),
            Some("MT_StaticRelease")
        );
        assert_eq!(
            args.runtime_resolution.include_roots().collect::<Vec<_>>(),
            ["forced symbol"]
        );
        assert!(args.edit_and_continue);
        assert_eq!(args.disallowed_libraries, ["libcmtd"]);
    }

    #[test]
    fn command_line_and_directives_share_runtime_validation() {
        let mut args = CoffArgs::default();
        parse(
            &mut args,
            [
                "/ALTERNATENAME:CaseSensitive=TargetName",
                "/FAILIFMISMATCH:RuntimeLibrary=MD",
            ]
            .into_iter(),
        )
        .unwrap();
        parse_directives(
            &mut args,
            "/alternatename:CaseSensitive=TargetName /failifmismatch:RuntimeLibrary=MT",
        )
        .unwrap_err();

        assert_eq!(
            args.runtime_resolution.alternate_target("CaseSensitive"),
            Some("TargetName")
        );
        assert_eq!(
            args.runtime_resolution.alternate_target("casesensitive"),
            None
        );
    }

    #[test]
    fn fail_if_mismatch_diagnostic_is_independent_of_value_order() {
        fn conflict(first: &str, second: &str) -> String {
            let mut args = CoffArgs::default();
            parse(
                &mut args,
                [
                    format!("/FAILIFMISMATCH:RuntimeLibrary={first}"),
                    format!("/FAILIFMISMATCH:RuntimeLibrary={second}"),
                ]
                .into_iter(),
            )
            .unwrap_err()
            .to_string()
        }

        assert_eq!(conflict("MD", "MT"), conflict("MT", "MD"));
    }

    #[test]
    fn parses_guard_and_manifest_dependency_options() {
        let dependency = "type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0'";
        let mut args = CoffArgs::default();
        parse_directives(
            &mut args,
            &format!(r#"/GuArD:CF,NOLONGJMP /MANIFESTDEPENDENCY:"{dependency}""#),
        )
        .unwrap();

        assert_eq!(args.guard.control_flow, OptSetting::Enabled);
        assert!(args.guard.no_long_jump);
        assert_eq!(
            args.manifest_dependencies,
            [ManifestDependency {
                value: dependency.to_owned()
            }]
        );

        let mut disabled = CoffArgs::default();
        parse(&mut disabled, ["/GUARD:NO"].into_iter()).unwrap();
        assert_eq!(disabled.guard.control_flow, OptSetting::Disabled);
    }

    #[test]
    fn parses_crt_guard_symbols_with_case_insensitive_flags() {
        let mut args = CoffArgs::default();
        parse_directives(
            &mut args,
            "/GUARDSYM:__C_specific_handler,S /guardsym:CaseSensitive,s /GuArDsYm:plain",
        )
        .unwrap();

        assert_eq!(
            args.guard_symbols,
            [
                GuardSymbol {
                    symbol: "__C_specific_handler".into(),
                    flags: GuardSymbolFlags { suppressed: true },
                },
                GuardSymbol {
                    symbol: "CaseSensitive".into(),
                    flags: GuardSymbolFlags { suppressed: true },
                },
                GuardSymbol {
                    symbol: "plain".into(),
                    flags: GuardSymbolFlags::default(),
                },
            ]
        );
    }

    #[test]
    fn command_line_accepts_guard_symbol_and_rejects_bad_flags() {
        let mut args = CoffArgs::default();
        parse(&mut args, ["/guardsym:handler,S"].into_iter()).unwrap();
        assert_eq!(args.guard_symbols[0].symbol, "handler");

        for invalid in [
            "/GUARDSYM:",
            "/GUARDSYM:symbol,",
            "/GUARDSYM:symbol,X",
            "/GUARDSYM:symbol,SS",
            "/GUARDSYM:symbol,S,extra",
        ] {
            let mut args = CoffArgs::default();
            assert!(
                parse(&mut args, [invalid].into_iter()).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn rejects_malformed_runtime_and_conflicting_guard_options() {
        for invalid in [
            "/ALTERNATENAME:missing-target",
            "/ALTERNATENAME:same=same",
            "/FAILIFMISMATCH:=value",
            "/GUARD:CF,NO",
            "/GUARD:UNKNOWN",
        ] {
            let mut args = CoffArgs::default();
            assert!(
                parse(&mut args, [invalid].into_iter()).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn rejects_invalid_or_unsupported_values() {
        for invalid in [
            "/ALIGN:3000",
            "/FILEALIGN:128",
            "/BASE:1234",
            "/STACK:1,2",
            "/VERSION:1.",
            "/DYNAMICBASE:YES",
            "/FIXED:MAYBE",
            "/NXCOMPAT:TRUE",
            "/FORCE:DUPLICATES",
            "/MERGE:.a",
            "/SECTION:.text,X",
            "/DEBUG:FASTLINK",
        ] {
            let mut args = CoffArgs::default();
            assert!(
                parse(&mut args, [invalid].into_iter()).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn default_security_settings_are_enabled() {
        let args = CoffArgs::default();
        assert!(args.dynamic_base);
        assert!(!args.fixed);
        assert!(args.nx_compat);
        assert!(args.manifest);
    }
}
