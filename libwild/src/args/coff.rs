//! Command-line parsing for the MSVC-compatible (`link.exe`) driver.

use super::{CommonArgs, Input, InputSpec, Modifiers};
use crate::alignment::Alignment;
use crate::bail;
use crate::error::{Context, Result};
use crate::platform;
use std::path::Path;
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

#[derive(Debug)]
pub struct CoffArgs {
    pub(crate) common: CommonArgs,
    pub(crate) entry: Option<String>,
    pub(crate) subsystem: Option<SubsystemSpec>,
    pub(crate) is_dll: bool,
    pub(crate) machine: CoffMachine,
    pub(crate) lib_search_path: Vec<Box<Path>>,
    pub(crate) default_libraries: Vec<String>,
    pub(crate) no_default_libraries: bool,
    pub(crate) excluded_default_libraries: Vec<String>,
    pub(crate) exports: Vec<String>,
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
            subsystem: None,
            is_dll: false,
            machine: CoffMachine::X86_64,
            lib_search_path: Vec::new(),
            default_libraries: Vec::new(),
            no_default_libraries: false,
            excluded_default_libraries: Vec::new(),
            exports: Vec::new(),
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
    parse_tokens(args, expanded.iter().map(String::as_str))?;
    validate_alignments(args)?;
    args.common.report_unrecognized()
}

/// Parses the contents of a COFF `.drectve` section through the regular link.exe option parser.
///
/// MSVC emits these strings using the Windows command-line quoting rules rather than shell
/// quoting. Keeping this entry point shared prevents compiler-generated directives from subtly
/// differing from their command-line equivalents.
pub(crate) fn parse_directives(args: &mut CoffArgs, directives: &str) -> Result {
    let tokens = windows_command_line_args(directives)?;
    parse_tokens(args, tokens.iter().map(String::as_str))?;
    validate_alignments(args)?;
    args.common.report_unrecognized()
}

fn parse_tokens<'a, I>(args: &mut CoffArgs, input: I) -> Result
where
    I: Iterator<Item = &'a str>,
{
    let mut input = input.peekable();

    while let Some(arg) = input.next() {
        if !arg.starts_with('/') {
            add_input(args, arg);
            continue;
        }

        let option = &arg[1..];
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
                    args.excluded_default_libraries.push(value.to_owned())
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
                args.exports.push(value.to_owned());
            }
            "include" => {
                let value = required_value("/INCLUDE", inline_value, &mut input)?;
                args.force_undefined.push(value.to_owned());
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
            "manifest" => args.manifest = parse_yes_no("/MANIFEST", inline_value)?,
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
            _ if option.contains('/') => add_input(args, arg),
            _ => args.common.unrecognized_options.push(arg.to_owned()),
        }
    }
    Ok(())
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
    if let (Some(section), Some(file)) = (args.section_alignment, args.file_alignment) {
        if section < file {
            bail!("/ALIGN ({section}) must not be smaller than /FILEALIGN ({file})");
        }
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

fn parse_opt(options: &mut OptimizationOptions, value: &str) -> Result {
    for value in value.split(',') {
        match value.to_ascii_lowercase().as_str() {
            "ref" => options.ref_ = OptSetting::Enabled,
            "noref" => options.ref_ = OptSetting::Disabled,
            "icf" => options.icf = OptSetting::Enabled,
            "noicf" => options.icf = OptSetting::Disabled,
            _ => bail!(
                "unsupported /OPT value `{value}`; supported values are REF, NOREF, ICF, and NOICF"
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
fn windows_command_line_args(input: &str) -> Result<Vec<String>> {
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
                        quoted = !quoted;
                    } else {
                        value.push('"');
                    }
                    index += 1;
                } else {
                    value.extend(std::iter::repeat_n('\\', count));
                }
            } else if chars[index] == '"' {
                quoted = !quoted;
                index += 1;
            } else {
                value.push(chars[index]);
                index += 1;
            }
        }
        if quoted {
            bail!("unterminated double quote in COFF directive string");
        }
        result.push(value);
    }
    Ok(result)
}

fn expand_response_files<S: AsRef<str>, I: Iterator<Item = S>>(input: I) -> Result<Vec<String>> {
    let mut output = Vec::new();
    for arg in input {
        let arg = arg.as_ref();
        if let Some(path) = arg.strip_prefix('@') {
            let contents = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read response file `{path}`"))?;
            let nested = windows_command_line_args(&contents)?;
            output.extend(expand_response_files(nested.into_iter())?);
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
                "/DEFAULTLIB:ucrt.lib",
                "/NODEFAULTLIB:oldnames.lib",
                "/LIBPATH:sdk/lib",
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
        assert_eq!(args.exports, ["answer,@7"]);
        assert_eq!(args.force_undefined, ["forced_symbol"]);
        assert!(args.debug);
        assert!(matches!(
            args.common.inputs[0].spec,
            InputSpec::File(ref path) if &**path == Path::new("main.obj")
        ));
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
    fn rejects_unsupported_machine_and_unknown_options() {
        let mut args = CoffArgs::default();
        assert!(parse(&mut args, ["/machine:arm64"].into_iter()).is_err());
        assert!(parse(&mut args, ["/not-a-real-option"].into_iter()).is_err());
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
            "/OPT:LBR",
            "/FORCE:DUPLICATES",
            "/MANIFEST:EMBED",
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
