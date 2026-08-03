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
    let mut input = expanded.iter().map(String::as_str).peekable();

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
                args.debug = true;
            }
            // On Unix hosts an absolute path also begins with '/'. Do not mistake it for an
            // option merely because the link.exe spelling uses the same prefix.
            _ if option.contains('/') => add_input(args, arg),
            _ => args.common.unrecognized_options.push(arg.to_owned()),
        }
    }

    args.common.report_unrecognized()
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
    args.common.save_dir.handle_file(value);
    args.common.inputs.push(Input {
        spec: InputSpec::File(Box::from(Path::new(value))),
        search_first: None,
        modifiers: Modifiers::default(),
    });
}

fn expand_response_files<S: AsRef<str>, I: Iterator<Item = S>>(input: I) -> Result<Vec<String>> {
    let mut output = Vec::new();
    for arg in input {
        let arg = arg.as_ref();
        if let Some(path) = arg.strip_prefix('@') {
            let nested = super::read_args_from_file(Path::new(path))?;
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
}
