//! MSVC-compatible default PE entry-point selection.

use crate::args::coff::CoffArgs;
use crate::args::coff::Subsystem;
use crate::bail;
use crate::error;
use crate::error::Context;
use crate::error::Result;
use object::Object;
use object::ObjectSymbol;
use std::collections::BTreeSet;

const USER_ENTRIES: [(&[u8], &str, EntryFamily); 4] = [
    (b"main", "mainCRTStartup", EntryFamily::Console),
    (b"wmain", "wmainCRTStartup", EntryFamily::Console),
    (b"WinMain", "WinMainCRTStartup", EntryFamily::Windows),
    (b"wWinMain", "wWinMainCRTStartup", EntryFamily::Windows),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryFamily {
    Console,
    Windows,
}

/// Select the symbol placed in AddressOfEntryPoint and rooted during archive extraction.
///
/// Only symbols from direct object inputs participate in executable entry inference. This is
/// intentional: archive contents must not accidentally decide whether a program is console or
/// GUI, and the selected CRT startup symbol needs to become the demand that extracts the right
/// archive member.
#[cfg(test)]
fn select(args: &CoffArgs, objects: &[crate::coff::CoffObject<'_>]) -> Result<Option<String>> {
    select_from_objects(args, objects.iter())
}

pub(super) fn select_from_objects<'data, 'objects>(
    args: &CoffArgs,
    objects: impl IntoIterator<Item = &'objects crate::coff::CoffObject<'data>>,
) -> Result<Option<String>>
where
    'data: 'objects,
{
    if args.no_entry {
        return Ok(None);
    }
    if let Some(entry) = &args.entry {
        return Ok(Some(entry.clone()));
    }
    if args.is_dll {
        return Ok(Some("_DllMainCRTStartup".to_owned()));
    }

    let definitions = user_definitions(objects)?;
    select_executable(args.subsystem.as_ref().map(|spec| &spec.kind), |name| {
        definitions.contains(name)
    })
    .map(|entry| Some(entry.to_owned()))
}

fn user_definitions<'data, 'objects>(
    objects: impl IntoIterator<Item = &'objects crate::coff::CoffObject<'data>>,
) -> Result<BTreeSet<Vec<u8>>>
where
    'data: 'objects,
{
    let mut definitions = BTreeSet::new();
    for object in objects {
        for symbol in object.file().symbols() {
            if !symbol.is_global() || (!symbol.is_definition() && !symbol.is_common()) {
                continue;
            }
            let name = symbol
                .name_bytes()
                .context("invalid COFF symbol name while selecting entry point")?;
            if !name.is_empty() {
                definitions.insert(name.to_vec());
            }
        }
    }
    Ok(definitions)
}

fn select_executable(
    subsystem: Option<&Subsystem>,
    mut is_defined: impl FnMut(&[u8]) -> bool,
) -> Result<&'static str> {
    let required_family = match subsystem {
        Some(Subsystem::Console) => Some(EntryFamily::Console),
        Some(Subsystem::Windows) => Some(EntryFamily::Windows),
        None => None,
        Some(other) => {
            bail!(
                "cannot infer a default entry point for /SUBSYSTEM:{}; specify /ENTRY:<symbol>",
                subsystem_name(other)
            )
        }
    };
    let candidates = USER_ENTRIES
        .iter()
        .filter(|(user, _, family)| {
            required_family.is_none_or(|required| required == *family) && is_defined(user)
        })
        .collect::<Vec<_>>();

    match candidates.as_slice() {
        [(_, startup, _)] => Ok(startup),
        [] => {
            let expected = match required_family {
                Some(EntryFamily::Console) => "`main` or `wmain`",
                Some(EntryFamily::Windows) => "`WinMain` or `wWinMain`",
                None => "`main`, `wmain`, `WinMain`, or `wWinMain`",
            };
            Err(error!(
                "cannot infer PE entry point: no user definition of {expected}; specify /ENTRY:<symbol>"
            ))
        }
        _ => Err(error!(
            "cannot infer PE entry point: ambiguous user entry definitions {}; specify /ENTRY:<symbol>",
            candidates
                .iter()
                .map(|(name, _, _)| format!("`{}`", String::from_utf8_lossy(name)))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn subsystem_name(subsystem: &Subsystem) -> &'static str {
    match subsystem {
        Subsystem::Console => "CONSOLE",
        Subsystem::Windows => "WINDOWS",
        Subsystem::Native => "NATIVE",
        Subsystem::EfiApplication => "EFI_APPLICATION",
        Subsystem::EfiBootServiceDriver => "EFI_BOOT_SERVICE_DRIVER",
        Subsystem::EfiRuntimeDriver => "EFI_RUNTIME_DRIVER",
        Subsystem::EfiRom => "EFI_ROM",
        Subsystem::Posix => "POSIX",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn choose(subsystem: Option<&Subsystem>, definitions: &[&[u8]]) -> Result<&'static str> {
        select_executable(subsystem, |name| definitions.contains(&name))
    }

    #[test]
    fn maps_the_four_msvc_user_entry_conventions() {
        assert_eq!(choose(None, &[b"main"]).unwrap(), "mainCRTStartup");
        assert_eq!(choose(None, &[b"wmain"]).unwrap(), "wmainCRTStartup");
        assert_eq!(choose(None, &[b"WinMain"]).unwrap(), "WinMainCRTStartup");
        assert_eq!(choose(None, &[b"wWinMain"]).unwrap(), "wWinMainCRTStartup");
    }

    #[test]
    fn subsystem_restricts_the_entry_family() {
        assert_eq!(
            choose(Some(&Subsystem::Console), &[b"main", b"WinMain"]).unwrap(),
            "mainCRTStartup"
        );
        assert_eq!(
            choose(Some(&Subsystem::Windows), &[b"main", b"WinMain"]).unwrap(),
            "WinMainCRTStartup"
        );
    }

    #[test]
    fn ambiguous_and_missing_intent_are_diagnostic() {
        let ambiguous = choose(None, &[b"main", b"wmain"]).unwrap_err().to_string();
        assert!(ambiguous.contains("ambiguous"));
        assert!(ambiguous.contains("`main`"));
        assert!(ambiguous.contains("`wmain`"));

        let missing = choose(Some(&Subsystem::Windows), &[b"main"])
            .unwrap_err()
            .to_string();
        assert!(missing.contains("`WinMain` or `wWinMain`"));
    }

    #[test]
    fn non_crt_subsystems_require_an_explicit_entry() {
        let error = choose(Some(&Subsystem::Native), &[b"main"])
            .unwrap_err()
            .to_string();
        assert!(error.contains("/SUBSYSTEM:NATIVE"));
        assert!(error.contains("/ENTRY:<symbol>"));
    }

    #[test]
    fn dll_default_and_noentry_obey_msvc_conventions() {
        let dll = CoffArgs {
            is_dll: true,
            ..Default::default()
        };
        assert_eq!(
            select(&dll, &[]).unwrap().as_deref(),
            Some("_DllMainCRTStartup")
        );

        let resource_only = CoffArgs {
            is_dll: true,
            no_entry: true,
            ..Default::default()
        };
        assert_eq!(select(&resource_only, &[]).unwrap(), None);
    }

    #[test]
    fn explicit_entry_wins_without_user_entry_inference() {
        let args = CoffArgs {
            entry: Some("custom_start".to_owned()),
            ..Default::default()
        };
        assert_eq!(select(&args, &[]).unwrap().as_deref(), Some("custom_start"));
    }
}
