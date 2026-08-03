//! MSVC-compatible runtime directives and default-symbol policy for COFF.
//!
//! This module deliberately does not read object files or mutate a linker's
//! symbol table. It models the resolution state contributed by `.drectve`
//! sections and exposes deterministic queries that a PE linker can integrate
//! into its own archive-extraction loop.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use object::LittleEndian as LE;
use object::pe;
use object::read::coff::{CoffHeader as _, Symbol as _};

/// A malformed or contradictory runtime-link directive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoffRuntimeError {
    message: String,
}

impl CoffRuntimeError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for CoffRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for CoffRuntimeError {}

pub type Result<T> = std::result::Result<T, CoffRuntimeError>;

/// One weak alias encoded in a legacy MSVC `Machine=UNKNOWN` object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyAlias<'data> {
    pub symbol: &'data [u8],
    pub target: &'data [u8],
}

/// A validated legacy alias-map member found in Microsoft CRT archives.
///
/// The CRT's `sdknames` and `almap` members are ordinary, small COFF objects
/// except that their machine field is `IMAGE_FILE_MACHINE_UNKNOWN`. Their
/// useful payload is one or more `SEARCH_ALIAS` weak externals. They are
/// architecture-neutral metadata and must not be rejected as foreign code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyAliasObject<'data> {
    aliases: Vec<LegacyAlias<'data>>,
}

impl<'data> LegacyAliasObject<'data> {
    #[must_use]
    pub fn aliases(&self) -> &[LegacyAlias<'data>] {
        &self.aliases
    }

    /// Converts the member payload to the same directives used for
    /// `/alternatename`, ready to feed into [`RuntimeResolution::apply`].
    pub fn directives(&self) -> Result<Vec<RuntimeDirective>> {
        self.aliases
            .iter()
            .map(|alias| {
                let symbol = std::str::from_utf8(alias.symbol)
                    .map_err(|_| CoffRuntimeError::new("legacy alias source is not valid UTF-8"))?;
                let target = std::str::from_utf8(alias.target)
                    .map_err(|_| CoffRuntimeError::new("legacy alias target is not valid UTF-8"))?;
                Ok(RuntimeDirective::AlternateName {
                    symbol: symbol.to_owned(),
                    target: target.to_owned(),
                })
            })
            .collect()
    }
}

/// Classifies and parses a legacy CRT alias-map object.
///
/// Returns `Ok(None)` for normal machine-specific COFF objects and non-COFF
/// data. A structurally COFF-like `Machine=UNKNOWN` member is instead fully
/// validated, producing an error rather than being silently ignored.
pub fn parse_legacy_alias_object(data: &[u8]) -> Result<Option<LegacyAliasObject<'_>>> {
    const COFF_HEADER_SIZE: usize = 20;
    if data.len() < COFF_HEADER_SIZE
        || u16::from_le_bytes(data[0..2].try_into().unwrap()) != pe::IMAGE_FILE_MACHINE_UNKNOWN.0
        || u16::from_le_bytes(data[2..4].try_into().unwrap()) == pe::IMPORT_OBJECT_HDR_SIG2
    {
        return Ok(None);
    }

    let file =
        object::read::coff::CoffFile::<_, pe::ImageFileHeader>::parse(data).map_err(|error| {
            CoffRuntimeError::new(format!("malformed legacy alias object: {error}"))
        })?;
    if file.coff_header().machine() != pe::IMAGE_FILE_MACHINE_UNKNOWN {
        return Ok(None);
    }

    let table = file.coff_symbol_table();
    let strings = table.strings();
    let mut aliases = Vec::new();
    for (index, symbol) in table.iter() {
        if !symbol.has_aux_weak_external() {
            continue;
        }
        let auxiliary = table.aux_weak_external(index).map_err(|error| {
            CoffRuntimeError::new(format!("invalid legacy weak alias record: {error}"))
        })?;
        let search = auxiliary.weak_search_type.get(LE);
        if search != pe::IMAGE_WEAK_EXTERN_SEARCH_ALIAS {
            return Err(CoffRuntimeError::new(format!(
                "legacy Machine=UNKNOWN weak external uses search type {search}, expected SEARCH_ALIAS"
            )));
        }
        let target_index = object::SymbolIndex(
            usize::try_from(auxiliary.weak_default_sym_index.get(LE)).map_err(|_| {
                CoffRuntimeError::new("legacy weak alias target index does not fit in usize")
            })?,
        );
        let target = table.symbol(target_index).map_err(|error| {
            CoffRuntimeError::new(format!("invalid legacy weak alias target index: {error}"))
        })?;
        let symbol_name = symbol.name(strings).map_err(|error| {
            CoffRuntimeError::new(format!("invalid legacy alias source name: {error}"))
        })?;
        let target_name = target.name(strings).map_err(|error| {
            CoffRuntimeError::new(format!("invalid legacy alias target name: {error}"))
        })?;
        if symbol_name.is_empty() || target_name.is_empty() {
            return Err(CoffRuntimeError::new(
                "legacy weak alias contains an empty symbol name",
            ));
        }
        aliases.push(LegacyAlias {
            symbol: symbol_name,
            target: target_name,
        });
    }
    if aliases.is_empty() {
        return Err(CoffRuntimeError::new(
            "Machine=UNKNOWN COFF member contains no SEARCH_ALIAS weak externals",
        ));
    }
    aliases.sort_unstable_by(|left, right| {
        left.symbol
            .cmp(right.symbol)
            .then_with(|| left.target.cmp(right.target))
    });
    aliases.dedup();
    Ok(Some(LegacyAliasObject { aliases }))
}

/// Resolution-relevant directives commonly emitted by clang-cl and MSVC.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeDirective {
    /// Use `target` if `symbol` remains undefined.
    AlternateName { symbol: String, target: String },
    /// Require all objects carrying `key` to agree on its value.
    FailIfMismatch { key: String, value: String },
    /// Make a symbol an archive-extraction/garbage-collection root.
    Include(String),
}

/// Parses the runtime-relevant options from the contents of a `.drectve`
/// section. Option names are ASCII case-insensitive, as in `link.exe`.
/// Unrelated valid options (for example `/DEFAULTLIB`) are ignored.
///
/// Windows command-line quoting is honoured: whitespace inside double quotes
/// is preserved, pairs of backslashes before a quote follow the usual MSVC
/// rules, and quotes can surround only the option value.
pub fn parse_runtime_directives(input: &str) -> Result<Vec<RuntimeDirective>> {
    tokenize_windows(input)?
        .into_iter()
        .filter_map(|token| match parse_runtime_token(&token) {
            Ok(Some(directive)) => Some(Ok(directive)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

/// Parses one already-unquoted command-line token. Returns `None` for an
/// option outside this module's scope.
pub fn parse_runtime_token(token: &str) -> Result<Option<RuntimeDirective>> {
    let option = token
        .strip_prefix('/')
        .or_else(|| token.strip_prefix('-'))
        .ok_or_else(|| CoffRuntimeError::new(format!("invalid directive token `{token}`")))?;
    let Some((name, value)) = option.split_once(':') else {
        return Ok(None);
    };

    if name.eq_ignore_ascii_case("alternatename") {
        let (symbol, target) = split_assignment(value, "alternatename")?;
        if symbol == target {
            return Err(CoffRuntimeError::new(format!(
                "alternatename `{symbol}` aliases a symbol to itself"
            )));
        }
        return Ok(Some(RuntimeDirective::AlternateName {
            symbol: symbol.to_owned(),
            target: target.to_owned(),
        }));
    }
    if name.eq_ignore_ascii_case("failifmismatch") {
        let (key, value) = split_assignment(value, "failifmismatch")?;
        return Ok(Some(RuntimeDirective::FailIfMismatch {
            key: key.to_owned(),
            value: value.to_owned(),
        }));
    }
    if name.eq_ignore_ascii_case("include") {
        require_nonempty(value, "include symbol")?;
        return Ok(Some(RuntimeDirective::Include(value.to_owned())));
    }
    Ok(None)
}

fn split_assignment<'a>(value: &'a str, option: &str) -> Result<(&'a str, &'a str)> {
    let (left, right) = value.split_once('=').ok_or_else(|| {
        CoffRuntimeError::new(format!("/{option} requires a `name=value` argument"))
    })?;
    require_nonempty(left, &format!("{option} name"))?;
    require_nonempty(right, &format!("{option} value"))?;
    Ok((left, right))
}

fn require_nonempty(value: &str, description: &str) -> Result<()> {
    if value.is_empty() {
        Err(CoffRuntimeError::new(format!("{description} is empty")))
    } else {
        Ok(())
    }
}

fn tokenize_windows(input: &str) -> Result<Vec<String>> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        while index < chars.len() && chars[index].is_whitespace() {
            index += 1;
        }
        if index == chars.len() {
            break;
        }
        let mut token = String::new();
        let mut quoted = false;
        while index < chars.len() && (quoted || !chars[index].is_whitespace()) {
            if chars[index] == '\\' {
                let start = index;
                while index < chars.len() && chars[index] == '\\' {
                    index += 1;
                }
                let count = index - start;
                if index < chars.len() && chars[index] == '"' {
                    token.extend(std::iter::repeat_n('\\', count / 2));
                    if count % 2 == 0 {
                        quoted = !quoted;
                    } else {
                        token.push('"');
                    }
                    index += 1;
                } else {
                    token.extend(std::iter::repeat_n('\\', count));
                }
            } else if chars[index] == '"' {
                quoted = !quoted;
                index += 1;
            } else {
                token.push(chars[index]);
                index += 1;
            }
        }
        if quoted {
            return Err(CoffRuntimeError::new(
                "unterminated double quote in COFF directive section",
            ));
        }
        if !token.is_empty() {
            tokens.push(token);
        }
    }
    Ok(tokens)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectiveValue {
    value: String,
    source: String,
}

/// Accumulated `.drectve` state used during symbol resolution.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeResolution {
    alternate_names: BTreeMap<String, DirectiveValue>,
    mismatches: BTreeMap<String, DirectiveValue>,
    include_roots: BTreeSet<String>,
}

impl RuntimeResolution {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds all relevant directives from one object. `source` is included in
    /// diagnostics and should be a stable object or archive-member name.
    pub fn parse_and_apply(&mut self, input: &str, source: &str) -> Result<()> {
        for directive in parse_runtime_directives(input)? {
            self.apply(directive, source)?;
        }
        Ok(())
    }

    pub fn apply(&mut self, directive: RuntimeDirective, source: &str) -> Result<()> {
        match directive {
            RuntimeDirective::AlternateName { symbol, target } => {
                insert_consistent(
                    &mut self.alternate_names,
                    "alternate name",
                    symbol,
                    target,
                    source,
                )?;
            }
            RuntimeDirective::FailIfMismatch { key, value } => {
                insert_consistent(&mut self.mismatches, "fail-if-mismatch", key, value, source)?;
            }
            RuntimeDirective::Include(symbol) => {
                self.include_roots.insert(symbol);
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn include_roots(&self) -> impl ExactSizeIterator<Item = &str> {
        self.include_roots.iter().map(String::as_str)
    }

    /// Resolves an `/alternatename` chain. A fallback is followed only while
    /// the current symbol is undefined, matching weak-alias semantics.
    ///
    /// The callback should report definitions already selected by the link.
    /// A returned symbol is either defined or the last unresolved name in the
    /// chain. Alias cycles are rejected with a canonical, stable diagnostic.
    pub fn resolve_alternate_name<'a>(
        &'a self,
        symbol: &'a str,
        mut is_defined: impl FnMut(&str) -> bool,
    ) -> Result<&'a str> {
        let mut current = symbol;
        let mut path = Vec::new();
        let mut positions = BTreeMap::new();
        loop {
            if is_defined(current) {
                return Ok(current);
            }
            let Some(next) = self.alternate_names.get(current) else {
                return Ok(current);
            };
            if let Some(&cycle_start) = positions.get(current) {
                return Err(alias_cycle_error(&path[cycle_start..]));
            }
            positions.insert(current, path.len());
            path.push(current);
            current = &next.value;
        }
    }

    #[must_use]
    pub fn alternate_target(&self, symbol: &str) -> Option<&str> {
        self.alternate_names
            .get(symbol)
            .map(|value| value.value.as_str())
    }

    #[must_use]
    pub fn mismatch_value(&self, key: &str) -> Option<&str> {
        self.mismatches.get(key).map(|value| value.value.as_str())
    }
}

fn insert_consistent(
    map: &mut BTreeMap<String, DirectiveValue>,
    kind: &str,
    key: String,
    value: String,
    source: &str,
) -> Result<()> {
    if let Some(existing) = map.get(&key) {
        if existing.value == value {
            return Ok(());
        }
        let mut choices = [
            (existing.value.as_str(), existing.source.as_str()),
            (value.as_str(), source),
        ];
        choices.sort_unstable();
        return Err(CoffRuntimeError::new(format!(
            "conflicting {kind} for `{key}`: `{}` from `{}` versus `{}` from `{}`",
            choices[0].0, choices[0].1, choices[1].0, choices[1].1
        )));
    }
    map.insert(
        key,
        DirectiveValue {
            value,
            source: source.to_owned(),
        },
    );
    Ok(())
}

fn alias_cycle_error(cycle: &[&str]) -> CoffRuntimeError {
    let first = cycle
        .iter()
        .enumerate()
        .min_by_key(|(_, name)| *name)
        .map_or(0, |(index, _)| index);
    let ordered = cycle[first..]
        .iter()
        .chain(&cycle[..first])
        .copied()
        .chain(std::iter::once(cycle[first]))
        .collect::<Vec<_>>()
        .join(" -> ");
    CoffRuntimeError::new(format!("alternatename cycle: {ordered}"))
}

/// PE subsystem families that affect MSVC's default startup symbol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeSubsystem {
    Console,
    Windows,
    Native,
    /// Let the user-facing symbol select Console or Windows.
    Unspecified,
}

/// Inputs to default entry-point selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DefaultEntryConfig {
    pub dll: bool,
    pub subsystem: RuntimeSubsystem,
}

/// The user symbol and corresponding startup routine chosen by MSVC policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DefaultEntry {
    pub user_symbol: Option<&'static str>,
    pub startup_symbol: &'static str,
    pub inferred_subsystem: RuntimeSubsystem,
}

/// Selects the conventional entry point used when `/ENTRY` was not supplied.
/// `symbols` contains user definitions already known to the resolver.
///
/// The search order matches lld-link/link.exe conventions when both narrow
/// and wide variants are present: `main` before `wmain`, and `WinMain` before
/// `wWinMain`. `None` means that no compatible user entry was found.
#[must_use]
pub fn select_default_entry<'a>(
    config: DefaultEntryConfig,
    symbols: impl IntoIterator<Item = &'a str>,
) -> Option<DefaultEntry> {
    if config.dll {
        return Some(DefaultEntry {
            user_symbol: None,
            startup_symbol: "_DllMainCRTStartup",
            inferred_subsystem: config.subsystem,
        });
    }
    if config.subsystem == RuntimeSubsystem::Native {
        return Some(DefaultEntry {
            user_symbol: None,
            startup_symbol: "NtProcessStartup",
            inferred_subsystem: RuntimeSubsystem::Native,
        });
    }

    let symbols: BTreeSet<&str> = symbols.into_iter().collect();
    let console = [("main", "mainCRTStartup"), ("wmain", "wmainCRTStartup")];
    let windows = [
        ("WinMain", "WinMainCRTStartup"),
        ("wWinMain", "wWinMainCRTStartup"),
    ];
    let candidates: &[(&str, &str)] = match config.subsystem {
        RuntimeSubsystem::Console => &console,
        RuntimeSubsystem::Windows => &windows,
        RuntimeSubsystem::Unspecified => &[console[0], console[1], windows[0], windows[1]],
        RuntimeSubsystem::Native => unreachable!(),
    };
    candidates
        .iter()
        .find(|(user, _)| symbols.contains(user))
        .map(|&(user_symbol, startup_symbol)| DefaultEntry {
            user_symbol: Some(user_symbol),
            startup_symbol,
            inferred_subsystem: if windows.contains(&(user_symbol, startup_symbol)) {
                RuntimeSubsystem::Windows
            } else {
                RuntimeSubsystem::Console
            },
        })
}

/// A synthetic symbol value supplied by the PE linker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkerDefinedValue {
    /// A virtual address in the loaded image.
    VirtualAddress(u64),
    /// A relative virtual address from the image base.
    Rva(u32),
}

/// One laid-out output section, used for optional GNU/MinGW-compatible section
/// sentinels (`__start_NAME` and `__stop_NAME`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputSection<'a> {
    pub name: &'a str,
    pub start_rva: u32,
    pub size: u32,
}

/// Resolves common symbols synthesized by PE linkers.
///
/// MSVC's canonical image-base name is `__ImageBase`; `_ImageBase` is
/// accepted as a compatibility alias. Section sentinels are recognized only
/// when `NAME` matches an actual output section after removing its leading
/// dot, preventing arbitrary undefined names from becoming definitions.
#[must_use]
pub fn linker_defined_symbol(
    name: &str,
    image_base: u64,
    sections: &[OutputSection<'_>],
) -> Option<LinkerDefinedValue> {
    if matches!(name, "__ImageBase" | "_ImageBase") {
        return Some(LinkerDefinedValue::VirtualAddress(image_base));
    }
    let (prefix, wanted) = if let Some(wanted) = name.strip_prefix("__start_") {
        (Sentinel::Start, wanted)
    } else if let Some(wanted) = name.strip_prefix("__stop_") {
        (Sentinel::Stop, wanted)
    } else {
        return None;
    };
    let section = sections
        .iter()
        .find(|section| section.name.trim_start_matches('.') == wanted)?;
    let rva = match prefix {
        Sentinel::Start => section.start_rva,
        Sentinel::Stop => section.start_rva.checked_add(section.size)?,
    };
    Some(LinkerDefinedValue::Rva(rva))
}

#[derive(Clone, Copy)]
enum Sentinel {
    Start,
    Stop,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_alias_object(search_type: u32) -> Vec<u8> {
        const HEADER_SIZE: usize = 20;
        const SECTION_SIZE: usize = 40;
        const SYMBOL_SIZE: usize = 18;
        let symbol_offset = HEADER_SIZE + SECTION_SIZE;
        let mut data = vec![0; symbol_offset + SYMBOL_SIZE * 3 + 4];
        data[2..4].copy_from_slice(&1_u16.to_le_bytes());
        data[8..12].copy_from_slice(&(symbol_offset as u32).to_le_bytes());
        data[12..16].copy_from_slice(&3_u32.to_le_bytes());
        data[HEADER_SIZE..HEADER_SIZE + 8].copy_from_slice(b".debug$S");
        data[HEADER_SIZE + 36..HEADER_SIZE + 40].copy_from_slice(&0x4210_0040_u32.to_le_bytes());

        let target = symbol_offset;
        data[target..target + 6].copy_from_slice(b"target");
        data[target + 16] = pe::IMAGE_SYM_CLASS_EXTERNAL.0;

        let alias = target + SYMBOL_SIZE;
        data[alias..alias + 5].copy_from_slice(b"alias");
        data[alias + 16] = pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL.0;
        data[alias + 17] = 1;

        let auxiliary = alias + SYMBOL_SIZE;
        data[auxiliary..auxiliary + 4].copy_from_slice(&0_u32.to_le_bytes());
        data[auxiliary + 4..auxiliary + 8].copy_from_slice(&search_type.to_le_bytes());
        let string_table = auxiliary + SYMBOL_SIZE;
        data[string_table..string_table + 4].copy_from_slice(&4_u32.to_le_bytes());
        data
    }

    #[test]
    fn parses_legacy_msvc_alias_member() {
        let data = legacy_alias_object(pe::IMAGE_WEAK_EXTERN_SEARCH_ALIAS.0);
        let parsed = parse_legacy_alias_object(&data).unwrap().unwrap();
        assert_eq!(
            parsed.aliases(),
            [LegacyAlias {
                symbol: b"alias",
                target: b"target",
            }]
        );
        assert_eq!(
            parsed.directives().unwrap(),
            [RuntimeDirective::AlternateName {
                symbol: "alias".into(),
                target: "target".into(),
            }]
        );
    }

    #[test]
    fn legacy_alias_classifier_ignores_normal_objects_and_short_imports() {
        let mut normal = legacy_alias_object(pe::IMAGE_WEAK_EXTERN_SEARCH_ALIAS.0);
        normal[0..2].copy_from_slice(&pe::IMAGE_FILE_MACHINE_AMD64.0.to_le_bytes());
        assert_eq!(parse_legacy_alias_object(&normal).unwrap(), None);

        let mut import = vec![0; 20];
        import[2..4].copy_from_slice(&pe::IMPORT_OBJECT_HDR_SIG2.to_le_bytes());
        assert_eq!(parse_legacy_alias_object(&import).unwrap(), None);
    }

    #[test]
    fn rejects_unknown_machine_members_without_alias_semantics() {
        let data = legacy_alias_object(pe::IMAGE_WEAK_EXTERN_SEARCH_LIBRARY.0);
        assert_eq!(
            parse_legacy_alias_object(&data).unwrap_err().to_string(),
            "legacy Machine=UNKNOWN weak external uses search type 2, expected SEARCH_ALIAS"
        );
    }

    #[test]
    fn parses_clang_cl_runtime_directives_and_quotes() {
        let parsed = parse_runtime_directives(
            r#" /DEFAULTLIB:libcmt /alternatename:old=new /FAILIFMISMATCH:"RuntimeLibrary=MT_Static Release" /include:"forced symbol""#,
        )
        .unwrap();
        assert_eq!(
            parsed,
            [
                RuntimeDirective::AlternateName {
                    symbol: "old".into(),
                    target: "new".into(),
                },
                RuntimeDirective::FailIfMismatch {
                    key: "RuntimeLibrary".into(),
                    value: "MT_Static Release".into(),
                },
                RuntimeDirective::Include("forced symbol".into()),
            ]
        );
    }

    #[test]
    fn windows_quoting_preserves_escaped_quote_and_backslash() {
        let tokens = tokenize_windows(r#"/include:"a\"b\\c""#).unwrap();
        assert_eq!(tokens, [r#"/include:a"b\\c"#]);
    }

    #[test]
    fn malformed_relevant_directives_are_diagnosed() {
        assert_eq!(
            parse_runtime_token("/alternatename:a")
                .unwrap_err()
                .to_string(),
            "/alternatename requires a `name=value` argument"
        );
        assert_eq!(
            parse_runtime_token("/include:").unwrap_err().to_string(),
            "include symbol is empty"
        );
        assert!(parse_runtime_directives("/include:\"x").is_err());
    }

    #[test]
    fn alias_chains_stop_at_a_strong_definition() {
        let mut state = RuntimeResolution::new();
        state
            .parse_and_apply(
                "/alternatename:malloc=custom_malloc /alternatename:custom_malloc=fallback",
                "runtime.obj",
            )
            .unwrap();
        assert_eq!(
            state
                .resolve_alternate_name("malloc", |name| name == "custom_malloc")
                .unwrap(),
            "custom_malloc"
        );
        assert_eq!(
            state.resolve_alternate_name("malloc", |_| false).unwrap(),
            "fallback"
        );
    }

    #[test]
    fn alias_cycle_diagnostic_is_canonical() {
        let directives = [
            RuntimeDirective::AlternateName {
                symbol: "z".into(),
                target: "a".into(),
            },
            RuntimeDirective::AlternateName {
                symbol: "a".into(),
                target: "m".into(),
            },
            RuntimeDirective::AlternateName {
                symbol: "m".into(),
                target: "z".into(),
            },
        ];
        let mut state = RuntimeResolution::new();
        for directive in directives {
            state.apply(directive, "aliases.obj").unwrap();
        }
        assert_eq!(
            state
                .resolve_alternate_name("z", |_| false)
                .unwrap_err()
                .to_string(),
            "alternatename cycle: a -> m -> z -> a"
        );
    }

    #[test]
    fn mismatch_conflicts_are_independent_of_input_order() {
        fn conflict(first: (&str, &str), second: (&str, &str)) -> String {
            let mut state = RuntimeResolution::new();
            let directive = |value: &str| RuntimeDirective::FailIfMismatch {
                key: "RuntimeLibrary".into(),
                value: value.into(),
            };
            state.apply(directive(first.0), first.1).unwrap();
            state
                .apply(directive(second.0), second.1)
                .unwrap_err()
                .to_string()
        }
        let forward = conflict(("MD", "b.obj"), ("MT", "a.obj"));
        let reverse = conflict(("MT", "a.obj"), ("MD", "b.obj"));
        assert_eq!(forward, reverse);
    }

    #[test]
    fn mismatch_and_include_state_is_stable() {
        let mut state = RuntimeResolution::new();
        state
            .parse_and_apply(
                "/include:z /include:a /include:z /failifmismatch:RuntimeLibrary=MT",
                "one.obj",
            )
            .unwrap();
        state
            .parse_and_apply("/failifmismatch:RuntimeLibrary=MT", "two.obj")
            .unwrap();
        assert_eq!(state.include_roots().collect::<Vec<_>>(), ["a", "z"]);
        assert_eq!(state.mismatch_value("RuntimeLibrary"), Some("MT"));
    }

    #[test]
    fn chooses_console_and_windows_crt_startups() {
        let console = select_default_entry(
            DefaultEntryConfig {
                dll: false,
                subsystem: RuntimeSubsystem::Console,
            },
            ["wmain"],
        )
        .unwrap();
        assert_eq!(console.startup_symbol, "wmainCRTStartup");
        assert_eq!(console.inferred_subsystem, RuntimeSubsystem::Console);

        let windows = select_default_entry(
            DefaultEntryConfig {
                dll: false,
                subsystem: RuntimeSubsystem::Unspecified,
            },
            ["wWinMain"],
        )
        .unwrap();
        assert_eq!(windows.startup_symbol, "wWinMainCRTStartup");
        assert_eq!(windows.inferred_subsystem, RuntimeSubsystem::Windows);
    }

    #[test]
    fn startup_selection_has_stable_precedence_and_special_cases() {
        let entry = select_default_entry(
            DefaultEntryConfig {
                dll: false,
                subsystem: RuntimeSubsystem::Unspecified,
            },
            ["wWinMain", "wmain", "main", "WinMain"],
        )
        .unwrap();
        assert_eq!(entry.startup_symbol, "mainCRTStartup");

        let dll = select_default_entry(
            DefaultEntryConfig {
                dll: true,
                subsystem: RuntimeSubsystem::Windows,
            },
            std::iter::empty(),
        )
        .unwrap();
        assert_eq!(dll.startup_symbol, "_DllMainCRTStartup");

        let native = select_default_entry(
            DefaultEntryConfig {
                dll: false,
                subsystem: RuntimeSubsystem::Native,
            },
            std::iter::empty(),
        )
        .unwrap();
        assert_eq!(native.startup_symbol, "NtProcessStartup");
    }

    #[test]
    fn resolves_image_base_aliases_and_section_sentinels() {
        let sections = [OutputSection {
            name: ".CRT",
            start_rva: 0x3000,
            size: 0x98,
        }];
        assert_eq!(
            linker_defined_symbol("__ImageBase", 0x1_4000_0000, &sections),
            Some(LinkerDefinedValue::VirtualAddress(0x1_4000_0000))
        );
        assert_eq!(
            linker_defined_symbol("_ImageBase", 0x1_4000_0000, &sections),
            Some(LinkerDefinedValue::VirtualAddress(0x1_4000_0000))
        );
        assert_eq!(
            linker_defined_symbol("__start_CRT", 0, &sections),
            Some(LinkerDefinedValue::Rva(0x3000))
        );
        assert_eq!(
            linker_defined_symbol("__stop_CRT", 0, &sections),
            Some(LinkerDefinedValue::Rva(0x3098))
        );
        assert_eq!(linker_defined_symbol("__start_text", 0, &sections), None);
    }

    #[test]
    fn section_sentinel_overflow_is_not_defined() {
        let sections = [OutputSection {
            name: ".last",
            start_rva: u32::MAX,
            size: 1,
        }];
        assert_eq!(linker_defined_symbol("__stop_last", 0, &sections), None);
    }
}
