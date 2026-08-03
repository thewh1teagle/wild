//! Parser for Microsoft module-definition files and `/EXPORT:` arguments.
//!
//! This module is deliberately independent of linker state. It preserves the
//! spelling and source location needed for diagnostics while normalizing both
//! input syntaxes into the same deterministic export representation.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

/// A one-based location in an input file or command-line value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceLocation {
    pub line: usize,
    pub column: usize,
    pub offset: usize,
}

impl SourceLocation {
    const fn command_line() -> Self {
        Self {
            line: 1,
            column: 1,
            offset: 0,
        }
    }
}

/// A parse or validation error with a stable source location.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefError {
    pub location: SourceLocation,
    pub message: String,
}

impl DefError {
    fn new(location: SourceLocation, message: impl Into<String>) -> Self {
        Self {
            location,
            message: message.into(),
        }
    }
}

impl fmt::Display for DefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}: {}",
            self.location.line, self.location.column, self.message
        )
    }
}

impl Error for DefError {}

pub type Result<T> = std::result::Result<T, DefError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageKind {
    Library,
    Program,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageName {
    pub kind: ImageKind,
    pub name: Option<String>,
    pub base: Option<u64>,
    pub location: SourceLocation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SizeSpec {
    pub reserve: u64,
    pub commit: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionSpec {
    pub major: u16,
    pub minor: u16,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExportFlags {
    pub noname: bool,
    pub data: bool,
    pub private: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportOrigin {
    DefinitionFile,
    CommandLine,
}

/// A normalized export. `target` is an internal symbol or a forwarder string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportSpec {
    pub name: String,
    pub target: Option<String>,
    pub ordinal: Option<u16>,
    pub flags: ExportFlags,
    pub location: SourceLocation,
    pub origin: ExportOrigin,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SectionFlags {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub shared: bool,
    pub discardable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SectionSpec {
    pub name: String,
    pub flags: SectionFlags,
    pub location: SourceLocation,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DefinitionFile {
    pub image: Option<ImageName>,
    pub exports: Vec<ExportSpec>,
    pub heap_size: Option<SizeSpec>,
    pub stack_size: Option<SizeSpec>,
    pub version: Option<VersionSpec>,
    pub sections: Vec<SectionSpec>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Block {
    None,
    Exports,
    Sections,
}

/// Parses a complete Microsoft module-definition file.
pub fn parse_definition_file(input: &str) -> Result<DefinitionFile> {
    let (input, mut offset) = input
        .strip_prefix('\u{feff}')
        .map_or((input, 0), |input| (input, '\u{feff}'.len_utf8()));
    let mut output = DefinitionFile::default();
    let mut block = Block::None;

    for (line_index, raw_line) in input.split_inclusive('\n').enumerate() {
        let line = raw_line.strip_suffix('\n').unwrap_or(raw_line);
        let line = line.strip_suffix('\r').unwrap_or(line);
        let uncommented = strip_comment(line);
        let leading = uncommented.len() - uncommented.trim_start().len();
        let text = uncommented.trim();
        let location = SourceLocation {
            line: line_index + 1,
            column: leading + 1,
            offset: offset + leading,
        };
        offset += raw_line.len();
        if text.is_empty() {
            continue;
        }

        let (word, rest) = take_word(text, location)?;
        let directive = word.value.to_ascii_uppercase();
        if !word.quoted && is_directive(&directive) {
            block = Block::None;
            parse_directive(&mut output, &directive, rest.trim(), location, &mut block)?;
        } else {
            match block {
                Block::Exports => {
                    output.exports.push(parse_export(
                        text,
                        location,
                        ExportOrigin::DefinitionFile,
                    )?);
                }
                Block::Sections => output.sections.push(parse_section(text, location)?),
                Block::None => {
                    return Err(DefError::new(
                        location,
                        format!("unknown module-definition directive `{}`", word.value),
                    ));
                }
            }
        }
    }

    validate_exports(&output.exports)?;
    validate_sections(&output.sections)?;
    Ok(output)
}

/// Parses the value following a link.exe-compatible `/EXPORT:` option.
pub fn parse_export_argument(value: &str) -> Result<ExportSpec> {
    let location = SourceLocation::command_line();
    let value = value.trim();
    if value.is_empty() {
        return Err(DefError::new(location, "empty /EXPORT value"));
    }
    parse_export(value, location, ExportOrigin::CommandLine)
}

/// Validates exports collected from multiple `.def` files and command-line
/// options. Call this after concatenating all sources.
pub fn validate_exports(exports: &[ExportSpec]) -> Result<()> {
    let mut names = BTreeMap::<&str, SourceLocation>::new();
    let mut ordinals = BTreeMap::<u16, SourceLocation>::new();
    for export in exports {
        if export.name.is_empty() {
            return Err(DefError::new(export.location, "export name is empty"));
        }
        if export.name.as_bytes().contains(&0) {
            return Err(DefError::new(
                export.location,
                "export name contains a NUL byte",
            ));
        }
        if let Some(previous) = names.insert(&export.name, export.location) {
            return Err(DefError::new(
                export.location,
                format!(
                    "duplicate export `{}` (first declared at {}:{})",
                    export.name, previous.line, previous.column
                ),
            ));
        }
        if export.flags.noname && export.ordinal.is_none() {
            return Err(DefError::new(
                export.location,
                format!("export `{}` uses NONAME without an ordinal", export.name),
            ));
        }
        if let Some(ordinal) = export.ordinal {
            if ordinal == 0 {
                return Err(DefError::new(
                    export.location,
                    format!("export `{}` uses reserved ordinal zero", export.name),
                ));
            }
            if let Some(previous) = ordinals.insert(ordinal, export.location) {
                return Err(DefError::new(
                    export.location,
                    format!(
                        "duplicate export ordinal {ordinal} (first declared at {}:{})",
                        previous.line, previous.column
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn parse_directive(
    output: &mut DefinitionFile,
    directive: &str,
    rest: &str,
    location: SourceLocation,
    block: &mut Block,
) -> Result<()> {
    match directive {
        "LIBRARY" | "NAME" => {
            if output.image.is_some() {
                return Err(DefError::new(
                    location,
                    "multiple LIBRARY/NAME directives are not allowed",
                ));
            }
            let mut name = None;
            let mut base = None;
            for token in words(rest, location)? {
                let token = token.value;
                if token
                    .get(..5)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("BASE="))
                {
                    if base.is_some() {
                        return Err(DefError::new(location, "multiple image base addresses"));
                    }
                    base = Some(parse_integer(
                        token.get(5..).expect("ASCII prefix"),
                        location,
                    )?);
                } else if name.is_none() {
                    name = Some(token);
                } else {
                    return Err(DefError::new(location, "unexpected text after image name"));
                }
            }
            output.image = Some(ImageName {
                kind: if directive == "LIBRARY" {
                    ImageKind::Library
                } else {
                    ImageKind::Program
                },
                name,
                base,
                location,
            });
        }
        "EXPORTS" => {
            *block = Block::Exports;
            if !rest.is_empty() {
                output
                    .exports
                    .push(parse_export(rest, location, ExportOrigin::DefinitionFile)?);
            }
        }
        "HEAPSIZE" => set_once_size(&mut output.heap_size, rest, location, "HEAPSIZE")?,
        "STACKSIZE" => set_once_size(&mut output.stack_size, rest, location, "STACKSIZE")?,
        "VERSION" => {
            if output.version.is_some() {
                return Err(DefError::new(location, "duplicate VERSION directive"));
            }
            output.version = Some(parse_version(rest, location)?);
        }
        "SECTIONS" | "SEGMENTS" => {
            *block = Block::Sections;
            if !rest.is_empty() {
                output.sections.push(parse_section(rest, location)?);
            }
        }
        _ => unreachable!("known directive"),
    }
    Ok(())
}

fn set_once_size(
    slot: &mut Option<SizeSpec>,
    rest: &str,
    location: SourceLocation,
    directive: &str,
) -> Result<()> {
    if slot.is_some() {
        return Err(DefError::new(
            location,
            format!("duplicate {directive} directive"),
        ));
    }
    *slot = Some(parse_size(rest, location)?);
    Ok(())
}

fn parse_size(text: &str, location: SourceLocation) -> Result<SizeSpec> {
    let fields = split_delimited(text, ',', location)?;
    if fields.is_empty() || fields.len() > 2 || fields[0].is_empty() {
        return Err(DefError::new(location, "expected reserve[,commit]"));
    }
    Ok(SizeSpec {
        reserve: parse_integer(&fields[0], location)?,
        commit: fields
            .get(1)
            .filter(|value| !value.is_empty())
            .map(|value| parse_integer(value, location))
            .transpose()?,
    })
}

fn parse_version(text: &str, location: SourceLocation) -> Result<VersionSpec> {
    let (major, minor) = text.split_once('.').unwrap_or((text, "0"));
    let major = parse_integer(major.trim(), location)?;
    let minor = parse_integer(minor.trim(), location)?;
    Ok(VersionSpec {
        major: u16::try_from(major)
            .map_err(|_| DefError::new(location, "VERSION major is too large"))?,
        minor: u16::try_from(minor)
            .map_err(|_| DefError::new(location, "VERSION minor is too large"))?,
    })
}

fn parse_integer(text: &str, location: SourceLocation) -> Result<u64> {
    if text.is_empty() {
        return Err(DefError::new(location, "missing integer"));
    }
    let result = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        text.parse()
    };
    result.map_err(|_| DefError::new(location, format!("invalid integer `{text}`")))
}

fn parse_export(text: &str, location: SourceLocation, origin: ExportOrigin) -> Result<ExportSpec> {
    let fields = split_delimited(text, ',', location)?;
    let head = fields
        .first()
        .ok_or_else(|| DefError::new(location, "missing export name"))?;
    let head_words = words(head, location)?;
    if head_words.is_empty() {
        return Err(DefError::new(location, "missing export name"));
    }

    let mut core = String::new();
    let mut tail = Vec::new();
    for word in head_words {
        if !word.quoted && (is_export_attribute(&word.value) || word.value.starts_with('@')) {
            tail.push(word.value);
        } else if tail.is_empty() {
            core.push_str(&word.value);
        } else {
            return Err(DefError::new(
                location,
                format!("unexpected export token `{}`", word.value),
            ));
        }
    }
    let (name, target) = split_alias(&core, location)?;
    let mut ordinal = None;
    let mut flags = ExportFlags::default();
    for item in fields.iter().skip(1).chain(tail.iter()) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        if let Some(value) = item.strip_prefix('@') {
            if ordinal.is_some() {
                return Err(DefError::new(location, "multiple export ordinals"));
            }
            let value = parse_integer(value, location)?;
            ordinal = Some(u16::try_from(value).map_err(|_| {
                DefError::new(location, format!("export ordinal {value} is too large"))
            })?);
            continue;
        }
        match item.to_ascii_uppercase().as_str() {
            "NONAME" if !flags.noname => flags.noname = true,
            "DATA" if !flags.data => flags.data = true,
            "PRIVATE" if !flags.private => flags.private = true,
            "NONAME" | "DATA" | "PRIVATE" => {
                return Err(DefError::new(
                    location,
                    format!("duplicate export attribute `{item}`"),
                ));
            }
            _ => {
                return Err(DefError::new(
                    location,
                    format!("unknown export attribute `{item}`"),
                ));
            }
        }
    }
    let export = ExportSpec {
        name,
        target,
        ordinal,
        flags,
        location,
        origin,
    };
    validate_exports(std::slice::from_ref(&export))?;
    Ok(export)
}

fn split_alias(text: &str, location: SourceLocation) -> Result<(String, Option<String>)> {
    let mut parts = text.splitn(3, '=');
    let name = parts.next().unwrap_or_default().trim();
    let target = parts.next().map(str::trim);
    if parts.next().is_some() {
        return Err(DefError::new(
            location,
            "export contains multiple `=` signs",
        ));
    }
    if name.is_empty() {
        return Err(DefError::new(location, "missing export name"));
    }
    if target == Some("") {
        return Err(DefError::new(location, "missing export target after `=`"));
    }
    Ok((name.to_owned(), target.map(str::to_owned)))
}

fn parse_section(text: &str, location: SourceLocation) -> Result<SectionSpec> {
    let tokens = words(text, location)?;
    let (name, attributes) = tokens
        .split_first()
        .ok_or_else(|| DefError::new(location, "missing section name"))?;
    let mut flags = SectionFlags::default();
    for attribute in attributes {
        for attribute in attribute.value.split(',').filter(|item| !item.is_empty()) {
            match attribute.to_ascii_uppercase().as_str() {
                "READ" if !flags.read => flags.read = true,
                "WRITE" if !flags.write => flags.write = true,
                "EXECUTE" if !flags.execute => flags.execute = true,
                "SHARED" if !flags.shared => flags.shared = true,
                "DISCARDABLE" if !flags.discardable => flags.discardable = true,
                "READ" | "WRITE" | "EXECUTE" | "SHARED" | "DISCARDABLE" => {
                    return Err(DefError::new(
                        location,
                        format!("duplicate section attribute `{attribute}`"),
                    ));
                }
                _ => {
                    return Err(DefError::new(
                        location,
                        format!("unknown section attribute `{attribute}`"),
                    ));
                }
            }
        }
    }
    Ok(SectionSpec {
        name: name.value.clone(),
        flags,
        location,
    })
}

fn validate_sections(sections: &[SectionSpec]) -> Result<()> {
    let mut names = BTreeSet::new();
    for section in sections {
        if !names.insert(&section.name) {
            return Err(DefError::new(
                section.location,
                format!("duplicate section declaration `{}`", section.name),
            ));
        }
    }
    Ok(())
}

fn is_directive(word: &str) -> bool {
    matches!(
        word,
        "LIBRARY"
            | "NAME"
            | "EXPORTS"
            | "HEAPSIZE"
            | "STACKSIZE"
            | "VERSION"
            | "SECTIONS"
            | "SEGMENTS"
    )
}

fn is_export_attribute(word: &str) -> bool {
    matches!(
        word.to_ascii_uppercase().as_str(),
        "NONAME" | "DATA" | "PRIVATE"
    )
}

fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    for (index, character) in line.char_indices() {
        if character == '"' {
            quoted = !quoted;
        } else if character == ';' && !quoted {
            return &line[..index];
        }
    }
    line
}

fn take_word(text: &str, location: SourceLocation) -> Result<(Word, &str)> {
    let mut tokens = words_with_ends(text, location)?;
    if tokens.is_empty() {
        return Err(DefError::new(location, "missing token"));
    }
    let word = tokens.remove(0);
    let end = word.end;
    Ok((word, &text[end..]))
}

fn words(text: &str, location: SourceLocation) -> Result<Vec<Word>> {
    words_with_ends(text, location)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Word {
    value: String,
    end: usize,
    quoted: bool,
}

fn words_with_ends(text: &str, location: SourceLocation) -> Result<Vec<Word>> {
    let mut output = Vec::new();
    let mut value = String::new();
    let mut quoted = false;
    let mut contains_quotes = false;
    let mut active = false;
    for (index, character) in text.char_indices() {
        if character == '"' {
            quoted = !quoted;
            contains_quotes = true;
            active = true;
        } else if character.is_whitespace() && !quoted {
            if active {
                output.push(Word {
                    value: std::mem::take(&mut value),
                    end: index,
                    quoted: contains_quotes,
                });
                active = false;
                contains_quotes = false;
            }
        } else {
            value.push(character);
            active = true;
        }
    }
    if quoted {
        return Err(DefError::new(location, "unterminated quoted identifier"));
    }
    if active {
        output.push(Word {
            value,
            end: text.len(),
            quoted: contains_quotes,
        });
    }
    Ok(output)
}

fn split_delimited(text: &str, delimiter: char, location: SourceLocation) -> Result<Vec<String>> {
    let mut output = Vec::new();
    let mut value = String::new();
    let mut quoted = false;
    for character in text.chars() {
        if character == '"' {
            quoted = !quoted;
            value.push(character);
        } else if character == delimiter && !quoted {
            output.push(value.trim().to_owned());
            value.clear();
        } else {
            value.push(character);
        }
    }
    if quoted {
        return Err(DefError::new(location, "unterminated quoted identifier"));
    }
    output.push(value.trim().to_owned());
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_complete_definition_file() {
        let parsed = parse_definition_file(
            r#"; generated exports
LIBRARY "my library.dll" BASE=0x180000000
VERSION 12.34
HEAPSIZE 0x100000,0x1000
STACKSIZE 2097152,8192
EXPORTS
    ordinary=internal @7 NONAME DATA PRIVATE
    "name with spaces"="other.dll.forwarded" @9
    ?Method@Class@@QEAAHXZ
SECTIONS
    ".shared data" READ,WRITE SHARED
    .text READ EXECUTE
"#,
        )
        .unwrap();

        assert_eq!(
            parsed.image.as_ref().unwrap().name.as_deref(),
            Some("my library.dll")
        );
        assert_eq!(parsed.image.as_ref().unwrap().base, Some(0x1_8000_0000));
        assert_eq!(
            parsed.version,
            Some(VersionSpec {
                major: 12,
                minor: 34
            })
        );
        assert_eq!(parsed.heap_size.unwrap().reserve, 0x10_0000);
        assert_eq!(parsed.exports.len(), 3);
        assert_eq!(parsed.exports[0].target.as_deref(), Some("internal"));
        assert_eq!(parsed.exports[0].ordinal, Some(7));
        assert!(parsed.exports[0].flags.noname);
        assert_eq!(parsed.exports[1].name, "name with spaces");
        assert_eq!(
            parsed.exports[1].target.as_deref(),
            Some("other.dll.forwarded")
        );
        assert_eq!(parsed.exports[2].name, "?Method@Class@@QEAAHXZ");
        assert_eq!(parsed.sections[0].name, ".shared data");
        assert!(parsed.sections[0].flags.shared);
    }

    #[test]
    fn parses_link_export_spellings() {
        let decorated = parse_export_argument("?f@C@@QEAAHXZ,@42,NONAME,DATA,PRIVATE").unwrap();
        assert_eq!(decorated.name, "?f@C@@QEAAHXZ");
        assert_eq!(decorated.ordinal, Some(42));
        assert_eq!(
            decorated.flags,
            ExportFlags {
                noname: true,
                data: true,
                private: true
            }
        );

        let forwarded = parse_export_argument("Alias=KERNEL32.Sleep,@3").unwrap();
        assert_eq!(forwarded.name, "Alias");
        assert_eq!(forwarded.target.as_deref(), Some("KERNEL32.Sleep"));

        let quoted = parse_export_argument(r#""public name"="internal name",DATA"#).unwrap();
        assert_eq!(quoted.name, "public name");
        assert_eq!(quoted.target.as_deref(), Some("internal name"));
    }

    #[test]
    fn comments_do_not_affect_quoted_identifiers() {
        let parsed =
            parse_definition_file("LIBRARY x\nEXPORTS\n \"semi;colon\" ; real comment\n").unwrap();
        assert_eq!(parsed.exports[0].name, "semi;colon");
    }

    #[test]
    fn reports_duplicate_names_and_ordinals_at_second_location() {
        let error = parse_definition_file("EXPORTS\n first @1\n first @2\n").unwrap_err();
        assert_eq!(error.location.line, 3);
        assert!(error.to_string().contains("first declared at 2:2"));

        let error = parse_definition_file("EXPORTS\n first @1\n second @1\n").unwrap_err();
        assert_eq!(error.location.line, 3);
        assert!(error.message.contains("ordinal 1"));
    }

    #[test]
    fn validates_conflicting_directives_and_attributes() {
        assert!(parse_definition_file("NAME one\nLIBRARY two\n").is_err());
        assert!(parse_definition_file("EXPORTS\n foo NONAME\n").is_err());
        assert!(parse_definition_file("EXPORTS\n foo @0\n").is_err());
        assert!(parse_export_argument("foo,@1,@2").is_err());
        assert!(parse_export_argument("foo,DATA,DATA").is_err());
        assert!(parse_definition_file("SECTIONS\n.text READ READ\n").is_err());
    }

    #[test]
    fn merged_sources_can_be_validated() {
        let mut exports = parse_definition_file("EXPORTS\n foo @1\n").unwrap().exports;
        exports.push(parse_export_argument("bar,@1").unwrap());
        let error = validate_exports(&exports).unwrap_err();
        assert!(error.message.contains("duplicate export ordinal 1"));
        assert_eq!(error.location, SourceLocation::command_line());

        let aliases =
            parse_definition_file("EXPORTS\n foo=target @1\n bar=target @1\n").unwrap_err();
        assert!(aliases.message.contains("duplicate export ordinal 1"));
    }

    #[test]
    fn parses_inline_blocks_and_hex_sizes() {
        let parsed = parse_definition_file(
            "NAME app.exe\nEXPORTS one\nSECTIONS .rdata READ\nVERSION 2\nHEAPSIZE 0X20\n",
        )
        .unwrap();
        assert_eq!(parsed.exports[0].name, "one");
        assert_eq!(parsed.version, Some(VersionSpec { major: 2, minor: 0 }));
        assert_eq!(parsed.heap_size.unwrap().reserve, 32);
    }

    #[test]
    fn quoted_keywords_and_ordinal_like_names_remain_identifiers() {
        let parsed = parse_definition_file(
            "EXPORTS\n  \"DATA\"\n  \"EXPORTS\"\n  \"NONAME\"\n  \"PRIVATE\"\n  \"@named\"\n",
        )
        .unwrap();
        assert_eq!(
            parsed
                .exports
                .iter()
                .map(|export| export.name.as_str())
                .collect::<Vec<_>>(),
            ["DATA", "EXPORTS", "NONAME", "PRIVATE", "@named"]
        );
    }

    #[test]
    fn quoted_backslashes_are_literal_and_utf8_bom_is_accepted() {
        let parsed = parse_definition_file(
            "\u{feff}LIBRARY \"C:\\build\\example.dll\"\nEXPORTS\n  public=\"C:\\symbols\\target\" DATA\n",
        )
        .unwrap();
        assert_eq!(
            parsed.image.as_ref().unwrap().name.as_deref(),
            Some("C:\\build\\example.dll")
        );
        assert_eq!(
            parsed.exports[0].target.as_deref(),
            Some("C:\\symbols\\target")
        );
    }

    #[test]
    fn parses_rustc_proc_macro_definition_file() {
        let parsed = parse_definition_file(
            "LIBRARY\nEXPORTS\n  __rustc_proc_macro_decls_42a2b693c51fe47a__ DATA\n  rust_metadata_example_42a2b693c51fe47a DATA\n",
        )
        .unwrap();
        assert_eq!(parsed.image.as_ref().unwrap().name, None);
        assert_eq!(parsed.exports.len(), 2);
        assert!(parsed.exports.iter().all(|export| export.flags.data));
        assert_eq!(
            parsed.exports[0].name,
            "__rustc_proc_macro_decls_42a2b693c51fe47a__"
        );
        assert_eq!(
            parsed.exports[1].name,
            "rust_metadata_example_42a2b693c51fe47a"
        );
    }
}
