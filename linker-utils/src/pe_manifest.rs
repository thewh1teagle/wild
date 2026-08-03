//! Construction of embedded Windows application manifests.
//!
//! The PE resource writer owns the binary resource tree. This module owns only
//! the linker-facing manifest XML and turns it into one `RT_MANIFEST` record,
//! so command-line parsing and PE layout can remain independent.

use crate::pe_resources::ResourceId;
use crate::pe_resources::ResourceRecord;
use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;

/// Win32 `RT_MANIFEST` resource type.
pub const RT_MANIFEST: u16 = 24;
/// Default manifest resource ID for an executable.
pub const EXE_MANIFEST_ID: u16 = 1;
/// Default manifest resource ID for a DLL.
pub const DLL_MANIFEST_ID: u16 = 2;
/// Neutral language used by link.exe's embedded manifests.
pub const MANIFEST_LANGUAGE_NEUTRAL: u16 = 0;

/// The requested execution level included in a generated application manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionLevel {
    AsInvoker,
    HighestAvailable,
    RequireAdministrator,
}

impl ExecutionLevel {
    fn xml(self) -> &'static str {
        match self {
            Self::AsInvoker => "asInvoker",
            Self::HighestAvailable => "highestAvailable",
            Self::RequireAdministrator => "requireAdministrator",
        }
    }
}

/// Linker-generated content merged into an application manifest. Dependency
/// strings use link.exe's `/MANIFESTDEPENDENCY` attribute-list syntax.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GeneratedManifest<'a> {
    pub dependencies: &'a [&'a str],
    pub execution_level: Option<ExecutionLevel>,
    pub ui_access: bool,
}

/// Returns the default resource ID for an executable or DLL.
#[must_use]
pub const fn default_manifest_id(is_dll: bool) -> u16 {
    if is_dll {
        DLL_MANIFEST_ID
    } else {
        EXE_MANIFEST_ID
    }
}

/// Wraps an explicit manifest payload in its canonical PE resource record.
pub fn manifest_resource(id: u16, language: u16, data: Vec<u8>) -> Result<ResourceRecord> {
    ensure!(id != 0, "manifest resource ID must not be zero");
    ensure!(!data.is_empty(), "embedded manifest is empty");
    Ok(ResourceRecord {
        resource_type: ResourceId::Id(RT_MANIFEST),
        name: ResourceId::Id(id),
        language,
        data_version: 0,
        memory_flags: 0,
        version: 0,
        characteristics: 0,
        data,
    })
}

/// Generates the compact UTF-8 application manifest used when no explicit
/// manifest input file was supplied.
#[must_use]
pub fn generate_manifest(options: &GeneratedManifest<'_>) -> Vec<u8> {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n");
    xml.push_str(
        "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n",
    );
    append_generated_elements(&mut xml, options);
    xml.push_str("</assembly>\r\n");
    xml.into_bytes()
}

/// Merges `/MANIFESTINPUT` documents and linker-generated dependency/UAC
/// elements into one UTF-8 application manifest.
///
/// The Windows manifest tool performs schema-aware merging. The linker only
/// needs the deterministic subset used by native build systems: preserve the
/// first assembly as the base and append top-level children from later input
/// assemblies in command-line order.
pub fn merge_manifest_documents(
    documents: &[&[u8]],
    options: &GeneratedManifest<'_>,
) -> Result<Vec<u8>> {
    ensure!(!documents.is_empty(), "no manifest input documents");
    let mut decoded = documents
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            decode_manifest(bytes).with_context(|| format!("invalid manifest input #{}", index + 1))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut base = decoded.remove(0);
    let (base_namespace, _) = assembly_root_namespaces(&base)?;
    let base_namespace = base_namespace.map(str::to_owned);
    let (_, mut close) = assembly_content_bounds(&base)?;
    let mut insertion = String::new();
    for document in decoded {
        let (namespace, has_prefixed_declarations) = assembly_root_namespaces(&document)?;
        ensure!(
            !has_prefixed_declarations,
            "secondary manifest declares a namespace prefix on its assembly root; declare it on the child element instead"
        );
        ensure!(
            namespace == base_namespace.as_deref(),
            "manifest input assembly roots use different default namespaces"
        );
        let (start, end) = assembly_content_bounds(&document)?;
        let content = document[start..end].trim();
        if !content.is_empty() {
            insertion.push_str(content);
            insertion.push_str("\r\n");
        }
    }
    append_generated_elements(&mut insertion, options);
    base.insert_str(close, &insertion);
    close += insertion.len();
    debug_assert!(
        base[close..]
            .to_ascii_lowercase()
            .starts_with("</assembly>")
    );
    Ok(base.into_bytes())
}

fn append_generated_elements(xml: &mut String, options: &GeneratedManifest<'_>) {
    for dependency in options.dependencies {
        xml.push_str("<dependency><dependentAssembly><assemblyIdentity ");
        xml.push_str(dependency);
        xml.push_str("/></dependentAssembly></dependency>\r\n");
    }
    if let Some(level) = options.execution_level {
        xml.push_str("<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"");
        xml.push_str(level.xml());
        xml.push_str("\" uiAccess=\"");
        xml.push_str(if options.ui_access { "true" } else { "false" });
        xml.push_str("\"/></requestedPrivileges></security></trustInfo>\r\n");
    }
}

fn decode_manifest(bytes: &[u8]) -> Result<String> {
    ensure!(!bytes.is_empty(), "manifest input is empty");
    if let Some(payload) = bytes.strip_prefix(&[0xff, 0xfe]) {
        ensure!(
            payload.len().is_multiple_of(2),
            "odd-length UTF-16LE manifest"
        );
        let words = payload
            .chunks_exact(2)
            .map(|word| u16::from_le_bytes([word[0], word[1]]));
        return String::from_utf16(&words.collect::<Vec<_>>()).context("invalid UTF-16LE manifest");
    }
    if let Some(payload) = bytes.strip_prefix(&[0xfe, 0xff]) {
        ensure!(
            payload.len().is_multiple_of(2),
            "odd-length UTF-16BE manifest"
        );
        let words = payload
            .chunks_exact(2)
            .map(|word| u16::from_be_bytes([word[0], word[1]]));
        return String::from_utf16(&words.collect::<Vec<_>>()).context("invalid UTF-16BE manifest");
    }
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    std::str::from_utf8(bytes)
        .context("manifest is neither UTF-8 nor BOM-marked UTF-16")
        .map(str::to_owned)
}

fn assembly_content_bounds(xml: &str) -> Result<(usize, usize)> {
    let lower = xml.to_ascii_lowercase();
    let mut search_from = 0;
    let opening_end = loop {
        let relative = lower[search_from..]
            .find("<assembly")
            .context("manifest has no assembly root element")?;
        let opening = search_from + relative;
        let after_name = opening + "<assembly".len();
        if lower
            .as_bytes()
            .get(after_name)
            .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b'>')
        {
            break lower[after_name..]
                .find('>')
                .map(|relative| after_name + relative + 1)
                .context("unterminated assembly root element")?;
        }
        search_from = after_name;
    };
    let closing = lower
        .rfind("</assembly>")
        .context("manifest has no closing assembly root element")?;
    ensure!(opening_end <= closing, "malformed manifest assembly root");
    Ok((opening_end, closing))
}

fn assembly_root_namespaces(xml: &str) -> Result<(Option<&str>, bool)> {
    let (content_start, _) = assembly_content_bounds(xml)?;
    let lower = xml[..content_start].to_ascii_lowercase();
    let opening = lower
        .rfind("<assembly")
        .context("manifest has no assembly root element")?;
    let tag = &xml[opening + "<assembly".len()..content_start - 1];
    let mut default_namespace = None;
    let mut has_prefixed_declarations = false;
    let bytes = tag.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        while at < bytes.len() && bytes[at].is_ascii_whitespace() {
            at += 1;
            if at == bytes.len() {
                return Ok((default_namespace, has_prefixed_declarations));
            }
        }
        let name_start = at;
        while at < bytes.len()
            && !bytes[at].is_ascii_whitespace()
            && bytes[at] != b'='
            && bytes[at] != b'/'
        {
            at += 1;
        }
        let name = &tag[name_start..at];
        while at < bytes.len() && bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        ensure!(
            at < bytes.len() && bytes[at] == b'=',
            "malformed assembly root attribute `{name}`"
        );
        at += 1;
        while at < bytes.len() && bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        ensure!(
            at < bytes.len(),
            "missing value for assembly root attribute `{name}`"
        );
        let quote = bytes[at];
        ensure!(
            quote == b'\'' || quote == b'"',
            "unquoted assembly root attribute `{name}`"
        );
        at += 1;
        let value_start = at;
        while at < bytes.len() && bytes[at] != quote {
            at += 1;
        }
        ensure!(
            at < bytes.len(),
            "unterminated assembly root attribute `{name}`"
        );
        let value = &tag[value_start..at];
        at += 1;
        if name.eq_ignore_ascii_case("xmlns") {
            ensure!(
                default_namespace.is_none(),
                "duplicate default namespace on assembly root"
            );
            default_namespace = Some(value);
        } else if name
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("xmlns:"))
        {
            has_prefixed_declarations = true;
        }
    }
    Ok((default_namespace, has_prefixed_declarations))
}

/// Builds the standard neutral `RT_MANIFEST` record from generated inputs.
pub fn generated_manifest_resource(
    id: u16,
    options: &GeneratedManifest<'_>,
) -> Result<ResourceRecord> {
    manifest_resource(id, MANIFEST_LANGUAGE_NEUTRAL, generate_manifest(options))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe_resources::build_resource_section;

    #[test]
    fn generated_manifest_uses_the_executable_resource_identity() {
        let record =
            generated_manifest_resource(EXE_MANIFEST_ID, &GeneratedManifest::default()).unwrap();
        assert_eq!(record.resource_type, ResourceId::Id(RT_MANIFEST));
        assert_eq!(record.name, ResourceId::Id(EXE_MANIFEST_ID));
        assert_eq!(record.language, MANIFEST_LANGUAGE_NEUTRAL);
        assert!(
            std::str::from_utf8(&record.data)
                .unwrap()
                .contains("urn:schemas-microsoft-com:asm.v1")
        );
        assert!(build_resource_section(&[record], 0x1000).is_ok());
    }

    #[test]
    fn generated_manifest_preserves_dependencies_and_uac() {
        let dependencies =
            ["type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0'"];
        let data = generate_manifest(&GeneratedManifest {
            dependencies: &dependencies,
            execution_level: Some(ExecutionLevel::RequireAdministrator),
            ui_access: true,
        });
        let xml = std::str::from_utf8(&data).unwrap();
        assert!(xml.contains("Microsoft.Windows.Common-Controls"));
        assert!(xml.contains("level=\"requireAdministrator\" uiAccess=\"true\""));
    }

    #[test]
    fn merges_multiple_utf8_and_utf16_manifest_inputs() {
        let first = br#"<?xml version="1.0"?><assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><assemblyIdentity name="app" version="1.0.0.0" type="win32"/></assembly>"#;
        let second_text = r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><description>merged</description></assembly>"#;
        let mut second = vec![0xff, 0xfe];
        second.extend(second_text.encode_utf16().flat_map(u16::to_le_bytes));
        let dependencies = ["type='win32' name='Common.Controls' version='6.0.0.0'"];

        let merged = merge_manifest_documents(
            &[first, &second],
            &GeneratedManifest {
                dependencies: &dependencies,
                execution_level: Some(ExecutionLevel::AsInvoker),
                ui_access: false,
            },
        )
        .unwrap();
        let xml = std::str::from_utf8(&merged).unwrap();
        assert!(xml.contains("<description>merged</description>"));
        assert!(xml.contains("<assemblyIdentity type='win32' name='Common.Controls'"));
        assert!(xml.contains("level=\"asInvoker\""));
        assert_eq!(xml.matches("</assembly>").count(), 1);
    }

    #[test]
    fn rejects_secondary_root_namespaces_that_cannot_be_preserved() {
        let base = br#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"></assembly>"#;
        let different = br#"<assembly xmlns="urn:example:different" manifestVersion="1.0"><description>unsafe</description></assembly>"#;
        let prefixed = br#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" xmlns:v3="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0"><v3:trustInfo/></assembly>"#;

        let different_error =
            merge_manifest_documents(&[base, different], &GeneratedManifest::default())
                .unwrap_err()
                .to_string();
        assert!(different_error.contains("different default namespaces"));

        let prefixed_error =
            merge_manifest_documents(&[base, prefixed], &GeneratedManifest::default())
                .unwrap_err()
                .to_string();
        assert!(prefixed_error.contains("namespace prefix"));
    }

    #[test]
    fn explicit_payload_and_dll_id_are_preserved() {
        let record = manifest_resource(DLL_MANIFEST_ID, 0x409, b"<assembly/>".to_vec()).unwrap();
        assert_eq!(record.name, ResourceId::Id(DLL_MANIFEST_ID));
        assert_eq!(record.language, 0x409);
        assert_eq!(record.data, b"<assembly/>");
        assert_eq!(default_manifest_id(false), EXE_MANIFEST_ID);
        assert_eq!(default_manifest_id(true), DLL_MANIFEST_ID);
    }
}
