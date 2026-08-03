#![no_main]

use libfuzzer_sys::fuzz_target;
use linker_utils::coff_archives::CoffArchive;
use linker_utils::coff_imports::ImportLibrary;
use linker_utils::coff_imports::ImportLibraryMember;
use linker_utils::coff_imports::ShortImportObject;
use object::FileKind;
use object::Object as _;
use object::ObjectComdat as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;

// Keep parser fuzzing in a standalone cargo-fuzz package so normal workspace
// builds do not pull in libFuzzer. Archive member iteration is included because
// it validates lazily parsed headers and payloads beyond ImportLibrary::parse.
fn walk_coff(data: &[u8]) {
    if matches!(
        FileKind::parse(data),
        Ok(FileKind::Coff | FileKind::CoffBig)
    ) && let Ok(file) = object::File::parse(data)
    {
        for section in file.sections() {
            let _ = section.name_bytes();
            let _ = section.data();
            let _ = section.compressed_file_range();
            let _ = file.section_by_index(section.index());
            for (offset, relocation) in section.relocations() {
                let _ = (
                    offset,
                    relocation.kind(),
                    relocation.encoding(),
                    relocation.size(),
                    relocation.target(),
                    relocation.addend(),
                    relocation.has_implicit_addend(),
                    relocation.flags(),
                );
            }
        }
        for symbol in file.symbols() {
            let _ = symbol.name_bytes();
            let _ = (
                symbol.address(),
                symbol.size(),
                symbol.kind(),
                symbol.section(),
                symbol.section_index(),
                symbol.scope(),
                symbol.flags(),
            );
            let _ = file.symbol_by_index(symbol.index());
        }
        // COFF COMDAT iteration reads section-definition auxiliary records.
        for comdat in file.comdats() {
            let _ = (comdat.kind(), comdat.symbol(), comdat.name_bytes());
            for section in comdat.sections() {
                let _ = file.section_by_index(section);
            }
        }
    }
    // This linker-utils path directly traverses weak-external auxiliary records.
    let _ = linker_utils::coff_runtime::parse_weak_externals(data);
}

fuzz_target!(|data: &[u8]| {
    walk_coff(data);
    if let Ok(archive) = CoffArchive::parse(data) {
        for member in archive.members() {
            let _ = (
                member.index(),
                member.name(),
                member.kind(),
                member.opaque_error(),
            );
            for definition in member.definitions() {
                let _ = definition;
            }
            walk_coff(member.data());
        }
    }
    if let Ok(imports) = ImportLibrary::parse(data) {
        for member in imports.members() {
            match member {
                Ok(ImportLibraryMember::CoffObject(member)) => {
                    let _ = (member.name, member.is_bigobj);
                    walk_coff(member.data);
                }
                Ok(ImportLibraryMember::ShortImport { name, import }) => {
                    let _ = (
                        name,
                        import.symbol(),
                        import.dll(),
                        import.ordinal_or_hint(),
                        import.import_type(),
                        import.name_type(),
                        import.target(),
                    );
                }
                Err(_) => {}
            }
        }
    }
    if let Ok(import) = ShortImportObject::parse(data) {
        let _ = (
            import.symbol(),
            import.dll(),
            import.ordinal_or_hint(),
            import.import_type(),
            import.name_type(),
            import.target(),
        );
    }
});
