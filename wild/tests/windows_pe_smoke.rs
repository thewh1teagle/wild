//! Small, freestanding PE/COFF programs used to compare Wild with `lld-link`.
//!
//! Windows CI executes every reference image. Setting `WILD_PE_LINKER` runs
//! the exact same objects and assertions through a candidate Wild linker.

#[cfg(any(windows, target_os = "macos"))]
mod corpus {
    use std::ffi::OsStr;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    #[cfg_attr(not(windows), allow(dead_code))]
    struct Case {
        name: &'static str,
        sources: &'static [&'static str],
        exit_code: i32,
        kernel32: bool,
        #[cfg_attr(windows, allow(dead_code))]
        object_relocations: &'static [&'static str],
    }

    const CASES: &[Case] = &[
        Case {
            name: "exit_process",
            sources: &["minimal_exit_code.c"],
            exit_code: 37,
            kernel32: true,
            object_relocations: &["IMAGE_REL_AMD64_REL32", "IMAGE_REL_AMD64_ADDR32NB"],
        },
        Case {
            name: "entry_return",
            sources: &["entry_return.s"],
            exit_code: 41,
            kernel32: false,
            object_relocations: &[],
        },
        Case {
            name: "rel32_cross_object",
            sources: &["rel32_caller.c", "rel32_target.c"],
            exit_code: 43,
            kernel32: false,
            object_relocations: &["IMAGE_REL_AMD64_REL32"],
        },
        Case {
            name: "rip_relative_data",
            sources: &["rip_relative_data.c"],
            exit_code: 47,
            kernel32: false,
            object_relocations: &["IMAGE_REL_AMD64_REL32"],
        },
        Case {
            name: "bss_external",
            sources: &["bss_entry.c", "bss_storage.c"],
            exit_code: 53,
            kernel32: false,
            object_relocations: &["IMAGE_REL_AMD64_REL32"],
        },
        Case {
            name: "absolute_pointer",
            sources: &["absolute_pointer.c"],
            exit_code: 59,
            kernel32: false,
            object_relocations: &["IMAGE_REL_AMD64_ADDR64", "IMAGE_REL_AMD64_REL32"],
        },
    ];

    #[cfg(windows)]
    #[test]
    fn reference_pe_corpus_executes_and_candidate_matches() {
        let temp_dir = tempfile::tempdir().expect("create PE smoke-test directory");
        let candidate = std::env::var_os("WILD_PE_LINKER");

        for case in CASES {
            run_case(case, temp_dir.path(), candidate.as_deref());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn reference_pe_corpus_is_structurally_valid() {
        let tools = ["clang-cl", "lld-link", "llvm-readobj"];
        if let Some(missing) = tools.iter().find(|tool| !tool_is_available(tool)) {
            eprintln!("skipped: {missing} is unavailable for local PE inspection");
            return;
        }

        let temp_dir = tempfile::tempdir().expect("create PE inspection directory");
        for case in CASES.iter().filter(|case| !case.kernel32) {
            let case_dir = temp_dir.path().join(case.name);
            std::fs::create_dir(&case_dir)
                .unwrap_or_else(|error| panic!("create {}: {error}", case_dir.display()));
            let objects = compile_coff(case, &case_dir);
            assert_object_relocations(case, &objects);

            let reference = case_dir.join("reference.exe");
            link_pe(OsStr::new("lld-link"), case, &objects, &reference);
            let inspection = run_tool(
                "llvm-readobj",
                &["--file-headers", "--sections", "--coff-basereloc"],
                &reference,
            );
            assert!(
                inspection.contains("IMAGE_FILE_MACHINE_AMD64"),
                "{}: reference image is not AMD64:\n{inspection}",
                case.name
            );
            if case.name == "absolute_pointer" {
                assert!(
                    inspection.contains("Type: DIR64"),
                    "{}: lld-link did not emit the expected DIR64 base relocation:\n{inspection}",
                    case.name
                );
            }
        }
    }

    #[cfg(windows)]
    fn run_case(case: &Case, temp_dir: &Path, candidate: Option<&OsStr>) {
        let case_dir = temp_dir.join(case.name);
        std::fs::create_dir(&case_dir)
            .unwrap_or_else(|error| panic!("create {}: {error}", case_dir.display()));
        let objects = compile_coff(case, &case_dir);

        let reference = case_dir.join("reference.exe");
        link_pe(OsStr::new("lld-link"), case, &objects, &reference);
        assert_exit_code(case, "lld-link reference", &reference);

        if let Some(linker) = candidate {
            let output = case_dir.join("wild.exe");
            link_pe(linker, case, &objects, &output);
            assert_exit_code(case, "Wild candidate", &output);
        }
    }

    fn compile_coff(case: &Case, output_dir: &Path) -> Vec<PathBuf> {
        case.sources
            .iter()
            .map(|source_name| {
                let source = source_dir().join(source_name);
                let object = output_dir.join(format!("{source_name}.obj"));
                compile_one(&source, &object);
                object
            })
            .collect()
    }

    fn compile_one(source: &Path, output: &Path) {
        let mut failures = Vec::new();
        let compilers: &[&str] = if cfg!(windows) {
            &["clang-cl", "cl"]
        } else {
            &["clang-cl"]
        };
        for compiler in compilers {
            let mut command = Command::new(compiler);
            command.args(["/nologo", "/c", "/GS-", "/O1", "/Zl"]);
            if cfg!(not(windows)) {
                command.arg("/clang:--target=x86_64-pc-windows-msvc");
            }
            let result = command
                .arg(format!("/Fo{}", output.display()))
                .args(if cfg!(not(windows)) { &["--"][..] } else { &[] })
                .arg(source)
                .output();

            match result {
                Ok(result) if result.status.success() => return,
                Ok(result) => failures.push(format_output(compiler, &result)),
                Err(error) => failures.push(format!("{compiler}: {error}")),
            }
        }

        panic!(
            "neither clang-cl nor cl could compile {}:\n{}",
            source.display(),
            failures.join("\n")
        );
    }

    fn link_pe(linker: &OsStr, case: &Case, objects: &[PathBuf], output: &Path) {
        let mut command = Command::new(linker);
        command.args([
            "/nologo",
            "/entry:mainCRTStartup",
            "/subsystem:console",
            "/nodefaultlib",
            "/dynamicbase",
            "/machine:x64",
        ]);
        command.arg(format!("/out:{}", output.display()));
        command.args(objects);
        if case.kernel32 {
            command.arg("kernel32.lib");
        }

        let result = command.output().unwrap_or_else(|error| {
            panic!(
                "{}: failed to start {}: {error}",
                case.name,
                linker.to_string_lossy()
            )
        });
        assert!(
            result.status.success(),
            "{}: {} failed to link:\n{}",
            case.name,
            linker.to_string_lossy(),
            format_output(&linker.to_string_lossy(), &result)
        );
        assert!(
            output.is_file(),
            "{}: linker did not create {}",
            case.name,
            output.display()
        );
    }

    #[cfg(windows)]
    fn assert_exit_code(case: &Case, producer: &str, executable: &Path) {
        let result = Command::new(executable).output().unwrap_or_else(|error| {
            panic!(
                "{}: failed to execute {producer} image {}: {error}",
                case.name,
                executable.display()
            )
        });
        assert_eq!(
            result.status.code(),
            Some(case.exit_code),
            "{}: {producer} returned an unexpected status; stdout: {}; stderr: {}",
            case.name,
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }

    fn source_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/sources/coff")
    }

    #[cfg(target_os = "macos")]
    fn assert_object_relocations(case: &Case, objects: &[PathBuf]) {
        let mut inspection = String::new();
        for object in objects {
            inspection.push_str(&run_tool("llvm-readobj", &["--relocations"], object));
        }
        for relocation in case.object_relocations {
            assert!(
                inspection.contains(relocation),
                "{}: objects lack required {relocation}:\n{inspection}",
                case.name
            );
        }
    }

    #[cfg(target_os = "macos")]
    fn tool_is_available(tool: &str) -> bool {
        Command::new(tool)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    #[cfg(target_os = "macos")]
    fn run_tool(tool: &str, arguments: &[&str], input: &Path) -> String {
        let output = Command::new(tool)
            .args(arguments)
            .arg(input)
            .output()
            .unwrap_or_else(|error| panic!("failed to run {tool} on {}: {error}", input.display()));
        assert!(
            output.status.success(),
            "{tool} failed on {}:\n{}",
            input.display(),
            format_output(tool, &output)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn format_output(program: &str, output: &Output) -> String {
        format!(
            "{program} exited with {}; stdout: {}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }
}

#[cfg(all(not(windows), not(target_os = "macos")))]
#[test]
fn windows_pe_smoke_requires_windows() {
    eprintln!("skipped: PE execution is verified on a real Windows runner");
}
