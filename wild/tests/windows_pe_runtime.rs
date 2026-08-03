//! Runtime acceptance tests for the experimental PE/COFF linker.
//!
//! Every fixture is linked with `lld-link` first. On Windows those reference
//! images are executed. Set `WILD_PE_LINKER_FULL` to run the same inputs through
//! Wild; unlike the small smoke corpus, these cases intentionally require the
//! CRT, C++ runtime, DLL exports/imports, and the Rust standard library.

#[cfg(any(windows, target_os = "macos"))]
mod corpus {
    use std::ffi::{OsStr, OsString};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    struct ExpectedProgram {
        label: &'static str,
        stdout: &'static str,
        exit_code: i32,
    }

    type RuntimeRunner = fn(&Toolchain, &OsStr, &Path, &ExpectedProgram);

    struct RuntimeCase {
        expected: ExpectedProgram,
        run: RuntimeRunner,
    }

    const CASES: &[RuntimeCase] = &[
        RuntimeCase {
            expected: ExpectedProgram {
                label: "C executable using the UCRT",
                stdout: "wild-pe-c-runtime\r\n",
                exit_code: 61,
            },
            run: run_c_runtime,
        },
        RuntimeCase {
            expected: ExpectedProgram {
                label: "C++ executable using initialization, STL, heap, and unwind",
                stdout: "wild-pe-cpp-runtime 42\r\n",
                exit_code: 62,
            },
            run: run_cpp_runtime,
        },
        RuntimeCase {
            expected: ExpectedProgram {
                label: "consumer of named function and data DLL exports",
                stdout: "wild-pe-dll 42 17\r\n",
                exit_code: 63,
            },
            run: run_dll_runtime,
        },
        RuntimeCase {
            expected: ExpectedProgram {
                label: "Rust std executable",
                stdout: "wild-pe-rust-runtime\n",
                exit_code: 64,
            },
            run: run_rust_runtime,
        },
    ];

    #[test]
    fn reference_runtime_corpus_and_full_candidate() {
        let Some(toolchain) = Toolchain::discover() else {
            return;
        };
        let temporary = tempfile::tempdir().expect("create PE runtime-test directory");
        let reference_dir = temporary.path().join("reference");
        std::fs::create_dir(&reference_dir).expect("create reference output directory");

        for case in CASES {
            (case.run)(
                &toolchain,
                OsStr::new("lld-link"),
                &reference_dir,
                &case.expected,
            );
        }

        if let Some(candidate) = std::env::var_os("WILD_PE_LINKER_FULL") {
            let candidate_dir = temporary.path().join("wild");
            std::fs::create_dir(&candidate_dir).expect("create Wild output directory");
            for case in CASES {
                (case.run)(&toolchain, &candidate, &candidate_dir, &case.expected);
            }
        }
    }

    struct Toolchain {
        clang_cl: OsString,
        library_paths: Vec<PathBuf>,
        include_paths: Vec<PathBuf>,
    }

    impl Toolchain {
        fn discover() -> Option<Self> {
            for tool in ["clang-cl", "lld-link", "llvm-readobj", "rustc"] {
                if !tool_is_available(tool) {
                    if cfg!(windows) {
                        panic!("required PE runtime-test tool is unavailable: {tool}");
                    }
                    eprintln!("skipped: {tool} is unavailable for local PE runtime inspection");
                    return None;
                }
            }

            if cfg!(windows) {
                return Some(Self {
                    clang_cl: "clang-cl".into(),
                    library_paths: Vec::new(),
                    include_paths: Vec::new(),
                });
            }

            let root = std::env::var_os("XWIN_ROOT")
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".xwin")))
                .expect("HOME or XWIN_ROOT is required to locate xwin");
            let include_paths = [
                root.join("crt/include"),
                root.join("sdk/include/ucrt"),
                root.join("sdk/include/shared"),
                root.join("sdk/include/um"),
            ];
            let library_paths = [
                root.join("crt/lib/x86_64"),
                root.join("sdk/lib/ucrt/x86_64"),
                root.join("sdk/lib/um/x86_64"),
            ];
            if let Some(missing) = include_paths
                .iter()
                .chain(library_paths.iter())
                .find(|path| !path.is_dir())
            {
                eprintln!(
                    "skipped: xwin sysroot is incomplete (missing {})",
                    missing.display()
                );
                return None;
            }

            Some(Self {
                clang_cl: "clang-cl".into(),
                library_paths: library_paths.into(),
                include_paths: include_paths.into(),
            })
        }

        fn compile(&self, source: &Path, object: &Path, cpp: bool, strip_defaults: bool) {
            let mut command = Command::new(&self.clang_cl);
            command.args(["/nologo", "/c", "/GS-", "/O1"]);
            if cpp {
                command.args(["/EHsc", "/std:c++17"]);
                if cfg!(target_os = "macos") {
                    // xwin may contain a newer MSVC STL than the locally installed Clang.
                    command.arg("/D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH");
                }
            }
            if strip_defaults {
                command.arg("/Zl");
            } else {
                command.arg("/MD");
            }
            if cfg!(target_os = "macos") {
                command.arg("/clang:--target=x86_64-pc-windows-msvc");
                for include in &self.include_paths {
                    command.arg(format!("/imsvc{}", include.display()));
                }
            }
            command.arg(format!("/Fo{}", object.display()));
            if cfg!(target_os = "macos") {
                command.arg("--");
            }
            command.arg(source);
            assert_success(&mut command, "compile runtime fixture");
        }

        fn add_library_paths(&self, command: &mut Command) {
            for library_path in &self.library_paths {
                command.arg(format!("/libpath:{}", library_path.display()));
            }
        }
    }

    fn run_c_runtime(
        toolchain: &Toolchain,
        linker: &OsStr,
        directory: &Path,
        expected: &ExpectedProgram,
    ) {
        let object = directory.join("c_runtime.obj");
        toolchain.compile(&source("c_runtime.c"), &object, false, false);
        let executable = directory.join("c_runtime.exe");
        link_executable(toolchain, linker, &[object], &executable, &[]);
        verify_image_and_maybe_run(expected, &executable, directory);
    }

    fn run_cpp_runtime(
        toolchain: &Toolchain,
        linker: &OsStr,
        directory: &Path,
        expected: &ExpectedProgram,
    ) {
        let object = directory.join("cpp_runtime.obj");
        toolchain.compile(&source("cpp_runtime.cpp"), &object, true, false);
        let executable = directory.join("cpp_runtime.exe");
        link_executable(toolchain, linker, &[object], &executable, &[]);
        verify_image_and_maybe_run(expected, &executable, directory);
    }

    fn run_dll_runtime(
        toolchain: &Toolchain,
        linker: &OsStr,
        directory: &Path,
        expected: &ExpectedProgram,
    ) {
        let dll_object = directory.join("runtime_exports.obj");
        toolchain.compile(&source("runtime_exports.c"), &dll_object, false, true);
        let dll = directory.join("runtime_exports.dll");
        let import_library = directory.join("runtime_exports.lib");
        let mut dll_link = Command::new(linker);
        dll_link
            .current_dir(directory)
            .args([
                "/nologo",
                "/dll",
                "/noentry",
                "/nodefaultlib",
                "/machine:x64",
            ])
            .arg(format!("/out:{}", dll.display()))
            .arg(format!("/implib:{}", import_library.display()))
            .arg(&dll_object);
        toolchain.add_library_paths(&mut dll_link);
        assert_success(&mut dll_link, "link runtime export DLL");
        assert!(
            import_library.is_file(),
            "DLL linker did not create import library {}",
            import_library.display()
        );
        assert_dll_exports(&dll);

        let consumer_object = directory.join("dll_consumer.obj");
        toolchain.compile(&source("dll_consumer.c"), &consumer_object, false, false);
        let executable = directory.join("dll_consumer.exe");
        link_executable(
            toolchain,
            linker,
            &[consumer_object],
            &executable,
            &[import_library],
        );
        verify_image_and_maybe_run(expected, &executable, directory);
    }

    fn assert_dll_exports(dll: &Path) {
        let inspection = inspect_image(dll);
        for export in ["Name: add_exported", "Name: exported_value"] {
            assert!(
                inspection.contains(export),
                "{} lacks expected export {export}:\n{inspection}",
                dll.display()
            );
        }
    }

    fn run_rust_runtime(
        toolchain: &Toolchain,
        linker: &OsStr,
        directory: &Path,
        expected: &ExpectedProgram,
    ) {
        let executable = directory.join("rust_runtime.exe");
        let mut command = Command::new("rustc");
        command
            .current_dir(directory)
            .args(["--target", "x86_64-pc-windows-msvc"])
            .arg(source("rust_runtime.rs"))
            .arg("-C")
            .arg(format!("linker={}", linker.to_string_lossy()))
            .arg("-C")
            .arg("opt-level=1")
            .arg("-o")
            .arg(&executable);
        for library_path in &toolchain.library_paths {
            command
                .arg("-C")
                .arg(format!("link-arg=/libpath:{}", library_path.display()));
        }
        assert_success(&mut command, "compile and link Rust runtime fixture");
        verify_image_and_maybe_run(expected, &executable, directory);
    }

    fn link_executable(
        toolchain: &Toolchain,
        linker: &OsStr,
        objects: &[PathBuf],
        output: &Path,
        libraries: &[PathBuf],
    ) {
        let mut command = Command::new(linker);
        command
            .current_dir(output.parent().expect("output has a parent directory"))
            .args(["/nologo", "/subsystem:console", "/machine:x64"])
            .arg(format!("/out:{}", output.display()))
            .args(objects)
            .args(libraries);
        toolchain.add_library_paths(&mut command);
        assert_success(&mut command, "link runtime executable");
    }

    fn verify_image_and_maybe_run(expected: &ExpectedProgram, executable: &Path, directory: &Path) {
        let inspection = inspect_image(executable);
        assert!(
            inspection.contains("IMAGE_FILE_MACHINE_AMD64"),
            "{} is not AMD64:\n{inspection}",
            expected.label
        );

        #[cfg(windows)]
        {
            let output = Command::new(executable)
                .current_dir(directory)
                .output()
                .unwrap_or_else(|error| {
                    panic!(
                        "execute {} at {}: {error}",
                        expected.label,
                        executable.display()
                    )
                });
            assert_eq!(
                output.status.code(),
                Some(expected.exit_code),
                "{} returned the wrong exit code:\n{}",
                expected.label,
                format_output(&executable.to_string_lossy(), &output)
            );
            assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                expected.stdout,
                "{} wrote unexpected stdout; stderr: {}",
                expected.label,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        #[cfg(not(windows))]
        let _ = (directory, expected.stdout, expected.exit_code);
    }

    fn inspect_image(image: &Path) -> String {
        let inspection = Command::new("llvm-readobj")
            .args(["--file-headers", "--coff-imports", "--coff-exports"])
            .arg(image)
            .output()
            .unwrap_or_else(|error| panic!("inspect {}: {error}", image.display()));
        assert!(
            inspection.status.success(),
            "{} is not a readable PE image:\n{}",
            image.display(),
            format_output("llvm-readobj", &inspection)
        );
        let inspection = String::from_utf8_lossy(&inspection.stdout);
        assert!(
            inspection.contains("IMAGE_FILE_MACHINE_AMD64"),
            "{} is not AMD64:\n{inspection}",
            image.display()
        );
        inspection.into_owned()
    }

    fn source(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/sources/coff/runtime")
            .join(name)
    }

    fn tool_is_available(tool: &str) -> bool {
        Command::new(tool)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    fn assert_success(command: &mut Command, operation: &str) {
        let display = format!("{command:?}");
        let output = command
            .output()
            .unwrap_or_else(|error| panic!("{operation}: failed to start {display}: {error}"));
        assert!(
            output.status.success(),
            "{operation} failed: {display}\n{}",
            format_output(&display, &output)
        );
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
fn windows_pe_runtime_requires_windows_or_xwin() {
    eprintln!("skipped: full PE runtime coverage requires Windows or an xwin sysroot");
}
