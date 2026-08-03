//! Runtime acceptance tests for the experimental PE/COFF linker.
//!
//! Every fixture is linked with `lld-link` first. On Windows those reference
//! images are executed. Set `WILD_PE_LINKER_FULL` to run the same inputs through
//! Wild; unlike the small smoke corpus, these cases intentionally require the
//! CRT, C++ runtime, DLL exports/imports, and the Rust standard library.

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
mod corpus {
    use object::Object as _;
    use object::ObjectSection as _;
    use std::ffi::OsStr;
    use std::ffi::OsString;
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::Command;
    use std::process::Output;

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
                label: "consumer of a C++ runtime DLL export",
                stdout: "wild-pe-cpp-dll 42\r\n",
                exit_code: 66,
            },
            run: run_cpp_dll_runtime,
        },
        RuntimeCase {
            expected: ExpectedProgram {
                label: "Rust std executable",
                stdout: "wild-pe-rust-runtime\n",
                exit_code: 64,
            },
            run: run_rust_runtime,
        },
        RuntimeCase {
            expected: ExpectedProgram {
                label: "consumer of a Rust cdylib export",
                stdout: "wild-pe-rust-dll 42\r\n",
                exit_code: 67,
            },
            run: run_rust_dll_runtime,
        },
        RuntimeCase {
            expected: ExpectedProgram {
                label: "compiler-generated static TLS and callback executable",
                stdout: "",
                exit_code: 65,
            },
            run: run_tls_runtime,
        },
        RuntimeCase {
            expected: ExpectedProgram {
                label: "consumer of an ordinal-only DLL export",
                stdout: "wild-pe-ordinal-import 42\r\n",
                exit_code: 68,
            },
            run: run_ordinal_import_runtime,
        },
        RuntimeCase {
            expected: ExpectedProgram {
                label: "consumer of a forwarded DLL export",
                stdout: "wild-pe-forwarded-export\r\n",
                exit_code: 69,
            },
            run: run_forwarded_export_runtime,
        },
        RuntimeCase {
            expected: ExpectedProgram {
                label: "consumer of a delay-loaded DLL export",
                stdout: "wild-pe-delay 42\r\n",
                exit_code: 70,
            },
            run: run_delay_load_runtime,
        },
        RuntimeCase {
            expected: ExpectedProgram {
                label: "executable with a merged embedded manifest",
                stdout: "wild-pe-c-runtime\r\n",
                exit_code: 61,
            },
            run: run_manifest_runtime,
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

        for case in CASES.iter().filter(|case| selected(case)) {
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
            for case in CASES.iter().filter(|case| selected(case)) {
                (case.run)(&toolchain, &candidate, &candidate_dir, &case.expected);
            }
            compare_candidate_structure(&reference_dir, &candidate_dir);
        }
    }

    #[test]
    fn malformed_pe_is_rejected_by_inspectors_and_cannot_execute() {
        if !tool_is_available("llvm-readobj") {
            eprintln!("skipped: llvm-readobj is unavailable for malformed-PE validation");
            return;
        }
        let temporary = tempfile::tempdir().expect("create malformed-PE test directory");
        let mut truncated_optional = malformed_pe_with_out_of_bounds_import();
        truncated_optional[0x84..0x86].copy_from_slice(&0x14c_u16.to_le_bytes());
        truncated_optional.truncate(0xb8);
        let fixtures = [
            (
                "truncated-mz.exe",
                b"MZ".to_vec(),
                "DOS header without e_lfanew",
            ),
            (
                "wrong-machine-truncated-optional.exe",
                truncated_optional,
                "I386 header with a truncated PE32+ optional header",
            ),
            (
                "out-of-bounds-import.exe",
                malformed_pe_with_out_of_bounds_import(),
                "AMD64 PE32+ import directory beyond SizeOfImage",
            ),
        ];

        for (name, bytes, description) in fixtures {
            let malformed = temporary.path().join(name);
            std::fs::write(&malformed, &bytes).expect("write malformed PE fixture");
            let object_rejected = match object::File::parse(bytes.as_slice()) {
                Err(_) => true,
                Ok(image) => {
                    image.architecture() != object::Architecture::X86_64 || image.imports().is_err()
                }
            };
            assert!(
                object_rejected,
                "in-process PE validation accepted {description}: {}",
                malformed.display()
            );

            let inspection = Command::new("llvm-readobj")
                .args(["--file-headers", "--coff-imports"])
                .arg(&malformed)
                .output()
                .expect("start llvm-readobj for malformed PE");
            assert!(
                !inspection.status.success(),
                "llvm-readobj accepted {description} at {}:\n{}",
                malformed.display(),
                format_output("llvm-readobj", &inspection)
            );

            #[cfg(windows)]
            {
                match Command::new(&malformed).output() {
                    Err(error) => {
                        let error_code = error.raw_os_error();
                        assert!(
                            matches!(error_code, Some(193 | 216)),
                            "{description} failed process creation with an unexpected outcome \
                             (expected Windows error 193 or 216, got {error_code:?}): {error}"
                        );
                    }
                    Ok(output) => assert!(
                        !output.status.success(),
                        "{description} unexpectedly executed successfully:\n{}",
                        format_output(&malformed.display().to_string(), &output)
                    ),
                }
            }
        }
    }

    fn malformed_pe_with_out_of_bounds_import() -> Vec<u8> {
        let mut image = vec![0_u8; 0x400];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
        image[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
        image[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
        image[0x96..0x98].copy_from_slice(&0x22_u16.to_le_bytes());

        let optional = 0x98;
        image[optional..optional + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
        image[optional + 4..optional + 8].copy_from_slice(&0x200_u32.to_le_bytes());
        image[optional + 16..optional + 20].copy_from_slice(&0x1000_u32.to_le_bytes());
        image[optional + 20..optional + 24].copy_from_slice(&0x1000_u32.to_le_bytes());
        image[optional + 24..optional + 32]
            .copy_from_slice(&0x0000_0001_4000_0000_u64.to_le_bytes());
        image[optional + 32..optional + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
        image[optional + 36..optional + 40].copy_from_slice(&0x200_u32.to_le_bytes());
        image[optional + 40..optional + 42].copy_from_slice(&6_u16.to_le_bytes());
        image[optional + 48..optional + 50].copy_from_slice(&6_u16.to_le_bytes());
        image[optional + 56..optional + 60].copy_from_slice(&0x2000_u32.to_le_bytes());
        image[optional + 60..optional + 64].copy_from_slice(&0x200_u32.to_le_bytes());
        image[optional + 68..optional + 70].copy_from_slice(&3_u16.to_le_bytes());
        image[optional + 72..optional + 80].copy_from_slice(&0x10_0000_u64.to_le_bytes());
        image[optional + 80..optional + 88].copy_from_slice(&0x1000_u64.to_le_bytes());
        image[optional + 88..optional + 96].copy_from_slice(&0x10_0000_u64.to_le_bytes());
        image[optional + 96..optional + 104].copy_from_slice(&0x1000_u64.to_le_bytes());
        image[optional + 108..optional + 112].copy_from_slice(&16_u32.to_le_bytes());
        // Import directory (entry 1): its entire range lies beyond SizeOfImage (0x2000).
        image[optional + 120..optional + 124].copy_from_slice(&0x3000_u32.to_le_bytes());
        image[optional + 124..optional + 128].copy_from_slice(&40_u32.to_le_bytes());

        let section = optional + 0xf0;
        image[section..section + 5].copy_from_slice(b".text");
        image[section + 8..section + 12].copy_from_slice(&1_u32.to_le_bytes());
        image[section + 12..section + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        image[section + 16..section + 20].copy_from_slice(&0x200_u32.to_le_bytes());
        image[section + 20..section + 24].copy_from_slice(&0x200_u32.to_le_bytes());
        image[section + 36..section + 40].copy_from_slice(&0x6000_0020_u32.to_le_bytes());
        image[0x200] = 0xc3;
        image
    }

    fn selected(case: &RuntimeCase) -> bool {
        let Ok(filter) = std::env::var("WILD_PE_RUNTIME_FILTER") else {
            return true;
        };
        case.expected
            .label
            .to_ascii_lowercase()
            .contains(&filter.to_ascii_lowercase())
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
                if cfg!(not(windows)) {
                    // xwin may contain a newer MSVC STL than the locally installed Clang.
                    command.arg("/D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH");
                }
            }
            if strip_defaults {
                command.arg("/Zl");
            } else {
                command.arg("/MD");
            }
            if cfg!(not(windows)) {
                command.arg("/clang:--target=x86_64-pc-windows-msvc");
                for include in &self.include_paths {
                    command.arg(format!("/imsvc{}", include.display()));
                }
            }
            command.arg(format!("/Fo{}", object.display()));
            if cfg!(not(windows)) {
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

    fn run_manifest_runtime(
        toolchain: &Toolchain,
        linker: &OsStr,
        directory: &Path,
        expected: &ExpectedProgram,
    ) {
        let object = directory.join("manifest_runtime.obj");
        toolchain.compile(&source("c_runtime.c"), &object, false, false);
        let input = directory.join("manifest_input.xml");
        std::fs::write(
            &input,
            br#"<?xml version="1.0"?><assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><assemblyIdentity type="win32" name="wild.manifest.runtime" version="1.0.0.0"/><description>manifest runtime input</description></assembly>"#,
        )
        .expect("write manifest input");
        let executable = directory.join("manifest_runtime.exe");
        let mut command = Command::new(linker);
        command
            .current_dir(directory)
            .args([
                "/nologo",
                "/subsystem:windows",
                "/entry:mainCRTStartup",
                "/machine:x64",
                "/opt:ref",
            ])
            .arg(format!("/out:{}", executable.display()))
            .arg("/manifest:embed,id=7")
            .arg(format!("/manifestinput:{}", input.display()))
            .arg("/manifestuac:level='asInvoker' uiAccess='false'")
            .arg("/manifestdependency:type='win32' name='Runtime.Manifest.Dependency' version='1.0.0.0'")
            .arg(&object);
        toolchain.add_library_paths(&mut command);
        assert_success(&mut command, "link embedded-manifest runtime executable");

        let bytes = std::fs::read(&executable).expect("read manifest runtime executable");
        let image = object::File::parse(bytes.as_slice()).expect("parse manifest runtime PE");
        let resource = image
            .section_by_name(".rsrc")
            .expect("manifest runtime PE has .rsrc");
        let data = resource.data().expect("read manifest runtime .rsrc");
        for expected_text in [
            "manifest runtime input",
            "asInvoker",
            "Runtime.Manifest.Dependency",
        ] {
            assert!(
                data.windows(expected_text.len())
                    .any(|window| window == expected_text.as_bytes()),
                "{} .rsrc lacks {expected_text:?}",
                executable.display()
            );
        }
        let inspection = inspect_image(&executable);
        assert!(
            inspection.contains("IMAGE_SUBSYSTEM_WINDOWS_GUI"),
            "{} is not a GUI-subsystem image:\n{inspection}",
            executable.display()
        );
        verify_image_and_maybe_run(expected, &executable, directory);
    }

    fn run_tls_runtime(
        toolchain: &Toolchain,
        linker: &OsStr,
        directory: &Path,
        expected: &ExpectedProgram,
    ) {
        let object = directory.join("tls_runtime.obj");
        toolchain.compile(&source("tls_runtime.c"), &object, false, false);
        let executable = directory.join("tls_runtime.exe");
        link_executable(toolchain, linker, &[object], &executable, &[]);
        let inspection = inspect_image(&executable);
        assert!(
            inspection.contains("TLSDirectory") || inspection.contains("TLSTableRVA"),
            "{} lacks a PE TLS directory:\n{inspection}",
            executable.display()
        );
        assert!(
            inspection.contains("Type: DIR64"),
            "{} lacks TLS base relocations:\n{inspection}",
            executable.display()
        );
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

    fn run_ordinal_import_runtime(
        toolchain: &Toolchain,
        linker: &OsStr,
        directory: &Path,
        expected: &ExpectedProgram,
    ) {
        let dll_object = directory.join("ordinal_exports.obj");
        toolchain.compile(&source("ordinal_exports.c"), &dll_object, false, true);
        let dll = directory.join("ordinal_exports.dll");
        let import_library = directory.join("ordinal_exports.lib");
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
            .arg("/export:ordinal_export,@7,NONAME")
            .arg(&dll_object);
        toolchain.add_library_paths(&mut dll_link);
        assert_success(&mut dll_link, "link ordinal-only export DLL");

        let consumer_object = directory.join("ordinal_import_consumer.obj");
        toolchain.compile(
            &source("ordinal_import_consumer.c"),
            &consumer_object,
            false,
            false,
        );
        let executable = directory.join("ordinal_import_consumer.exe");
        link_executable(
            toolchain,
            linker,
            &[consumer_object],
            &executable,
            &[import_library],
        );
        verify_image_and_maybe_run(expected, &executable, directory);
    }

    fn run_forwarded_export_runtime(
        toolchain: &Toolchain,
        linker: &OsStr,
        directory: &Path,
        expected: &ExpectedProgram,
    ) {
        let dll_object = directory.join("forwarded_exports.obj");
        toolchain.compile(&source("forwarded_exports.c"), &dll_object, false, true);
        let dll = directory.join("forwarded_exports.dll");
        let import_library = directory.join("forwarded_exports.lib");
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
            .arg("/export:forwarded_sleep=KERNEL32.Sleep")
            .arg(&dll_object);
        toolchain.add_library_paths(&mut dll_link);
        assert_success(&mut dll_link, "link forwarded-export DLL");

        let consumer_object = directory.join("forwarded_export_consumer.obj");
        toolchain.compile(
            &source("forwarded_export_consumer.c"),
            &consumer_object,
            false,
            false,
        );
        let executable = directory.join("forwarded_export_consumer.exe");
        link_executable(
            toolchain,
            linker,
            &[consumer_object],
            &executable,
            &[import_library],
        );
        verify_image_and_maybe_run(expected, &executable, directory);
    }

    fn run_delay_load_runtime(
        toolchain: &Toolchain,
        linker: &OsStr,
        directory: &Path,
        expected: &ExpectedProgram,
    ) {
        let dll_object = directory.join("delay_exports.obj");
        toolchain.compile(&source("delay_exports.c"), &dll_object, false, true);
        let dll = directory.join("delay_exports.dll");
        let import_library = directory.join("delay_exports.lib");
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
        assert_success(&mut dll_link, "link delay-load export DLL");

        let consumer_object = directory.join("delay_consumer.obj");
        toolchain.compile(&source("delay_consumer.c"), &consumer_object, false, false);
        let executable = directory.join("delay_consumer.exe");
        let mut command = Command::new(linker);
        command
            .current_dir(directory)
            .args(["/nologo", "/subsystem:console", "/machine:x64", "/opt:ref"])
            .arg(format!("/out:{}", executable.display()))
            .arg("/delayload:delay_exports.dll")
            .arg(&consumer_object)
            .arg(&import_library)
            .arg("delayimp.lib");
        toolchain.add_library_paths(&mut command);
        assert_success(&mut command, "link delay-load runtime executable");
        let inspection = inspect_image(&executable);
        assert!(
            inspection.contains("DelayImport") || inspection.contains("Delay Import"),
            "{} lacks a delay-import directory:\n{inspection}",
            executable.display()
        );
        assert!(
            inspection.contains("delay_exports.dll"),
            "{} lacks its delayed DLL name:\n{inspection}",
            executable.display()
        );
        if linker != OsStr::new("lld-link") {
            let unwind = inspect_unwind(&executable);
            assert_eq!(
                unwind.matches("ALLOC_LARGE size=136").count(),
                1,
                "{} lacks exactly one unwind record for its non-leaf delay resolver:\n{unwind}",
                executable.display()
            );
        }
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

    fn run_cpp_dll_runtime(
        toolchain: &Toolchain,
        linker: &OsStr,
        directory: &Path,
        expected: &ExpectedProgram,
    ) {
        let dll_object = directory.join("cpp_runtime_exports.obj");
        toolchain.compile(&source("cpp_runtime_exports.cpp"), &dll_object, true, false);
        let dll = directory.join("cpp_runtime_exports.dll");
        let import_library = directory.join("cpp_runtime_exports.lib");
        link_dll(toolchain, linker, &dll_object, &dll, &import_library);
        assert_named_export(&dll, "cpp_exported");

        let consumer_object = directory.join("cpp_dll_consumer.obj");
        toolchain.compile(
            &source("cpp_dll_consumer.c"),
            &consumer_object,
            false,
            false,
        );
        let executable = directory.join("cpp_dll_consumer.exe");
        link_executable(
            toolchain,
            linker,
            &[consumer_object],
            &executable,
            &[import_library],
        );
        verify_image_and_maybe_run(expected, &executable, directory);
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
            .arg("-C")
            .arg("link-arg=/OPT:REF")
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

    fn run_rust_dll_runtime(
        toolchain: &Toolchain,
        linker: &OsStr,
        directory: &Path,
        expected: &ExpectedProgram,
    ) {
        let dll = directory.join("rust_cdylib.dll");
        let import_library = directory.join("rust_cdylib.lib");
        let mut command = Command::new("rustc");
        command
            .current_dir(directory)
            .args(["--crate-type", "cdylib"])
            .args(["--target", "x86_64-pc-windows-msvc"])
            .arg(source("rust_cdylib.rs"))
            .arg("-C")
            .arg(format!("linker={}", linker.to_string_lossy()))
            .arg("-C")
            .arg("opt-level=1")
            .arg("-C")
            .arg("link-arg=/OPT:REF")
            .arg("-C")
            .arg(format!("link-arg=/implib:{}", import_library.display()))
            .arg("-o")
            .arg(&dll);
        for library_path in &toolchain.library_paths {
            command
                .arg("-C")
                .arg(format!("link-arg=/libpath:{}", library_path.display()));
        }
        assert_success(&mut command, "compile and link Rust cdylib");
        assert!(
            import_library.is_file(),
            "Rust cdylib linker did not create import library {}",
            import_library.display()
        );
        assert_named_export(&dll, "rust_exported");

        let consumer_object = directory.join("rust_dll_consumer.obj");
        toolchain.compile(
            &source("rust_dll_consumer.c"),
            &consumer_object,
            false,
            false,
        );
        let executable = directory.join("rust_dll_consumer.exe");
        link_executable(
            toolchain,
            linker,
            &[consumer_object],
            &executable,
            &[import_library],
        );
        verify_image_and_maybe_run(expected, &executable, directory);
    }

    fn link_dll(
        toolchain: &Toolchain,
        linker: &OsStr,
        object: &Path,
        dll: &Path,
        import_library: &Path,
    ) {
        let mut command = Command::new(linker);
        command
            .current_dir(dll.parent().expect("DLL has a parent directory"))
            .args(["/nologo", "/dll", "/machine:x64"])
            .arg(format!("/out:{}", dll.display()))
            .arg(format!("/implib:{}", import_library.display()))
            .arg(object);
        toolchain.add_library_paths(&mut command);
        assert_success(&mut command, "link runtime DLL");
        assert!(
            import_library.is_file(),
            "DLL linker did not create import library {}",
            import_library.display()
        );
    }

    fn assert_named_export(dll: &Path, name: &str) {
        let inspection = inspect_image(dll);
        assert!(
            inspection.contains(&format!("Name: {name}")),
            "{} lacks expected export {name}:\n{inspection}",
            dll.display()
        );
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
            .args(["/nologo", "/subsystem:console", "/machine:x64", "/opt:ref"])
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

    fn compare_candidate_structure(reference_dir: &Path, candidate_dir: &Path) {
        for reference in std::fs::read_dir(reference_dir)
            .expect("read reference PE directory")
            .map(|entry| entry.expect("read reference PE entry").path())
            .filter(|path| {
                matches!(
                    path.extension().and_then(|value| value.to_str()),
                    Some("exe" | "dll")
                )
                    // LLVM 18's COFF export dumper rejects lld-link's valid pure-NONAME
                    // export table by trying to read a zero-length name-ordinal table at the
                    // first byte beyond the export directory. The consumer image still exposes
                    // ordinal 7 to structural comparison and is executed on Windows.
                    && path.file_name() != Some(OsStr::new("ordinal_exports.dll"))
            })
        {
            let name = reference.file_name().expect("reference PE has file name");
            let candidate = candidate_dir.join(name);
            assert!(
                candidate.is_file(),
                "Wild did not create candidate image {}",
                candidate.display()
            );
            assert_eq!(
                loader_visible_identity(&reference),
                loader_visible_identity(&candidate),
                "Wild image {} differs from lld-link in machine/type or imported/exported identities",
                name.to_string_lossy()
            );
        }
    }

    fn loader_visible_identity(image: &Path) -> Vec<String> {
        let inspection = inspect_image(image);
        let mut identity = inspection
            .lines()
            .map(str::trim)
            // `Name` is used for imported DLLs and exports by llvm-readobj;
            // unlike symbol lists and section layout, these are direct loader
            // contracts. Ordinals cover NONAME exports/imports.
            .filter(|line| {
                line.starts_with("Machine:")
                    || line.starts_with("Magic:")
                    || line.starts_with("Name:")
                    || line.starts_with("Ordinal:")
            })
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        identity.sort();
        identity
    }

    fn inspect_image(image: &Path) -> String {
        let inspection = Command::new("llvm-readobj")
            .args([
                "--file-headers",
                "--coff-imports",
                "--coff-exports",
                "--coff-basereloc",
                "--coff-tls-directory",
            ])
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

    fn inspect_unwind(image: &Path) -> String {
        let inspection = Command::new("llvm-readobj")
            .arg("--unwind")
            .arg(image)
            .output()
            .unwrap_or_else(|error| panic!("inspect unwind data in {}: {error}", image.display()));
        assert!(
            inspection.status.success(),
            "{} has malformed unwind data:\n{}",
            image.display(),
            format_output("llvm-readobj --unwind", &inspection)
        );
        String::from_utf8_lossy(&inspection.stdout).into_owned()
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

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
#[test]
fn windows_pe_runtime_requires_windows_or_xwin() {
    eprintln!("skipped: full PE runtime coverage requires Windows or an xwin sysroot");
}
