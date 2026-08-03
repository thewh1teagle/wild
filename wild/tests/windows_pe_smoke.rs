//! A small, real-Windows execution test for the PE/COFF development loop.
//!
//! Today this establishes the reference path with `lld-link`. Once Wild can
//! produce PE files, set `WILD_PE_LINKER` to its executable to run the same
//! object and assertions through Wild as well.

#[cfg(windows)]
mod windows {
    use std::ffi::OsStr;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    const EXPECTED_EXIT_CODE: i32 = 37;

    #[test]
    fn reference_pe_executes_and_candidate_matches() {
        let temp_dir = tempfile::tempdir().expect("create PE smoke-test directory");
        let object = temp_dir.path().join("exit_code.obj");
        compile_coff(&object);

        let reference = temp_dir.path().join("reference.exe");
        link_pe(OsStr::new("lld-link"), &object, &reference);
        assert_exit_code(&reference, EXPECTED_EXIT_CODE);

        if let Some(linker) = std::env::var_os("WILD_PE_LINKER") {
            let candidate = temp_dir.path().join("wild.exe");
            link_pe(&linker, &object, &candidate);
            assert_exit_code(&candidate, EXPECTED_EXIT_CODE);
        }
    }

    fn compile_coff(output: &Path) {
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/sources/coff/minimal_exit_code.c");
        let mut failures = Vec::new();

        for compiler in ["clang-cl", "cl"] {
            let result = Command::new(compiler)
                .args(["/nologo", "/c", "/GS-"])
                .arg(&source)
                .arg(format!("/Fo{}", output.display()))
                .output();

            match result {
                Ok(result) if result.status.success() => return,
                Ok(result) => failures.push(format_output(compiler, &result)),
                Err(error) => failures.push(format!("{compiler}: {error}")),
            }
        }

        panic!(
            "neither clang-cl nor cl could compile the COFF fixture:\n{}",
            failures.join("\n")
        );
    }

    fn link_pe(linker: &OsStr, object: &Path, output: &Path) {
        let result = Command::new(linker)
            .args([
                "/nologo",
                "/entry:mainCRTStartup",
                "/subsystem:console",
                "/nodefaultlib",
                "/dynamicbase",
            ])
            .arg(format!("/out:{}", output.display()))
            .arg(object)
            .arg("kernel32.lib")
            .output()
            .unwrap_or_else(|error| {
                panic!("failed to start {}: {error}", linker.to_string_lossy())
            });

        assert!(
            result.status.success(),
            "{} failed to link the PE fixture:\n{}",
            linker.to_string_lossy(),
            format_output(&linker.to_string_lossy(), &result)
        );
        assert!(
            output.is_file(),
            "linker did not create {}",
            output.display()
        );
    }

    fn assert_exit_code(executable: &Path, expected: i32) {
        let result = Command::new(executable)
            .output()
            .unwrap_or_else(|error| panic!("failed to execute {}: {error}", executable.display()));

        assert_eq!(
            result.status.code(),
            Some(expected),
            "{} returned an unexpected status; stdout: {}; stderr: {}",
            executable.display(),
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
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

#[cfg(not(windows))]
#[test]
fn windows_pe_smoke_requires_windows() {
    eprintln!("skipped: PE execution is verified on a real Windows runner");
}
