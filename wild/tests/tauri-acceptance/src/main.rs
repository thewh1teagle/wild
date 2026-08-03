#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    let app = tauri::Builder::default()
        .build(tauri::generate_context!())
        .expect("build Tauri acceptance application");
    let exit_code = app.run_return(|_app, event| {
        if matches!(event, tauri::RunEvent::Ready) {
            // Tauri/Wry currently maps `app.exit(code)` to Tao's zero-valued `Exit` control
            // flow. Exit directly so this fixture verifies that Windows reached the Ready event
            // and preserves a nonzero process status across Wild's PE entry point.
            std::process::exit(73);
        }
    });
    std::process::exit(exit_code);
}

#[cfg(not(windows))]
fn main() {
    panic!("the Tauri acceptance fixture must target Windows");
}
