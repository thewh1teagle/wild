#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    let app = tauri::Builder::default()
        .build(tauri::generate_context!())
        .expect("build Tauri acceptance application");
    let exit_code = app.run_return(|app, event| {
        if matches!(event, tauri::RunEvent::Ready) {
            app.exit(73);
        }
    });
    std::process::exit(exit_code);
}

#[cfg(not(windows))]
fn main() {
    panic!("the Tauri acceptance fixture must target Windows");
}
