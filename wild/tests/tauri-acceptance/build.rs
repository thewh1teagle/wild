fn main() {
    // Both tauri-build and generate_context! require a real ICO for Windows.
    // Generate the tiny test-only asset so the fixture stays text-only.
    let manifest = std::path::PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"),
    );
    let icon = manifest.join("icons/icon.ico");
    std::fs::create_dir_all(icon.parent().expect("icon has a parent"))
        .expect("create generated icon directory");
    std::fs::write(&icon, minimal_icon()).expect("write acceptance-test icon");

    let windows = tauri_build::WindowsAttributes::new().window_icon_path(icon);
    let attributes = tauri_build::Attributes::new().windows_attributes(windows);
    tauri_build::try_build(attributes).expect("build Tauri application metadata");
}

fn minimal_icon() -> Vec<u8> {
    let mut icon = Vec::with_capacity(70);
    icon.extend_from_slice(&[0, 0, 1, 0, 1, 0]);
    icon.extend_from_slice(&[1, 1, 0, 0, 1, 0, 32, 0]);
    icon.extend_from_slice(&48_u32.to_le_bytes());
    icon.extend_from_slice(&22_u32.to_le_bytes());
    icon.extend_from_slice(&40_u32.to_le_bytes());
    icon.extend_from_slice(&1_i32.to_le_bytes());
    icon.extend_from_slice(&2_i32.to_le_bytes());
    icon.extend_from_slice(&1_u16.to_le_bytes());
    icon.extend_from_slice(&32_u16.to_le_bytes());
    icon.extend_from_slice(&0_u32.to_le_bytes());
    icon.extend_from_slice(&4_u32.to_le_bytes());
    icon.extend_from_slice(&[0; 16]);
    icon.extend_from_slice(&[0x33, 0x99, 0xff, 0xff]);
    icon.extend_from_slice(&[0; 4]);
    icon
}
