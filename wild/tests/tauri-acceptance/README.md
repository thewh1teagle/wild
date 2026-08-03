# Tauri PE acceptance fixture

This standalone Tauri 2/Wry application exercises a representative Windows
desktop link: Rust `std`, WebView2, Windows UI import libraries, the MSVC CRT,
generated resources, TLS, unwind data, and debug information. It creates a
hidden webview and exits with code 73 when the event loop becomes ready.

The manual `PE/COFF Tauri acceptance` workflow builds and executes both debug
and release profiles using Wild. It intentionally stays out of the main Cargo
workspace and the fast PE workflow.

The linker is selected exactly as Cargo selects any MSVC linker:

```powershell
$env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = 'C:\path\to\link.exe'
./verify.ps1 -Linker $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER `
  -TargetDirectory 'C:\path\to\target\tauri-acceptance'
```

Wild must be copied or renamed to `link.exe` so its argument-flavor detection
uses the MSVC/COFF driver. Windows requires the x86-64 MSVC Rust target, Visual
C++ Build Tools with the Windows SDK, and the WebView2 Runtime.
