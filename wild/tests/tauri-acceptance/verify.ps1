param(
    [Parameter(Mandatory = $true)]
    [string] $Linker,

    [Parameter(Mandatory = $true)]
    [string] $TargetDirectory
)

$ErrorActionPreference = 'Stop'
$manifest = Join-Path $PSScriptRoot 'Cargo.toml'
$env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = $Linker

foreach ($profile in @('debug', 'release')) {
    $arguments = @(
        'build',
        '--locked',
        '--manifest-path', $manifest,
        '--target', 'x86_64-pc-windows-msvc',
        '--target-dir', $TargetDirectory
    )
    if ($profile -eq 'release') {
        $arguments += '--release'
    }

    & cargo @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Tauri $profile build failed with exit code $LASTEXITCODE"
    }

    $executable = Join-Path $TargetDirectory "x86_64-pc-windows-msvc/$profile/wild-pe-tauri-acceptance.exe"
    $process = Start-Process -FilePath $executable -Wait -PassThru
    if ($process.ExitCode -ne 73) {
        throw "Tauri $profile executable returned $($process.ExitCode), expected 73"
    }
}
