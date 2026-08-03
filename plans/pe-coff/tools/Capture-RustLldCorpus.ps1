#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ProjectPath,

    [Parameter(Mandatory = $true)]
    [string] $Bin,

    [Parameter(Mandatory = $true)]
    [string] $OutputRoot,

    [string] $Package,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]*$')]
    [string] $Profile = 'release',
    [string] $Target = 'x86_64-pc-windows-msvc',
    [string] $Toolchain = '1.95.0-x86_64-pc-windows-msvc',
    [string] $LldLinkPath = 'C:\Program Files\LLVM\bin\lld-link.exe',
    [string] $NasmPath = 'C:\Users\user1\AppData\Local\bin\NASM\nasm.exe',
    [string[]] $CargoArgs = @(),
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-FullPath {
    param([Parameter(Mandatory = $true)][string] $Path)
    return [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path))
}

function Test-IsInside {
    param(
        [Parameter(Mandatory = $true)][string] $Candidate,
        [Parameter(Mandatory = $true)][string] $Parent
    )
    $candidateFull = (Get-FullPath $Candidate).TrimEnd('\', '/')
    $parentFull = (Get-FullPath $Parent).TrimEnd('\', '/')
    if ($candidateFull.Equals($parentFull, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    return $candidateFull.StartsWith($parentFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
}

function Invoke-Captured {
    param(
        [Parameter(Mandatory = $true)][string] $FilePath,
        [string[]] $ArgumentList = @(),
        [switch] $AllowFailure
    )
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { $_.ToString() })
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorAction
    }
    if (-not $AllowFailure -and $exitCode -ne 0) {
        throw "Command failed ($exitCode): $FilePath $($ArgumentList -join ' ')`n$($output -join [Environment]::NewLine)"
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Output = $output }
}

function Get-GitValue {
    param(
        [Parameter(Mandatory = $true)][string] $WorkingDirectory,
        [Parameter(Mandatory = $true)][string[]] $Arguments
    )
    $result = Invoke-Captured -FilePath 'git.exe' -ArgumentList (@('-C', $WorkingDirectory) + $Arguments) -AllowFailure
    if ($result.ExitCode -ne 0) { return $null }
    return ($result.Output -join "`n").Trim()
}

function Import-VsDevEnvironment {
    $vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        throw "Visual Studio locator not found: $vswhere"
    }
    $install = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath).Trim()
    if (-not $install) { throw 'No Visual Studio installation with MSVC x64 tools was found.' }
    $vsDevCmd = Join-Path $install 'Common7\Tools\VsDevCmd.bat'
    if (-not (Test-Path -LiteralPath $vsDevCmd -PathType Leaf)) {
        throw "VsDevCmd.bat not found: $vsDevCmd"
    }

    $cmdLine = "call `"$vsDevCmd`" -arch=amd64 -host_arch=amd64 >nul && set"
    $environmentLines = @(& $env:ComSpec /d /c $cmdLine)
    if ($LASTEXITCODE -ne 0) { throw "VsDevCmd.bat failed with exit code $LASTEXITCODE." }
    foreach ($line in $environmentLines) {
        $separator = $line.IndexOf('=')
        if ($separator -gt 0) {
            $name = $line.Substring(0, $separator)
            $value = $line.Substring($separator + 1)
            [Environment]::SetEnvironmentVariable($name, $value, 'Process')
        }
    }
    return $install
}

function Test-ReproduceArchive {
    param(
        [Parameter(Mandatory = $true)][string] $ArchivePath,
        [string] $ExtractResponseTo
    )
    if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) { return $false }
    if ((Get-Item -LiteralPath $ArchivePath).Length -eq 0) { return $false }

    $listing = Invoke-Captured -FilePath 'tar.exe' -ArgumentList @('-tf', $ArchivePath) -AllowFailure
    if ($listing.ExitCode -ne 0) { return $false }
    $responseEntry = @($listing.Output | Where-Object { $_ -match '(^|/)response\.txt$' })
    if ($responseEntry.Count -ne 1) { return $false }
    $relativeResponse = $responseEntry[0].Replace('\', '/')
    while ($relativeResponse.StartsWith('./')) { $relativeResponse = $relativeResponse.Substring(2) }
    if ($relativeResponse.StartsWith('/') -or $relativeResponse -match '^[A-Za-z]:' -or @($relativeResponse.Split('/') | Where-Object { $_ -eq '..' }).Count -gt 0) { return $false }

    $temporaryParent = if ($ExtractResponseTo) { Split-Path -Parent (Get-FullPath $ExtractResponseTo) } else { [IO.Path]::GetTempPath() }
    if (-not (Test-Path -LiteralPath $temporaryParent -PathType Container)) { return $false }
    $temporaryDirectory = Join-Path $temporaryParent ('.lld-response-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
    try {
        $extract = Invoke-Captured -FilePath 'tar.exe' -ArgumentList @('-xf', $ArchivePath, '-C', $temporaryDirectory, $responseEntry[0]) -AllowFailure
        if ($extract.ExitCode -ne 0) { return $false }
        $extractedResponse = Get-FullPath (Join-Path $temporaryDirectory ($relativeResponse.Replace('/', [IO.Path]::DirectorySeparatorChar)))
        if (-not (Test-IsInside -Candidate $extractedResponse -Parent $temporaryDirectory)) { return $false }
        if (-not (Test-Path -LiteralPath $extractedResponse -PathType Leaf) -or (Get-Item -LiteralPath $extractedResponse).Length -eq 0) { return $false }
        $responseText = [IO.File]::ReadAllText($extractedResponse)
        if ($responseText -notmatch '(?im)(^|\s)[/-](out|entry|subsystem|machine):') { return $false }
        if ($ExtractResponseTo) { Copy-Item -LiteralPath $extractedResponse -Destination $ExtractResponseTo }
        return $true
    }
    finally {
        if (Test-Path -LiteralPath $temporaryDirectory) { Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force }
    }
}

function Test-ExtractedResponse {
    param([Parameter(Mandatory = $true)][string] $ResponsePath)
    if (-not (Test-Path -LiteralPath $ResponsePath -PathType Leaf)) { return $false }
    if ((Get-Item -LiteralPath $ResponsePath).Length -eq 0) { return $false }
    $responseText = [IO.File]::ReadAllText($ResponsePath)
    return $responseText -match '(?im)(^|\s)[/-](out|entry|subsystem|machine):'
}

function ConvertTo-SafeName {
    param([Parameter(Mandatory = $true)][string] $Value)
    $safe = $Value -replace '[^A-Za-z0-9._-]', '-'
    return $safe.Trim('-', '.')
}

function Get-ShortHash {
    param([Parameter(Mandatory = $true)][string] $Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').Substring(0, 16).ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

function Get-SourceFingerprint {
    param(
        [Parameter(Mandatory = $true)][string] $SourceRoot,
        [Parameter(Mandatory = $true)][bool] $IsGitRepository,
        [string] $Commit,
        [string] $Status
    )
    if ($IsGitRepository -and $Commit -and -not $Status) { return $Commit }

    $parts = [Collections.Generic.List[string]]::new()
    if ($IsGitRepository) {
        $parts.Add($Status)
        $diff = Get-GitValue -WorkingDirectory $SourceRoot -Arguments @('diff', '--binary', '--no-ext-diff', 'HEAD')
        if ($diff) { $parts.Add($diff) }
        $untracked = Get-GitValue -WorkingDirectory $SourceRoot -Arguments @('ls-files', '--others', '--exclude-standard')
        foreach ($relativePath in @($untracked -split "`n" | Where-Object { $_ })) {
            $fullPath = Join-Path $SourceRoot $relativePath
            if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
                $parts.Add("$relativePath`0$((Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash)")
            }
        }
    }
    else {
        foreach ($file in Get-ChildItem -LiteralPath $SourceRoot -File -Recurse | Sort-Object FullName) {
            $relativePath = $file.FullName.Substring($SourceRoot.TrimEnd('\', '/').Length).TrimStart('\', '/')
            if ($relativePath -notmatch '(^|[\\/])(target|\.git)([\\/]|$)') {
                $parts.Add("$relativePath`0$((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash)")
            }
        }
    }
    return Get-ShortHash ($parts -join "`n")
}

$projectFull = Get-FullPath $ProjectPath
$manifestPath = if (Test-Path -LiteralPath $projectFull -PathType Leaf) {
    if ([IO.Path]::GetFileName($projectFull) -ne 'Cargo.toml') { throw 'ProjectPath must be a directory or a Cargo.toml file.' }
    $projectFull
}
else {
    Join-Path $projectFull 'Cargo.toml'
}
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw "Cargo manifest not found: $manifestPath" }
$projectDirectory = Split-Path -Parent $manifestPath
$outputFull = Get-FullPath $OutputRoot

$sourceRoot = Get-GitValue -WorkingDirectory $projectDirectory -Arguments @('rev-parse', '--show-toplevel')
$isGitRepository = [bool]$sourceRoot
if (-not $sourceRoot) { $sourceRoot = $projectDirectory }
$helperRoot = Get-GitValue -WorkingDirectory $PSScriptRoot -Arguments @('rev-parse', '--show-toplevel')
foreach ($repositoryRoot in @($sourceRoot, $helperRoot) | Select-Object -Unique) {
    if ($repositoryRoot -and (Test-IsInside -Candidate $outputFull -Parent $repositoryRoot)) {
        throw "OutputRoot must be outside repository '$repositoryRoot': $outputFull"
    }
}
if (-not (Test-Path -LiteralPath $LldLinkPath -PathType Leaf)) { throw "lld-link not found: $LldLinkPath" }
if (-not (Test-Path -LiteralPath $NasmPath -PathType Leaf)) { throw "NASM not found: $NasmPath" }
if (-not (Get-Command rustup.exe -ErrorAction SilentlyContinue)) { throw 'rustup.exe was not found on PATH.' }
if (-not (Get-Command tar.exe -ErrorAction SilentlyContinue)) { throw 'tar.exe was not found on PATH.' }
foreach ($cargoArg in $CargoArgs) {
    if ($cargoArg -eq '--' -or $cargoArg -match '^(--(bin|bins|example|examples|lib|tests?|benches|all-targets|target|profile|release|package|workspace|all|exclude|manifest-path|target-dir|config)(=|$)|-p.*$)') {
        throw "CargoArgs may not override capture scope, build location, or Cargo configuration: $cargoArg"
    }
}

$commit = Get-GitValue -WorkingDirectory $projectDirectory -Arguments @('rev-parse', 'HEAD')
if (-not $commit) { $commit = 'not-a-git-repository' }
$dirtyText = Get-GitValue -WorkingDirectory $projectDirectory -Arguments @('status', '--porcelain=v1', '--untracked-files=normal')
$sourceDirty = [bool]$dirtyText
$sourceFingerprint = Get-SourceFingerprint -SourceRoot $sourceRoot -IsGitRepository $isGitRepository -Commit $commit -Status $dirtyText
$helperSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$projectName = ConvertTo-SafeName (Split-Path -Leaf $sourceRoot)
if (-not $projectName) { $projectName = 'rust-project' }
$packageName = if ($Package) { ConvertTo-SafeName $Package } else { 'default-package' }
$identityData = @(
    $sourceRoot.ToLowerInvariant(), $commit, $sourceFingerprint, $manifestPath.ToLowerInvariant(),
    $packageName, $Bin, $Profile, $Target, $Toolchain, ($CargoArgs -join [char]31), $helperSha256
) -join "`n"
$identityHash = Get-ShortHash $identityData
$commitLabel = if ($commit.Length -ge 12) { $commit.Substring(0, 12) } else { ConvertTo-SafeName $commit }
$captureName = "$(ConvertTo-SafeName $packageName)-$(ConvertTo-SafeName $Bin)-$Profile-$identityHash"
$captureParent = Join-Path (Join-Path (Join-Path $outputFull 'captures') $projectName) $commitLabel
$finalDirectory = Join-Path $captureParent $captureName
$finalArchive = Join-Path $finalDirectory 'link-repro.tar'
$finalResponse = Join-Path $finalDirectory 'response.txt'
$finalMetadata = Join-Path $finalDirectory 'metadata.json'

if (-not $Force -and (Test-ReproduceArchive -ArchivePath $finalArchive) -and (Test-ExtractedResponse -ResponsePath $finalResponse) -and (Test-Path -LiteralPath $finalMetadata -PathType Leaf)) {
    Write-Output $finalDirectory
    return
}
if ((Test-Path -LiteralPath $finalDirectory) -and -not $Force) {
    throw "Existing capture is incomplete or invalid; inspect it or rerun with -Force: $finalDirectory"
}

New-Item -ItemType Directory -Force -Path $captureParent | Out-Null
$stagingRoot = Join-Path $outputFull '.staging'
New-Item -ItemType Directory -Force -Path $stagingRoot | Out-Null
$stage = Join-Path $stagingRoot ("capture-{0}-{1}" -f $PID, [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
$archive = Join-Path $stage 'link-repro.tar'
$responsePath = Join-Path $stage 'response.txt'
$buildLog = Join-Path $stage 'cargo-build.log'
$originalEnvironment = @{}
Get-ChildItem Env: | ForEach-Object { $originalEnvironment[$_.Name] = $_.Value }

try {
    $vsInstall = Import-VsDevEnvironment
    $rustcVersion = (Invoke-Captured -FilePath 'rustup.exe' -ArgumentList @('run', $Toolchain, 'rustc', '-Vv')).Output -join "`n"
    $cargoVersion = (Invoke-Captured -FilePath 'rustup.exe' -ArgumentList @('run', $Toolchain, 'cargo', '-V')).Output -join "`n"
    $lldVersion = (Invoke-Captured -FilePath $LldLinkPath -ArgumentList @('--version')).Output -join "`n"
    $nasmVersion = (Invoke-Captured -FilePath $NasmPath -ArgumentList @('-v')).Output -join "`n"

    $targetCache = Join-Path (Join-Path $outputFull '.cargo-target') "$projectName-$identityHash"
    New-Item -ItemType Directory -Force -Path $targetCache | Out-Null
    $env:CARGO_TARGET_DIR = $targetCache
    $env:PATH = "$(Split-Path -Parent $NasmPath);$(Split-Path -Parent $LldLinkPath);$env:PATH"
    Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
    Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue
    Get-ChildItem Env: | Where-Object { $_.Name -match '^CARGO_TARGET_.*_RUSTFLAGS$' } | Remove-Item
    $cargoCommand = @('run', $Toolchain, 'cargo', 'rustc', '--config', 'build.rustflags=[]', '--manifest-path', $manifestPath, '--target', $Target, '--profile', $Profile)
    if ($Package) { $cargoCommand += @('--package', $Package) }
    $cargoCommand += @('--bin', $Bin)
    $cargoCommand += $CargoArgs
    $cargoCommand += @('--', '-C', "linker=$LldLinkPath", '-C', "link-arg=/reproduce:$archive")

    $build = Invoke-Captured -FilePath 'rustup.exe' -ArgumentList $cargoCommand -AllowFailure
    [IO.File]::WriteAllLines($buildLog, $build.Output, [Text.UTF8Encoding]::new($false))
    if ($build.ExitCode -ne 0) {
        throw "Cargo failed with exit code $($build.ExitCode).`n$($build.Output -join [Environment]::NewLine)"
    }
    if (-not (Test-ReproduceArchive -ArchivePath $archive -ExtractResponseTo $responsePath)) {
        throw "lld-link did not create a valid reproduce archive containing a usable response.txt: $archive"
    }

    $archiveInfo = Get-Item -LiteralPath $archive
    $metadata = [ordered]@{
        schemaVersion = 1
        createdUtc = [DateTime]::UtcNow.ToString('o')
        captureDirectory = $finalDirectory
        archive = [ordered]@{
            file = 'link-repro.tar'
            bytes = $archiveInfo.Length
            sha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
            responseFile = 'response.txt'
            validated = $true
        }
        source = [ordered]@{
            projectPath = $projectDirectory
            manifestPath = $manifestPath
            repositoryRoot = $sourceRoot
            commit = $commit
            dirty = $sourceDirty
            stateFingerprint = $sourceFingerprint
        }
        cargo = [ordered]@{
            package = $Package
            bin = $Bin
            profile = $Profile
            target = $Target
            extraArgs = $CargoArgs
            targetDirectory = $targetCache
            version = $cargoVersion
        }
        toolchain = [ordered]@{
            rustup = $Toolchain
            rustc = $rustcVersion
            linkerPath = $LldLinkPath
            linkerVersion = $lldVersion
            nasmPath = $NasmPath
            nasmVersion = $nasmVersion
            visualStudioPath = $vsInstall
            vcToolsVersion = $env:VCToolsVersion
            windowsSdkVersion = $env:WindowsSDKVersion
            helperSha256 = $helperSha256
        }
        invocation = [ordered]@{
            executable = 'rustup.exe'
            arguments = $cargoCommand
        }
    }
    $metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $stage 'metadata.json') -Encoding UTF8

    if ($Force -and (Test-Path -LiteralPath $finalDirectory)) {
        if (-not (Test-IsInside -Candidate $finalDirectory -Parent $outputFull)) { throw "Refusing to replace path outside OutputRoot: $finalDirectory" }
        Remove-Item -LiteralPath $finalDirectory -Recurse -Force
    }
    Move-Item -LiteralPath $stage -Destination $finalDirectory
    if (-not (Test-ReproduceArchive -ArchivePath $finalArchive) -or -not (Test-Path -LiteralPath $finalResponse -PathType Leaf)) {
        throw "Post-move validation failed: $finalDirectory"
    }
    Write-Output $finalDirectory
}
finally {
    if (Test-Path -LiteralPath $stage) {
        if (Test-IsInside -Candidate $stage -Parent $stagingRoot) { Remove-Item -LiteralPath $stage -Recurse -Force }
    }
    foreach ($variable in Get-ChildItem Env:) {
        if (-not $originalEnvironment.ContainsKey($variable.Name)) {
            [Environment]::SetEnvironmentVariable($variable.Name, $null, 'Process')
        }
    }
    foreach ($entry in $originalEnvironment.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
    }
}
