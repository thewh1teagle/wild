#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ArchivePath,

    [Parameter(Mandatory = $true)]
    [string] $ReplayRoot,

    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]*$')]
    [string] $DestinationName,
    [ValidateRange(3, 120)]
    [int] $MaxReplayRootLength = 64,
    [ValidateRange(80, 32760)]
    [int] $MaxExtractedPathLength = 240,
    [string] $LldLinkPath = 'C:\Program Files\LLVM\bin\lld-link.exe',
    [string] $WildPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-FullPath {
    param([Parameter(Mandatory = $true)][string] $Path)
    return [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)).TrimEnd('\', '/')
}

function Test-IsInside {
    param(
        [Parameter(Mandatory = $true)][string] $Candidate,
        [Parameter(Mandatory = $true)][string] $Parent
    )
    $candidateFull = Get-FullPath $Candidate
    $parentFull = Get-FullPath $Parent
    if ($candidateFull.Equals($parentFull, [StringComparison]::OrdinalIgnoreCase)) { return $true }
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
    finally { $ErrorActionPreference = $previousErrorAction }
    if (-not $AllowFailure -and $exitCode -ne 0) {
        throw "Command failed ($exitCode): $FilePath $($ArgumentList -join ' ')`n$($output -join [Environment]::NewLine)"
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Output = $output }
}

$archiveFull = Get-FullPath $ArchivePath
if (-not (Test-Path -LiteralPath $archiveFull -PathType Leaf)) { throw "Archive not found: $archiveFull" }
if ((Get-Item -LiteralPath $archiveFull).Length -eq 0) { throw "Archive is empty: $archiveFull" }
if (-not (Get-Command tar.exe -ErrorAction SilentlyContinue)) { throw 'tar.exe was not found on PATH.' }
$lldLinkFull = Get-FullPath $LldLinkPath
if (-not (Test-Path -LiteralPath $lldLinkFull -PathType Leaf)) { throw "lld-link not found: $lldLinkFull" }
$wildFull = if ($WildPath) { Get-FullPath $WildPath } else { $null }
if ($wildFull -and -not (Test-Path -LiteralPath $wildFull -PathType Leaf)) { throw "Wild executable not found: $wildFull" }

$replayRootFull = Get-FullPath $ReplayRoot
if ($replayRootFull.Length -gt $MaxReplayRootLength) {
    throw "ReplayRoot is $($replayRootFull.Length) characters; use a path no longer than $MaxReplayRootLength characters: $replayRootFull"
}
if (-not $DestinationName) {
    $archiveHash = (Get-FileHash -LiteralPath $archiveFull -Algorithm SHA256).Hash.ToLowerInvariant()
    $DestinationName = "r-$($archiveHash.Substring(0, 16))"
}
$destination = Join-Path $replayRootFull $DestinationName
if (Test-Path -LiteralPath $destination) { throw "Destination must not already exist: $destination" }

$helperRepository = (Invoke-Captured -FilePath 'git.exe' -ArgumentList @('-C', $PSScriptRoot, 'rev-parse', '--show-toplevel') -AllowFailure)
if ($helperRepository.ExitCode -eq 0) {
    $helperRoot = ($helperRepository.Output -join "`n").Trim()
    if ($helperRoot -and (Test-IsInside -Candidate $destination -Parent $helperRoot)) {
        throw "Destination must be outside repository '$helperRoot': $destination"
    }
}

$listing = Invoke-Captured -FilePath 'tar.exe' -ArgumentList @('-tf', $archiveFull)
$entries = @($listing.Output | Where-Object { $_ })
if ($entries.Count -eq 0) { throw "Archive has no entries: $archiveFull" }
$responseEntries = @($entries | Where-Object { $_ -match '(^|/)response\.txt$' })
if ($responseEntries.Count -ne 1) {
    throw "Archive must contain exactly one response.txt; found $($responseEntries.Count): $archiveFull"
}

$longestPath = $null
$longestLength = 0
foreach ($entry in $entries) {
    $relative = $entry.Replace('\', '/').TrimEnd('/')
    if (-not $relative) { continue }
    if ($relative.StartsWith('/') -or $relative -match '^[A-Za-z]:' -or @($relative.Split('/') | Where-Object { $_ -eq '..' }).Count -gt 0) {
        throw "Archive contains an unsafe path: $entry"
    }
    $expandedPath = Get-FullPath (Join-Path $destination ($relative.Replace('/', [IO.Path]::DirectorySeparatorChar)))
    if (-not (Test-IsInside -Candidate $expandedPath -Parent $destination)) {
        throw "Archive entry escapes destination: $entry"
    }
    if ($expandedPath.Length -gt $longestLength) {
        $longestLength = $expandedPath.Length
        $longestPath = $expandedPath
    }
}
if ($longestLength -gt $MaxExtractedPathLength) {
    throw "Extraction would create a $longestLength-character path, exceeding MaxExtractedPathLength=$MaxExtractedPathLength. Use a shorter ReplayRoot. Longest path: $longestPath"
}

$createdDestination = $false
try {
    New-Item -ItemType Directory -Force -Path $replayRootFull | Out-Null
    if (Test-Path -LiteralPath $destination) { throw "Destination appeared before extraction: $destination" }
    New-Item -ItemType Directory -Path $destination | Out-Null
    $createdDestination = $true
    $extract = Invoke-Captured -FilePath 'tar.exe' -ArgumentList @('-xf', $archiveFull, '-C', $destination) -AllowFailure
    if ($extract.ExitCode -ne 0) { throw "Archive extraction failed ($($extract.ExitCode)):`n$($extract.Output -join [Environment]::NewLine)" }

    $responseRelative = $responseEntries[0].Replace('/', [IO.Path]::DirectorySeparatorChar)
    $responsePath = Get-FullPath (Join-Path $destination $responseRelative)
    if (-not (Test-Path -LiteralPath $responsePath -PathType Leaf)) { throw "Extracted response file not found: $responsePath" }
    $extractedResponses = @(Get-ChildItem -LiteralPath $destination -Recurse -File -Filter response.txt)
    if ($extractedResponses.Count -ne 1 -or -not $extractedResponses[0].FullName.Equals($responsePath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Extracted destination must contain exactly the archived response.txt; found $($extractedResponses.Count)."
    }
    $responseDirectory = Split-Path -Parent $responsePath
    $responseText = [IO.File]::ReadAllText($responsePath)
    $outMatch = [regex]::Match($responseText, '(?im)^/OUT:(?:"([^"]+)"|(\S+))\s*$')
    if (-not $outMatch.Success) { throw "response.txt has no usable /OUT: directive: $responsePath" }
    $outputValue = if ($outMatch.Groups[1].Success) { $outMatch.Groups[1].Value } else { $outMatch.Groups[2].Value }
    $outputPath = Get-FullPath (Join-Path $responseDirectory $outputValue)
    if (-not (Test-IsInside -Candidate $outputPath -Parent $responseDirectory)) { throw "Response /OUT path escapes replay directory: $outputValue" }

    Push-Location $responseDirectory
    try {
        $lldReplay = Invoke-Captured -FilePath $lldLinkFull -ArgumentList @('@response.txt') -AllowFailure
        [IO.File]::WriteAllLines((Join-Path $responseDirectory 'lld-replay.log'), $lldReplay.Output, [Text.UTF8Encoding]::new($false))
        if ($lldReplay.ExitCode -ne 0) { throw "lld-link replay failed ($($lldReplay.ExitCode)):`n$($lldReplay.Output -join [Environment]::NewLine)" }
        if (-not (Test-Path -LiteralPath $outputPath -PathType Leaf)) { throw "lld-link succeeded but did not create /OUT: $outputPath" }
        $lldOutput = Join-Path $responseDirectory ("lld-" + [IO.Path]::GetFileName($outputPath))
        Copy-Item -LiteralPath $outputPath -Destination $lldOutput

        $wildOutput = $null
        if ($wildFull) {
            Remove-Item -LiteralPath $outputPath -Force
            $wildReplay = Invoke-Captured -FilePath $wildFull -ArgumentList @('@response.txt') -AllowFailure
            [IO.File]::WriteAllLines((Join-Path $responseDirectory 'wild-replay.log'), $wildReplay.Output, [Text.UTF8Encoding]::new($false))
            if ($wildReplay.ExitCode -ne 0) { throw "Wild replay failed ($($wildReplay.ExitCode)):`n$($wildReplay.Output -join [Environment]::NewLine)" }
            if (-not (Test-Path -LiteralPath $outputPath -PathType Leaf)) { throw "Wild succeeded but did not create /OUT: $outputPath" }
            $wildOutput = Join-Path $responseDirectory ("wild-" + [IO.Path]::GetFileName($outputPath))
            Move-Item -LiteralPath $outputPath -Destination $wildOutput
        }
    }
    finally { Pop-Location }

    $result = [ordered]@{
        archive = $archiveFull
        archiveSha256 = (Get-FileHash -LiteralPath $archiveFull -Algorithm SHA256).Hash.ToLowerInvariant()
        responseDirectory = $responseDirectory
        responsePath = $responsePath
        maximumExtractedPathLength = $longestLength
        lldOutput = $lldOutput
        wildOutput = $wildOutput
    }
    $result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $responseDirectory 'replay-results.json') -Encoding UTF8
    $createdDestination = $false
    Write-Output $responseDirectory
}
finally {
    if ($createdDestination -and (Test-Path -LiteralPath $destination) -and (Test-IsInside -Candidate $destination -Parent $replayRootFull)) {
        Remove-Item -LiteralPath $destination -Recurse -Force
    }
}
