#Requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$captureScript = Join-Path $PSScriptRoot 'Capture-RustLldCorpus.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($captureScript, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw "Capture helper has $($parseErrors.Count) parse error(s)." }
foreach ($functionName in @('Get-FullPath', 'Test-IsInside', 'Invoke-Captured', 'Test-ReproduceArchive')) {
    $definition = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName
    }, $true))
    if ($definition.Count -ne 1) { throw "Expected exactly one $functionName definition; found $($definition.Count)." }
    Invoke-Expression $definition[0].Extent.Text
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('corpus-tools-' + [Guid]::NewGuid().ToString('N'))
$archiveRoot = Join-Path $testRoot 'archive-root'
$reproDirectory = Join-Path $archiveRoot 'link-repro'
$archive = Join-Path $testRoot 'repro.tar'
$extracted = Join-Path $testRoot 'extracted-response.txt'
New-Item -ItemType Directory -Path $reproDirectory -Force | Out-Null
try {
    $expectedBytes = [Text.Encoding]::UTF8.GetBytes("/NOLOGO`n`"quoted object.o`"`n/OUT:`"quoted output.exe`"`n")
    [IO.File]::WriteAllBytes((Join-Path $reproDirectory 'response.txt'), $expectedBytes)
    $tar = Invoke-Captured -FilePath 'tar.exe' -ArgumentList @('-cf', $archive, '-C', $archiveRoot, 'link-repro') -AllowFailure
    if ($tar.ExitCode -ne 0) { throw "Could not create regression archive: $($tar.Output -join [Environment]::NewLine)" }
    if (-not (Test-ReproduceArchive -ArchivePath $archive -ExtractResponseTo $extracted)) { throw 'Valid regression archive was rejected.' }
    $actualBytes = [IO.File]::ReadAllBytes($extracted)
    if ($actualBytes.Length -ne $expectedBytes.Length) { throw "Byte length changed: expected $($expectedBytes.Length), found $($actualBytes.Length)." }
    for ($index = 0; $index -lt $expectedBytes.Length; $index++) {
        if ($actualBytes[$index] -ne $expectedBytes[$index]) { throw "Response byte changed at offset $index." }
    }
    Write-Output "PASS: response.txt preserved $($actualBytes.Length) exact LF/quoted bytes"
}
finally {
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
