[CmdletBinding()]
param(
    [ValidateSet('x64', 'arm64')]
    [string]$Architecture = 'x64',
    [string]$OutputDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'outputs')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$manifest = Get-Content -LiteralPath (Join-Path $repoRoot 'Cargo.toml') -Raw
$versionMatch = [regex]::Match($manifest, '(?m)^version\s*=\s*"([^"]+)"')
if (-not $versionMatch.Success) {
    throw 'Could not read the OroResea version from Cargo.toml.'
}
$version = $versionMatch.Groups[1].Value
$target = if ($Architecture -eq 'arm64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
$builtExecutable = Join-Path $repoRoot "target\$target\release\ororesea.exe"
if (-not (Test-Path -LiteralPath $builtExecutable -PathType Leaf)) {
    throw "Build the $target release executable before packaging: $builtExecutable"
}

$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
$packageName = "OroResea-v$version-$Architecture"
$packageDirectory = Join-Path $outputRoot $packageName
$archivePath = Join-Path $outputRoot "$packageName.zip"
$archiveChecksumPath = "$archivePath.sha256"
foreach ($targetPath in @($packageDirectory, $archivePath, $archiveChecksumPath)) {
    if (Test-Path -LiteralPath $targetPath) {
        throw "Release output already exists; choose a clean output directory: $targetPath"
    }
}

New-Item -ItemType Directory -Path $packageDirectory -Force | Out-Null
Copy-Item -LiteralPath $builtExecutable -Destination (Join-Path $packageDirectory 'OroResea.exe')
Copy-Item -LiteralPath (Join-Path $repoRoot 'README.md') -Destination $packageDirectory
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Install-OroResea.ps1') -Destination $packageDirectory
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'install.cmd') -Destination $packageDirectory

$executableHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $packageDirectory 'OroResea.exe')).Hash
[IO.File]::WriteAllText(
    (Join-Path $packageDirectory 'SHA256SUMS.txt'),
    "$executableHash  OroResea.exe`r`n",
    [Text.Encoding]::ASCII
)
Compress-Archive -Path (Join-Path $packageDirectory '*') -DestinationPath $archivePath -CompressionLevel Optimal
$archiveHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
[IO.File]::WriteAllText(
    $archiveChecksumPath,
    "$archiveHash  $packageName.zip`r`n",
    [Text.Encoding]::ASCII
)
Write-Host "Package: $archivePath"
Write-Host "SHA-256: $archiveHash"
