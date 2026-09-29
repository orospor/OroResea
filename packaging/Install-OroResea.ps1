[CmdletBinding()]
param(
    [string]$InstallDirectory = (Join-Path $env:LOCALAPPDATA "Programs\OroResea"),
    [switch]$NoStartMenuShortcut
)

$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "OroResea is a Windows application."
}

$sourceExecutable = Join-Path $PSScriptRoot "OroResea.exe"
$checksumFile = Join-Path $PSScriptRoot "SHA256SUMS.txt"

if (-not (Test-Path -LiteralPath $sourceExecutable -PathType Leaf)) {
    throw "OroResea.exe is missing from the installation package."
}

if (-not (Test-Path -LiteralPath $checksumFile -PathType Leaf)) {
    throw "SHA256SUMS.txt is missing from the installation package."
}

$checksumLine = Get-Content -LiteralPath $checksumFile |
    Where-Object { $_ -match '\s+OroResea\.exe$' } |
    Select-Object -First 1

if (-not $checksumLine) {
    throw "The package checksum manifest does not contain OroResea.exe."
}

$expectedHash = ($checksumLine -split '\s+', 2)[0].ToUpperInvariant()
$actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceExecutable).Hash.ToUpperInvariant()

if ($actualHash -ne $expectedHash) {
    throw "OroResea.exe failed SHA-256 verification. Expected $expectedHash but found $actualHash."
}

$resolvedParent = [IO.Path]::GetFullPath((Split-Path -Parent $InstallDirectory))
New-Item -ItemType Directory -Force -Path $resolvedParent | Out-Null
New-Item -ItemType Directory -Force -Path $InstallDirectory | Out-Null

$installedExecutable = Join-Path $InstallDirectory "OroResea.exe"
Copy-Item -LiteralPath $sourceExecutable -Destination $installedExecutable -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "README.md") -Destination (Join-Path $InstallDirectory "README.md") -Force
Copy-Item -LiteralPath $checksumFile -Destination (Join-Path $InstallDirectory "SHA256SUMS.txt") -Force

if (-not $NoStartMenuShortcut) {
    $startMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
    $shortcutPath = Join-Path $startMenu "OroResea.lnk"
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $installedExecutable
    $shortcut.WorkingDirectory = $InstallDirectory
    $shortcut.Description = "OroResea capture-protection analyzer"
    $shortcut.Save()
}

Write-Host "OroResea installed successfully."
Write-Host "Executable: $installedExecutable"
Write-Host "SHA-256:   $actualHash"
