[CmdletBinding()]
param([string]$Built, [string]$Out)
$ErrorActionPreference = 'Stop'
if (-not $Built) { $Built = Join-Path $PSScriptRoot '..\package' }
if (-not $Out) { $Out = Join-Path $PSScriptRoot '..\release' }
$Built = [IO.Path]::GetFullPath($Built)
$Out = [IO.Path]::GetFullPath($Out)
[void][IO.Directory]::CreateDirectory($Out)
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$sourceFiles = @('MatchaFixer.cs','Reporting.cs','FileChecks.cs','RepairChecks.cs','LoaderLink.cs','Troubleshooting.cs','Tests.cs','build.ps1','package-release.ps1','app.manifest','README.md','TECHNICAL.md','LICENSE','.gitignore','.github/workflows/build.yml','assets/matcha-fixer.png','server/fixer.mjs','server/fixer-release.mjs','server/refresh-release.mjs','server/0010.sql','server/README.md')
$releaseFiles = @('matcha-fixer.exe','README.md','TECHNICAL.md','LICENSE','SHA256SUMS.txt','source-code.txt','assets/matcha-fixer.png','server/fixer.mjs','server/fixer-release.mjs','server/refresh-release.mjs','server/0010.sql','server/README.md')
function Write-Archive([string]$Base, [string[]]$Files, [string]$Path) {
    $stream = [IO.File]::Open($Path,[IO.FileMode]::Create,[IO.FileAccess]::ReadWrite)
    $zip = [IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create)
    try { foreach ($name in $Files) { [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,(Join-Path $Base $name),$name.Replace('\','/'),[IO.Compression.CompressionLevel]::Optimal) } }
    finally { $zip.Dispose(); $stream.Dispose() }
}
Write-Archive $Built $releaseFiles (Join-Path $Out 'matcha-fixer-1.0.0-windows-x64.zip')
Write-Archive $PSScriptRoot $sourceFiles (Join-Path $Out 'matcha-fixer-1.0.0-source.zip')
$sums = foreach ($name in @('matcha-fixer-1.0.0-windows-x64.zip','matcha-fixer-1.0.0-source.zip')) {
    (Get-FileHash -LiteralPath (Join-Path $Out $name) -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $name
}
[IO.File]::WriteAllLines((Join-Path $Out 'SHA256SUMS.txt'),$sums,[Text.UTF8Encoding]::new($false))
Write-Output ('release files: ' + $Out)
