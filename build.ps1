[CmdletBinding()]
param([string]$Out, [switch]$Test)
$ErrorActionPreference = 'Stop'
if (-not $Out) { $Out = Join-Path $PSScriptRoot 'package' }
$Out = [IO.Path]::GetFullPath($Out)
[void][IO.Directory]::CreateDirectory($Out)
$compiler = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw '.net framework compiler is missing' }
$framework = Split-Path $compiler
$references = @('System.Windows.Forms','System.Drawing','System.Web.Extensions','System.ServiceProcess','System.Security') | ForEach-Object { '/reference:' + (Join-Path $framework ($_ + '.dll')) }
$readable = 'matcha fixer 1.0.0 - complete source' + "`r`n"
foreach ($name in @('MatchaFixer.cs','Reporting.cs','FileChecks.cs','RepairChecks.cs','LoaderLink.cs','Troubleshooting.cs','build.ps1','package-release.ps1','app.manifest','README.md','TECHNICAL.md','LICENSE','Tests.cs','server/fixer.mjs','server/fixer-release.mjs','server/refresh-release.mjs','server/0010.sql','server/README.md')) {
    $readable += "`r`n===== $name =====`r`n" + [IO.File]::ReadAllText((Join-Path $PSScriptRoot $name))
}
[IO.File]::WriteAllText((Join-Path $Out 'source-code.txt'), $readable, [Text.UTF8Encoding]::new($false))
Add-Type -AssemblyName System.Drawing
$bitmap = [Drawing.Bitmap]::new(128,128)
$graphics = [Drawing.Graphics]::FromImage($bitmap)
$graphics.ScaleTransform(4,4)
$graphics.SmoothingMode = 'AntiAlias'
$mint = [Drawing.SolidBrush]::new([Drawing.Color]::FromArgb(160,225,193))
$eye = [Drawing.SolidBrush]::new([Drawing.Color]::FromArgb(14,18,16))
$graphics.FillEllipse($mint,3,12,24,15)
$graphics.FillPolygon($mint,[Drawing.Point[]]@([Drawing.Point]::new(24,20),[Drawing.Point]::new(29,7),[Drawing.Point]::new(31,13),[Drawing.Point]::new(29,23)))
$graphics.FillRectangle($mint,11,6,2,7)
$graphics.FillEllipse($mint,8,4,5,3)
$graphics.FillEllipse($mint,13,3,5,3)
$graphics.FillEllipse($eye,8,17,3,3)
$bandage = [Drawing.SolidBrush]::new([Drawing.Color]::FromArgb(245,235,202))
$graphics.FillRectangle($bandage,15,16,10,5)
$graphics.FillRectangle($eye,19,17,2,3)
$bandage.Dispose()
[void][IO.Directory]::CreateDirectory((Join-Path $PSScriptRoot 'assets'))
$bitmap.Save((Join-Path $PSScriptRoot 'assets\matcha-fixer.png'), [Drawing.Imaging.ImageFormat]::Png)
$icon = [Drawing.Icon]::FromHandle($bitmap.GetHicon())
$iconStream = [IO.File]::Create((Join-Path $Out 'matcha.ico'))
try { $icon.Save($iconStream) } finally { $iconStream.Dispose(); $icon.Dispose(); $graphics.Dispose(); $bitmap.Dispose(); $mint.Dispose(); $eye.Dispose() }
& $compiler /nologo /target:winexe /optimize+ /platform:x64 @references "/out:$Out\matcha-fixer.exe" "/win32icon:$Out\matcha.ico" "/win32manifest:$PSScriptRoot\app.manifest" "/resource:$Out\source-code.txt,Source" "$PSScriptRoot\MatchaFixer.cs" "$PSScriptRoot\Reporting.cs" "$PSScriptRoot\FileChecks.cs" "$PSScriptRoot\RepairChecks.cs" "$PSScriptRoot\LoaderLink.cs" "$PSScriptRoot\Troubleshooting.cs"
if ($LASTEXITCODE -ne 0) { throw 'compilation failed' }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.md') -Destination $Out -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'LICENSE') -Destination $Out -Force
[void][IO.Directory]::CreateDirectory((Join-Path $Out 'assets'))
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'assets\matcha-fixer.png') -Destination (Join-Path $Out 'assets') -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'TECHNICAL.md') -Destination $Out -Force
[void][IO.Directory]::CreateDirectory((Join-Path $Out 'server'))
foreach ($name in @('fixer.mjs','fixer-release.mjs','refresh-release.mjs','0010.sql','README.md')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot ('server\' + $name)) -Destination (Join-Path $Out 'server') -Force
}
if ($Test) {
    & $compiler /nologo /target:exe /platform:x64 /main:Tests @references "/out:$Out\tests.exe" "$PSScriptRoot\MatchaFixer.cs" "$PSScriptRoot\Reporting.cs" "$PSScriptRoot\FileChecks.cs" "$PSScriptRoot\RepairChecks.cs" "$PSScriptRoot\LoaderLink.cs" "$PSScriptRoot\Troubleshooting.cs" "$PSScriptRoot\Tests.cs"
    if ($LASTEXITCODE -ne 0) { throw 'test compilation failed' }
    & (Join-Path $Out 'tests.exe') (Join-Path $Out 'previews')
    if ($LASTEXITCODE -ne 0) { throw 'verification failed' }
}
$hash = (Get-FileHash -LiteralPath (Join-Path $Out 'matcha-fixer.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $Out 'SHA256SUMS.txt'), $hash + "  matcha-fixer.exe`r`n")
Write-Output ('built: ' + (Join-Path $Out 'matcha-fixer.exe'))
