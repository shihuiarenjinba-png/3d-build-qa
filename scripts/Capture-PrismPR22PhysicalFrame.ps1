# Read-only PR22 full-desktop frame recorder. Does not launch/modify game or attest human QA.
# Run on the actual physical Windows desktop, once for each requested state.
param(
    [Parameter(Mandatory=$true)][ValidateSet('ja','en')][string]$Language,
    [Parameter(Mandatory=$true)][ValidateSet(100,125,150)][int]$DpiPercent,
    [Parameter(Mandatory=$true)][ValidateSet('guide','active','scan_warning','timeout','trap','sentinel','retry')][string]$State,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    throw 'PHYSICAL_HOLD: Windows only'
}
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class PrismPhysicalDpi {
  [DllImport("user32.dll")] public static extern uint GetDpiForSystem();
}
'@
$screen = [System.Windows.Forms.Screen]::PrimaryScreen
$bounds = $screen.Bounds
if ($bounds.Width -ne 1024 -or $bounds.Height -ne 768) {
    throw "PHYSICAL_HOLD: desktop must be 1024x768, actual $($bounds.Width)x$($bounds.Height)"
}
$reportedDpi = [PrismPhysicalDpi]::GetDpiForSystem()
$reportedPercent = [int][Math]::Round($reportedDpi / 96.0 * 100)
if ($reportedPercent -ne $DpiPercent) {
    throw "PHYSICAL_HOLD: Windows system DPI $reportedPercent%, expected $DpiPercent%. Verify display settings; no DPI spoofing."
}
$dest = [System.IO.Path]::GetFullPath($OutputDirectory)
[System.IO.Directory]::CreateDirectory($dest) | Out-Null
$name = "$Language-$DpiPercent-$State.png"
$path = Join-Path $dest $name
if (Test-Path -LiteralPath $path) {
    throw "PHYSICAL_HOLD: existing capture $name; never overwrite evidence"
}
$bitmap = New-Object System.Drawing.Bitmap(1024, 768)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
try {
    # Full primary desktop including visible taskbar, not cropped game client.
    $graphics.CopyFromScreen($bounds.Left, $bounds.Top, 0, 0, $bounds.Size)
    $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
} finally {
    $graphics.Dispose()
    $bitmap.Dispose()
}
$hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
$record = [ordered]@{
    capture_kind = 'PHYSICAL_WINDOWS_DESKTOP_SCREENSHOT_UNREVIEWED'
    filename = $name
    sha256 = $hash
    bytes = (Get-Item -LiteralPath $path).Length
    utc_captured_at = (Get-Date).ToUniversalTime().ToString('o')
    reported_system_dpi_percent = $reportedPercent
    desktop_resolution = @(1024, 768)
    taskbar_visible = $null
    screenshot_readability_human_verified = $null
    human_play_verified = $null
    physical_qa = 'PHYSICAL_HOLD'
    sale_ready = $false
}
$meta = Join-Path $dest ($name + '.unreviewed.json')
$record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $meta -Encoding utf8
Write-Host "UNREVIEWED: $path SHA256=$hash"
Write-Host "Human must inspect taskbar, game visibility, language and real gameplay; no PASS issued."
