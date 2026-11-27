[CmdletBinding()]
param([string]$OutputPath)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $tempRoot = $env:RUNNER_TEMP
    if ([string]::IsNullOrWhiteSpace($tempRoot)) { $tempRoot = $env:TEMP }
    if ([string]::IsNullOrWhiteSpace($tempRoot)) { $tempRoot = [IO.Path]::GetTempPath() }
    $OutputPath = Join-Path $tempRoot 'prism-makeappx-capability-readonly.json'
}
$pf86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
if ([string]::IsNullOrWhiteSpace($pf86)) { $pf86 = 'C:\Program Files (x86)' }
$sdkRoot = Join-Path $pf86 'Windows Kits\10\bin'
$tools = @()
if (Test-Path -LiteralPath $sdkRoot -PathType Container) {
    foreach ($v in Get-ChildItem -LiteralPath $sdkRoot -Directory -ErrorAction SilentlyContinue) {
        $p = Join-Path $v.FullName 'x64\MakeAppx.exe'
        if (Test-Path -LiteralPath $p -PathType Leaf) { $tools += Get-Item -LiteralPath $p }
    }
}
$tools = @($tools | Sort-Object FullName -Descending)
$r = [ordered]@{
    schema_version = 1
    kind = 'WINDOWS_SDK_MAKEAPPX_CAPABILITY_READ_ONLY'
    scope = 'QA_FIXTURE_ONLY_NOT_PRODUCT'
    host_os = [Environment]::OSVersion.VersionString
    runner_image = $env:ImageOS
    sdk_root = $sdkRoot
    makeappx_found = ($tools.Count -gt 0)
    makeappx_path = $null
    file_version = $null
    sha256 = $null
    signature_status = 'NOT_CHECKED'
    signer_subject = $null
    help_probe_invoked = $false
    help_probe_exit_code = $null
    help_probe_contains_pack_usage = $false
    package_build_invoked = $false
    package_file_created = $false
    product_msix_created = $false
    store_submission_allowed = $false
    sale_ready = $false
    status = 'HOLD_MAKEAPPX_NOT_FOUND'
}
if ($tools.Count -gt 0) {
    $tool = $tools[0]
    $sig = Get-AuthenticodeSignature -LiteralPath $tool.FullName
    $ver = [Diagnostics.FileVersionInfo]::GetVersionInfo($tool.FullName)
    $hash = (Get-FileHash -LiteralPath $tool.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    # No arguments request usage text only; no pack/unpack operation or output path.
    $help = (& $tool.FullName 2>&1 | Out-String)
    $r.makeappx_path = $tool.FullName
    $r.file_version = $ver.FileVersion
    $r.sha256 = $hash
    $r.signature_status = $sig.Status.ToString()
    if ($null -ne $sig.SignerCertificate) { $r.signer_subject = $sig.SignerCertificate.Subject }
    $r.help_probe_invoked = $true
    $r.help_probe_exit_code = $LASTEXITCODE
    $r.help_probe_contains_pack_usage = [bool](($help -match '(?i)makeappx') -and ($help -match '(?i)pack'))
    if (($sig.Status -eq [Management.Automation.SignatureStatus]::Valid) -and
        ($r.signer_subject -match '(?i)Microsoft') -and $r.help_probe_contains_pack_usage) {
        $r.status = 'MAKEAPPX_CAPABILITY_VERIFIED_READ_ONLY'
    } else {
        $r.status = 'HOLD_MAKEAPPX_SIGNATURE_OR_HELP_PROBE'
    }
}
$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$r | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM
Write-Output ($r | ConvertTo-Json -Depth 8)
