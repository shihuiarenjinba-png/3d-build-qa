[CmdletBinding()]
param([string]$Operator = '')

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

function Read-YesNo {
    param([string]$Prompt)
    while ($true) {
        $answer = (Read-Host "$Prompt [Y/N]").Trim().ToUpperInvariant()
        if ($answer -in @('Y', 'YES')) { return $true }
        if ($answer -in @('N', 'NO')) { return $false }
        Write-Host 'Enter Y or N.' -ForegroundColor Yellow
    }
}
function Read-FirstGoalSeconds {
    while ($true) {
        $raw = Read-Host '実際に最初の目標を理解できた秒数 (0-1800。30秒超も実測値を入力)'
        $value = 0.0
        if ([double]::TryParse($raw, [ref]$value) -and $value -ge 0 -and $value -le 1800) {
            return [Math]::Round($value, 1)
        }
        Write-Host '0〜1800の実測秒数を入力してください。30秒超はゲートでHOLDになります。' -ForegroundColor Yellow
    }
}
function Wait-ForMainWindow {
    param($Process)
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        $Process.Refresh()
        if ($Process.HasExited) { throw 'HOLD: candidate.exe exited before a visible game window appeared.' }
        if ($Process.MainWindowHandle -ne [IntPtr]::Zero) { return $Process.MainWindowHandle }
        Start-Sleep -Milliseconds 250
    }
    throw 'HOLD: no visible candidate.exe window within 30 seconds.'
}
function Focus-GameWindow {
    param([IntPtr]$Handle)
    if (-not [PrismCaptureNative]::SetForegroundWindow($Handle)) {
        throw 'HOLD: Windows did not allow the game window to become foreground; no screenshot was accepted.'
    }
    Start-Sleep -Milliseconds 300
}
function Capture-PrimaryScreen {
    param([string]$Destination)
    $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    if ($bounds.Width -ne 1024 -or $bounds.Height -ne 768) {
        throw "HOLD: primary display must be exactly 1024x768; detected $($bounds.Width)x$($bounds.Height)."
    }
    $bitmap = [System.Drawing.Bitmap]::new(1024, 768)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
        $bitmap.Save($Destination, [System.Drawing.Imaging.ImageFormat]::Png)
    } finally {
        $graphics.Dispose()
        $bitmap.Dispose()
    }
    $file = Get-Item -LiteralPath $Destination
    if ($file.Length -le 1024) { throw "HOLD: captured PNG is unexpectedly small: $Destination" }
    return (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Wait-ForActualNinetySeconds {
    param([DateTimeOffset]$StartedAt)
    while ((([DateTimeOffset]::Now - $StartedAt).TotalSeconds) -lt 90) {
        $remaining = [Math]::Ceiling(90 - ([DateTimeOffset]::Now - $StartedAt).TotalSeconds)
        [void](Read-Host "実際のプレイ開始から90秒経過するまで続けてください。残り約$remaining秒。経過後Enter")
    }
}

if (-not (Get-Command py -ErrorAction SilentlyContinue)) { throw 'HOLD: Python launcher (py) is required.' }
& py -3 .\prism_pr25_physical_handoff.py --verify .
if ($LASTEXITCODE -ne 0) { throw 'HOLD: exact PR25 handoff verification failed.' }

$ExpectedExe = '66b26ad96df7458ea917b632a73ac7c88bb058db24dbd11a457fd50435ab7b13'
$ExpectedPck = 'b7abc0f9caf2e505a1dcaf834b4cb897d8f00df4060c31708914e8bb4f3d5666'
$ExePath = (Resolve-Path .\candidate.exe).Path
$PckPath = (Resolve-Path .\candidate.pck).Path
if ((Get-FileHash -LiteralPath $ExePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedExe) { throw 'HOLD: candidate.exe SHA256 mismatch.' }
if ((Get-FileHash -LiteralPath $PckPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedPck) { throw 'HOLD: candidate.pck SHA256 mismatch.' }

if ([string]::IsNullOrWhiteSpace($Operator)) { $Operator = Read-Host '実際に操作する担当者 (3文字以上)' }
if ($Operator.Trim().Length -lt 3) { throw 'HOLD: operator attestation must contain at least 3 characters.' }
if (-not (Read-YesNo 'これは仮想マシンではなく、実際のWindows PCですか')) { throw 'HOLD: physical-device operator attestation was not given.' }

if (-not ('PrismCaptureNative' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class PrismCaptureNative {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern uint GetDpiForWindow(IntPtr hwnd);
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr SetThreadDpiAwarenessContext(IntPtr dpiContext);
}
'@
}
$PreviousDpiContext = [PrismCaptureNative]::SetThreadDpiAwarenessContext([IntPtr](-4))
if ($PreviousDpiContext -eq [IntPtr]::Zero) { throw 'HOLD: could not establish per-monitor-v2 DPI awareness for accurate physical screenshot coordinates.' }
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$Os = Get-CimInstance -ClassName Win32_OperatingSystem
$WindowsBuild = "$($Os.Caption) build $($Os.BuildNumber)"
$FrameDirectory = Join-Path $Root 'physical-frames'
New-Item -ItemType Directory -Force -Path $FrameDirectory | Out-Null
if (Test-Path -LiteralPath (Join-Path $Root 'physical-capture.json')) { throw 'HOLD: physical-capture.json already exists; preserve it and use a fresh handoff folder.' }
if (@(Get-ChildItem -LiteralPath $FrameDirectory -File).Count -gt 0) { throw 'HOLD: physical-frames already contains files; preserve them and use a fresh handoff folder.' }

$FramePlan = @(
    @{ key = 'guide'; file = 'guide'; label = 'Initial guide / onboarding' },
    @{ key = 'active'; file = 'active'; label = 'Active gameplay' },
    @{ key = 'scan_warning'; file = 'scan'; label = 'Sentinel scan warning (yellow/red)' },
    @{ key = 'trap'; file = 'trap'; label = 'Time or warp trap' },
    @{ key = 'outcome'; file = 'outcome'; label = 'Win or lose outcome' },
    @{ key = 'retry'; file = 'retry'; label = 'Post-outcome retry' }
)
$ObservationFields = @(
    @{ key = 'goal_understood_in_30s'; label = '初回30秒以内に目的を理解できた' },
    @{ key = 'tower_order_1_2_3_understood'; label = '塔1→2→3の順番を理解できた' },
    @{ key = 'controls_understood'; label = '操作方法を理解できた' },
    @{ key = 'sentinel_colors_understood'; label = 'Sentinelの黄色警告・赤いscanを区別できた' },
    @{ key = 'traps_understood'; label = '時間罠・warp罠を理解できた' },
    @{ key = 'start_action_understood'; label = 'Start操作と開始条件を理解できた' },
    @{ key = 'clock_frozen_until_start'; label = 'Start前に90秒時計が停止していた' },
    @{ key = 'no_clipping'; label = '表示の切れ・重なりがなかった' },
    @{ key = 'no_debug_ui'; label = 'debug表示がなかった' },
    @{ key = 'failure_reason_understood'; label = '失敗理由を理解できた' },
    @{ key = 'retry_completed'; label = '再挑戦まで完了できた' }
)
$Sessions = New-Object 'System.Collections.Generic.List[object]'
$SeenHashes = @{}
$CodeIntegrityStatus = 'NOT_CHECKED'

foreach ($Language in @('ja', 'en')) {
    foreach ($DpiPercent in @(100, 125, 150)) {
        Write-Host ''
        Write-Host "=== PR25 PHYSICAL SESSION: $($Language.ToUpperInvariant()) / DPI $DpiPercent% ===" -ForegroundColor Cyan
        Write-Host 'Windowsの表示解像度を1024x768、拡大率を指定値に設定してください。'
        Write-Host 'ゲーム内の表示言語も指定言語にしてください。設定変更はこのスクリプトでは行いません。'
        [void](Read-Host '設定を確認し、Enterでcandidate.exeを起動')

        $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        if ($bounds.Width -ne 1024 -or $bounds.Height -ne 768) { throw "HOLD: primary display must be 1024x768; detected $($bounds.Width)x$($bounds.Height)." }

        $captureStarted = [DateTimeOffset]::Now
        $Process = Start-Process -FilePath $ExePath -WorkingDirectory $Root -PassThru
        $WindowHandle = Wait-ForMainWindow -Process $Process
        Focus-GameWindow -Handle $WindowHandle
        $ActualDpi = [int][PrismCaptureNative]::GetDpiForWindow($WindowHandle)
        $ExpectedDpi = [int](96 * $DpiPercent / 100)
        if ($ActualDpi -ne $ExpectedDpi) { throw "HOLD: game window DPI mismatch; expected $ExpectedDpi, detected $ActualDpi." }
        if (-not (Read-YesNo "画面上のゲーム言語は $Language ですか")) { throw 'HOLD: visible game language does not match this session.' }
        if (-not (Read-YesNo '既存のWindowsセキュリティポリシーのままでゲームが正常起動しましたか')) { throw 'HOLD: Code Integrity/SmartScreen launch not confirmed; do not bypass security.' }
        $CodeIntegrityStatus = 'ALLOWED_BY_EXISTING_POLICY'

        $Frames = [ordered]@{}
        $GuideFrame = $FramePlan[0]
        [void](Read-Host "Start前の『$($GuideFrame.label)』を表示してEnterで画面を撮影")
        Focus-GameWindow -Handle $WindowHandle
        $GuideName = "$Language-$DpiPercent-$($GuideFrame.file).png"
        $GuidePath = Join-Path $FrameDirectory $GuideName
        $GuideHash = Capture-PrimaryScreen -Destination $GuidePath
        if ($SeenHashes.ContainsKey($GuideHash)) { throw "HOLD: duplicate screenshot bytes detected for $GuideName." }
        $SeenHashes[$GuideHash] = $GuideName
        $Frames[$GuideFrame.key] = $GuideName

        [void](Read-Host 'ゲーム内でStartを押し、実際に開始した直後にEnter')
        $PlayStarted = [DateTimeOffset]::Now
        $StartPressed = Read-YesNo '実際にStartを押してゲームを開始しましたか'
        $FirstGoalSeconds = Read-FirstGoalSeconds

        foreach ($Frame in @($FramePlan | Select-Object -Skip 1)) {
            [void](Read-Host "ゲームを『$($Frame.label)』の状態にしてEnterで画面を撮影")
            Focus-GameWindow -Handle $WindowHandle
            $FileName = "$Language-$DpiPercent-$($Frame.file).png"
            $Destination = Join-Path $FrameDirectory $FileName
            $Hash = Capture-PrimaryScreen -Destination $Destination
            if ($SeenHashes.ContainsKey($Hash)) { throw "HOLD: duplicate screenshot bytes detected for $FileName." }
            $SeenHashes[$Hash] = $FileName
            $Frames[$Frame.key] = $FileName
        }

        Wait-ForActualNinetySeconds -StartedAt $PlayStarted
        $CaptureFinished = [DateTimeOffset]::Now
        $ElapsedPlaySeconds = [Math]::Round(($CaptureFinished - $PlayStarted).TotalSeconds, 1)
        $Observations = [ordered]@{}
        foreach ($Observation in $ObservationFields) { $Observations[$Observation.key] = Read-YesNo $Observation.label }
        $Uncoached = Read-YesNo 'この条件は、事前の操作指示なしの初回プレイでしたか'

        $Session = [ordered]@{
            language = $Language
            dpi_percent = $DpiPercent
            resolution = @(1024, 768)
            capture_started_at = $captureStarted.ToString('o')
            capture_finished_at = $CaptureFinished.ToString('o')
            elapsed_play_seconds = $ElapsedPlaySeconds
            first_goal_seconds = $FirstGoalSeconds
            uncoached_first_launch = $Uncoached
            start_pressed = $StartPressed
            screenshots = $Frames
        }
        foreach ($Key in $Observations.Keys) { $Session[$Key] = $Observations[$Key] }
        $Sessions.Add($Session)

        [void](Read-Host 'ゲームを通常操作で終了し、プロセスが閉じた後にEnter')
        $Process.Refresh()
        if (-not $Process.HasExited) { throw 'HOLD: candidate.exe is still running; close it normally before the next session.' }
    }
}

if ($Sessions.Count -ne 6 -or $SeenHashes.Count -ne 36) { throw "HOLD: expected 6 sessions and 36 distinct screenshots; got $($Sessions.Count) and $($SeenHashes.Count)." }

$Capture = [ordered]@{
    schema_version = 1
    capture_kind = 'PHYSICAL_WINDOWS_OPERATOR_ATTESTATION'
    source_sha = 'b03ce7b16c3f75c04fe20fdda224c45849eeba0d'
    request_id = '3d-prism-route-3d-b03ce7b16c3f'
    factory_artifact_id = 14797309778
    factory_artifact_expires_at = $null
    code_integrity_status = $CodeIntegrityStatus
    exe_sha256 = $ExpectedExe
    pck_sha256 = $ExpectedPck
    exe_path = $ExePath
    pck_path = $PckPath
    physical_device = $true
    operator = $Operator.Trim()
    windows_build = $WindowsBuild
    sessions = @($Sessions.ToArray())
}
$CapturePath = Join-Path $Root 'physical-capture.json'
$JsonText = $Capture | ConvertTo-Json -Depth 12
[System.IO.File]::WriteAllText($CapturePath, $JsonText + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))

Write-Host ''
Write-Host 'All six sessions and 36 distinct screenshots have been recorded. Running fail-closed review gate.' -ForegroundColor Cyan
& py -3 .\prism_first30s_physical_windows_gate.py --software-receipt .\qa11\pck-runtime-independent-receipt.json --software-screenshot-dir .\qa11\screenshots --capture .\physical-capture.json --screenshot-dir .\physical-frames --out .\physical-review-receipt.json
$GateExit = $LASTEXITCODE
if ($GateExit -ne 0) { throw "PHYSICAL_QA_HOLD: review gate returned exit code $GateExit. Inspect physical-review-receipt.json; do not alter security policy or fabricate evidence." }
Write-Host 'Evidence package passed structural checks and is awaiting human review. This is NOT SALE_READY and NOT Store submission approval.' -ForegroundColor Green
