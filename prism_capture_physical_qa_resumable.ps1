[CmdletBinding()]
param([string]$Operator = '')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

function Read-YesNo([string]$Prompt) {
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
        Write-Host '0〜1800の実測秒数を入力してください。30秒超はHOLDになります。' -ForegroundColor Yellow
    }
}
function Write-JsonExclusive([string]$Path, [object]$Value) {
    $json = ($Value | ConvertTo-Json -Depth 12) + [Environment]::NewLine
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json)
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush() } finally { $stream.Dispose() }
}
function Wait-ForMainWindow($Process) {
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        $Process.Refresh()
        if ($Process.HasExited) { throw 'HOLD: candidate.exe exited before a visible game window appeared.' }
        if ($Process.MainWindowHandle -ne [IntPtr]::Zero) { return $Process.MainWindowHandle }
        Start-Sleep -Milliseconds 250
    }
    throw 'HOLD: no visible candidate.exe window within 30 seconds.'
}
function Focus-GameWindow([IntPtr]$Handle, $Process) {
    $Process.Refresh()
    if ($Process.HasExited) { throw 'HOLD: candidate.exe exited during the session.' }
    if (-not [PrismCaptureNative]::SetForegroundWindow($Handle)) {
        throw 'HOLD: Windows did not allow the game window to become foreground; no screenshot was accepted.'
    }
    Start-Sleep -Milliseconds 300
}
function Capture-PrimaryScreen([string]$Destination) {
    $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    if ($bounds.Width -ne 1024 -or $bounds.Height -ne 768) {
        throw "HOLD: primary display must be exactly 1024x768; detected $($bounds.Width)x$($bounds.Height)."
    }
    if (Test-Path -LiteralPath $Destination) { throw "HOLD: refuse to overwrite existing screenshot bytes: $Destination" }
    $bitmap = [System.Drawing.Bitmap]::new(1024, 768)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $memory = [System.IO.MemoryStream]::new()
    try {
        $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
        $bitmap.Save($memory, [System.Drawing.Imaging.ImageFormat]::Png)
        $bytes = $memory.ToArray()
        if ($bytes.Length -le 1024) { throw "HOLD: captured PNG is unexpectedly small: $Destination" }
        $stream = [System.IO.File]::Open($Destination, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush() } finally { $stream.Dispose() }
    } finally { $memory.Dispose(); $graphics.Dispose(); $bitmap.Dispose() }
    return (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Wait-ForActualNinetySeconds([Diagnostics.Stopwatch]$Watch, $Process) {
    while ($Watch.Elapsed.TotalSeconds -lt 90) {
        $Process.Refresh()
        if ($Process.HasExited) { throw 'HOLD: game exited before 90 real seconds of gameplay elapsed.' }
        $remaining = [Math]::Ceiling(90 - $Watch.Elapsed.TotalSeconds)
        [void](Read-Host "実際のプレイ開始から90秒経過するまで続けてください。残り約$remaining秒。経過後Enter")
    }
    $Process.Refresh()
    if ($Process.HasExited) { throw 'HOLD: game exited before the 90-second observation completed.' }
}

if (-not (Get-Command py -ErrorAction SilentlyContinue)) { throw 'HOLD: Python launcher (py) is required.' }
& py -3 .\prism_pr25_physical_handoff.py --verify $Root
if ($LASTEXITCODE -ne 0) { throw 'HOLD: exact PR25 handoff verification failed.' }

$ExpectedSource = 'b03ce7b16c3f75c04fe20fdda224c45849eeba0d'
$ExpectedRequest = '3d-prism-route-3d-b03ce7b16c3f'
$ExpectedArtifact = 14797309778
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
if ($PreviousDpiContext -eq [IntPtr]::Zero) { throw 'HOLD: per-monitor-v2 DPI awareness could not be established.' }
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$Os = Get-CimInstance -ClassName Win32_OperatingSystem
$WindowsBuild = "$($Os.Caption) build $($Os.BuildNumber)"

$StatusText = & py -3 .\prism_physical_capture_checkpoint.py --root $Root status
if ($LASTEXITCODE -ne 0) { throw 'HOLD: existing session checkpoints failed validation; preserve all bytes.' }
$Status = ($StatusText -join [Environment]::NewLine) | ConvertFrom-Json

$FramePlan = @(
    @{ key = 'guide'; file = 'guide.png'; label = 'Initial guide / onboarding' },
    @{ key = 'active'; file = 'active.png'; label = 'Active gameplay' },
    @{ key = 'scan_warning'; file = 'scan.png'; label = 'Sentinel scan warning (yellow/red)' },
    @{ key = 'trap'; file = 'trap.png'; label = 'Time or warp trap' },
    @{ key = 'outcome'; file = 'outcome.png'; label = 'Win or lose outcome' },
    @{ key = 'retry'; file = 'retry.png'; label = 'Post-outcome retry' }
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

foreach ($Language in @('ja', 'en')) {
    foreach ($DpiPercent in @(100, 125, 150)) {
        $Key = "$Language-$DpiPercent"
        if (@($Status.completed_sessions) -contains $Key) {
            Write-Host "RESUME: $Key checkpoint and all six screenshot hashes validated; skipping capture." -ForegroundColor Green
            continue
        }
        $Incomplete = @($Status.incomplete_attempts | Where-Object { $_.session_key -eq $Key })
        $Corrupt = @($Status.corrupt_attempts | Where-Object { $_.session_key -eq $Key })
        if (($Incomplete.Count + $Corrupt.Count) -gt 0) {
            Write-Host "HOLD history for $Key. Existing attempts are preserved and will not be overwritten." -ForegroundColor Yellow
            if (-not (Read-YesNo '不完全attemptを保持したまま、新しい空attemptでこの条件を最初から撮り直しますか')) {
                Write-Host "$Key remains HOLD; other independent conditions may continue." -ForegroundColor Yellow
                continue
            }
        }

        Write-Host ''
        Write-Host "=== PR25 PHYSICAL SESSION: $($Language.ToUpperInvariant()) / DPI $DpiPercent% ===" -ForegroundColor Cyan
        Write-Host 'Windowsの表示解像度を1024x768、拡大率を指定値に設定してください。'
        Write-Host 'ゲーム内の表示言語も指定言語にしてください。設定変更はこのスクリプトでは行いません。'
        $SessionParent = Join-Path $Root "physical-session-attempts\$Key"
        if (Test-Path -LiteralPath $SessionParent) {
            $ParentItem = Get-Item -LiteralPath $SessionParent -Force
            if ($ParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "HOLD: reparse point: $SessionParent" }
        } else {
            New-Item -ItemType Directory -Path $SessionParent | Out-Null
        }
        $AttemptId = [Guid]::NewGuid().ToString('N')
        $AttemptDirectory = Join-Path $SessionParent $AttemptId
        if (Test-Path -LiteralPath $AttemptDirectory) { throw 'HOLD: generated attempt directory already exists.' }
        New-Item -ItemType Directory -Path $AttemptDirectory | Out-Null
        $AttemptRelative = "physical-session-attempts/$Key/$AttemptId"

        [void](Read-Host '設定を確認し、Enterでcandidate.exeを起動')
        $CaptureStarted = [DateTimeOffset]::Now
        $Process = Start-Process -FilePath $ExePath -WorkingDirectory $Root -PassThru
        $WindowHandle = Wait-ForMainWindow -Process $Process
        Focus-GameWindow -Handle $WindowHandle -Process $Process
        $ActualDpi = [int][PrismCaptureNative]::GetDpiForWindow($WindowHandle)
        $ExpectedDpi = [int](96 * $DpiPercent / 100)
        if ($ActualDpi -ne $ExpectedDpi) { throw "HOLD: expected game DPI $ExpectedDpi, detected $ActualDpi." }
        if (-not (Read-YesNo "画面上のゲーム言語は $Language ですか")) { throw 'HOLD: visible game language mismatch.' }
        if (-not (Read-YesNo '既存のWindowsセキュリティポリシーのままでゲームが正常起動しましたか')) {
            throw 'HOLD: normal Code Integrity/SmartScreen launch not confirmed; do not bypass security.'
        }

        $Frames = [ordered]@{}
        $Hashes = [ordered]@{}
        $GuideFrame = $FramePlan[0]
        [void](Read-Host "Start前の『$($GuideFrame.label)』を表示してEnterで画面を撮影")
        Focus-GameWindow -Handle $WindowHandle -Process $Process
        $Frames[$GuideFrame.key] = $GuideFrame.file
        $Hashes[$GuideFrame.key] = Capture-PrimaryScreen -Destination (Join-Path $AttemptDirectory $GuideFrame.file)

        [void](Read-Host 'ゲーム内でStartを押し、実際に開始した直後にEnter')
        $PlayStarted = [DateTimeOffset]::Now
        $PlayWatch = [Diagnostics.Stopwatch]::StartNew()
        $StartPressed = Read-YesNo '実際にStartを押してゲームを開始しましたか'
        if (-not $StartPressed) { throw 'HOLD: Start was not confirmed; partial attempt is preserved.' }
        $FirstGoalSeconds = Read-FirstGoalSeconds

        foreach ($Frame in @($FramePlan | Select-Object -Skip 1)) {
            [void](Read-Host "ゲームを『$($Frame.label)』の状態にしてEnterで画面を撮影")
            Focus-GameWindow -Handle $WindowHandle -Process $Process
            $Frames[$Frame.key] = $Frame.file
            $Hashes[$Frame.key] = Capture-PrimaryScreen -Destination (Join-Path $AttemptDirectory $Frame.file)
        }

        Wait-ForActualNinetySeconds -Watch $PlayWatch -Process $Process
        $PlayFinished = [DateTimeOffset]::Now
        $ElapsedPlaySeconds = [Math]::Round($PlayWatch.Elapsed.TotalSeconds, 1)
        $Observations = [ordered]@{}
        foreach ($Observation in $ObservationFields) {
            $Observations[$Observation.key] = Read-YesNo $Observation.label
        }
        $Uncoached = Read-YesNo 'この条件は、事前の操作指示なしの初回プレイでしたか'
        $CaptureFinished = [DateTimeOffset]::Now

        [void](Read-Host 'ゲームを通常操作で終了し、プロセスが閉じた後にEnter')
        $Process.Refresh()
        if (-not $Process.HasExited) { throw 'HOLD: candidate.exe is still running; close it normally before recording.' }

        $Session = [ordered]@{
            schema_version = 1
            session_key = $Key
            language = $Language
            dpi_percent = [int]$DpiPercent
            actual_dpi = $ActualDpi
            resolution = @(1024, 768)
            attempt_id = $AttemptId
            attempt_dir = $AttemptRelative
            source_sha = $ExpectedSource
            request_id = $ExpectedRequest
            factory_artifact_id = $ExpectedArtifact
            factory_artifact_expires_at = $null
            exe_sha256 = $ExpectedExe
            pck_sha256 = $ExpectedPck
            exe_path = $ExePath
            pck_path = $PckPath
            physical_device = $true
            operator = $Operator.Trim()
            windows_build = $WindowsBuild
            code_integrity_status = 'ALLOWED_BY_EXISTING_POLICY'
            capture_started_at = $CaptureStarted.ToString('o')
            play_started_at = $PlayStarted.ToString('o')
            play_finished_at = $PlayFinished.ToString('o')
            capture_finished_at = $CaptureFinished.ToString('o')
            elapsed_play_seconds = $ElapsedPlaySeconds
            first_goal_seconds = $FirstGoalSeconds
            uncoached_first_launch = $Uncoached
            start_pressed = $StartPressed
            screenshots = $Frames
            screenshot_sha256 = $Hashes
        }
        foreach ($Field in $Observations.Keys) { $Session[$Field] = $Observations[$Field] }

        $CandidatePath = Join-Path $AttemptDirectory 'session.json'
        Write-JsonExclusive -Path $CandidatePath -Value $Session
        & py -3 .\prism_physical_capture_checkpoint.py --root $Root record --session-json $CandidatePath
        if ($LASTEXITCODE -ne 0) { throw "HOLD: $Key candidate failed strict validation. Preserve its bytes; do not edit or overwrite." }
        Write-Host "$Key checkpoint recorded; its six images and hashes are resumable." -ForegroundColor Green
    }
}

& py -3 .\prism_physical_capture_checkpoint.py --root $Root finalize
if ($LASTEXITCODE -ne 0) {
    throw 'PHYSICAL_QA_HOLD: one or more conditions remain incomplete/corrupt. Existing bytes were preserved.'
}
Write-Host 'All six session checkpoints and 36 distinct screenshot hashes were revalidated.' -ForegroundColor Cyan
& py -3 .\prism_first30s_physical_windows_gate.py --software-receipt .\qa11\pck-runtime-independent-receipt.json --software-screenshot-dir .\qa11\screenshots --capture .\physical-capture.json --screenshot-dir .\physical-frames --out .\physical-review-receipt.json
$GateExit = $LASTEXITCODE
if ($GateExit -ne 0) {
    throw "PHYSICAL_QA_HOLD: review gate returned exit code $GateExit. Inspect physical-review-receipt.json; do not alter security policy or fabricate evidence."
}
Write-Host 'Evidence package passed structural checks and is awaiting human review. This is NOT SALE_READY and NOT Store submission approval.' -ForegroundColor Green
