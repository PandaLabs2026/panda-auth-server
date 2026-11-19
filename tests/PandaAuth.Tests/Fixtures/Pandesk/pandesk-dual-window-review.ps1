param([Parameter(Mandatory)][int]$WindowPid, [Parameter(Mandatory)][string]$EvidenceDirectory)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class PandeskTestWindow {
    [StructLayout(LayoutKind.Sequential)]
    public struct Rect { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Point { public int X, Y; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr window, out Rect rect);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr window, IntPtr drawing, uint flags);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
    [DllImport("user32.dll")] private static extern IntPtr SetThreadDpiAwarenessContext(IntPtr context);
    [DllImport("user32.dll")] private static extern bool ScreenToClient(IntPtr window, ref Point point);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessageTimeout(IntPtr window, uint message, UIntPtr character,
        IntPtr keyState, uint flags, uint timeout, out UIntPtr result);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool PostMessage(IntPtr window, uint message, UIntPtr key, IntPtr keyState);
    public static bool WriteCharacter(IntPtr window, char value) {
        UIntPtr result;
        return SendMessageTimeout(window, 0x0102, new UIntPtr(value), new IntPtr(1), 2, 1000, out result) != IntPtr.Zero;
    }
    public static bool PressKey(IntPtr window, uint key) {
        var value = new UIntPtr(key);
        return PostMessage(window, 0x0100, value, new IntPtr(1)) &&
            PostMessage(window, 0x0101, value, new IntPtr(unchecked((int)0xc0000001)));
    }
    public static bool ClickField(IntPtr window, int x, int y) {
        var point = new Point { X = x, Y = y };
        if (!ScreenToClient(window, ref point) || point.X < 0 || point.Y < 0) return false;
        var position = new IntPtr((point.Y << 16) | point.X);
        UIntPtr result;
        return SendMessageTimeout(window, 0x0201, new UIntPtr(1), position, 2, 1000, out result) != IntPtr.Zero &&
            SendMessageTimeout(window, 0x0202, UIntPtr.Zero, position, 2, 1000, out result) != IntPtr.Zero;
    }
    public static bool UsePhysicalCoordinates() { return SetThreadDpiAwarenessContext(new IntPtr(-4)) != IntPtr.Zero; }
}
'@

if (![PandeskTestWindow]::UsePhysicalCoordinates()) { throw 'Cannot set DPI awareness in the test driver.' }
$app = Get-Process -Id $WindowPid
$window = $app.MainWindowHandle
if ($app.MainWindowTitle -ne 'Pandesk · 隔离认证联调' -or $window -eq [IntPtr]::Zero) {
    throw 'The expected isolated Pandesk window is unavailable.'
}
$root = [System.Windows.Automation.AutomationElement]::FromHandle($window)

function Wait-Control([string]$Name) {
    $condition = [System.Windows.Automation.PropertyCondition]::new(
        [System.Windows.Automation.AutomationElement]::NameProperty, $Name)
    for ($i = 0; $i -lt 50; $i++) {
        $control = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
        if ($control -and $control.Current.IsEnabled) { return $control }
        Start-Sleep -Milliseconds 150
    }
    throw "The expected Pandesk control did not become available: $Name"
}

function Invoke-Control([string]$Name) {
    $control = Wait-Control $Name
    $control.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
}

function Press-AuthKey([uint32]$Key) {
    [uint32]$owner = 0
    [void][PandeskTestWindow]::GetWindowThreadProcessId($window, [ref]$owner)
    if ($owner -ne $WindowPid -or ![PandeskTestWindow]::PressKey($window, $Key)) {
        throw 'Pandesk did not accept the keyboard action.'
    }
}

function Write-Field([string]$Name, [string]$Value, [switch]$AlreadyFocused) {
    $control = Wait-Control $Name
    [uint32]$owner = 0
    [void][PandeskTestWindow]::GetWindowThreadProcessId($window, [ref]$owner)
    $bounds = $control.Current.BoundingRectangle
    if ($owner -ne $WindowPid -or $control.Current.ProcessId -ne $WindowPid -or $bounds.IsEmpty) {
        throw "The isolated Pandesk field is unavailable: $Name"
    }
    if (!$AlreadyFocused -and ![PandeskTestWindow]::ClickField($window, [int]($bounds.Left + $bounds.Width / 2), [int]($bounds.Top + $bounds.Height / 2))) {
        throw "The isolated Pandesk field could not be selected: $Name"
    }
    Start-Sleep -Milliseconds 240
    if ($Name -eq '账号') {
        $field = Wait-Control $Name
        $valuePattern = $field.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
        $valuePattern.SetValue($Value)
        for ($i = 0; $i -lt 20; $i++) {
            if ($valuePattern.Current.Value -eq $Value) { return }
            Start-Sleep -Milliseconds 75
        }
        throw 'Pandesk did not receive the synthetic account name.'
    }
    foreach ($character in $Value.ToCharArray()) {
        if (![PandeskTestWindow]::WriteCharacter($window, $character)) { throw 'Pandesk did not accept window input.' }
    }
    Start-Sleep -Milliseconds 180
}

function Save-PandeskWindow([string]$Name) {
    $bounds = New-Object PandeskTestWindow+Rect
    if (![PandeskTestWindow]::GetWindowRect($window, [ref]$bounds)) { throw 'Cannot obtain Pandesk window bounds.' }
    $bitmap = [System.Drawing.Bitmap]::new(($bounds.Right - $bounds.Left), ($bounds.Bottom - $bounds.Top))
    try {
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        try {
            $drawing = $graphics.GetHdc()
            try { $captured = [PandeskTestWindow]::PrintWindow($window, $drawing, 2) }
            finally { $graphics.ReleaseHdc($drawing) }
        } finally { $graphics.Dispose() }
        if (!$captured) { throw 'Cannot capture the isolated Pandesk window.' }
        $bitmap.Save((Join-Path $EvidenceDirectory $Name), [System.Drawing.Imaging.ImageFormat]::Png)
    } finally { $bitmap.Dispose() }
}

function Submit-Password([string]$Organization) {
    Invoke-Control "Pandesk 联调组织 $Organization"
    Write-Field '账号' 'security-admin'
    Press-AuthKey 0x0d
    Write-Field '密码' $passwords[$Organization] -AlreadyFocused
    Press-AuthKey 0x0d
}

function Start-Login([string]$Organization) {
    Submit-Password $Organization
    [void](Wait-Control '验证码')
}

function Wait-Phase([string]$Name) {
    $phase = Join-Path $EvidenceDirectory $Name
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    while (!(Test-Path -LiteralPath $phase)) {
        if ($deadline.Elapsed.TotalSeconds -ge 7) { throw "The isolated issuer did not report phase: $Name" }
        Start-Sleep -Milliseconds 50
    }
}

function Check-LateChallenge {
    New-Item -ItemType File -Path (Join-Path $EvidenceDirectory 'delay-armed') | Out-Null
    try {
        Submit-Password A
        Wait-Phase 'delay-held'
        Press-AuthKey 0x1b
        Invoke-Control 'Pandesk 联调组织 B'
        [void](Wait-Control '账号')
    } finally {
        New-Item -ItemType File -Path (Join-Path $EvidenceDirectory 'delay-release') | Out-Null
    }
    Wait-Phase 'delay-cancelled'
    $field = Wait-Control '账号'
    $value = $field.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).Current.Value
    if ($value) { throw 'A delayed challenge changed the fresh account field in organization B.' }
    [void](Wait-Control '继续')
    Save-PandeskWindow '00-b-after-a-delayed-challenge.png'
    Press-AuthKey 0x1b
}

function Get-FreshTotp([string]$Organization) {
    do {
        $seconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $step = [int64][Math]::Floor($seconds / 30)
        if ($step -le $lastStep[$Organization] -or ($seconds % 30) -ge 26) { Start-Sleep -Milliseconds 250 }
    } while ($step -le $lastStep[$Organization] -or ($seconds % 30) -ge 26)
    $lastStep[$Organization] = $step
    $counter = [BitConverter]::GetBytes($step)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($counter) }
    $mac = New-Object System.Security.Cryptography.HMACSHA1
    try {
        $mac.Key = $keys[$Organization]
        $hash = $mac.ComputeHash($counter)
        $offset = $hash[$hash.Length - 1] -band 15
        $value = (([int]$hash[$offset] -band 127) -shl 24) -bor
            ([int]$hash[$offset + 1] -shl 16) -bor ([int]$hash[$offset + 2] -shl 8) -bor [int]$hash[$offset + 3]
        return ($value % 1000000).ToString('D6')
    } finally { $mac.Dispose() }
}

function Complete-Login([string]$Organization, [string]$Screenshot) {
    Start-Login $Organization
    Write-Field '验证码' (Get-FreshTotp $Organization)
    Press-AuthKey 0x0d
    [void](Wait-Control '切换组织')
    Save-PandeskWindow $Screenshot
}

$passwords = @{ A = $env:PANDESK_REVIEW_PASSWORD_A; B = $env:PANDESK_REVIEW_PASSWORD_B }
$keys = @{ A = [Convert]::FromBase64String($env:PANDESK_REVIEW_SEED_A); B = [Convert]::FromBase64String($env:PANDESK_REVIEW_SEED_B) }
$currentStep = [int64][Math]::Floor([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() / 30)
$lastStep = @{ A = $currentStep; B = $currentStep }
Remove-Item Env:PANDESK_REVIEW_PASSWORD_A, Env:PANDESK_REVIEW_PASSWORD_B, Env:PANDESK_REVIEW_SEED_A, Env:PANDESK_REVIEW_SEED_B
try {
    Check-LateChallenge
    Complete-Login A '01-signed-in-a.png'
    Invoke-Control '切换组织'
    Complete-Login B '02-signed-in-b.png'
    Invoke-Control '切换组织'
    Complete-Login A '03-signed-in-a-again.png'
} finally {
    foreach ($key in $keys.Values) { [Array]::Clear($key, 0, $key.Length) }
    $passwords.Clear()
    $app.Dispose()
}
