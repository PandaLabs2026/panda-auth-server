Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$script:key = [Convert]::FromBase64String($env:PANDESK_REVIEW_SEED)
$script:mac = New-Object System.Security.Cryptography.HMACSHA1
$script:mac.Key = $script:key
$env:PANDESK_REVIEW_SEED = $null
$window = New-Object System.Windows.Forms.Form
$window.Text = 'Pandesk · 本机测试账号'
$window.Size = New-Object System.Drawing.Size(410,330)
$window.StartPosition = 'Manual'
$window.Location = New-Object System.Drawing.Point(24,72)
$window.Font = New-Object System.Drawing.Font('Microsoft YaHei UI',10)
$window.TopMost = $true
$window.MaximizeBox = $false
function Add-Label($text,$y) {
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $text
    $label.AutoSize = $true
    $label.Location = New-Object System.Drawing.Point(18,$y)
    $window.Controls.Add($label)
}
function Add-ReadOnly($text,$y) {
    $field = New-Object System.Windows.Forms.TextBox
    $field.Text = $text
    $field.ReadOnly = $true
    $field.Size = New-Object System.Drawing.Size(350,28)
    $field.Location = New-Object System.Drawing.Point(18,$y)
    $window.Controls.Add($field)
    return $field
}
Add-Label '仅用于当前 Pandesk 隔离联调' 16
Add-Label '账号' 52
$null = Add-ReadOnly 'security-admin' 76
Add-Label '本次测试密码' 110
$passwordBox = Add-ReadOnly $env:PANDESK_REVIEW_PASSWORD 134
$env:PANDESK_REVIEW_PASSWORD = $null
Add-Label '当前六位验证码' 167
$script:codeBox = Add-ReadOnly '' 191
$script:clockLabel = New-Object System.Windows.Forms.Label
$script:clockLabel.AutoSize = $true
$script:clockLabel.Location = New-Object System.Drawing.Point(18,227)
$window.Controls.Add($script:clockLabel)
Add-Label '重新登录时，等上方验证码换一组再输入。' 253
function Update-ReviewCode {
    $seconds = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $step = [int64][Math]::Floor($seconds / 30)
    $counter = [BitConverter]::GetBytes($step)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($counter) }
    $hash = $script:mac.ComputeHash($counter)
    $offset = $hash[$hash.Length - 1] -band 15
    $value = (([int]$hash[$offset] -band 127) -shl 24) -bor ([int]$hash[$offset+1] -shl 16) -bor ([int]$hash[$offset+2] -shl 8) -bor ([int]$hash[$offset+3])
    $code = ($value % 1000000).ToString('D6')
    if ($script:codeBox.Text -ne $code) { $script:codeBox.Text = $code }
    $script:clockLabel.Text = '约 {0} 秒后换码' -f (30 - ($seconds % 30))
}
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 1000
$timer.Add_Tick({ Update-ReviewCode })
Update-ReviewCode
$timer.Start()
try { [void]$window.ShowDialog() } finally {
    $timer.Dispose()
    $script:mac.Dispose()
    [Array]::Clear($script:key,0,$script:key.Length)
    $window.Dispose()
}
