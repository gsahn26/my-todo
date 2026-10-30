# Security Detective - clue collector.
# READ-ONLY: this script only reads information and never changes any setting.
# It writes report.js next to this file, which index.html reads.
$ErrorActionPreference = 'SilentlyContinue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$r = [ordered]@{
  time = (Get-Date).ToString('yyyy-MM-dd HH:mm')
  computer = $env:COMPUTERNAME
  user = $env:USERNAME
  admin = $isAdmin
}

$sigCache = @{}
function Get-Sig([string]$path) {
  if (-not $path -or -not (Test-Path -LiteralPath $path)) { return [ordered]@{ ok = $null; signer = '' } }
  if (-not $sigCache.ContainsKey($path)) {
    $s = Get-AuthenticodeSignature -LiteralPath $path
    $signer = ''
    if ($s.SignerCertificate) { $signer = (($s.SignerCertificate.Subject -split ',')[0] -replace '^CN=', '') -replace '"', '' }
    $sigCache[$path] = [ordered]@{ ok = ($s.Status -eq 'Valid'); signer = $signer }
  }
  $sigCache[$path]
}

function Get-ExePath([string]$cmd) {
  if (-not $cmd) { return '' }
  $cmd = [Environment]::ExpandEnvironmentVariables($cmd).Trim()
  if ($cmd -match '^"([^"]+)"') { return $matches[1] }
  if ($cmd -match '^(.+?\.exe)\b') { return $matches[1] }
  return ($cmd -split ' ')[0]
}

Write-Host '  [1/7] Antivirus (Windows Defender)'
$mp = Get-MpComputerStatus
$r.defender = [ordered]@{
  ok = [bool]$mp
  av = [bool]$mp.AntivirusEnabled
  realtime = [bool]$mp.RealTimeProtectionEnabled
  tamper = [bool]$mp.IsTamperProtected
  sigAge = [int64]$mp.AntivirusSignatureAge
  quickAge = [int64]$mp.QuickScanAge
  fullAge = [int64]$mp.FullScanAge
}
$r.threats = @(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 20 | ForEach-Object {
  $name = (Get-MpThreat -ThreatID $_.ThreatID | Select-Object -First 1).ThreatName
  [ordered]@{ name = [string]$name; time = $_.InitialDetectionTime.ToString('yyyy-MM-dd HH:mm'); fixed = [bool]$_.ActionSuccess; files = (@($_.Resources) -join ', ') }
})

Write-Host '  [2/7] Firewall and remote desktop'
$r.firewall = @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ name = [string]$_.Name; on = ([string]$_.Enabled -eq 'True') } })
$ts = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
$r.rdpOn = ($ts.fDenyTSConnections -eq 0)

Write-Host '  [3/7] User accounts'
$adminNames = @()
try { $adminNames = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { ($_.Name -split '\\')[-1] }) }
catch { $adminNames = @(net localgroup Administrators | Select-Object -Skip 6 | Where-Object { $_ }) }
$r.users = @(Get-LocalUser | ForEach-Object {
  $last = ''
  if ($_.LastLogon) { $last = $_.LastLogon.ToString('yyyy-MM-dd HH:mm') }
  [ordered]@{ name = [string]$_.Name; enabled = [bool]$_.Enabled; admin = ($adminNames -contains $_.Name); last = $last }
})

Write-Host '  [4/7] Login records (last 7 days, needs administrator)'
$r.logAccess = $isAdmin
$r.failed = @()
$r.remote = @()
if ($isAdmin) {
  $since = (Get-Date).AddDays(-7)
  # 4625 = failed logon: [5] user, [10] logon type, [19] source IP
  $fails = @{}
  foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $since } -MaxEvents 3000)) {
    $user = [string]$e.Properties[5].Value; $ip = [string]$e.Properties[19].Value
    $key = "$user|$ip"
    if (-not $fails.ContainsKey($key)) { $fails[$key] = [ordered]@{ user = $user; ip = $ip; n = 0; last = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm') } }
    $fails[$key]['n'] += 1
  }
  $r.failed = @($fails.Values)
  # 4624 = successful logon: [5] user, [8] logon type, [18] source IP
  $rem = @{}
  foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = $since } -MaxEvents 5000)) {
    $user = [string]$e.Properties[5].Value; $type = [int]$e.Properties[8].Value; $ip = [string]$e.Properties[18].Value
    if ($user -like '*$') { continue }
    $fromNet = ($type -eq 3 -and $ip -and @('-', '127.0.0.1', '::1') -notcontains $ip)
    if (-not ($type -eq 10 -or $fromNet)) { continue }
    $key = "$user|$ip|$type"
    if (-not $rem.ContainsKey($key)) { $rem[$key] = [ordered]@{ user = $user; ip = $ip; type = $type; n = 0; last = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm') } }
    $rem[$key]['n'] += 1
  }
  $r.remote = @($rem.Values)
}

Write-Host '  [5/7] Programs talking to the internet'
$procById = @{}
foreach ($p in Get-Process) { $procById[[int]$p.Id] = $p }
$seen = @{}
$r.connections = @(Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0)' } | ForEach-Object {
  $p = $procById[[int]$_.OwningProcess]
  $name = "PID $($_.OwningProcess)"; $path = ''
  if ($p) { $name = $p.ProcessName; $path = [string]$p.Path }
  $key = "$name|$($_.RemoteAddress)"
  if (-not $seen.ContainsKey($key)) {
    $seen[$key] = 1
    $sig = Get-Sig $path
    [ordered]@{ proc = $name; path = $path; ip = [string]$_.RemoteAddress; port = [int]$_.RemotePort; signed = $sig.ok; signer = $sig.signer }
  }
})

Write-Host '  [6/7] Programs that start automatically'
$startup = New-Object System.Collections.ArrayList
$skip = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
$runKeys = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($k in $runKeys) {
  $props = Get-ItemProperty $k
  if (-not $props) { continue }
  foreach ($pp in $props.PSObject.Properties) {
    if ($skip -contains $pp.Name) { continue }
    $exe = Get-ExePath ([string]$pp.Value); $sig = Get-Sig $exe
    [void]$startup.Add([ordered]@{ kind = 'reg'; name = [string]$pp.Name; path = $exe; signed = $sig.ok; signer = $sig.signer })
  }
}
$shell = New-Object -ComObject WScript.Shell
foreach ($f in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")) {
  foreach ($file in @(Get-ChildItem -LiteralPath $f -File | Where-Object { $_.Name -ne 'desktop.ini' })) {
    $target = $file.FullName
    if ($file.Extension -eq '.lnk') { $target = $shell.CreateShortcut($file.FullName).TargetPath }
    $sig = Get-Sig $target
    [void]$startup.Add([ordered]@{ kind = 'folder'; name = $file.Name; path = [string]$target; signed = $sig.ok; signer = $sig.signer })
  }
}
foreach ($t in @(Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' })) {
  foreach ($a in @($t.Actions)) {
    if (-not $a.Execute) { continue }
    $exe = Get-ExePath $a.Execute; $sig = Get-Sig $exe
    [void]$startup.Add([ordered]@{ kind = 'task'; name = [string]$t.TaskName; path = $exe; signed = $sig.ok; signer = $sig.signer })
  }
}
$r.startup = @($startup)

Write-Host '  [7/7] Programs in odd places and newly installed programs'
$r.oddProcs = @(Get-Process | Where-Object { $_.Path -match '\\(AppData\\Local\\Temp|Downloads|Users\\Public)\\' } | Sort-Object Path -Unique | ForEach-Object {
  $sig = Get-Sig $_.Path
  [ordered]@{ name = $_.ProcessName; path = [string]$_.Path; signed = $sig.ok; signer = $sig.signer }
})
$cutDate = (Get-Date).Date.AddDays(-14)
function Test-Recent([string]$s) {
  $d = [datetime]::MinValue
  if (-not [datetime]::TryParseExact($s, 'yyyyMMdd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$d)) { return $false }
  return ($d -ge $cutDate -and $d -le (Get-Date))
}
$r.newPrograms = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
  Where-Object { $_.DisplayName -and (Test-Recent ([string]$_.InstallDate)) } | Sort-Object DisplayName -Unique | ForEach-Object {
    [ordered]@{ name = [string]$_.DisplayName; publisher = [string]$_.Publisher; date = [string]$_.InstallDate }
  })

$json = $r | ConvertTo-Json -Depth 6 -Compress
[IO.File]::WriteAllText((Join-Path $here 'report.js'), "window.REPORT = $json;", (New-Object Text.UTF8Encoding $false))
Write-Host '  Done! Opening the detective game...'
