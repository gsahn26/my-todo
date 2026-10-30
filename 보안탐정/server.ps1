# Security Detective - local helper.
# Serves the game on http://localhost only, and can move a suspicious file to the Recycle Bin
# when the player confirms it in the game. Only files flagged by the latest scan
# (unsigned or running from Temp/Downloads/Public) can be removed. Signed files and
# Windows system files are always refused.
param([switch]$NoBrowser)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Add-Type -AssemblyName Microsoft.VisualBasic

$raw = [IO.File]::ReadAllText((Join-Path $here 'report.js'), [Text.Encoding]::UTF8)
$report = ($raw -replace '^window\.REPORT = ', '' -replace ';\s*$', '') | ConvertFrom-Json
$oddPattern = '\\(AppData\\Local\\Temp|Downloads|Users\\Public)\\'

# Allowlist: suspicious programs from the "network" case of this scan
$allowed = @{}
foreach ($c in @($report.connections)) {
  if (-not $c.path) { continue }
  if ($c.signed -eq $false -or $c.path -match $oddPattern) { $allowed[$c.path.ToLower()] = [string]$c.path }
}

function Remove-Suspect([string]$p) {
  if (-not $p -or -not $allowed.ContainsKey($p.ToLower())) { return @{ ok = $false; code = 'not_allowed' } }
  $full = [IO.Path]::GetFullPath($allowed[$p.ToLower()])
  if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { return @{ ok = $false; code = 'missing' } }
  foreach ($root in @($env:windir, (Join-Path $env:ProgramFiles 'WindowsApps'))) {
    if ($full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { return @{ ok = $false; code = 'system' } }
  }
  if ((Get-AuthenticodeSignature -LiteralPath $full).Status -eq 'Valid') { return @{ ok = $false; code = 'signed' } }
  $stopped = 0
  try {
    foreach ($proc in @(Get-Process | Where-Object { $_.Path -and $_.Path -ieq $full })) { Stop-Process -Id $proc.Id -Force; $stopped++ }
  } catch { return @{ ok = $false; code = 'stop_failed' } }
  Start-Sleep -Milliseconds 600
  try { [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($full, 'OnlyErrorDialogs', 'SendToRecycleBin') }
  catch { return @{ ok = $false; code = 'failed'; detail = $_.Exception.Message } }
  Write-Host "  Moved to Recycle Bin: $full"
  return @{ ok = $true; code = 'done'; stopped = $stopped }
}

function Send($ctx, [int]$code, [string]$type, [string]$body) {
  $bytes = [Text.Encoding]::UTF8.GetBytes($body)
  $ctx.Response.StatusCode = $code
  $ctx.Response.ContentType = "$type; charset=utf-8"
  $ctx.Response.Headers.Add('Cache-Control', 'no-store')
  $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
  $ctx.Response.Close()
}

$token = [guid]::NewGuid().ToString('N')
$listener = $null
for ($i = 0; $i -lt 10 -and -not $listener; $i++) {
  $port = Get-Random -Minimum 49200 -Maximum 64000
  $l = New-Object Net.HttpListener
  $l.Prefixes.Add("http://localhost:$port/")
  try { $l.Start(); $listener = $l } catch { $l.Close() }
}
if (-not $listener) { Write-Host '  Could not start the helper. Opening the game without the delete feature.'; Start-Process (Join-Path $here 'index.html'); exit 1 }

$url = "http://localhost:$port/?t=$token"
Write-Host ''
Write-Host "  Game is ready: http://localhost:$port/"
Write-Host '  Keep this window open while playing. Close it when you are done.'
Write-Host '  (It also closes by itself after 60 minutes.)'
if ($NoBrowser) { Write-Host "  URL: $url" } else { Start-Process $url }

$deadline = (Get-Date).AddMinutes(60)
while ($listener.IsListening -and (Get-Date) -lt $deadline) {
  $task = $listener.GetContextAsync()
  while (-not $task.AsyncWaitHandle.WaitOne(1000)) { if ((Get-Date) -ge $deadline) { break } }
  if (-not $task.IsCompleted) { break }
  $ctx = $task.Result
  try {
    $req = $ctx.Request; $path = $req.Url.AbsolutePath
    if ($req.HttpMethod -eq 'GET' -and ($path -eq '/' -or $path -eq '/index.html')) {
      Send $ctx 200 'text/html' ([IO.File]::ReadAllText((Join-Path $here 'index.html'), [Text.Encoding]::UTF8))
    } elseif ($req.HttpMethod -eq 'GET' -and $path -eq '/report.js') {
      Send $ctx 200 'application/javascript' $raw
    } elseif ($req.HttpMethod -eq 'POST' -and $path -eq '/remove') {
      $origin = $req.Headers['Origin']
      if ($req.Headers['X-Token'] -ne $token -or ($origin -and $origin -ne "http://localhost:$port")) {
        Send $ctx 403 'application/json' '{"ok":false,"code":"forbidden"}'
      } else {
        $body = (New-Object IO.StreamReader($req.InputStream, [Text.Encoding]::UTF8)).ReadToEnd() | ConvertFrom-Json
        Send $ctx 200 'application/json' ((Remove-Suspect ([string]$body.path)) | ConvertTo-Json -Compress)
      }
    } else {
      Send $ctx 404 'text/plain' 'not found'
    }
  } catch {
    try { Send $ctx 500 'application/json' '{"ok":false,"code":"failed"}' } catch {}
  }
}
$listener.Stop()
