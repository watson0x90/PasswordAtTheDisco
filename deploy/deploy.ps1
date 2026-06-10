<#
  Password!AtTheDisco - guided deployment (Windows, PowerShell 5.1+).

  Default run = SETUP ONLY: builds the single self-contained binary (embedded SPA),
  walks through config, creates the first operator, optionally sets up TLS, and
  writes a run.ps1 launcher. It does NOT install a service.

  Installing the service is a separate, explicit step (run elevated):
      .\deploy\deploy.ps1 -InstallService   [-InstallDir DIR]
      .\deploy\deploy.ps1 -UninstallService [-InstallDir DIR]
  It registers a startup Scheduled Task running as SYSTEM. (For a true Windows
  service, wrap the binary with NSSM or WinSW; see deploy/DEPLOYMENT.md.)

  Setup options:
      -Binary PATH     use a prebuilt binary (skip the build)
      -InstallDir DIR  install location (default C:\PasswordAtTheDisco)
#>
[CmdletBinding()]
param(
  [string]$Binary = "",
  [switch]$InstallService,
  [switch]$UninstallService,
  [string]$InstallDir = ""
)
$ErrorActionPreference = "Stop"
$TaskName = "PasswordAtTheDisco"
$DefaultDir = "C:\PasswordAtTheDisco"

function Hdr($t)  { Write-Host "`n== $t ==" -ForegroundColor Cyan }
function Ok($t)   { Write-Host "[ok] $t" -ForegroundColor Green }
function Warn($t) { Write-Host "[!] $t"  -ForegroundColor Yellow }
function Die($t)  { Write-Host "ERROR: $t" -ForegroundColor Red; exit 1 }
function Ask($prompt, $default) {
  $a = Read-Host ("  {0}{1}" -f $prompt, $(if ($default) { " [$default]" } else { "" }))
  if ([string]::IsNullOrWhiteSpace($a)) { return $default } else { return $a }
}
function YesNo($q, $def = "y") {
  $a = Read-Host ("  {0} [{1}]" -f $q, $(if ($def -eq "y") { "Y/n" } else { "y/N" }))
  if ([string]::IsNullOrWhiteSpace($a)) { $a = $def }
  return $a -match '^[Yy]'
}
function WriteUtf8NoBom($path, $content) {
  [System.IO.File]::WriteAllText($path, $content, (New-Object System.Text.UTF8Encoding($false)))
}
function IsLoopback($addr) { ($addr -split ':')[0] -in @('127.0.0.1', '::1', 'localhost', '') }
function IsAdmin { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }

$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path

function Install-PatdService($dir) {
  $runPs = "$dir\run.ps1"
  if (-not (Test-Path $runPs)) { Die "no launcher at $runPs - run setup first (.\deploy\deploy.ps1)" }
  if (-not (Test-Path "$dir\patd.exe")) { Die "no binary at $dir\patd.exe - run setup first" }
  if (-not (IsAdmin)) { Die "registering the service needs an elevated PowerShell (Run as Administrator)" }
  $action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$runPs`""
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $princ   = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  $set     = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $princ -Settings $set -Force | Out-Null
  Start-ScheduledTask -TaskName $TaskName
  Ok "Registered + started Scheduled Task '$TaskName' (runs as SYSTEM at startup)."
  Write-Host "  manage:  Get-ScheduledTask $TaskName | Get-ScheduledTaskInfo  |  Stop-ScheduledTask $TaskName"
}
function Uninstall-PatdService {
  if (-not (IsAdmin)) { Die "removing the service needs an elevated PowerShell" }
  if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Ok "Removed Scheduled Task '$TaskName'."
  } else { Warn "no Scheduled Task '$TaskName' found." }
}

# ---- service modes: do only that, then exit --------------------------------
if ($InstallService -or $UninstallService) {
  $dir = if ($InstallDir) { $InstallDir } else { $DefaultDir }
  Hdr "Service $(if ($InstallService){'install'}else{'uninstall'}) - $dir"
  if ($InstallService) { Install-PatdService $dir } else { Uninstall-PatdService }
  exit 0
}

# =============================== SETUP ======================================
Hdr "Password!AtTheDisco - setup (windows/$env:PROCESSOR_ARCHITECTURE)"
if ($Binary -and -not (Test-Path $Binary)) { Die "-Binary not found: $Binary" }

# 1. location + address
Hdr "1/5  Location & address"
$dir  = Ask "Install directory" $(if ($InstallDir) { $InstallDir } else { $DefaultDir })
$Data = Ask "Data directory (encrypted store - back this up!)" "$dir\data"
$Bind = Ask "Bind address (host:port)" "127.0.0.1:8443"
New-Item -ItemType Directory -Force -Path $dir | Out-Null

# 2. TLS
Hdr "2/5  TLS"
$TlsCert = ""; $TlsKey = ""
if (IsLoopback $Bind) {
  Ok "Loopback bind - plain HTTP is allowed for local/dev (front with a TLS proxy for remote access)."
} else {
  Warn "Non-loopback bind ($Bind): the server refuses to start without TLS."
  $mode = Ask "TLS: [s]elf-signed, [b]ring-your-own cert/key" "s"
  if ($mode -match '^[Bb]') {
    $TlsCert = Ask "  Path to TLS certificate (PEM)" ""
    $TlsKey  = Ask "  Path to TLS private key (PEM)" ""
    if (-not (Test-Path $TlsCert) -or -not (Test-Path $TlsKey)) { Die "cert/key not found" }
  } else {
    if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) { Die "openssl not on PATH (needed for self-signed PEM). Use bring-your-own, or install OpenSSL." }
    $tlsDir = "$dir\tls"; New-Item -ItemType Directory -Force -Path $tlsDir | Out-Null
    $TlsCert = "$tlsDir\cert.pem"; $TlsKey = "$tlsDir\key.pem"
    $cn = ($Bind -split ':')[0]
    & openssl req -x509 -newkey rsa:2048 -nodes -keyout $TlsKey -out $TlsCert -days 825 -subj "/CN=$cn" 2>$null
    Ok "Generated self-signed cert for $cn (clients will warn; replace with a real cert for production)."
  }
}

# 3. binary
Hdr "3/5  Binary"
$Bin = "$dir\patd.exe"
if ($Binary) {
  Copy-Item $Binary $Bin -Force; Ok "Installed prebuilt binary -> $Bin"
} else {
  if (-not (Get-Command go -ErrorAction SilentlyContinue)) { Die "go not found (needed to build; or pass -Binary)" }
  if (-not (Test-Path "$RepoRoot\internal\webui\dist") -or (YesNo "Rebuild the web UI (runs npm)?" "n")) {
    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { Die "npm not found (needed to build the SPA; or pass -Binary)" }
    Warn "Building the SPA with npm. On a credential-bearing host prefer -Binary built elsewhere."
    Push-Location "$RepoRoot\web"; & npm ci --ignore-scripts; & npm run build; Pop-Location
    Remove-Item -Recurse -Force "$RepoRoot\internal\webui\dist" -ErrorAction SilentlyContinue
    Copy-Item -Recurse "$RepoRoot\web\dist" "$RepoRoot\internal\webui\dist"
  }
  Write-Host "  compiling (CGO-free, embedded SPA)..."
  Push-Location $RepoRoot; $env:CGO_ENABLED = "0"
  & go build -tags embed -trimpath -ldflags="-s -w" -o $Bin ./cmd/patd
  Pop-Location
  if ($LASTEXITCODE -ne 0) { Die "go build failed" }
  Ok "Built $Bin"
}

# 4. first operator
Hdr "4/5  First operator (lead)"
$UsersFile = "$dir\users.json"
if ((Test-Path $UsersFile) -and -not (YesNo "users.json exists - overwrite the operator?" "n")) {
  Ok "Keeping existing $UsersFile"
} else {
  $op = Ask "Operator username" "lead"
  while ($true) {
    $s1 = Read-Host "  Operator password" -AsSecureString
    $s2 = Read-Host "  Confirm password " -AsSecureString
    $p1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s1))
    $p2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s2))
    if ($p1 -and $p1 -eq $p2) { break }
    Warn "empty or mismatch - try again"
  }
  $hash = ($p1 | & $Bin hashpw)
  if (-not $hash) { Die "hashpw failed" }
  WriteUtf8NoBom $UsersFile "[`n  {`"username`":`"$op`",`"password_hash`":`"$hash`",`"role`":`"lead`"}`n]`n"
  $p1 = $null; $p2 = $null
  Ok "Wrote $UsersFile (lead: $op). Add more with: $Bin hashpw"
}

# 5. options + config + launcher
Hdr "5/5  Options & config"
$Hibp = Ask "HIBP NTLM index path (blank = disable breach correlation)" ""
$BheDefault = ""; if (Test-Path "$RepoRoot\config\bloodhound.json") { $BheDefault = "$RepoRoot\config\bloodhound.json" }
$Bhe  = Ask "BloodHound config path (blank = disable DA enrichment)" $BheDefault
$Lock = Ask "Idle auto-lock minutes (0 = never)" "60"
if (Test-Path "$RepoRoot\lists") { Copy-Item -Recurse -Force "$RepoRoot\lists" "$dir\" -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $Data | Out-Null
$token = [Convert]::ToBase64String((1..24 | ForEach-Object { Get-Random -Max 256 })) -replace '[/+=]', ''
$envLines = @(
  "`$env:PATD_ADDR='$Bind'"
  "`$env:PATD_DATA='$Data'"
  "`$env:PATD_USERS_FILE='$UsersFile'"
  "`$env:PATD_AUDIT_LOG='$dir\audit.log'"
  "`$env:PATD_AUTOLOCK_MIN='$Lock'"
  "`$env:PATD_INGEST_TOKEN='$token'"
)
if (Test-Path "$dir\lists") { $envLines += "`$env:PATD_LISTS='$dir\lists'" }
if ($Hibp) { $envLines += "`$env:PATD_HIBP='$Hibp'" }
if ($Bhe)  { $envLines += "`$env:PATD_BHE='$Bhe'" }
if ($TlsCert) { $envLines += "`$env:PATD_TLS_CERT='$TlsCert'"; $envLines += "`$env:PATD_TLS_KEY='$TlsKey'" }
$RunPs = "$dir\run.ps1"
WriteUtf8NoBom $RunPs (($envLines -join "`n") + "`n& '$Bin'`n")
Ok "Wrote $RunPs"

$scheme = if ($TlsCert) { "https" } else { "http" }
Hdr "Setup complete"
Write-Host "  URL:        ${scheme}://$Bind"
Write-Host "  Sign in:    the lead operator you just created"
Write-Host "  First run:  set the store passphrase on the unlock screen - it is NEVER stored;"
Write-Host "              if lost, the data in $Data is unrecoverable. Save it in a password manager."
Write-Host "  Back up:    $Data  (as a unit) - that IS your audits."
Write-Host ""
Write-Host "  Start it now (foreground):  & '$RunPs'"
Write-Host "  Or install as a service (elevated PowerShell):"
Write-Host "      .\deploy\deploy.ps1 -InstallService -InstallDir '$dir'"
Write-Host "      (.\deploy\deploy.ps1 -UninstallService  to remove)"
Write-Host ""
