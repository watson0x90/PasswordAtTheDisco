<#
  Password!AtTheDisco - guided deployment (Windows, PowerShell 5.1+).

  Builds the single self-contained binary (embedded SPA), walks through config,
  creates the first operator, optionally sets up TLS, and registers a startup
  Scheduled Task as the service. Re-runnable.

  Use a prebuilt binary (skip the build; recommended for a credential-bearing
  host so npm never runs there):
      .\deploy\deploy.ps1 -Binary C:\path\to\patd.exe

  For a true Windows service (vs. the startup Scheduled Task this registers),
  wrap the binary with NSSM or WinSW; see deploy/DEPLOYMENT.md.
#>
[CmdletBinding()]
param([string]$Binary = "")
$ErrorActionPreference = "Stop"

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
# UTF-8 WITHOUT BOM - Go's json/config readers don't strip a BOM.
function WriteUtf8NoBom($path, $content) {
  [System.IO.File]::WriteAllText($path, $content, (New-Object System.Text.UTF8Encoding($false)))
}
function IsLoopback($addr) { ($addr -split ':')[0] -in @('127.0.0.1', '::1', 'localhost', '') }

$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
Hdr "Password!AtTheDisco - deploy (windows/$env:PROCESSOR_ARCHITECTURE)"
if ($Binary -and -not (Test-Path $Binary)) { Die "-Binary not found: $Binary" }

# ---- 1. location + address -------------------------------------------------
Hdr "1/6  Location & address"
$InstallDir = Ask "Install directory" "C:\PasswordAtTheDisco"
$DataDir    = Ask "Data directory (encrypted store - back this up!)" "$InstallDir\data"
$Bind       = Ask "Bind address (host:port)" "127.0.0.1:8443"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# ---- 2. TLS ----------------------------------------------------------------
Hdr "2/6  TLS"
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
    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    if (-not $openssl) { Die "openssl not on PATH (needed for self-signed PEM). Use bring-your-own, or install OpenSSL." }
    $tlsDir = "$InstallDir\tls"; New-Item -ItemType Directory -Force -Path $tlsDir | Out-Null
    $TlsCert = "$tlsDir\cert.pem"; $TlsKey = "$tlsDir\key.pem"
    $cn = ($Bind -split ':')[0]
    & openssl req -x509 -newkey rsa:2048 -nodes -keyout $TlsKey -out $TlsCert -days 825 -subj "/CN=$cn" 2>$null
    Ok "Generated self-signed cert for $cn (clients will warn; replace with a real cert for production)."
  }
}

# ---- 3. binary -------------------------------------------------------------
Hdr "3/6  Binary"
$Bin = "$InstallDir\patd.exe"
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
  Push-Location $RepoRoot
  $env:CGO_ENABLED = "0"
  & go build -tags embed -trimpath -ldflags="-s -w" -o $Bin ./cmd/patd
  Pop-Location
  if ($LASTEXITCODE -ne 0) { Die "go build failed" }
  Ok "Built $Bin"
}

# ---- 4. first operator -----------------------------------------------------
Hdr "4/6  First operator (lead)"
$UsersFile = "$InstallDir\users.json"
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
  Ok "Wrote $UsersFile (lead: $op). Add more operators with: $Bin hashpw"
}

# ---- 5. options + config ---------------------------------------------------
Hdr "5/6  Options & config"
$Hibp = Ask "HIBP NTLM index path (blank = disable breach correlation)" ""
$BheDefault = ""; if (Test-Path "$RepoRoot\config\bloodhound.json") { $BheDefault = "$RepoRoot\config\bloodhound.json" }
$Bhe  = Ask "BloodHound config path (blank = disable DA enrichment)" $BheDefault
$Lock = Ask "Idle auto-lock minutes (0 = never)" "60"
if (Test-Path "$RepoRoot\lists") { Copy-Item -Recurse -Force "$RepoRoot\lists" "$InstallDir\" -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$token = [Convert]::ToBase64String((1..24 | ForEach-Object { Get-Random -Max 256 })) -replace '[/+=]', ''

# launcher script (sets env then runs the binary) - used by the scheduled task
$envLines = @(
  "`$env:PATD_ADDR='$Bind'"
  "`$env:PATD_DATA='$DataDir'"
  "`$env:PATD_USERS_FILE='$UsersFile'"
  "`$env:PATD_AUDIT_LOG='$InstallDir\audit.log'"
  "`$env:PATD_AUTOLOCK_MIN='$Lock'"
  "`$env:PATD_INGEST_TOKEN='$token'"
)
if (Test-Path "$InstallDir\lists") { $envLines += "`$env:PATD_LISTS='$InstallDir\lists'" }
if ($Hibp) { $envLines += "`$env:PATD_HIBP='$Hibp'" }
if ($Bhe)  { $envLines += "`$env:PATD_BHE='$Bhe'" }
if ($TlsCert) { $envLines += "`$env:PATD_TLS_CERT='$TlsCert'"; $envLines += "`$env:PATD_TLS_KEY='$TlsKey'" }
$RunPs = "$InstallDir\run.ps1"
WriteUtf8NoBom $RunPs (($envLines -join "`n") + "`n& '$Bin'`n")
Ok "Wrote launcher $RunPs"

# ---- 6. service (startup Scheduled Task) -----------------------------------
Hdr "6/6  Service (Scheduled Task)"
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$started = $false
if ($admin) {
  try {
    $action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$RunPs`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $princ   = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $set     = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName "PasswordAtTheDisco" -Action $action -Trigger $trigger -Principal $princ -Settings $set -Force | Out-Null
    Start-ScheduledTask -TaskName "PasswordAtTheDisco"
    $started = $true
    Ok "Registered + started Scheduled Task 'PasswordAtTheDisco' (runs as SYSTEM at startup)."
  } catch { Warn "Could not register the Scheduled Task: $($_.Exception.Message)" }
} else {
  Warn "Not elevated - skipping service registration. Run PowerShell as Administrator to register the startup task,"
  Warn "or just run the launcher manually:  & '$RunPs'"
}

$scheme = if ($TlsCert) { "https" } else { "http" }
Hdr "Done"
Write-Host "  URL:        $scheme`://$Bind"
Write-Host "  Sign in:    the operator you just created (lead)"
Write-Host "  First run:  set the store passphrase on the unlock screen - it is NEVER stored;"
Write-Host "              if lost, the data in $DataDir is unrecoverable. Save it in a password manager."
Write-Host "  Back up:    $DataDir  (as a unit) - that IS your audits."
if ($started) { Write-Host "  Manage:     Get-ScheduledTask PasswordAtTheDisco | Get-ScheduledTaskInfo   |   Stop-ScheduledTask PasswordAtTheDisco" }
else          { Write-Host "  Start:      & '$RunPs'" }
Write-Host ""
