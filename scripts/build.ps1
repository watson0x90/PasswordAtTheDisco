# Build a stamped, self-contained patd.exe (Go API + embedded React SPA) on Windows.
# Never runs `npm install`.
#
#   scripts\build.ps1                  # build SPA + embed + stamped binary
#   scripts\build.ps1 -SkipWeb         # reuse existing web\dist
#   scripts\build.ps1 -Output bin\patd.exe
param(
  [switch]$SkipWeb,
  [string]$Output = "patd.exe"
)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path "$PSScriptRoot\..").Path
Set-Location $root

if (-not $SkipWeb) {
  if (-not (Test-Path "web\node_modules")) {
    Write-Error "web\node_modules missing - run 'cd web; npm ci --ignore-scripts' once first."
  }
  Write-Host "==> building SPA (npm run build)"
  Push-Location web; npm run build; if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Error "npm run build failed" }; Pop-Location
}

if (-not (Test-Path "web\dist")) {
  Write-Error "web\dist missing - run without -SkipWeb to build the SPA first."
}

Write-Host "==> embedding SPA (internal\webui\dist <- web\dist)"
Remove-Item -Recurse -Force "internal\webui\dist" -ErrorAction SilentlyContinue
Copy-Item -Recurse "web\dist" "internal\webui\dist"

$version = (git describe --tags --always)
$commit  = (git rev-parse --short HEAD)
$buildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Host "==> stamping version=$version commit=$commit date=$buildDate"

$env:CGO_ENABLED = "0"
$ldflags = "-s -w -X main.version=$version -X main.commit=$commit -X main.buildDate=$buildDate"
go build -tags embed -trimpath -ldflags="$ldflags" -o $Output ./cmd/patd
if ($LASTEXITCODE -ne 0) { Write-Error "go build failed" }

Write-Host "==> built $Output ($version / $commit)"
