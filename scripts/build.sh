#!/usr/bin/env bash
# Build a stamped, self-contained patd binary (Go API + embedded React SPA).
# Cross-platform: Linux, macOS, and Windows via Git Bash. Never runs `npm install`.
#
#   scripts/build.sh                 # build SPA + embed + stamped binary
#   scripts/build.sh --skip-web      # reuse existing web/dist
#   scripts/build.sh --output bin/patd
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SKIP_WEB=0
OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --skip-web) SKIP_WEB=1; shift ;;
    --output) OUT="$2"; shift 2 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

# Default output name: patd.exe on Windows (Git Bash), patd elsewhere.
if [ -z "$OUT" ]; then
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) OUT="patd.exe" ;;
    *) OUT="patd" ;;
  esac
fi

if [ "$SKIP_WEB" -eq 0 ]; then
  if [ ! -d web/node_modules ]; then
    echo "ERROR: web/node_modules missing — run 'cd web && npm ci --ignore-scripts' once first." >&2
    exit 1
  fi
  echo "==> building SPA (npm run build)"
  ( cd web && npm run build )
fi

if [ ! -d web/dist ]; then
  echo "ERROR: web/dist missing — run without --skip-web to build the SPA first." >&2
  exit 1
fi

echo "==> embedding SPA (internal/webui/dist <- web/dist)"
rm -rf internal/webui/dist
cp -r web/dist internal/webui/dist

VERSION="$(git describe --tags --always)"
COMMIT="$(git rev-parse --short HEAD)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "==> stamping version=$VERSION commit=$COMMIT date=$BUILD_DATE"

CGO_ENABLED=0 go build -tags embed -trimpath \
  -ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.buildDate=$BUILD_DATE" \
  -o "$OUT" ./cmd/patd

echo "==> built $OUT ($VERSION / $COMMIT)"
