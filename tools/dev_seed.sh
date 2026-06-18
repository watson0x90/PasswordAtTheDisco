#!/usr/bin/env bash
# dev_seed.sh — stand up a DISPOSABLE Password!AtTheDisco instance preloaded with
# synthetic data, in one command, for local UI/dev testing.
#
#   bash tools/dev_seed.sh          # generate data + start :8444 + load it
#   bash tools/dev_seed.sh --stop   # stop the instance + remove all .dev* artifacts
#
# Everything it creates is disposable and isolated from your real instance:
#   - separate port (127.0.0.1:8444), data dir (.devdata), users file (.devusers.json)
#   - BloodHound OFF, loopback only, throwaway operator/passphrase (NOT secrets)
# It never touches the real data/, config/, users.json, or audit.log.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Resolve a Python 3 interpreter that actually RUNS (not just one on PATH). On
# Windows, `python3` is often a Microsoft Store alias stub that prints "Python was
# not found" and exits non-zero — so verify each candidate executes Python 3.
PY=""
for cand in python3 python py; do
  if command -v "$cand" >/dev/null 2>&1 \
     && "$cand" -c 'import sys; sys.exit(0 if sys.version_info[0]==3 else 1)' >/dev/null 2>&1; then
    PY="$cand"; break
  fi
done
[ -n "$PY" ] || { echo "ERROR: no working Python 3 on PATH (tried python3, python, py)"; exit 1; }

PORT="127.0.0.1:8444"
BASE="http://$PORT"
DATA="$ROOT/.devdata"
USERS="$ROOT/.devusers.json"
PIDFILE="$ROOT/.devpid"
DEV_USER="dev"
DEV_PASS="devpass123456"        # throwaway, disposable instance only
DEV_PHRASE="devstorepass123"    # throwaway store passphrase, in-memory only
SYN="$ROOT/sample_data/synthetic"
DOMAINS=(CORP.LOCAL EU.CORP.LOCAL LAB.LOCAL)

stop() {
  if [ -f "$PIDFILE" ]; then
    PID="$(cat "$PIDFILE")"
    kill "$PID" 2>/dev/null && echo "stopped dev instance PID $PID" || echo "PID $PID not running"
    sleep 0.6   # let the process release its log/store file handles before rm
  fi
  # tolerant: a just-killed process may still briefly hold .devaudit.log
  rm -rf "$DATA" "$USERS" "$PIDFILE" \
         "$ROOT/.devaudit.log" "$ROOT/.devout.log" "$ROOT/.devcookies.txt" 2>/dev/null || true
  echo "cleaned .dev* artifacts"
}

if [ "${1:-}" = "--stop" ]; then stop; exit 0; fi

# Fresh start: stop any prior dev instance and wipe its store so init always works.
stop >/dev/null 2>&1 || true

echo "==> 1/6 synthetic data"
if [ ! -f "$SYN/cracks.txt" ]; then "$PY" tools/gen_synthetic.py; else echo "    present ($SYN)"; fi

echo "==> 2/6 throwaway operator ($DEV_USER, lead)"
DEVHASH="$(printf '%s\n' "$DEV_PASS" | go run ./cmd/patd hashpw 2>/dev/null | grep -E '^\$argon2' | head -1)"
[ -n "$DEVHASH" ] || { echo "ERROR: could not generate password hash via 'patd hashpw'"; exit 1; }
printf '[\n  {"username":"%s","password_hash":"%s","role":"lead"}\n]\n' "$DEV_USER" "$DEVHASH" > "$USERS"

echo "==> 3/6 start disposable instance ($BASE, BloodHound off)"
[ -f "$ROOT/patd.exe" ] || { echo "ERROR: patd.exe missing — build first (bash .claude/skills/build-and-run/scripts/build.sh)"; exit 1; }
mkdir -p "$DATA"
PATD_ADDR="$PORT" PATD_DATA="$DATA" PATD_USERS_FILE="$USERS" \
  PATD_AUDIT_LOG="$ROOT/.devaudit.log" PATD_BHE="$ROOT/.no-bloodhound.json" \
  "$ROOT/patd.exe" > "$ROOT/.devout.log" 2>&1 &
echo $! > "$PIDFILE"
# wait for it to answer
for _ in $(seq 1 20); do
  if curl -sf "$BASE/api/version" >/dev/null 2>&1; then break; fi
  sleep 0.3
done
curl -sf "$BASE/api/version" >/dev/null 2>&1 || { echo "ERROR: instance did not come up — see $ROOT/.devout.log"; exit 1; }

J="$ROOT/.devcookies.txt"; rm -f "$J"
echo "==> 4/6 login + unlock (init store)"
CSRF="$(curl -s -c "$J" -X POST "$BASE/api/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$DEV_USER\",\"password\":\"$DEV_PASS\"}" \
  | "$PY" -c 'import sys,json; print(json.load(sys.stdin)["csrf_token"])')"
curl -s -b "$J" -X POST "$BASE/api/unlock" -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" -d "{\"passphrase\":\"$DEV_PHRASE\"}" >/dev/null

echo "==> 5/6 create audit + upload 3 domains + apply cracks"
AID="$(curl -s -b "$J" -X POST "$BASE/api/audits" -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" -d '{"name":"Dev Seed","notes":"synthetic"}' \
  | "$PY" -c 'import sys,json; print(json.load(sys.stdin)["id"])')"
curl -s -b "$J" -X POST "$BASE/api/audits/$AID/open" -H "X-CSRF-Token: $CSRF" -o /dev/null
for D in "${DOMAINS[@]}"; do
  curl -s -b "$J" -X POST "$BASE/api/upload" -H "X-CSRF-Token: $CSRF" \
    -F "domain=$D" -F "uncracked=@$SYN/${D}_dump.txt" -o /dev/null
  echo "    uploaded $D"
done
curl -s -b "$J" -X POST "$BASE/api/upload/cracks" -H "X-CSRF-Token: $CSRF" \
  -F "crackfile=@$SYN/cracks.txt" -o /dev/null

echo "==> 6/6 done"
SUM="$(curl -s -b "$J" "$BASE/api/summary")"
echo "    summary: $SUM"
cat <<EOF

  ── Disposable instance ready ─────────────────────────────
   URL:        $BASE
   Operator:   $DEV_USER / $DEV_PASS   (lead)
   Passphrase: $DEV_PHRASE
   PID:        $(cat "$PIDFILE")
   Stop+clean: bash tools/dev_seed.sh --stop
  ──────────────────────────────────────────────────────────
EOF
