#!/usr/bin/env bash
# Load a generated sample dataset into a RUNNING patd instance, end to end:
# login -> (unlock if needed) -> create audit -> upload each domain dump ->
# apply cracks -> run BloodHound enrichment (if configured) -> upload bheusers
# -> print the summary.
#
# Credentials come from the environment so they never land in argv/history:
#   PATD_OP          operator username           (default: dev)
#   PATD_PW          operator password           (REQUIRED)
#   PATD_PASSPHRASE  store passphrase             (only used if the store is locked)
#
# Usage:
#   PATD_OP=watson PATD_PW='...' bash tools/load_sample.sh [data_dir] [base_url] [audit_name]
#
# Examples:
#   PATD_OP=watson PATD_PW='...' bash tools/load_sample.sh sample_data/bhsample http://127.0.0.1:8443
#   PATD_PW=devpass123456        bash tools/load_sample.sh sample_data/synthetic http://127.0.0.1:8444
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DATA="${1:-sample_data/bhsample}"
BASE="${2:-http://127.0.0.1:8443}"
AUDIT_NAME="${3:-Sample data ($(basename "$DATA"))}"
OP="${PATD_OP:-dev}"
PW="${PATD_PW:?set PATD_PW to the operator password (kept out of the transcript)}"

# Resolve a Python 3 that actually runs (Windows `python3` is often a Store stub).
PY=""
for cand in python3 python py; do
  if command -v "$cand" >/dev/null 2>&1 \
     && "$cand" -c 'import sys; sys.exit(0 if sys.version_info[0]==3 else 1)' >/dev/null 2>&1; then
    PY="$cand"; break
  fi
done
[ -n "$PY" ] || { echo "ERROR: no working Python 3 on PATH"; exit 1; }

[ -d "$DATA" ] || { echo "ERROR: data dir not found: $DATA"; exit 1; }
J="$(mktemp)"; trap 'rm -f "$J"' EXIT

jget() { "$PY" -c "import sys,json;d=json.load(sys.stdin);print(d.get('$1',''))"; }

echo "==> login to $BASE as $OP"
LOGIN="$(curl -s -c "$J" -X POST "$BASE/api/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$OP\",\"password\":\"$PW\"}")"
CSRF="$(printf '%s' "$LOGIN" | jget csrf_token)"
[ -n "$CSRF" ] || { echo "ERROR: login failed: $LOGIN"; exit 1; }

if [ "$(printf '%s' "$LOGIN" | jget store_unlocked)" != "True" ]; then
  [ -n "${PATD_PASSPHRASE:-}" ] || { echo "ERROR: store is locked; set PATD_PASSPHRASE"; exit 1; }
  echo "==> unlocking store"
  curl -s -b "$J" -X POST "$BASE/api/unlock" -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $CSRF" -d "{\"passphrase\":\"$PATD_PASSPHRASE\"}" >/dev/null
fi

echo "==> create + open audit: $AUDIT_NAME"
AID="$(curl -s -b "$J" -X POST "$BASE/api/audits" -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" -d "{\"name\":\"$AUDIT_NAME\",\"notes\":\"loaded by load_sample.sh\"}" | jget id)"
[ -n "$AID" ] || { echo "ERROR: could not create audit"; exit 1; }
curl -s -b "$J" -X POST "$BASE/api/audits/$AID/open" -H "X-CSRF-Token: $CSRF" -o /dev/null

echo "==> upload domain dumps"
for f in "$DATA"/*_dump.txt; do
  [ -e "$f" ] || { echo "  (no *_dump.txt in $DATA)"; break; }
  dom="$(basename "$f" _dump.txt)"
  curl -s -b "$J" -X POST "$BASE/api/upload" -H "X-CSRF-Token: $CSRF" \
    -F "domain=$dom" -F "uncracked=@$f" -o /dev/null
  echo "  uploaded $dom"
done

if [ -f "$DATA/cracks.txt" ]; then
  echo "==> apply cracks"
  curl -s -b "$J" -X POST "$BASE/api/upload/cracks" -H "X-CSRF-Token: $CSRF" \
    -F "crackfile=@$DATA/cracks.txt" -o /dev/null
fi

echo "==> BloodHound enrichment (best effort; no-op if BHE is off)"
curl -s -b "$J" -X POST "$BASE/api/enrich" -H "X-CSRF-Token: $CSRF" >/dev/null 2>&1 || true
for _ in $(seq 1 90); do
  ph="$(curl -s -b "$J" "$BASE/api/enrich/job" | jget phase 2>/dev/null)"
  [ "$ph" = "running" ] || break
  sleep 2
done

if [ -f "$DATA/bheusers.json" ]; then
  echo "==> upload bheusers (synthetic pwd-age / never-expires / controlled)"
  curl -s -b "$J" -X POST "$BASE/api/upload/bheusers" -H "X-CSRF-Token: $CSRF" \
    -F "bheusers=@$DATA/bheusers.json" -o /dev/null
fi

echo "==> done — summary:"
curl -s -b "$J" "$BASE/api/summary" | "$PY" -c '
import sys,json
d=json.load(sys.stdin)
for k in ("total_accounts","cracked","hibp_breached","da_pathways","never_expires",
          "stale_passwords","escalated_by_shared_da","high_controlled","policy_violations"):
    print("   %-22s %s" % (k, d.get(k,"-")))
'
echo "   audit: $AUDIT_NAME ($AID) on $BASE"
