#!/usr/bin/env bash
#
# Password!AtTheDisco — guided deployment (Linux / macOS).
#
# Builds the single self-contained binary (embedded SPA), walks through config,
# creates the first operator, optionally sets up TLS, and installs + starts a
# service (systemd on Linux, launchd on macOS). Re-runnable.
#
# Non-interactive: pre-set any prompt via env, e.g.
#   PATD_BIND=0.0.0.0:8443 PATD_OPERATOR=lead1 PATD_OPERATOR_PW=... \
#   PATD_ASSUME_YES=1 ./deploy/deploy.sh
#
# Use a prebuilt binary (skip the build; recommended for a credential-bearing
# host so npm never runs there):  ./deploy/deploy.sh --binary /path/to/patd
#
set -euo pipefail

# ---- helpers ---------------------------------------------------------------
c_bold=$'\033[1m'; c_cyan=$'\033[36m'; c_yel=$'\033[33m'; c_red=$'\033[31m'; c_grn=$'\033[32m'; c_off=$'\033[0m'
say()  { printf '%s\n' "$*"; }
hdr()  { printf '\n%s== %s ==%s\n' "$c_bold$c_cyan" "$*" "$c_off"; }
warn() { printf '%s! %s%s\n' "$c_yel" "$*" "$c_off"; }
die()  { printf '%sERROR: %s%s\n' "$c_red" "$*" "$c_off" >&2; exit 1; }
ok()   { printf '%s✓ %s%s\n' "$c_grn" "$*" "$c_off"; }

# ask VAR "Prompt" "default"  — honors a pre-set env var of the same name (non-interactive)
ask() {
  local __var=$1 __prompt=$2 __def=${3-} __cur=${!1-} __ans
  if [ -n "${__cur}" ]; then printf -v "$__var" '%s' "$__cur"; return; fi
  if [ "${PATD_ASSUME_YES:-0}" = 1 ]; then printf -v "$__var" '%s' "$__def"; return; fi
  read -r -p "  $__prompt${__def:+ [$__def]}: " __ans || true
  printf -v "$__var" '%s' "${__ans:-$__def}"
}
yesno() { # yesno "Question" default(y/n)
  local q=$1 def=${2:-y} a
  if [ "${PATD_ASSUME_YES:-0}" = 1 ]; then [ "$def" = y ]; return; fi
  read -r -p "  $q [$( [ "$def" = y ] && echo Y/n || echo y/N )]: " a || true
  a=${a:-$def}; [[ $a =~ ^[Yy] ]]
}
is_loopback() { case "${1%%:*}" in 127.0.0.1|::1|localhost|"") return 0;; *) return 1;; esac; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OS="$(uname -s)"; ARCH="$(uname -m)"
PREBUILT=""
[ "${1:-}" = "--binary" ] && { PREBUILT="${2:-}"; [ -x "$PREBUILT" ] || die "--binary path not executable: $PREBUILT"; }

hdr "Password!AtTheDisco — deploy ($OS/$ARCH)"

# ---- 1. install location + config ------------------------------------------
hdr "1/6  Location & address"
default_install="/opt/patd"; [ "$OS" = Darwin ] && default_install="$HOME/patd"
[ "$(id -u)" -ne 0 ] && [ "$OS" = Linux ] && default_install="$HOME/patd"
ask INSTALL_DIR "Install directory" "$default_install"
ask PATD_DATA   "Data directory (encrypted store — back this up!)" "$INSTALL_DIR/data"
ask PATD_BIND   "Bind address (host:port)" "127.0.0.1:8443"

# ---- 2. TLS ----------------------------------------------------------------
hdr "2/6  TLS"
TLS_CERT=""; TLS_KEY=""
if is_loopback "$PATD_BIND"; then
  ok "Loopback bind — plain HTTP is allowed for local/dev (front with a TLS proxy for remote access)."
else
  warn "Non-loopback bind ($PATD_BIND): the server refuses to start without TLS."
  ask TLS_MODE "TLS: [s]elf-signed, [b]ring-your-own cert/key" "s"
  if [[ $TLS_MODE =~ ^[Bb] ]]; then
    ask TLS_CERT "  Path to TLS certificate (PEM)" ""
    ask TLS_KEY  "  Path to TLS private key (PEM)" ""
    [ -f "$TLS_CERT" ] && [ -f "$TLS_KEY" ] || die "cert/key not found"
  else
    command -v openssl >/dev/null || die "openssl not found (needed for self-signed); install it or use bring-your-own"
    TLS_DIR="$INSTALL_DIR/tls"; mkdir -p "$TLS_DIR"
    TLS_CERT="$TLS_DIR/cert.pem"; TLS_KEY="$TLS_DIR/key.pem"
    cn="${PATD_BIND%%:*}"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TLS_KEY" -out "$TLS_CERT" \
      -days 825 -subj "/CN=$cn" -addext "subjectAltName=DNS:$cn,IP:$cn" >/dev/null 2>&1 \
      || openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TLS_KEY" -out "$TLS_CERT" -days 825 -subj "/CN=$cn" >/dev/null 2>&1
    chmod 600 "$TLS_KEY"
    ok "Generated self-signed cert for $cn (clients will warn; replace with a real cert for production)."
  fi
fi

# ---- 3. build (or use prebuilt) --------------------------------------------
hdr "3/6  Binary"
mkdir -p "$INSTALL_DIR"
BIN="$INSTALL_DIR/patd"
if [ -n "$PREBUILT" ]; then
  cp "$PREBUILT" "$BIN"; ok "Installed prebuilt binary -> $BIN"
else
  command -v go >/dev/null || die "go not found (needed to build; or pass --binary <prebuilt>)"
  if [ ! -d "$REPO_ROOT/internal/webui/dist" ] || yesno "Rebuild the web UI (runs npm)?" n; then
    command -v npm >/dev/null || die "npm not found (needed to build the SPA; or pass --binary <prebuilt>)"
    warn "Building the SPA with npm. On a credential-bearing host prefer --binary built elsewhere."
    ( cd "$REPO_ROOT/web" && npm ci --ignore-scripts && npm run build )
    rm -rf "$REPO_ROOT/internal/webui/dist" && cp -r "$REPO_ROOT/web/dist" "$REPO_ROOT/internal/webui/dist"
  fi
  say "  compiling (CGO-free, embedded SPA)…"
  ( cd "$REPO_ROOT" && CGO_ENABLED=0 go build -tags embed -trimpath -ldflags="-s -w" -o "$BIN" ./cmd/patd )
  ok "Built $BIN ($("$BIN" version 2>/dev/null || echo embedded))"
fi

# ---- 4. first operator -----------------------------------------------------
hdr "4/6  First operator (lead)"
USERS_FILE="$INSTALL_DIR/users.json"
if [ -f "$USERS_FILE" ] && ! yesno "users.json exists — overwrite the operator?" n; then
  ok "Keeping existing $USERS_FILE"
else
  ask PATD_OPERATOR "Operator username" "lead"
  if [ -n "${PATD_OPERATOR_PW:-}" ]; then op_pw="$PATD_OPERATOR_PW"; else
    while :; do
      read -r -s -p "  Operator password: " op_pw; echo
      read -r -s -p "  Confirm password : " op_pw2; echo
      [ -n "$op_pw" ] && [ "$op_pw" = "$op_pw2" ] && break
      warn "empty or mismatch — try again"
    done
  fi
  hash="$(printf '%s\n' "$op_pw" | "$BIN" hashpw)"
  [ -n "$hash" ] || die "hashpw failed"
  printf '[\n  {"username":"%s","password_hash":"%s","role":"lead"}\n]\n' "$PATD_OPERATOR" "$hash" > "$USERS_FILE"
  chmod 600 "$USERS_FILE"; unset op_pw op_pw2
  ok "Wrote $USERS_FILE (lead: $PATD_OPERATOR). Add more operators with: $BIN hashpw"
fi

# ---- 5. optional integrations + env file -----------------------------------
hdr "5/6  Options & config"
ask PATD_HIBP "HIBP NTLM index path (blank = disable breach correlation)" "${PATD_HIBP:-}"
ask PATD_BHE  "BloodHound config path (blank = disable DA enrichment)" "$( [ -f "$REPO_ROOT/config/bloodhound.json" ] && echo "$REPO_ROOT/config/bloodhound.json" )"
ask PATD_AUTOLOCK "Idle auto-lock minutes (0 = never)" "60"
[ -d "$REPO_ROOT/lists" ] && { cp -r "$REPO_ROOT/lists" "$INSTALL_DIR/" 2>/dev/null || true; }
INGEST_TOKEN="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"
mkdir -p "$PATD_DATA"
ENV_FILE="$INSTALL_DIR/patd.env"
{
  echo "PATD_ADDR=$PATD_BIND"
  echo "PATD_DATA=$PATD_DATA"
  echo "PATD_USERS_FILE=$USERS_FILE"
  echo "PATD_AUDIT_LOG=$INSTALL_DIR/audit.log"
  echo "PATD_AUTOLOCK_MIN=$PATD_AUTOLOCK"
  echo "PATD_INGEST_TOKEN=$INGEST_TOKEN"
  [ -d "$INSTALL_DIR/lists" ] && echo "PATD_LISTS=$INSTALL_DIR/lists"
  [ -n "${PATD_HIBP:-}" ] && echo "PATD_HIBP=$PATD_HIBP"
  [ -n "${PATD_BHE:-}" ]  && echo "PATD_BHE=$PATD_BHE"
  [ -n "$TLS_CERT" ] && { echo "PATD_TLS_CERT=$TLS_CERT"; echo "PATD_TLS_KEY=$TLS_KEY"; }
} > "$ENV_FILE"
chmod 600 "$ENV_FILE"
ok "Wrote $ENV_FILE"

# ---- 6. service ------------------------------------------------------------
hdr "6/6  Service"
scheme=http; [ -n "$TLS_CERT" ] && scheme=https
url="$scheme://$PATD_BIND"
start_hint=""
if [ "$OS" = Linux ] && command -v systemctl >/dev/null; then
  if [ "$(id -u)" -eq 0 ]; then
    id -u patd >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin patd 2>/dev/null || true
    chown -R patd:patd "$INSTALL_DIR"
    unit=/etc/systemd/system/patd.service
    cat > "$unit" <<UNIT
[Unit]
Description=Password!AtTheDisco
After=network-online.target
Wants=network-online.target

[Service]
User=patd
EnvironmentFile=$ENV_FILE
ExecStart=$BIN
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$INSTALL_DIR
AmbientCapabilities=
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now patd.service
    ok "Installed + started systemd service 'patd' (as user 'patd')."
    start_hint="systemctl status patd   ·   journalctl -u patd -f"
  else
    # user service
    mkdir -p "$HOME/.config/systemd/user"
    cat > "$HOME/.config/systemd/user/patd.service" <<UNIT
[Unit]
Description=Password!AtTheDisco
[Service]
EnvironmentFile=$ENV_FILE
ExecStart=$BIN
Restart=on-failure
[Install]
WantedBy=default.target
UNIT
    systemctl --user daemon-reload && systemctl --user enable --now patd.service
    ok "Installed + started user systemd service 'patd'."
    start_hint="systemctl --user status patd   ·   journalctl --user -u patd -f"
  fi
elif [ "$OS" = Darwin ]; then
  plist="$HOME/Library/LaunchAgents/com.passwordatthedisco.patd.plist"
  mkdir -p "$HOME/Library/LaunchAgents"
  {
    echo '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    echo '<plist version="1.0"><dict>'
    echo '  <key>Label</key><string>com.passwordatthedisco.patd</string>'
    echo "  <key>ProgramArguments</key><array><string>$BIN</string></array>"
    echo '  <key>EnvironmentVariables</key><dict>'
    while IFS='=' read -r k v; do printf '    <key>%s</key><string>%s</string>\n' "$k" "$v"; done < "$ENV_FILE"
    echo '  </dict>'
    echo '  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>'
    echo "  <key>StandardErrorPath</key><string>$INSTALL_DIR/patd.log</string>"
    echo '</dict></plist>'
  } > "$plist"
  launchctl unload "$plist" 2>/dev/null || true
  launchctl load "$plist"
  ok "Installed + started launchd agent."
  start_hint="launchctl list | grep patd   ·   tail -f $INSTALL_DIR/patd.log"
else
  cat > "$INSTALL_DIR/run.sh" <<RUN
#!/usr/bin/env bash
set -a; . "$ENV_FILE"; set +a
exec "$BIN"
RUN
  chmod +x "$INSTALL_DIR/run.sh"
  warn "No systemd/launchd detected — wrote $INSTALL_DIR/run.sh (run it to start in the foreground)."
  start_hint="$INSTALL_DIR/run.sh"
fi

hdr "Done"
say "  ${c_bold}URL:${c_off}        $url"
say "  ${c_bold}Sign in:${c_off}    operator you just created (lead)"
say "  ${c_bold}First run:${c_off}  set the store passphrase on the unlock screen — it is NEVER stored;"
say "              if lost, the data in $PATD_DATA is unrecoverable. Save it in a password manager."
say "  ${c_bold}Back up:${c_off}    $PATD_DATA  (as a unit) — that IS your audits."
[ -n "$start_hint" ] && say "  ${c_bold}Manage:${c_off}     $start_hint"
say ""
