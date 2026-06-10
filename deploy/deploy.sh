#!/usr/bin/env bash
#
# Password!AtTheDisco - guided deployment (Linux / macOS).
#
# Default run = SETUP ONLY: builds the single self-contained binary (embedded SPA),
# walks through config, creates the first operator, optionally sets up TLS, and
# writes a run.sh launcher. It does NOT install a service.
#
# Installing a background service is a separate, explicit step (usually needs root):
#   sudo ./deploy/deploy.sh --install-service   [--install-dir DIR]
#   sudo ./deploy/deploy.sh --uninstall-service [--install-dir DIR]
#
# Setup options:
#   --binary PATH    use a prebuilt binary (skip the build; recommended for a
#                    credential-bearing host so npm never runs there)
#   --install-dir D  install location (default below); also honored by the service modes
# Non-interactive setup: pre-set prompts via env + PATD_ASSUME_YES=1.
#
set -euo pipefail

# ---- helpers ---------------------------------------------------------------
c_bold=$'\033[1m'; c_cyan=$'\033[36m'; c_yel=$'\033[33m'; c_red=$'\033[31m'; c_grn=$'\033[32m'; c_off=$'\033[0m'
say()  { printf '%s\n' "$*"; }
hdr()  { printf '\n%s== %s ==%s\n' "$c_bold$c_cyan" "$*" "$c_off"; }
warn() { printf '%s! %s%s\n' "$c_yel" "$*" "$c_off"; }
die()  { printf '%sERROR: %s%s\n' "$c_red" "$*" "$c_off" >&2; exit 1; }
ok()   { printf '%s* %s%s\n' "$c_grn" "$*" "$c_off"; }
ask() { # ask VAR "Prompt" "default"  - honors a pre-set env var of the same name
  local __var=$1 __prompt=$2 __def=${3-} __cur=${!1-} __ans
  if [ -n "${__cur}" ]; then printf -v "$__var" '%s' "$__cur"; return; fi
  if [ "${PATD_ASSUME_YES:-0}" = 1 ]; then printf -v "$__var" '%s' "$__def"; return; fi
  read -r -p "  $__prompt${__def:+ [$__def]}: " __ans || true
  printf -v "$__var" '%s' "${__ans:-$__def}"
}
yesno() {
  local q=$1 def=${2:-y} a
  if [ "${PATD_ASSUME_YES:-0}" = 1 ]; then [ "$def" = y ]; return; fi
  read -r -p "  $q [$( [ "$def" = y ] && echo Y/n || echo y/N )]: " a || true
  a=${a:-$def}; [[ $a =~ ^[Yy] ]]
}
is_loopback() { case "${1%%:*}" in 127.0.0.1|::1|localhost|"") return 0;; *) return 1;; esac; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OS="$(uname -s)"; ARCH="$(uname -m)"
SELF="$0"

default_install_dir() {
  if [ "$OS" = Darwin ]; then echo "$HOME/patd"
  elif [ "$(id -u)" -eq 0 ]; then echo "/opt/patd"
  else echo "$HOME/patd"; fi
}

# ---- service install / uninstall (separate post-setup step) ----------------
install_service() {
  local dir=$1 bin="$1/patd" env="$1/patd.env"
  [ -x "$bin" ] || die "no binary at $bin - run setup first (./deploy/deploy.sh)"
  [ -f "$env" ] || die "no config at $env - run setup first (./deploy/deploy.sh)"
  if [ "$OS" = Linux ] && command -v systemctl >/dev/null; then
    if [ "$(id -u)" -eq 0 ]; then
      id -u patd >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin patd 2>/dev/null || true
      chown -R patd:patd "$dir"
      cat > /etc/systemd/system/patd.service <<UNIT
[Unit]
Description=Password!AtTheDisco
After=network-online.target
Wants=network-online.target

[Service]
User=patd
EnvironmentFile=$env
ExecStart=$bin
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$dir
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNIT
      systemctl daemon-reload && systemctl enable --now patd.service
      ok "Installed + started systemd service 'patd' (runs as user 'patd')."
      say "  manage:  systemctl status patd  |  journalctl -u patd -f"
    else
      mkdir -p "$HOME/.config/systemd/user"
      cat > "$HOME/.config/systemd/user/patd.service" <<UNIT
[Unit]
Description=Password!AtTheDisco
[Service]
EnvironmentFile=$env
ExecStart=$bin
Restart=on-failure
[Install]
WantedBy=default.target
UNIT
      systemctl --user daemon-reload && systemctl --user enable --now patd.service
      ok "Installed + started user systemd service 'patd'."
      say "  manage:  systemctl --user status patd  |  journalctl --user -u patd -f"
    fi
  elif [ "$OS" = Darwin ]; then
    local plist="$HOME/Library/LaunchAgents/com.passwordatthedisco.patd.plist"
    mkdir -p "$HOME/Library/LaunchAgents"
    {
      echo '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
      echo '<plist version="1.0"><dict>'
      echo '  <key>Label</key><string>com.passwordatthedisco.patd</string>'
      echo "  <key>ProgramArguments</key><array><string>$bin</string></array>"
      echo '  <key>EnvironmentVariables</key><dict>'
      while IFS='=' read -r k v; do printf '    <key>%s</key><string>%s</string>\n' "$k" "$v"; done < "$env"
      echo '  </dict>'
      echo '  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>'
      echo "  <key>StandardErrorPath</key><string>$dir/patd.log</string>"
      echo '</dict></plist>'
    } > "$plist"
    launchctl unload "$plist" 2>/dev/null || true
    launchctl load "$plist"
    ok "Installed + started launchd agent."
    say "  manage:  launchctl list | grep patd  |  tail -f $dir/patd.log"
  else
    die "no systemd/launchd here - start it in the foreground with $dir/run.sh"
  fi
}
uninstall_service() {
  local dir=$1
  if [ "$OS" = Linux ] && command -v systemctl >/dev/null; then
    if [ "$(id -u)" -eq 0 ] && [ -f /etc/systemd/system/patd.service ]; then
      systemctl disable --now patd.service 2>/dev/null || true
      rm -f /etc/systemd/system/patd.service && systemctl daemon-reload
      ok "Removed system service 'patd'."
    elif [ -f "$HOME/.config/systemd/user/patd.service" ]; then
      systemctl --user disable --now patd.service 2>/dev/null || true
      rm -f "$HOME/.config/systemd/user/patd.service" && systemctl --user daemon-reload
      ok "Removed user service 'patd'."
    else warn "no installed systemd service found."; fi
  elif [ "$OS" = Darwin ]; then
    local plist="$HOME/Library/LaunchAgents/com.passwordatthedisco.patd.plist"
    [ -f "$plist" ] && { launchctl unload "$plist" 2>/dev/null || true; rm -f "$plist"; ok "Removed launchd agent."; } || warn "no launchd agent found."
  else die "no service manager here."; fi
}

# ---- arg parse -------------------------------------------------------------
MODE=setup; PREBUILT=""; ARG_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --binary) PREBUILT="${2:-}"; shift 2;;
    --install-service)   MODE=install;   shift;;
    --uninstall-service) MODE=uninstall; shift;;
    --install-dir) ARG_DIR="${2:-}"; shift 2;;
    -h|--help)
      cat <<USAGE
Password!AtTheDisco deploy (Linux/macOS)

  ./deploy/deploy.sh [--binary PATH] [--install-dir DIR]
      Guided SETUP: build (or use --binary), operator, TLS, config, run.sh launcher.
      Does NOT install a service. Non-interactive: set prompts via env + PATD_ASSUME_YES=1.

  sudo ./deploy/deploy.sh --install-service   [--install-dir DIR]
      Install + start a service (systemd / launchd) from an existing setup.
  sudo ./deploy/deploy.sh --uninstall-service [--install-dir DIR]
      Stop + remove the service.

Full guide: deploy/DEPLOYMENT.md
USAGE
      exit 0;;
    *) die "unknown argument: $1 (try --help)";;
  esac
done

# ---- service modes: do only that, then exit --------------------------------
if [ "$MODE" = install ] || [ "$MODE" = uninstall ]; then
  DIR="${ARG_DIR:-${INSTALL_DIR:-$(default_install_dir)}}"
  hdr "Service ${MODE} ($OS) - $DIR"
  [ "$MODE" = install ] && install_service "$DIR" || uninstall_service "$DIR"
  exit 0
fi

# =============================== SETUP ======================================
hdr "Password!AtTheDisco - setup ($OS/$ARCH)"
[ -n "$PREBUILT" ] && { [ -x "$PREBUILT" ] || die "--binary path not executable: $PREBUILT"; }

# 1. location + address
hdr "1/5  Location & address"
ask INSTALL_DIR "Install directory" "${ARG_DIR:-$(default_install_dir)}"
ask PATD_DATA   "Data directory (encrypted store - back this up!)" "$INSTALL_DIR/data"
ask PATD_BIND   "Bind address (host:port)" "127.0.0.1:8443"

# 2. TLS
hdr "2/5  TLS"
TLS_CERT=""; TLS_KEY=""
if is_loopback "$PATD_BIND"; then
  ok "Loopback bind - plain HTTP is allowed for local/dev (front with a TLS proxy for remote access)."
else
  warn "Non-loopback bind ($PATD_BIND): the server refuses to start without TLS."
  ask TLS_MODE "TLS: [s]elf-signed, [b]ring-your-own cert/key" "s"
  if [[ $TLS_MODE =~ ^[Bb] ]]; then
    ask TLS_CERT "  Path to TLS certificate (PEM)" ""
    ask TLS_KEY  "  Path to TLS private key (PEM)" ""
    [ -f "$TLS_CERT" ] && [ -f "$TLS_KEY" ] || die "cert/key not found"
  else
    command -v openssl >/dev/null || die "openssl not found (needed for self-signed); install it or use bring-your-own"
    mkdir -p "$INSTALL_DIR/tls"
    TLS_CERT="$INSTALL_DIR/tls/cert.pem"; TLS_KEY="$INSTALL_DIR/tls/key.pem"
    cn="${PATD_BIND%%:*}"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TLS_KEY" -out "$TLS_CERT" -days 825 \
      -subj "/CN=$cn" -addext "subjectAltName=DNS:$cn,IP:$cn" >/dev/null 2>&1 \
      || openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TLS_KEY" -out "$TLS_CERT" -days 825 -subj "/CN=$cn" >/dev/null 2>&1
    chmod 600 "$TLS_KEY"
    ok "Generated self-signed cert for $cn (clients will warn; replace with a real cert for production)."
  fi
fi

# 3. binary
hdr "3/5  Binary"
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
  say "  compiling (CGO-free, embedded SPA)..."
  ( cd "$REPO_ROOT" && CGO_ENABLED=0 go build -tags embed -trimpath -ldflags="-s -w" -o "$BIN" ./cmd/patd )
  ok "Built $BIN"
fi

# 4. first operator
hdr "4/5  First operator (lead)"
USERS_FILE="$INSTALL_DIR/users.json"
if [ -f "$USERS_FILE" ] && ! yesno "users.json exists - overwrite the operator?" n; then
  ok "Keeping existing $USERS_FILE"
else
  ask PATD_OPERATOR "Operator username" "lead"
  if [ -n "${PATD_OPERATOR_PW:-}" ]; then op_pw="$PATD_OPERATOR_PW"; else
    while :; do
      read -r -s -p "  Operator password: " op_pw; echo
      read -r -s -p "  Confirm password : " op_pw2; echo
      [ -n "$op_pw" ] && [ "$op_pw" = "$op_pw2" ] && break
      warn "empty or mismatch - try again"
    done
  fi
  hash="$(printf '%s\n' "$op_pw" | "$BIN" hashpw)"
  [ -n "$hash" ] || die "hashpw failed"
  printf '[\n  {"username":"%s","password_hash":"%s","role":"lead"}\n]\n' "$PATD_OPERATOR" "$hash" > "$USERS_FILE"
  chmod 600 "$USERS_FILE"; unset op_pw op_pw2
  ok "Wrote $USERS_FILE (lead: $PATD_OPERATOR). Add more with: $BIN hashpw"
fi

# 5. options + config + launcher
hdr "5/5  Options & config"
ask PATD_HIBP "HIBP NTLM index path (blank = disable breach correlation)" "${PATD_HIBP:-}"
ask PATD_BHE  "BloodHound config path (blank = disable DA enrichment)" "$( [ -f "$REPO_ROOT/config/bloodhound.json" ] && echo "$REPO_ROOT/config/bloodhound.json" )"
ask PATD_AUTOLOCK "Idle auto-lock minutes (0 = never)" "60"
[ -d "$REPO_ROOT/lists" ] && cp -r "$REPO_ROOT/lists" "$INSTALL_DIR/" 2>/dev/null || true
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
cat > "$INSTALL_DIR/run.sh" <<RUN
#!/usr/bin/env bash
set -a; . "$ENV_FILE"; set +a
exec "$BIN"
RUN
chmod +x "$INSTALL_DIR/run.sh"
ok "Wrote $ENV_FILE + run.sh"

scheme=http; [ -n "$TLS_CERT" ] && scheme=https
hdr "Setup complete"
say "  ${c_bold}URL:${c_off}        $scheme://$PATD_BIND"
say "  ${c_bold}Sign in:${c_off}    the lead operator you just created"
say "  ${c_bold}First run:${c_off}  set the store passphrase on the unlock screen - it is NEVER stored;"
say "              if lost, the data in $PATD_DATA is unrecoverable. Save it in a password manager."
say "  ${c_bold}Back up:${c_off}    $PATD_DATA  (as a unit) - that IS your audits."
say ""
say "  ${c_bold}Start it now (foreground):${c_off}  $INSTALL_DIR/run.sh"
say "  ${c_bold}Or install as a service:${c_off}"
sudo_hint=""; { [ "$OS" = Linux ] && [ "$(id -u)" -ne 0 ]; } && sudo_hint="sudo "
say "      ${sudo_hint}$SELF --install-service --install-dir $INSTALL_DIR"
say "      (${sudo_hint}$SELF --uninstall-service --install-dir $INSTALL_DIR  to remove)"
say ""
