# Deploying Password!AtTheDisco

Password!AtTheDisco ships as a **single static binary** with the React UI embedded.
No runtime dependencies, no CGO — copy it to a host and run. Configuration is by
environment variable; the encrypted store's passphrase is set on first unlock in
the UI and is never written to disk.

## Supported platforms

Built and verified to cross-compile (CGO-free, static):

| OS | Arch | Service mechanism | Notes |
|----|------|-------------------|-------|
| **Linux** | amd64, arm64 | systemd | primary server target |
| **macOS** | amd64, arm64 | launchd | |
| **Windows** | amd64, arm64 | Scheduled Task (or NSSM/WinSW for a true service) | |

Other Go targets (FreeBSD, etc.) build too; just not packaged by the scripts.

Deployment is **two steps**: (1) guided setup, then (2) — optionally — install a
background service. Setup never touches the system service manager, so you can run
it unprivileged and decide on a service afterward.

## Quick start

### Linux / macOS

```bash
git clone https://github.com/watson0x90/PasswordAtTheDisco
cd PasswordAtTheDisco

# 1) setup: build -> operator -> TLS -> config + run.sh launcher  (no service)
./deploy/deploy.sh

# 2) run it now in the foreground …
<install-dir>/run.sh
# … or install + start it as a service (usually needs root):
sudo ./deploy/deploy.sh --install-service --install-dir <install-dir>
sudo ./deploy/deploy.sh --uninstall-service --install-dir <install-dir>   # to remove
```

As root the service is a system-wide systemd unit under a dedicated `patd` user;
unprivileged, it's a `--user` systemd service or a launchd agent. Setup prints the
exact `--install-service` command (with the right `--install-dir` and `sudo`) when
it finishes.

**Non-interactive setup** (e.g. CI / config management):

```bash
INSTALL_DIR=/opt/patd PATD_BIND=0.0.0.0:8443 \
PATD_OPERATOR=lead1 PATD_OPERATOR_PW='…' PATD_ASSUME_YES=1 \
./deploy/deploy.sh
sudo ./deploy/deploy.sh --install-service --install-dir /opt/patd
```

**Credential-bearing host?** Build the binary on a clean box and deploy that one
(so `npm` never runs on the prod host — see the supply-chain rule in `CLAUDE.md`):

```bash
# on a build host:
cd web && npm ci --ignore-scripts && npm run build && cd ..
rm -rf internal/webui/dist && cp -r web/dist internal/webui/dist
CGO_ENABLED=0 go build -tags embed -trimpath -ldflags="-s -w" -o patd ./cmd/patd
# on the prod host:
./deploy/deploy.sh --binary /path/to/patd
```

### Windows

```powershell
# 1) setup (no service): build -> operator -> TLS -> config + run.ps1 launcher
.\deploy\deploy.ps1                      # or: -Binary C:\path\to\patd.exe

# 2) run it now …
& '<install-dir>\run.ps1'
# … or, in an ELEVATED PowerShell, register a startup Scheduled Task (runs as SYSTEM):
.\deploy\deploy.ps1 -InstallService -InstallDir '<install-dir>'
.\deploy\deploy.ps1 -UninstallService                              # to remove
```

## What the scripts configure

| Env var | Meaning | Script default |
|---------|---------|----------------|
| `PATD_ADDR` | bind `host:port` | `127.0.0.1:8443` |
| `PATD_DATA` | encrypted store dir (**back up**) | `<install>/data` |
| `PATD_USERS_FILE` | operator file (argon2id hashes) | `<install>/users.json` |
| `PATD_AUDIT_LOG` | append-only audit log (never contains passwords) | `<install>/audit.log` |
| `PATD_TLS_CERT` / `PATD_TLS_KEY` | TLS PEM cert + key | self-signed or provided |
| `PATD_AUTOLOCK_MIN` | idle minutes before the store auto-locks (0 = never) | `60` |
| `PATD_HIBP` | HIBP NTLM index path (blank = disabled) | unset |
| `PATD_BHE` | BloodHound config path (blank = disabled) | `config/bloodhound.json` if present |
| `PATD_LISTS` | wordlists/policy dir | `<install>/lists` |
| `PATD_INGEST_TOKEN` | bearer token for the engine ingest API | random |

## TLS

- **Loopback bind** (`127.0.0.1`) serves plain HTTP — fine for local use or behind a
  TLS-terminating reverse proxy (nginx/Caddy).
- **Any other bind** requires TLS — the server **refuses to start** otherwise. The
  scripts offer a generated self-signed cert (clients will warn; fine for internal
  use) or you supply real cert/key paths. HSTS is sent when serving over TLS.

## Managing the service

| Platform | Status | Logs | Stop |
|----------|--------|------|------|
| systemd (system) | `systemctl status patd` | `journalctl -u patd -f` | `systemctl stop patd` |
| systemd (user) | `systemctl --user status patd` | `journalctl --user -u patd -f` | `systemctl --user stop patd` |
| launchd | `launchctl list \| grep patd` | `tail -f <install>/patd.log` | `launchctl unload <plist>` |
| Windows | `Get-ScheduledTask PasswordAtTheDisco` | `<install>\audit.log` | `Stop-ScheduledTask PasswordAtTheDisco` |

## First run

1. Open the URL, sign in with the operator you created (a `lead`).
2. **Set the store passphrase** on the unlock screen. It is held only in memory and
   **never stored** — choose a strong one and keep it in a password manager.
3. Create an audit, then ingest dumps (web Upload, or the `patd audit` CLI).
   > Note: `patd audit --out FILE` writes the analyzed dataset — which **includes
   > cleartext cracked passwords** — to disk (0600, written atomically). It's an
   > optional intermediate for offline ingest; protect and delete it, or skip `--out`
   > and POST directly to the server with `--api`.

Add more operators any time:

```bash
<install>/patd hashpw    # prompts for a password, prints an argon2id hash
# add an entry to users.json: {"username":"…","password_hash":"…","role":"analyst|lead"}
```

## Backup & recovery

- **Back up the whole `PATD_DATA` directory as a unit** — that *is* your audits
  (`keyfile.json`, the encrypted `index.enc`, and `audits/*.enc`).
- **Losing the passphrase or `keyfile.json` is total, unrecoverable loss** — there is
  no reset or escrow.
- A corrupt `index.enc` self-heals (rebuilt from the blobs on unlock); `patd reindex`
  forces it. An undecryptable blob is quarantined to `*.enc.corrupt` (and logged).
- **`keyfile.json.bak`** is a transient crash-safety copy written during a rotation
  and removed on success — never restore it after an interrupted *data-key* rotation
  (it holds only the old key); keep `keyfile.json` and re-run the rotation to resume.
- Rotations (lead, Policies tab): **change passphrase** (re-wraps the same key) and
  **rotate data key** (re-encrypts everything under a fresh key; crash-safe/resumable).

## Optional integrations

- **HIBP breach correlation** — set `PATD_HIBP` to the NTLM index file from the
  `PwnedPasswordsDownloader` submodule (~74 GB). Leave blank to disable.
- **BloodHound DA-pathway enrichment** — create an API token in BloodHound CE
  (Administration -> API Tokens), put `token_id`/`token_key` (plus `domain`/`port`/
  `scheme`) in `config/bloodhound.json`, and point `PATD_BHE` at it. The file is
  gitignored. Without it, DA-pathway signals are simply absent.

## Security posture the deploy sets

- Dedicated `patd` system user + systemd hardening (`NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, scoped `ReadWritePaths`).
- `users.json`, `patd.env`, and the TLS key are written `0600`.
- The store starts **locked**; a restart always requires re-entering the passphrase.
