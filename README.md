# Password!AtTheDisco

**Active Directory password-exposure auditing — without leaving cracked credentials lying around.**

[![CI](https://github.com/watson0x90/PasswordAtTheDisco/actions/workflows/ci.yml/badge.svg)](https://github.com/watson0x90/PasswordAtTheDisco/actions/workflows/ci.yml)

Password!AtTheDisco ingests credential dumps from an AD password audit, correlates
them against Have I Been Pwned, enriches them with BloodHound (Domain Admin
pathways, controlled objects), scores each account with a CVSS-style risk model,
and serves the results through an authenticated web console — as a single Go
binary.

It is a ground-up Go + React rewrite of the original Python tool. (The Python v1
has been fully superseded and removed; it remains in git history before this
point if ever needed.)

## Why it exists

The original tool's output was a self-contained HTML report — which necessarily
wrote **cleartext cracked passwords to disk**. This rewrite never does:

- **Cleartext lives only in process memory.** The audit pushes data to the API;
  it is never persisted in the clear.
- **Redacted by default.** Every list/table/summary endpoint omits the password.
- **Cleartext is a deliberate, gated, logged action.** Only a `lead`-role
  operator can reveal a single account's password, and every reveal (allowed or
  denied) is written to an append-only audit log — *who, which account, when* —
  never the password value itself.
- **Authenticated + hardened.** argon2id local auth, revocable sessions
  (HttpOnly/SameSite=Strict), per-IP login rate-limiting, CSRF tokens, strict CSP,
  TLS-capable.

## How it works

```
  credential dumps ─▶ patd audit ─────────────▶  patd (server)  ◀── React console
   (NTDS/secretsdump)   parse · HIBP · analyze     in-memory store     redacted views +
                        BloodHound · CVSS score    + JSON API          lead-gated reveal
                        → POST /api/ingest         (TLS, authn/z, audit)
```

One binary serves both the JSON API and the embedded single-page app.

## Quick start

```bash
# 1. Build
go build -o patd ./cmd/patd

# 2. Create an operator (argon2id). Copy the template and add the printed hash.
cp users.example.json users.json
go run ./cmd/patd hashpw            # prompts for a password, prints its hash

# 3. Build the web console (deps are vetted + pinned; never run a bare npm install)
cd web && npm ci --ignore-scripts && npm run build && cd ..

# 4. Run the server
PATD_INGEST_TOKEN=$(openssl rand -hex 32) PATD_USERS_FILE=users.json \
  PATD_AUDIT_LOG=audit.log PATD_STATIC_DIR=web/dist ./patd
#   (set PATD_TLS_CERT / PATD_TLS_KEY for HTTPS)

# 5. Run an audit and push results to the running server
./patd audit -token "$PATD_INGEST_TOKEN" \
  -hibp PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt \
  CORP cracked.txt uncracked.txt
```

Then open the console, sign in, and triage: **Overview → Actionable → Domains →
Accounts** (with the lead-gated reveal).

Input is impacket `secretsdump` NTDS format
(`user:rid:lm:nt:::password`) or a simple `user:hash[:password]`; HIBP and
BloodHound are optional. See [`docs/architecture.md`](docs/architecture.md) for
the full data flow, API, scoring model, and config.

## Single-binary release

```bash
cd web && npm ci --ignore-scripts && npm run build && cd ..
rm -rf internal/webui/dist && cp -r web/dist internal/webui/dist
go build -tags embed -o patd ./cmd/patd     # ~10 MB; SPA baked in, zero disk deps
```

## Deploy

Guided, full-setup deploy scripts (build → first operator → TLS → service → start):

```bash
./deploy/deploy.sh        # Linux / macOS  (systemd / launchd)
```
```powershell
.\deploy\deploy.ps1       # Windows  (startup Scheduled Task)
```

Static CGO-free binary → runs on **Linux / macOS / Windows (amd64 + arm64)**. Full
guide, env vars, TLS, service management, and backup/recovery: **[deploy/DEPLOYMENT.md](deploy/DEPLOYMENT.md)**.

## Features

- **Engine:** secretsdump parsing, HIBP NTLM lookup over a 74 GB prefix-indexed
  dump, password analysis (complexity / policy / wordlists / similarity),
  BloodHound Enterprise enrichment, and CVSS-style base/temporal/environmental
  scoring with a risk vector.
- **Console:** at-a-glance dashboard, an **Actionable** view (DA pathways /
  breached / reused remediation lists), per-**Domain** stats, and a searchable,
  risk-filtered accounts table with role-gated reveal.
- **CLI:** `patd audit` (run the engine over dumps → ingest), `patd hashpw`.

## ⚠️ Store passphrase & data recovery — read this

Audits are encrypted at rest under a **store passphrase** that is **separate from
your login password** and is **never written to disk**. There is intentionally
**no recovery or reset**:

- **If you lose the store passphrase, every audit is permanently unrecoverable.**
  A lead can rotate it while unlocked (Settings → change passphrase), but cannot
  recover a forgotten one.
- **`data/keyfile.json` is as critical as the passphrase** — it holds the
  passphrase-wrapped data key. Lose it (or `data/`) and the encrypted blobs can't
  be opened either. **Back up the entire `data/` directory together**, and protect
  it: anyone with the keyfile can mount an *offline* guess against your passphrase,
  so choose a strong one (≥12 chars; longer is better).

Operational notes: the store starts **locked** after every restart — a lead
unlocks it via the UI (`/healthz` returns `503 {"status":"locked"}` until then).
It **auto-locks after idle** (`PATD_AUTOLOCK_MIN`, default 60; `0` disables),
dropping the key *and* clearing decrypted data from memory.

## Security & supply chain

- **Go is stdlib-first** — one external module (`golang.org/x/crypto`, for
  argon2). `govulncheck` runs in CI.
- **Web dependencies are vetted before install** — resolve the tree without
  running scripts, inspect it, `npm audit` (0 advisories), then
  `npm ci --ignore-scripts` from an exact-pinned, integrity-checked lockfile.
  `npm audit` runs in CI.
- See [CI](.github/workflows/ci.yml); the full policy is in this repo's
  `CLAUDE.md`.

## Layout

```
cmd/patd/        server + CLI (audit, hashpw, reindex)
internal/        engine + API: secretsdump · hibp · pwanalysis · bloodhound ·
                 risk · engine · report · policy · store · vault · model ·
                 auth · audit · httpapi · webui
web/             React + Vite console (TypeScript)
docs/            architecture, API, scoring
```

## Development

```bash
go build ./... && go vet ./... && go test ./...   # backend
cd web && npm run build                            # frontend (tsc + vite)
```

## License

See [LICENSE](LICENSE).
