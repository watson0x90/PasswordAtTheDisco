# Password!AtTheDisco

**Windows Active Directory password-exposure auditing — without leaving cracked credentials lying around.**

[![CI](https://github.com/watson0x90/PasswordAtTheDisco/actions/workflows/ci.yml/badge.svg)](https://github.com/watson0x90/PasswordAtTheDisco/actions/workflows/ci.yml)

Password!AtTheDisco ingests credential dumps from a Windows AD password audit, correlates
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

## What's new in 2.29

**Getting Tier-0 right — accurate detection, a justified verdict, and the receipts.**

- **Transitive outbound-control detection.** The bulk BloodHound enricher counted only *first-degree*
  control, so an account that controls thousands of objects *through group membership* read as harmless.
  It now fetches BloodHound's **true transitive** outbound-control count and runs a **reachable** Tier-0/DA
  shortest-path sweep for the credential-obtainable set (cracked / HIBP / roastable) — a cracked admin
  controlling 16k objects with a DA path now scores **Critical**, not Low. (Enrichment runs in two labelled
  phases: *Step 1* bulk baseline, *Step 2* per-candidate detail.)
- **A justified verdict, not a tripwire.** "Critical" is reserved for accumulation an org will believe —
  **≥2 reachable Tier-0 controllers, or 1 + a reachable DA path**; a *lone* reachable Tier-0 reads **High
  Risk**. Every Tier-0 verdict states its composition ("Critical — 7 reachable Tier-0 controllers"), so the
  rating always carries its receipts.
- **Exposure "blast radius" table.** A ranked, flagged (T0/DA/Crk/RCH) table of the cracked/HIBP-exposed
  accounts controlling the most objects — the on-screen evidence behind the verdict.

Earlier: the executive scoring rework — Hygiene × Reachability + Tier-0 gate (2.28); reuse-floor mid tier
(2.27); mass-reuse escalation + bulk Tier-0 flagging (2.26); BloodHound upload fidelity (2.24); an **MCP
server** for AI agents (2.21).

## What's new in 2.28

**Executive scoring rework — the headline can no longer contradict itself.**

- **Two orthogonal axes replace the single "Posture" number.** *Credential Hygiene* (an honest average
  over **enabled** accounts — the dead privilege term removed, disabled no longer padding it) × *Breach
  Reachability* (a smooth, scale-aware, worst-path likelihood). A **one-way Tier-0/reachability gate**
  means the headline **Verdict** can't read "Strong" while a reachable path to domain-control exists — a
  reachable Tier-0/DCSync path caps it at **Critical** regardless of hygiene (SSL-Labs / CVSS / BloodHound
  Enterprise convention). Vetted by a 3-expert panel (offensive-security, measurement theory, risk
  frameworks).
- **HIBP-breached uncracked hashes now count as reachable** — a password in the public breach corpus is
  effectively obtainable; an uncracked hash *not* in HIBP is not held against you.
- **Breach impact is reachability-driven** (not Critical-count), **dormant privileged** (disabled but
  pre-compromised) accounts are surfaced, and the model is mirrored Go⇄TS with a 10-case parity golden.

Surfaced by auditing a **sanitized review export** (2.25). Earlier: reuse-floor mid tier (2.27);
mass-reuse escalation + bulk Tier-0 flagging (2.26); BloodHound upload fidelity (2.24); sharper Exposure
weights (2.23); an **MCP server** for AI agents (2.21).

See **[CHANGELOG.md](CHANGELOG.md)** for the full release history.

> Lab note: this repo ships **fictional** placeholder domains
> (`PHANTOM.CORP` / `GHOST.CORP`) in `lists/password_policy.json`. Point it at
> your own domains locally — real domain names, usernames, and cracked data are
> never committed.

## Build

**One command builds everything** — the React web UI *and* the Go server, bundled into a
single self-contained executable. You don't build the frontend separately; the build
script compiles the SPA, embeds it, and builds the binary in one step.

**Prerequisites:** Go 1.26+ and Node 20+. (Node is needed only at build time — the
finished binary embeds the web UI and has no Node/runtime dependency.)

```bash
# one-time: install the web UI's dependencies
cd web && npm ci --ignore-scripts && cd ..

# build the whole thing — run ONE of these (same build, one per shell — not both):
scripts/build.sh      # Linux, macOS, or Windows (Git Bash)
scripts\build.ps1     # Windows (PowerShell)
```

Each script builds the SPA, embeds it, stamps the version from `git describe`, and
produces `patd` (`patd.exe` on Windows). Flags: `--skip-web` (skip the SPA rebuild and
reuse the existing `web/dist`), `--output <path>` (`-SkipWeb` / `-Output` in PowerShell).

Confirm the stamp:

```bash
./patd --version          # patd v2.31.0 (abc1234, built 2026-06-25T...Z)
```

**Quick dev loop (no full build):** `go run ./cmd/patd` runs the server and serves
`web/dist` from disk (re-run `cd web && npm run build` when you change the UI); it reports
`version=dev`. Use the build scripts when you want the real single-file, versioned binary.

## Run

```bash
patd                       # 127.0.0.1:8443 (default)
patd --port 9000           # 127.0.0.1:9000
patd --addr 0.0.0.0:8443   # bind all interfaces (requires TLS, see below)
PATD_ADDR=127.0.0.1:9000 patd
```

Precedence is `--addr`/`--port` flag → `PATD_ADDR` → default `127.0.0.1:8443`. Binding a
non-loopback address requires TLS — set `PATD_TLS_CERT` and `PATD_TLS_KEY`, or the server
refuses to serve plaintext off loopback. `patd --help` lists all flags and key env vars.

## First run — operators

Bootstrap the first lead operator, then start the server and log in:

```bash
patd user add admin --role lead     # prompts for a password (stdin)
patd user list                      # USERNAME  ROLE  STATUS
patd user passwd admin              # reset a password
```

While the server is running it owns `users.json` — add or edit operators in the **UI**
(Admin → Operators), not the CLI. The CLI refuses to edit the file when it detects a
running server; pass `--force` to override (last resort; can clobber the server's copy).

> Setting up a real instance? Use the **guided installer** instead — see
> [Deploy (first-time setup)](#deploy-first-time-setup), which builds the binary, creates
> your first operator, and sets up TLS in one guided flow.

## Run an audit

Run the engine over your dumps and push the results to the running server. `-token` is the
ingest bearer token the server was started with (`PATD_INGEST_TOKEN`):

```bash
# Run an audit and push results to the running server
./patd audit -token "$PATD_INGEST_TOKEN" \
  -hibp PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt \
  CORP cracked.txt uncracked.txt

#    Or the dump-first workflow: load the full pwdump, then apply hashcat output
#    by NT hash (one cracked hash flips every account that shares it):
./patd audit -crackfile cracked.potfile CORP ntds.pwdump
```

The same flow works in the console **Upload** tab: drop the full secretsdump/pwdump in
the *uncracked* slot (every account loads with its NT hash), then **Apply hashcat
results** (`user:hash:password`) — matched by hash, re-scored, no re-upload.

Then open the console, sign in, and triage: **Overview → Actionable → Domains →
Accounts** (with the lead-gated reveal).

**No data handy? Generate some.** `python tools/gen_synthetic.py` writes a
self-contained multi-domain sample set — synthetic NTLM hashes + a crack file with
realistic reuse / HIBP / weak-password scenarios — to `sample_data/synthetic/`:
upload each `*_dump.txt`, then apply `cracks.txt`. Credentials are 100% synthetic
(no real hashes or passwords). If you have a BloodHound lab connected,
`tools/gen_bh_sample.py` builds a much larger dataset seeded from your real BHE
users (still synthetic credentials) so the DA-pathway, kerberoastable, controlled-
objects, and network-graph dashboards populate too.

Input is impacket `secretsdump` NTDS format
(`user:rid:lm:nt:::password`) or a simple `user:hash[:password]`; HIBP and
BloodHound are optional. See [`docs/architecture.md`](docs/architecture.md) for
the full data flow, API, scoring model, and config.

## Deploy (first-time setup)

The **guided installer** is the recommended path. It builds the binary, creates your
first **lead** operator (`patd hashpw` → `users.json`), sets up TLS, writes the config,
and leaves a launcher — *without* installing a service (that's a separate, opt-in step).

```bash
git clone https://github.com/watson0x90/PasswordAtTheDisco
cd PasswordAtTheDisco

./deploy/deploy.sh                         # Linux/macOS — prompts for dir, address, operator, TLS
<install-dir>/run.sh                       # start it in the foreground …
sudo ./deploy/deploy.sh --install-service  # … or install it as a service (systemd / launchd)
```
```powershell
.\deploy\deploy.ps1                        # Windows — same guided flow
.\deploy\deploy.ps1 -InstallService        # elevated: register a startup Scheduled Task
```

Then, **on first run in the browser**:

1. Open the URL the installer printed and **sign in** as the lead operator you created.
2. **Set the store passphrase** on the unlock screen. This is the at-rest encryption
   key — held only in memory, **never written to disk**, with no reset. Save it in a
   password manager (see the recovery warning below).
3. Add more operators in **Operators**, and — optionally — wire up **HIBP** (the *HIBP*
   tab builds + downloads the NTLM set) and **BloodHound** (`config/bloodhound.json`).

> Credential-bearing host? Build the binary on a clean box and deploy that one with
> `./deploy/deploy.sh --binary /path/to/patd`, so `npm` never runs on the prod host.

Static CGO-free binary → runs on **Linux / macOS / Windows (amd64 + arm64)**. Full
guide (env vars, TLS, service management, backup/recovery): **[deploy/DEPLOYMENT.md](deploy/DEPLOYMENT.md)**.

## MCP server (for AI agents)

Password!AtTheDisco speaks the **Model Context Protocol**, so an AI agent (Gemini CLI,
Kiro, Claude Desktop, …) can query an audit through a scoped token. One endpoint,
bearer-authenticated, every call audited — no operator password is ever handed to the agent.

**1. Mint a token** (managing tokens requires the **lead** role):

- In the console: **Admin → MCP Tokens → Issue token**. Pick **analyst** (redacted data
  only) or **lead** (may also reveal cleartext), then copy the secret — it is shown once.
- Or from the CLI, for the first token before the UI is reachable (run it while the server
  is **stopped** — the running server owns the token file):

  ```bash
  patd token create --role analyst --label gemini   # prints patdmcp_… once
  patd token list                                    # id, label, role, last-used, status
  patd token revoke <id>
  ```

  Tokens are stored **hashed** in `mcp_tokens.json` (path via `PATD_MCP_TOKENS_FILE`;
  gitignored). Once the server is running, manage tokens in the **Admin UI** so changes
  take effect live.

**2. Connect your agent.** The server is Streamable-HTTP MCP at `POST /api/mcp` with an
`Authorization: Bearer <token>` header. The config key name varies by client
(`httpUrl` / `url` / `serverUrl`); the essentials are the `/api/mcp` URL and the bearer
header:

```json
{
  "mcpServers": {
    "passwordatthedisco": {
      "httpUrl": "https://your-host:8443/api/mcp",
      "headers": { "Authorization": "Bearer patdmcp_…" }
    }
  }
}
```

Smoke-test it with curl (lists the tools your token's role may use):

```bash
curl -s -H "Authorization: Bearer patdmcp_…" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  https://your-host:8443/api/mcp
```

> The data store must be **unlocked** (a lead unlocks it in the UI) for the data tools to
> return results — the MCP token authenticates the *agent*; it does not unseal the vault.

**3. Tools.** `audit_id` is optional on every data tool (defaults to the most recent audit):

| Tool | Role | Returns |
|---|---|---|
| `list_audits` | analyst | available audits (id, name, account counts) |
| `get_posture` | analyst | org posture: counts, risk score, breach-impact, BloodHound coverage |
| `list_accounts` | analyst | redacted accounts — filter (risk/cracked/domain/HIBP/DA), sort, paginate (≤200) |
| `search_accounts` | analyst | redacted accounts matching a username/domain query |
| `domain_breakdown` | analyst | per-domain accounts / cracked / breached / critical / DA-path counts |
| `password_in_use` | analyst | which accounts use a given password (matched by NT hash; the candidate is never stored or logged) |
| `get_report` | analyst | the actionable report (redacted) |
| `diff_audits` | analyst | newly-cracked / remediated / regressed / newly-breached between two audits |
| `reveal_password` | **lead** | the cleartext for **one** account — audit-logged, fail-closed |

**Security model.** Tokens are role-scoped and SHA-256-hashed (shown once). Every
non-reveal tool returns the same **redacted** shapes as the web console — no cleartext,
no NT hash. `reveal_password` is **lead-only**, one account per call, and **audit-logged**
(the account, never the password); if the audit write fails, the cleartext is withheld.
Analyst tokens never even see `reveal_password` in `tools/list`. Revoke a token any time
in the Admin UI — revocation is immediate.

## Features

- **Engine:** secretsdump parsing, HIBP NTLM lookup over a 74 GB prefix-indexed
  dump, password analysis (complexity / policy / wordlists / similarity),
  BloodHound Enterprise enrichment, and CVSS-style base/temporal/environmental
  scoring with a risk vector.
- **Console:** at-a-glance dashboard, an **Actionable** view with full remediation
  reports (DA pathways, cracked credentials, accounts sharing a *cracked* password,
  accounts sharing an *uncracked* NT hash, and HIBP-exposed accounts with breach
  counts — reuse grouped server-side by NT hash so the hash never leaves the process),
  per-**Domain** stats, a sortable, paginated, risk-filtered accounts table with
  role-gated reveal, a **⌘K command palette** and a **Search** tab (account search +
  a password-in-use NTLM probe), and a **Reports** tab that exports redacted reports
  as **CSV or HTML** — a
  per-account summary (crack status, HIBP exposure, password reuse, Tier-0/privileged
  pathway — never a password or hash), plus focused cracked-only, HIBP-exposed, and
  password-reuse-group reports.
- **Administration (lead-only):** runtime **Operator** management (add / disable /
  remove with live effect, no restart; per-account **login lockout** + last-login),
  a searchable, CSV-exportable **Activity** view over the audit log, an **HIBP**
  page that builds the bundled PwnedPasswordsDownloader and downloads + indexes the
  NTLM set in the background, and a **BloodHound** page to configure + test the BHE
  connection from the console — both hot-swap the live integration without a restart.
- **CLI:** `patd audit` (run the engine over dumps → ingest), `patd user`
  (bootstrap / manage operators), `patd hashpw`, `patd token` (manage MCP API tokens),
  `patd reindex`; `patd --help` / `patd --version`.
- **MCP server:** a Streamable-HTTP JSON-RPC endpoint (`POST /api/mcp`) that lets AI
  agents query an audit through role-scoped tokens — redacted read tools plus a lead-only,
  audited cleartext reveal. See **[MCP server (for AI agents)](#mcp-server-for-ai-agents)**.

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
cmd/patd/        server + CLI (audit, user, hashpw, token, reindex)
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
