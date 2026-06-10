# Password!AtTheDisco — architecture (Go + React rewrite)

This is a **full rewrite** of Password!AtTheDisco as a Go API + React frontend.
The original Python tool has been fully ported and **removed** — there is no
Python in the tree (it remains in git history if a port detail is ever needed).

The driver is delivery security: the Python tool's output is a self-contained
offline HTML bundle that necessarily writes **cleartext cracked passwords to
disk**. The new stack never does — cleartext lives only in process memory and is
revealed only to authorized operators, one account at a time, with an audit log.

```
  ingest (NTDS/dump) ─▶ Go engine (HIBP, BloodHound, risk) ─▶ Go API (TLS, authn/authz, audit) ─▶ React SPA
   parsing in Go        in-process, typed                      single binary: static assets + JSON
```

## Layout

```
cmd/patd/            server binary (+ hashpw, audit, reindex subcommands)
internal/
  httpapi/ auth/ audit/ store/ vault/ model/ policy/    API + persistence
  secretsdump/ hibp/ bloodhound/ pwanalysis/ risk/ engine/ report/   analysis
  webui/              embeds the built SPA (build tag `embed`)
web/                 React + Vite SPA (built to web/dist/, served by the binary)
```

## Architecture

- **Runtime = one Go binary.** Serves the built React SPA as static assets plus
  a JSON API over TLS. Only one external Go module (`golang.org/x/crypto`),
  keeping the runtime supply-chain surface tiny.
- **Node/npm is build-time only.** It compiles the React SPA to static files
  (`web/dist/`). Nothing from npm ships in the runtime; the Vite dev server is
  never used in production.
- **Engine logic moves into Go packages** (`internal/secretsdump`, `hibp`,
  `bloodhound`, `risk`) — typed, in-process, no cleartext rendered to disk.

## Security model

- **No cleartext credentials on disk.** Sensitive data lives in an
  access-controlled store and is served only by authenticated, authorized,
  **audit-logged** endpoints. Redacted-by-default; cleartext is an explicit,
  role-gated, logged action.
- **TLS-only** in production (`PATD_TLS_CERT` / `PATD_TLS_KEY`): the server
  **refuses to start** on a non-loopback address without TLS (plain HTTP is allowed
  only on loopback for local dev); HSTS is set when serving over TLS.
- **Strict CSP** + security headers; same-origin only (no external CDNs — assets
  are self-hosted, consistent with the v1 offline vendoring).
- **Isolated build.** `npm` runs only on a build host with **no secrets/creds**
  present (the 2025 npm worms steal exactly those).

## Persistence & recovery

Audits are encrypted at rest under a random 32-byte data-encryption key (DEK). The
DEK is wrapped by an argon2id key derived from the store passphrase. Everything
lives under `PATD_DATA` (default `data/`):

| File | Contents | If lost |
|---|---|---|
| `keyfile.json` | the DEK wrapped under the passphrase | **total loss** — the DEK (and thus every audit) is unrecoverable; there is no reset or escrow |
| `audits/<id>.enc` | one encrypted audit dataset (AES-256-GCM, AAD = `patd-audit:<id>`) | that audit is lost; others are unaffected |
| `index.enc` | encrypted metadata index (names/counts) — a **derived cache** (AAD = `patd-index`) | self-heals: on unlock the server rebuilds it from the blobs; `patd reindex` forces a rebuild |
| `keyfile.json.bak` | **transient** crash-safety copy written during *either* rotation (change-passphrase or rotate-data-key) and removed on success | **do not restore it.** It holds only the *old* key/passphrase; after an interrupted **data-key** rotation it would make every already-re-sealed blob undecryptable. To recover an interrupted rotation, keep `keyfile.json` (it carries both keys) and re-run *Rotate data key* to resume. |

Operational rules:
- **Back up `data/` as a unit** (a consistent snapshot). The files reference each
  other; a torn backup (new index, old blobs) is reconciled on load but avoid it.
- **The passphrase is unrecoverable.** Losing it (or `keyfile.json`) loses all
  audits — there is no recovery key. Store it in a team password manager.
- **Two rotations are available (lead, Policies tab):**
  - *Change passphrase* re-wraps the **same** DEK under a new passphrase and deletes
    `keyfile.json.bak`, so the old passphrase stops working going forward.
  - *Rotate data key* generates a **new DEK** and re-encrypts every audit + the
    index under it (passphrase unchanged). Use after a suspected key exposure, or to
    reset the GCM nonce space. It is crash-safe: the keyfile holds **both** keys
    during the migration (so an interruption leaves every blob readable) and a
    re-run **resumes**; the old key is dropped only once all blobs are re-sealed.
  - Either way, snapshots taken *before* the rotation remain decryptable with the
    old credential/key — to truly retire a leaked one, rotate **and** re-snapshot,
    discarding old backups. A data-key rotation makes pre-rotation blob backups
    cryptographically stale (they can't be read with the new DEK).
- **Tamper resistance.** Each blob is AEAD-bound to its audit id and the index to
  its role, so an attacker with write access to `data/` cannot swap one ciphertext
  for another. (A full-snapshot rollback still requires external integrity
  anchoring, which is out of scope.)
- **Idle auto-lock** (`PATD_AUTOLOCK_MIN`, default 60) drops the DEK + clears
  decrypted data from memory after inactivity; a lead re-enters the passphrase. A
  restart always starts locked.

## Supply-chain controls (hard gate)

Every dependency is CVE/advisory-checked **before** use, and the surface is kept
minimal:

| Layer | Dependencies | Notes |
|---|---|---|
| Go runtime | stdlib + `golang.org/x/crypto/argon2` **v0.52.0** (+ `x/sys` transitive) | official modules; only `/argon2` is used, not the `/ssh` CVE surface; checksummed in `go.sum`; `govulncheck ./...` reports **no vulnerabilities** |
| Web runtime (shipped) | `react` 19.2.7, `react-dom` 19.2.7 | the only npm code that reaches users |
| Web build (dev only) | `vite` 8.0.16, `@vitejs/plugin-react` 6.0.2, `typescript` 6.0.3, `@types/*` | Vite ≥ 8.0.5 patches the dev-server file-read CVEs (CVE-2026-39363/39364, CVE-2025-31125); we also bind dev to localhost. Using `plugin-react` (not the RCE-affected `plugin-rsc`). |

Process:
- **Exact-pinned** versions (no `^`/`~`); lockfiles (`go.sum`, `package-lock.json`)
  committed with integrity hashes.
- `npm ci --ignore-scripts` — blocks the install/postinstall payload vector used
  by the 2025 Qix/chalk-debug and Shai-Hulud compromises.
- CI gates (blocking): `govulncheck ./...` (Go) and `npm audit` (web); Dependabot on.
- Review the full transitive tree before the first install; re-pin deliberately.

## API & access model

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /api/login` | — (rate-limited per IP) | authenticate; sets HttpOnly/SameSite=Strict session cookie, returns a CSRF token |
| `POST /api/logout` | session + CSRF | revoke the session |
| `GET /api/me` | session | current operator, role, and CSRF token |
| `POST /api/ingest` | bearer token | analysis engine pushes the dataset (fails closed) |
| `GET /api/accounts`, `GET /api/summary` | session (any role) | **redacted** data + aggregates |
| `GET /api/accounts/{username}/secret` | session, **`lead` role** | reveal one cleartext password — **always audit-logged** |

Roles: `analyst` (redacted only) · `lead` (may reveal). Every reveal attempt
(allowed *or* denied) is written to the audit log with actor/target/time —
**never the password value**.

## Build & run

```bash
# Backend (from repo root):
go build ./... && go vet ./... && go test ./...
go build -o patd ./cmd/patd

# Create operators (argon2id hashes; copy users.example.json -> users.json):
go run ./cmd/patd hashpw       # prompts on stderr, prints the hash on stdout

PATD_TLS_CERT=cert.pem PATD_TLS_KEY=key.pem PATD_INGEST_TOKEN=$(openssl rand -hex 32) \
  PATD_USERS_FILE=users.json PATD_AUDIT_LOG=audit.log PATD_STATIC_DIR=web/dist ./patd

# Frontend (vet deps first; see Supply-chain controls):
cd web && npm ci --ignore-scripts && npm audit --audit-level=moderate && npm run build

# Single-binary release (SPA embedded via embed.FS, served with zero disk deps):
cd web && npm ci --ignore-scripts && npm run build && cd ..
rm -rf internal/webui/dist && cp -r web/dist internal/webui/dist
go build -tags embed -o patd ./cmd/patd        # ~11 MB self-contained binary
```

Static SPA serving: the binary serves `internal/webui` (embedded, `-tags embed`)
when present, else `PATD_STATIC_DIR` on disk (default `web/dist`) — so default/CI
builds need no frontend.

Env: `PATD_ADDR` (default `127.0.0.1:8443`), `PATD_TLS_CERT`/`PATD_TLS_KEY` (TLS;
plain HTTP with a warning if unset), `PATD_INGEST_TOKEN` (engine bearer token;
ingestion disabled if unset), `PATD_USERS_FILE` (default `users.json`),
`PATD_AUDIT_LOG` (default stdout; file is created `0600`), `PATD_STATIC_DIR`
(built SPA, default `web/dist`).

## Status

**Shipped.** The rewrite is merged into `main` (the repo's default branch) and is
green in CI on GitHub Actions. The full stack was verified end-to-end (browser +
API): authn/authz, role enforcement in both the UI and the API, redaction,
audited cleartext reveal, CSRF, session lifecycle, real-HIBP scoring, and the
audit log (no cleartext). Remaining items are optional polish.

- [x] Go API skeleton — TLS-capable, strict security headers, `/healthz`,
      `/api/version`, SPA static serving with path-traversal protection, graceful
      shutdown. Builds/vets clean, zero deps.
- [x] React SPA skeleton — pinned, build-time-only toolchain.
- [x] In-memory store (cleartext only in RAM, never on disk) + token-gated
      `POST /api/ingest` (fails closed) + **redacted-by-default** `GET /api/accounts`
      and `GET /api/summary`. Unit-tested + verified end-to-end.
- [x] AuthN/AuthZ — local users (argon2id), in-memory sessions (HttpOnly cookie),
      `analyst`/`lead` roles. `golang.org/x/crypto` vetted + govulncheck-clean.
- [x] Role-gated, **audit-logged** cleartext reveal (`/api/accounts/{u}/secret`).
      Unit-tested + verified end-to-end (analyst denied, lead allowed, no cleartext
      in the audit log).
- [x] **Session hardening** — per-IP login rate-limiting (429 + `Retry-After`),
      synchronizer CSRF token on state-changing requests, sliding idle + absolute
      session expiry. Unit-tested + verified live.
- [x] **Engine ports** (from the now-removed Python v1): `secretsdump` ✅ →
      `hibp` ✅ → `risk` (scoring + vector) ✅ → `bloodhound` (BHE client + DA
      pathways) ✅.
- [x] **Password analysis** (`pwanalysis`): complexity / policy / wordlist /
      keyboard / similarity (Levenshtein) signals feeding `risk.Analysis`.
- [x] **Orchestration pipeline** (`engine`): parse → HIBP → analysis → BHE →
      score per account → `model.Account` (shared-with, similarity caching,
      simplified uncracked scoring). HIBP/BHE injected behind interfaces; a
      `BloodhoundEnricher` adapter wraps the real client. (Deferred refinements:
      post-hoc shared-password risk boost, domain-risk factor, cross-domain reuse.)
- [x] **Wiring / CLI** (`patd audit`): loads lists + HIBP + (optional) BHE, runs
      the engine over domain dumps, and POSTs the dataset to `/api/ingest`.
      Verified end-to-end: dumps → real HIBP correlation → scored, redacted serving.
- [x] **React UI**: login, dashboard, **Actionable** (DA pathways / breached /
      reused remediation lists), **Domains** (per-domain stat cards), and the
      accounts table (search + risk filter) with **lead-gated audited reveal** —
      wired to the live API (cookie session + CSRF). Actionable/Domains derive
      client-side from `/api/accounts` via a shared provider. SOC console /
      disco-noir theme, strict-CSP-friendly. Vetted/built/browser-verified.
      Next: table pagination/virtualization for large datasets, account detail.
      (Build: `cd web && npm ci --ignore-scripts && npm run build`.)
- [x] **SPA embedded in the binary** (`internal/webui`, `-tags embed` via
      `embed.FS`): single self-contained ~11 MB binary, fs.FS static serving with
      on-disk fallback. Verified serving the embedded SPA with no disk deps.
- [x] **CI security gates** (`.github/workflows/ci.yml`): Go job
      (build/vet/gofmt/test + **govulncheck**) and web job
      (`npm ci --ignore-scripts` + **`npm audit --audit-level=moderate`** +
      tsc/vite build). Both blocking; **green in CI on GitHub Actions**.
- [ ] **Persistence + packaging**: encrypted-at-rest store, TLS cert setup.
