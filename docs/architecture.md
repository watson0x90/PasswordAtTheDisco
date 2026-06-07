# Password!AtTheDisco — architecture (Go + React rewrite)

This is a **full rewrite** of Password!AtTheDisco as a Go API + React frontend.
The original Python tool (now under `legacy-python/`) is kept only as a porting
reference and is removed subsystem-by-subsystem as each Go replacement reaches
parity. **End state: no Python.**

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
cmd/patd/            server binary (+ `hashpw` subcommand)
internal/
  httpapi/ auth/ audit/ store/ model/    built
  secretsdump/ hibp/ bloodhound/ risk/    to port from legacy-python/
web/                 React + Vite SPA (built to web/dist/, served by the binary)
legacy-python/       v1 reference, deleted as parity is reached
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
- **TLS-only** in production (`PATD_TLS_CERT` / `PATD_TLS_KEY`).
- **Strict CSP** + security headers; same-origin only (no external CDNs — assets
  are self-hosted, consistent with the v1 offline vendoring).
- **Isolated build.** `npm` runs only on a build host with **no secrets/creds**
  present (the 2025 npm worms steal exactly those).

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

# Frontend (in an isolated build env, no secrets present):
cd web && npm ci --ignore-scripts && npm audit --audit-level=moderate && npm run build
```

Env: `PATD_ADDR` (default `127.0.0.1:8443`), `PATD_TLS_CERT`/`PATD_TLS_KEY` (TLS;
plain HTTP with a warning if unset), `PATD_INGEST_TOKEN` (engine bearer token;
ingestion disabled if unset), `PATD_USERS_FILE` (default `users.json`),
`PATD_AUDIT_LOG` (default stdout; file is created `0600`), `PATD_STATIC_DIR`
(built SPA, default `web/dist`).

## Status

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
- [x] **Engine ports** from `legacy-python/`: `secretsdump` ✅ → `hibp` ✅ →
      `risk` (scoring + vector) ✅ → `bloodhound` (BHE client + DA pathways) ✅.
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
- [ ] **React UI** (next): login → dashboard → redacted table/search → reveal →
      actionable / per-domain views.
- [ ] **Persistence + packaging**: encrypted-at-rest store, SPA embedded in the
      binary, TLS, CI security gates (`govulncheck`, `npm audit`) — CI deferred.
