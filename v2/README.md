# Password!AtTheDisco — v2 secure delivery stack

The Python tool (repo root) is the **analysis engine**: it parses SecretsDump
output, correlates against HIBP, enriches via BloodHound, and computes CVSS-style
risk. Its v1 output is a self-contained, offline HTML report bundle — which
necessarily writes **cleartext cracked passwords to disk**.

v2 replaces *delivery* (not the engine) with an access-controlled stack so those
credentials are never sitting in world-readable static files:

```
  Python engine  ──structured data──▶  Go API (TLS, authn/authz, audit)  ──▶  React SPA
   (keep as-is)                         single binary, stdlib-only              (static, served by Go)
```

## Architecture

- **Runtime = one Go binary.** Serves the built React SPA as static assets plus
  a JSON API over TLS. **Standard library only** — zero third-party runtime
  dependencies, so the runtime supply-chain surface is just the Go toolchain.
- **Node/npm is build-time only.** It compiles the React SPA to static files
  (`web/dist/`). Nothing from npm ships in the runtime; the Vite dev server is
  never used in production.
- **The engine stays Python.** The hard, well-tested logic (parsing, HIBP,
  BloodHound, scoring) is reused; it will emit structured data into the API's
  store rather than rendering cleartext HTML.

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
| Go runtime | **stdlib only** | no `go.sum`; `govulncheck` clean |
| Go (later, for auth) | `golang.org/x/crypto/argon2` (official) | avoid `/ssh` (CVE-2024-45337 etc. are SSH-only); pin ≥ v0.45.0 |
| Web runtime (shipped) | `react` 19.2.7, `react-dom` 19.2.7 | the only npm code that reaches users |
| Web build (dev only) | `vite` 8.0.16, `@vitejs/plugin-react` 6.0.2, `typescript` 6.0.3, `@types/*` | Vite ≥ 8.0.5 patches the dev-server file-read CVEs (CVE-2026-39363/39364, CVE-2025-31125); we also bind dev to localhost. Using `plugin-react` (not the RCE-affected `plugin-rsc`). |

Process:
- **Exact-pinned** versions (no `^`/`~`); lockfiles (`go.sum`, `package-lock.json`)
  committed with integrity hashes.
- `npm ci --ignore-scripts` — blocks the install/postinstall payload vector used
  by the 2025 Qix/chalk-debug and Shai-Hulud compromises.
- CI gates (blocking): `govulncheck ./...` (Go) and `npm audit` (web); Dependabot on.
- Review the full transitive tree before the first install; re-pin deliberately.

## Build & run

```bash
# Backend (Go installed):
cd v2/api && go build ./... && go vet ./...
PATD_TLS_CERT=cert.pem PATD_TLS_KEY=key.pem PATD_STATIC_DIR=../web/dist ./api

# Frontend (in an isolated build env, no secrets present):
cd v2/web && npm ci --ignore-scripts && npm audit --audit-level=moderate && npm run build
```

`PATD_ADDR` (default `127.0.0.1:8443`), `PATD_TLS_CERT`/`PATD_TLS_KEY` (TLS;
plain HTTP with a warning if unset), `PATD_STATIC_DIR` (built SPA, default
`../web/dist`).

## Status

- [x] Go API skeleton — TLS-capable, strict security headers, `/healthz`,
      `/api/version`, SPA static serving with path-traversal protection, graceful
      shutdown. Builds/vets clean, zero deps.
- [x] React SPA skeleton — pinned, build-time-only toolchain.
- [ ] Engine → API data ingestion (structured findings).
- [ ] AuthN/AuthZ + session handling.
- [ ] Redacted-by-default views; role-gated, audit-logged cleartext.
- [ ] CI security gates (`govulncheck`, `npm audit`).
