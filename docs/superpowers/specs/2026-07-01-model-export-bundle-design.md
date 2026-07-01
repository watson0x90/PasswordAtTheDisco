# Model Export Bundle (JSON + SVG images) — Design

**Status:** Approved (2026-07-01)

## Goal
Give downstream models (Gemini, Kiro, etc.) a single, self-contained download per audit scope that carries (a) the full derived metrics as JSON, (b) the account rows, and (c) the dashboard charts/graphs as image files the JSON references — so a model can post-process the numbers and embed the visuals into a report it generates. Two variants: a **sanitized** bundle (open) and a **gated cleartext** bundle (cracked passwords included).

## Context (what already exists)
- `GET /api/metrics` (+`?domain=D`) returns the Go metrics bundle: `{summary, matrix, charts, reports, domains[]}` — the single source all dashboards + exports now render (post drift-elimination campaign).
- `GET /api/export/sanitized.json` returns `report.SanitizedReport {schema_version, generated_at, tool_version, summary, domains[], accounts[]}` (account allowlist; no matrix/charts/reports).
- The HTML export (`internal/report/report.go HTML()`, `internal/report/charts.go`) renders every chart + the 2 network graphs as **standalone inline `<svg>`** documents.
- Cleartext exports (`POST /api/export/cleartext.{csv,html}`) are lead-gated: `requireAuth→requireCSRF→requireUnlocked` middleware + handler lead-role + `{acknowledge:true}` body + fail-closed `auditOrFail` (`Action:"export_cleartext"`, never logs a password). Account projections: `SanitizedAccount` (no secrets) and `model.Account.RedactedKeepPassword()` (keeps cleartext Password, strips NTHash/BannedWords/KeyboardPatterns).

## Non-goals
- No PNG rasterization (decided: ship SVG, zero new deps, no drift). No new third-party dependencies — stdlib `archive/zip` + `encoding/json` only.
- No cleartext ever in the default sanitized bundle. NT hashes / wordlist fragments never exported in ANY bundle (JSON or SVG).
- Focused exports (cracked/hibp/weak/reuse) are out of scope — this is the org/per-domain full bundle.

## Artifact
A `.zip` per scope:
```
audit_report.zip
 ├─ report.json
 └─ images/
     ├─ risk_distribution.svg
     ├─ reuse_graph.svg
     └─ … (every non-empty chart + graph)
```

### report.json schema (one schema for both variants)
```jsonc
{
  "schema_version": 1,
  "generated_at": "<RFC3339 UTC>",
  "tool_version": "<build version>",
  "scope": "org",                 // or "domain:CORP.LOCAL"
  "cleartext": false,             // true only in the cleartext bundle
  "metrics": { /* the metrics bundle: summary, matrix, charts, reports, domains[] (domain-scoped when ?domain=) */ },
  "accounts": [ /* IDENTIFIED, secret-free BundleAccount rows: real username+domain + safe scoring fields; +cleartext "password" for cracked accounts in the cleartext variant only (never nt_hash) */ ],
  "images": {                     // manifest: chart name -> relative path in the zip
    "risk_distribution": "images/risk_distribution.svg",
    "reuse_graph": "images/reuse_graph.svg"
    // … one entry per emitted svg; omitted when the chart's dataset is empty
  }
}
```
- **Org scope:** `metrics` = the full org bundle (includes `domains[]`); `accounts` = all accounts; `images` = org chart set.
- **Per-domain scope (`?domain=D` / body `domain`):** `metrics` = that domain's `DomainMetrics` (`{domain, summary, matrix, charts, reports}`); `accounts` = that domain's accounts; `images` = that domain's chart set (no `reuse_graph` — cross-domain is org-only, matching the dashboards). 404 `{"error":"domain not found"}` when the domain has no accounts.

## Endpoints
| Method | Path | Variant | Gating |
|---|---|---|---|
| GET | `/api/export/bundle.zip` (`?domain=D`) | sanitized | `requireAuth`+`requireUnlocked` (any operator, like `sanitized.json`) |
| POST | `/api/export/cleartext.zip` (body `{acknowledge, domain?}`) | cleartext | `requireAuth`+`requireCSRF`+`requireUnlocked` middleware; handler: lead-role else fail-closed-audited 403; `acknowledge:true` else 400; fail-closed `auditOrFail` `Action:"export_cleartext"` `Result:"ok"|"denied"` (Target = name/scope, never a password) |

Filenames via existing `download()` + `safeFilename`: sanitized org `Name.zip`; per-domain `Name_<Domain>.zip`; cleartext org `Name_CLEARTEXT.zip`; cleartext per-domain `Name_<Domain>_CLEARTEXT.zip`.

## Images
- Reuse the exact SVG the HTML export produces. Each `images/<name>.svg` is a complete standalone `<svg xmlns=…>` document (they already are).
- Chart set = the full-visual set already in the HTML export: `risk_distribution`, `hibp_split`/`hibp_exposure`, `expiration`, `length`, `score`, `sharing`, `controlled`, `similarity`, `complexity`, `da_by_domain`, `hibp_vs_risk`, `password_age_scatter`, `axis_factor_bars`, `reuse_graph`, `similarity_graph`. Names are stable snake_case keys.
- Empty datasets are skipped in BOTH the files and the `images` manifest (same rule the HTML export uses).
- SVGs are identical across sanitized/cleartext variants — they contain only counts/labels; node labels are usernames/domains (already non-secret, `html.EscapeString`'d). No account secret is ever rendered into an image.

## Account projection (`BundleAccount`)
A NEW identified allowlist projection in the report package (NOT the opaque `SanitizedAccount`): real `username` + `domain` + every safe scoring/structural field (risk level/score/vector, exposure/impact, hibp, shared/reuse, has_da_path + da_domains, controlled/tier0, enabled, coverage, policy/wordlist counts, password age/expiry, spn/preauth, similarity + similar_peers as real username/domain, score_breakdown). It is an ALLOWLIST (nothing copied from `model.Account` except named fields), so future fields are excluded by default. A single builder `bundleAccounts(accounts []model.Account, cleartext bool, now) []BundleAccount` emits `password` (cleartext) ONLY when `cleartext && a.Cracked`; it NEVER emits `NTHash`, `BannedWords`, or `KeyboardPatterns`.

## Security
- **Sanitized bundle:** `bundleAccounts(..., cleartext=false)` — identities kept, no password, no NT hash. Open to any authenticated, unlocked operator.
- **Cleartext bundle:** `bundleAccounts(..., cleartext=true)` — adds cleartext `password` for cracked accounts (never NTHash/wordlist). Lead + CSRF + acknowledge + fail-closed audit. `report.json.cleartext = true`.
- **Redaction guard:** extend the metrics/report redaction canary so the SANITIZED bundle's full serialized zip (report.json + all svg) is asserted free of any cleartext / NT hash / wordlist fragment on a secret-bearing fixture. The CLEARTEXT bundle test asserts the cleartext password appears in `accounts` but NOT in any `images/*.svg` and NOT as an NT hash anywhere, and that no audit event contains the password.

## Implementation (DRY / anti-drift)
- **Extract chart SVGs once:** refactor the HTML export's per-chart SVG generation into a reusable helper, e.g. `report.ChartSVGs(m metrics.Metrics) map[string]string` (org) and the per-domain equivalent from `DomainMetrics`, returning stable-named standalone SVG strings. `HTML()` and the new bundle both consume it — one source of chart rendering (consistent with the just-completed campaign; no second copy to drift).
- **Bundle writer:** `report.BundleZip(w io.Writer, meta, scope, cleartext bool, m, accounts, now)` builds `report.json` + `images/*.svg` into a `zip.Writer` (stdlib `archive/zip`). Accounts come from `bundleAccounts(accounts, cleartext, now)` (the `cleartext` flag toggles the `password` field).
- **Handlers:** `handleExportBundle` (GET, sanitized, `?domain=`) and `handleExportCleartextBundle` (POST, gated, body domain) — the latter reuses the exact gate sequence from `handleExportCleartextCSV/HTML`.
- **Frontend (optional, follow the existing pattern):** add bundle download to `Reports.tsx` (org) — a plain `<a href="/api/export/bundle.zip" download>` for sanitized; a lead-only acknowledged control (reuse `api.exportCleartext`-style blob POST) for `cleartext.zip`. Per-domain bundle links in `Domains.tsx DomainDetail`. (SPA wiring can be a later increment if we want to ship the API first.)

## Testing
- Unzip the sanitized org bundle: `report.json` parses; `scope=="org"`, `cleartext==false`; `metrics`/`accounts`/`images` present; every path in `images` exists as a zip entry and is a well-formed `<svg`; empty-dataset charts absent from both.
- Per-domain bundle: `scope=="domain:X"`, metrics/accounts scoped to X, `reuse_graph` absent, unknown domain → 404.
- Sanitized redaction canary (secret-bearing fixture): no cleartext/NT hash/wordlist anywhere in the zip bytes.
- Cleartext bundle: cleartext password present in `accounts`, absent from every `images/*.svg`; no NT hash anywhere; gating matrix (analyst→403+denied audit, no-ack→400, no-CSRF→403, happy→200 + `export_cleartext ok` audit with no password); `Content-Disposition` has `CLEARTEXT`.
- `report.ChartSVGs` parity: the SVG the bundle emits for a chart equals what the HTML export embeds (shared helper — assert one call site).

## Constraints (carry-over)
- CGO-free, stdlib-first, no new deps. NEVER `npm install` (frontend build = `cd web && npm run build`). Stage explicit paths. Commit trailer `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
