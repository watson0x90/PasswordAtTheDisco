# Unredacted (Cleartext) Export Tier — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox syntax.

**Goal:** Add a lead-only, deliberately-gated export tier that includes cleartext cracked passwords (HTML + CSV), complementing the always-redacted default exports and the sanitized JSON.

**Architecture:** New POST endpoints `/api/export/cleartext.csv` and `/api/export/cleartext.html` render the SAME metrics bundle + account tables as the redacted exports, but with an added cleartext `password` column for cracked accounts. NT hashes and wordlist fragments are NEVER included. Access is gated by lead role + CSRF + an explicit acknowledgement flag, and every generation is fail-closed audit-logged (never logging any password). Sanitized JSON has NO cleartext variant.

**Tech Stack:** Go stdlib (net/http, encoding/csv, html/template), React/TS SPA.

## Global Constraints (binding on every task)
- **Cleartext scope:** ONLY `model.Account.Password` (the cracked cleartext), and only for `Cracked` accounts. NEVER emit `NTHash`. NEVER emit `BannedWords`/`KeyboardPatterns` (those are cleartext fragments too). The cleartext projection = redacted account with Password kept, NThash+wordlist stripped.
- **Formats:** HTML + CSV only. Sanitized JSON stays sanitized — do NOT add a cleartext JSON path.
- **Gating (ALL required, checked server-side every request):** (1) `sess.Role == auth.RoleLead` else 403; (2) valid CSRF (`X-CSRF-Token` == session CSRF, constant-time) else 403; (3) request body `{"acknowledge": true}` else 400; (4) fail-closed audit via `auditOrFail` — if the audit write fails, REFUSE (500) and do not emit the file. Audit event: `Action:"export_cleartext"`, `Target: <audit name> — <format>[ (domain=X)]`, `Result:"ok"|"denied"`. NEVER put a password (or any account secret) in the audit event.
- **Method:** POST (not GET) — avoids browser history/proxy/prefetch caching of a secret-bearing URL and carries the acknowledgement + CSRF cleanly.
- **Watermark:** CSV → `_CLEARTEXT` filename suffix only (no comment line — keeps it strictly parseable); the `password` column is self-evident. HTML → a prominent visible "⚠ CONTAINS CLEARTEXT PASSWORDS" banner at the top, ALWAYS, plus `_CLEARTEXT` filename suffix.
- **Per-domain:** both endpoints accept an optional `domain` (JSON body field). Present → scope to that domain's accounts, 404 `{"error":"domain not found"}` if none; filename gets the sanitized domain suffix (in addition to `_CLEARTEXT`). Absent → org-wide.
- Redacted defaults are UNCHANGED. `report.HTML` (redacted) must still self-redact and never emit cleartext. The existing `TestExportEndpoints` / `TestHTMLGraphsAndScatter` / `TestExportHTMLIncludesReuseGraph` leak guards must stay green.
- Stage explicit paths on commit. Commit trailer EXACTLY: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. NEVER `npm install`/`npm ci` — frontend build is only `cd web && npm run build`.

---

## Task 1: Report layer — cleartext CSV + HTML variants + model projection

**Files:**
- Modify: `internal/model/model.go` — add `func (a Account) RedactedKeepPassword() Account` (clears `NTHash`, `BannedWords`, `KeyboardPatterns`; KEEPS `Password`).
- Modify: `internal/report/report.go` — add `CSVCleartext(w, accounts)` and `HTMLCleartext(w, name, generated, accounts)`; refactor the existing `CSV`/`HTML` to share a private renderer that takes a `cleartext bool`.
- Modify: `internal/report/report_test.go` + `internal/model/*_test.go` — tests.

**Interfaces:**
- Produces: `report.CSVCleartext(io.Writer, []model.Account) error`, `report.HTMLCleartext(io.Writer, string, time.Time, []model.Account) error`, `model.Account.RedactedKeepPassword() model.Account`.

**Design:**
- CSV: add a `password` column immediately after `username`. Redacted `CSV` omits it; `CSVCleartext` includes `csvSafe(a.Password)` for cracked accounts, `""` otherwise. Implement via a shared `csvReport(w, accounts, cleartext bool)`; `CSV` → false, `CSVCleartext` → true.
- HTML: implement via a shared private `htmlReport(w, name, generated, accounts, cleartext bool)`. `HTML` → false (projects each account via `.Redacted()`, as today, `d.Cleartext=false`). `HTMLCleartext` → true (projects via `.RedactedKeepPassword()`, `d.Cleartext=true`). Add to `htmlData` a `Cleartext bool`. Template gains: (a) `{{if .Cleartext}}<div class="cleartext-banner">⚠ CONTAINS CLEARTEXT PASSWORDS — handle per your data policy</div>{{end}}` near the top; (b) a `Password` column in the Accounts table header and rows, guarded by `{{if $.Cleartext}}`, rendering `{{if .Cracked}}{{.Password}}{{else}}—{{end}}`. The bundle (charts/matrix/graphs) is computed identically and stays redaction-safe.
- The redacted path MUST remain provably redacted: `HTML`/`CSV` never render Password regardless of input.

**Tests (required):**
- `model`: `RedactedKeepPassword` keeps `Password`, clears `NTHash`+`BannedWords`+`KeyboardPatterns`.
- `report`: `CSVCleartext` output for a cracked account WITH `Password="Hunter2"` + `NTHash="AAAA..."` contains `Hunter2` in a `password` column, does NOT contain the NT hash; an uncracked account's password cell is empty. Redacted `CSV` for the same accounts contains NEITHER `Hunter2` NOR the hash, and has NO `password` column.
- `report`: `HTMLCleartext` output contains `Hunter2` (cracked) + the "CONTAINS CLEARTEXT" banner, does NOT contain the NT hash or a wordlist fragment (feed `BannedWords`/`KeyboardPatterns`), and has no `<script>`. Redacted `HTML` for the same full accounts contains NEITHER the password NOR the hash (extend the existing self-redaction guard).

**Gate:** `gofmt -l`, `go vet ./...`, `go test ./internal/model/... ./internal/report/...` green. Commit.

---

## Task 2: HTTP endpoints + routing + audit gating

**Files:**
- Modify: `internal/httpapi/server.go` — routes for `POST /api/export/cleartext.csv` and `POST /api/export/cleartext.html`; handlers `handleExportCleartextCSV`, `handleExportCleartextHTML`.
- Modify: `internal/httpapi/server_test.go` — tests.

**Interfaces:**
- Consumes: `report.CSVCleartext`, `report.HTMLCleartext`, `auth.RoleLead`, `s.auditOrFail`, `s.activeAudit`, `s.Store.Accounts(id,true)`, `safeFilename`, `download`, `filterAccounts`.

**Design (both handlers, in order):**
1. Resolve session. If `sess.Role != auth.RoleLead` → fail-closed audit `Result:"denied"` then 403 `{"error":"requires lead role"}` (mirror `handleReportTerms`).
2. CSRF: register the route behind `s.requireCSRF(...)` (like `POST /api/audits`). (Middleware covers CSRF; the handler still does role + acknowledge.)
3. Decode JSON body `{"acknowledge": bool, "domain": string}`. If `!acknowledge` → 400 `{"error":"acknowledgement required"}`.
4. Resolve active audit (`activeAudit`); load FULL accounts `Store.Accounts(id,true)`.
5. If `domain != ""` → `filterAccounts` to it; 404 `{"error":"domain not found"}` if empty.
6. Fail-closed audit (`auditOrFail`) with `Action:"export_cleartext"`, `Target: meta.Name — <"cleartext CSV"|"cleartext HTML">[ (domain=X)]`, `Result:"ok"`. If it fails, the helper already wrote 500 — return.
7. `download(w, meta.Name, suffix, ext)` where `suffix` = `"CLEARTEXT"` (org) or `safeFilename(domain)+"_CLEARTEXT"` (per-domain); ext `csv`/`html`.
8. `report.CSVCleartext(w, accts)` / `report.HTMLCleartext(w, meta.Name[ + " — " + domain], now, accts)`.

**Tests (required):** analyst → 403 (+ denied audit event, no file); missing/false `acknowledge` → 400; missing CSRF → 403; happy path (lead + CSRF + acknowledge) → 200, body contains a seeded cleartext (`Welcome1`) in the CSV `password` column / HTML, and does NOT contain the NT hash; audit log has an `export_cleartext` `ok` event and NO password substring; `?domain` scoping via body → scoped + 404 for unknown; `Content-Disposition` contains `CLEARTEXT`.

**Gate:** `gofmt -l`, `go vet ./...`, `go test ./...` green. Commit.

---

## Task 3: Frontend — acknowledged, lead-only cleartext download UI

**Files:**
- Modify: `web/src/api.ts` — add `exportCleartext(format:"csv"|"html", domain:string|undefined, csrf:string)` that POSTs with the CSRF header + `{acknowledge:true, domain}`, reads the response as a blob, and triggers a browser download using the `Content-Disposition` filename (add a small blob-download helper).
- Modify: `web/src/components/Reports.tsx` — org-wide cleartext section: lead-only; a warning + an "I understand this contains cleartext passwords" checkbox; HTML + CSV buttons enabled only when checked.
- Modify: `web/src/components/Domains.tsx` — per-domain cleartext buttons in `DomainDetail`, same lead-only + checkbox acknowledgement gate, passing the domain.
- Modify: `web/src/styles.css` — `.cleartext-banner` (report) + minimal styling for the warning/checkbox controls.

**Design:** Non-lead operators do not see the cleartext controls (gate on the existing `isLead`/role signal used elsewhere, e.g. AccountDetail's `isLead`). The checkbox must be checked to enable the buttons; unchecking disables them. Surface API errors (403/400) inline. Reuse the existing `.btn`/warning styles.

**Tests:** none required (SPA has no test runner here); verify via `cd web && npm run build` (tsc + vite green) and the controller's live Playwright/curl pass.

**Gate:** `cd web && npm run build` succeeds (NO npm install). Commit.

---

## Verification (controller, after all tasks)
Rebuild embed binary + `dev_seed` :8444. As lead: acknowledge + download cleartext CSV/HTML (org + one domain) → assert a known cracked cleartext IS present, NT hashes are ABSENT (0 32-hex tokens), banner present in HTML, `_CLEARTEXT` filenames, audit log shows `export_cleartext ok` with no password. As analyst (or via curl without lead): assert 403. Without acknowledge → 400. Tear down :8444.
