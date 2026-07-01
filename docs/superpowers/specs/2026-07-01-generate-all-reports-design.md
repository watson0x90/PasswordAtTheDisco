# Generate-all-reports ZIP — Design

**Status:** Approved (2026-07-01)

## Goal
One click in the Reports tab produces a single ZIP containing every export for the active audit, so an
operator doesn't download ten files individually. Two variants: an **open redacted** bundle and a
**lead-gated cleartext** bundle (adds cracked passwords, never NT hashes).

## Context (existing generators — all reused, no new report logic)
- `report.CSV(w, accounts)` — accounts summary CSV (redacted). `report.CSVCleartext(w, accounts)` — +password column.
- `report.HTML(w, name, generated, accounts)` — full self-contained HTML (self-redacts). `report.HTMLCleartext(...)` — +cleartext + banner.
- `report.AccountsHTML(w, name, subtitle, generated, accounts)` — focused HTML lists. `report.ReuseGroupsCSV(w, rep)` / focused reuse HTML.
- `report.SanitizedJSON(w, accounts, summary, now, version)` — identity-stripped scoring JSON.
- `report.BundleZip(w, name, scope, cleartext, m, accounts, now, version)` — model bundle (report.json + images/*.svg).
- Focused filters (from the existing handlers): cracked = `a.Cracked`; hibp = `a.HIBPBreached` (sorted by breach count desc); weak = `a.IsWeak()`; reuse = `model.BuildReport(accts)` groups.
- Gate primitives: `requireAuth`/`requireCSRF`/`requireUnlocked` middleware; handler `sess.Role==auth.RoleLead`, `{acknowledge}` body, fail-closed `auditOrFail` (`Action:"export_cleartext"`, never a password); `activeAudit`, `Store.Accounts(id,true)`, `download`, `safeFilename`, `Build.Version`.

## Endpoints
| Method | Path | Variant | Gating |
|---|---|---|---|
| GET | `/api/export/all.zip` | redacted | `requireAuth`+`requireUnlocked` (any operator) |
| POST | `/api/export/all-cleartext.zip` | redacted + cleartext | `requireAuth`+`requireCSRF`+`requireUnlocked` mw; handler: lead-role else fail-closed-audited 403; `{"acknowledge":true}` else 400; fail-closed `auditOrFail` `Action:"export_cleartext"` `Result:"ok"` (Target = audit name, never a password) before writing bytes |

Filenames via `download()`+`safeFilename`: `<Audit>_reports.zip` and `<Audit>_reports_CLEARTEXT.zip`.

## ZIP contents

### `all.zip` (redacted)
```
accounts.csv                     report.CSV(accts)
cracked.csv / cracked.html       filter Cracked        -> report.CSV / report.AccountsHTML
hibp.csv / hibp.html             filter HIBPBreached   -> (sorted) report.CSV / report.AccountsHTML
weak.csv / weak.html             filter IsWeak()       -> report.CSV / report.AccountsHTML
reuse.csv / reuse.html           model.BuildReport     -> report.ReuseGroupsCSV / reuse HTML
full_report.html                 report.HTML(accts)    (self-redacts)
sanitized.json                   report.SanitizedJSON(accts, summary, now, ver)
model_bundle/report.json         model bundle (sanitized), via the shared helper below
model_bundle/images/*.svg
```
No cleartext, no NT hashes anywhere.

### `all-cleartext.zip`
Everything in `all.zip` **plus** a segregated `cleartext/` folder (so the secret-bearing files are obvious):
```
cleartext/accounts_CLEARTEXT.csv           report.CSVCleartext(accts)
cleartext/full_report_CLEARTEXT.html       report.HTMLCleartext(accts)
cleartext/model_bundle/report.json + images/   model bundle (cleartext), shared helper
```
Cracked cleartext passwords only; **NT hashes never appear** anywhere in either ZIP.

## Implementation
- **Shared bundle helper (small refactor):** extract the "write report.json + images/*.svg into a
  `*zip.Writer` under a path prefix" logic currently inside `report.BundleZip` into
  `writeBundleInto(zw *zip.Writer, prefix string, name, scope string, cleartext bool, m metrics.Metrics,
  accounts []model.Account, now time.Time, version string) error`. `BundleZip` becomes a thin wrapper
  (`prefix=""` + its own `zip.NewWriter`); the all-reports assembler calls it with
  `prefix="model_bundle/"` (or `cleartext/model_bundle/`). One source, no drift.
- **Assembler:** `report.AllReportsZip(w io.Writer, name string, cleartext bool, accounts []model.Account,
  summary model.Summary, now time.Time, version string) error` opens one `zip.NewWriter`, and for each
  entry creates the file and calls the matching existing generator writing into that entry. When
  `cleartext` is true it additionally writes the `cleartext/` entries. Reuses the focused-report filter
  predicates from the existing handlers (extract them to small shared funcs if that reads cleaner).
- **Handlers:** `handleExportAllZip` (GET, redacted, `cleartext=false`) and `handleExportAllCleartextZip`
  (POST, gated, `cleartext=true`) — the latter mirrors `handleExportCleartextCSV`'s gate sequence exactly.
  The redacted handler may load redacted accounts (`Store.Accounts(id,false)`) except the model bundle
  needs full accounts for the reuse graph — so load full accounts (`Store.Accounts(id,true)`) and let the
  redacted generators self-redact (as `report.HTML`/`BundleZip` already do), exactly like `handleExportHTML`.

## Security
- `all.zip`: no cleartext/NThash — the redacted generators (`report.HTML` self-redacts, `report.CSV`
  redacts, `SanitizedJSON` is identity-stripped, the sanitized bundle is redaction-safe) guarantee it even
  though full accounts are loaded (needed for the reuse graph). Extend the redaction canary to the
  assembled `all.zip` bytes (decompressed-entry scan) on a secret-bearing fixture.
- `all-cleartext.zip`: lead + CSRF + acknowledge + fail-closed audit; cleartext only in the `cleartext/`
  folder; NT hashes never. The audit event never contains a password.

## Frontend (`web/src/components/Reports.tsx`)
- A prominent **"Generate all reports (.zip)"** button — plain `<a className="btn btn-primary"
  href="/api/export/all.zip" download>`.
- A **"Generate all + cleartext (.zip)"** button inside the *existing* lead-only acknowledged cleartext
  section, reusing the same `ctAcked` checkbox + `ctBusy`/`ctErr` state and the `downloadBlob` POST helper
  (add `api.exportAllCleartext(csrf)` posting `{acknowledge:true}` to `/api/export/all-cleartext.zip`).

## Testing
- Redacted: unzip `all.zip`; assert every expected entry is present and well-formed (CSV header,
  `<svg`/`<html` where applicable, `report.json` parses); decompressed-entry scan finds **no** seeded
  cleartext (`Welcome1`) or NT hash anywhere.
- Cleartext: gate matrix (analyst→403 + `export_cleartext` denied audit; no-ack→400; no-CSRF→403;
  happy→200); the `cleartext/` entries contain `Welcome1`, the non-`cleartext/` entries do **not**, no NT
  hash anywhere, `Content-Disposition` has `CLEARTEXT`, and the ok audit event has no password.
- `BundleZip` unchanged behavior after the `writeBundleInto` refactor (existing bundle tests stay green).

## Constraints (carry-over)
- CGO-free stdlib only (`archive/zip`), no new deps. NEVER `npm install` (build = `cd web && npm run build`).
- Stage explicit paths. Commit trailer EXACTLY: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
