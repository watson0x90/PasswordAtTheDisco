# Generate-all-reports ZIP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** One click in the Reports tab downloads a single ZIP of every export for the active audit — an open redacted bundle and a lead-gated cleartext bundle.

**Architecture:** A new `report.AllReportsZip` orchestrates the EXISTING generators into one `archive/zip`; a small refactor extracts `writeBundleInto` from `BundleZip` so the model bundle nests as folder contents. Two handlers (GET redacted, POST gated cleartext) mirror the existing export patterns; two Reports.tsx buttons reuse the existing download helpers.

**Tech Stack:** Go stdlib (`archive/zip`), existing `internal/report` + `internal/metrics`, React/TS.

**Spec:** `docs/superpowers/specs/2026-07-01-generate-all-reports-design.md`.

## Global Constraints
- CGO-free, stdlib-first, **no new deps**. NEVER `npm install`/`npm ci` (frontend build = `cd web && npm run build`).
- Cracked cleartext passwords appear ONLY in the `cleartext/` folder of `all-cleartext.zip`. NT hashes NEVER appear in ANY entry of EITHER zip. The redacted `all.zip` has no cleartext anywhere.
- Cleartext endpoint gating (mirror `handleExportCleartextCSV` exactly): `requireAuth`→`requireCSRF`→`requireUnlocked` middleware; handler lead-role else fail-closed-audited 403; `{"acknowledge":true}` else 400; fail-closed `auditOrFail` `Action:"export_cleartext"` `Result:"ok"|"denied"`, Target = audit name only (NEVER a password).
- Stage explicit paths. Commit trailer EXACTLY: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

## File Structure
- `internal/report/bundle.go` (modify) — extract `writeBundleInto`; `BundleZip` becomes a wrapper.
- `internal/report/allreports.go` (new) — `AllReportsZip`.
- `internal/report/allreports_test.go` (new) — assembler tests.
- `internal/httpapi/server.go` (modify) — routes + `handleExportAllZip`, `handleExportAllCleartextZip`.
- `internal/httpapi/server_test.go` (modify) — handler tests.
- `web/src/api.ts`, `web/src/components/Reports.tsx` (modify) — buttons.

## Existing generators (all reused; exact signatures)
- `report.CSV(w, accounts)` · `report.CSVCleartext(w, accounts)`
- `report.HTML(w, name, generated, accounts)` (self-redacts) · `report.HTMLCleartext(w, name, generated, accounts)`
- `report.AccountsHTML(w, name, subtitle, generated, accounts)` (cracked/hibp focused HTML)
- `report.WeakPasswordsHTML(w, name, generated, accounts)` (weak focused HTML)
- `report.ReuseGroupsCSV(w, rep)` · `report.ReuseGroupsHTML(w, name, generated, rep)` where `rep = model.BuildReport(accounts)`
- `report.SanitizedJSON(w, accounts, summary, now, version)`
- `report.BundleZip(w, name, scope, cleartext, m, accounts, now, version)` where `m = metrics.Compute(accounts, now)`
- Filters (inline in the assembler — the httpapi `filterAccounts`/`byBreachDesc` are not in the report pkg): cracked=`a.Cracked`; hibp=`a.HIBPBreached` sorted by `HIBPBreachCount` desc; weak=`a.IsWeak()`.

---

### Task 1: Extract `writeBundleInto` from `BundleZip`

**Files:** Modify `internal/report/bundle.go`; Test `internal/report/bundle_test.go`.

**Interfaces:**
- Produces: `func writeBundleInto(zw *zip.Writer, prefix, name, scope string, cleartext bool, m metrics.Metrics, accounts []model.Account, now time.Time, version string) error` — writes `prefix+"report.json"` and `prefix+"images/<name>.svg"` into `zw` (does NOT create or Close the writer). `BundleZip` keeps its current signature/behavior as a thin wrapper.

Read `internal/report/bundle.go` `BundleZip` first. Move its body (the `charts := ChartSVGs(m)`, `images` manifest, `bundleReport` marshal, and the per-file `zw.Create`/write loop) into `writeBundleInto`, prefixing every entry path with `prefix` (the manifest values become `prefix+"images/<name>.svg"` — keep the manifest RELATIVE to the bundle root, i.e. still `"images/<name>.svg"` inside report.json, but the zip ENTRY path is `prefix+"images/..."`; when `prefix==""` these are identical, preserving current output).

- [ ] **Step 1: Failing test** (add to `bundle_test.go`)
```go
func TestWriteBundleIntoPrefix(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	accts := []model.Account{{Username: "alice", Domain: "A", Cracked: true, RiskLevel: "High", RiskScore: 7}}
	m := metrics.Compute(accts, now)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if err := writeBundleInto(zw, "model_bundle/", "Eng", "org", false, m, accts, now, "v"); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	var haveReport bool
	for _, f := range zr.File {
		if f.Name == "model_bundle/report.json" {
			haveReport = true
		}
		if !strings.HasPrefix(f.Name, "model_bundle/") {
			t.Errorf("entry %q not under prefix", f.Name)
		}
	}
	if !haveReport {
		t.Error("missing model_bundle/report.json")
	}
}
```

- [ ] **Step 2: Run, verify FAIL** — `go test ./internal/report/ -run TestWriteBundleIntoPrefix` → undefined `writeBundleInto`.
- [ ] **Step 3: Implement** the refactor (extract `writeBundleInto`, `BundleZip` wraps it: `zw := zip.NewWriter(w); if err := writeBundleInto(zw, "", name, scope, cleartext, m, accounts, now, version); err != nil { return err }; return zw.Close()`).
- [ ] **Step 4: Run** — `go test ./internal/report/...` → PASS (the new test AND the existing `TestBundleZip` — proving `BundleZip` output is unchanged for `prefix==""`).
- [ ] **Step 5: Commit** `internal/report/bundle.go internal/report/bundle_test.go` — `refactor(report): extract writeBundleInto so the model bundle can nest under a prefix`.

---

### Task 2: `AllReportsZip` assembler

**Files:** Create `internal/report/allreports.go`; Test `internal/report/allreports_test.go`.

**Interfaces:**
- Consumes: `writeBundleInto` (Task 1), and the existing generators listed above.
- Produces: `func AllReportsZip(w io.Writer, name string, cleartext bool, accounts []model.Account, summary model.Summary, now time.Time, version string) error`.

- [ ] **Step 1: Failing test** (`allreports_test.go`)
```go
package report

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

func unzipAll(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		d, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = d
	}
	return out
}

func TestAllReportsZip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	accts := []model.Account{
		{Username: "alice", Domain: "CORP", NTHash: "AAAA0000AAAA0000AAAA0000AAAA0000", Password: "Welcome1",
			Cracked: true, PasswordLength: 8, RiskLevel: "High", RiskScore: 7, HIBPBreached: true, HIBPBreachCount: 5},
		{Username: "bob", Domain: "SUB", NTHash: "AAAA0000AAAA0000AAAA0000AAAA0000", Password: "Welcome1",
			Cracked: true, PasswordLength: 8, RiskLevel: "High", RiskScore: 7},
	}
	sum := model.Summarize(accts, now)

	// --- redacted ---
	var buf bytes.Buffer
	if err := AllReportsZip(&buf, "Eng", false, accts, sum, now, "vt"); err != nil {
		t.Fatal(err)
	}
	files := unzipAll(t, buf.Bytes())
	for _, want := range []string{
		"accounts.csv", "cracked.csv", "cracked.html", "hibp.csv", "hibp.html",
		"weak.csv", "weak.html", "reuse.csv", "reuse.html", "full_report.html",
		"sanitized.json", "model_bundle/report.json",
	} {
		if _, ok := files[want]; !ok {
			t.Errorf("redacted zip missing %s", want)
		}
	}
	for name, content := range files {
		if bytes.Contains(content, []byte("Welcome1")) {
			t.Errorf("redacted entry %s LEAKED cleartext", name)
		}
		if bytes.Contains(content, []byte("AAAA0000")) {
			t.Errorf("redacted entry %s LEAKED NT hash", name)
		}
		if strings.HasPrefix(name, "cleartext/") {
			t.Errorf("redacted zip must have no cleartext/ folder, got %s", name)
		}
	}

	// --- cleartext ---
	var cbuf bytes.Buffer
	if err := AllReportsZip(&cbuf, "Eng", true, accts, sum, now, "vt"); err != nil {
		t.Fatal(err)
	}
	cf := unzipAll(t, cbuf.Bytes())
	// cleartext folder present with the password; NO NT hash anywhere.
	ctFound := false
	for name, content := range cf {
		hasPw := bytes.Contains(content, []byte("Welcome1"))
		if strings.HasPrefix(name, "cleartext/") {
			if hasPw {
				ctFound = true
			}
		} else if hasPw {
			t.Errorf("non-cleartext entry %s LEAKED cleartext", name)
		}
		if bytes.Contains(content, []byte("AAAA0000")) {
			t.Errorf("entry %s LEAKED NT hash", name)
		}
	}
	if !ctFound {
		t.Error("cleartext zip: no cleartext/ entry contains the password")
	}
	for _, want := range []string{
		"cleartext/accounts_CLEARTEXT.csv", "cleartext/full_report_CLEARTEXT.html",
		"cleartext/model_bundle/report.json",
	} {
		if _, ok := cf[want]; !ok {
			t.Errorf("cleartext zip missing %s", want)
		}
	}
}
```

- [ ] **Step 2: Run, verify FAIL** — `go test ./internal/report/ -run TestAllReportsZip` → undefined `AllReportsZip`.

- [ ] **Step 3: Implement** `internal/report/allreports.go`:
```go
package report

import (
	"archive/zip"
	"io"
	"sort"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/metrics"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// AllReportsZip assembles every export for the audit into one ZIP by delegating to the
// existing generators. cleartext=false is the redacted, open bundle; cleartext=true adds a
// segregated cleartext/ folder (cracked passwords only, never NT hashes) and MUST be caller-gated.
func AllReportsZip(w io.Writer, name string, cleartext bool, accounts []model.Account, summary model.Summary, now time.Time, version string) error {
	zw := zip.NewWriter(w)
	rep := model.BuildReport(accounts)
	m := metrics.Compute(accounts, now)

	filter := func(keep func(model.Account) bool) []model.Account {
		out := make([]model.Account, 0)
		for _, a := range accounts {
			if keep(a) {
				out = append(out, a)
			}
		}
		return out
	}
	cracked := filter(func(a model.Account) bool { return a.Cracked })
	hibp := filter(func(a model.Account) bool { return a.HIBPBreached })
	sort.SliceStable(hibp, func(i, j int) bool { return hibp[i].HIBPBreachCount > hibp[j].HIBPBreachCount })
	weak := filter(func(a model.Account) bool { return a.IsWeak() })

	// add creates a zip entry and runs gen(entryWriter); the first error aborts.
	var firstErr error
	add := func(path string, gen func(io.Writer) error) {
		if firstErr != nil {
			return
		}
		f, err := zw.Create(path)
		if err != nil {
			firstErr = err
			return
		}
		if err := gen(f); err != nil {
			firstErr = err
		}
	}

	add("accounts.csv", func(f io.Writer) error { return CSV(f, accounts) })
	add("cracked.csv", func(f io.Writer) error { return CSV(f, cracked) })
	add("cracked.html", func(f io.Writer) error {
		return AccountsHTML(f, name+" — Cracked accounts", "cracked accounts", now, cracked)
	})
	add("hibp.csv", func(f io.Writer) error { return CSV(f, hibp) })
	add("hibp.html", func(f io.Writer) error {
		return AccountsHTML(f, name+" — HIBP-exposed accounts", "accounts whose NT hash is in HIBP", now, hibp)
	})
	add("weak.csv", func(f io.Writer) error { return CSV(f, weak) })
	add("weak.html", func(f io.Writer) error { return WeakPasswordsHTML(f, name, now, weak) })
	add("reuse.csv", func(f io.Writer) error { return ReuseGroupsCSV(f, rep) })
	add("reuse.html", func(f io.Writer) error { return ReuseGroupsHTML(f, name+" — Password-reuse groups", now, rep) })
	add("full_report.html", func(f io.Writer) error { return HTML(f, name, now, accounts) })
	add("sanitized.json", func(f io.Writer) error { return SanitizedJSON(f, accounts, summary, now, version) })

	if firstErr == nil {
		firstErr = writeBundleInto(zw, "model_bundle/", name, "org", false, m, accounts, now, version)
	}

	if cleartext && firstErr == nil {
		add("cleartext/accounts_CLEARTEXT.csv", func(f io.Writer) error { return CSVCleartext(f, accounts) })
		add("cleartext/full_report_CLEARTEXT.html", func(f io.Writer) error { return HTMLCleartext(f, name, now, accounts) })
		if firstErr == nil {
			firstErr = writeBundleInto(zw, "cleartext/model_bundle/", name, "org", true, m, accounts, now, version)
		}
	}

	if firstErr != nil {
		_ = zw.Close()
		return firstErr
	}
	return zw.Close()
}
```

- [ ] **Step 4: Run** — `go test ./internal/report/...` → PASS (incl. `TestAllReportsZip`). Also `gofmt -l internal/report` empty, `go vet ./internal/report/...`.
- [ ] **Step 5: Commit** `internal/report/allreports.go internal/report/allreports_test.go` — `feat(report): AllReportsZip assembles every export into one zip (redacted + cleartext)`.

---

### Task 3: HTTP handlers + routes

**Files:** Modify `internal/httpapi/server.go` (routes near the other `/api/export/*`; two handlers); Test `internal/httpapi/server_test.go`.

**Interfaces:**
- Consumes: `report.AllReportsZip`; `s.activeAudit`, `s.Store.Accounts(id,true)`, `s.Store.Summary(id)`, `download`, `auditOrFail`, `auth.RoleLead`, `s.Build.Version`. Read `handleExportCleartextCSV` (gate) and `handleExportHTML`/`handleExportSanitized` (full accounts + summary + version) first and mirror them.

Routes:
```go
mux.Handle("GET /api/export/all.zip", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleExportAllZip))))
mux.Handle("POST /api/export/all-cleartext.zip", s.requireAuth(s.requireCSRF(s.requireUnlocked(http.HandlerFunc(s.handleExportAllCleartextZip)))))
```

`handleExportAllZip` (redacted, GET): resolve session; `activeAudit`; `accts, err := s.Store.Accounts(id, true)` (full — needed for the reuse graph; generators self-redact) → on err 409 `{"error":"no audit selected"}`; `sum, _ := s.Store.Summary(id)`; `ver := s.Build.Version; if ver == "" { ver = "dev" }`; `download(w, meta.Name, "reports", "zip")`; `_ = report.AllReportsZip(w, meta.Name, false, accts, sum, time.Now().UTC(), ver)`.

`handleExportAllCleartextZip` (POST, gated): EXACT gate order from `handleExportCleartextCSV` — lead-role else fail-closed `auditOrFail` denied + 403; decode `{"acknowledge": bool}` → `!acknowledge` → 400 `{"error":"acknowledgement required"}`; `activeAudit`; `Store.Accounts(id,true)`; `sum, _ := s.Store.Summary(id)`; `ver`; fail-closed `auditOrFail` `Action:"export_cleartext"` `Result:"ok"` Target `meta.Name + " — all reports (cleartext)"` (NEVER a password) — if false, return; `download(w, meta.Name, "reports_CLEARTEXT", "zip")`; `_ = report.AllReportsZip(w, meta.Name, true, accts, sum, time.Now().UTC(), ver)`.

- [ ] **Step 1: Failing tests** (`server_test.go`) reusing existing helpers (`newServerAudit`, `loginCSRF`, `openAudit`, `do`, `postJSON`, `ingestAndOpen`, `cleartextFixture`, the `parseZip` decompressing helper). Cover:
  - `TestExportAllZip`: GET `/api/export/all.zip` → 200, `Content-Disposition` has `reports` + `.zip`; unzip → `accounts.csv`, `full_report.html`, `sanitized.json`, `model_bundle/report.json` present; NO decompressed entry contains `Welcome1` or the NT-hash string; no `cleartext/` entry; no-auth → 401.
  - `TestExportAllCleartextZip`: analyst → 403 + `export_cleartext` `denied` audit, no cleartext; no-`acknowledge` → 400; no-CSRF → 403; lead+CSRF+`acknowledge` → 200 (`Content-Disposition` has `CLEARTEXT`); a `cleartext/` decompressed entry contains `Welcome1`, no NON-`cleartext/` entry does, no entry contains the NT hash; `export_cleartext ok` audit exists whose serialized form lacks `Welcome1`.
- [ ] **Step 2: Run, verify FAIL** (routes/handlers undefined → 404/405).
- [ ] **Step 3: Implement** routes + both handlers.
- [ ] **Step 4: Run** `gofmt -l internal/httpapi` empty, `go vet ./...`, `go test ./...` → all green.
- [ ] **Step 5: Commit** `internal/httpapi/server.go internal/httpapi/server_test.go` — `feat(export): all.zip (open) + all-cleartext.zip (gated) — one-click all reports`.

---

### Task 4: Frontend buttons

**Files:** Modify `web/src/api.ts`, `web/src/components/Reports.tsx`.

**Interfaces:** Consumes the existing `downloadBlob` helper + the `ctAcked`/`ctBusy`/`ctErr` state and `useAuth` `csrf` in `Reports.tsx` (read `exportCleartext`/`exportCleartextBundle` and the cleartext section in Reports.tsx first).

- [ ] **Step 1:** Add to `api.ts`: `exportAllCleartext(csrf: string): Promise<void>` that calls the existing private `downloadBlob("/export/all-cleartext.zip", {method:"POST", headers:{"X-CSRF-Token": csrf, "Content-Type":"application/json"}, body: JSON.stringify({acknowledge:true})})` — same shape as `exportCleartextBundle`, no duplication.
- [ ] **Step 2:** In `Reports.tsx`: a prominent redacted button near the top of the export panels — `<a className="btn btn-primary" href="/api/export/all.zip" download>Generate all reports (.zip)</a>` with a one-line sub ("Every report above in one ZIP — no passwords or hashes."). And inside the EXISTING lead-only acknowledged cleartext section, a third action button `Generate all + cleartext (.zip)` — `disabled={!ctAcked || ctBusy}`, `onClick` → a `downloadAllCleartext()` handler mirroring `downloadCleartextBundle` (`setCtErr("")`/`setCtBusy(true)`/try `api.exportAllCleartext(csrf)`/catch `ApiError`/finally `setCtBusy(false)`).
- [ ] **Step 3:** `cd web && npm run build` → tsc + vite green (NEVER npm install).
- [ ] **Step 4: Commit** `web/src/api.ts web/src/components/Reports.tsx` — `feat(web): 'Generate all reports' buttons (redacted + gated cleartext)`.

---

## Verification (controller, after all tasks)
Rebuild embed binary + `dev_seed` :8444. `GET /api/export/all.zip` → unzip, confirm all entries + 0 NThash tokens + no cleartext. `POST /api/export/all-cleartext.zip` (acknowledge) → confirm `cleartext/` folder carries a known cracked password, non-cleartext entries don't, 0 NThash; no-ack → 400; audit shows `export_cleartext ok` without the password. UI: both buttons render (cleartext one gated by the checkbox). Tear down :8444.
