# Model Export Bundle (JSON + SVG images zip) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Ship a downloadable `.zip` per audit scope (`report.json` + `images/*.svg`) that gives models (Gemini/Kiro) the full metrics, identified account rows, and referenceable chart images — in a sanitized (open) and a gated-cleartext variant.

**Architecture:** A new identified account projection (`BundleAccount`) + a shared chart-SVG extractor (`ChartSVGs`, also consumed by the existing HTML export so there is one source) + a zip writer (`BundleZip`), wired to two HTTP handlers that mirror the existing sanitized-GET / cleartext-POST export split.

**Tech Stack:** Go stdlib only (`archive/zip`, `encoding/json`, `html/template`), existing `internal/metrics` bundle, React/TS SPA.

**Spec:** `docs/superpowers/specs/2026-07-01-model-export-bundle-design.md`.

## Global Constraints
- CGO-free, stdlib-first, **no new dependencies**. NEVER `npm install`/`npm ci` (frontend build = `cd web && npm run build`; tests = `cd web && npx vitest run`).
- Cleartext appears ONLY in the cleartext bundle's `accounts[].password`, ONLY for `Cracked` accounts. NEVER emit `NTHash`, `BannedWords`, or `KeyboardPatterns` in ANY bundle (JSON or SVG). Images carry no account secrets (counts/labels only; node labels are usernames/domains, already non-secret).
- Cleartext bundle gating (ALL server-side, mirror `handleExportCleartextCSV`): `requireAuth`→`requireCSRF`→`requireUnlocked` middleware; handler: lead-role else fail-closed-audited 403; `{"acknowledge":true}` body else 400; fail-closed `auditOrFail` `Action:"export_cleartext"`, `Result:"ok"|"denied"`, Target = name/scope only (NEVER a password).
- Per-domain: filter accounts to the domain, 404 `{"error":"domain not found"}` if none; filenames via `download()`+`safeFilename` (`_<Domain>`, `_CLEARTEXT` suffixes).
- Stage explicit paths. Commit trailer EXACTLY: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

## File Structure
- `internal/report/bundle.go` (new) — `BundleAccount`, `bundleAccounts()`, `bundleReport`, `BundleZip()`.
- `internal/report/charts.go` (modify) — add `ChartSVG` + `ChartSVGs()`.
- `internal/report/report.go` (modify) — refactor `HTML()` chart/graph section to consume `ChartSVGs()`.
- `internal/report/bundle_test.go`, `charts_test.go` (new/modify) — unit tests.
- `internal/httpapi/server.go` (modify) — routes + `handleExportBundle`, `handleExportCleartextBundle`.
- `internal/httpapi/server_test.go` (modify) — handler tests.
- `web/src/api.ts`, `web/src/components/Reports.tsx`, `web/src/components/Domains.tsx` (modify, Task 5 — optional) — download UI.

---

### Task 1: `BundleAccount` identified projection

**Files:**
- Create: `internal/report/bundle.go`
- Test: `internal/report/bundle_test.go`

**Interfaces:**
- Produces: `type BundleAccount struct{…}`; `func bundleAccounts(accounts []model.Account, cleartext bool, now time.Time) []BundleAccount`.

Model the fields on `SanitizedAccount` (see `internal/report/sanitize.go`) but IDENTIFIED: real `username`/`domain`, real `da_domains`, `similar_peers` as real `{username,domain,score}`. ALLOWLIST — copy only named fields. `Password` is `json:"password,omitempty"` and set ONLY when `cleartext && a.Cracked`.

- [ ] **Step 1: Write the failing test**
```go
package report

import (
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

func TestBundleAccounts(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	accts := []model.Account{
		{Username: "alice", Domain: "CORP", Cracked: true, Password: "Hunter2", NTHash: "AAAA1111AAAA1111AAAA1111AAAA1111",
			BannedWords: []string{"zzbanzz"}, KeyboardPatterns: []string{"zzkbzz"},
			RiskLevel: "Critical", RiskScore: 8.1, DADomains: "CORP", PasswordLength: 7},
		{Username: "bob", Domain: "CORP", Cracked: false, RiskLevel: "Low"},
	}
	// sanitized: identities present, no password/hash/wordlist.
	san := bundleAccounts(accts, false, now)
	if len(san) != 2 || san[0].Username != "alice" || san[0].Domain != "CORP" {
		t.Fatalf("identities missing: %+v", san)
	}
	if san[0].Password != "" {
		t.Error("sanitized bundle must not carry a password")
	}
	if san[0].DADomains != "CORP" || !san[0].HasDAPath {
		t.Error("da_domains / has_da_path should be identified, not stripped")
	}
	// cleartext: password present for cracked, empty for uncracked; still no hash/wordlist.
	ct := bundleAccounts(accts, true, now)
	if ct[0].Password != "Hunter2" {
		t.Errorf("cleartext bundle: cracked account missing password, got %q", ct[0].Password)
	}
	if ct[1].Password != "" {
		t.Error("uncracked account must have empty password")
	}
	// The struct must have no NTHash/BannedWords/KeyboardPatterns fields at all —
	// assert via JSON that those never appear.
	raw := mustJSON(t, ct)
	for _, bad := range []string{"AAAA1111", "zzbanzz", "zzkbzz", "nt_hash"} {
		if strings.Contains(raw, bad) {
			t.Errorf("bundle account leaked %q", bad)
		}
	}
}
```
(Add a `mustJSON` test helper that `json.Marshal`s and `t.Fatal`s on error; add the `strings`/`encoding/json` imports.)

- [ ] **Step 2: Run it, verify it fails** — `go test ./internal/report/ -run TestBundleAccounts` → FAIL (undefined `bundleAccounts`).

- [ ] **Step 3: Implement `BundleAccount` + `bundleAccounts`** in `bundle.go`. Struct fields (JSON tags): `username`, `domain`, `password,omitempty`, `reuse_group,omitempty` (reuse the opaque `reuseGroupKey`+group-id logic from sanitize.go if useful, or a shared count), `cracked`, `password_length`, `complexity,omitempty`, `risk_level`, `risk_score`, `risk_vector`, `exposure_score`, `impact_score`, `impact_known`, `percentile`, `hibp_breached`, `hibp_breach_count`, `shared_with`, `escalated_by_shared_da,omitempty`, `escalated_by_mass_reuse,omitempty`, `has_da_path`, `da_domains,omitempty`, `controlled_object_count`, `controls_tier0,omitempty`, `enabled`, `coverage,omitempty`, `meets_policy`, `policy_violations,omitempty`, `is_common,omitempty`, `is_dictionary_word,omitempty`, `banned_word_count,omitempty`, `keyboard_pattern_count,omitempty`, `contains_unicode,omitempty`, `password_age_days`, `pwd_never_expires,omitempty`, `days_out_of_compliance,omitempty`, `has_spn,omitempty`, `dont_req_preauth,omitempty`, `similarity_score,omitempty`, `similar_peers,omitempty` (`[]BundlePeer{Username,Domain,Score}`), `score_breakdown,omitempty`. Set `Password` only when `cleartext && a.Cracked`. Reuse `ageDays()` from sanitize.go for `password_age_days`. Use `a.HasDAPathway()` for `has_da_path`.

- [ ] **Step 4: Run test** → PASS.

- [ ] **Step 5: Commit** — `git add internal/report/bundle.go internal/report/bundle_test.go && git commit`.

---

### Task 2: `ChartSVGs()` — one source of chart SVGs

**Files:**
- Modify: `internal/report/charts.go` (add `ChartSVG`, `ChartSVGs`)
- Modify: `internal/report/report.go` (`HTML()` consumes `ChartSVGs`)
- Test: `internal/report/charts_test.go`

**Interfaces:**
- Produces: `type ChartSVG struct { Name, Title, SVG string; Wide bool }`; `func ChartSVGs(m metrics.Metrics) []ChartSVG` — ordered, empty-dataset charts skipped, `Wide=true` for the two network graphs.

`ChartSVGs` calls the SAME `svgSliceAsBar`/`svgBarChart`/`svgScatter`/`svgAxisFactorBars`/`svgNetworkGraph` helpers `HTML()` currently calls inline (see `report.go` HTML() chart/graph section). Names are stable snake_case: `risk_distribution`, `hibp_exposure`, `expiration`, `length`, `score`, `sharing`, `controlled`, `similarity`, `complexity`, `da_by_domain`, `hibp_vs_risk`, `password_age_scatter`, `axis_factor_bars`, `reuse_graph`(Wide), `similarity_graph`(Wide). Titles = the human titles `HTML()` already uses. Skip when the helper returns `""`.

- [ ] **Step 1: Write the failing test** (`charts_test.go`)
```go
func TestChartSVGs(t *testing.T) {
	accts := []model.Account{
		{Username: "alice", Domain: "A", NTHash: "AAAA0000AAAA0000AAAA0000AAAA0000", Cracked: true, PasswordLength: 8, RiskLevel: "High", RiskScore: 7, HIBPBreached: true, HIBPBreachCount: 3},
		{Username: "bob", Domain: "B", NTHash: "AAAA0000AAAA0000AAAA0000AAAA0000", Cracked: true, PasswordLength: 8, RiskLevel: "High", RiskScore: 7},
	}
	m := metrics.Compute(accts, time.Unix(1_700_000_000, 0))
	svgs := ChartSVGs(m)
	byName := map[string]ChartSVG{}
	for _, c := range svgs {
		byName[c.Name] = c
		if !strings.Contains(c.SVG, "<svg") {
			t.Errorf("%s: not a standalone svg", c.Name)
		}
	}
	if _, ok := byName["risk_distribution"]; !ok {
		t.Error("expected risk_distribution chart")
	}
	if _, ok := byName["reuse_graph"]; !ok {
		t.Error("cross-domain reuse graph expected (alice/A + bob/B share a hash)")
	}
	if !byName["reuse_graph"].Wide {
		t.Error("reuse_graph should be Wide")
	}
	// Empty dataset (password age) must be skipped.
	if _, ok := byName["password_age_scatter"]; ok {
		t.Error("empty password_age_scatter must be skipped")
	}
}
```

- [ ] **Step 2: Run it, verify it fails** — `go test ./internal/report/ -run TestChartSVGs` → FAIL (undefined `ChartSVGs`).

- [ ] **Step 3: Implement `ChartSVGs`** in `charts.go` (ordered append with an `add(name,title,svg,wide)` closure that skips `svg==""`). Then **refactor `report.go HTML()`**: replace the inline `allCards`/graph construction with a loop over `ChartSVGs(m)` — non-`Wide` → `chartCard(c.Title, template.HTML(c.SVG))` into `d.Charts`; `Wide` → into `d.Graphs`. The rendered HTML output must be UNCHANGED (same titles, same SVGs, same two-section layout).

- [ ] **Step 4: Run tests** — `go test ./internal/report/...` → PASS (incl. the existing `TestHTMLGraphsAndScatter`/`TestHTMLCleartextAndRedacted` which pin the HTML export output — they must stay green, proving the refactor preserved output).

- [ ] **Step 5: Commit.**

---

### Task 3: `BundleZip()` writer

**Files:**
- Modify: `internal/report/bundle.go` (add `bundleReport`, `BundleZip`)
- Test: `internal/report/bundle_test.go`

**Interfaces:**
- Consumes: `bundleAccounts` (Task 1), `ChartSVGs` (Task 2).
- Produces: `func BundleZip(w io.Writer, name, scope string, cleartext bool, m metrics.Metrics, accounts []model.Account, now time.Time, version string) error`.

`bundleReport` = `{schema_version:1, generated_at, tool_version, scope, cleartext, metrics: m, accounts: bundleAccounts(accounts,cleartext,now), images: map[name]"images/<name>.svg"}`. `BundleZip` uses `zip.NewWriter`: write `report.json` (indented JSON of `bundleReport`), then for each `ChartSVGs(m)` entry write `images/<name>.svg`. The `images` manifest maps only the charts actually written.

- [ ] **Step 1: Write the failing test**
```go
func TestBundleZip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	accts := []model.Account{
		{Username: "alice", Domain: "A", NTHash: "AAAA0000AAAA0000AAAA0000AAAA0000", Cracked: true, Password: "Hunter2", PasswordLength: 7, RiskLevel: "High", RiskScore: 7},
		{Username: "bob", Domain: "B", NTHash: "AAAA0000AAAA0000AAAA0000AAAA0000", Cracked: true, Password: "Hunter2", PasswordLength: 7, RiskLevel: "High", RiskScore: 7},
	}
	m := metrics.Compute(accts, now)

	// --- sanitized ---
	var buf bytes.Buffer
	if err := BundleZip(&buf, "Eng", "org", false, m, accts, now, "vtest"); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		files[f.Name] = b
	}
	rj, ok := files["report.json"]
	if !ok {
		t.Fatal("missing report.json")
	}
	var rep bundleReport
	if err := json.Unmarshal(rj, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Cleartext || rep.Scope != "org" {
		t.Errorf("scope/cleartext wrong: %+v", rep.Scope)
	}
	// every image in the manifest exists as a zip entry.
	for name, path := range rep.Images {
		if _, ok := files[path]; !ok {
			t.Errorf("manifest references missing image %s -> %s", name, path)
		}
	}
	// sanitized zip bytes carry no cleartext/hash.
	all := buf.String()
	if strings.Contains(all, "Hunter2") || strings.Contains(all, "AAAA0000") {
		t.Error("sanitized bundle LEAKED a secret")
	}

	// --- cleartext ---
	var cbuf bytes.Buffer
	if err := BundleZip(&cbuf, "Eng", "org", true, m, accts, now, "vtest"); err != nil {
		t.Fatal(err)
	}
	czr, _ := zip.NewReader(bytes.NewReader(cbuf.Bytes()), int64(cbuf.Len()))
	var cj []byte
	imgHasSecret := false
	for _, f := range czr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		if f.Name == "report.json" {
			cj = b
		} else if strings.HasPrefix(f.Name, "images/") && strings.Contains(string(b), "Hunter2") {
			imgHasSecret = true
		}
	}
	if !strings.Contains(string(cj), "Hunter2") {
		t.Error("cleartext bundle report.json should contain the password")
	}
	if imgHasSecret {
		t.Error("cleartext MUST NOT appear in any image svg")
	}
	if strings.Contains(string(cj), "AAAA0000") {
		t.Error("NT hash must never appear")
	}
}
```
(Imports: `archive/zip`, `bytes`, `encoding/json`, `io`, `strings`, `time`, `metrics`, `model`.)

- [ ] **Step 2: Run it, verify it fails** → FAIL (undefined `BundleZip`/`bundleReport`).
- [ ] **Step 3: Implement `bundleReport` + `BundleZip`** as described.
- [ ] **Step 4: Run test** → PASS.
- [ ] **Step 5: Commit.**

---

### Task 4: HTTP handlers + routes

**Files:**
- Modify: `internal/httpapi/server.go` (routes near the other `/api/export/*`; `handleExportBundle`, `handleExportCleartextBundle`)
- Test: `internal/httpapi/server_test.go`

**Interfaces:**
- Consumes: `report.BundleZip`, `metrics.Compute`, `s.activeAudit`, `s.Store.Accounts(id,true)`, `filterAccounts`, `download`, `safeFilename`, `s.auditOrFail`, `auth.RoleLead`. Read `handleExportCleartextCSV` (gate sequence) and `handleExportHTML` (per-domain filter) first and mirror them.

Routes:
```go
mux.Handle("GET /api/export/bundle.zip", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleExportBundle))))
mux.Handle("POST /api/export/cleartext.zip", s.requireAuth(s.requireCSRF(s.requireUnlocked(http.HandlerFunc(s.handleExportCleartextBundle)))))
```

`handleExportBundle` (sanitized, GET): resolve session; `activeAudit`; `Store.Accounts(id,true)` (full — needed so `metrics.Compute` builds reuse groups; the bundle sanitizes its own output); read `?domain`; if set → `filterAccounts` to it, 404 if empty, `scope="domain:"+domain`, else `scope="org"`; `m := metrics.Compute(accts, time.Now())`; `download(w, meta.Name, suffix, "zip")` (suffix `safeFilename(domain)` or ``); tool version via `ver := s.Build.Version; if ver == "" { ver = "dev" }` (exactly as `handleExportSanitized` does); `report.BundleZip(w, meta.Name, scope, false, m, accts, now, ver)`.

`handleExportCleartextBundle` (POST, gated): EXACT gate order from `handleExportCleartextCSV` — lead-role else audit-denied 403; decode `{acknowledge, domain}`; `!acknowledge`→400; `activeAudit`; `Store.Accounts(id,true)`; domain filter/404; `auditOrFail` `Action:"export_cleartext"` `Result:"ok"` Target `meta.Name — cleartext bundle[ (domain=X)]`; `download(w, meta.Name, suffix+"_CLEARTEXT", "zip")` (or `"CLEARTEXT"` org-wide, matching the CSV/HTML suffix convention); `report.BundleZip(w, name, scope, true, m, accts, now, version)`.

- [ ] **Step 1: Write failing tests** (`server_test.go`), reusing helpers (`newServerAudit`, `loginCSRF`, `openAudit`, `do`, `postJSON`, `ingestAndOpen`, the `cleartextFixture`). Assert, unzipping the response body:
  - `TestExportBundleSanitized`: GET `/api/export/bundle.zip` → 200, `Content-Type`/`Content-Disposition` (`.zip`), `report.json` present + parses, `images/` entries exist, and the raw zip bytes contain NO `Welcome1`/NT-hash. `?domain=CORP` → scoped (`scope=="domain:CORP"`, only CORP usernames), unknown domain → 404. No-auth → 401.
  - `TestExportCleartextBundle`: analyst → 403 + `export_cleartext` `denied` audit, no cleartext; no-`acknowledge` → 400; no-CSRF → 403; lead+CSRF+`acknowledge` → 200, `report.json` `accounts` contains `Welcome1`, NO image contains `Welcome1`, NT hash absent everywhere, `Content-Disposition` has `CLEARTEXT`, `export_cleartext` `ok` audit exists whose serialized form lacks `Welcome1`.
- [ ] **Step 2: Run, verify they fail** (routes/handlers undefined → 404/method-not-allowed).
- [ ] **Step 3: Implement routes + both handlers.**
- [ ] **Step 4: Run** `gofmt -l internal/httpapi`, `go vet ./...`, `go test ./...` → all green.
- [ ] **Step 5: Commit.**

---

### Task 5 (OPTIONAL — may be a later increment): download UI

**Files:** `web/src/api.ts`, `web/src/components/Reports.tsx`, `web/src/components/Domains.tsx`.

- Sanitized bundle: a plain `<a className="btn" href="/api/export/bundle.zip" download>Model bundle (.zip)</a>` in `Reports.tsx` (org) and a `?domain=` variant in `Domains.tsx DomainDetail`.
- Cleartext bundle: reuse the existing lead-only acknowledged control pattern (`api.exportCleartext` blob-POST) — add `api.exportCleartextBundle(domain, csrf)` POSTing to `/api/export/cleartext.zip` with `{acknowledge:true, domain}` and a blob download; place a checkbox-gated button next to the existing cleartext CSV/HTML controls in both `Reports.tsx` and `Domains.tsx`.
- [ ] Implement; `cd web && npm run build` (NEVER npm install) green; commit.

---

## Notes for the executor
- Per-domain scope uses `metrics.Compute(filteredAccounts, now)` (same pattern as `handleExportHTML` per-domain) — this naturally yields an empty cross-domain reuse graph for a single domain, so `reuse_graph` is skipped there, matching the spec.
- Do NOT change the redacted HTML/CSV or sanitized.json exports' behavior. Task 2's `HTML()` refactor must keep the HTML export output byte-stable (existing tests guard it).
