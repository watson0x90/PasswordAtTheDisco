# Report Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** Fix the three findings from the live exportable-reports review — raw complexity labels in HTML+CSV exports, low-contrast weak-report category bars, and synthetic data that never exercises the CSV-injection guard.

**Architecture:** Add a Go-side `pwanalysis.ComplexityLabel` (mirror of the TS `complexityLabel`) co-located with the `Complexity()` enum it labels, and use it in both the CSV writer and the three HTML report templates in `internal/report/report.go`. Bump one CSS rule for the weak-report category bars. Add a formula-injection-probe account to the synthetic generator + a regression test proving `csvSafe` escapes it. No new deps, no security-model change (redaction is unaffected — labels are derived from the already-redacted `Complexity` field).

**Tech Stack:** Go stdlib (`html/template`, `encoding/csv`); Python (synthetic generator). No frontend change.

**Branch:** `feature/report-polish` (off `main`, post-`v2.10.0`).

**Gates:** `gofmt -l cmd internal`; `go build/vet/test ./...`; `govulncheck ./...`. Final: rebuild + `tools/dev_seed.sh` + Playwright re-verify the reports.

---

## Task 1: `pwanalysis.ComplexityLabel` + wire into CSV & HTML reports

**Files:** `internal/pwanalysis/pwanalysis.go` (after `Complexity()` ~line 200), `internal/pwanalysis/pwanalysis_test.go`, `internal/report/report.go` (CSV row :114; FuncMaps :282 + :385; templates :371, :446, :535), `internal/report/report_test.go`.

- [ ] **Step 1 — failing test** in `internal/pwanalysis/pwanalysis_test.go`:
```go
func TestComplexityLabel(t *testing.T) {
	cases := map[string]string{
		"mixedalphaspecialnum": "a–z A–Z 0–9 !@#",
		"loweralphanum":        "a–z 0–9",
		"none":                 "(none)",
		"weird":                "weird", // unknown passes through
	}
	for in, want := range cases {
		if got := ComplexityLabel(in); got != want {
			t.Errorf("ComplexityLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
```
(en-dash `–` is U+2013, not a hyphen — match exactly.)

- [ ] **Step 2 — run, expect FAIL:** `go test ./internal/pwanalysis/ -run TestComplexityLabel -v`.

- [ ] **Step 3 — implement** in `internal/pwanalysis/pwanalysis.go`, right after `Complexity()` (the 16 values must match `Complexity()`'s returns exactly):
```go
// complexityLabels maps the Complexity() enum to readable character-class tokens
// (the same notation the web UI and Policies page use), so reports read
// "a–z A–Z 0–9 !@#" instead of "mixedalphaspecialnum".
var complexityLabels = map[string]string{
	"loweralpha":           "a–z",
	"upperalpha":           "A–Z",
	"numeric":              "0–9",
	"special":              "!@#",
	"loweralphanum":        "a–z 0–9",
	"upperalphanum":        "A–Z 0–9",
	"mixedalpha":           "a–z A–Z",
	"loweralphaspecial":    "a–z !@#",
	"upperalphaspecial":    "A–Z !@#",
	"specialnum":           "0–9 !@#",
	"mixedalphanum":        "a–z A–Z 0–9",
	"loweralphaspecialnum": "a–z 0–9 !@#",
	"mixedalphaspecial":    "a–z A–Z !@#",
	"upperalphaspecialnum": "A–Z 0–9 !@#",
	"mixedalphaspecialnum": "a–z A–Z 0–9 !@#",
	"none":                 "(none)",
}

// ComplexityLabel returns a readable label for a Complexity() key (passthrough for
// unknown keys).
func ComplexityLabel(key string) string {
	if v, ok := complexityLabels[key]; ok {
		return v
	}
	return key
}
```

- [ ] **Step 4 — run, expect PASS:** `go test ./internal/pwanalysis/ -run TestComplexityLabel -v`.

- [ ] **Step 5 — wire into the CSV writer.** In `internal/report/report.go` line ~114, change `csvSafe(a.Complexity)` to `csvSafe(pwanalysis.ComplexityLabel(a.Complexity))`. Add the import `"github.com/watson0x90/PasswordAtTheDisco/internal/pwanalysis"` to report.go if absent (no import cycle: pwanalysis is low-level and does not import report).

- [ ] **Step 6 — wire into the 3 HTML templates.** Add a template func `"clabel": pwanalysis.ComplexityLabel` to BOTH FuncMaps — the inline one at line ~282 (`htmlTemplate`, used by the full report) and `tmplFuncs` at line ~385 (used by focused + weak templates). Then change the complexity cell in all three templates from `{{.Complexity}}` to `{{clabel .Complexity}}`:
  - line ~371 (full report): `<td class="muted">{{if .Cracked}}{{clabel .Complexity}}{{else}}—{{end}}</td>`
  - line ~446 (focused accounts): same change.
  - line ~535 (weak report): same change.

- [ ] **Step 7 — fix any test expecting the raw key.** Grep `internal/report/report_test.go` for `mixedalpha`/`complexity`; if a test asserts the raw key in CSV/HTML output, update it to the readable label. The redaction tests (no-cleartext) are unaffected — confirm they still pass.

- [ ] **Step 8 — verify + commit.** `gofmt -w internal/...`; `go build ./... && go vet ./... && go test ./...`. Commit:
```
git add internal/pwanalysis/pwanalysis.go internal/pwanalysis/pwanalysis_test.go internal/report/report.go internal/report/report_test.go
git commit -m "feat(report): readable complexity labels in CSV + HTML exports (a–z/A–Z/0–9/!@#)"
```

---

## Task 2: Weak-report category-bar contrast

**Files:** `internal/report/report.go` (the weak-report category-bar CSS/markup — near `weakTemplate` ~517 and its CSS block ~510-515; the category bars render the Forbidden/Common/Dictionary/Keyboard counts).

- [ ] **Step 1 — locate the bar.** In `internal/report/report.go`, find the weak-report "by violation category" bar markup + its fill CSS class (the bars whose fill is currently too dark to see against the row background). Read the surrounding CSS to get the exact class name and current color.

- [ ] **Step 2 — bump contrast.** Raise the bar-fill contrast so the fill is clearly visible against the panel background — use a visible accent (e.g. match the posture `.fill` gradient `linear-gradient(90deg,#0e7490,#22d3ee)` at line 307, or a solid `#22d3ee`/severity color), and ensure the empty track is a darker base so the fill reads. Keep it consistent with the report's existing palette (no new colors invented; reuse the cyan/severity hexes already in the file).

- [ ] **Step 3 — verify + commit.** `go build ./... && go test ./internal/report/`. (Visual confirmation happens in Task 4's Playwright pass.) Commit:
```
gofmt -w internal/report/report.go
git add internal/report/report.go
git commit -m "fix(report): readable contrast for weak-report category bars"
```

---

## Task 3: Injection-probe synthetic account + csvSafe regression test

**Files:** `tools/gen_synthetic.py` (add one account whose username starts with a formula char), `internal/report/report_test.go` (regression test for the leading-quote escape).

- [ ] **Step 1 — failing regression test** in `internal/report/report_test.go`. Build an account whose username starts with `=` and assert the CSV output escapes it with a leading apostrophe (csvSafe / CWE-1236):
```go
func TestCSVEscapesFormulaInjection(t *testing.T) {
	accts := []model.Account{{Username: "=cmd|calc@CORP.LOCAL", Domain: "CORP.LOCAL"}}
	var buf bytes.Buffer
	if err := CSV(&buf, accts); err != nil {
		t.Fatalf("CSV: %v", err)
	}
	if !strings.Contains(buf.String(), `'=cmd`) {
		t.Errorf("formula-injection username not neutralized (expected leading apostrophe): %s", buf.String())
	}
}
```
Adjust `CSV(&buf, accts)` to the real signature (check how other report_test.go tests call it — it may be `report.CSV(w, accounts)` or take a `*model.Report`; mirror an existing test exactly). Add imports `bytes`, `strings`, `model` if missing.

- [ ] **Step 2 — run, expect PASS already** (csvSafe exists). This test LOCKS IN the behavior; if it unexpectedly fails, csvSafe regressed — investigate. Run: `go test ./internal/report/ -run TestCSVEscapesFormulaInjection -v`.

- [ ] **Step 3 — add an injection-probe account to the generator.** In `tools/gen_synthetic.py`, add ONE account to a domain whose username begins with a formula character (e.g. `=cmd|'/c calc'!A0@CORP.LOCAL` or simply `=injection.test@CORP.LOCAL`) so every live export exercises the csvSafe path. Keep it a valid dump line (no `:` in the username — the secretsdump parser splits on `:`). Give it a real NT hash like the others (or leave uncracked). Update the account-count comment/printout if the script asserts a fixed total.

- [ ] **Step 4 — regenerate + verify.** `python tools/gen_synthetic.py` (confirm it still writes the 3 dumps + cracks without error and the new account is present). `go test ./internal/report/`.

- [ ] **Step 5 — commit.**
```
git add tools/gen_synthetic.py internal/report/report_test.go
git commit -m "test(report): synthetic formula-injection probe + csvSafe regression test"
```

---

## Task 4: Gate, rebuild, Playwright re-verify, docs, finish

- [ ] **Step 1 — full gate:** `gofmt -l cmd internal`; `go build ./... && go vet ./... && go test ./...`; `(cd web && npx tsc --noEmit && npx vitest run && npm run build)`; `govulncheck ./...`.
- [ ] **Step 2 — rebuild:** `bash .claude/skills/build-and-run/scripts/build.sh`.
- [ ] **Step 3 — seed + re-verify the reports:** `bash tools/dev_seed.sh`; download the exports (login → open audit → GET each `/api/export/*`); confirm via grep/Playwright: (a) HTML + CSV complexity columns read `a–z A–Z 0–9 !@#` (no `mixedalphaspecialnum`); (b) the weak-report category bars are clearly visible; (c) the injection-probe username appears in the CSV with a leading `'`; (d) re-run the **no-cleartext leak grep** (passwords/hashes/forbidden-words) — still 0 hits. Then `bash tools/dev_seed.sh --stop` + clean artifacts.
- [ ] **Step 4 — README bullet** noting readable report labels + the injection-probe hardening. Commit.
- [ ] **Step 5 — final whole-branch review + finishing-a-development-branch.**

---

## Self-review
- **Coverage:** #1 labels → Task 1 (CSV + 3 HTML templates, user chose HTML+CSV both); #2 bars → Task 2; #3 injection probe → Task 3. All findings mapped.
- **Types:** `pwanalysis.ComplexityLabel(string) string` used by report.go CSV + the `clabel` template func in both FuncMaps; 16 keys mirror `Complexity()` exactly.
- **Security unchanged:** labels derive from the already-redacted `Complexity` field; the no-cleartext leak grep is re-run in Task 4 as the gate.
- **Confirm-by-reading:** the `CSV()` signature in report_test.go (Task 3); the exact weak-bar CSS class name (Task 2); whether report.go already imports pwanalysis (Task 1).
