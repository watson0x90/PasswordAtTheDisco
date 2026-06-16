# Password-Violation Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface wordlist violations richly — a category chart everywhere, an app-only lead-gated/audited drill-down into the actual recurring forbidden words & keyboard patterns — without ever writing a matched word (a cleartext fragment) to disk.

**Architecture:** Store the matched words on the encrypted `model.Account` (stripped by `Redacted()`, exactly like `Password`/`NTHash`). Category *counts* are redacted-safe and travel in `/api/report` + the weak-passwords HTML export. The actual words leave the process only via a new lead-only, audit-logged `GET /api/report/terms`. The web app's existing **Actionable → Weak Passwords** section gains a CSS-bar category chart plus a lead-gated reveal of the term drill-down. No new nav tab, no new export file, no new dependency.

**Tech Stack:** Go (stdlib + golang.org/x/crypto), `html/template` self-contained reports, React + Vite (TypeScript), vitest, Playwright. Gates: `go build ./... && go vet ./... && go test ./...`, `gofmt -l cmd internal` empty, `npm run build` (tsc), `npx vitest run`, `govulncheck ./...`.

**Spec:** `docs/superpowers/specs/2026-06-16-password-violation-reporting-design.md`

---

## File Structure

- `internal/model/model.go` — `Account.BannedWords`/`KeyboardPatterns` fields; `Redacted()` strips them.
- `internal/model/report.go` — `ViolationCounts` (+ `BuildReport` fill); `Term`/`Terms` + `AggregateTerms`.
- `internal/engine/engine.go` — `scoreCracked` stores the matched-word slices.
- `internal/report/report.go` — `WeakPasswordsHTML` (category chart + table).
- `internal/httpapi/server.go` — `handleReportTerms` + route; swap `handleExportWeakHTML` to `WeakPasswordsHTML`.
- `web/src/api.ts` — `ViolationCounts` on `Report`; `Term`/`Terms`; `api.reportTerms()`.
- `web/src/components/BarChart.tsx` — small CSS-bar chart (new).
- `web/src/components/Actionable.tsx` — category chart + lead-gated term reveal.
- `web/src/components/Activity.tsx` — add `reveal_violation_terms` to the action filter.
- `web/src/violations.test.ts` — vitest for the chart data transform (new).

---

## Task 1: Store matched words on the account, strip them on redaction

**Files:**
- Modify: `internal/model/model.go` (Account struct ~line 113-119; `Redacted()` ~line 128-134)
- Test: `internal/model/model_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/model/model_test.go`:

```go
func TestRedactedStripsMatchedWords(t *testing.T) {
	a := Account{
		Username: "alice", Domain: "CORP",
		Password: "Summer2021!", NTHash: "ABC",
		BannedWords: []string{"summer", "2021"}, KeyboardPatterns: []string{"qwerty"},
		BannedWordCount: 2, KeyboardPatternCount: 1, IsCommon: true,
	}
	r := a.Redacted()
	if r.BannedWords != nil || r.KeyboardPatterns != nil {
		t.Fatalf("Redacted leaked matched words: %+v / %+v", r.BannedWords, r.KeyboardPatterns)
	}
	if r.Password != "" || r.NTHash != "" {
		t.Fatalf("Redacted leaked credential")
	}
	// redacted-safe metadata is preserved
	if r.BannedWordCount != 2 || !r.IsCommon {
		t.Fatalf("Redacted dropped safe metadata: %+v", r)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/model/ -run TestRedactedStripsMatchedWords`
Expected: FAIL — `Account` has no field `BannedWords`/`KeyboardPatterns` (compile error).

- [ ] **Step 3: Add the fields and strip them**

In `internal/model/model.go`, in the `Account` struct, after the `KeyboardPatternCount` line, add:

```go
	// BannedWords / KeyboardPatterns are the ACTUAL matched substrings -- cleartext
	// fragments. Like Password/NTHash they are persisted only in the encrypted store
	// and stripped by Redacted(); they leave the process only via the lead-gated,
	// audited terms endpoint.
	BannedWords      []string `json:"banned_words,omitempty"`
	KeyboardPatterns []string `json:"keyboard_patterns,omitempty"`
```

In `Redacted()`, add the two clears:

```go
func (a Account) Redacted() Account {
	a.Password = ""
	a.NTHash = ""
	a.BannedWords = nil
	a.KeyboardPatterns = nil
	return a
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/model/ -run TestRedactedStripsMatchedWords`
Expected: PASS

- [ ] **Step 5: gofmt + commit**

```bash
gofmt -w internal/model/model.go internal/model/model_test.go
git add internal/model/model.go internal/model/model_test.go
git commit -m "feat(model): store matched wordlist terms on Account, strip on Redacted"
```

---

## Task 2: Engine stores the matched-word slices for cracked accounts

**Files:**
- Modify: `internal/engine/engine.go` (`scoreCracked` return, the block that sets `BannedWordCount`/`KeyboardPatternCount`)
- Test: `internal/engine/engine_test.go`

- [ ] **Step 1: Write the failing test**

First inspect how existing engine tests build an `Engine` + `Lists` (open `internal/engine/engine_test.go` and copy the setup helper they use). Then add a test that scores a password containing a forbidden word and asserts the slice is populated. Use a forbidden word that exists in the engine's configured lists, or construct the `Engine` with an inline `pwanalysis.Lists`:

```go
func TestScoreCrackedStoresMatchedWords(t *testing.T) {
	eng := &Engine{
		Lists: pwanalysis.Lists{
			ForbiddenWords:   pwanalysis.NewSet("summer"),
			KeyboardPatterns: pwanalysis.NewSet("qwerty"),
			CommonPasswords:  pwanalysis.NewSet(),
			DictionaryWords:  pwanalysis.NewSet(),
		},
	}
	a := eng.scoreCracked("CORP",
		secretsdump.ParsedAccount{Username: "alice", Hash: "ABC", Password: "Summerqwerty1", Cracked: true},
		0, nil, map[string]*pwanalysis.Analysis{}, map[string]float64{}, time.Now())
	if len(a.BannedWords) == 0 || a.BannedWords[0] != "summer" {
		t.Fatalf("BannedWords not stored: %+v", a.BannedWords)
	}
	if len(a.KeyboardPatterns) == 0 || a.KeyboardPatterns[0] != "qwerty" {
		t.Fatalf("KeyboardPatterns not stored: %+v", a.KeyboardPatterns)
	}
	if a.BannedWordCount != 1 || a.KeyboardPatternCount != 1 {
		t.Fatalf("counts wrong: %d / %d", a.BannedWordCount, a.KeyboardPatternCount)
	}
}
```

Note: if `scoreCracked`'s signature differs, match it exactly from the source. Add any missing imports (`time`, `secretsdump`, `pwanalysis`).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/engine/ -run TestScoreCrackedStoresMatchedWords`
Expected: FAIL — `a.BannedWords` empty (engine stores only the count today).

- [ ] **Step 3: Store the slices**

In `internal/engine/engine.go`, in the `scoreCracked` `return model.Account{...}` block, alongside the existing weakness lines add:

```go
		BannedWords:          an.BannedWords,
		KeyboardPatterns:     an.KeyboardPatterns,
```

(Keep the existing `BannedWordCount: len(an.BannedWords)` / `KeyboardPatternCount: len(an.KeyboardPatterns)`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/engine/ -run TestScoreCrackedStoresMatchedWords`
Expected: PASS

- [ ] **Step 5: gofmt + commit**

```bash
gofmt -w internal/engine/engine.go internal/engine/engine_test.go
git add internal/engine/engine.go internal/engine/engine_test.go
git commit -m "feat(engine): persist matched forbidden words + keyboard patterns"
```

---

## Task 3: `ViolationCounts` on the report

**Files:**
- Modify: `internal/model/report.go` (`Report` struct; `BuildReport`)
- Test: `internal/model/report_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/model/report_test.go`:

```go
func TestBuildReportViolationCounts(t *testing.T) {
	accts := []Account{
		{Username: "a", Domain: "C", Cracked: true, IsCommon: true, BannedWordCount: 1},   // common + forbidden
		{Username: "b", Domain: "C", Cracked: true, IsDictionaryWord: true},               // dictionary
		{Username: "c", Domain: "C", Cracked: true, KeyboardPatternCount: 2},              // keyboard
		{Username: "d", Domain: "C", Cracked: true},                                       // clean
	}
	vc := BuildReport(accts).ViolationCounts
	if vc.Common != 1 || vc.Dictionary != 1 || vc.Forbidden != 1 || vc.Keyboard != 1 {
		t.Fatalf("violation counts wrong: %+v", vc)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/model/ -run TestBuildReportViolationCounts`
Expected: FAIL — `Report` has no field `ViolationCounts` (compile error).

- [ ] **Step 3: Add the type, field, and fill**

In `internal/model/report.go`, add the type near `Report`:

```go
// ViolationCounts is the number of accounts tripping each wordlist category.
type ViolationCounts struct {
	Common     int `json:"common"`
	Dictionary int `json:"dictionary"`
	Forbidden  int `json:"forbidden"`
	Keyboard   int `json:"keyboard"`
}
```

Add the field to `Report` (after `WeakPasswords`):

```go
	ViolationCounts ViolationCounts `json:"violation_counts"`
```

In `BuildReport`, inside the per-account loop (next to the `IsWeak()` block), add:

```go
		if a.IsCommon {
			rep.ViolationCounts.Common++
		}
		if a.IsDictionaryWord {
			rep.ViolationCounts.Dictionary++
		}
		if a.BannedWordCount > 0 {
			rep.ViolationCounts.Forbidden++
		}
		if a.KeyboardPatternCount > 0 {
			rep.ViolationCounts.Keyboard++
		}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/model/ -run TestBuildReportViolationCounts`
Expected: PASS

- [ ] **Step 5: gofmt + commit**

```bash
gofmt -w internal/model/report.go internal/model/report_test.go
git add internal/model/report.go internal/model/report_test.go
git commit -m "feat(model): per-category violation counts on Report"
```

---

## Task 4: `AggregateTerms` — top recurring forbidden words & keyboard patterns

**Files:**
- Modify: `internal/model/report.go` (add `Term`, `Terms`, `AggregateTerms`)
- Test: `internal/model/report_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestAggregateTerms(t *testing.T) {
	accts := []Account{
		{BannedWords: []string{"summer", "2021"}, KeyboardPatterns: []string{"qwerty"}},
		{BannedWords: []string{"2021"}},
		{BannedWords: []string{"2021", "2021"}}, // duplicate within one account counts once
		{IsCommon: true, IsDictionaryWord: true}, // common/dictionary must NOT appear as terms
	}
	tr := AggregateTerms(accts, 25)
	if len(tr.Forbidden) != 2 {
		t.Fatalf("want 2 forbidden terms, got %+v", tr.Forbidden)
	}
	// sorted by count desc: 2021 (3) before summer (1)
	if tr.Forbidden[0].Term != "2021" || tr.Forbidden[0].Count != 3 {
		t.Fatalf("top forbidden wrong: %+v", tr.Forbidden[0])
	}
	if len(tr.Keyboard) != 1 || tr.Keyboard[0].Term != "qwerty" || tr.Keyboard[0].Count != 1 {
		t.Fatalf("keyboard wrong: %+v", tr.Keyboard)
	}
}

func TestAggregateTermsTopN(t *testing.T) {
	var accts []Account
	for _, w := range []string{"a", "b", "c", "d"} {
		accts = append(accts, Account{BannedWords: []string{w}})
	}
	if got := len(AggregateTerms(accts, 2).Forbidden); got != 2 {
		t.Fatalf("topN cap failed: got %d", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/model/ -run TestAggregateTerms`
Expected: FAIL — `AggregateTerms` undefined.

- [ ] **Step 3: Implement**

`sort` is already imported in `report.go`. Add:

```go
// Term is one recurring wordlist match and how many accounts' passwords contain it.
type Term struct {
	Term  string `json:"term"`
	Count int    `json:"count"`
}

// Terms is the recurring forbidden words + keyboard patterns. The matched strings
// are cleartext fragments -- this is only ever returned by the lead-gated, audited
// terms endpoint, never persisted or exported. Common/dictionary are deliberately
// excluded: their "term" is the whole password.
type Terms struct {
	Forbidden []Term `json:"forbidden"`
	Keyboard  []Term `json:"keyboard"`
}

// AggregateTerms counts each distinct matched term once per account and returns the
// top-N of each kind, sorted by count (desc), then term (asc) for stability.
func AggregateTerms(accts []Account, topN int) Terms {
	tally := func(get func(Account) []string) []Term {
		counts := map[string]int{}
		for _, a := range accts {
			seen := map[string]bool{}
			for _, t := range get(a) {
				if t == "" || seen[t] {
					continue
				}
				seen[t] = true
				counts[t]++
			}
		}
		out := make([]Term, 0, len(counts))
		for t, c := range counts {
			out = append(out, Term{Term: t, Count: c})
		}
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].Count != out[j].Count {
				return out[i].Count > out[j].Count
			}
			return out[i].Term < out[j].Term
		})
		if topN > 0 && len(out) > topN {
			out = out[:topN]
		}
		return out
	}
	return Terms{
		Forbidden: tally(func(a Account) []string { return a.BannedWords }),
		Keyboard:  tally(func(a Account) []string { return a.KeyboardPatterns }),
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/model/ -run TestAggregateTerms`
Expected: PASS (both functions)

- [ ] **Step 5: gofmt + commit**

```bash
gofmt -w internal/model/report.go internal/model/report_test.go
git add internal/model/report.go internal/model/report_test.go
git commit -m "feat(model): AggregateTerms for recurring forbidden/keyboard terms"
```

---

## Task 5: Lead-gated, audited `GET /api/report/terms`

**Files:**
- Modify: `internal/httpapi/server.go` (route registration near `GET /api/report`; new `handleReportTerms` near `handleReport`)
- Test: `internal/httpapi/server_test.go`

- [ ] **Step 1: Write the failing test**

Open `internal/httpapi/server_test.go` and find the existing helper that builds an authenticated request as a given role + reads the audit log (the reveal tests use one — reuse it). Then add a test asserting: (a) a non-lead gets 403 and a `denied` audit event; (b) a lead gets 200 with `Terms` and an `ok` audit event; (c) `/api/report` never contains a planted matched word. Model it on the existing `handleReveal` tests. Skeleton (adapt names to the file's helpers):

```go
func TestReportTermsLeadGatedAndAudited(t *testing.T) {
	srv, cleanup := newTestServerWithData(t, []model.Account{
		{Username: "alice", Domain: "C", Cracked: true, NTHash: "ABC",
			BannedWords: []string{"plantedword"}, BannedWordCount: 1},
	})
	defer cleanup()

	// non-lead -> 403 + denied audit
	res := srv.doAs(t, "analyst", "GET", "/api/report/terms", nil)
	if res.Code != http.StatusForbidden {
		t.Fatalf("non-lead got %d, want 403", res.Code)
	}
	if !srv.auditHas(t, "reveal_violation_terms", "denied") {
		t.Fatal("missing denied audit event")
	}

	// lead -> 200 + ok audit + the term present
	res = srv.doAs(t, "lead", "GET", "/api/report/terms", nil)
	if res.Code != http.StatusOK {
		t.Fatalf("lead got %d, want 200", res.Code)
	}
	if !strings.Contains(res.Body.String(), "plantedword") {
		t.Fatalf("terms missing planted word: %s", res.Body.String())
	}
	if !srv.auditHas(t, "reveal_violation_terms", "ok") {
		t.Fatal("missing ok audit event")
	}

	// /api/report must NOT contain the matched word
	rep := srv.doAs(t, "lead", "GET", "/api/report", nil)
	if strings.Contains(rep.Body.String(), "plantedword") {
		t.Fatal("/api/report leaked a matched word")
	}
}
```

If the test helpers have different names, adapt — the assertions (403+denied, 200+ok+word, report-has-no-word) are what matter.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/httpapi/ -run TestReportTermsLeadGatedAndAudited`
Expected: FAIL — route 404 (handler not registered).

- [ ] **Step 3: Add the handler + route**

In `internal/httpapi/server.go`, immediately after `handleReport`, add:

```go
// handleReportTerms returns the recurring forbidden words + keyboard patterns --
// the ACTUAL matched strings (cleartext fragments). Lead-only, and every call is
// audit-logged (the terms themselves never go in the log). This is the single place
// these words leave the process; they are never persisted unredacted or exported.
func (s *Server) handleReportTerms(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	id, ok := s.activeAudit(w, sess)
	if !ok {
		return
	}
	if sess.Role != auth.RoleLead {
		s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "reveal_violation_terms", Source: r.RemoteAddr, Result: "denied"})
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "revealing violation terms requires the lead role"})
		return
	}
	accts, err := s.Store.Accounts(id, true) // need unredacted matches
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "no audit selected"})
		return
	}
	meta, _ := s.Store.Meta(id)
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "reveal_violation_terms", Target: meta.Name, Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, model.AggregateTerms(accts, 25))
}
```

Register the route right after the `GET /api/report` line:

```go
	mux.Handle("GET /api/report/terms", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleReportTerms))))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/httpapi/ -run TestReportTermsLeadGatedAndAudited`
Expected: PASS

- [ ] **Step 5: gofmt + commit**

```bash
gofmt -w internal/httpapi/server.go internal/httpapi/server_test.go
git add internal/httpapi/server.go internal/httpapi/server_test.go
git commit -m "feat(api): lead-gated, audited GET /api/report/terms"
```

---

## Task 6: `WeakPasswordsHTML` — category chart on the weak export

**Files:**
- Modify: `internal/report/report.go` (add `WeakPasswordsHTML` + template + `catBar`/`weakData`)
- Modify: `internal/httpapi/server.go` (`handleExportWeakHTML` calls `WeakPasswordsHTML`)
- Test: `internal/report/report_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestWeakPasswordsHTML(t *testing.T) {
	accts := []model.Account{
		{Username: "alice", Domain: "CORP", Cracked: true, Password: "Summer2021!",
			BannedWords: []string{"summer", "2021"}, BannedWordCount: 2, IsCommon: true,
			RiskLevel: "Critical", RiskScore: 9},
		{Username: "bob", Domain: "CORP", Cracked: true, KeyboardPatterns: []string{"qwerty"},
			KeyboardPatternCount: 1, RiskLevel: "High", RiskScore: 7},
	}
	var b bytes.Buffer
	if err := WeakPasswordsHTML(&b, "Eng", time.Unix(1_700_000_000, 0), accts); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	// chart + table render
	if !strings.Contains(out, "by violation category") || !strings.Contains(out, "alice") || !strings.Contains(out, "</html>") {
		t.Fatalf("weak HTML malformed:\n%s", out)
	}
	// the matched WORD and the cleartext must never appear (counts/category only)
	for _, leak := range []string{"summer", "2021", "qwerty", "Summer2021!"} {
		if strings.Contains(out, leak) {
			t.Fatalf("weak HTML leaked %q", leak)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/report/ -run TestWeakPasswordsHTML`
Expected: FAIL — `WeakPasswordsHTML` undefined.

- [ ] **Step 3: Implement**

In `internal/report/report.go`, after the `focusedAccountsTemplate` block, add the chart builder + a dedicated template. It reuses `focusedCSS` (already defined) plus a couple of bar classes appended inline:

```go
type catBar struct {
	Label string
	N     int
	Pct   int
}

type weakData struct {
	Name, Generated string
	Count           int
	Bars            []catBar
	Accounts        []model.Account
}

// WeakPasswordsHTML renders the weak-passwords report: a by-category bar chart
// (counts only) over the supplied accounts, then the redacted account table. It
// never emits a matched word -- the actual terms are app-only (the terms endpoint).
func WeakPasswordsHTML(w io.Writer, name string, generated time.Time, accounts []model.Account) error {
	var common, dict, forbidden, keyboard int
	for _, a := range accounts {
		if a.IsCommon {
			common++
		}
		if a.IsDictionaryWord {
			dict++
		}
		if a.BannedWordCount > 0 {
			forbidden++
		}
		if a.KeyboardPatternCount > 0 {
			keyboard++
		}
	}
	bars := []catBar{
		{"Forbidden", forbidden, 0}, {"Common", common, 0},
		{"Dictionary", dict, 0}, {"Keyboard", keyboard, 0},
	}
	max := 1
	for _, b := range bars {
		if b.N > max {
			max = b.N
		}
	}
	for i := range bars {
		bars[i].Pct = bars[i].N * 100 / max
	}
	return weakTemplate.Execute(w, weakData{
		Name: name, Generated: generated.UTC().Format("2006-01-02 15:04 UTC"),
		Count: len(accounts), Bars: bars, Accounts: accounts,
	})
}

const weakCSS = focusedCSS + `
.cbar{display:grid;grid-template-columns:90px 1fr 30px;align-items:center;gap:10px;margin:7px 0;font:12px/1 ui-monospace,monospace}
.cbar .cl{color:#8a96b2;text-align:right}
.cbar .ct2{height:13px;background:#11182b;border-radius:4px;overflow:hidden}
.cbar .cf{height:100%;border-radius:4px;background:linear-gradient(90deg,#0e7490,#22d3ee)}
.cbar .cn{color:#e8edf7;text-align:right}`

var weakTemplate = template.Must(template.New("weak").Funcs(tmplFuncs).Parse(
	`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{{.Name}} — Weak passwords</title>
<style>` + weakCSS + `</style></head>
<body><div class="wrap">
<h1>{{.Name}} — Weak passwords</h1>
<div class="sub">Password!AtTheDisco — wordlist violations · generated {{.Generated}}</div>
<span class="redact">Redacted report · categories &amp; counts only — never the matched word</span>
<div class="label">By violation category</div>
<div class="panel">
{{range .Bars}}<div class="cbar"><span class="cl">{{.Label}}</span><span class="ct2"><span class="cf" style="width:{{.Pct}}%"></span></span><span class="cn">{{.N}}</span></div>{{end}}
</div>
<div class="label">{{.Count}} account{{if ne .Count 1}}s{{end}}</div>
<div class="panel"><table>
<tr><th>Username</th><th>Domain</th><th>Risk</th><th>Score</th><th>Weaknesses</th></tr>
{{range .Accounts}}<tr>
<td>{{.Username}}</td><td class="muted">{{.Domain}}</td>
<td><span class="badge" style="color:{{color .RiskLevel}};border-color:{{color .RiskLevel}}">{{.RiskLevel}}</span></td>
<td>{{f1 .RiskScore}}</td>
<td>{{if .IsCommon}}<span class="wtag">common</span> {{end}}{{if .IsDictionaryWord}}<span class="wtag">dictionary</span> {{end}}{{if gt .BannedWordCount 0}}<span class="wtag">forbidden</span> {{end}}{{if gt .KeyboardPatternCount 0}}<span class="wtag">keyboard</span> {{end}}{{if not .IsWeak}}<span class="muted">—</span>{{end}}</td>
</tr>{{end}}
{{if not .Accounts}}<tr><td colspan="5" class="empty">none</td></tr>{{end}}
</table></div>
<div class="foot">Generated by Password!AtTheDisco · cleartext passwords are never written to disk or included in reports</div>
</div></body></html>`))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/report/ -run TestWeakPasswordsHTML`
Expected: PASS

- [ ] **Step 5: Point the export handler at it**

In `internal/httpapi/server.go`, in `handleExportWeakHTML`, replace the `report.AccountsHTML(...)` call with:

```go
	_ = report.WeakPasswordsHTML(w, meta.Name, time.Now().UTC(), weak)
```

(Keep the `download(w, meta.Name, "weak-passwords", "html")` line and the `weak := filterAccounts(...)` line above it.)

- [ ] **Step 6: Run the report + httpapi tests**

Run: `go test ./internal/report/ ./internal/httpapi/`
Expected: ok ok

- [ ] **Step 7: gofmt + commit**

```bash
gofmt -w internal/report/report.go internal/report/report_test.go internal/httpapi/server.go
git add internal/report/report.go internal/report/report_test.go internal/httpapi/server.go
git commit -m "feat(report): category chart on the weak-passwords HTML export"
```

---

## Task 7: Frontend API types + `reportTerms()`

**Files:**
- Modify: `web/src/api.ts` (`Report` interface; new `ViolationCounts`/`Term`/`Terms`; `api.reportTerms`)

- [ ] **Step 1: Add the types**

In `web/src/api.ts`, add near the `Report` interface:

```ts
export interface ViolationCounts {
  common: number
  dictionary: number
  forbidden: number
  keyboard: number
}

export interface Term {
  term: string
  count: number
}

export interface Terms {
  forbidden: Term[]
  keyboard: Term[]
}
```

Add to the `Report` interface (after `weak_passwords`):

```ts
  violation_counts: ViolationCounts
```

- [ ] **Step 2: Add the API method**

In the `api` object, right after `report: () => request<Report>("/report"),` add:

```ts
  reportTerms: () => request<Terms>("/report/terms"),
```

- [ ] **Step 3: Typecheck**

Run: `cd web && npx tsc --noEmit`
Expected: no errors (any `Report` literal in tests that now needs `violation_counts` is handled in Task 9's test; if `npx tsc` flags an existing test fixture, add `violation_counts: {common:0,dictionary:0,forbidden:0,keyboard:0}` to it).

- [ ] **Step 4: Commit**

```bash
git add web/src/api.ts
git commit -m "feat(web): Report.violation_counts + reportTerms() API"
```

---

## Task 8: `BarChart` component

**Files:**
- Create: `web/src/components/BarChart.tsx`
- Test: `web/src/violations.test.ts`

- [ ] **Step 1: Write the failing test**

Create `web/src/violations.test.ts`:

```ts
import { describe, it, expect } from "vitest"
import { toBars } from "./components/BarChart"

describe("toBars", () => {
  it("scales widths to the max and preserves order", () => {
    const bars = toBars([
      { label: "Forbidden", n: 6 },
      { label: "Common", n: 3 },
      { label: "Keyboard", n: 0 },
    ])
    expect(bars[0]).toEqual({ label: "Forbidden", n: 6, pct: 100 })
    expect(bars[1].pct).toBe(50)
    expect(bars[2].pct).toBe(0)
  })

  it("handles all-zero without dividing by zero", () => {
    const bars = toBars([{ label: "X", n: 0 }])
    expect(bars[0].pct).toBe(0)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run violations`
Expected: FAIL — cannot import `toBars`.

- [ ] **Step 3: Implement the component**

Create `web/src/components/BarChart.tsx`:

```tsx
export interface BarInput {
  label: string
  n: number
}

export interface Bar extends BarInput {
  pct: number
}

// toBars scales each row's width to the largest value (0 when all are zero).
export function toBars(rows: BarInput[]): Bar[] {
  const max = Math.max(1, ...rows.map((r) => r.n))
  return rows.map((r) => ({ ...r, pct: Math.round((r.n / max) * 100) }))
}

// BarChart renders a horizontal CSS bar chart (no chart library).
export function BarChart({ rows, accent }: { rows: BarInput[]; accent?: "term" }) {
  const bars = toBars(rows)
  return (
    <div className={accent === "term" ? "barchart term" : "barchart"}>
      {bars.map((b) => (
        <div className="barrow" key={b.label}>
          <span className="barlabel">{b.label}</span>
          <span className="bartrack">
            <span className="barfill" style={{ width: `${b.pct}%` }} />
          </span>
          <span className="barn">{b.n.toLocaleString()}</span>
        </div>
      ))}
    </div>
  )
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web && npx vitest run violations`
Expected: PASS

- [ ] **Step 5: Add the CSS**

In `web/src/styles.css`, after the `.wtags`/`.badge.wtag` block, add:

```css
/* CSS bar charts (violation category + term drill-down) */
.barchart { display: flex; flex-direction: column; gap: 7px; }
.barrow { display: grid; grid-template-columns: 96px 1fr 36px; align-items: center; gap: 10px; font-family: var(--mono); font-size: 12px; }
.barlabel { color: var(--dim); text-align: right; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.bartrack { height: 13px; background: #11182b; border-radius: 4px; overflow: hidden; }
.barfill { display: block; height: 100%; border-radius: 4px; background: linear-gradient(90deg, #0e7490, #22d3ee); }
.barchart.term .barfill { background: linear-gradient(90deg, #9f1239, #fb7185); }
.barchart.term .barlabel { color: var(--crit); }
.barn { color: var(--text); text-align: right; }
```

- [ ] **Step 6: Commit**

```bash
git add web/src/components/BarChart.tsx web/src/violations.test.ts web/src/styles.css
git commit -m "feat(web): reusable CSS BarChart component"
```

---

## Task 9: Wire charts into Actionable → Weak Passwords

**Files:**
- Modify: `web/src/components/Actionable.tsx` (category chart + lead-gated term reveal in the Weak Passwords section)
- Modify: `web/src/components/Activity.tsx` (add `reveal_violation_terms` to the action filter)

- [ ] **Step 1: Add imports + auth/role + term state to `Actionable`**

At the top of `web/src/components/Actionable.tsx`, extend the imports:

```tsx
import { api, ApiError, type Report, type ReportAccount, type ReuseGroup, type Terms } from "../api"
import { useAuth } from "../auth"
import { BarChart } from "./BarChart"
```

Inside the `Actionable` component body (where `report`/`error` state lives), add:

```tsx
  const { me } = useAuth()
  const [terms, setTerms] = useState<Terms | null>(null)
  const [termsBusy, setTermsBusy] = useState(false)
  const [termsErr, setTermsErr] = useState("")

  async function revealTerms() {
    setTermsBusy(true)
    setTermsErr("")
    try {
      setTerms(await api.reportTerms())
    } catch (e) {
      setTermsErr(e instanceof ApiError ? e.message : "failed to load terms")
    } finally {
      setTermsBusy(false)
    }
  }
```

Also reset terms when the audit changes — in the existing `useEffect(... , [activeId])` that loads the report, add `setTerms(null)` alongside the other resets.

- [ ] **Step 2: Render the category chart + reveal inside the Weak Passwords `<Section>`**

In the "Weak Passwords" `<Section>`, immediately before the `<AccountTable .../>`, insert:

```tsx
        <div className="weak-charts">
          <div className="weak-chart-label">Accounts by violation category</div>
          <BarChart
            rows={[
              { label: "Forbidden", n: report.violation_counts.forbidden },
              { label: "Common", n: report.violation_counts.common },
              { label: "Dictionary", n: report.violation_counts.dictionary },
              { label: "Keyboard", n: report.violation_counts.keyboard },
            ]}
          />
          {me?.role === "lead" && (
            <div className="weak-terms">
              {!terms ? (
                <button className="btn" onClick={() => void revealTerms()} disabled={termsBusy}>
                  {termsBusy ? "Revealing…" : "🔓 Reveal recurring terms"}
                </button>
              ) : (
                <>
                  <div className="weak-chart-label">
                    Top recurring terms <span className="muted">— audit-logged reveal; actual words, in-app only</span>
                  </div>
                  {terms.forbidden.length > 0 && (
                    <BarChart accent="term" rows={terms.forbidden.slice(0, 10).map((t) => ({ label: t.term, n: t.count }))} />
                  )}
                  {terms.keyboard.length > 0 && (
                    <BarChart accent="term" rows={terms.keyboard.slice(0, 10).map((t) => ({ label: t.term, n: t.count }))} />
                  )}
                  {terms.forbidden.length === 0 && terms.keyboard.length === 0 && (
                    <div className="muted">No recurring forbidden words or keyboard patterns.</div>
                  )}
                </>
              )}
              {termsErr && <div className="error">{termsErr}</div>}
            </div>
          )}
        </div>
```

- [ ] **Step 3: Add the supporting CSS**

In `web/src/styles.css`, after the bar-chart block from Task 8, add:

```css
.weak-charts { margin-bottom: 16px; max-width: 520px; }
.weak-chart-label { font-size: 12px; color: var(--faint); margin: 4px 0 10px; }
.weak-terms { margin-top: 16px; padding-top: 14px; border-top: 1px solid var(--hairline); }
.weak-terms .barchart { margin-bottom: 10px; }
```

- [ ] **Step 4: Add the audit action to the Activity filter**

In `web/src/components/Activity.tsx`, in the `ACTIONS` array, add `"reveal_violation_terms"` next to `"reveal_secret"`:

```ts
  "login", "logout", "reveal_secret", "reveal_violation_terms", "store_unlock", "store_lock", "store_passphrase_change", "store_rekey",
```

- [ ] **Step 5: Typecheck + build + vitest**

Run: `cd web && npx tsc --noEmit && npm run build && npx vitest run`
Expected: no TS errors; build succeeds; vitest green.

- [ ] **Step 6: Commit**

```bash
git add web/src/components/Actionable.tsx web/src/components/Activity.tsx web/src/styles.css
git commit -m "feat(web): violation category chart + lead-gated term drill-down in Actionable"
```

---

## Task 10: Full gate, embedded rebuild, live verification

**Files:** none (verification + release)

- [ ] **Step 1: Backend gate**

Run:
```bash
gofmt -l cmd internal
go build ./... && go vet ./... && go test ./...
govulncheck ./...
```
Expected: gofmt prints nothing; all packages `ok`; "No vulnerabilities found."

- [ ] **Step 2: Rebuild embedded binary + restart**

Run:
```bash
taskkill //F //IM patd.exe 2>/dev/null; sleep 1
rm -rf internal/webui/dist && cp -r web/dist internal/webui/dist
CGO_ENABLED=0 go build -tags embed -trimpath -ldflags="-s -w" -o patd.exe ./cmd/patd
PATD_ADDR=127.0.0.1:8443 PATD_INGEST_TOKEN=tok PATD_USERS_FILE=users.json PATD_AUDIT_LOG=audit.log \
  PATD_HIBP=PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt PATD_LISTS=lists \
  PATD_BHE=config/bloodhound.json PATD_DATA=data ./patd.exe > server.log 2>&1 &
sleep 3
```
Note: re-ingest is required — accounts scored before Task 2 have no stored matched words. Delete the lab audit and re-run the dump+apply flow (the established `/api/upload` + `/api/upload/cracks` sequence with the `sample_data` dumps), as in prior sessions.

- [ ] **Step 2b: Verify the data path (logged in as lead)**

- `GET /api/report` → `violation_counts` populated; grep the body for a known forbidden word (e.g. `2021`) → MUST be absent.
- `GET /api/report/terms` → returns `forbidden`/`keyboard` arrays with the actual words (e.g. `2021`).
- `GET /api/export/weak.html` → contains "by violation category" + bars; grep for `2021` → MUST be absent.
- Confirm an `reveal_violation_terms` `ok` event is in the audit log after the terms call.

- [ ] **Step 3: Browser check (Playwright)**

Log in (`watson`/`discotime`), unlock (`disco-vault-2026`), open the lab audit, go to **Actionable → Weak Passwords**: the category chart renders; as a lead, "🔓 Reveal recurring terms" expands the term chart; screenshot it. Sign in as a non-lead (if one exists) and confirm the button is absent.

- [ ] **Step 4: README note + commit**

Add a one-line note to the README "What's new in 2.2" Actionable bullet (or a 2.2.1 line) that violations now show a category chart + an in-app, audited term drill-down. Commit:

```bash
git add README.md
git commit -m "docs: note violation charts + audited term drill-down"
```

- [ ] **Step 5: Push**

```bash
git push
```
Then confirm CI is green on the pushed commit.

---

## Self-Review notes

- **Spec coverage:** matched-word storage+redaction (T1), engine fill (T2), category counts (T3), term aggregation excl. common/dictionary (T4), lead-gated audited endpoint (T5), category chart in export (T6), API types (T7), chart component (T8), app wiring incl. Activity filter (T9), gate+live+redaction grep (T10). All spec sections mapped.
- **Type consistency:** `Terms{forbidden,keyboard}` / `Term{term,count}` identical in Go (`report.go`) and TS (`api.ts`); `ViolationCounts{common,dictionary,forbidden,keyboard}` identical both sides; `WeakPasswordsHTML(w,name,generated,accounts)` signature matches its caller in T6 Step 5.
- **Redaction guard:** T5 asserts `/api/report` lacks the planted word; T6 asserts the export lacks it; T10 greps live. Three independent leak checks.
- **No new dependency:** charts are CSS-only (`BarChart`), consistent with the stdlib-first rule.
