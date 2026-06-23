# Sanitized audit-review export — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new `/api/export/sanitized.json` export (+ Reports-tab button) that emits every per-account scoring signal and the audit aggregates with opaque structure preserved, carrying **zero** identifying or secret data (no usernames, domain names, hashes, cleartext, matched wordlist substrings, DA domain names, raw password-set timestamps, or audit name).

**Architecture:** A pure, allowlist-based sanitizer in `internal/report/sanitize.go` builds **separate output structs** (never marshals `model.Account`), so any future sensitive field is excluded by default. A thin HTTP handler reads the **unredacted** accounts (NT hash needed only to compute opaque reuse groups — never emitted), computes the summary, and streams the sanitized JSON; a Reports-tab anchor downloads it.

**Tech Stack:** Go 1.26 stdlib (`encoding/json`, `time`, `testing`, `bytes`); React 18 + TS (a plain `<a download>`).

**Spec:** `docs/superpowers/specs/2026-06-23-sanitized-review-export-design.md`

## File Structure
- `internal/report/sanitize.go` (new) — output structs + `Sanitize(...)` builder + `SanitizedJSON(...)` encoder. (Task 1)
- `internal/report/sanitize_test.go` (new) — canary-leak + transform + structure tests. (Task 1)
- `internal/httpapi/server.go` — `download` gains a `json` content-type case; new route + `handleExportSanitized`. (Task 2)
- `internal/httpapi/server_test.go` — handler test. (Task 2)
- `web/src/components/Reports.tsx` — a "Sanitized JSON" download panel. (Task 3)

**Gates (repo root):** `gofmt -l cmd internal` · `go build ./...` · `go vet ./...` · `go test ./...` · `govulncheck ./...`. Web (in `web/`, NEVER `npm install`): `npx tsc --noEmit` · `npx vitest run` · `npm run build`.

**Branch:** `feature/sanitized-review-export` (already created). Every implementer: confirm `git branch --show-current` == that; NEVER `git checkout`/`switch`/`branch`. Bash tool for git/go (POSIX).

---

## Task 1: The sanitizer (pure, allowlist)

**Files:**
- Create: `internal/report/sanitize.go`
- Create: `internal/report/sanitize_test.go`

- [ ] **Step 1: Write the failing tests (canary + transforms + structure)**

Create `internal/report/sanitize_test.go`:

```go
package report

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// TestSanitizedNoLeak is the decisive guarantee: no identifying/secret value
// appears anywhere in the serialized output, even though the input carries them.
func TestSanitizedNoLeak(t *testing.T) {
	now := time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC)
	accts := []model.Account{{
		Username: "CANARY_USER", Domain: "CANARY.CORP", Password: "CANARY_PW",
		NTHash: "CANARYHASH", BannedWords: []string{"CANARYWORD"}, KeyboardPatterns: []string{"CANARYKBD"},
		DADomains: "CANARY.CORP", Cracked: true, PasswordLength: 9,
		SimilarPeers: []model.SimilarPeer{{Username: "CANARY_PEER", Domain: "CANARY.CORP", Score: 0.9}},
	}}
	var buf bytes.Buffer
	if err := SanitizedJSON(&buf, accts, model.Summary{}, now, "v9.9.9"); err != nil {
		t.Fatalf("SanitizedJSON: %v", err)
	}
	for _, canary := range []string{"CANARY_USER", "CANARY.CORP", "CANARY_PW", "CANARYHASH", "CANARYWORD", "CANARYKBD", "CANARY_PEER"} {
		if bytes.Contains(buf.Bytes(), []byte(canary)) {
			t.Errorf("LEAK: output contains %q", canary)
		}
	}
}

func TestSanitizedTransforms(t *testing.T) {
	now := time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC)
	pwdLastSet := now.AddDate(0, 0, -100).Unix() // 100 days old
	rep := Sanitize([]model.Account{
		{Username: "a", Domain: "CORP", DADomains: "CORP.LOCAL", PwdLastSet: pwdLastSet}, // has DA path
		{Username: "b", Domain: "CORP", DADomains: "None"},                                 // no DA path, no pwdlastset
	}, model.Summary{}, now, "v1")

	if got := rep.Accounts[0].HasDAPath; !got {
		t.Errorf("acct a HasDAPath = false, want true (DADomains set)")
	}
	if got := rep.Accounts[1].HasDAPath; got {
		t.Errorf("acct b HasDAPath = true, want false (DADomains None)")
	}
	if got := rep.Accounts[0].PasswordAgeDays; got != 100 {
		t.Errorf("acct a PasswordAgeDays = %d, want 100", got)
	}
	if got := rep.Accounts[1].PasswordAgeDays; got != 0 {
		t.Errorf("acct b PasswordAgeDays = %d, want 0 (no pwdlastset)", got)
	}
	// Opaque labels, no names.
	if rep.Accounts[0].ID != "a1" || rep.Accounts[1].ID != "a2" {
		t.Errorf("ids = %q,%q, want a1,a2", rep.Accounts[0].ID, rep.Accounts[1].ID)
	}
	if rep.Accounts[0].DomainLabel != "D1" || rep.Accounts[1].DomainLabel != "D1" {
		t.Errorf("same domain must share a label, got %q,%q", rep.Accounts[0].DomainLabel, rep.Accounts[1].DomainLabel)
	}
}

func TestSanitizedReuseGroupsAndPeers(t *testing.T) {
	now := time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC)
	rep := Sanitize([]model.Account{
		{Username: "a", Domain: "CORP", NTHash: "SHARED", SimilarPeers: []model.SimilarPeer{{Username: "c", Domain: "CORP", Score: 0.8}}},
		{Username: "b", Domain: "CORP", NTHash: "SHARED"},
		{Username: "c", Domain: "CORP", NTHash: "UNIQUE"},
	}, model.Summary{}, now, "v1")

	// a and b share a hash -> same non-empty reuse_group; c is alone -> "".
	if rep.Accounts[0].ReuseGroup == "" || rep.Accounts[0].ReuseGroup != rep.Accounts[1].ReuseGroup {
		t.Errorf("a,b reuse_group = %q,%q, want equal+non-empty", rep.Accounts[0].ReuseGroup, rep.Accounts[1].ReuseGroup)
	}
	if rep.Accounts[2].ReuseGroup != "" {
		t.Errorf("c reuse_group = %q, want \"\" (no sharing)", rep.Accounts[2].ReuseGroup)
	}
	// a's similar peer "c" resolves to c's opaque id (a3).
	if len(rep.Accounts[0].SimilarPeers) != 1 || rep.Accounts[0].SimilarPeers[0].ID != "a3" {
		t.Errorf("a similar_peers = %+v, want one peer id a3", rep.Accounts[0].SimilarPeers)
	}
}

func TestSanitizedSummaryAndDomainsCarried(t *testing.T) {
	now := time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC)
	sum := model.Summary{TotalAccounts: 2, Cracked: 1}
	rep := Sanitize([]model.Account{
		{Username: "a", Domain: "CORP", RiskLevel: "High"},
		{Username: "b", Domain: "EU", RiskLevel: "Low"},
	}, sum, now, "v2.24.0")
	if rep.Summary.TotalAccounts != 2 || rep.ToolVersion != "v2.24.0" || rep.SchemaVersion != 1 {
		t.Errorf("header/summary not carried: %+v", rep)
	}
	if len(rep.Domains) != 2 {
		t.Fatalf("domains = %d, want 2 (CORP, EU as D1/D2)", len(rep.Domains))
	}
	// Round-trips as valid JSON.
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(rep); err != nil {
		t.Fatalf("encode: %v", err)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/report/ -run TestSanitized -v`
Expected: FAIL — compile error `undefined: SanitizedJSON` / `Sanitize`.

- [ ] **Step 3: Implement the sanitizer**

Create `internal/report/sanitize.go`:

```go
package report

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// emptyNTHash is the NT hash of an empty password (a public constant) -- accounts
// with it are "no password", not real reuse, so they are not grouped. Mirrors the
// exclusion in model.reuseKey (which is unexported).
const emptyNTHash = "31D6CFE0D16AE931B73C59D7E0C089C0"

// SanitizedReport is the top-level review export. It is an ALLOWLIST structure:
// nothing is copied from model.Account except the explicitly-named safe fields
// below, so any future field on model.Account is excluded by default.
type SanitizedReport struct {
	SchemaVersion int                `json:"schema_version"`
	GeneratedAt   time.Time          `json:"generated_at"`
	ToolVersion   string             `json:"tool_version"`
	Summary       model.Summary      `json:"summary"`
	Domains       []SanitizedDomain  `json:"domains"`
	Accounts      []SanitizedAccount `json:"accounts"`
}

// SanitizedDomain is a per-domain rollup with no domain name.
type SanitizedDomain struct {
	Label        string `json:"label"`
	AccountCount int    `json:"account_count"`
	RiskLevel    string `json:"risk_level,omitempty"`
}

// SanitizedPeer references another account in this report by its opaque id.
type SanitizedPeer struct {
	ID    string  `json:"id"`
	Score float64 `json:"score"`
}

// SanitizedAccount carries every per-account SCORING/STRUCTURAL signal with no
// identifying or secret data. Sensitive raw fields are transformed: domain ->
// DomainLabel, DA domain names -> HasDAPath, raw pwdLastSet -> PasswordAgeDays,
// peer usernames -> opaque ids.
type SanitizedAccount struct {
	ID          string `json:"id"`
	DomainLabel string `json:"domain_label"`
	ReuseGroup  string `json:"reuse_group,omitempty"`

	Cracked        bool   `json:"cracked"`
	PasswordLength int    `json:"password_length"`
	Complexity     string `json:"complexity,omitempty"`

	RiskLevel     string   `json:"risk_level"`
	RiskScore     float64  `json:"risk_score"`
	RiskVector    string   `json:"risk_vector"`
	ExposureScore float64  `json:"exposure_score"`
	ImpactScore   *float64 `json:"impact_score"`
	ImpactKnown   bool     `json:"impact_known"`
	Percentile    float64  `json:"percentile"`

	HIBPBreached    bool `json:"hibp_breached"`
	HIBPBreachCount int  `json:"hibp_breach_count"`

	SharedWith          int  `json:"shared_with"`
	EscalatedBySharedDA bool `json:"escalated_by_shared_da,omitempty"`
	HasDAPath           bool `json:"has_da_path"`
	ControlledObjects   int  `json:"controlled_object_count"`
	ControlsTier0       bool `json:"controls_tier0,omitempty"`

	Enabled  bool   `json:"enabled"`
	Coverage string `json:"coverage,omitempty"`

	MeetsPolicy          bool     `json:"meets_policy"`
	PolicyViolations     []string `json:"policy_violations,omitempty"`
	IsCommon             bool     `json:"is_common,omitempty"`
	IsDictionaryWord     bool     `json:"is_dictionary_word,omitempty"`
	BannedWordCount      int      `json:"banned_word_count,omitempty"`
	KeyboardPatternCount int      `json:"keyboard_pattern_count,omitempty"`
	ContainsUnicode      bool     `json:"contains_unicode,omitempty"`

	PasswordAgeDays     int   `json:"password_age_days"`
	PwdNeverExpires     *bool `json:"pwd_never_expires,omitempty"`
	DaysOutOfCompliance int   `json:"days_out_of_compliance,omitempty"`

	HasSPN         *bool `json:"has_spn,omitempty"`
	DontReqPreauth *bool `json:"dont_req_preauth,omitempty"`

	SimilarityScore float64               `json:"similarity_score,omitempty"`
	SimilarPeers    []SanitizedPeer       `json:"similar_peers,omitempty"`
	ScoreBreakdown  *model.ScoreBreakdown `json:"score_breakdown,omitempty"`
}

// peerKey normalizes a (username, domain) into the lookup key used to resolve
// similar-peer references to opaque account ids.
func peerKey(username, domain string) string {
	return strings.ToLower(strings.TrimSpace(username)) + "@" + strings.ToUpper(strings.TrimSpace(domain))
}

// reuseGroupKey mirrors model.reuseKey: uppercased NT hash, excluding empty/absent
// and the empty-password hash (those are not real reuse).
func reuseGroupKey(ntHash string) string {
	h := strings.ToUpper(strings.TrimSpace(ntHash))
	if h == "" || h == emptyNTHash {
		return ""
	}
	return h
}

func ageDays(pwdLastSet int64, now time.Time) int {
	if pwdLastSet <= 0 {
		return 0
	}
	d := int(now.Sub(time.Unix(pwdLastSet, 0).UTC()).Hours() / 24)
	if d < 0 {
		d = 0
	}
	return d
}

// Sanitize builds the allowlist report from the (unredacted) accounts. NT hashes
// and identities are used only to compute opaque structure; none are emitted.
func Sanitize(accounts []model.Account, summary model.Summary, now time.Time, version string) SanitizedReport {
	n := len(accounts)
	ids := make([]string, n)
	idByPeerKey := make(map[string]string, n)
	for i, a := range accounts {
		ids[i] = "a" + strconv.Itoa(i+1)
		idByPeerKey[peerKey(a.Username, a.Domain)] = ids[i]
	}

	// Domain labels (first-seen order) + per-domain rollup.
	domainLabel := make(map[string]string)
	var domainOrder []string
	domAccts := make(map[string][]model.Account)
	for _, a := range accounts {
		if _, ok := domainLabel[a.Domain]; !ok {
			domainLabel[a.Domain] = "D" + strconv.Itoa(len(domainOrder)+1)
			domainOrder = append(domainOrder, a.Domain)
		}
		domAccts[a.Domain] = append(domAccts[a.Domain], a)
	}
	domains := make([]SanitizedDomain, 0, len(domainOrder))
	for _, d := range domainOrder {
		domains = append(domains, SanitizedDomain{
			Label: domainLabel[d], AccountCount: len(domAccts[d]), RiskLevel: modeRiskLevel(domAccts[d]),
		})
	}

	// Reuse groups: one opaque id per NT hash shared by >=2 accounts.
	hashCount := make(map[string]int)
	for _, a := range accounts {
		if k := reuseGroupKey(a.NTHash); k != "" {
			hashCount[k]++
		}
	}
	reuseGroup := make(map[string]string)
	for _, a := range accounts {
		k := reuseGroupKey(a.NTHash)
		if k == "" || hashCount[k] < 2 {
			continue
		}
		if _, ok := reuseGroup[k]; !ok {
			reuseGroup[k] = "g" + strconv.Itoa(len(reuseGroup)+1)
		}
	}

	out := make([]SanitizedAccount, 0, n)
	for i, a := range accounts {
		var peers []SanitizedPeer
		for _, p := range a.SimilarPeers {
			if pid, ok := idByPeerKey[peerKey(p.Username, p.Domain)]; ok {
				peers = append(peers, SanitizedPeer{ID: pid, Score: p.Score})
			}
		}
		out = append(out, SanitizedAccount{
			ID:          ids[i],
			DomainLabel: domainLabel[a.Domain],
			ReuseGroup:  reuseGroup[reuseGroupKey(a.NTHash)],

			Cracked:        a.Cracked,
			PasswordLength: a.PasswordLength,
			Complexity:     a.Complexity,

			RiskLevel:     a.RiskLevel,
			RiskScore:     a.RiskScore,
			RiskVector:    a.RiskVector,
			ExposureScore: a.ExposureScore,
			ImpactScore:   a.ImpactScore,
			ImpactKnown:   a.ImpactKnown,
			Percentile:    a.Percentile,

			HIBPBreached:    a.HIBPBreached,
			HIBPBreachCount: a.HIBPBreachCount,

			SharedWith:          a.SharedWith,
			EscalatedBySharedDA: a.EscalatedBySharedDA,
			HasDAPath:           a.HasDAPathway(),
			ControlledObjects:   a.Controlled,
			ControlsTier0:       a.ControlsTier0,

			Enabled:  a.Enabled,
			Coverage: a.Coverage,

			MeetsPolicy:          a.MeetsPolicy,
			PolicyViolations:     a.PolicyViolations,
			IsCommon:             a.IsCommon,
			IsDictionaryWord:     a.IsDictionaryWord,
			BannedWordCount:      a.BannedWordCount,
			KeyboardPatternCount: a.KeyboardPatternCount,
			ContainsUnicode:      a.ContainsUnicode,

			PasswordAgeDays:     ageDays(a.PwdLastSet, now),
			PwdNeverExpires:     a.PwdNeverExpires,
			DaysOutOfCompliance: a.DaysOutOfCompliance,

			HasSPN:         a.HasSPN,
			DontReqPreauth: a.DontReqPreauth,

			SimilarityScore: a.SimilarityScore,
			SimilarPeers:    peers,
			ScoreBreakdown:  a.ScoreBreakdown,
		})
	}

	return SanitizedReport{
		SchemaVersion: 1,
		GeneratedAt:   now.UTC(),
		ToolVersion:   version,
		Summary:       summary,
		Domains:       domains,
		Accounts:      out,
	}
}

// modeRiskLevel returns the most common RiskLevel among the accounts (ties broken
// by severity Critical>High>Medium>Low). "" if none.
func modeRiskLevel(accts []model.Account) string {
	counts := make(map[string]int)
	for _, a := range accts {
		if a.RiskLevel != "" {
			counts[a.RiskLevel]++
		}
	}
	order := []string{"Critical", "High", "Medium", "Low"}
	best, bestN := "", 0
	for _, lvl := range order {
		if counts[lvl] > bestN {
			best, bestN = lvl, counts[lvl]
		}
	}
	return best
}

// SanitizedJSON builds and writes the sanitized report as indented JSON.
func SanitizedJSON(w io.Writer, accounts []model.Account, summary model.Summary, now time.Time, version string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(Sanitize(accounts, summary, now, version))
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/report/ -run TestSanitized -v` → all 4 PASS.
Run: `gofmt -l internal/report/sanitize.go internal/report/sanitize_test.go` → nothing.
Run: `go test ./internal/report/` → all green.

- [ ] **Step 5: Commit**

```bash
test "$(git branch --show-current)" = "feature/sanitized-review-export" || { echo "WRONG BRANCH"; exit 1; }
git add internal/report/sanitize.go internal/report/sanitize_test.go
git commit -m "feat(report): allowlist sanitizer — scoring data with no identity/secrets, opaque structure"
```

---

## Task 2: HTTP endpoint `GET /api/export/sanitized.json`

**Files:**
- Modify: `internal/httpapi/server.go` (`download` helper ~line where it maps ext→ctype; route registration near the other `/api/export/*` routes ~line 185; new handler near the other export handlers)
- Test: `internal/httpapi/server_test.go`

- [ ] **Step 1: Write the failing handler test**

Add to `internal/httpapi/server_test.go` (mirrors the export-handler tests: `newServer` → `loginCSRF` → `createAudit` → `Store.Replace` seed → GET via `Routes()`; the audit must be unlocked/active for the lead). Confirm the helper names against a neighboring export test first.

```go
func TestExportSanitizedJSON(t *testing.T) {
	srv := newServer("secret")
	srv.Engine = &engine.Engine{Policies: policy.DefaultSet()}
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	id := createAudit(t, srv, lc, lcsrf, "Acme Customer Audit") // name carries a "customer"

	if err := srv.Store.Replace(id, model.Dataset{
		Name: "Acme Customer Audit",
		Accounts: []model.Account{
			{Username: "SECRETUSER", Domain: "SECRET.CORP", NTHash: "SECRETHASH", Cracked: true, ExposureScore: 4.3},
		},
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/export/sanitized.json", nil)
	req.AddCookie(lc)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("sanitized export: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	for _, canary := range []string{"SECRETUSER", "SECRET.CORP", "SECRETHASH", "Acme Customer Audit"} {
		if strings.Contains(body, canary) {
			t.Errorf("LEAK in handler output: %q", canary)
		}
	}
	var rep map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if _, ok := rep["accounts"]; !ok {
		t.Errorf("missing accounts in output")
	}
}
```
(Ensure `strings`, `encoding/json`, `net/http`, `net/http/httptest` are imported in the test file — most already are from neighboring tests; add `encoding/json` to the import block if `go build` reports it missing.)

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/httpapi/ -run TestExportSanitizedJSON -v`
Expected: FAIL — 404 (route not registered) or the canary leak / missing-accounts assertion.

- [ ] **Step 3: Add a `json` case to the `download` helper**

In `internal/httpapi/server.go`, in `download`, where it sets `ctype` (currently `"text/csv…"` with an `if ext == "html"` branch), add a JSON branch:

```go
	ctype := "text/csv; charset=utf-8"
	if ext == "html" {
		ctype = "text/html; charset=utf-8"
	}
	if ext == "json" {
		ctype = "application/json; charset=utf-8"
	}
```

- [ ] **Step 4: Register the route**

In `internal/httpapi/server.go`, next to the other `/api/export/*` routes (after `GET /api/export/weak.html`), add:

```go
	mux.Handle("GET /api/export/sanitized.json", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleExportSanitized))))
```

- [ ] **Step 5: Add the handler**

In `internal/httpapi/server.go`, near the other export handlers, add. It reads **unredacted** accounts (NT hash needed for reuse grouping; the sanitizer emits none) and uses a **generic download filename** so the audit name never leaks via the filename:

```go
// handleExportSanitized streams a fully anonymized review export: every per-account
// scoring signal + audit aggregates, with no identity or secret data. It reads the
// UNREDACTED accounts because the NT hash is needed to compute opaque reuse groups
// (the hash itself is never emitted). The download filename is generic so the
// operator-chosen audit name does not leak.
func (s *Server) handleExportSanitized(w http.ResponseWriter, r *http.Request) {
	ver := s.Build.Version
	if ver == "" {
		ver = "dev"
	}
	writeEmpty := func(w http.ResponseWriter) { _ = report.SanitizedJSON(w, nil, model.Summary{}, time.Now().UTC(), ver) }
	_, id, ok := s.exportResolveRead(w, r, "sanitized JSON", "patd-sanitized", "", "json", writeEmpty)
	if !ok {
		return // empty 200 + audit-noop already handled
	}
	accts, err := s.Store.Accounts(id, true) // unredacted: NT hash for reuse grouping only; output is sanitized
	if err != nil {
		download(w, "patd-sanitized", "", "json")
		writeEmpty(w)
		return
	}
	sum, _ := s.Store.Summary(id)
	download(w, "patd-sanitized", "", "json")
	_ = report.SanitizedJSON(w, accts, sum, time.Now().UTC(), ver)
}
```
(`exportResolveRead` already audit-logs the export as `Action:"export", Target:"<auditName> — sanitized JSON"`. `report`, `model`, `time` are already imported in server.go.)

- [ ] **Step 6: Run to verify it passes + gates**

Run: `go test ./internal/httpapi/ -run TestExportSanitizedJSON -v` → PASS.
Run: `gofmt -l internal/httpapi/server.go internal/httpapi/server_test.go` → nothing.
Run: `go build ./... && go vet ./... && go test ./...` → all green.

- [ ] **Step 7: Commit**

```bash
test "$(git branch --show-current)" = "feature/sanitized-review-export" || { echo "WRONG BRANCH"; exit 1; }
git add internal/httpapi/server.go internal/httpapi/server_test.go
git commit -m "feat(httpapi): GET /api/export/sanitized.json — audit-logged anonymized review export"
```

---

## Task 3: Reports-tab download button

**Files:**
- Modify: `web/src/components/Reports.tsx` (add a panel after the "Full report (HTML)" panel, ~line 148)

- [ ] **Step 1: Add the sanitized-export panel**

In `web/src/components/Reports.tsx`, immediately AFTER the closing `</div>` of the "Full report (HTML)" panel (the `<div className="panel report-export">` that ends ~line 148), add:

```tsx
      <div className="panel report-export">
        <div className="report-export-head">
          <div>
            <div className="action-title">Sanitized review export (JSON)</div>
            <div className="action-sub">
              Every per-account <b>scoring signal</b> and the audit aggregates, with <b>all identity removed</b> —
              no usernames, domain names, hashes, cleartext, or audit name. Domains and password-reuse groups are
              preserved as opaque labels so the scoring can be reviewed (by a person or an AI) without exposing
              customer data.
            </div>
          </div>
          <a className="btn" href="/api/export/sanitized.json" download>
            Download JSON
          </a>
        </div>
      </div>
```

(Plain `<a download>` like the other exports — no new component, no inline styles. `styleguard.test.ts` bans literal inline spacing styles; this uses only existing classNames.)

- [ ] **Step 2: Verify the web gates**

Run (in `web/`): `npx tsc --noEmit` · `npx vitest run` · `npm run build`
Expected: tsc clean, all vitest pass (no test asserts the Reports panel set; if one snapshots it, update to include the new panel), build succeeds.

- [ ] **Step 3: Commit**

```bash
test "$(git branch --show-current)" = "feature/sanitized-review-export" || { echo "WRONG BRANCH"; exit 1; }
git add web/src/components/Reports.tsx
git commit -m "feat(web): Reports-tab download for the sanitized review export"
```

---

## Final verification (after all tasks)
- [ ] **Go gate:** `gofmt -l cmd internal` · `go build ./...` · `go vet ./...` · `go test ./...` · `govulncheck ./...`
- [ ] **Web gate (in `web/`):** `npx tsc --noEmit` · `npx vitest run` · `npm run build`
- [ ] **Live (build-and-run + restart):** on an audit with real-ish data, download `/api/export/sanitized.json`; confirm it parses, has `summary`/`domains`/`accounts`, every account has the scoring fields + opaque `id`/`domain_label`/`reuse_group`, and a grep for any known username/domain/hash returns nothing; confirm an audit-log `export` entry was written. Console clean.

## Definition of done
A lead can download a generic-named `patd-sanitized.json` from the Reports tab (and `GET /api/export/sanitized.json`) containing every per-account scoring signal + audit aggregates with opaque structure and **no** identity or secrets; the export is audit-logged; the canary test guarantees fail-closed sanitization; the scoring engine and existing exports are unchanged.
