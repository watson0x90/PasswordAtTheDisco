# Mass-reuse Level escalation (Finding 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Members of a large CRACKED password-reuse cluster escalate to Medium/High Level (scale-aware thresholds, cap High) so "one crack owns N accounts" stops reading as N×"Low" on the worklist — without inflating Impact.

**Architecture:** A new audit-level pass `model.EscalateLargeCrackedReuse` (mirroring `EscalateSharedWithDA`) raises Level/RiskScore/vector/flag only; Impact stays honest. It runs after `EscalateSharedWithDA`, before `ComputePercentiles`, at all three store pipeline sites. The `escalated_by_mass_reuse` flag flows to a Summary count, the sanitized export, and the account drawer.

**Tech Stack:** Go 1.26 stdlib (`math`, `strings`, `testing`); React 18 + TS.

**Spec:** `docs/superpowers/specs/2026-06-23-mass-reuse-escalation-design.md`

## File Structure
- `internal/model/model.go` — `EscalatedByMassReuse` field + const block + `massReuseTarget`/`levelRank`/`moreSevereLevel`/`levelFloorScore` + `EscalateLargeCrackedReuse` + `Summary.EscalatedByMassReuse`. (Tasks 1, 2)
- `internal/model/model_test.go` — pass + threshold tests. (Task 1)
- `internal/store/store.go` — 3 pipeline inserts + the Summary count. (Task 2)
- `internal/store/store_test.go` — pipeline/Summary test. (Task 2)
- `internal/report/sanitize.go` + `sanitize_test.go` — export field. (Task 3)
- `web/src/api.ts` + `web/src/components/AccountDrawer.tsx` — field + drawer row. (Task 4)

**Gates (repo root):** `gofmt -l cmd internal` · `go build ./...` · `go vet ./...` · `go test ./...` · `govulncheck ./...`. Web (in `web/`, NEVER `npm install`): `npx tsc --noEmit` · `npx vitest run` · `npm run build`.

**Branch:** `feature/mass-reuse-escalation` (already created). Every implementer: confirm `git branch --show-current` == that; NEVER `git checkout`/`switch`/`branch`. Bash tool for git/go.

---

## Task 1: The escalation pass + field + helpers (`internal/model`)

**Files:**
- Modify: `internal/model/model.go` (`Account` struct — add field near `EscalatedBySharedDA` ~line 221; the pass + helpers near `EscalateSharedWithDA`)
- Test: `internal/model/model_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `internal/model/model_test.go` (it is `package model`; `fmt`/`strings` may need importing — add them):

```go
func TestMassReuseTarget(t *testing.T) {
	cases := []struct {
		n, total int
		want     string
	}{
		{100, 10000, "High"},  // absolute High
		{25, 10000, "Medium"}, // absolute Medium (25 << 5% of 10000)
		{24, 10000, ""},       // below both
		{20, 30, "High"},      // hybrid: 20 >= 0.25*30=7.5 and >=5
		{8, 100, "Medium"},    // hybrid: 8 >= 0.05*100=5 and >=5
		{2, 4, ""},            // below the N>=5 fraction guard
		{4, 5, ""},            // 4 < 5 guard even though 80% of audit
	}
	for _, c := range cases {
		if got := massReuseTarget(c.n, c.total); got != c.want {
			t.Errorf("massReuseTarget(%d,%d)=%q want %q", c.n, c.total, got, c.want)
		}
	}
}

func TestEscalateLargeCrackedReuse(t *testing.T) {
	accts := make([]Account, 0, 102)
	for i := 0; i < 100; i++ { // 100 cracked share one hash -> High
		accts = append(accts, Account{Username: fmt.Sprintf("u%d", i), Domain: "CORP", NTHash: "SHARED", Cracked: true, RiskLevel: "Low", RiskScore: 0.8})
	}
	accts = append(accts, Account{Username: "x", Domain: "CORP", NTHash: "OTHER", Cracked: false, RiskLevel: "Low"})                                          // uncracked, untouched
	accts = append(accts, Account{Username: "crit", Domain: "CORP", NTHash: "SHARED", Cracked: true, RiskLevel: "Critical", RiskScore: 9.0, EscalatedBySharedDA: true}) // already Critical

	EscalateLargeCrackedReuse(accts)

	for i := 0; i < 100; i++ {
		a := accts[i]
		if a.RiskLevel != "High" {
			t.Fatalf("u%d level=%q want High", i, a.RiskLevel)
		}
		if !a.EscalatedByMassReuse || !strings.Contains(a.RiskVector, "MASS-REUSE") {
			t.Fatalf("u%d not flagged/tagged: %+v", i, a)
		}
		if a.RiskScore < 6.0 {
			t.Fatalf("u%d score=%v want >=6.0 (High floor)", i, a.RiskScore)
		}
		if a.ImpactKnown || a.ImpactScore != nil {
			t.Fatalf("u%d Impact must stay untouched", i)
		}
	}
	if accts[100].EscalatedByMassReuse || accts[100].RiskLevel != "Low" {
		t.Errorf("uncracked account wrongly escalated: %+v", accts[100])
	}
	if accts[101].RiskLevel != "Critical" || !accts[101].EscalatedByMassReuse {
		t.Errorf("already-Critical member must stay Critical AND be flagged: %+v", accts[101])
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/model/ -run 'TestMassReuseTarget|TestEscalateLargeCrackedReuse' -v`
Expected: FAIL — `undefined: massReuseTarget` / `EscalateLargeCrackedReuse` / `EscalatedByMassReuse`.

- [ ] **Step 3: Add the `EscalatedByMassReuse` field to `Account`**

In `internal/model/model.go`, immediately after the `EscalatedBySharedDA bool ...` field (~line 221):

```go
	// EscalatedByMassReuse is true when this account was escalated by
	// EscalateLargeCrackedReuse (member of a large CRACKED reuse cluster).
	EscalatedByMassReuse bool `json:"escalated_by_mass_reuse,omitempty"`
```

- [ ] **Step 4: Add the const block + helpers + the pass**

In `internal/model/model.go`, add near `EscalateSharedWithDA` (`math` and `strings` are already imported):

```go
// Mass-reuse Level escalation (Finding 1). A large CRACKED reuse cluster is collectively
// high-risk ("crack one, own N") even though each member's blast radius is low; the
// Exposure x Impact matrix caps low-Impact accounts at Medium, so without this pass a
// 402-account cracked cluster reads as 402x "Low". Hybrid + scale-aware so it isn't locked
// to one audit size. Tune the five knobs here.
const (
	massReuseHighN             = 100
	massReuseMediumN           = 25
	massReuseHighFrac          = 0.25
	massReuseMediumFrac        = 0.05
	massReuseMinClusterForFrac = 5 // the fraction path requires at least this many accounts
)

// massReuseTarget returns the Level a cracked cluster of n members (in an audit of total
// accounts) escalates to: "High", "Medium", or "" (none). Cap: High.
func massReuseTarget(n, total int) string {
	if n >= massReuseHighN || (n >= massReuseMinClusterForFrac && float64(n) >= massReuseHighFrac*float64(total)) {
		return "High"
	}
	if n >= massReuseMediumN || (n >= massReuseMinClusterForFrac && float64(n) >= massReuseMediumFrac*float64(total)) {
		return "Medium"
	}
	return ""
}

// levelRank maps a Level to a severity rank (higher = worse); mirrors triageKey.
func levelRank(level string) int {
	switch level {
	case "Critical":
		return 4
	case "High":
		return 3
	case "Medium":
		return 2
	case "Low":
		return 1
	default:
		return 0
	}
}

// moreSevereLevel returns whichever of cur/target is higher severity.
func moreSevereLevel(cur, target string) string {
	if levelRank(target) > levelRank(cur) {
		return target
	}
	return cur
}

// levelFloorScore is the display RiskScore floor for an escalated level (the tier minimum),
// so a Medium/High level doesn't show next to a near-zero RiskScore.
func levelFloorScore(level string) float64 {
	switch level {
	case "High":
		return 6.0
	case "Medium":
		return 4.0
	default:
		return 0
	}
}

// EscalateLargeCrackedReuse raises the Level of members of a large CRACKED reuse cluster
// (see massReuseTarget). It changes Level / RiskScore / vector / flag ONLY -- Impact stays
// honest (these accounts genuinely have low blast radius; the /MASS-REUSE tag + flag explain
// the override). Run AFTER EscalateSharedWithDA, BEFORE ComputePercentiles.
func EscalateLargeCrackedReuse(accts []Account) {
	total := len(accts)
	crackedN := map[string]int{}
	for i := range accts {
		if accts[i].Cracked {
			if k := reuseKey(accts[i].NTHash); k != "" {
				crackedN[k]++
			}
		}
	}
	for i := range accts {
		a := &accts[i]
		if !a.Cracked {
			continue
		}
		k := reuseKey(a.NTHash)
		if k == "" {
			continue
		}
		target := massReuseTarget(crackedN[k], total)
		if target == "" {
			continue
		}
		a.RiskLevel = moreSevereLevel(a.RiskLevel, target)
		if f := levelFloorScore(target); a.RiskScore < f {
			a.RiskScore = f
		}
		if !strings.Contains(a.RiskVector, "MASS-REUSE") {
			a.RiskVector += "/MASS-REUSE"
		}
		a.EscalatedByMassReuse = true
	}
}
```

- [ ] **Step 5: Run to verify PASS + gates**

Run: `go test ./internal/model/ -run 'TestMassReuseTarget|TestEscalateLargeCrackedReuse' -v` → PASS.
Run: `gofmt -l internal/model/model.go internal/model/model_test.go` → nothing.
Run: `go build ./... && go vet ./... && go test ./internal/model/` → green.

- [ ] **Step 6: Commit**

```bash
test "$(git branch --show-current)" = "feature/mass-reuse-escalation" || { echo "WRONG BRANCH"; exit 1; }
git add internal/model/model.go internal/model/model_test.go
git commit -m "feat(model): EscalateLargeCrackedReuse — large cracked clusters escalate Level (hybrid thresholds)"
```

---

## Task 2: Pipeline wiring + Summary count (`internal/store`)

**Files:**
- Modify: `internal/model/model.go` (`Summary` struct — add a count field near `EscalatedBySharedDA int` ~line 480)
- Modify: `internal/store/store.go` (3 pipeline sites ~lines 466/486/513; the Summary sum loop ~line 711)
- Test: `internal/store/store_test.go`

- [ ] **Step 1: Write the failing store test**

Add to `internal/store/store_test.go` (mirror the existing `TestSummary` setup for creating a store + audit — find it ~line 320 and reuse its `newStore`/`CreateAudit`/helper pattern; `fmt` is imported there):

```go
func TestMassReuseEscalationThroughPipeline(t *testing.T) {
	s, m := newStoreWithAudit(t) // use whatever helper the neighboring tests use to get a store + audit meta
	accts := make([]model.Account, 0, 100)
	for i := 0; i < 100; i++ { // 100 cracked share one hash -> High (absolute threshold)
		accts = append(accts, model.Account{Username: fmt.Sprintf("u%d", i), Domain: "D", NTHash: "SHARED", Cracked: true, RiskLevel: "Low"})
	}
	if err := s.Replace(m.ID, model.Dataset{Accounts: accts}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	sum, err := s.Summary(m.ID)
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if sum.EscalatedByMassReuse != 100 {
		t.Errorf("Summary.EscalatedByMassReuse=%d, want 100", sum.EscalatedByMassReuse)
	}
	got, err := s.Accounts(m.ID, false)
	if err != nil {
		t.Fatalf("Accounts: %v", err)
	}
	for _, a := range got {
		if a.RiskLevel != "High" || !a.EscalatedByMassReuse {
			t.Errorf("%s: level=%q flagged=%v, want High+flagged", a.Username, a.RiskLevel, a.EscalatedByMassReuse)
		}
	}
}
```
ADAPT the store/audit setup (`newStoreWithAudit`) to the real helper used by `TestSummary` and neighbors — read those tests first; do not invent an API.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/store/ -run TestMassReuseEscalationThroughPipeline -v`
Expected: FAIL — `sum.EscalatedByMassReuse` undefined (Summary field missing) and/or count 0 (pipeline not wired).

- [ ] **Step 3: Add the `Summary.EscalatedByMassReuse` count field**

In `internal/model/model.go`, in the `Summary` struct after `EscalatedBySharedDA int ...` (~line 480):

```go
	EscalatedByMassReuse int `json:"escalated_by_mass_reuse"` // escalated via a large cracked-reuse cluster
```

- [ ] **Step 4: Insert the pass into all 3 pipeline sites**

In `internal/store/store.go`, after EACH `model.EscalateSharedWithDA(...)` call (there are 3, at ~lines 466, 486, 513 — they operate on `merged`, `ds.Accounts`, and `next` respectively), add a matching line on the SAME slice:

```go
	model.EscalateLargeCrackedReuse(merged)     // (site 1)
```
```go
	model.EscalateLargeCrackedReuse(ds.Accounts) // (site 2)
```
```go
	model.EscalateLargeCrackedReuse(next)        // (site 3)
```
Each goes immediately BEFORE the `model.ComputePercentiles(...)` line at that site (so the level-first percentile sees the escalated levels). Match the variable name used at each site.

- [ ] **Step 5: Add the Summary count**

In `internal/store/store.go`, in the per-account Summary sum loop, after the `if acc.EscalatedBySharedDA { sum.EscalatedBySharedDA++ }` block (~line 711):

```go
		if acc.EscalatedByMassReuse {
			sum.EscalatedByMassReuse++
		}
```

- [ ] **Step 6: Run to verify PASS + gates**

Run: `go test ./internal/store/ -run TestMassReuseEscalationThroughPipeline -v` → PASS.
Run: `gofmt -l cmd internal` (empty) · `go build ./...` · `go vet ./...` · `go test ./...` → all green.

- [ ] **Step 7: Commit**

```bash
test "$(git branch --show-current)" = "feature/mass-reuse-escalation" || { echo "WRONG BRANCH"; exit 1; }
git add internal/model/model.go internal/store/store.go internal/store/store_test.go
git commit -m "feat(store): run EscalateLargeCrackedReuse in the pipeline + Summary count"
```

---

## Task 3: Sanitized export field (`internal/report`)

**Files:**
- Modify: `internal/report/sanitize.go` (`SanitizedAccount` struct ~line 68; the build loop ~line 204)
- Test: `internal/report/sanitize_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/report/sanitize_test.go`:

```go
func TestSanitizedCarriesMassReuse(t *testing.T) {
	now := time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC)
	rep := Sanitize([]model.Account{
		{Username: "a", Domain: "CORP", Cracked: true, EscalatedByMassReuse: true},
		{Username: "b", Domain: "CORP", Cracked: true},
	}, model.Summary{}, now, "v1")
	if !rep.Accounts[0].EscalatedByMassReuse {
		t.Errorf("acct a EscalatedByMassReuse = false, want true (carried)")
	}
	if rep.Accounts[1].EscalatedByMassReuse {
		t.Errorf("acct b EscalatedByMassReuse = true, want false")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/report/ -run TestSanitizedCarriesMassReuse -v`
Expected: FAIL — `SanitizedAccount has no field EscalatedByMassReuse`.

- [ ] **Step 3: Add the field + copy**

In `internal/report/sanitize.go`, in the `SanitizedAccount` struct after `EscalatedBySharedDA bool \`json:"escalated_by_shared_da,omitempty"\``:

```go
	EscalatedByMassReuse bool `json:"escalated_by_mass_reuse,omitempty"`
```

and in the build loop where it sets `EscalatedBySharedDA: a.EscalatedBySharedDA,`:

```go
			EscalatedByMassReuse: a.EscalatedByMassReuse,
```

- [ ] **Step 4: Run to verify PASS (incl. the canary leak test)**

Run: `go test ./internal/report/ -v` → all PASS (the new test + `TestSanitizedNoLeak`/`TestSanitizedNoForbiddenKeys` still green).
Run: `gofmt -l internal/report/` → nothing.

- [ ] **Step 5: Commit**

```bash
test "$(git branch --show-current)" = "feature/mass-reuse-escalation" || { echo "WRONG BRANCH"; exit 1; }
git add internal/report/sanitize.go internal/report/sanitize_test.go
git commit -m "feat(report): sanitized export carries escalated_by_mass_reuse"
```

---

## Task 4: Web — drawer row + api field

**Files:**
- Modify: `web/src/api.ts` (the `Account` interface — add near `escalated_by_shared_da?: boolean` ~line 139; the `Summary` interface near `escalated_by_shared_da: number` ~line 82)
- Modify: `web/src/components/AccountDrawer.tsx` (rows array ~line 75)

- [ ] **Step 1: Add the api fields**

In `web/src/api.ts`, in the `Account` interface after `escalated_by_shared_da?: boolean`:
```ts
  escalated_by_mass_reuse?: boolean
```
and in the `Summary` interface after `escalated_by_shared_da: number`:
```ts
  escalated_by_mass_reuse: number
```

- [ ] **Step 2: Add the drawer row**

In `web/src/components/AccountDrawer.tsx`, in the `rows` array immediately after the existing
`["Escalated (Shared-DA)", a.escalated_by_shared_da ? "Yes — shares hash with a DA account" : "—"],` line:
```tsx
    ["Escalated (Mass-reuse)", a.escalated_by_mass_reuse ? "Yes — one crack compromises this whole reuse cluster" : "—"],
```

- [ ] **Step 3: Verify the web gates**

Run (in `web/`): `npx tsc --noEmit` · `npx vitest run` · `npm run build`
Expected: tsc clean, all vitest pass (no test pins the drawer row set; update if one does), build succeeds.

- [ ] **Step 4: Commit**

```bash
test "$(git branch --show-current)" = "feature/mass-reuse-escalation" || { echo "WRONG BRANCH"; exit 1; }
git add web/src/api.ts web/src/components/AccountDrawer.tsx
git commit -m "feat(web): surface escalated_by_mass_reuse in the account drawer"
```

---

## Final verification (after all tasks)
- [ ] **Go gate:** `gofmt -l cmd internal` · `go build ./...` · `go vet ./...` · `go test ./...` · `govulncheck ./...`
- [ ] **Web gate (in `web/`):** `npx tsc --noEmit` · `npx vitest run` · `npm run build`
- [ ] **Live (build-and-run + restart):** Recalculate a real audit with a large cracked-reuse cluster; confirm the cluster's members now read **Medium/High** (was Low), carry `/MASS-REUSE` in the vector + the "Escalated (Mass-reuse)" drawer row, Impact still Low/Unknown; export a sanitized report and confirm `escalated_by_mass_reuse` is set on those rows and the Overview/Summary count reflects them. Console clean.

## Definition of done
Members of a large cracked-reuse cluster escalate to Medium/High (scale-aware thresholds, cap High), carry a `/MASS-REUSE` tag + `escalated_by_mass_reuse` flag (model, Summary count, sanitized export, drawer), with Impact left honest and `EscalateSharedWithDA` Criticals never downgraded; the 402×"Low" blind spot is fixed; the Exposure/Impact axes and existing escalation are unchanged.
