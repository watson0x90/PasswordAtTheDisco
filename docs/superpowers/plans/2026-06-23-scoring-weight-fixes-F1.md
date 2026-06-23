# Scoring Weight Fixes (sub-project F1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix four under-weighted/hidden Exposure-axis scoring signals the 2026-06-23 expert panel flagged — scale roastability (AS-REP > Kerberoast), scale password-reuse with a small-cluster bump *and* a large-cluster floor, score absolute credential age, and surface a "disabled — latent risk" badge — all from data already collected (no new ingestion).

**Architecture:** Route every Exposure bump through four pure helpers in `internal/risk/risk.go` (`roastableBump`, `reuseBump`, `reuseFloor`, `ageBump`) used by BOTH `exposureScore` and the `Breakdown` in `Score()`, eliminating today's duplicated inline computation. `reuseFloor` joins the `max(...)` floor terms (crack-status-independent, like HIBP prevalence); the others add as bumps under the `min(10, …)` clamp. A new `Context.PasswordAgeDays *int` (nil = unenriched/unknown) is computed in the engine from `PwdLastSet` and `now`. The disabled-latent-risk flag is frontend-only (a pure predicate + drawer badge), no score change. The Impact axis is untouched.

**Tech Stack:** Go 1.26 (stdlib only; `math`), table-driven `testing`; React 18 + TypeScript + Vite; Vitest (node-env, pure-logic — no jsdom).

**Spec:** `docs/superpowers/specs/2026-06-23-scoring-weight-fixes-F1-design.md`

---

## File Structure

- `internal/risk/risk.go` — add 4 helpers + `Context.PasswordAgeDays` + `Breakdown.AgePenalty`; rewrite `exposureScore`; consolidate `Score()` to use the helpers. (Tasks 1, 2)
- `internal/risk/risk_test.go` — helper unit tests + updated Exposure goldens. (Tasks 1, 2)
- `internal/engine/engine.go` — compute `ageDays`, set `PasswordAgeDays` in both `risk.Context` literals, copy `AgePenalty` into both `model.ScoreBreakdown` literals. (Task 3)
- `internal/engine/engine_test.go` — age-wiring test. (Task 3)
- `internal/model/model.go` — add `ScoreBreakdown.AgePenalty`. (Task 3)
- `web/src/api.ts` — add `age_penalty?: number` to the `ScoreBreakdown` interface. (Task 4)
- `web/src/components/AccountDrawer.tsx` — add an "Age" Exposure factor row; add the disabled-latent-risk badge row. (Tasks 4, 5)
- `web/src/disabledRisk.ts` (new) + `web/src/disabledRisk.test.ts` (new) — the `disabledLatentRisk` predicate + tests. (Task 5)

**Gates (run from repo root unless noted):** `gofmt -l cmd internal` (must be empty), `go build ./...`, `go vet ./...`, `go test ./...`, `govulncheck ./...`. Web (in `web/`, NEVER `npm install`): `npx tsc --noEmit`, `npx vitest run`, `npm run build`.

---

## Task 1: Pure Exposure helpers + `Context.PasswordAgeDays`

Add the four pure helpers and the new context field with NO call-site changes yet (so the helpers are unit-tested in isolation before `exposureScore`/`Score()` adopt them in Task 2). `Context.PasswordAgeDays` is added now because `ageBump` takes it; it stays nil at all existing call sites until Task 3 wires it.

**Files:**
- Modify: `internal/risk/risk.go` (add field at the `Context` struct ~line 44; add helpers after `crackedFloor` ~line 302)
- Test: `internal/risk/risk_test.go`

- [ ] **Step 1: Write the failing helper tests**

Add to `internal/risk/risk_test.go` (the file already has `almost(a, b float64) bool` — reuse it):

```go
func TestRoastableBump(t *testing.T) {
	cases := []struct {
		name string
		c    Context
		want float64
	}{
		{"neither", Context{}, 0},
		{"spn only", Context{HasSPN: true}, 0.5},
		{"asrep only", Context{DontReqPreauth: true}, 0.75},
		{"both", Context{HasSPN: true, DontReqPreauth: true}, 1.25},
	}
	for _, tc := range cases {
		if got := roastableBump(tc.c); !almost(got, tc.want) {
			t.Errorf("roastableBump(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestReuseBump(t *testing.T) {
	// boundaries: 0->0, 1->0.5, 2->0.75, 9->0.75, 10->1.0, 100->1.0 (ceiling 1.0; no higher bump tier)
	cases := []struct {
		shared int
		want   float64
	}{{0, 0}, {1, 0.5}, {2, 0.75}, {9, 0.75}, {10, 1.0}, {100, 1.0}, {5000, 1.0}}
	prev := -1.0
	for _, tc := range cases {
		got := reuseBump(tc.shared)
		if !almost(got, tc.want) {
			t.Errorf("reuseBump(%d) = %v, want %v", tc.shared, got, tc.want)
		}
		if got < prev {
			t.Errorf("reuseBump not monotone at %d: %v < %v", tc.shared, got, prev)
		}
		prev = got
	}
}

func TestReuseFloor(t *testing.T) {
	// floor is 0 below 100, 4.0 at 100-999, 5.0 at 1000+
	cases := []struct {
		shared int
		want   float64
	}{{0, 0}, {99, 0}, {100, 4.0}, {999, 4.0}, {1000, 5.0}, {50000, 5.0}}
	prev := -1.0
	for _, tc := range cases {
		got := reuseFloor(tc.shared)
		if !almost(got, tc.want) {
			t.Errorf("reuseFloor(%d) = %v, want %v", tc.shared, got, tc.want)
		}
		if got < prev {
			t.Errorf("reuseFloor not monotone at %d: %v < %v", tc.shared, got, prev)
		}
		prev = got
	}
}

func TestAgeBump(t *testing.T) {
	mk := func(d int) *int { return &d }
	cases := []struct {
		name string
		days *int
		want float64
	}{
		{"nil", nil, 0},
		{"364d", mk(364), 0},
		{"365d", mk(365), 0.25},
		{"729d", mk(729), 0.25},
		{"730d", mk(730), 0.5},
		{"1824d", mk(1824), 0.5},
		{"1825d", mk(1825), 0.75},
		{"6000d", mk(6000), 0.75},
	}
	for _, tc := range cases {
		if got := ageBump(tc.days); !almost(got, tc.want) {
			t.Errorf("ageBump(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/risk/ -run 'TestRoastableBump|TestReuseBump|TestReuseFloor|TestAgeBump' -v`
Expected: FAIL — compile error `undefined: roastableBump` / `reuseBump` / `reuseFloor` / `ageBump`.

- [ ] **Step 3: Add `PasswordAgeDays` to `Context`**

In `internal/risk/risk.go`, in the `Context` struct, after the `PasswordExpires string` line (~line 45):

```go
	PasswordExpires     string
	// PasswordAgeDays is the absolute age of the password in days since PwdLastSet
	// (nil = unenriched / unknown). Enriched-only; feeds ageBump only.
	PasswordAgeDays *int
```

- [ ] **Step 4: Add the four helpers**

In `internal/risk/risk.go`, immediately after `crackedFloor` (which ends ~line 302) and before `exposureScore`:

```go
// roastableBump: Kerberoast (SPN) +0.5; AS-REP roastable (DontReqPreauth) +0.75. AS-REP is a
// pre-auth exposure (no foothold needed) so it outweighs post-auth Kerberoast. Additive => both = 1.25.
func roastableBump(c Context) float64 {
	var b float64
	if c.HasSPN {
		b += 0.5
	}
	if c.DontReqPreauth {
		b += 0.75
	}
	return b
}

// reuseBump: a small-cluster Exposure bump. Large clusters use reuseFloor instead.
func reuseBump(sharedWith int) float64 {
	switch {
	case sharedWith >= 10:
		return 1.0
	case sharedWith >= 2:
		return 0.75
	case sharedWith >= 1:
		return 0.5
	default:
		return 0
	}
}

// reuseFloor: a huge reuse cluster is a standalone exposure fact (crack one hash -> own the
// cluster), independent of THIS account's crack status -- so it FLOORS Exposure like HIBP
// prevalence, ensuring a strong-but-massively-reused password isn't read as "Low".
func reuseFloor(sharedWith int) float64 {
	switch {
	case sharedWith >= 1000:
		return 5.0
	case sharedWith >= 100:
		return 4.0
	default:
		return 0
	}
}

// ageBump: an old password is materially more crackable; bounded, absolute age in days.
// ageDays nil (unenriched / PwdLastSet unknown) => 0.
func ageBump(ageDays *int) float64 {
	if ageDays == nil {
		return 0
	}
	switch d := *ageDays; {
	case d >= 1825:
		return 0.75 // 5y+
	case d >= 730:
		return 0.5 // 2-5y
	case d >= 365:
		return 0.25 // 1-2y
	default:
		return 0
	}
}
```

- [ ] **Step 5: Run the helper tests to verify they pass**

Run: `go test ./internal/risk/ -run 'TestRoastableBump|TestReuseBump|TestReuseFloor|TestAgeBump' -v`
Expected: PASS (4 tests). Also run `gofmt -l internal/risk/risk.go` → must print nothing.

- [ ] **Step 6: Confirm the rest of the package still builds (helpers unused-by-prod is fine — they're used by tests)**

Run: `go build ./internal/risk/ && go vet ./internal/risk/`
Expected: no output (success). (The helpers are referenced by the new tests, so Go won't flag them as unused.)

- [ ] **Step 7: Commit**

```bash
git add internal/risk/risk.go internal/risk/risk_test.go
git commit -m "feat(risk/F1): add roastable/reuse/reuseFloor/age Exposure helpers + Context.PasswordAgeDays"
```

---

## Task 2: Adopt the helpers in `exposureScore` + `Score()`; add `Breakdown.AgePenalty`

Rewrite `exposureScore` to use the helpers and add `reuseFloor` to the floor `max`. Consolidate `Score()` so the `Breakdown` reads the SAME helpers (delete the inline `reuse`/`roast` locals — today's duplicated source of truth) and add a new `AgePenalty` field.

**Files:**
- Modify: `internal/risk/risk.go` (`Breakdown` struct ~line 61; `Score()` ~lines 100-127; `exposureScore` ~lines 304-321)
- Test: `internal/risk/risk_test.go` (update two existing goldens; add a floor test)

- [ ] **Step 1: Update the existing Exposure goldens + add a floor test (these now fail)**

In `internal/risk/risk_test.go`, **replace** the `reuse` assertion inside `TestExposureBumps` (currently expects 3.5 for `SharedWith: 2`):

```go
	reuse := exposureScore(a, Context{Cracked: true, Coverage: "none", SharedWith: 2})
	if !almost(reuse, 3.75) { // crackedFloor 3.0 + reuseBump(2)=0.75
		t.Fatalf("reuse bump = %v, want 3.75", reuse)
	}
```

In the same file, **replace** the `c2` assertion inside `TestExposureUncracked` (currently expects 1.0):

```go
	// Uncracked + reuse(3)=0.75 + AS-REP roastable(0.75) bump still applies.
	c2 := Context{Cracked: false, Coverage: "full", SharedWith: 3, DontReqPreauth: true}
	if got := exposureScore(Analysis{}, c2); !almost(got, 1.5) {
		t.Fatalf("uncracked bumps-only exposure = %v, want 1.5", got)
	}
```

Add a new test for the floor (crack-status-independent), after `TestExposureUncracked`:

```go
func TestReuseFloorAppliesUncracked(t *testing.T) {
	// A strong, uncracked, zero-HIBP password in a 200-account reuse cluster must still
	// floor to >= Medium on the back of reuseFloor alone -- the panel's whole point.
	// Components: floor = max(0, reuseFloor(200)=4.0) = 4.0; bump = reuseBump(200)=1.0 (>=10 tier).
	// Exposure = min(10, 4.0 + 1.0) = 5.0.
	got := exposureScore(strong(), Context{Cracked: false, Coverage: "full", SharedWith: 200})
	if !almost(got, 5.0) {
		t.Fatalf("uncracked 200-cluster exposure = %v, want 5.0", got)
	}
}
```

- [ ] **Step 2: Run to verify the goldens fail**

Run: `go test ./internal/risk/ -run 'TestExposureBumps|TestExposureUncracked|TestReuseFloorAppliesUncracked' -v`
Expected: FAIL — `TestExposureBumps` reuse = 3.5 (want 3.75), `TestExposureUncracked` c2 = 1.0 (want 1.5), and `TestReuseFloorAppliesUncracked` is currently 3.0-ish (old code: no floor, no scaled bump) so it fails / or compile-references nothing new (it compiles; it just fails the assertion).

- [ ] **Step 3: Rewrite `exposureScore`**

In `internal/risk/risk.go`, replace the body of `exposureScore` (the current floor/bump block, ~lines 305-320) with:

```go
func exposureScore(a Analysis, c Context) float64 {
	var floor float64
	if c.Cracked {
		floor = math.Max(weaknessScore(a), math.Max(hibpExposureFloor(c.HIBPBreachCount), crackedFloor(a, true)))
	} else {
		// Uncracked: password unknown, no weakness signals.
		floor = hibpExposureFloor(c.HIBPBreachCount)
	}
	// Large-cluster reuse is a floor (crack-status-independent: crack one hash, own the cluster).
	floor = math.Max(floor, reuseFloor(c.SharedWith))
	bump := roastableBump(c) + reuseBump(c.SharedWith) + ageBump(c.PasswordAgeDays)
	// NOTE: bump is added pre-clamp; at a high floor the min(10,...) can absorb part of it, so the
	// per-factor breakdown values may sum to MORE than the displayed Exposure. That's the bounded-axis
	// clamp, not a drift bug -- the breakdown and the score read from the SAME helpers below.
	return math.Min(10.0, floor+bump)
}
```

- [ ] **Step 4: Add `AgePenalty` to the `Breakdown` struct**

In `internal/risk/risk.go`, in the `Breakdown` struct, after `RoastableBump float64 \`json:"roastable_bump"\`` (~line 61):

```go
	RoastableBump     float64 `json:"roastable_bump"`
	AgePenalty        float64 `json:"age_penalty"`
```

- [ ] **Step 5: Consolidate `Score()` to use the helpers**

In `internal/risk/risk.go` `Score()`, DELETE the inline locals (currently ~lines 100-106):

```go
	var reuse, roast float64
	if c.SharedWith > 0 {
		reuse = 0.5
	}
	if c.HasSPN || c.DontReqPreauth {
		roast = 0.5
	}
```

Then in the returned `Breakdown{...}` literal, change the `ReuseBump`/`RoastableBump` lines and add `AgePenalty` (the `round2` helper already exists in this file):

```go
			ReuseBump:         round2(reuseBump(c.SharedWith)),
			RoastableBump:     round2(roastableBump(c)),
			AgePenalty:        round2(ageBump(c.PasswordAgeDays)),
```

(Leave every other `Breakdown` field unchanged. `reuseFloor`'s contribution is reflected through `ExposureScore` itself — it is a floor, not a separate breakdown factor.)

- [ ] **Step 6: Run the risk tests to verify they pass**

Run: `go test ./internal/risk/ -v`
Expected: PASS (all, including the updated goldens and `TestReuseFloorAppliesUncracked`). Then `gofmt -l internal/risk/risk.go` → nothing.

- [ ] **Step 7: Commit**

```bash
git add internal/risk/risk.go internal/risk/risk_test.go
git commit -m "feat(risk/F1): reuseFloor + scaled bumps in exposureScore; consolidate Breakdown via helpers + AgePenalty"
```

---

## Task 3: Engine age wiring + `model.ScoreBreakdown.AgePenalty`

Compute absolute password age in days from `PwdLastSet`/`now`, set it on BOTH `risk.Context` literals, and copy `res.Breakdown.AgePenalty` into BOTH `model.ScoreBreakdown` literals. Add the `AgePenalty` field to the model struct.

**Files:**
- Modify: `internal/model/model.go` (`ScoreBreakdown` struct ~line 243)
- Modify: `internal/engine/engine.go` (new helper near `daysOutOfCompliance` ~line 506; `risk.Context` literals at ~line 296 and ~line 411; `ScoreBreakdown` literals at ~line 388 and ~line 471)
- Test: `internal/engine/engine_test.go`

- [ ] **Step 1: Add `AgePenalty` to `model.ScoreBreakdown`**

In `internal/model/model.go`, after `RoastableBump float64 \`json:"roastable_bump,omitempty"\`` (~line 243):

```go
	RoastableBump     float64 `json:"roastable_bump,omitempty"`
	AgePenalty        float64 `json:"age_penalty,omitempty"`
```

- [ ] **Step 2: Write the failing engine test**

Add this test to `internal/engine/engine_test.go`. It calls `scoreCracked` directly — the exact pattern existing tests use (see `TestScoreCrackedStoresMatchedWords` ~line 248: positional args are `domain, ParsedAccount, sharedWith, allPasswords, pwAccounts, analysisCache, simCache, peersCache, now, enricher`). The `now` is passed positionally as the 9th arg, and the enricher (10th arg) is a `fakeEnricher` (declared at line 29: `map[string]Enrichment`, keyed by normalized `username@DOMAIN`). The `bp(b bool) *bool` helper already exists (used at ~line 337). `model.Account.ExposureScore` is the asserted field (see `TestProcessDomainUncracked` line 138).

```go
func TestAgePenaltyWired(t *testing.T) {
	// Two enriched cracked accounts, identical except PwdLastSet: one ~3y old, one fresh.
	// The old one must carry AgePenalty 0.5 (730-1824d band) and Exposure >= the fresh one.
	eng := &Engine{
		Lists: pwanalysis.Lists{
			ForbiddenWords:   pwanalysis.NewSet(),
			KeyboardPatterns: pwanalysis.NewSet(),
			CommonPasswords:  pwanalysis.NewSet(),
			DictionaryWords:  pwanalysis.NewSet(),
		},
		Policies: policy.DefaultSet(),
	}
	now := time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC)
	oldSet := now.AddDate(-3, 0, 0).Unix()    // ~1095 days -> ageBump 0.5
	freshSet := now.AddDate(0, 0, -10).Unix() // 10 days -> ageBump 0

	score := func(pwdLastSet int64) model.Account {
		enr := fakeEnricher{"alice@CORP": Enrichment{Enriched: true, Enabled: bp(true), PwdLastSet: &pwdLastSet}}
		return eng.scoreCracked("CORP",
			secretsdump.ParsedAccount{Username: "alice", Hash: "ABC", Password: "Tr0ub4dour&3xpl0it!", Cracked: true},
			0, nil, nil, map[string]*pwanalysis.Analysis{}, map[string]float64{}, map[string][]model.SimilarPeer{}, now, enr)
	}

	oldAcct := score(oldSet)
	freshAcct := score(freshSet)

	if oldAcct.ScoreBreakdown == nil || freshAcct.ScoreBreakdown == nil {
		t.Fatal("expected score_breakdown on both accounts")
	}
	if got := oldAcct.ScoreBreakdown.AgePenalty; got != 0.5 {
		t.Errorf("old AgePenalty = %v, want 0.5", got)
	}
	if got := freshAcct.ScoreBreakdown.AgePenalty; got != 0 {
		t.Errorf("fresh AgePenalty = %v, want 0", got)
	}
	if oldAcct.ExposureScore < freshAcct.ExposureScore {
		t.Errorf("old exposure %v should be >= fresh %v", oldAcct.ExposureScore, freshAcct.ExposureScore)
	}
}
```

> IMPLEMENTER NOTE: confirm the `model.Account` exposure field name (`ExposureScore`) and the `Enrichment` field name (`PwdLastSet *int64`) against the current source if the build complains — both were verified at plan time (engine.go:35, engine_test.go:138). Do NOT invent a new ingestion path; this mirrors the existing `scoreCracked` call sites exactly.

- [ ] **Step 3: Run to verify it fails**

Run: `go test ./internal/engine/ -run TestAgePenaltyWired -v`
Expected: FAIL — `AgePenalty` not yet copied (0, want 0.5), because the engine doesn't set `PasswordAgeDays` or copy `AgePenalty` yet.

- [ ] **Step 4: Add the `passwordAgeDays` helper**

In `internal/engine/engine.go`, next to `daysOutOfCompliance` (~line 506), add:

```go
// passwordAgeDays returns the absolute age of the password in days since pwdLastSet
// (nil when pwdLastSet is nil/zero). Feeds risk.Context.PasswordAgeDays -> ageBump.
func passwordAgeDays(pwdLastSet *int64, now time.Time) *int {
	if pwdLastSet == nil || *pwdLastSet <= 0 {
		return nil
	}
	d := int(now.Sub(time.Unix(*pwdLastSet, 0).UTC()).Hours() / 24)
	if d < 0 {
		d = 0
	}
	return &d
}
```

- [ ] **Step 5: Set `PasswordAgeDays` on both `risk.Context` literals**

In `scoreCracked` (~line 296) AND `scoreUncracked` (~line 411), inside each `risk.Context{...}` literal, after the `PasswordExpires:` line add:

```go
			PasswordExpires:     passwordExpires(enrData.PwdNeverExpires),
			PasswordAgeDays:     passwordAgeDays(enrData.PwdLastSet, now),
```

(Both functions already have `enrData` and `now` in scope — confirmed: `scoreCracked` computes `daysOOC := daysOutOfCompliance(enrData.PwdLastSet, now, ...)` and `scoreUncracked` takes `now time.Time`.)

- [ ] **Step 6: Copy `AgePenalty` into both `model.ScoreBreakdown` literals**

In both `ScoreBreakdown{...}` literals (~line 388 in `scoreCracked`, ~line 471 in `scoreUncracked`), after `RoastableBump: res.Breakdown.RoastableBump,` add:

```go
			RoastableBump:     res.Breakdown.RoastableBump,
			AgePenalty:        res.Breakdown.AgePenalty,
```

- [ ] **Step 7: Run the engine test + full Go gates**

Run: `go test ./internal/engine/ -run TestAgePenaltyWired -v`
Expected: PASS.
Then: `gofmt -l cmd internal` (empty), `go build ./...`, `go vet ./...`, `go test ./...`
Expected: all pass (no other package asserts on the old reuse=0.5/roast=0.5 numbers; if any engine/store golden does, update it to the new helper values — search with `grep -rn "reuse_bump\|roastable_bump\|RoastableBump\|ReuseBump" internal/` and reconcile).

- [ ] **Step 8: Commit**

```bash
git add internal/model/model.go internal/engine/engine.go internal/engine/engine_test.go
git commit -m "feat(engine/F1): wire absolute password age -> ageBump; copy AgePenalty into ScoreBreakdown"
```

---

## Task 4: Frontend — `age_penalty` type + drawer "Age" Exposure row

Surface the new `AgePenalty` factor in the AccountDrawer's Exposure card (alongside the existing Reuse/Roastable rows, which now show the scaled values automatically since they read the same JSON keys).

**Files:**
- Modify: `web/src/api.ts` (`ScoreBreakdown` interface ~line 164)
- Modify: `web/src/components/AccountDrawer.tsx` (Exposure factor list ~line 124)

- [ ] **Step 1: Add `age_penalty` to the `ScoreBreakdown` interface**

In `web/src/api.ts`, after `roastable_bump?: number` (~line 164):

```ts
  roastable_bump?: number
  age_penalty?: number
```

- [ ] **Step 2: Add the "Age" factor row to the Exposure card**

In `web/src/components/AccountDrawer.tsx`, in the Exposure `BreakdownCard` `factors={[...]}` array, after `["Roastable", v("roastable_bump")],` (~line 124):

```tsx
                    ["Reuse", v("reuse_bump")],
                    ["Roastable", v("roastable_bump")],
                    ["Age", v("age_penalty")],
```

(The `v()` safe-accessor already coalesces a missing key → 0, so unenriched accounts simply show `Age 0` — correct, since `ageBump(nil)=0`.)

- [ ] **Step 3: Verify the web gates pass**

Run (in `web/`): `npx tsc --noEmit && npx vitest run && npm run build`
Expected: tsc clean, all vitest pass (no test asserts the exact Exposure factor row count; if `drawerFactors.test.ts` or a snapshot does, update it to include the Age row), build succeeds.

- [ ] **Step 4: Commit**

```bash
git add web/src/api.ts web/src/components/AccountDrawer.tsx
git commit -m "feat(web/F1): surface age_penalty as an Age row in the Exposure breakdown"
```

---

## Task 5: Frontend — `disabledLatentRisk` predicate + drawer badge

A pure predicate (no backend, derived from existing redacted `Account` fields) + a drawer badge so a disabled-but-dangerous account capped at Impact 2.0 isn't read as harmless. NO score change.

**Files:**
- Create: `web/src/disabledRisk.ts`
- Create: `web/src/disabledRisk.test.ts`
- Modify: `web/src/components/AccountDrawer.tsx` (rows array, after the "Enabled" row ~line 77)

- [ ] **Step 1: Write the failing predicate test**

Create `web/src/disabledRisk.test.ts`:

```ts
import { describe, it, expect } from "vitest"
import { disabledLatentRisk } from "./disabledRisk"
import type { Account } from "./api"

// Minimal Account factory: only the fields the predicate reads matter; cast the rest.
function acct(p: Partial<Account>): Account {
  return {
    enabled: true,
    controls_tier0: false,
    da_domains: "None",
    controlled_object_count: 0,
    shared_with: 0,
    ...p,
  } as Account
}

describe("disabledLatentRisk", () => {
  it("false when the account is enabled, regardless of risk signals", () => {
    expect(disabledLatentRisk(acct({ enabled: true, controls_tier0: true }))).toBe(false)
  })
  it("false when disabled but no risk signals", () => {
    expect(disabledLatentRisk(acct({ enabled: false }))).toBe(false)
  })
  it("true when disabled + controls Tier-0", () => {
    expect(disabledLatentRisk(acct({ enabled: false, controls_tier0: true }))).toBe(true)
  })
  it("true when disabled + DA pathway", () => {
    expect(disabledLatentRisk(acct({ enabled: false, da_domains: "CORP.LOCAL" }))).toBe(true)
  })
  it("true when disabled + controlled objects", () => {
    expect(disabledLatentRisk(acct({ enabled: false, controlled_object_count: 3 }))).toBe(true)
  })
  it("true when disabled + reused hash (shared_with >= 2)", () => {
    expect(disabledLatentRisk(acct({ enabled: false, shared_with: 2 }))).toBe(true)
  })
  it("false when disabled + shared_with == 1 (below the raised threshold)", () => {
    expect(disabledLatentRisk(acct({ enabled: false, shared_with: 1 }))).toBe(false)
  })
  it("nil-safe: undefined da_domains does not trip the predicate", () => {
    expect(disabledLatentRisk(acct({ enabled: false, da_domains: undefined as unknown as string }))).toBe(false)
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run (in `web/`): `npx vitest run disabledRisk`
Expected: FAIL — cannot resolve `./disabledRisk`.

- [ ] **Step 3: Implement the predicate**

Create `web/src/disabledRisk.ts`:

```ts
import type { Account } from "./api"
import { hasDA } from "./util"

// disabledLatentRisk reports whether a DISABLED account is still dangerous — it controls a
// Tier-0 asset, has a DA pathway, controls objects, or its hash is reused (>=2 accounts). The
// Impact axis is capped at 2.0 for disabled accounts (they can't authenticate), which can lull
// an operator into ignoring a re-enable / Pass-the-Hash persistence path; this flag surfaces it.
// The >=2 reuse threshold (raised from >0 by the 2026-06-23 panel) cuts badge noise. `?? ""`
// keeps hasDA nil-safe for hand-built objects (the API always sends a da_domains string).
export function disabledLatentRisk(a: Account): boolean {
  return (
    !a.enabled &&
    (a.controls_tier0 === true ||
      hasDA(a.da_domains ?? "") ||
      a.controlled_object_count > 0 ||
      a.shared_with >= 2)
  )
}
```

- [ ] **Step 4: Run to verify it passes**

Run (in `web/`): `npx vitest run disabledRisk`
Expected: PASS (8 assertions).

- [ ] **Step 5: Add the badge row to the drawer**

In `web/src/components/AccountDrawer.tsx`, add the import near the existing `hasDA` import:

```tsx
import { disabledLatentRisk } from "../disabledRisk"
```

Then in the `rows` array, replace the existing `["Enabled", a.enabled ? "Yes" : "No"],` line (~line 77) with that line followed by a conditional badge row:

```tsx
    ["Enabled", a.enabled ? "Yes" : "No"],
    ...(disabledLatentRisk(a)
      ? ([["Latent risk", "Disabled ⚠ — re-enable / Pass-the-Hash persistence path"]] as [string, ReactNode][])
      : []),
```

(This mirrors the existing conditional-row idiom already used for "Controls Tier-0" / "Contains Unicode" at lines 65/70 — same `as [string, ReactNode][]` cast, className-only styling, no new CSS.)

- [ ] **Step 6: Verify the web gates pass**

Run (in `web/`): `npx tsc --noEmit && npx vitest run && npm run build`
Expected: tsc clean, all vitest pass, build succeeds.

- [ ] **Step 7: Commit**

```bash
git add web/src/disabledRisk.ts web/src/disabledRisk.test.ts web/src/components/AccountDrawer.tsx
git commit -m "feat(web/F1): disabledLatentRisk predicate + drawer 'Latent risk' badge"
```

---

## Final verification (after all tasks)

- [ ] **Full Go gate:** `gofmt -l cmd internal` (empty) · `go build ./...` · `go vet ./...` · `go test ./...` · `govulncheck ./...`
- [ ] **Full web gate (in `web/`):** `npx tsc --noEmit` · `npx vitest run` · `npm run build`
- [ ] **Live smoke (build-and-run skill, restart the long-lived `patd.exe`):** Recalculate an audit; in an account drawer confirm the Exposure card shows Reuse/Roastable/**Age** rows with the scaled values, a widely-reused (≥100) account's Exposure is ≥ Medium even uncracked, an AS-REP-roastable account scores above an SPN-only one, and a disabled-but-privileged account shows the **"Latent risk"** badge. Browser console clean (no 4xx/errors).

---

## Definition of done (F1)

Roastability scales (AS-REP > Kerberoast), password-reuse scales with cluster size (small-cluster bump + large-cluster floor so a massively-reused strong password can't read as "Low"), an old password adds a bounded credential-intrinsic Exposure bump, and a disabled-but-dangerous account is flagged so the Impact-2.0 cap can't lull an operator. Exposure stays bounded [0,10]/monotone; Impact axis unchanged; all goldens green; existing audits adopt the new Exposure on their next Recalculate. F2 (delegation + LM-hash, new ingestion) is the next sub-project.
