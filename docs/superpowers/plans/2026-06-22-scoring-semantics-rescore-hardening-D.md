# Scoring-Semantics & Rescore Hardening (sub-project D) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Three scoring-correctness fixes (expert-reviewed): multiplicative Impact-only domain risk (#11), level-first triage percentile (#6), and a rescore HIBP-floor guard (#4).

**Architecture:** All Go. #11 changes `impactScore` from additive to multiplicative domain factor (Impact only; Exposure untouched) + makes `DR:` decode-faithful. #6 changes `ComputePercentiles` to a level-first composite sort. #4 adds an "unknown ≠ zero" HIBP fallback on rescore. Exposure axis math is unchanged; Impact values and percentile ordering change → all affected goldens update, and existing audits adopt the new numbers on their next **Recalculate**.

**Tech Stack:** Go 1.26 stdlib (`internal/risk`, `internal/model`, `internal/engine`, `internal/secretsdump`).

**Spec:** `docs/superpowers/specs/2026-06-22-scoring-semantics-rescore-hardening-design.md` (expert-reviewed; refinements folded in at commit `0d1d41b`).

**Branch discipline (every task):** confirm `git branch --show-current` == `feature/scoring-semantics-D`; NEVER `git checkout`/`git switch`. Commit on that branch. No `--no-verify`. No web change (the Policies UI already labels domain risk multiplicatively).

---

## File Structure

- **Modify** `internal/risk/risk.go` — `domainFactor` (replaces `domainModifier`); multiplicative `impactScore`; pre-cap `Breakdown.DomainModifier`; `domainCode` → `U` when unenriched.
- **Modify** `internal/risk/risk_test.go` — `TestImpactDomainModifier` + vector goldens.
- **Modify** `internal/model/model.go` — `triageKey` + composite `ComputePercentiles`; vestigial-`RiskScore` comments.
- **Modify** `internal/model/model_test.go` — level-first percentile tests.
- **Modify** `internal/secretsdump/secretsdump.go` — `ParsedAccount.HIBPBreachCount`.
- **Modify** `internal/engine/engine.go` — `freshHIBP`; carry prior HIBP in `rescoreWith`; fallback in `scoreCracked`/`scoreUncracked`.
- **Modify** `internal/engine/engine_test.go` — rescore-preserves-HIBP test + any vector golden.

---

## Task 1: #11 — Multiplicative Impact-only domain factor

**Files:**
- Modify: `internal/risk/risk.go` (`domainModifier` →`domainFactor` at :371; `impactScore` at :393; `Breakdown.DomainModifier` at :131; `domainCode`/`Vector` for the DR: fix)
- Test: `internal/risk/risk_test.go` (`TestImpactDomainModifier` at :186; vector goldens)

- [ ] **Step 1: Update the failing tests first (TDD).** Read `TestImpactDomainModifier` (risk_test.go:186) and change its expectations from additive to multiplicative. Example invariants to encode:
  - An enriched account with `max(priv,da)=5` in a **Critical** domain → `Impact = min(10, 5*1.3) = 6.5` (was `5+1.0=6.0`).
  - `max(priv,da)=5`, **High** → `min(10, 5*1.2)=6.0`; **Medium** → `min(10,5*1.1)=5.5`; **Normal/other** → `5.0` (×1.0).
  - `max(priv,da)=10` in **Critical** → `min(10,10*1.3)=10` (saturates — unchanged; document).
  - An **unenriched** account (Coverage "none") → Impact still Unknown (no change).
  Also update the two `TestVectorV2` goldens: the second one uses `Coverage:"full"` + a Critical domain (`DR:C`) — recompute its `IMP:` tier under multiplicative scoring if it shifts. The first uses `Coverage:"none"` → its `DR:` token must now be **`DR:U`** (see Step 4). New first golden ends `…/CO:U/T0:N/S:0/RO:N/DR:U/HIBP:N/EXP:L/IMP:U` (DR:C→DR:U). Grep `internal` for every other hard-coded vector/impact golden and update.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/risk/ -run "TestImpactDomain|TestVectorV2" -v`
Expected: FAIL (additive values / `DR:C` on unenriched).

- [ ] **Step 3: Implement `domainFactor` + multiplicative impact.** Replace `domainModifier` (risk.go:371):

```go
// domainFactor scales Impact by the domain's environmental criticality. Multiplicative
// (matches the operator-facing "1.1x/1.2x/1.3x" labels); applied to Impact only so the
// Exposure axis stays credential-intrinsic.
func domainFactor(level string) float64 {
	switch level {
	case "Critical":
		return 1.3
	case "High":
		return 1.2
	case "Medium":
		return 1.1
	default:
		return 1.0
	}
}
```

In `impactScore` (risk.go:393) change:
```go
	imp := math.Min(10.0, math.Max(priv, da)*domainFactor(c.DomainRiskLevel))
```
(The disabled cap `if !c.Enabled { imp = math.Min(imp, 2.0) }` stays AFTER, unchanged.)

- [ ] **Step 4: Make `Breakdown.DomainModifier` the pre-cap contribution + fix `DR:`.**
  In `Score()` where `Breakdown.DomainModifier` is set (risk.go:131), replace
  `DomainModifier: domainModifier(c.DomainRiskLevel)` with the **pre-cap, monotone** contribution:
```go
			DomainModifier: math.Max(privilegeSubScore(c.ControlledObjects, c.ControlsTier0), daComponent(c.DADomains)) * (domainFactor(c.DomainRiskLevel) - 1.0),
```
  (Pre-cap `base*(factor-1)` is monotone in base and ≥0 — the expert review showed the post-cap
  delta is non-monotonic. Don't use the post-cap form.)

  Fix the `DR:` token to be decode-faithful. Change `domainCode` to take the Context (or add a
  coverage check) so it returns `"U"` when `c.Coverage == "none"`:
```go
func domainCode(c Context) string {
	if c.Coverage == "none" {
		return "U" // domain risk does nothing while Impact is Unknown -- don't assert a contribution
	}
	switch c.DomainRiskLevel {
	case "Critical":
		return "C"
	case "High":
		return "H"
	case "Medium":
		return "M"
	case "Low":
		return "L"
	default:
		return "U"
	}
}
```
  Update the `Vector()` call site from `"DR:" + domainCode(c.DomainRiskLevel)` to `"DR:" + domainCode(c)`.

- [ ] **Step 5: Run to verify pass**

Run: `go test ./internal/risk/ ./internal/engine/ ./internal/model/ -v`
Expected: PASS — all impact/vector goldens green; **Exposure-value goldens unchanged** (only Impact + DR: changed).

- [ ] **Step 6: Commit**

```bash
test "$(git branch --show-current)" = "feature/scoring-semantics-D"
git add internal/risk/risk.go internal/risk/risk_test.go internal/engine/engine_test.go
git commit -m "feat(risk): multiplicative Impact-only domain factor + decode-faithful DR: token (#11)"
```

---

## Task 2: #6 — Level-first triage percentile

**Files:**
- Modify: `internal/model/model.go` (`ComputePercentiles` at :362; add `triageKey`)
- Test: `internal/model/model_test.go`

- [ ] **Step 1: Write the failing tests** — level-monotone ordering + the two regression fixtures.

```go
// internal/model/model_test.go
func TestComputePercentilesLevelFirst(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	// near-DA High account: moderate Exposure, high Impact.
	high := Account{Username: "svc", RiskLevel: "High", ExposureScore: 5, ImpactScore: f(9), ImpactKnown: true}
	// cracked-disabled: high Exposure, low Impact (disabled cap) -> Low level.
	lowNoise := Account{Username: "dis", RiskLevel: "Low", ExposureScore: 9, ImpactScore: f(2), ImpactKnown: true}
	// escalated shared-DA, uncracked: low Exposure, forced Impact 10, Critical.
	esc := Account{Username: "esc", RiskLevel: "Critical", ExposureScore: 1, ImpactScore: f(10), ImpactKnown: true, EscalatedBySharedDA: true}
	accts := []Account{lowNoise, high, esc}
	ComputePercentiles(accts)
	p := map[string]float64{}
	for _, a := range accts {
		p[a.Username] = a.Percentile
	}
	// Level-first: Critical > High > Low, regardless of Exposure.
	if !(p["esc"] > p["svc"] && p["svc"] > p["dis"]) {
		t.Fatalf("level-first violated: esc=%v svc=%v dis=%v", p["esc"], p["svc"], p["dis"])
	}
	// The high-Exposure/low-Impact noise account must be LAST (lowest percentile).
	if p["dis"] != 0 {
		t.Fatalf("disabled-noise should rank lowest, got %v", p["dis"])
	}
	// The escalated uncracked account must rank highest despite Exposure 1.
	if p["esc"] != 1 {
		t.Fatalf("escalated Critical should rank highest, got %v", p["esc"])
	}
}
```
> Implementer: keep/adapt the EXISTING `TestComputePercentiles` (it pins ties/range on RiskScore today). After the change it must rank on the composite; update its fixtures to set RiskLevel + axes (not just RiskScore) and re-derive expected percentiles, OR replace it with the level-first test above if it's now redundant. Don't delete coverage — preserve the tie-share + [0,1] + n<=1 assertions against the new key.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/model/ -run "TestComputePercentiles" -v`
Expected: FAIL (current sort is RiskScore-only; `esc` with low Exposure won't rank top).

- [ ] **Step 3: Implement `triageKey` + composite sort.** Add near `ComputePercentiles`:

```go
// triageKey is the level-first sort key for the triage percentile: rank by Level
// severity first (Critical>High>Medium>Low), then an Impact-weighted scalar within a
// level. Guarantees the percentile never contradicts the Level badge.
func triageKey(a Account) (levelRank int, scalar float64) {
	switch a.RiskLevel {
	case "Critical":
		levelRank = 4
	case "High":
		levelRank = 3
	case "Medium":
		levelRank = 2
	case "Low":
		levelRank = 1
	default:
		levelRank = 0
	}
	if a.ImpactKnown && a.ImpactScore != nil {
		scalar = 0.4*a.ExposureScore + 0.6*(*a.ImpactScore) // blast-radius-weighted
	} else {
		scalar = a.ExposureScore // Impact Unknown -> Exposure is the only basis
	}
	return levelRank, scalar
}

// less reports whether account i sorts BEFORE j (less urgent) by the level-first key.
func triageLess(a, b Account) bool {
	la, sa := triageKey(a)
	lb, sb := triageKey(b)
	if la != lb {
		return la < lb
	}
	return sa < sb
}

func triageEqual(a, b Account) bool {
	la, sa := triageKey(a)
	lb, sb := triageKey(b)
	return la == lb && sa == sb
}
```

Rewrite `ComputePercentiles` to sort by the composite and share ranks on equal composite keys (keep the existing run-walk + `rank/(n-1)` + n<=1 handling):

```go
func ComputePercentiles(accts []Account) {
	n := len(accts)
	if n == 0 {
		return
	}
	if n == 1 {
		accts[0].Percentile = 0
		return
	}
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		return triageLess(accts[order[i]], accts[order[j]])
	})
	denom := float64(n - 1)
	for i := 0; i < n; {
		j := i
		for j < n && triageEqual(accts[order[j]], accts[order[i]]) {
			j++
		}
		p := float64(i) / denom // rank = #strictly-less in the composite order
		for k := i; k < j; k++ {
			accts[order[k]].Percentile = p
		}
		i = j
	}
}
```

Update the `ComputePercentiles` doc comment (it currently says "from its RiskScore"). Add a one-line comment at this function and at `EscalateSharedWithDA`'s `RiskScore >= 9.0` floor noting `RiskScore` is now display/back-compat only — the percentile drives triage.

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/model/ -v` → PASS (new + preserved percentile coverage)

- [ ] **Step 5: Commit**

```bash
test "$(git branch --show-current)" = "feature/scoring-semantics-D"
git add internal/model/model.go internal/model/model_test.go
git commit -m "feat(model): level-first triage percentile (never contradicts the Level badge) (#6)"
```

---

## Task 3: #4 — HIBP-floor guard on rescore (unknown ≠ zero)

**Files:**
- Modify: `internal/secretsdump/secretsdump.go` (`ParsedAccount` struct at :23)
- Modify: `internal/engine/engine.go` (`hibpCount` at :473 → `freshHIBP`; `rescoreWith` at :237; `scoreCracked` at :289; `scoreUncracked` at :402)
- Test: `internal/engine/engine_test.go`

- [ ] **Step 1: Write the failing test** — a rescore with the index unavailable preserves the stored breach count.

```go
// internal/engine/engine_test.go
func TestRescorePreservesHIBPWhenIndexUnavailable(t *testing.T) {
	eng := newTestEngine() // adjust to the real constructor; eng.HIBP must be nil here
	// A previously-scored breached account (HIBP index NOT loaded now).
	in := []model.Account{{
		Username: "bob", Domain: "CORP", NTHash: "ABCD", Password: "password1", Cracked: true,
		HIBPBreached: true, HIBPBreachCount: 5000, ExposureScore: 9,
	}}
	out := eng.RescoreWith(in, nil)
	if len(out) != 1 {
		t.Fatalf("want 1 account")
	}
	if out[0].HIBPBreachCount != 5000 {
		t.Fatalf("rescore zeroed the breach count when HIBP was unavailable: got %d", out[0].HIBPBreachCount)
	}
	if !out[0].HIBPBreached {
		t.Fatalf("HIBPBreached should remain true (floor preserved)")
	}
}
```
> Implementer: confirm `newTestEngine()`/the real constructor and that `eng.HIBP` is nil in this fixture (no index). If the existing engine test helper sets an index, build one without it.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/engine/ -run TestRescorePreservesHIBP -v`
Expected: FAIL — `HIBPBreachCount` is 0 (rescore re-derived from the absent index).

- [ ] **Step 3: Add the prior-count field + the `freshHIBP` split + the fallback.**

In `internal/secretsdump/secretsdump.go`, add to `ParsedAccount`:
```go
	HIBPBreachCount int // prior stored breach count; set only by the rescore reconstruction, used as a fallback when the HIBP index is unavailable
```

In `internal/engine/engine.go`, refactor `hibpCount` (engine.go:473) into:
```go
// freshHIBP returns a fresh breach count and ok=true when the index answered (incl. a
// genuine 0), or ok=false when no fresh count could be obtained (index unloaded or a
// lookup error) -- so callers can distinguish "unknown" from "known zero".
func (e *Engine) freshHIBP(ntlm string) (count int, ok bool) {
	e.hibpMu.RLock()
	h := e.HIBP
	e.hibpMu.RUnlock()
	if h == nil {
		return 0, false
	}
	if _, c, err := h.LookupHash(ntlm); err == nil {
		return c, true
	}
	return 0, false
}
```
(Keep a thin `hibpCount` wrapper if other callers use it: `func (e *Engine) hibpCount(n string) int { c, _ := e.freshHIBP(n); return c }`.)

In `rescoreWith` (engine.go:237), carry the prior count onto the reconstructed ParsedAccount:
```go
		pa := secretsdump.ParsedAccount{Username: a.Username, Domain: a.Domain, Hash: a.NTHash, Password: a.Password, Cracked: a.Password != "", HIBPBreachCount: a.HIBPBreachCount}
```

In `scoreCracked` (engine.go:289) and `scoreUncracked` (engine.go:402), replace `count := e.hibpCount(a.Hash)` with:
```go
	count, ok := e.freshHIBP(a.Hash)
	if !ok && a.HIBPBreachCount > 0 {
		count = a.HIBPBreachCount // preserve the stored breach floor when HIBP is unavailable
	}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/engine/ ./internal/secretsdump/ -v` → PASS

- [ ] **Step 5: Commit**

```bash
test "$(git branch --show-current)" = "feature/scoring-semantics-D"
git add internal/secretsdump/secretsdump.go internal/engine/engine.go internal/engine/engine_test.go
git commit -m "fix(engine): rescore preserves stored HIBP floor when the index is unavailable (#4)"
```

---

## Task 4: Whole-of-D verification

**Files:** none (verification only)

- [ ] **Step 1: Full backend gates.**

Run: `gofmt -l cmd internal` → empty
Run: `go build ./... && go vet ./... && go test ./...` → all PASS (Impact/vector/percentile goldens updated; **Exposure-value goldens unchanged**)
Run: `govulncheck ./...` → clean

- [ ] **Step 2: Frontend gates (no web change, confirm nothing regressed).**

Run: `cd web && npx tsc --noEmit && npx vitest run && npm run build` → clean
(The TS `ScoreBreakdown.domain_modifier` still a number; the drawer renders it unchanged.)

- [ ] **Step 3: Live verification (build-and-run, then Playwright at `http://127.0.0.1:8443`).** Open an audit, **Recalculate** (so existing accounts adopt the new numbers), then confirm:
  - a **BloodHound-enriched** account in a **Critical** domain (not already Impact-maxed) shows a higher Impact than under additive scoring, and its drawer "Domain" row shows a positive, monotone contribution; an Impact-maxed (DA/Tier-0) account's Impact is unchanged (saturation).
  - an **unenriched** account's risk vector shows `DR:U` (not `DR:C`).
  - the **triage percentile / worklist ordering** is level-consistent: no Low-level account ranks above a High one; an escalated shared-DA account sits at the top.
  - if HIBP is loaded, a rescore keeps breach counts; (optional) with the index unloaded, a rescore preserves a breached account's count rather than zeroing it.
  - assert the browser console has no 4xx/error noise.

- [ ] **Step 4: Report evidence** (gate output + before/after Impact for a Critical-domain account + the level-consistent percentile). No commit; proceed to the final whole-branch review, then finishing-a-development-branch.

---

## Self-Review notes (for the controller)

- **Spec coverage:** #11 (multiplicative + DomainModifier + DR:U) → Task 1; #6 (level-first percentile) → Task 2; #4 (HIBP fallback) → Task 3; verification → Task 4. All spec §3 items + the folded-in refinements (pre-cap DomainModifier, DR:U, escalation-ordering fixture, vestigial-RiskScore comment, sticky-per-hash) mapped.
- **Invariant — Exposure unchanged:** only Impact, the DR: token, and the percentile basis change. Any Exposure-value golden that changes is a BUG — investigate, don't just update it.
- **Type consistency:** `domainFactor` defined/used in Task 1; `triageKey`/`triageLess`/`triageEqual` defined/used in Task 2; `freshHIBP` + `ParsedAccount.HIBPBreachCount` defined in Task 3 and consumed by the rescore reconstruction + scoring fallback.
- **Placeholder honesty:** Task 1 Step 1 and Task 3 Step 1 flag "grep for every other hard-coded vector/impact golden" and "confirm the real engine test constructor / nil HIBP" as verify-against-real-code steps — the exact golden set and the test-engine constructor must be confirmed in-repo, not assumed.
