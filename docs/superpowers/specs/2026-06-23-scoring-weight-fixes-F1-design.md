# Scoring Weight Fixes (sub-project F1) — Design

> **F1 of sub-project F** (scoring model coverage). F splits by data-feasibility: **F1** = scoring-weight
> fixes that use data we ALREADY collect (no new ingestion); **F2** (next) = delegation + LM-hash
> coverage (new BloodHound/parser ingestion). Seed backlog:
> `docs/superpowers/specs/2026-06-22-scoring-model-coverage-backlog.md`. Directions here were
> recommended by the 2026-06-22 expert security/math panel.

**Goal:** Fix three under-weighted/hidden scoring signals the panel flagged, using existing data: scale
roastability + password-reuse (#2), surface the disabled-cap lull (#3), and score credential age (#4).

**Like D, this shifts Exposure scores** — existing audits adopt the new numbers on their next
**Recalculate**. Exposure stays credential-intrinsic (these are all "how easily is this credential
compromised" signals); the Impact axis is unchanged.

---

## 1. Decisions locked during brainstorming (incl. the 2026-06-23 expert-panel adjustments)

- **#2 Roastable:** replace the flat `+0.5 if (SPN || AS-REP)` with **SPN +0.5 and AS-REP +0.75,
  additive** (both → +1.25). *(Panel: AS-REP roasting is a pre-auth exposure — no foothold needed —
  so it outweighs Kerberoast, a post-auth escalation.)*
- **#2b Roastable FLOOR (added 2026-06-22 post-build security panel):** AS-REP roastability is not
  only worse than Kerberoast, it is **crack-status-independent and foothold-independent** — an
  anonymous attacker pulls the AS-REP hash and cracks it offline — exactly the rationale that earned
  reuse a floor. So **AS-REP (`DontReqPreauth`) also raises an Exposure FLOOR of 3.0** (`roastableFloor`),
  joining the `max(...)` floor terms; **SPN earns no floor** (Kerberoast needs a domain foothold, so it
  stays a bump). The AS-REP +0.75 bump is **retained on top** (stacks like reuse's floor+bump), keeping
  "Roastable" visible in the breakdown. Net for a strong, uncracked AS-REP account: floor 3.0 + bump
  0.75 = **3.75** (the low/Medium border, vs 0.75 ≈ bottom-of-Low before). *(Panel SHIP; this is the one
  place F1's weighting was internally inconsistent with its own floor philosophy.)*
- **#2 Reuse:** a **small-cluster bump** (1→+0.5, 2–9→+0.75, **10+→+1.0**) PLUS a **large-cluster
  Exposure FLOOR** (independent of crack status, like HIBP prevalence): **SharedWith ≥100 → floor 4.0
  (Medium), ≥1000 → floor 5.0**. *(Panel: a bump can't lift a zero-floor account out of "Low", so a
  huge strong-password spray cluster — crack one, own 100 — would be mis-triaged; a floor fixes it.)*
- **#3 Disabled-cap lull:** **flag only** — keep the `Impact ≤ 2.0` cap (correct for live auth), but
  surface a "disabled — latent risk" badge when a disabled account has Tier-0 control, a DA path, a
  controlled object, or a **reused hash (SharedWith ≥ 2)**, so the operator isn't lulled. **No score
  change.** *(Panel: the `shared_with>0` arm was raised to ≥2 to cut badge noise. A genuinely-missed
  case — a disabled, cracked, privileged-**by-group-membership** account with 0 controlled objects —
  needs a group-membership-privilege signal we don't collect today; that's an **F2** gap, noted.)*
- **#4 Credential age:** a bounded **absolute-age** Exposure bump (enriched-only, where `PwdLastSet`
  is known): <1yr +0, 1–2yr +0.25, 2–5yr +0.5, 5yr+ +0.75. *(Panel: SOUND, keep — including the
  deliberate stack with roastable, which correctly elevates a never-rotated RC4 service account.)*

---

## 2. Scope

**In scope (F1):** the three scoring/surfacing changes above + updated goldens. Exposure-axis only;
**Impact axis unchanged**; no new data ingestion (all from existing `HasSPN`/`DontReqPreauth`/
`SharedWith`/`PwdLastSet`/`Enabled`/`da_domains`/`controlled_object_count`/`controls_tier0`).

**Out of scope:** delegation + LM-hash (F2, needs new ingestion); any Impact-axis change; a vector
token for age (the breakdown + drawer carry it; the vector stays as-is for F1).

**Noted:** the engine currently computes the reuse/roastable bumps in TWO places (`exposureScore`
inline AND `Score()` for the `Breakdown`). F1 fixes that by routing both through shared helpers
(one source of truth) — the kind of recompute the 2026-06-22 tech-debt audit flagged.

---

## 3. Architecture

### 3.1 Shared Exposure-bump helpers (`internal/risk/risk.go`)
Add four pure helpers, used by BOTH `exposureScore` and the `Breakdown` in `Score()`:
```go
// roastableBump: Kerberoast (SPN) +0.5; AS-REP roastable (no pre-auth) +0.75 -- AS-REP is a
// pre-auth exposure (no foothold needed) so it outweighs Kerberoast. Additive => both = +1.25.
func roastableBump(c Context) float64 {
	var b float64
	if c.HasSPN { b += 0.5 }
	if c.DontReqPreauth { b += 0.75 }
	return b
}

// reuseBump: a small-cluster Exposure bump. Large clusters use reuseFloor instead (below).
func reuseBump(sharedWith int) float64 {
	switch {
	case sharedWith >= 10: return 1.0
	case sharedWith >= 2:  return 0.75
	case sharedWith >= 1:  return 0.5
	default:               return 0
	}
}

// reuseFloor: a huge reuse cluster is a standalone exposure fact (crack one hash -> own the
// cluster), independent of this account's crack status -- so it FLOORS Exposure like HIBP
// prevalence, ensuring a strong-but-massively-reused password isn't read as "Low".
func reuseFloor(sharedWith int) float64 {
	switch {
	case sharedWith >= 1000: return 5.0
	case sharedWith >= 100:  return 4.0
	default:                 return 0
	}
}

// ageBump: an old password is materially more crackable; bounded, absolute age in days.
// ageDays nil (unenriched / PwdLastSet unknown) => 0.
func ageBump(ageDays *int) float64 {
	if ageDays == nil { return 0 }
	switch d := *ageDays; {
	case d >= 1825: return 0.75 // 5y+
	case d >= 730:  return 0.5  // 2-5y
	case d >= 365:  return 0.25 // 1-2y
	default:        return 0
	}
}
```
`exposureScore` (risk.go:305-321) becomes — `reuseFloor` joins the `max(...)` floor terms, the
small bumps add on top:
```go
	var floor float64
	if c.Cracked {
		floor = math.Max(weaknessScore(a), math.Max(hibpExposureFloor(c.HIBPBreachCount), crackedFloor(a, true)))
	} else {
		floor = hibpExposureFloor(c.HIBPBreachCount)
	}
	floor = math.Max(floor, reuseFloor(c.SharedWith)) // large-cluster reuse is a floor, crack-status-independent
	bump := roastableBump(c) + reuseBump(c.SharedWith) + ageBump(c.PasswordAgeDays)
	// NOTE: bump is added pre-clamp; at a high floor the min(10,...) can absorb part of it, so the
	// per-factor breakdown values may sum to MORE than the displayed Exposure. That's the bounded-axis
	// clamp, not a drift bug -- the breakdown and the score read from the SAME helpers.
	return math.Min(10.0, floor+bump)
```
`Score()`'s `Breakdown` fields use the same helpers: `ReuseBump: reuseBump(c.SharedWith)`,
`RoastableBump: roastableBump(c)`, and a new `AgePenalty: ageBump(c.PasswordAgeDays)`. (Remove the
old inline `reuse`/`roast` locals so there is one source of truth.) The `reuseFloor` contribution is
reflected via the overall Exposure (it joins the floor `max`, not a separate breakdown factor).

### 3.2 `Context.PasswordAgeDays` + engine wiring
Add `PasswordAgeDays *int` to `risk.Context` (absolute days since `PwdLastSet`; nil = unknown). In
`internal/engine/engine.go`, where `scoreCracked`/`scoreUncracked` build the `risk.Context`, compute
it from the enrichment's `PwdLastSet` and `now`:
```go
var ageDays *int
if enrData.PwdLastSet != nil && *enrData.PwdLastSet > 0 {
	d := int(now.Sub(time.Unix(*enrData.PwdLastSet, 0)).Hours() / 24)
	if d < 0 { d = 0 }
	ageDays = &d
}
// ... PasswordAgeDays: ageDays in the risk.Context literal
```
(Enriched-only by construction: unenriched accounts have `PwdLastSet == nil` → `ageDays == nil` →
`ageBump` returns 0, so Exposure is unaffected for them.)

### 3.3 `AgePenalty` in the breakdown (Go + TS)
- `internal/risk/risk.go` `Breakdown`: add `AgePenalty float64 \`json:"age_penalty"\``.
- `internal/model/model.go` `ScoreBreakdown`: add `AgePenalty float64 \`json:"age_penalty,omitempty"\``;
  `internal/engine/engine.go` copies `res.Breakdown.AgePenalty` into the account's `ScoreBreakdown`
  (both score paths).
- `web/src/api.ts` `ScoreBreakdown`: add `age_penalty?: number`.
- `web/src/components/AccountDrawer.tsx`: the Exposure card's factor list gains an **"Age"** row (it
  already renders Reuse/Roastable; add Age alongside, reading `age_penalty`). The Reuse/Roastable rows
  now show the new scaled values automatically.

### 3.4 Disabled latent-risk flag (#3 — frontend only, no score change)
A pure predicate + a drawer badge (no backend, derivable from existing redacted `Account` fields):
- `web/src/coverage.ts` (or a small `web/src/disabledRisk.ts`) — `disabledLatentRisk(a: Account): boolean`
  = `!a.enabled && (a.controls_tier0 === true || hasDA(a.da_domains ?? "") || a.controlled_object_count > 0 || a.shared_with >= 2)`.
  (The `shared_with >= 2` threshold — raised from `> 0` per the panel — cuts badge noise; the
  `?? ""` keeps `hasDA` nil-safe for hand-built objects even though the API always sends a string.
  **Known F2 gap:** a disabled+cracked account privileged only *by group membership* — `controlled==0`,
  not Tier-0, no DA path — won't trip this predicate; surfacing it needs a group-membership-privilege
  signal we don't collect until F2.)
- `web/src/components/AccountDrawer.tsx`: when `disabledLatentRisk(a)`, show a badge/row near the
  "Enabled" field — e.g. **"Disabled — latent risk (re-enable / Pass-the-Hash persistence)"** — so a
  disabled-but-dangerous account capped at Impact 2.0 isn't read as harmless. Reuse existing badge
  classes; className only.
- (The flag changes NO score — the 2.0 cap stays. It is a surfacing-only safety net.)

---

## 4. Files
- **Go:** `internal/risk/risk.go` (helpers + `exposureScore` + `Breakdown.AgePenalty` + `Context.PasswordAgeDays`);
  `internal/engine/engine.go` (compute `ageDays`, copy `AgePenalty`); `internal/model/model.go`
  (`ScoreBreakdown.AgePenalty`). Tests: `internal/risk/risk_test.go` (bump goldens + monotonicity),
  `internal/engine/engine_test.go` (age wiring).
- **Web:** `web/src/api.ts` (`age_penalty?`); `web/src/disabledRisk.ts` + test (the predicate);
  `web/src/components/AccountDrawer.tsx` (Age breakdown row + disabled-latent-risk badge).

No Impact-axis change, no new endpoints, no new ingestion.

## 5. Testing
- **#2/#4 (Go):** `reuseBump` tiers (0/0.5/0.75/1.0 at the boundaries 0/1/2/10 — note the ceiling is now
  1.0; there is no 100+ bump tier, large clusters use the floor instead); `reuseFloor` (0 below 100,
  4.0 at 100, 5.0 at 1000); `roastableBump` (SPN-only 0.5, AS-REP-only 0.75, both 1.25, neither 0);
  `ageBump` tiers at 364/365/730/1825 days + nil→0; each is **monotone non-decreasing** in its input.
  `exposureScore` is still bounded [0,10] and the bumps+floor compose under the clamp. **Floor-vs-crack
  independence:** an UNCRACKED account with `SharedWith ≥ 100` gets Exposure ≥ 4.0 (≥ Medium) even with
  a strong password / zero HIBP — the new floor's whole point. Update the affected Exposure/vector
  goldens. An **unenriched** account's Exposure is unchanged for the age axis (ageBump 0 via nil);
  reuse/roastable still apply as before.
- **#3 (web):** `disabledLatentRisk` — true for a disabled account with Tier-0 / DA-path / controlled>0 /
  **shared_with ≥ 2**; false for an enabled account, a disabled account with none of those, and a
  disabled account with **shared_with == 1** (below the raised threshold). Verify `da_domains`
  absent/`undefined` does NOT trip the predicate (nil-safe `?? ""`).
- **Gates:** `gofmt`, `go build/vet/test`, `govulncheck`; `tsc`/`vitest`/`build`. Live: Recalculate an
  audit, confirm a widely-reused or roastable or old-password account's Exposure rose, the drawer shows
  the Age/Reuse/Roastable rows, and a disabled-but-privileged account shows the latent-risk badge;
  console clean.

## 6. Definition of done (F1)
Roastability scales (AS-REP > Kerberoast) and password-reuse scales with cluster size — a small-cluster
bump plus a large-cluster Exposure **floor** so a massively-reused strong password can't read as "Low";
an old password adds a bounded, credential-intrinsic Exposure bump; and a disabled-but-dangerous account
is flagged so the Impact-2.0 cap can't lull an operator. Exposure stays bounded/monotone; Impact unchanged; all goldens
green; existing audits adopt the new Exposure on their next Recalculate. F2 (delegation + LM-hash) is next.
