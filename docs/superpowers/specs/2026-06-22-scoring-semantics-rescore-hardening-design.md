# Scoring-Semantics & Rescore Hardening (sub-project D) — Design

> **Sub-project D** of the "scoring & dashboard completeness" effort (C→D→E→B).
> C is merged; D **changes the numbers**, so existing audits need a **Recalculate** (sub-project
> A) to pick up the new scores. From the 2026-06-22 completeness sweep (Tier-1 #4, Tier-2 #6, #11).

**Goal:** Fix three scoring-correctness issues: a rescore can silently drop the HIBP Exposure
floor (#4); the triage percentile rides the de-emphasized legacy `RiskScore` (#6); and domain
risk is applied additively despite the UI promising a multiplier (#11).

---

## 1. Decisions locked during brainstorming

- **#4 HIBP guard:** on rescore, when a fresh breach count can't be obtained (index unloaded OR a
  lookup error), **fall back to the account's stored `HIBPBreachCount`** instead of zeroing it.
  When the index IS available, refresh as today. Initial upload (no prior) is unchanged.
- **#6 percentile basis:** rank the triage percentile **by level first** (Critical>High>Medium>Low),
  then by a two-axis scalar within each level — so the percentile can never contradict the level
  badge, and within a tier it's blast-radius-weighted.
- **#11 domain risk:** make it **multiplicative on Impact only** (×1.1/1.2/1.3; Normal/Low ×1.0).
  Exposure stays credential-intrinsic (untouched). Unenriched/Impact-Unknown accounts get no
  domain effect (their blast radius is Unknown anyway — `DR:` is "pending enrichment", not a bug).
  Bonus: the Policies UI already labels domain risk "1.1×/1.2×/1.3×", so the code now matches it —
  **no UI relabel needed.**

---

## 2. Scope

**In scope (D):** the three scoring changes above + updated goldens. NO other scoring factor
changes. NO UI behavior change (the domain-risk dropdown labels were already multiplicative).

**Out of scope:** dashboard-consistency drift (E — including the PostureScore threshold unification
and the TS per-domain posture, which will shift once D changes levels); the coverage tab (B).

**Cross-cutting note (for sequencing):** #11 (and to a lesser extent #4/#6) shifts Impact, levels,
and therefore `PostureScore` and the dashboards on existing audits after Recalculate. That's
intended. E runs after D so its posture-consistency work sees the new numbers. The CHANGELOG for
the eventual tag should note "scoring refined — Recalculate existing audits to apply."

---

## 3. Architecture (item by item)

### #11 — Multiplicative Impact-only domain factor
`internal/risk/risk.go`:
- Replace `domainModifier(level string) float64` (additive +1.0/0.6/0.3/0) with
  `domainFactor(level string) float64` → `Critical:1.3, High:1.2, Medium:1.1, default:1.0`.
- In `impactScore` (risk.go:393), change
  `imp := math.Min(10.0, math.Max(priv, da)+domainModifier(...))` to
  `imp := math.Min(10.0, math.Max(priv, da)*domainFactor(c.DomainRiskLevel))`.
  The disabled cap (`if !c.Enabled { imp = min(imp, 2.0) }`) stays AFTER, unchanged.
- `Breakdown.DomainModifier` (risk.go:131) becomes the **additive-equivalent contribution** so the
  drawer's "Domain" factor row keeps showing a positive number:
  `domainContribution := math.Min(10, math.Max(priv,da)*domainFactor) - math.Min(10, math.Max(priv,da))`
  (i.e. how much the domain factor added, post-cap). Store that in `Breakdown.DomainModifier`.
- The `DR:` vector token (`domainCode`, uses the level string) is unchanged in format.
- Because Impact is Unknown when `Coverage=="none"` (impactScore returns early), unenriched
  accounts are unaffected — exactly the intended semantics.

### #6 — Level-first triage percentile
`internal/model/model.go`, `ComputePercentiles`:
- Add a helper `triageKey(a Account) (levelRank int, scalar float64)`:
  - `levelRank`: `Critical:4, High:3, Medium:2, Low:1, default:0` (higher = worse).
  - `scalar`: if `a.ImpactKnown && a.ImpactScore != nil` → `0.4*a.ExposureScore + 0.6*(*a.ImpactScore)`;
    else → `a.ExposureScore`. (Impact-weighted within a level; Exposure-only when Unknown.)
- Change the sort from a single `RiskScore` float to the composite `(levelRank, scalar)` ascending,
  so the **worst** account (highest level, then highest scalar) gets the highest percentile (~1.0),
  matching today's "higher = more urgent" convention.
- Preserve the existing tie semantics: accounts with an EQUAL composite key share a rank
  (`rank = #accounts strictly-less in (levelRank, scalar) lexicographic order`), `Percentile =
  rank/(n-1)`; 0/1-account sets get 0. `RiskScore` is no longer the sort key but is otherwise
  unchanged (still displayed, still used by the shared-DA 9.0 floor).
- Idempotent: depends only on level + axes, never on a prior `Percentile`.

### #4 — HIBP-floor guard on rescore
`internal/secretsdump` + `internal/engine`:
- Add `HIBPBreachCount int` to `secretsdump.ParsedAccount` (the prior count; populated ONLY when
  the rescore path reconstructs from a stored account).
- In `engine.rescoreWith` (engine.go:237), set `pa.HIBPBreachCount = a.HIBPBreachCount` on the
  reconstructed `ParsedAccount`. (The upload/initial path leaves it 0.)
- Refactor `hibpCount` into `freshHIBP(ntlm string) (count int, ok bool)` that returns
  `ok=false` when no fresh count could be obtained — i.e. `e.HIBP == nil` OR `LookupHash` errored —
  and `ok=true` with the real count (incl. a genuine 0) when the index answered. (Keep a thin
  `hibpCount` wrapper if other callers want the old signature: `c, _ := e.freshHIBP(h); return c`.)
- In `scoreCracked` (engine.go:~289) and `scoreUncracked` (engine.go:~399), replace
  `count := e.hibpCount(a.Hash)` with:
  ```go
  count, ok := e.freshHIBP(a.Hash)
  if !ok && a.HIBPBreachCount > 0 {
      count = a.HIBPBreachCount // preserve the stored breach floor when HIBP is unavailable
  }
  ```
- Net: a rescore never LOWERS a breached account's Exposure just because HIBP was momentarily
  unavailable (nil index or lookup error); a genuinely-fresh zero (index up, hash truly absent)
  still clears it; initial upload (prior 0) is unchanged.

---

## 4. Files

**Go:**
- `internal/risk/risk.go` — `domainFactor` (replaces `domainModifier`); `impactScore` multiplicative;
  `Breakdown.DomainModifier` = additive-equivalent contribution.
- `internal/model/model.go` — `triageKey` + composite-sort `ComputePercentiles`.
- `internal/secretsdump/*.go` — `ParsedAccount.HIBPBreachCount` field.
- `internal/engine/engine.go` — carry prior HIBP in `rescoreWith`; `freshHIBP`/`hibpAvailable`
  fallback in `scoreCracked`/`scoreUncracked`.
- Tests: `internal/risk/risk_test.go` (impactScore + vector goldens for domain levels — values
  change for non-Normal domains), `internal/model/model_test.go` (percentile level-first ordering),
  `internal/engine/engine_test.go` (rescore-preserves-HIBP-when-index-down; any vector/score golden).

**Web:** none required (the domain-risk UI labels were already multiplicative and now match;
`ScoreBreakdown.domain_modifier` keeps the same TS type — it still carries a number).

## 5. Testing

- **#11:** an enriched account with `priv/da = X` in a Critical domain gets `Impact = min(10, X*1.3)`
  (was `min(10, X+1.0)`); a Normal-domain account is unchanged (×1.0); an UNENRICHED account is
  unaffected (Impact stays Unknown). Update the domain-level goldens.
- **#6:** percentile is level-monotone — for any two accounts, a higher-level one always gets a
  `Percentile >= ` a lower-level one; within a level the Impact-weighted scalar orders them; ties
  share rank; the worst account → highest percentile. A regression fixture: a cracked-disabled
  high-Exposure/low-Impact account must NOT outrank a near-DA High account.
- **#4:** rescore with `e.HIBP == nil` preserves a stored `HIBPBreachCount` (Exposure floor intact);
  rescore with the index loaded refreshes it; initial upload with no index yields 0 (unchanged). A
  lookup-error path also preserves the prior count.
- **Gates:** `gofmt -l cmd internal`, `go build/vet/test ./...`, `govulncheck`; web `tsc`/`vitest`/
  `build` (no web change, but confirm green). Live: Recalculate an audit, confirm a Critical-domain
  enriched account's Impact rose multiplicatively and the worklist/percentile ordering is
  level-consistent; console clean.

## 6. Definition of done (D)

Domain risk multiplies Impact as the UI always claimed (Exposure untouched, unenriched unaffected);
the triage percentile is level-first so it never contradicts the level badge; and a Recalculate can
never silently drop a breached account's HIBP Exposure floor when the index is momentarily down.
All scoring goldens updated and green; no new secret exposure; existing audits adopt the new numbers
on their next Recalculate.
