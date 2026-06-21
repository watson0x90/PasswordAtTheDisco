# Scoring Engine v2 — Two-Axis (Exposure × Impact) Risk Model — Design

**Date:** 2026-06-20
**Topic:** Re-architect the password-risk scoring engine to fix the defects surfaced by the expert-panel review (controlled-objects cap, HIBP triple-count, complexity-nullified-by-length, tier collapse, exposure-drowns-impact, ignored Enabled/roastable signals, missing near-DA / shared-hash-to-DA escalation, opaque handling of absent BloodHound data, and a misleading "factor contribution" radar). Replace the single blended 0–10 score with a **two-axis Exposure × Impact** model that degrades gracefully when BloodHound data is present for some, all, or none of an audit's accounts.

## Provenance

This design follows a four-person expert-panel critique (applied mathematician, AD/BloodHound security engineer, risk-quantification specialist, measurement-theory/viz specialist) of the current engine (`internal/risk/risk.go`, `web/src/insights.ts:riskFactorsRadar`, `internal/bloodhound/bloodhound.go`). Every flaw below was identified from the actual code; the load-bearing claims (the `limit=10` controllables cap discarding `env.Count`, the HIBP triple-count across `floorBase`/`finalFloor`/`hibpF`, the absence of an `Enabled` field in `risk.Context`, and the `combined*(10/4)` base whose true max is 2.6) were verified against source.

## Problem (what's broken today)

1. **Outbound control is truncated to ~10.** `GetUserControllables` queries `…/controllables?limit=10` and `ExtractControllableCount` sums only the returned page, discarding the API's true total `env.Count`. The privilege tiers in `risk.go` (`>10/>50/>100/>500/>1000`) are therefore largely unreachable; "High Privilege: controls >100 objects" is a structural zero. A principal controlling 5000 objects gets the same privilege boost (zero) as one controlling nothing.
2. **HIBP is triple-counted** — the same `hibpCount` drives `floorBase`, `finalFloor`, and the `hibpF` multiplier, giving public-breach exposure ~3× the leverage of blast radius (which is capped per #1).
3. **Complexity is nullified by length** — the base uses the *product* `complexityF·lengthF`, so a long password collapses complexity's entire contribution; a 16-char all-lowercase and a 16-char mixed-special password score identically. The `×(10/4)` scale is also wrong (the summed term's true max is 2.6, so the `min(10,·)` cap is dead and the base alone can never reach High).
4. **Tier collapse** — two aggressive floors pin most *cracked* accounts to High/Critical, so the 0–10 score barely orders them; a score that rates everything Critical can't answer "which 20 of 500 first?".
5. **Exposure drowns Impact** — privilege is a ×1.5-max multiplier on a floored base, so password breach status moves the score more than how many objects an account can compromise — backwards for prioritization.
6. **Ignored high-signal inputs** — `Enabled` (disabled ⇒ can't authenticate) and roastable flags are captured at `engine.go:333/349/350` but never reach `risk.Score`. The sample audit was 69/69 disabled yet scored as live.
7. **Missing escalation** — control of a Tier-0 object (DCSync, DA-group, AdminSDHolder, KRBTGT) and "shares a hash with a DA-reachable account" are not modeled as DA-equivalent.
8. **Opaque absent-BloodHound handling** — without enrichment the entire impact side silently collapses to neutral (1.0), so "we don't know the blast radius" and "the blast radius is low" look identical, with no operator-visible signal.
9. **The radar misleads** — it linearly rescales incommensurable factors onto one axis, clips variance, and averages the same factors that defined the tier (circular); visual spoke size has no monotone relationship to a factor's real effect on the score.

## Decision (the v2 model)

Replace the single blended score with **two independent axes plus a derived level**, and make BloodHound coverage an explicit, per-account, first-class concept. Approved via brainstorming. Three keystone choices were made by the owner:

- **Two-axis Exposure × Impact** (not a single fixed score).
- **Absent Impact = explicit per-account `Unknown` state** (never a number, never "low") **plus an audit-level coverage banner**.
- **Overall level from a 2D Exposure×Impact matrix** (not `max()`, not two separate badges).

### Axis 1 — Exposure (0–10): "how easily is this credential compromised?"

Computed from the **dump + HIBP + cross-account reuse**, so it is *always* trustworthy regardless of BloodHound. Inputs and construction:

- **Weakness sub-score (cracked accounts):** a **weighted sum of bounded [0,1] penalties**, scaled ×10 — not a product. Each penalty is independent so complexity is no longer nullified by length:
  - `lengthPenalty` = the existing logistic `1/(1+e^((len−10)/2))` (already [0,1], higher = shorter = worse) — kept verbatim; it is the one well-designed piece.
  - `complexityPenalty` = `(1.0 − complexityF)/0.8`, mapping `complexityF∈[0.2,1.0]` → `[0,1]` (higher = less complex = worse).
  - `dictPenalty` = the existing additive dictionary/common/banned/keyboard term, clamped [0,1].
  - `simPenalty` = the existing similarity term normalized to [0,1].
  - `weaknessScore = 10 · (w_len·lengthPenalty + w_cx·complexityPenalty + w_dict·dictPenalty + w_sim·simPenalty)`, weights summing to 1 (proposed `0.30/0.20/0.35/0.15`; **exact weights locked with golden tests in the sub-project B plan**).
- **HIBP — single channel.** HIBP raises Exposure in **exactly one place** (kills the triple-count): an `hibpExposureFloor(count)` tiered minimum (proposed: ≥1M→9.0, ≥100k→8.5, ≥10k→8.0, ≥1k→7.0, ≥100→6.0, ≥10→5.0, ≥1→4.5). `Exposure = max(weaknessScore, hibpExposureFloor, crackedFloor)`.
- **Cracked floor.** "Cracked is itself exposure": a cracked password floors Exposure at a small baseline (proposed: `<8 chars → 4.0`, else `3.0`), applied **once**.
- **Reuse bump.** Shared-hash count adds a small, capped amount (more copies = more chances).
- **Roastable bump (only adds).** If known (Kerberoastable `HasSPN` / AS-REP `DontReqPreauth`), add a small capped amount. When BloodHound is absent the bump is simply omitted — Exposure stays valid, at worst slightly conservative. No false safety.
- **Uncracked accounts.** Password is unknown, so weakness penalties don't apply; Exposure comes from `hibpExposureFloor` (the NT hash can match the HIBP NTLM index even uncracked), the roastable bump, and the reuse bump. Lower band, not zero.

Exposure tier cutoffs reuse the familiar bands: Critical ≥8, High ≥6, Medium ≥4, Low <4.

### Axis 2 — Impact (0–10 **or** `Unknown`): "blast radius if this credential is compromised?"

Almost entirely **BloodHound-derived**. If the account has **no enrichment (coverage = None) ⇒ Impact = `Unknown`** (an explicit state, not a number). Otherwise:

- **Enabled gate.** A disabled account cannot authenticate → **Impact capped at Low (≤2)**. (If `Enabled` is unknown that means no BloodHound, so Impact is `Unknown` anyway.)
- **Privilege / blast-radius.** From the **real controlled-objects count** (`env.Count`, per sub-project A — no longer capped at 10), **sensitivity-weighted by object label** (Group / Computer / DC ≫ User). Mapped to a privilege sub-score on [0,10] via tiers that are now actually reachable.
- **DA reachability.** A confirmed traversable Domain-Admin path ⇒ Impact = max (10).
- **DA-equivalent (near-DA).** Control of a Tier-0 object — DCSync rights on the domain, control of the Domain Admins group, AdminSDHolder, or KRBTGT — ⇒ Impact = max (10), even without a literal shortest-path edge.
- **Shared-hash-to-DA escalation.** If this account's NT hash is shared with a DA-reachable or DA-equivalent account, it **inherits** that Impact (cracking it = DA).
- **Domain risk.** A minor additive modifier (proposed +0…+1) from the domain's risk level.
- **Privilege contributes to a floor, not just a multiplier** — a powerful account cannot read low merely because its password looked strong.
- `Impact = enabledGate( max(privilegeSubScore, daComponent, sharedDAComponent) + domainModifier )`, clamped [0,10].

Impact tier cutoffs mirror Exposure: Critical ≥8, High ≥6, Medium ≥4, Low <4; plus the distinct `Unknown` state.

### Coverage / confidence model

- **Per-account coverage state:** `Full` (this account was enriched by BloodHound) or `None` (not enriched). Drives the `Unknown` Impact state and the "provisional" level badge. (Coverage is per-account because a single audit can be partially enriched — some accounts have BloodHound data, others don't.)
- **Audit-level coverage banner:** when enriched/total < 100%, the dashboard shows "BloodHound: N/M accounts enriched" so the gap is visible at a glance (owner asked for the banner *in addition to* the per-account state).

### Overall level — the 2D matrix

`Level = matrix(ExposureTier, ImpactTier)` → Critical / High / Medium / Low. Design intent (exact cells locked in the sub-project B plan), rows = Impact, cols = Exposure (Critical→Low):

| Impact ↓ \ Exposure → | Critical | High | Medium | Low |
|---|---|---|---|---|
| **Critical** | Critical | Critical | Critical | High |
| **High** | Critical | High | High | Medium |
| **Medium** | High | High | Medium | Medium |
| **Low** | Medium | Medium | Low | Low |

- **Hard override (preserved):** a cracked account with a confirmed DA path (or DA-equivalent) is **Critical** regardless of the matrix.
- **Impact = `Unknown`:** the level is computed **from Exposure alone**, rendered with a **"provisional"** badge, and the account is routed to a **"needs enrichment"** worklist. The UI never claims such an account is low-impact.

### Triage — percentile rank

To defeat tier collapse, the engine computes a **within-audit percentile rank** (a sort key, **not** a displayed score) so that even a large block of "Critical" accounts yields a strict order. Default worklist = **enabled + cracked**, ordered by Level, then Impact desc, then Exposure desc, with **`Unknown`-impact accounts segregated** into the needs-enrichment section rather than blended into the impact-sorted list.

## Data model changes (`internal/model`)

`Account` gains: `exposure_score` (float, 0–10), `impact_score` (`*float`, nil = Unknown), `impact_known` (bool), `coverage` (`"full"|"none"`), `percentile` (float). `risk_level` is now produced by the matrix; `risk_score` is **retained** as a back-compat blended value (de-emphasized in the UI) so existing views/sorts don't break. `score_breakdown` is extended to carry the per-axis sub-scores and the leave-one-out contribution inputs the radar needs.

## Decomposition — three sub-projects (each its own spec→plan→build, in order)

The model is shared; this single design doc is the shared architecture. Each sub-project gets a **focused implementation plan** and a review/finish cycle. Dependency order **A → B → C**.

### A — Ingestion correctness (`internal/bloodhound`, `internal/engine`, `internal/model`)
*Produces the Impact signals; ships independently and is unit-testable without any scoring change.*
- Carry the API's true `env.Count` per domain through `DomainControllables` / `ExtractControllableCount` (kills the 10-cap); keep `limit` only to bound the **display sample**, not the count. Fix the `>10` boundary so the threshold and any sample cap can't coincide.
- Retain each controllable's `Label` → **sensitivity buckets** (Group/Computer/DC vs User); detect **Tier-0 / DA-equivalent** control (DCSync, Domain Admins group, AdminSDHolder, KRBTGT).
- Wire `Enabled` and roastable flags (already captured, currently dropped before scoring) into the scored context.
- Compute **shared-hash cluster max privilege** so the shared-hash-to-DA escalation signal is available to B.
- Derive per-account **coverage state** (`Full` / `None`).

### B — Scoring engine v2 (`internal/risk`, `internal/engine`)
*The keystone.*
- New `Context`/`Analysis` fields from A. `Score` returns **Exposure, Impact (or Unknown), Level (matrix), breakdown**; the engine computes the **audit-relative percentile** during aggregation.
- Exposure reweight + single HIBP channel + single cracked floor.
- Impact with Enabled gate, sensitivity-weighted privilege floor, DA / DA-equivalent max, shared-DA inheritance.
- Unknown → neutral defaults (remove the silent-deflation bias and the `finalFloor` hack it required).
- 2D matrix level mapping; provisional flag when Impact Unknown; populate the new `model.Account` fields.

### C — Dashboard honesty (`web/src`)
*Consumes B; uses the `frontend-design` skill and live Playwright verification.*
- **Radar → leave-one-out marginal contribution** in score-points (`Δ_k = Score(all) − Score(factor k neutralized)`), averaged per tier; Impact spokes greyed/omitted when Impact is Unknown. (A stacked bar of the same deltas is an acceptable alternative if the radar proves awkward — decided in the C plan.)
- Surface **Exposure × Impact** (the two axis values per account; the matrix as a heatmap), the **coverage banner**, **provisional badges**, and the **needs-enrichment worklist**.
- Update KPIs (incl. the now-reachable "controls >100 objects").

## Vector string

Keep the CVSS-like vector. Extend `CO:` to reflect the **real** controlled count (not the capped sample) and add **two axis codes** (`EXP:` / `IMP:`, with `IMP:U` for Unknown) so the vector mirrors the two-axis model.

## Out of scope

- Compare / longitudinal trend features (shelved — no real audit history yet).
- A relational store (persistence stays flat-JSON + hot-reload; unchanged here).
- Any change to the reveal / audit-log security model.
- Re-deriving BloodHound enrichment semantics beyond the controllables-count fix and the Tier-0 / shared-DA signals named above.

## Testing

- **A & B (Go, table-driven):** controllables count >10 via `env.Count`; sensitivity buckets; Tier-0 detection; shared-DA propagation; coverage state. Exposure monotonicity (improving any input never raises Exposure); **HIBP counted once** (golden numbers proving the old triple-count is gone); complexity contributes independently of length; Enabled gate caps Impact; privilege floor; matrix level mapping; `Unknown` handling; percentile ordering. `gofmt -l` empty, `go build/vet/test ./...`, `govulncheck ./...` green per commit.
- **C (web):** `npx tsc --noEmit`, `npx vitest run` (incl. styleguard), `npm run build`. Live **Playwright** on the loaded sample data: coverage banner appears when enrichment is partial/absent, provisional badges on Unknown-impact accounts, the redesigned radar renders with greyed Impact spokes when Unknown, the "controls >N" KPI is non-zero, browser console has **0 errors/0 warnings**.
- **Cross-cutting:** the enriched synthetic dataset (`tools/gen_synthetic.py`) should exercise both a fully-enriched cohort and a no-BloodHound cohort so the coverage states are visible end-to-end; extend it in the C plan if needed.

## Risks / migration

- **Score continuity:** v2 shifts every account's numbers. Acceptable because Compare/longitudinal is shelved; existing audits re-score when reloaded. The **persist-vs-recompute** detail (whether scores are stored or computed on read) is confirmed and handled in the sub-project B plan so reloading an old audit can't show a stale v1 score next to a v2 one.
- **BHE API/perf:** taking the count from `env.Count` while sampling only a small `limit` page means no deep pagination — the perf posture is unchanged.
- **Constant calibration:** all proposed weights/tiers/matrix cells are design intent; each is pinned with golden unit tests in the relevant plan so the numbers are reviewable and stable.
