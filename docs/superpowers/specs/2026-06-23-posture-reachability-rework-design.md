# Executive scoring rework: Hygiene × Reachability with a Tier-0 gate — Design

> Resolves the "Strong posture (87.6) next to Very-High breach likelihood" contradiction surfaced by
> auditing a real 6,069-account export. Vetted by a 3-expert panel (offensive-security, measurement
> theory, risk-frameworks) which converged unanimously. This reworks the **audit-level executive
> rollup only** — the per-account two-axis engine (`internal/risk`) is unchanged.

## 1. Problem (panel consensus)
The dashboard shows two numbers computed on incompatible scales:
- **Posture 87.6 / "Strong"** — a *ratio/average* hygiene blend. Dilutes rare-but-catastrophic signals
  across the whole estate (incl. 2,256 disabled accounts padding the denominator).
- **Breach Likelihood "Very High" / >75%** — an *absolute-count tripwire* (`crit>50 || da>20`).

Three real **formula defects** (not just labels):
1. **Dead privilege term.** `max(0, 15 − da/total·100)` has slope −0.0165 pts/DA-path; 21 paths cost
   0.35 of 15 pts; it needs ~455 paths to react. A *mean* is the wrong operator for a weakest-link
   (min-cut) property — in AD the attacker exploits the single worst path, never the average.
2. **Tier-0/DCSync invisible to posture.** The live DCSync account controlling 5,477/6,069 objects
   contributes **zero**. `ControlsTier0`/`Controlled` exist but the rollup ignores them.
3. **Breach-impact $ keyed off Critical count, ignores reachability.** A DCSync-reachable estate is
   mis-sized "$50K–$100K / 2–4 wks" when it is realistically $1M+ / months.
Plus the tripwire is **brittle** (20 vs 21 DA paths flips the exec headline) and **not scale-aware**.

The per-account engine already does this right (`LevelFromAxes` `daOverride` forces Critical on
cracked+DA-path); the audit rollup regressed to a compensatory mean. **Fix = make the rollup inherit
the weakest-link/gate discipline the per-account scorer already endorses.** (FAIR/NIST/CVSS/BloodHound
Enterprise/SSL-Labs precedent: a single reachable Tier-0 path caps the headline regardless of hygiene.)

## 2. Approach — two orthogonal axes + a one-way gate
Replace the single "Posture" verdict with **three** related outputs and a gated headline:

- **Credential Hygiene** (0–100, intensive/average — *correct* for hygiene breadth). Relabel of the
  current score; keep the average but (a) exclude **disabled** accounts from denominators, (b) **drop**
  the dead privilege term, (c) redistribute its weight. Shown as a *component*, never the headline.
- **Breach Reachability** `L ∈ [0,1)` (extremal/worst-path — count-driven, smooth, scale-aware).
- **Overall** = `Hygiene × (1 − L)` (0–100, gated — keeps one comparable number for trend/Compare).
- **Verdict** word = `min_severity(HygieneRating, gateCap(L, tier0))` — the contradiction-proof headline.

### 2.1 Credential Hygiene (0–100)
Counts taken over **enabled** accounts only (`active = #{Enabled}`); if `active==0`, Verdict "No Data".
```
risk       = max(0, 100 − crit/active·200 − high/active·150 − med/active·50)/100 · 45
strength   = uncrackedActive/active · 35
compliance = (active − crackedViolationsActive)/active · 20
Hygiene    = round1(risk + strength + compliance)            // 0..100, privilege term removed
HygieneRating = Strong (≥85) | Fair (≥70) | Weak (else)
```
`crit/high/med/uncracked/crackedViolations` are tallied among enabled accounts only. Weights
45/35/20 (was 40/30/15 + 15 privilege); panel to confirm split at spec review.

### 2.2 Breach Reachability  L
"Probability at least one catastrophic path is exploitable" — the natural generative model:
```
L = 1 − (1−p_da)^da · (1−p_t0)^t0 · (1−p_crit)^critN · (1−p_reuse)^reuseN
```
- `da`     = #accounts with a DA pathway (`HasDAPathway()`), `p_da   = 0.50`
- `t0`     = #Tier-0/DCSync controllers (`ControlsTier0`),    `p_t0   = 0.70`
- `critN`  = #Critical-level accounts,                        `p_crit = 0.15`
- `reuseN` = #distinct large CRACKED reuse clusters (the mass-reuse-escalated groups), `p_reuse = 0.10`
- Ordinal: `Low <0.25 ≤ Medium <0.5 ≤ High <0.75 ≤ Very High`.

Properties: strictly monotone (any added catastrophe-enabler only raises L), bounded [0,1), smooth
(no cliffs), **scale-aware by construction** (keyed off catastrophe *counts*, not /total — one DA path
reads High whether the estate is 30 or 600k accounts). With `p_da=0.5`: **1 DA path → L≥0.5 → High**;
**2 → Very High**. Independence is a conservative upper bound (shared choke points correlate paths) —
report the **band only**, never a 2-decimal % (panel caveat). `critN` mild double-count with da/t0 is
acceptable (conservative). Seed probabilities are tunable; **panel vets exact values at spec review.**

### 2.3 Overall + the gate (contradiction-proof headline)
```
Overall = round1(Hygiene · (1 − L))                 // 0..100, derived sort/trend key
Verdict ladder (best→worst): Strong, Fair, Weak, At Risk, Critical
if t0 ≥ 1:            Verdict = "Critical"           // hard cap — reachable Tier-0/DCSync
elif L ≥ 0.75:        Verdict = "At Risk"            // Reachability Very High
elif L ≥ 0.50:        Verdict = worse(HygieneRating, "Fair")   // High → cannot be Strong
else:                 Verdict = HygieneRating        // Med/Low reachability → no cap
```
The gate only ever **lowers** the verdict; the Hygiene number stays honest as a component. This audit:
`t0=1 → Critical`, `Overall = 87.6·(1−~0.9999) ≈ 0–4`, Hygiene 87.6 (component), Reachability Very High.

### 2.4 Breach impact ($/recovery) — reachability-driven
Replace the `crit`-count switch with a reachability/Tier-0 ladder:
```
if t0 ≥ 1:      "$1M – $5M+",    "6–12 months"   // full-domain credential theft
elif L ≥ 0.75:  "$500K – $1M",   "3–6 months"
elif L ≥ 0.50:  "$100K – $500K", "1–3 months"
else:           "$50K – $100K",  "2–4 weeks"
Probability / ProbabilityPct ← the same L band (Very High >75% … Low <25%)  // single source
```

### 2.5 The mandatory explanatory line (UI)
On the executive card, one sentence so the two axes read as intentional, not contradictory:
> *"Hygiene is the average health of all accounts; Breach Reachability is whether any path to
> domain-control exists — one is enough. A healthy-on-average estate can still be highly breachable."*

## 3. Data model & surfacing
**`model.Posture`** (extend; keep existing JSON keys for back-compat):
- keep `score` (now = Hygiene), `rating` (HygieneRating), `breakdown` (risk/strength/compliance; drop
  privilege or keep at 0 — decide in plan), `likelihood` (= Reachability band, back-compat alias).
- add `reachability string` (band), `reachability_score float64` (L), `overall float64`,
  `verdict string`.
**`model.BreachImpact`** — unchanged shape; values now reachability-driven.
**Callsite** `internal/store/store.go:727-728` — `PostureScore(accounts)` already has everything;
`EstimateBreachImpact` gains the reachability inputs (t0, L) — pass them or fold into one
`ExecutiveSummary(accounts)` builder (plan decides; keep churn low).
**TS mirror** `web/src/insights.ts` — must stay byte-parity with Go (golden test enforces).
**Dashboard** — headline = Verdict; show Hygiene + Reachability as components + the §2.5 sentence +
Overall for trend. **Sanitized export** (`internal/report/sanitize.go`) — add reachability/overall/
verdict to the summary block. **HTML report** (`internal/report/report.go`) — same rollup. **Help**
(`web/src/components/help/ChapterScoring.tsx`) — explain the two axes + gate. **Compare** — switch the
tracked composite to `Overall` (still one number; now moves with reachability).

## 4. Files
- **Go:** `internal/model/model.go` (PostureScore + EstimateBreachImpact rework, struct fields, helpers
  `breachReachability`, `gateVerdict`, `worseRating`); `internal/store/store.go` (callsite);
  `internal/report/sanitize.go` + `internal/report/report.go` (export/report fields).
  Tests: `internal/model/model_test.go` (golden + invariants), `internal/report/sanitize_test.go`.
- **Web:** `web/src/insights.ts` (mirror), the dashboard executive card component(s),
  `web/src/components/help/ChapterScoring.tsx`, Compare wiring, `web/src/api.ts` (types).

## 5. Testing
- **Invariants (Go + TS parity):** monotonicity (adding a DA path / Tier-0 / Critical never raises
  Hygiene, Overall, or improves Verdict); boundedness (Hygiene∈[0,100], L∈[0,1), Overall∈[0,100]);
  Hygiene scale-invariance under estate-cloning; L scale-robustness (1 DA path → High at any N);
  gate (t0≥1 ⇒ Critical; L≥0.75 ⇒ At Risk; Strong hygiene + L≥0.5 ⇒ ≤Fair). Golden values pinned at
  da∈{0,1,2,21}, t0∈{0,1}.
- **The real audit:** Hygiene ≈ Strong (~88–92 after removing disabled + privilege), Reachability Very
  High, Verdict **Critical** (DCSync), Overall ≈ low single digits, breach impact $1M+/6–12mo.
- **Gates:** `gofmt -l cmd internal`, `go build/vet/test ./...`, `govulncheck`; web `tsc`/`vitest`/
  `build` (NEVER `npm install`). **Live:** rebuild, restart, re-export sanitized — confirm the card
  reads Critical with both components shown + the explanatory line; console clean.

## 6. Definition of done
The executive rollup shows Credential Hygiene (honest average, disabled excluded, dead privilege term
gone), Breach Reachability (smooth, count-driven, scale-aware L), a gated Overall + Verdict that
**cannot** read "Strong" while a Tier-0 path is reachable, reachability-driven breach $/recovery, and
the one-line explanation. Go ⇄ TS parity with extended golden + invariant tests. Per-account engine,
Exposure/Impact axes, and Findings 1–3 untouched. Tag v2.28.0.

## 7. Open items for panel spec-review (before build)
- Hygiene component reweight (proposed 45/35/20) and whether to keep a zeroed `privilege` breakdown
  field for back-compat or remove it.
- Reachability seed probabilities `p_da/p_t0/p_crit/p_reuse` (0.50/0.70/0.15/0.10) and whether `critN`
  should exclude accounts already counted in da/t0 (de-dup vs. conservative over-count).
- Verdict vocabulary ("At Risk"/"Critical" vs alternatives) and whether Tier-0 → "Critical" should
  instead be "Critical — Tier-0 Reachable".
- Whether `reuseN` belongs in L v1 or is deferred.
