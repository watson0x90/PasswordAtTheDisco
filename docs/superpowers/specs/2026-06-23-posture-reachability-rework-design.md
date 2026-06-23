# Executive scoring rework: Hygiene × Reachability with a Tier-0 gate — Design (v2, panel-vetted)

> Resolves the "Strong posture (87.6) next to Very-High breach likelihood" contradiction surfaced by
> auditing a real 6,069-account export. Designed and then spec-vetted by a 3-expert panel
> (offensive-security/IR, measurement theory, risk-frameworks) — both rounds unanimous. **v2 folds in
> every required change from the spec-vetting round** (marked ⟐). Reworks the **audit-level executive
> rollup only**; the per-account two-axis engine (`internal/risk`) is unchanged.

## 1. Problem (panel consensus)
Two numbers on incompatible scales: **Posture 87.6/"Strong"** (a ratio *average* — dilutes catastrophe
across the estate, incl. 2,256 disabled accounts padding the denominator) vs **Breach Likelihood
"Very High"** (an absolute-count tripwire `crit>50 || da>20`). Three real **formula defects**:
1. **Dead privilege term** `max(0,15−da/total·100)` — slope −0.0165 pts/path; 21 paths cost 0.35/15;
   needs ~455 paths to react. A *mean* is the wrong operator for a weakest-link (min-cut) property.
2. **Tier-0/DCSync invisible** to posture (the live DCSync controlling 5,477 objects scores zero).
3. **Breach-$ keyed off Critical count, ignores reachability** (mis-sizes a DCSync estate at $50K/2wk).
Plus a brittle, non-scale-aware tripwire. The per-account engine already gates correctly
(`LevelFromAxes` `daOverride`); the rollup regressed to a compensatory mean. Fix = make the rollup
inherit the weakest-link/gate discipline (FAIR / NIST 800-30 / CVSS worst-case / BloodHound Enterprise /
SSL-Labs "one fatal flaw caps the grade" precedent).

## 2. Approach — two orthogonal axes + a one-way gate
Three related outputs + a gated headline:
- **Credential Hygiene** (0–100, intensive average — correct for hygiene breadth). Component only.
- **Breach Reachability** `L ∈ [0,1)` (extremal, count-driven, smooth, scale-aware). Component.
- **Overall** `= Hygiene·(1−L)` (0–100) — a **labeled trend/sort key, never a bare headline scalar** ⟐.
- **Verdict** + **VerdictReason** — the contradiction-proof headline word (§2.5).

### 2.1 Credential Hygiene (0–100)  — over ENABLED accounts only
`active = #{a.Enabled}`. ⟐ **Guard `active==0` BEFORE any division** → return Verdict "No Data",
Hygiene 0, but still surface §2.6 dormant-privileged and let the Tier-0 gate fire if applicable.
```
risk       = max(0, 100 − crit/active·200 − high/active·150 − med/active·50)/100 · 45
strength   = uncrackedActive/active · 35
compliance = (active − crackedViolationsActive)/active · 20
Hygiene    = round1(risk + strength + compliance)              // privilege term REMOVED
HygieneRating = Strong (≥85) | Fair (≥70) | Weak (else)
```
`crit/high/med/uncracked/crackedViolations` counted among **enabled** accounts only. ⟐
`crackedViolationsActive` MUST be the count of *enabled* cracked-non-compliant accounts (a subset of
`active`) so the compliance term cannot go negative. Each term stays in [0, weight] ⇒ Hygiene∈[0,100],
and Hygiene is 0-homogeneous (scale-invariant) since every term is a ratio. Weights 45/35/20 (was
40/30/15 + a removed 15 privilege); panel-confirmed as a defensible +5/+5/+5 redistribution.

### 2.2 Breach Reachability  L  — reachable catastrophe-enablers only ⟐
Define **reachable(a)** = `a.Enabled && (a.Cracked || a.EscalatedBySharedDA || a.EscalatedByMassReuse)`
— a privileged object the auditor can actually obtain/authenticate as. Then:
```
da          = #{ a : a.HasDAPathway() && reachable(a) }                       // p_da   = 0.55  ⟐
t0Reachable = #{ a : a.ControlsTier0  && reachable(a) }                       // p_t0   = 0.70
critN       = min( #{ a : a.RiskLevel=="Critical" && !a.HasDAPathway() && !a.ControlsTier0 }, capCrit )  // p_crit=0.15, capCrit=5 ⟐

L = 1 − (1−p_da)^da · (1−p_t0)^t0Reachable · (1−p_crit)^critN
```
⟐ **`reuseN` deferred (NOT in v1).** Reasons: (a) Breach Reachability measures *path-to-domain-control*;
large CRACKED reuse clusters are non-privileged lateral-spread, already captured by Hygiene's strength
term and Finding 1's Level escalation — folding them into a *DA-reachability* score conflates two
things. (b) Hard constraint: the redacted `/api/accounts` payload strips `nt_hash` and exposes no
reuse-group token, so the TS mirror cannot compute distinct cracked-reuse clusters → Go⇄TS parity would
break. The panel listed reuseN as v1-optional. Privileged reuse (a cracked account that IS a DA/Tier-0
controller) still counts — via `reachable()` → da/t0.
- ⟐ **`da`/`t0` count only reachable (enabled + cracked/reused) paths** — a structural DA edge through
  a strong, uncracked, or disabled account is NOT a live breach path (else every hardened domain reads
  Very High forever, the existence-vs-reachability error this rework exists to fix).
- ⟐ **`critN` de-duped** out of da∪t0 (measures Criticals that aren't *already* the catastrophe) and
  **capped** so a large estate's Critical *volume* can't auto-pin Very High (keeps L scale-aware:
  da/t0 are true catastrophe counts → raw; critN/reuseN are population-ish → capped, reusing the
  project's existing absolute-cap discipline).
- ⟐ **`p_da = 0.55`** (not 0.50): da=1 → L≈0.45 (unambiguously High), da=2 → L≈0.80 (unambiguously Very
  High), with ~0.05 margin from every cutpoint — removes the exact-boundary float/parity hazard.
- Properties: strictly monotone (any added enabler only raises L), bounded [0,1), smooth.
  Scale-robust by construction (one reachable DA path → High at any N).
- Independence overstates L when paths share choke points → it is a **conservative upper bound**;
  ⟐ report the **band + range only, never a point %** (a UI invariant + test, not just a comment).

**Bands (integer-scaled, parity-safe)** ⟐ — compare `Ls = round(L·1e6)` (integer) against integer
cutpoints, never the rounded display value:
`Low: Ls<250000 · Medium: <500000 · High: <750000 · Very High: ≥750000` (>75% / 50–75% / 25–50% / <25%).

### 2.3 Overall + the Verdict gate (one register, contradiction-proof) ⟐
```
Overall = round1(Hygiene · (1 − L))            // trend/sort key only; shown only WITH a cap-reason
Verdict ladder, one outcome register (best→worst):
  Sound · Guarded · Elevated · High Risk · Critical · Critical — Tier-0 Reachable
```
Computed (first match wins; gate only lowers; VerdictReason is a separate field):
```
if active == 0 && t0Reachable == 0:   Verdict = "No Data"
elif t0Reachable ≥ 1:                  Verdict = "Critical", Reason = "Tier-0 Reachable"
elif L band == Very High:              Verdict = "Critical", Reason = "multiple reachable domain-control paths"
elif L band == High:                   Verdict = "High Risk", Reason = "a reachable path to domain-control exists"
else:  // L Medium/Low → hygiene-derived
        Strong → "Sound" · Fair → "Guarded" · Weak → "Elevated"
```
⟐ Replaces the earlier mixed-register `min(HygieneRating, cap)` ladder ("At Risk" sandwiched above
"Weak" read backwards to a CISO). `verdict_reason` is a first-class field (machine-stable verdict +
human reason), mirroring SSL-Labs "grade capped because …". This audit: `t0Reachable=1` → **Critical —
Tier-0 Reachable**; Hygiene ≈88 Strong (component); Reachability Very High; Overall ≈0–4 (trend only).

### 2.4 Breach impact ($/recovery) — reachability-driven, single-source ⟐
Driven by the SAME `t0Reachable`/`L` (so $ and verdict cannot disagree); labeled **modeled/illustrative**:
```
if t0Reachable ≥ 1:  "$1M – $5M+",   "6–12 months"     // full-domain credential theft
elif L == Very High: "$500K – $1M",  "3–6 months"
elif L == High:      "$100K – $500K","1–3 months"
else:                "$50K – $100K", "2–4 weeks"
Probability / ProbabilityPct ← the L band (single source with Reachability).
```

### 2.5 Card copy (two layers + per-axis definitions) ⟐
**Relationship line (always):** *"Two independent questions. Credential Hygiene measures the average
health of all **enabled** accounts. Breach Reachability measures whether **any single path** to
domain-control credentials exists — and one is enough. A fleet healthy on average can still be fully
breachable."*
**Gate-reason line (only when gated):** *"Why the verdict is Critical: one reachable Tier-0 / DCSync
path can compromise the whole domain regardless of password hygiene — fix the path to lift it."*
**Priority-action line (placed in the dollar eye-line):** *"Remediate the reachable Tier-0 / DA path(s)
before the password-reset backlog; hygiene is already Strong — the exposure is structural."*
Per-axis sub-labels: Hygiene = "avg password health across enabled accounts (strength, crackability,
compliance)"; Reachability = "likelihood ≥1 path to domain-control is exploitable; attack-path driven,
modeled upper bound." ⟐ Hygiene component carries a footnote with the enabled-count
(e.g. "over 3,813 enabled; 2,256 disabled excluded").

### 2.6 Dormant privileged accounts (don't hide the disabled landmines) ⟐
`dormantPrivileged = #{ a : !a.Enabled && (a.ControlsTier0 || a.HasDAPathway()) && (a.Cracked ||
a.EscalatedBySharedDA || a.EscalatedByMassReuse) }`. Excluded from Hygiene and L (not *currently*
reachable), but surfaced as an explicit Summary + sanitized-export + card line: *"Dormant privileged
(disabled) accounts: N — pre-compromised credentials that become live if re-enabled."*

## 3. Data model & surfacing
**`model.Posture`** (extend; keep existing JSON keys for back-compat): keep `score`(=Hygiene),
`rating`(HygieneRating), `breakdown`(risk/strength/compliance — privilege removed or kept 0),
`likelihood`(= Reachability band alias). **Add** `reachability string`, `reachability_score float64`
(L), `reachability_pct string` (band range, no point value), `overall float64`, `verdict string`,
`verdict_reason string`, `dormant_privileged int`. **`model.BreachImpact`** — values reachability-driven.
**Callsite** `internal/store/store.go:727-728` — fold into one `ExecutiveSummary(accounts)` builder (it
already has all accounts) producing Posture + BreachImpact + dormant count; keep churn low.
**TS mirror** `web/src/insights.ts` — byte-parity with Go (golden test enforces). **Dashboard** —
Verdict headline; Hygiene + Reachability components + §2.5 copy; Overall only as a labeled trend value.
⟐ **Trend/Compare**: track **Hygiene and Reachability as the two primary series** (hygiene = remediation
program; reachability = structural exposure); Overall is a labeled secondary. Compare leads with the
two-axis delta ("Hygiene +6, Reachability unchanged — Tier-0 path still open"). **Sanitized export**
(`internal/report/sanitize.go`) + **HTML report** (`internal/report/report.go`) — new summary fields.
**Help** (`web/src/components/help/ChapterScoring.tsx`) — the two axes + gate. **api.ts** — types.

## 4. Files
- **Go:** `internal/model/model.go` (ExecutiveSummary/PostureScore + EstimateBreachImpact rework, struct
  fields, helpers `breachReachability`, `reachBand`, `gateVerdict`, `reachable`, const block); store.go
  callsite; report/sanitize.go + report/report.go. Tests: model_test.go (golden + invariants),
  sanitize_test.go.
- **Web:** insights.ts (mirror), the executive-card component(s), ChapterScoring.tsx, Compare wiring,
  api.ts types.

## 5. Testing
- **Invariants (Go + TS parity, golden):** monotonicity (adding a reachable DA path / Tier-0 / Critical
  never raises Hygiene/Overall or improves Verdict); boundedness (Hygiene∈[0,100], L∈[0,1),
  Overall∈[0,100]); Hygiene scale-invariance; L scale-robustness (1 reachable DA path → High at any N);
  gate (t0Reachable≥1 ⇒ Critical—Tier-0 Reachable; Very-High L ⇒ Critical; High L ⇒ High Risk).
  ⟐ Pin **band/verdict strings** (not floats) cross-language at da∈{0,1,2,21}, t0∈{0,1}; assert da=1→High,
  da=2→Very High. ⟐ Negative-guard test: disabled cracked DA account ⇒ 0 to L, +1 to dormantPrivileged.
  ⟐ active==0 + t0Reachable≥1 ⇒ Critical (not "No Data").
- **The real audit:** Hygiene ≈ Strong (~88–92), Reachability Very High, **Verdict Critical — Tier-0
  Reachable**, Overall ≈ low single digits, impact $1M+/6–12mo, dormant-privileged surfaced.
- **Gates:** `gofmt -l cmd internal`, `go build/vet/test ./...`, `govulncheck`; web `tsc`/`vitest`/
  `build` (NEVER `npm install`). **Live:** rebuild, restart, re-export sanitized; card reads Critical —
  Tier-0 Reachable with both components + §2.5 copy; console clean.

## 6. Definition of done
The executive rollup shows honest Credential Hygiene (disabled excluded, dead privilege term gone),
smooth scale-aware Breach Reachability over **reachable** enablers, a one-register gated Verdict +
reason that cannot read "Sound/Strong" while a Tier-0 path is reachable, reachability-driven illustrative
breach $/recovery, dormant-privileged surfaced, two-layer card copy with modeled-upper-bound
disclaimers, two-axis trend/Compare, and Go⇄TS parity with extended golden + invariant tests.
Per-account engine, Exposure/Impact axes, and Findings 1–3 untouched. Tag v2.28.0.

## 7. Settled constants (panel-tuned; golden-test them)
`p_da=0.55, p_t0=0.70, p_crit=0.15`; `capCrit=5`; Hygiene weights 45/35/20; band cutpoints (×1e6)
250000/500000/750000; Hygiene rating ≥85/≥70. All in one named `const` block.
Deferred to v2-of-this-feature: (a) `reuseN` as a reachability enabler (needs a safe reuse-group token in
the redacted payload for TS parity; also arguably a Hygiene not a reachability signal); (b) a correlation
discount (`effective_count = n^α`) for shared choke points — v1 uses de-duped + capped raw counts
(band-only reporting absorbs the rest).
