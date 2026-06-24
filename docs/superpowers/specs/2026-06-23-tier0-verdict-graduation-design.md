# Tier-0 verdict graduation — Design

> Refines the v2.28.0 executive verdict gate. Today **any** reachable Tier-0 controller (`t0Reachable ≥ 1`)
> hard-slams **Critical — "Tier-0 Reachable"**. Now that the enrichment fix detects Tier-0 reachability
> **transitively** (far more controllers surface), that hard slam fires for almost every real estate and
> gives a vague, hard-to-justify reason. Graduate it: **Critical only when justified**, with a **counted,
> composed reason** so every Critical comes with its receipts. Ships with the enrichment fix as v2.29.0.

## 1. Problem (validated against a real 6,069-account export, post-enrichment-fix)
The v2.28.0 gate: `t0Reachable ≥ 1 → Critical, reason "Tier-0 Reachable"`. With the *first-degree* enrichment
bug this rarely fired (the real audit detected **1** Tier-0 controller). With the transitive-enrichment fix
it now detects **13** controllers / **7 reachable** — so the hard slam fires broadly, and the reason
("Tier-0 Reachable") reads as an opaque tripwire. **Operator principle (owner):** "I don't mind saying
something is Critical, but we have to justify it. If we can't provide good accurate data, we get ignored."
An unjustified blanket-Critical erodes trust with the audited org exactly when the finding is real.

## 2. Approach — graduate by accumulation; justify with a counted reason
A single *compromised* Tier-0 controller is **really bad but not the absolute worst** — call it **High Risk**.
Reserve **Critical** for accumulation that an org will believe. (The gate already requires "compromised
first": `t0Reachable` only counts controllers whose credential is *obtainable* — cracked / HIBP / shared-DA
/ mass-reuse — via the existing `reachable()`. A clean uncracked admin never trips it.)

**Critical iff** `t0Reachable ≥ 2` **OR** (`t0Reachable ≥ 1` AND reachable `da ≥ 1`); a **lone** reachable
Tier-0 controller (no 2nd, no DA path) → **High Risk**. Every Tier-0 verdict carries a reason that **states
the composition with counts** — the "describe how we reached this" requirement.

### 2.1 Verdict gate (precedence — first match wins)
`gateVerdict` gains the reachable-DA count `da` (already computed by `breachReachability`):
```
1. active==0 && t0Reachable==0           → "No Data"
2. t0Reachable ≥ 2                        → "Critical",  reason "N reachable Tier-0 controllers"
3. t0Reachable ≥ 1 AND da ≥ 1            → "Critical",  reason "1 reachable Tier-0 controller + N reachable DA pathway(s)"
4. t0Reachable == 1                       → "High Risk", reason "1 reachable Tier-0 controller — one compromised account reaches domain-control"
5. Reachability band == "Very High"       → "Critical",  reason "multiple reachable domain-control paths"
6. Reachability band == "High"            → "High Risk", reason "a reachable path to domain-control exists"
7. else (Med/Low band)                    → hygiene-derived: Strong→"Sound" · Fair→"Guarded" · Weak→"Elevated"
```
Rules 2-4 take precedence over the generic band rules 5-6, so the Tier-0 case is decided exactly by the
owner's rule and the reason names the count. Pluralize correctly ("1 controller" vs "N controllers", "1
DA pathway" vs "N DA pathways"). The reason strings are first-class (`verdict_reason`), already surfaced on
the card / sanitized export / HTML report.

### 2.2 Reachability band (display) — unchanged
`L` still includes the Tier-0 enabler (`p_t0=0.70`) so the **Reachability** component band stays coherent
with the verdict (lone Tier-0 → L≈0.70 → High band ↔ High Risk; 2+ → Very High ↔ Critical). The band is a
component; the **verdict** is the gated headline driven by §2.1. (Precedence rule 4 caps a lone Tier-0 at
High Risk even if `L` is independently Very High from critN — matching the owner's rule; in practice a lone
Tier-0 with `da==0` can't reach Very High via critN alone since critN is capped at 5 → L≤0.56.)

### 2.3 The "no false Sound" guarantee survives
A lone reachable Tier-0 is now **High Risk** (not Critical), but still never **Sound/Strong** — the
contradiction-proofing the v2.28.0 rework was built for is intact (a reachable domain-control path always
yields ≥ High Risk).

## 3. Validation (real export `patd_sanitized_5.json`, v2.28.0-11-gb8c08e2)
- `t0Reachable = 7`, reachable `da = 7` → **Critical** under both gates — but the reason upgrades from the
  opaque "Tier-0 Reachable" to **"7 reachable Tier-0 controllers"** (justified, specific). The 7 are cracked
  accounts each controlling 2,542–16,778 objects with DA paths — genuinely Critical, and now *defensible*.
- The softening only changes the *lone-controller* estate (1 reachable Tier-0, no 2nd, no DA) → **High Risk**.
  This estate doesn't qualify for softening because it's legitimately dire — so we lose nothing here and
  gain credibility on the estates where the old hard slam was over-claiming.

## 4. Files
- **Go:** `internal/model/model.go` — `gateVerdict(hygieneRating, band string, t0, da, active int)` (add
  `da`; implement §2.1, with a small `pluralize`/count helper for the reason strings); `PostureScore`
  passes the `da` it already gets from `breachReachability`. Tests: `internal/model/model_test.go`
  (`TestGateVerdict` cases + golden fixture additions).
- **Web:** `web/src/insights.ts` — mirror `gateVerdict` exactly (same precedence, same reason strings,
  same pluralization). The redacted `Account` already carries `controls_tier0`/`da_domains`/`enabled`/
  obtainable flags, so the TS side can recompute `t0`/`da` over the subset.
- **Golden parity:** `internal/model/testdata/posture_golden.json` (+ web copy, kept byte-identical) — add
  cases: lone Tier-0 → High Risk; 2 Tier-0 → Critical "2 reachable Tier-0 controllers"; 1 Tier-0 + 1 DA →
  Critical "1 reachable Tier-0 controller + 1 reachable DA pathway"; confirm existing non-Tier-0 cases
  unchanged. Both Go `TestPostureGolden` and the TS golden assert the same `verdict`/`verdict_reason`.
- No change to `L`, the Reachability band, Hygiene, breach impact, or the enrichment.

## 5. Testing
- **Unit (Go + TS parity):** the §2.1 precedence table, exact reason strings + pluralization, the lone-Tier-0
  High-Risk cap vs the 2+/1+DA Critical, and the "no Sound while reachable" invariant. Reuse the shared
  golden fixture so Go and TS produce byte-identical verdict+reason.
- **Gates:** `gofmt -l cmd internal`, `go build/vet/test ./...`, `govulncheck`; web `tsc`/`vitest`/`build`.
- **Live (owner):** re-export; confirm the verdict reads **Critical — "7 reachable Tier-0 controllers"**
  (specific & justified), and sanity-check the 7 controllers are real crown jewels, not transitive
  over-reach through a noisy anchor (e.g. `Administrators`).

## 6. Definition of done
The executive verdict reserves **Critical** for `≥2` reachable Tier-0 controllers OR `1 Tier-0 + a reachable
DA path`; a lone reachable Tier-0 reads **High Risk**; every Tier-0 verdict carries a **counted, composed**
reason. The "no Sound while a domain-control path is reachable" guarantee holds. Go⇄TS parity pinned by
golden cases. Per-account scoring, Reachability band, Hygiene, and the enrichment are unchanged. Ships with
the BloodHound transitive-enrichment fix as **v2.29.0**.
