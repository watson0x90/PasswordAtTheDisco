# Decision: kerberoastable high-privilege accounts stay High without a demonstrated crack

**Date:** 2026-07-01
**Status:** DECIDED — no code change. Documented to prevent re-litigation.
**Area:** `internal/risk/risk.go` (two-axis Exposure×Impact scoring)

## Context

A live account was questioned on the dashboard: it controls a **Tier-0 asset** and has a
**Domain-Admin pathway** (Impact = Critical), is **Kerberoastable** (SPN), but was **not cracked**
in our pass, is **not in HIBP**, and is **not shared/reused**. It is rated **High**.

Risk vector: `.../DA:Y/CO:E/T0:Y/S:0/RO:K/HIBP:N/EXP:L/IMP:C`.

Mechanically: Exposure ≈ 0.5 (just the +0.5 SPN bump → **Low** tier); Impact ≈ 10 (**Critical** tier);
`levelMatrix[Impact-Critical][Exposure-Low]` = **High**. The Critical hard-override
(`daOverride = cracked && has-DA-path`) correctly does **not** fire because the account isn't cracked.

The operator's initial proposal: risk should be grounded **only** in the three *demonstrated*
obtainability factors — **cracked / in-HIBP / shared(reused)** — so an account that is none of these
should not be High/Critical regardless of privilege or attack surface (which would drop this account to
Medium/Low). The operator then reconsidered: a kerberoastable account's **hash is obtainable** (any
authenticated principal requests the TGS and cracks the password-derived key **offline**, on their own
clock), so "not cracked in our finite pass" is not evidence the credential is safe — and asked a panel
to reach consensus.

## Panel

Four independent expert lenses (opus subagents): **Red Team**, **Mathematician / decision-theory**,
**Blue Team**, **CISO**. Each was given the same neutral brief and steelmanned the opposing view.

## Decision

**Leave the scoring as-is. The account is correctly High.** Unanimous (4/4) verdict: **High** — not
Critical (no *demonstrated* compromise), not Medium/Low (Tier-0/DA + a real, self-service offline path).

### Why (consensus reasoning)

1. **"Not cracked in our pass" ≠ safe.** A negative *finite* crack test is evidence of *some* password
   strength, not `P(compromise) ≈ 0`. The offline attacker has unbounded time/compute against the same
   obtainable hash; our failed pass measures *our* crack budget, not the account's safety. (Treating
   absence-of-a-crack as evidence-of-safety is an estimator/estimand category error.)
2. **Kerberoast is a *partial* obtainability factor** — a genuine obtainability *path* that raises
   `P(compromise)` above baseline (so it legitimately belongs on the Exposure axis), but *probabilistic*
   (bounded by the unknown password strength). It ranks **above** mere attack-surface and **below** the
   three *demonstrated* factors.
3. **The three demonstrated factors gate CRITICAL, not all elevation.** cracked / HIBP / shared are
   *demonstrated* obtainment → they (via the `cracked && DA` override, HIBP/reuse floors, etc.) are what
   may drive **Critical**. Roastability is *attempted/likely* obtainment → it elevates via
   Exposure×Impact and can reach **High**, but must never reach Critical on its own. This *validates* the
   operator's three-factor instinct, correctly scoped to the Critical tier.
4. **Impact-gating already controls noise.** A kerberoastable *low-privilege* account correctly stays
   Low/Medium; roastability alone must never manufacture High. The matrix (`Impact-Critical ×
   Exposure-Low = High`) does exactly this — the crown jewel lands High, a random SPN does not.
5. **Under-rating is worse than over-rating here.** Kerberoasting (MITRE T1558.003) is actively exploited
   against exactly this account shape. Downgrading a Tier-0 account the tool itself flags as roastable,
   on "our wordlist missed it," is textbook negligence in a post-incident/regulator review. Calling it
   Critical would overstate (no demonstrated compromise) and erode tier trust; **High is the defensible
   middle** — catastrophic impact + a named exploitable path + honest uncertainty.
6. **Keep the Kerberoast vs AS-REP asymmetry.** AS-REP (`DontReqPreauth`) is foothold-free → 3.0 Exposure
   floor; Kerberoast needs any authenticated foothold → +0.5 bump. Caveat (noted, not acted on): under an
   assumed-breach posture the foothold gap is smaller than the scoring gap, so Kerberoast is arguably
   *under*-weighted, not over.

Board-facing justification (CISO): *"This account can take over the domain if its password breaks, and
its Kerberos configuration lets any authenticated attacker pull the hash and crack it offline at their
leisure — we have not proven the password is weak, so it is High (remediate), not Critical (proven)."*

## Alternatives considered and rejected

- **Demonstrated-only gate** (only cracked/HIBP/shared may drive High/Critical): **rejected.** It
  conflates *proof* with *likelihood* — the Exposure axis is defined as likelihood — and zeroes the risk
  axis for the exact population adversaries hunt first (Tier-0 roastable SPNs). Coherent only as a
  Neyman-Pearson false-positive-rate calibration, but the Impact axis + matrix already provide that
  discrimination.
- **Give Kerberoast a small Exposure floor (~2–3)** so a roastable Tier-0 credential clears a tier on
  Exposure *merit* rather than solely via the matrix: **deferred (optional polish, not needed).** The
  current level is already correct.
- **Impact-scaled Kerberoast bump** (bump grows with Impact): **deferred (optional polish).** If ever
  pursued, pick *exactly one* of this or the floor — doing both double-counts the incentive coupling.

## Consequences / guidance for future edits

- Do not add a "demonstrated-obtainability-only" gate to the Exposure axis or the level.
- Keep **Critical** reserved for *demonstrated* obtainment (the `cracked && DA` override and the
  HIBP/reuse-based escalations); do not let roastability reach Critical on its own.
- Keep the Kerberoast (bump) vs AS-REP (floor) asymmetry and the Impact-gating that keeps low-privilege
  roastable accounts out of High.
- If a future change strengthens Kerberoast's Exposure weight, use the floor **or** the impact-scaled
  bump, never both.
</content>
