# Scoring Model Coverage — backlog (seed for sub-project F)

> Output of the 2026-06-22 expert scoring review (red-team / mathematics / scoring-framework
> lenses) over the complete scoring system. The review **endorsed sub-project D** (semantics
> fixes) but surfaced these **attacker-primitive gaps in the EXISTING model** — new scoring
> *factors*, not semantics. Decision: build them as **sub-project F**, AFTER C→D→E→B and the
> tag, each with a feasibility check (some need data we may not ingest yet). This file is the
> seed for F's brainstorm — do NOT treat as an approved spec.

## Gaps (ranked by the red-team review)

1. **Kerberos delegation is entirely unscored (highest severity).** Unconstrained /
   constrained-with-protocol-transition / RBCD are direct or near-direct DA-compromise paths
   the model currently scores as ordinary object control — "a Critical account could score
   Medium." Proposal: treat unconstrained delegation on a non-Tier-0 host as Tier-0-equivalent
   Impact (privilege→10), gated like `ControlsTier0`. **Feasibility:** needs the delegation
   flags (`TrustedForDelegation`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, `AllowedToDelegate`)
   in the BloodHound/ingest feed — verify they're collected before committing.

2. **Roastable & reuse are flat/binary (under-weighted).** Today `SPN || AS-REP → +0.5`
   Exposure and `SharedWith>0 → +0.5` Exposure. A Kerberoastable account with a crackable RC4
   ticket is a top offline-escalation primitive; AS-REP-roast is independently severe; reuse
   across 500 accounts is a spray-once-own-everything event scored the same as 1 reuse.
   Proposal: tier roastability (SPN +0.5, AS-REP +0.5, both +1.0; gate higher if also stale/
   never-expires) and scale the reuse bump by the existing log10 `shareCode` magnitude (the
   vector already computes it; the score discards it). **Feasibility:** data already present
   (HasSPN/DontReqPreauth/SharedWith) — low risk, mostly a weighting change. Coordinate with
   sub-project C's `RO:` vector token.

3. **Disabled-cap lull.** A disabled account whose hash is reused on an enabled/DA account, or a
   cracked disabled admin (re-enable persistence, Silver/Golden-ticket material), can render as
   Impact 2 / Low. The shared-DA escalation DOES still fire for disabled accounts (it keys on
   hash, not Enabled — confirmed in the review), but a distinct "disabled-but-reused/crackable"
   flag would stop the cap from making a genuinely dangerous credential look benign.
   **Feasibility:** data present — low risk.

4. **Credential age (`pwdLastSet`) is carried for the vector only, not scored.** A 6-year-old
   service password protected by RC4 is materially more crackable; today it contributes 0 to
   Exposure. **Feasibility:** `PwdLastSet` is already ingested; a bounded age→Exposure signal is
   straightforward. (Note: it's an Exposure signal — keep it credential-intrinsic.)

5. **LM-hash / reversible-encryption presence is unscored.** If the dump carries LM hashes or
   `UF_ENCRYPTED_TEXT_PWD_ALLOWED`, that's near-instant compromise — a stronger Exposure floor
   than most HIBP buckets. **Feasibility:** verify the secretsdump parser even surfaces the LM
   field / the UAC flag before committing.

## Notes carried from the review (already folded into D, recorded here for continuity)
- `Breakdown.DomainModifier` must be the pre-cap contribution `base·(factor-1)` (monotone).
- `DR:` vector token → `U` when unenriched (decode-faithful).
- After the percentile change, `RiskScore` is display/back-compat only (vestigial for triage).
