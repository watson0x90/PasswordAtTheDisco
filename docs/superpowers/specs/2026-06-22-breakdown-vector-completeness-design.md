# Per-account Breakdown & Vector Completeness (sub-project C) — Design

> **Sub-project C** of the "scoring & dashboard completeness" effort (C → D → E → B).
> Independent of D/E/B. Came out of the 2026-06-22 completeness sweep (Tier-1 items #1,#2,#3
> + #5, and #9).

**Goal:** Every per-account scoring signal is surfaced and self-consistent — no
computed-but-hidden factor, and no breakdown card that contradicts the headline number.

**Problem it solves:** The completeness sweep found (a) `controls_tier0` persisted but rendered
nowhere; (b) the weakness sub-penalties serialized but collapsed into one bar; (c) a shared-DA
escalated account whose drawer shows Impact 10 while its Impact card shows the *pre-escalation*
sub-scores; (d) `ContainsUnicode` / `PolicyViolations` computed by `pwanalysis` but dropped at
the `model.Account` boundary; (e) the risk vector omitting any token for the roastable bump or
Tier-0 control.

---

## 1. Scope

**In scope (C):**
- **#1** Surface `controls_tier0` in the AccountDrawer.
- **#2** Decompose the Exposure card's "Weakness" into its persisted sub-penalties.
- **#3** Sync `ScoreBreakdown.ImpactScore` on shared-DA escalation + explain it in the drawer.
- **#5** Persist `ContainsUnicode` + `PolicyViolations` on `model.Account`, surface in the drawer.
- **#9** Add `RO:` (roastable) and `T0:` (Tier-0) tokens to the risk vector.
- Fix the stale "uncracked emits no breakdown" comment in `AccountDrawer.tsx`.

**Out of scope:** any change to scoring *formulas* (Exposure/Impact values are unchanged — C
only surfaces, persists, and re-syncs already-computed signals); the percentile basis, the
domain modifier, and the rescore-HIBP guard (sub-project D); dashboard charts (sub-project E).

**Security:** `PolicyViolations` entries are rule names like "No uppercase" / "Length < 14" —
they reveal nothing beyond the already-exposed `password_length` and `complexity`. `ContainsUnicode`
is a boolean weakness flag. Both are descriptive, not credentials → they survive `Redacted()`.
No password/NT-hash is added to any new field, the vector, or the audit log.

---

## 2. Architecture (item by item)

### #5 — Persist the dropped analysis signals (do this first; #1/#2 build on the data)
`pwanalysis.Analysis` already carries `PolicyViolations []string` (pwanalysis.go:106) and
`ContainsUnicode bool` (pwanalysis.go:107); `scoreCracked` builds it as `an` (engine.go:255)
but never copies these two to `model.Account`.
- Add to `model.Account`: `ContainsUnicode bool \`json:"contains_unicode,omitempty"\`` and
  `PolicyViolations []string \`json:"policy_violations,omitempty"\``, placed near the wordlist
  weakness signals (`IsCommon`/`BannedWordCount`).
- In `scoreCracked`'s returned literal, set `ContainsUnicode: an.ContainsUnicode` and
  `PolicyViolations: an.PolicyViolations`. (`scoreUncracked` leaves both zero — password unknown.)
- `Redacted()` is unchanged (it only zeroes Password/NTHash/BannedWords/KeyboardPatterns); a new
  bool + a non-secret string slice survive by value. Add a test asserting both survive `Redacted()`.
- TS: add `contains_unicode?: boolean` and `policy_violations?: string[]` to the `Account`
  interface in `web/src/api.ts`.

### #3 — Escalation breakdown sync (Go, `EscalateSharedWithDA`)
At model.go:~347, after `max := 10.0; a.ImpactScore = &max; a.ImpactKnown = true`, also:
```go
if a.ScoreBreakdown != nil {
    a.ScoreBreakdown.ImpactScore = max
}
```
This makes `Account.ImpactScore` (10) and `ScoreBreakdown.ImpactScore` agree for shared-DA
accounts. (Exposure side is intentionally untouched — escalation is an Impact event; the
legacy `RiskScore=9.0` blend is also left as-is.) An escalated account may be uncracked; uncracked
accounts DO carry a breakdown (engine.go:453), but guard nil anyway for safety. Add a test:
an account escalated by `EscalateSharedWithDA` has `ScoreBreakdown.ImpactScore == 10`.

### #9 — Vector tokens (Go, `risk.Vector`)
Add two tokens to the `parts` slice in `Vector()` (risk.go:402). `Context` already carries
`HasSPN`, `DontReqPreauth`, `ControlsTier0`.
- `T0:` immediately after `CO:` (privilege/Impact cluster): `tier0Code(c)` → `"Y"` if
  `c.ControlsTier0` else `"N"`.
- `RO:` immediately after `S:` (Exposure-bump cluster): `roastableCode(c)` →
  `"K"` (SPN/Kerberoastable only), `"A"` (AS-REP only), `"KA"` (both), `"N"` (neither).
- New token order: `… DA:_/CO:_/T0:_/S:_/RO:_/DR:_/HIBP:_/EXP:_/IMP:_`.
- Update the two golden strings in `TestVectorV2` (risk.go_test:266-278) to include the new
  tokens (TDD: change the expectation first, watch it fail, add the tokens). Re-derive any other
  vector golden in `risk_test.go`.

### #1 — Surface `controls_tier0` (UI, AccountDrawer)
- Add a Tier-0 row to the identity `<dl>` (near "Controlled objects"): "Controls Tier-0 — yes"
  when `a.controls_tier0`.
- In the **Impact** `BreakdownCard` (AccountDrawer.tsx:128-136), when `a.controls_tier0`, add a
  factor row "Tier-0 control — yes" and a short note that it pins Privilege to 10 (it's why
  `privilege_sub_score` is maxed). Only shown when true (un-enriched accounts have it false/absent).

### #2 — Decompose the Weakness bar (UI, AccountDrawer)
The Exposure `BreakdownCard` (AccountDrawer.tsx:111-121) lists "Weakness" as one factor reading
`weakness_score`. Expand it to also show the persisted sub-penalties — `length_penalty`,
`complexity_penalty`, `dict_penalty`, `sim_penalty` — as nested/indented rows under Weakness,
rendering **only the non-zero** ones (they `omitempty` out for uncracked / strong passwords).
Use the existing `v("…")` safe-accessor (coalesces undefined→0). No backend change — the four
fields are already in `ScoreBreakdown` (api.ts) and serialized by both score paths.

### #5 (UI) — Surface policy violations + unicode
- Expand the drawer's "Meets policy" row: when `meets_policy` is false and
  `policy_violations?.length`, render the failed rule names (e.g. a compact list "No uppercase ·
  Length < 14"). When the array is absent (older audits), keep today's plain "no".
- Add "Contains Unicode" to the weakness-flags row (the `is_common`/`is_dictionary_word`/… group)
  when `a.contains_unicode`.

### Stale-comment fix (UI)
Update the AccountDrawer comment at line ~108 ("the Go scoreUncracked path emits no
score_breakdown") — it is wrong (engine.go:449-470 emits a full breakdown for uncracked). The
gating on `bd` still works (bd is present for uncracked); just correct the comment so the next
reader isn't misled.

### Glossary / Help
Add `RO:` and `T0:` to wherever the risk-vector tokens are documented (the drawer "Risk vector"
tooltip / `glossary.ts` / the Help scoring chapter if it enumerates tokens). Keep the legend in
sync with `Vector()`.

---

## 3. Files

**Go:**
- `internal/model/model.go` — add `ContainsUnicode` + `PolicyViolations` fields; `EscalateSharedWithDA` breakdown sync.
- `internal/engine/engine.go` — set the two new fields in `scoreCracked`.
- `internal/risk/risk.go` — `roastableCode`, `tier0Code`, two new tokens in `Vector()`.
- Tests: `internal/model/model_test.go` (fields round-trip + survive Redacted; escalation sync),
  `internal/risk/risk_test.go` (vector goldens).

**Web:**
- `web/src/api.ts` — `Account` gains `contains_unicode?`, `policy_violations?`.
- `web/src/components/AccountDrawer.tsx` — #1 Tier-0 rows, #2 weakness sub-rows, #3 escalation
  note, #5 violations + unicode, stale-comment fix.
- `web/src/glossary.ts` (and/or the Help scoring chapter) — `RO:`/`T0:` token docs.
- Tests: a pure-logic test for any new display helper (e.g. a `weaknessSubFactors(bd)` or
  `policyViolationSummary(a)` helper, kept pure and node-env tested).

No new endpoints. No Go scoring-formula change.

## 4. Testing

- **Go:** `ContainsUnicode`/`PolicyViolations` round-trip through JSON and survive `Redacted()`;
  `scoreCracked` populates them for a unicode / policy-failing password; `EscalateSharedWithDA`
  syncs `ScoreBreakdown.ImpactScore` to 10; `Vector()` emits `T0:Y`/`RO:K|A|KA` in the right
  positions (golden updates). All existing scoring goldens still pass (formulas unchanged).
- **Web:** `tsc` + `vitest` green (incl. styleguard — className only, no inline spacing); a
  pure-logic test for the weakness-sub-factor / policy-violation display helpers.
- **Playwright (live):** open the drawer on (a) a Tier-0-controlling enriched account → Tier-0
  row + Impact note; (b) a shared-DA escalated account → Impact card shows the "forced to 10"
  explanation, not stale sub-scores; (c) a cracked policy-failing account → the failed rules
  list + any unicode flag + the decomposed weakness rows. Assert the console is clean.
- **Gates:** `gofmt -l cmd internal`, `go build/vet/test ./...`, `govulncheck`; web `tsc`/`vitest`/`build`.

## 5. Definition of done (C)

The AccountDrawer explains every per-account factor it has data for: the weakness bar breaks
into its sub-penalties, Tier-0 control and roastability are visible (in the card and the vector),
a shared-DA escalated account's Impact card explains the forced 10 instead of contradicting it,
and a policy-failing cracked account lists which rules it broke. `ContainsUnicode` and
`PolicyViolations` are persisted (surviving `Redacted()`). No scoring formula changed; all
goldens green; no new secret leaves the process.
