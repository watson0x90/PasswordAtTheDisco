# Per-account Breakdown & Vector Completeness (sub-project C) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface, persist, and re-sync every per-account scoring signal so the AccountDrawer and the risk vector are complete and self-consistent — with **no change to any scoring formula**.

**Architecture:** Five surfacing/persistence fixes from the 2026-06-22 completeness sweep: persist two dropped `pwanalysis` signals (#5), sync the shared-DA escalation into the breakdown (#3), add two risk-vector tokens (#9), and render Tier-0 + decomposed-weakness + policy-violations in the drawer (#1/#2/#5-UI). Exposure/Impact *values* are untouched; we only expose data already computed and make stored fields agree with each other.

**Tech Stack:** Go 1.26 stdlib (`internal/model`, `internal/engine`, `internal/risk`), React 18 + TS (`web/src/components/AccountDrawer.tsx`, `web/src/api.ts`, `web/src/glossary.ts`).

**Spec:** `docs/superpowers/specs/2026-06-22-breakdown-vector-completeness-design.md`

**Branch discipline (every task):** confirm `git branch --show-current` == `feature/breakdown-vector-completeness`; NEVER run `git checkout`/`git switch`. Commit on that branch only. Web rule: NEVER `npm install`/`npm ci`; use `npx tsc --noEmit` / `npx vitest run` only. Don't use `git commit --no-verify`.

---

## File Structure

- **Modify** `internal/model/model.go` — add `ContainsUnicode bool` + `PolicyViolations []string` to `Account`; sync `ScoreBreakdown.ImpactScore` in `EscalateSharedWithDA`.
- **Modify** `internal/model/model_test.go` — round-trip + Redacted-survival; escalation-sync test.
- **Modify** `internal/engine/engine.go` — set the two new fields in `scoreCracked`.
- **Modify** `internal/risk/risk.go` — `tier0Code`, `roastableCode`, two new `Vector()` tokens.
- **Modify** `internal/risk/risk_test.go` — vector golden updates.
- **Modify** `web/src/api.ts` — `Account` gains `contains_unicode?`, `policy_violations?`.
- **Modify** `web/src/components/AccountDrawer.tsx` — Tier-0 row, decomposed weakness rows, escalation note, policy-violation list, unicode flag, stale-comment fix.
- **Create** `web/src/coverageDrawer.ts` (small pure helpers) **OR** put helpers inline + test — see Task 4.
- **Modify** `web/src/glossary.ts` — `RO:`/`T0:` token docs if it enumerates vector tokens.

---

## Task 1: Persist `ContainsUnicode` + `PolicyViolations` (#5 backend + contract)

**Files:**
- Modify: `internal/model/model.go` (Account struct, near the wordlist weakness block ~lines 173-185)
- Modify: `internal/engine/engine.go` (`scoreCracked` returned literal, near `KeyboardPatterns: an.KeyboardPatterns` ~line 362)
- Modify: `web/src/api.ts` (`Account` interface, near `keyboard_pattern_count?`)
- Test: `internal/model/model_test.go`

- [ ] **Step 1: Write the failing test** — both fields round-trip through JSON and survive `Redacted()`.

```go
// internal/model/model_test.go
func TestUnicodeAndPolicyViolationsRoundTripAndSurviveRedaction(t *testing.T) {
	a := Account{
		Username: "u", Domain: "CORP",
		Password: "s3cret", NTHash: "ABCD",
		ContainsUnicode:  true,
		PolicyViolations: []string{"No uppercase", "Length < 14"},
	}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var got Account
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !got.ContainsUnicode || len(got.PolicyViolations) != 2 || got.PolicyViolations[0] != "No uppercase" {
		t.Fatalf("lost on round-trip: %+v", got)
	}
	red := a.Redacted()
	if !red.ContainsUnicode || len(red.PolicyViolations) != 2 {
		t.Fatalf("ContainsUnicode/PolicyViolations must survive Redacted() (non-secret descriptors)")
	}
	if red.Password != "" || red.NTHash != "" {
		t.Fatalf("Redacted() must still strip Password/NTHash")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/model/ -run TestUnicodeAndPolicy -v`
Expected: FAIL — `unknown field ContainsUnicode in struct literal of type Account`.

- [ ] **Step 3: Add the fields.** In `internal/model/model.go`, after the wordlist weakness block (after `KeyboardPatterns []string ...`, ~line 185) insert:

```go
	// ContainsUnicode flags a cracked password containing non-ASCII runes; PolicyViolations
	// is the list of failed policy rules ("No uppercase", "Length < 14"). Both are descriptive
	// (reveal nothing beyond the already-exposed length/complexity) -- not credentials -- so
	// they survive Redacted().
	ContainsUnicode  bool     `json:"contains_unicode,omitempty"`
	PolicyViolations []string `json:"policy_violations,omitempty"`
```

`Account.Redacted()` only zeroes Password/NTHash/BannedWords/KeyboardPatterns, so these survive unchanged — no edit to `Redacted()`. The test asserts this. Do NOT touch `Redacted()`.

- [ ] **Step 4: Set them in `scoreCracked`.** In `internal/engine/engine.go`, in the `model.Account{...}` returned by `scoreCracked`, next to `KeyboardPatterns: an.KeyboardPatterns,` (~line 362) add:

```go
		ContainsUnicode:  an.ContainsUnicode,
		PolicyViolations: an.PolicyViolations,
```

(`an` is the `pwanalysis.Analyze(...)` result built at engine.go:255; it has `ContainsUnicode bool` and `PolicyViolations []string` — confirm at pwanalysis.go:106-107. `scoreUncracked` leaves both zero — password unknown.)

- [ ] **Step 5: Add the TS contract.** In `web/src/api.ts`, in the `Account` interface near `keyboard_pattern_count?: boolean`, add:

```ts
  contains_unicode?: boolean
  policy_violations?: string[]
```

- [ ] **Step 6: Run tests + typecheck to verify they pass**

Run: `go test ./internal/model/ ./internal/engine/ -v` → PASS
Run: `cd web && npx tsc --noEmit` → clean

- [ ] **Step 7: Commit**

```bash
test "$(git branch --show-current)" = "feature/breakdown-vector-completeness"
git add internal/model/model.go internal/model/model_test.go internal/engine/engine.go web/src/api.ts
git commit -m "feat(model): persist ContainsUnicode + PolicyViolations (surface dropped analysis signals)"
```

---

## Task 2: Sync `ScoreBreakdown.ImpactScore` on shared-DA escalation (#3)

**Files:**
- Modify: `internal/model/model.go` (`EscalateSharedWithDA`, ~lines 335-350)
- Test: `internal/model/model_test.go`

- [ ] **Step 1: Write the failing test** — an escalated account's breakdown Impact agrees with its `ImpactScore`.

```go
// internal/model/model_test.go
func TestEscalateSharedWithDASyncsBreakdownImpact(t *testing.T) {
	da := Account{Username: "admin", Domain: "CORP", NTHash: "AA", DADomains: "CORP.LOCAL",
		Cracked: true, ImpactScore: ptr10(), ImpactKnown: true}
	victim := Account{Username: "bob", Domain: "CORP", NTHash: "AA", Cracked: true,
		ScoreBreakdown: &ScoreBreakdown{ImpactScore: 3.0, PrivilegeSubScore: 1.0}}
	accts := []Account{da, victim}
	EscalateSharedWithDA(accts)
	// bob shares NT hash AA with a DA-pathway account -> Impact forced to 10.
	var bob Account
	for _, a := range accts {
		if a.Username == "bob" {
			bob = a
		}
	}
	if bob.ImpactScore == nil || *bob.ImpactScore != 10 {
		t.Fatalf("victim ImpactScore = %v, want 10", bob.ImpactScore)
	}
	if bob.ScoreBreakdown == nil || bob.ScoreBreakdown.ImpactScore != 10 {
		t.Fatalf("breakdown ImpactScore must be synced to 10, got %v", bob.ScoreBreakdown)
	}
}

func ptr10() *float64 { v := 10.0; return &v }
```

> Implementer: confirm `EscalateSharedWithDA`'s exact escalation predicate (it escalates accounts that share an NT hash with a DA-pathway account and don't already have their own DA pathway — model.go ~307-330). Adjust the fixture if needed so `bob` is actually escalated (same NT hash as a DA account; bob has no own DADomains). If `ptr10` collides with an existing helper, reuse the existing one.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/model/ -run TestEscalateSharedWithDASyncs -v`
Expected: FAIL — breakdown ImpactScore is still 3.0 (not synced).

- [ ] **Step 3: Implement the sync.** In `EscalateSharedWithDA`, right after the existing
`max := 10.0; a.ImpactScore = &max; a.ImpactKnown = true` block (~model.go:347-349), add:

```go
		if a.ScoreBreakdown != nil {
			a.ScoreBreakdown.ImpactScore = max
		}
```

(Exposure side intentionally untouched — escalation is an Impact event. Nil-guarded because an
escalated account could in principle lack a breakdown.)

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/model/ -v` → PASS (this test + all existing escalation tests)

- [ ] **Step 5: Commit**

```bash
test "$(git branch --show-current)" = "feature/breakdown-vector-completeness"
git add internal/model/model.go internal/model/model_test.go
git commit -m "fix(model): sync ScoreBreakdown.ImpactScore on shared-DA escalation (breakdown no longer contradicts the headline 10)"
```

---

## Task 3: Add `RO:` (roastable) + `T0:` (Tier-0) risk-vector tokens (#9)

**Files:**
- Modify: `internal/risk/risk.go` (`Vector` ~line 402; add two helper funcs near `controlledCode`/`shareCode`)
- Test: `internal/risk/risk_test.go` (`TestVectorV2` goldens ~lines 266-280, plus any other vector golden)

- [ ] **Step 1: Update the failing golden first (TDD).** In `internal/risk/risk_test.go`, edit the two expected vector strings in `TestVectorV2` to include the new tokens in their positions: `T0:` immediately after `CO:`, `RO:` immediately after `S:`. For `strong()` with no SPN/AS-REP/Tier-0 both are `N`:

```go
	// first golden (cracked, coverage none): insert /T0:N after CO:U and /RO:N after S:0
	if want := "C:C1/L:VL/D:N/SM:N/CM:U/EX:U/DA:N/CO:U/T0:N/S:0/RO:N/DR:U/HIBP:N/EXP:L/IMP:U"; got != want {
		t.Fatalf("vector = %q, want %q", got, want)
	}
	// second golden (coverage full, CO:H, DR:C): insert /T0:N after CO:H and /RO:N after S:0
	if want := "C:C1/L:VL/D:N/SM:N/CM:U/EX:U/DA:N/CO:H/T0:N/S:0/RO:N/DR:C/HIBP:N/EXP:L/IMP:C"; got != want {
		t.Fatalf("vector = %q, want %q", got, want)
	}
```

> Implementer: also grep `internal/risk/risk_test.go` and the engine/report tests for any OTHER hard-coded vector string (e.g. `grep -rn "EXP:" internal`) and update each to the new token order. There may be more than `TestVectorV2`.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/risk/ -run TestVectorV2 -v`
Expected: FAIL — got string lacks `/T0:N` and `/RO:N`.

- [ ] **Step 3: Add the helpers + tokens.** In `internal/risk/risk.go`, add near the other `*Code` helpers:

```go
// tier0Code marks an account that controls a Tier-0 / DA-equivalent asset (forces
// privilege=10). The CO: code can read CO:U/CO:L for a Tier-0 controller with a small
// controlled-object count, so T0: is the unambiguous signal.
func tier0Code(c Context) string {
	if c.ControlsTier0 {
		return "Y"
	}
	return "N"
}

// roastableCode encodes Kerberoast (SPN) / AS-REP roastability, the +0.5 Exposure bumps
// that otherwise have no vector token. K=SPN only, A=AS-REP only, KA=both, N=neither.
func roastableCode(c Context) string {
	spn := boolOrFalse(c.HasSPN)
	asrep := boolOrFalse(c.DontReqPreauth)
	switch {
	case spn && asrep:
		return "KA"
	case spn:
		return "K"
	case asrep:
		return "A"
	default:
		return "N"
	}
}
```

(Confirm `boolOrFalse(*bool) bool` exists in this package — it's used by the scorer; if the field
names on `Context` differ, match them. `Context.ControlsTier0` is a `bool`, `HasSPN`/`DontReqPreauth`
are `*bool`.)

Then in `Vector()`'s `parts` slice insert the two tokens in the documented positions:

```go
		"CO:" + controlledCode(c.ControlledObjects),
		"T0:" + tier0Code(c),
		"S:" + shareCode(c.SharedWith),
		"RO:" + roastableCode(c),
		"DR:" + domainCode(c.DomainRiskLevel),
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/risk/ ./internal/engine/ ./internal/model/ -v` → PASS (all vector goldens green)

- [ ] **Step 5: Commit**

```bash
test "$(git branch --show-current)" = "feature/breakdown-vector-completeness"
git add internal/risk/risk.go internal/risk/risk_test.go
git commit -m "feat(risk): add RO: (roastable) and T0: (Tier-0) risk-vector tokens"
```

---

## Task 4: AccountDrawer — Tier-0, decomposed weakness, escalation note, policy violations, unicode (#1,#2,#5-UI,#3-UI) + token docs

**Files:**
- Create: `web/src/drawerFactors.ts` — pure helpers (tested)
- Test: `web/src/drawerFactors.test.ts`
- Modify: `web/src/components/AccountDrawer.tsx`
- Modify: `web/src/glossary.ts` (if it enumerates vector tokens — add `RO:`/`T0:`)

- [ ] **Step 1: Write the failing pure-logic test** for the display helpers.

```ts
// web/src/drawerFactors.test.ts
import { describe, expect, it } from "vitest"
import type { Account, ScoreBreakdown } from "./api"
import { weaknessSubFactors, policyViolationText } from "./drawerFactors"

const bd = (o: Partial<ScoreBreakdown>): ScoreBreakdown => ({
  exposure_score: 0, weakness_score: 0, hibp_floor: 0, cracked_floor: 0, reuse_bump: 0,
  roastable_bump: 0, impact_score: 0, privilege_sub_score: 0, da_component: 0,
  domain_modifier: 0, ...o,
})

describe("weaknessSubFactors", () => {
  it("returns only the non-zero sub-penalties, labeled", () => {
    const got = weaknessSubFactors(bd({ length_penalty: 1.2, complexity_penalty: 0, dict_penalty: 3, sim_penalty: 0 }))
    expect(got).toEqual([["Length", 1.2], ["Dictionary", 3]])
  })
  it("returns [] when no breakdown / all zero", () => {
    expect(weaknessSubFactors(undefined)).toEqual([])
    expect(weaknessSubFactors(bd({}))).toEqual([])
  })
})

describe("policyViolationText", () => {
  it("joins the failed rules when policy not met", () => {
    const a = { meets_policy: false, policy_violations: ["No uppercase", "Length < 14"] } as Account
    expect(policyViolationText(a)).toBe("No — No uppercase · Length < 14")
  })
  it("plain No when no detail; Yes when met", () => {
    expect(policyViolationText({ meets_policy: false } as Account)).toBe("No")
    expect(policyViolationText({ meets_policy: true } as Account)).toBe("Yes")
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd web && npx vitest run drawerFactors` → FAIL (module not found)

- [ ] **Step 3: Implement the helpers.**

```ts
// web/src/drawerFactors.ts
import type { Account, ScoreBreakdown } from "./api"

// weaknessSubFactors decomposes the Exposure "Weakness" bar into its persisted sub-penalties,
// returning only the non-zero ones (omitempty zeros are not informative).
export function weaknessSubFactors(bd: ScoreBreakdown | undefined): [string, number][] {
  if (!bd) return []
  const rows: [string, keyof ScoreBreakdown][] = [
    ["Length", "length_penalty"],
    ["Complexity", "complexity_penalty"],
    ["Dictionary", "dict_penalty"],
    ["Similarity", "sim_penalty"],
  ]
  const out: [string, number][] = []
  for (const [label, key] of rows) {
    const x = bd[key]
    if (typeof x === "number" && x > 0) out.push([label, x])
  }
  return out
}

// policyViolationText renders the "Meets policy" value: "Yes", "No", or "No — <rules>".
export function policyViolationText(a: Account): string {
  if (a.meets_policy) return "Yes"
  const v = a.policy_violations
  return v && v.length ? `No — ${v.join(" · ")}` : "No"
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd web && npx vitest run drawerFactors` → PASS

- [ ] **Step 5: Wire the helpers + new rows into AccountDrawer.tsx.**
  1. Import: `import { weaknessSubFactors, policyViolationText } from "../drawerFactors"`.
  2. **#5 (policy):** change the "Meets policy" row (line 59) to `["Meets policy", a.cracked ? policyViolationText(a) : "—"]`.
  3. **#5 (unicode):** add a row after "Weaknesses" (line 63): `...(a.cracked && a.contains_unicode ? ([["Contains Unicode", "Yes ⚠ — non-ASCII characters"]] as [string, ReactNode][]) : [])`.
  4. **#1 (Tier-0 identity row):** add after "Controlled objects" (line 67): `...(a.controls_tier0 ? ([["Controls Tier-0", "Yes ⚠ — DA-equivalent asset"]] as [string, ReactNode][]) : [])`.
  5. **#2 (decomposed weakness):** in the Exposure `BreakdownCard` (lines 111-121), after the `["Weakness", v("weakness_score")]` factor, spread the sub-factors: `...weaknessSubFactors(bd).map(([label, val]) => [`· ${label}`, val] as [string, number])`. (The leading "· " visually nests them under Weakness; reuse the card's existing factor rendering — confirm `BreakdownCard`'s `factors` prop type accepts `[string, number][]`.)
  6. **#1 (Tier-0 in Impact card):** in the Impact `BreakdownCard` factors (lines 131-135), append `...(a.controls_tier0 ? [["Tier-0 control", 10] as [string, number]] : [])` and/or a note; simplest: add a `bd`/`a.controls_tier0` note under the card (next to the enabled-gated note, line 151): `{a.controls_tier0 && <p className="bd-note">Privilege pinned to 10 — controls a Tier-0 / DA-equivalent asset.</p>}`.
  7. **#3 (escalation note):** add next to the enabled-gated note: `{a.escalated_by_shared_da && <p className="bd-note">Impact forced to 10 — shares a password with a Domain-Admin account.</p>}`.
  8. **Stale comment:** fix the comment at line ~108 — replace "the Go scoreUncracked path emits no score_breakdown" with the truth: uncracked accounts DO carry a breakdown (engine.go:449-470); the Exposure card still gates on `bd` which is present for them.

  Use ONLY existing classes (`bd-note`, `badge`, `drawer-row`, etc.) — no inline spacing styles (styleguard). Do not change `BreakdownCard`'s component beyond what its existing `factors: [string, number][]` API allows; if a string-label factor needs different rendering, prefer adding rows via the existing mechanism rather than restyling.

- [ ] **Step 6: Token docs.** Grep `web/src/glossary.ts` and `web/src/components/help/` for where the risk-vector tokens are enumerated. If `glossary.ts` (or a Help scoring chapter) lists tokens like `CO:`/`DA:`, add `RO:` (roastable: K/A/KA/N) and `T0:` (Tier-0: Y/N) entries so the legend matches `Vector()`. If no such enumeration exists, skip (note it in the report).

- [ ] **Step 7: Run gates + commit**

Run: `cd web && npx tsc --noEmit && npx vitest run` → clean + all green
```bash
test "$(git branch --show-current)" = "feature/breakdown-vector-completeness"
git add web/src/drawerFactors.ts web/src/drawerFactors.test.ts web/src/components/AccountDrawer.tsx web/src/glossary.ts
git commit -m "feat(web): drawer surfaces Tier-0, decomposed weakness, escalation reason, policy violations, unicode"
```

---

## Task 5: Whole-of-C verification

**Files:** none (verification only)

- [ ] **Step 1: Full backend gates.**

Run: `gofmt -l cmd internal` → empty
Run: `go build ./... && go vet ./... && go test ./...` → all PASS (scoring goldens unchanged in value, vector goldens updated)
Run: `govulncheck ./...` → clean

- [ ] **Step 2: Full frontend gates.**

Run: `cd web && npx tsc --noEmit && npx vitest run && npm run build` → clean

- [ ] **Step 3: Live verification (build-and-run skill, then Playwright at `http://127.0.0.1:8443`).**
  Seed/open an audit with (a) a cracked policy-failing password (e.g. a short lowercase one), (b) ideally a BloodHound-enriched Tier-0 / shared-DA account if available; otherwise verify what the data allows. Open the AccountDrawer and confirm:
  - the **Meets policy** row lists the failed rules; a unicode password shows the "Contains Unicode" flag;
  - the **Exposure** breakdown card shows the decomposed weakness sub-rows;
  - a **shared-DA escalated** account's Impact card shows the "forced to 10" note (not stale sub-scores) and the headline Impact == 10 matches;
  - a **Tier-0** account shows the Tier-0 rows + `T0:Y` in the risk vector; a roastable account shows `RO:K|A|KA`.
  - Assert the browser console has no 4xx/error noise.

- [ ] **Step 4: Confirm no secret leakage.** Grep that the new fields/vector never carry a password or NT hash: inspect a redacted `/api/accounts` payload (or a unit assertion) — `policy_violations` contain only rule names; no cleartext.

- [ ] **Step 5: Report evidence** (gate output + drawer screenshots). No commit; proceed to the final whole-branch review, then finishing-a-development-branch.

---

## Self-Review notes (for the controller)

- **Spec coverage:** #5 persist → Task 1; #3 sync → Task 2; #9 vector → Task 3; #1 Tier-0 + #2 weakness + #5-UI + #3-UI note + stale comment + token docs → Task 4; verification → Task 5. All spec §2 items mapped.
- **No formula change:** Tasks only surface/persist/sync already-computed values; Exposure/Impact scoring goldens must stay green unchanged (only the *vector string* goldens change, Task 3).
- **Type consistency:** `weaknessSubFactors`/`policyViolationText` defined in Task 4 Step 3 and consumed in Step 5; `contains_unicode?`/`policy_violations?` defined in Task 1 (api.ts) and read in Task 4; `tier0Code`/`roastableCode` defined and used in Task 3; `ScoreBreakdown.ImpactScore` synced in Task 2 matches the field read by the drawer Impact card.
- **Placeholder honesty:** Task 2's escalation fixture and Task 3's "grep for other vector goldens" + Task 4's glossary-enumeration check are flagged as verify-against-real-code steps (the exact escalation predicate, the full set of hard-coded vector strings, and whether glossary lists tokens are things to confirm in-repo, not invent).
