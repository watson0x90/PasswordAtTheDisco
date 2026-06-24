# Tier-0 Verdict Graduation + Exposure Blast-Radius Table — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended)
> or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** (B) Reserve the executive **Critical** verdict for justified Tier-0 accumulation (≥2 reachable
Tier-0 controllers, or 1 + a reachable DA path), with **counted, composed reasons**; a lone reachable
Tier-0 → **High Risk**. (C) Add an Exposure-tab **blast-radius table** of the top object-controllers — the
visible evidence behind the verdict.

**Architecture:** B is the audit-level verdict gate in `internal/model/model.go` + its TS mirror
`web/src/insights.ts`, pinned byte-for-byte by the shared golden fixture. C is pure frontend over the
existing redacted accounts payload. Specs: `…/2026-06-23-tier0-verdict-graduation-design.md` and
`…/2026-06-23-exposure-blast-radius-table-design.md`.

**Tech Stack:** Go 1.26 stdlib; React 18 + TS + Vite. Gates: `gofmt -l cmd internal`, `go build/vet/test`,
`govulncheck`; `cd web` → `npx tsc --noEmit`, `npx vitest run`, `npm run build` (NEVER `npm install`).

**Branch:** `feature/bloodhound-transitive-enrichment` (the v2.29.0 umbrella; A already on it). Every
implementer: confirm `git branch --show-current` == that branch; NEVER `git checkout`/`switch`; NEVER
`git add -A` (stage explicit paths).

---

## File Structure
- `internal/model/model.go` — `gateVerdict` gains `da`, implements the precedence rule + reason strings;
  `PostureScore` passes the `da` it already gets from `breachReachability`.
- `internal/model/model_test.go` — `TestGateVerdict` cases.
- `internal/model/testdata/posture_golden.json` (+ byte-identical `web/src/__fixtures__/` copy) — new/updated
  Tier-0 cases.
- `web/src/insights.ts` — `gateVerdict` mirror; `isReachable` + `topControllers` helpers.
- `web/src/insights.golden.test.ts` — parity assertions on the new cases.
- `web/src/components/Exposure.tsx` (+ optional `BlastRadiusTable.tsx`) — the table.
- `web/src/styles.css` — table classes (CSS tokens only).

---

## Sub-project B — Verdict graduation

### Task B1: Go `gateVerdict` precedence + counted reasons

**Files:** `internal/model/model.go`; Test `internal/model/model_test.go`

- [ ] **Step 1: Write the failing test** — extend `TestGateVerdict`:

```go
func TestGateVerdictTier0Graduation(t *testing.T) {
	cases := []struct {
		name, rating, band            string
		t0, da, active                int
		verdict, reason               string
	}{
		{"2 tier0 -> critical", "Strong", "Very High", 2, 0, 100, "Critical", "2 reachable Tier-0 controllers"},
		{"7 tier0 -> critical counted", "Strong", "Very High", 7, 7, 100, "Critical", "7 reachable Tier-0 controllers"},
		{"1 tier0 + 1 da -> critical", "Strong", "High", 1, 1, 100, "Critical", "1 reachable Tier-0 controller + 1 reachable DA pathway"},
		{"1 tier0 + 3 da -> critical plural", "Strong", "High", 1, 3, 100, "Critical", "1 reachable Tier-0 controller + 3 reachable DA pathways"},
		{"lone tier0 -> high risk", "Strong", "High", 1, 0, 100, "High Risk", "1 reachable Tier-0 controller — one compromised account reaches domain-control"},
		{"no tier0, very-high L -> critical", "Strong", "Very High", 0, 2, 100, "Critical", "multiple reachable domain-control paths"},
		{"no tier0, high L -> high risk", "Fair", "High", 0, 1, 100, "High Risk", "a reachable path to domain-control exists"},
		{"clean strong -> sound", "Strong", "Low", 0, 0, 100, "Sound", ""},
		{"all disabled no t0 -> no data", "No Data", "Low", 0, 0, 0, "No Data", ""},
		{"all disabled but t0>=2 -> critical", "No Data", "Low", 2, 0, 0, "Critical", "2 reachable Tier-0 controllers"},
	}
	for _, c := range cases {
		v, r := gateVerdict(c.rating, c.band, c.t0, c.da, c.active)
		if v != c.verdict || r != c.reason {
			t.Errorf("%s: got %q/%q want %q/%q", c.name, v, r, c.verdict, c.reason)
		}
	}
}
```

- [ ] **Step 2: Run → FAIL** (signature is `gateVerdict(_, _, t0, active)` today; `da` missing).

- [ ] **Step 3: Implement** — replace `gateVerdict`, add the `da` param + a small DA-pluralizer:

```go
func daPathsPhrase(da int) string {
	if da == 1 {
		return "1 reachable DA pathway"
	}
	return fmt.Sprintf("%d reachable DA pathways", da)
}

// gateVerdict: one-register, one-way headline. Critical is reserved for justified Tier-0 accumulation
// (>=2 reachable Tier-0 controllers, or 1 + a reachable DA path); a lone reachable Tier-0 is High Risk.
// Every Tier-0 verdict states its composition (reason), so a Critical always carries its receipts.
func gateVerdict(hygieneRating, band string, t0, da, active int) (verdict, reason string) {
	switch {
	case active == 0 && t0 == 0:
		return "No Data", ""
	case t0 >= 2:
		return "Critical", fmt.Sprintf("%d reachable Tier-0 controllers", t0)
	case t0 >= 1 && da >= 1:
		return "Critical", "1 reachable Tier-0 controller + " + daPathsPhrase(da)
	case t0 >= 1:
		return "High Risk", "1 reachable Tier-0 controller — one compromised account reaches domain-control"
	case band == "Very High":
		return "Critical", "multiple reachable domain-control paths"
	case band == "High":
		return "High Risk", "a reachable path to domain-control exists"
	default:
		switch hygieneRating {
		case "Strong":
			return "Sound", ""
		case "Fair":
			return "Guarded", ""
		default:
			return "Elevated", ""
		}
	}
}
```
Add `"fmt"` to model.go imports if absent. In `PostureScore`, the call site becomes
`gateVerdict(rating, band, t0, da, active)` — `da` is already returned by `breachReachability`
(currently discarded as `_`); capture it. Check BOTH call sites (the `active==0` early-return path and the
normal path) pass `da` (the early path has `da==0` from its `breachReachability` call — fine).

- [ ] **Step 4: Run → PASS**; `go test ./internal/model/ -run TestGateVerdict`.

- [ ] **Step 5: Commit** — `feat(model): graduate Tier-0 verdict (>=2 or 1+DA -> Critical) with counted reasons`.

### Task B2: TS mirror + golden parity (the byte-identical contract)

**Files:** `web/src/insights.ts`; `internal/model/testdata/posture_golden.json` (+ web copy);
`internal/model/model_test.go` (golden); `web/src/insights.golden.test.ts`

- [ ] **Step 1: Mirror `gateVerdict` in `insights.ts`** EXACTLY — same precedence, same reason strings,
  same DA pluralization. The TS `posture()` already computes `da` and `t0` (for L); pass `da` into the
  mirrored `gateVerdict(rating, band, t0, da, active)`. Reason strings must match Go character-for-character
  (e.g. `` `${t0} reachable Tier-0 controllers` ``, `"1 reachable Tier-0 controller + " + daPathsPhrase(da)`,
  the em-dash `—` in the lone-Tier-0 reason). `npx tsc --noEmit` clean.

- [ ] **Step 2: Update the golden fixture** (edit `internal/model/testdata/posture_golden.json`, then
  `cp` it to `web/src/__fixtures__/posture_golden.json` so they stay byte-identical; `TestPostureGoldenFixtureInSync`
  enforces it). Changes:
  - The existing v2.28.0 Tier-0 case (currently expecting `verdict:"Critical", verdict_reason:"Tier-0 Reachable"`)
    now has a DIFFERENT expectation under the new rule — READ that case: if it's a lone reachable Tier-0 (1
    controller, no reachable DA), update its expect to `verdict:"High Risk", verdict_reason:"1 reachable
    Tier-0 controller — one compromised account reaches domain-control"`. If it has a reachable DA too,
    expect `Critical` + the composed reason. Recompute deliberately.
  - ADD cases (construct accounts that yield the counts via `breachReachability` — a reachable Tier-0
    controller = `enabled + cracked + controls_tier0`; a reachable DA = `enabled + cracked + da_domains`):
    - `tier0-two-critical`: 2 reachable Tier-0 controllers → `Critical` / `"2 reachable Tier-0 controllers"`.
    - `tier0-one-plus-da`: 1 reachable Tier-0 controller + 1 reachable DA account → `Critical` /
      `"1 reachable Tier-0 controller + 1 reachable DA pathway"`.
    - `tier0-lone-high-risk`: 1 reachable Tier-0 controller, no reachable DA → `High Risk` / the lone reason.
  - Confirm all NON-Tier-0 cases (Sound/Guarded/Elevated, the L-band High/Very-High ones) are UNCHANGED.

- [ ] **Step 3: Update both golden tests** — Go `TestPostureGolden` and `web/src/insights.golden.test.ts`
  already assert `verdict`/`verdict_reason` from the shared fixture; just ensure they read the new cases.
  Run `go test ./internal/model/` and `cd web && npx vitest run insights` — both green, identical expects.

- [ ] **Step 4: Gates** — `gofmt`, `go test ./...`; `tsc`/`vitest`. Confirm the two fixture files are
  byte-identical (`cmp`).

- [ ] **Step 5: Commit** — `feat(web): mirror graduated Tier-0 verdict + golden cases (Go⇄TS parity)`.

---

## Sub-project C — Exposure blast-radius table

### Task C1: `isReachable` + `topControllers` helpers (pure, tested)

**Files:** `web/src/insights.ts`; Test `web/src/insights.test.ts` (or a new `*.test.ts`)

- [ ] **Step 1: Failing test**

```ts
import { isReachable, topControllers } from "./insights"
// isReachable: enabled && (cracked || hibp_breached || escalated_by_shared_da || escalated_by_mass_reuse)
test("isReachable", () => {
  expect(isReachable({ enabled: true, cracked: true } as any)).toBe(true)
  expect(isReachable({ enabled: true, hibp_breached: true } as any)).toBe(true)
  expect(isReachable({ enabled: false, cracked: true } as any)).toBe(false)
  expect(isReachable({ enabled: true } as any)).toBe(false)
})
test("topControllers: filter >0, sort desc, top N + remaining >100 count", () => {
  const a = (n: number) => ({ controlled_object_count: n } as any)
  const { rows, moreOver100 } = topControllers([a(0), a(5), a(16778), a(101), a(2542), a(150)], 2)
  expect(rows.map(r => r.controlled_object_count)).toEqual([16778, 2542]) // desc, top 2
  expect(moreOver100).toBe(2) // 101 and 150 are >100 and not shown (150,101); 5 is not >100
})
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement** in `insights.ts`:

```ts
export const isReachable = (a: Account): boolean =>
  !!a.enabled && (!!a.cracked || !!a.hibp_breached || !!a.escalated_by_shared_da || !!a.escalated_by_mass_reuse)

export function topControllers(accts: Account[], n: number): { rows: Account[]; moreOver100: number } {
  const controllers = accts.filter(a => (a.controlled_object_count || 0) > 0)
    .sort((x, y) => (y.controlled_object_count || 0) - (x.controlled_object_count || 0)
      || (x.username || "").localeCompare(y.username || "")) // stable tie-break
  const rows = controllers.slice(0, n)
  const moreOver100 = controllers.slice(n).filter(a => (a.controlled_object_count || 0) > 100).length
  return { rows, moreOver100 }
}
```
(If `isReachable` duplicates the existing reachable() used by `posture()`, dedupe to the one exported
helper so the table and the verdict agree.)

- [ ] **Step 4: Run → PASS** (`npx vitest run insights`).

- [ ] **Step 5: Commit** — `feat(web): isReachable + topControllers helpers for the blast-radius table`.

### Task C2: The blast-radius table on the Exposure tab

**Files:** `web/src/components/Exposure.tsx` (+ optional `BlastRadiusTable.tsx`); `web/src/styles.css`

REQUIRED SUB-SKILL: invoke **frontend-design** for the table; verify live with **Playwright** MCP on the
disposable `:8444` instance ONLY (never the owner's `:8443`).

- [ ] **Step 1:** Add a section "Blast radius — accounts controlling the most objects" to `Exposure.tsx`,
  rendering `topControllers(accts, 25)`. Columns per spec C §2: **#**, **Account** (username; row clickable →
  open the existing `AccountDrawer` — read `AccountsTable.tsx` for the open pattern), **Domain**,
  **Controlled objects** (thousands-separated, right-aligned), **Risk** (level badge, app colour tokens),
  **Flags** — small badges: `T0` (controls_tier0), `DA` (`hasDA(da_domains)`), `Crk` (cracked), `RCH`
  (`isReachable(a)`). Footer: when `moreOver100 > 0`, "+{moreOver100} more accounts control >100 objects."
  Empty state (no controllers): muted "No controlled-object data — run BloodHound enrichment to populate."
  CSS tokens only (styleguard test bans literal inline spacing).

- [ ] **Step 2: Gates** — `cd web` → `npx tsc --noEmit`, `npx vitest run` (styleguard green), `npm run build`.

- [ ] **Step 3: Live verify (Playwright, :8444 disposable only):** seed via `tools/dev_seed.sh`; the table
  renders, sorts descending, big controllers on top with correct flags, a row click opens the drawer,
  console has no 4xx/errors; screenshot.

- [ ] **Step 4: Commit** — `feat(web): Exposure blast-radius table (top object-controllers, flagged)`.

---

## After all tasks
Whole-branch review (opus) over A+B+C together. Then superpowers:finishing-a-development-branch → merge to
main + tag **v2.29.0** (one tag for A enrichment fix + B verdict graduation + C blast-radius table) +
README "What's new in 2.29" + CHANGELOG. **PUSH:** v2.28.0 + v2.29.0 push together once the owner gives the
word (history already scrubbed). Owner live-validates: verdict reads "Critical — 7 reachable Tier-0
controllers" and the Exposure table lists the 7 with their object counts.

## Self-review notes
- Spec coverage: B precedence+reasons (B1) + TS parity & golden (B2); C helpers (C1) + table UI (C2). ✓
- Parity risk concentrated in B2 — the reason strings must be byte-identical Go⇄TS; the shared golden
  fixture + fixture-in-sync test catch drift. ✓
- The existing v2.28.0 Tier-0 golden case CHANGES expectation under B — B2 Step 2 calls this out explicitly. ✓
- C is pure frontend over existing data; no endpoint, no new reveal surface (rows open the existing drawer). ✓
