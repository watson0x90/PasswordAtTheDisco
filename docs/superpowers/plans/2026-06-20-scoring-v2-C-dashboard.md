# Scoring Engine v2 — Sub-project C: Dashboard Honesty (two-axis Exposure × Impact UI) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to execute this plan — dispatch a fresh implementer subagent per task, each doing strict TDD for pure-logic tasks (failing test → run/verify red → minimal impl → run/verify green → commit) and implement-then-verify for presentational tasks, followed by a spec-then-quality review before the next task. Do not batch tasks; keep the tree green (`npx tsc --noEmit`, `npx vitest run`, `npm run build`) and shippable after every commit. Use the **frontend-design** skill for every `.tsx` UI/UX change (distinctive, class-based, no generic AI aesthetic) and the **build-and-run** skill for the embed rebuild + PowerShell restart before any Playwright verification.

**Goal:** Make the dashboard tell the truth that sub-project B's engine now computes. B serves, per account, `exposure_score` (0–10, always), `impact_score` (number **or null** when Unknown), `impact_known`, `coverage` (`"full"|"none"`), `percentile` (0–1), and a v2 `score_breakdown` of per-axis sub-scores. The current frontend still reads the **v1** `score_breakdown` fields — now always zero — so the radar and the AccountDrawer breakdown cards render meaningless zeros, and nothing surfaces the two axes, the per-account `Unknown` Impact state, audit coverage, or percentile triage. C: (1) move `api.ts` types to the v2 shape; (2) **replace** the misleading per-tier radar with an honest per-axis sub-score bar; (3) surface Exposure × Impact per account plus a 2D matrix heatmap; (4) add an audit-level coverage banner; (5) render provisional badges for Unknown-impact accounts; (6) segregate Unknown-impact accounts into a needs-enrichment worklist and sort the rest by Level → Impact → Exposure (percentile-backed); (7) relabel/fix KPIs for the two-axis world incl. the now-reachable High-Privilege KPI; (8) delete the dead v1 breakdown rendering and v1 `ScoreBreakdown` fields once nothing reads them.

**Architecture:** Single source of truth stays in Go. The frontend **never re-derives** the scoring formula (no leave-one-out simulation in TS — that would duplicate the engine and drift). C only *displays* numbers B already computed. The codebase's established split holds: **pure derivation logic lives in `.ts` files** (`insights.ts`, `worklist.ts`, `exposure.ts`, plus a new `matrix.ts`) and is unit-tested directly with vitest (node env, no DOM); **presentational `.tsx` components** consume those functions and are verified live via Playwright. Charts reuse the existing recharts wrappers in `components/Charts.tsx` (`Bars`, `HBars`, grouped-bar via recharts `Bar` stacks) and inline-SVG/CSS — **no new npm dependency** (supply-chain hard rule). All inline spacing/size uses CSS token classes (the `styleguard.test.ts` ban on literal inline spacing styles is enforced per commit).

**Tech Stack:** React + Vite SPA (TypeScript strict), recharts (already vendored), vitest (node-env pure-logic tests), Playwright MCP for live verification against `http://127.0.0.1:8443` (plain HTTP, loopback; server boots locked, a lead unlocks via the UI). Frontend bins are project-local: `npx tsc`, `npx vitest`, `npm run build`, `npm ci --ignore-scripts` — **never `npm install`** (this box holds real lab creds).

---

## Key design decisions (resolved here — the spec defers them to this plan)

**D1 — Radar replacement = grouped/stacked bar of B's breakdown SUB-SCORES, NOT a TS leave-one-out.**
The spec's first choice (`Δ_k = Score(all) − Score(factor k neutralized)`, per the radar redesign in §9) requires re-running the score with each factor neutralized. Doing that in TS means **re-implementing the Go scoring formula in the frontend** — two engines to keep in lock-step, exactly the kind of drift CLAUDE.md warns against ("keep this formula in sync" is already a maintenance tax on `posture()`). A true leave-one-out would instead need a backend delta endpoint, which is **out of C's frontend scope**. The honest, low-maintenance, in-scope choice (named as acceptable in the spec, "A stacked bar of the same deltas is an acceptable alternative"): render a **per-tier grouped bar of the v2 breakdown sub-scores B already exposes**, each already in score-points and commensurable *within* an axis:
- **Exposure factors** (always shown): `weakness_score`, `hibp_floor`, `cracked_floor`, `reuse_bump`, `roastable_bump`.
- **Impact factors** (greyed/omitted when Impact is Unknown for the whole tier): `privilege_sub_score`, `da_component`, `domain_modifier`.
This fixes every radar defect from §9: no incommensurable-axis rescaling, no variance clipping, no circular re-averaging of the tier-defining factors, and bar length is the *actual* score-point contribution. The chart is grouped by risk tier (Critical/High/Medium/Low) so it answers "what drives each tier's score". When a tier has no enriched accounts, the Impact group renders greyed with an "Impact unknown for this tier" note rather than a deceptive zero.

**D2 — `omitempty` means "missing key = 0", never "unknown".** B's v2 `score_breakdown` fields carry Go `omitempty`, so a legitimately-zero factor (e.g. `reuse_bump: 0`) is **absent** from JSON. The frontend MUST treat a missing breakdown key as numeric `0`. We encode this by typing every v2 breakdown field as **optional** (`field?: number`) and reading it through a `bd(key)` helper that coalesces `undefined → 0`. (Contrast: `impact_score` is `number | null` where `null` genuinely means Unknown — that nullability is load-bearing and is NOT coalesced to 0.)

**D3 — `coverage` and `percentile` serialization.** Per B's model: `coverage` is `"full" | "none"` with `omitempty`, so it is absent only when there is no enrichment record at all (treat absent ⇒ `"none"`). `percentile` carries `omitempty`, so a true 0th-percentile account omits the key (treat absent ⇒ `0`). Both are handled with `?:` optional typing + coalescing.

**D4 — Naming collision: the existing "Exposure" view vs the new Exposure axis.** The current `Exposure.tsx` / `exposure.ts` view is about **cross-domain credential reuse** ("How do attackers move between domains?") — bridges, HIBP triage, blast-radius worklist. That is *not* the new per-account **Exposure axis** ("how easily is this credential compromised?"). To avoid confusion we DO NOT rename the existing view (out of scope, high blast radius), but we (a) never label the new axis column simply "Exposure" without the "axis" framing in glossary tooltips, and (b) keep the new two-axis matrix/columns inside the Overview + Accounts surfaces, leaving the cross-domain "Exposure" view untouched. A glossary note disambiguates. This is a resolved spec ambiguity.

**D5 — `risk_score` / `risk_level` retained.** B keeps `risk_score` as a de-emphasized back-compat blend and `risk_level` as the matrix output. C keeps existing `risk_level` badges/sorts working (they are now matrix-derived and correct) and de-emphasizes raw `risk_score` (kept in the drawer + as a tie-break, not promoted). No mass removal of `risk_score` reads — that would touch every table and is unnecessary.

**D6 — Matrix heatmap source.** The Exposure×Impact count matrix is computed in TS purely from each account's tiers (derived from `exposure_score` / `impact_score`), with an explicit **"Impact Unknown"** column for `impact_known=false` accounts (they can't be placed in an Impact tier). Tier cutoffs mirror B exactly: ≥8 Critical, ≥6 High, ≥4 Medium, else Low. This is documentation-only duplication of *cutoffs* (4 thresholds), not the *formula*, and is pinned by a vitest test against the same numbers B's golden tests use.

---

## File Structure

| File | Responsibility | Change in C |
|---|---|---|
| `web/src/api.ts` | Typed API client | `interface Account` (~96): add `exposure_score`, `impact_score: number\|null`, `impact_known`, `coverage`, `percentile`. `interface ScoreBreakdown` (~131): replace the 13 v1 fields with the v2 optional fields. |
| `web/src/matrix.ts` | **NEW** pure logic: axis tiers, Exposure×Impact count matrix, coverage stats, provisional flag, breakdown coalescing helper | new file |
| `web/src/matrix.test.ts` | **NEW** vitest for `matrix.ts` | new file |
| `web/src/insights.ts` | Chart/derivation logic | Replace `riskFactorsRadar` (~268–313) with `axisFactorBars` (grouped sub-score bars per tier). Drop the `RadarDatum`/`RadarSeries` types if unused after. |
| `web/src/insights.test.ts` | vitest for insights | Replace radar coverage with `axisFactorBars` tests. |
| `web/src/components/Charts.tsx` | recharts wrappers | Add `GroupedBars` (or `AxisFactorChart`) for the grouped sub-score bars; add `MatrixHeatmap` (inline-CSS grid). Remove `RiskRadar` + its types once unused. |
| `web/src/components/Insights.tsx` | Insights view | Swap the radar `ChartCard` for the axis-factor grouped bars; render the matrix heatmap; relabel. |
| `web/src/components/AccountDrawer.tsx` | Per-account detail drawer | Replace v1 breakdown cards with v2 Exposure/Impact axis cards (provisional handling); add Exposure/Impact/coverage/percentile rows. |
| `web/src/components/AccountsTable.tsx` | Accounts table | Add Exposure + Impact columns (Impact shows "Unknown" + provisional badge when `impact_known=false`); add coverage indicator. |
| `web/src/components/Dashboard.tsx` | Overview | Add the coverage banner + the Exposure×Impact matrix heatmap; fix/relabel KPI cards (High-Privilege now reachable). |
| `web/src/worklist.ts` | Remediation worklist logic | Segregate `impact_known=false` into a `needsEnrichment` list; sort the rest by Level → Impact desc → Exposure desc (percentile tie-break). |
| `web/src/worklist.test.ts` | vitest for worklist | New tests for segregation + axis ordering. |
| `web/src/components/Actionable.tsx` | Worklist view | Render the needs-enrichment section separately from the prioritized worklist; surface Exposure/Impact/provisional. |
| `web/src/glossary.ts` | Tooltip terms | Add `exposure_axis`, `impact_axis`, `impact_unknown`, `coverage`, `percentile`, `provisional`. |

---

## Gates (run before EVERY commit — from `web/`; never `npm install`)

```
npx tsc --noEmit
npx vitest run            # includes styleguard.test.ts (bans literal inline spacing in .tsx)
npm run build
```
For presentational tasks add a live Playwright pass AFTER a build-and-run rebuild+restart (see each task). Live verification needs the **v2-scored sample data loaded** (a fully-enriched cohort AND a no-BloodHound cohort so coverage/Unknown states are visible) — see the "Sample data" note below.

### Sample data note
The cross-cutting test data is `tools/gen_synthetic.py`. Before T3+ Playwright steps, confirm the active audit has been **re-scored under v2** (reload/re-ingest so accounts carry `exposure_score`/`impact_score`/`coverage`) and that it contains both a fully-enriched cohort and a no-BloodHound cohort (so the coverage banner is non-trivial and provisional badges appear). If the loaded sample lacks a no-BloodHound cohort, extend `gen_synthetic.py` to emit one before verifying (small, additive; keep it CGO-free/offline). Capture this as a precondition in the first Playwright task (T4) and reuse the same audit for T5–T8.

---

### Task C1 — `api.ts` v2 types

**Why:** Every downstream task reads these types. Until `Account` and `ScoreBreakdown` carry the v2 shape, TypeScript blocks the new fields and the dead v1 fields keep compiling. This is a types-only change with no runtime behavior, so it leaves tsc/vitest/build green on its own (existing reads of `risk_score`/`risk_level` are unaffected; the v1 `ScoreBreakdown` consumers in `AccountDrawer.tsx`/`insights.ts` are migrated in C2/C5, so we keep this commit green by adding the v2 fields and removing v1 fields **only after** confirming the two consumers are touched in the same PR sequence — see Step 4).

**Files:**
- Modify: `web/src/api.ts`

#### Steps

- [ ] **Step 1: Extend `interface Account`.** In `web/src/api.ts`, inside `interface Account` (after `risk_score: number` ~line 102), add the v2 axis fields:
  ```ts
    // --- scoring engine v2 (two-axis Exposure × Impact) ---
    // exposure_score: 0–10, ALWAYS present (dump+HIBP+reuse derived).
    exposure_score: number
    // impact_score: 0–10, or null when Impact is Unknown (no BloodHound coverage).
    // null is load-bearing — never coalesce it to 0/low.
    impact_score: number | null
    // impact_known: false => Impact is Unknown; render "Unknown" + a provisional level badge.
    impact_known: boolean
    // coverage: "full" = this account was BloodHound-enriched; "none" = not enriched.
    // Absent (omitempty) means no enrichment record at all → treat as "none".
    coverage?: "full" | "none"
    // percentile: within-audit triage rank [0,1] (sort key, not a displayed score).
    // Absent (omitempty) means 0th percentile → treat as 0.
    percentile?: number
  ```

- [ ] **Step 2: Replace `interface ScoreBreakdown` with the v2 shape.** Replace the whole v1 block (lines ~131–145) with:
  ```ts
  // v2 score_breakdown: per-axis sub-scores. Go serializes these with omitempty, so a
  // legitimately-zero factor is ABSENT — readers MUST treat a missing key as 0, never
  // "unknown" (see the bd() helper in matrix.ts). All optional for that reason.
  export interface ScoreBreakdown {
    // Exposure axis
    exposure_score?: number
    weakness_score?: number
    length_penalty?: number
    complexity_penalty?: number
    dict_penalty?: number
    sim_penalty?: number
    hibp_floor?: number
    cracked_floor?: number
    reuse_bump?: number
    roastable_bump?: number
    // Impact axis
    impact_score?: number
    privilege_sub_score?: number
    da_component?: number
    domain_modifier?: number
    enabled_gated?: boolean
  }
  ```

- [ ] **Step 3: Run the type gate; verify the expected RED on the two v1 consumers.**
  ```
  npx tsc --noEmit
  ```
  Expected errors ONLY in `components/AccountDrawer.tsx` (reads `bd.base_score`, `bd.temporal_score`, etc.) and `insights.ts` `riskFactorsRadar` (reads `bd.complexity_factor`, etc.). These are migrated in C2 and C5. To keep THIS commit green without doing C2/C5's full work, apply the minimal bridge in Step 4.

- [ ] **Step 4: Minimal compile bridge so C1 commits green.** The radar (`riskFactorsRadar`) and the AccountDrawer cards are fully replaced in C2/C5; to avoid a knowingly-broken intermediate commit, do ONE of:
  - **(Preferred)** Sequence C1+C2+C5's first edits in a single working session and only commit once all three compile — but per subagent-driven-development each task commits independently, so instead:
  - Add a temporary `// @ts-expect-error v1 breakdown field removed in v2 — replaced in C2/C5` is NOT acceptable (hides real errors). Instead, in this commit, ALSO delete the now-dead `riskFactorsRadar` body's v1 reads by stubbing it to `return []` (the Insights radar card already renders an empty-state when the series is empty) and replace the AccountDrawer `{bd && (...)}` block with `{null}` temporarily, leaving a `// TODO(C2/C5): v2 breakdown` marker. Both are restored properly in C2/C5.

  > Resolved ambiguity: the spec lists api.ts as T1 and radar/drawer later, which transiently breaks compilation. We resolve it by stubbing the two v1 consumers to no-ops in C1 (tree stays green) and fully implementing them in C2/C5. This keeps each commit shippable.

- [ ] **Step 5: Gate + commit.**
  ```
  npx tsc --noEmit && npx vitest run && npm run build
  ```
  ```
  git commit -am "feat(ui-v2): api.ts Account axis fields + v2 ScoreBreakdown; stub dead v1 radar/drawer (#C1)"
  ```

---

### Task C2 — Replace `riskFactorsRadar` with honest per-axis sub-score bars

**Why (D1):** The v1 radar linearly rescales 10 incommensurable multipliers onto one axis, clips variance, and circularly re-averages the same factors that defined the tier — and every input it reads is now a structural zero. Replace it with a grouped bar of B's v2 breakdown **sub-scores** (already in score-points, commensurable within an axis), grouped by risk tier, Impact group greyed when a tier has no enriched accounts. Pure logic → TDD.

**Files:**
- Modify: `web/src/insights.ts` (replace `riskFactorsRadar` ~268–313; drop `RadarDatum`/`RadarSeries` if unused elsewhere — `grep` first)
- Modify: `web/src/insights.test.ts`

#### Steps

- [ ] **Step 1: Write the failing test.** Append to `web/src/insights.test.ts`:
  ```ts
  import { axisFactorBars } from "./insights"

  const bdAcct = (level: string, impactKnown: boolean, bd: Partial<NonNullable<Account["score_breakdown"]>>): Account =>
    acct({
      risk_level: level,
      impact_known: impactKnown,
      exposure_score: 5,
      impact_score: impactKnown ? 5 : null,
      score_breakdown: bd,
    } as Partial<Account>)

  describe("axisFactorBars", () => {
    it("groups Exposure + Impact sub-scores per tier, coalescing missing keys to 0", () => {
      const bars = axisFactorBars([
        bdAcct("Critical", true, { weakness_score: 8, hibp_floor: 4, privilege_sub_score: 7 }),
        bdAcct("Critical", true, { weakness_score: 6, hibp_floor: 4, privilege_sub_score: 9 }),
      ])
      const crit = bars.find((b) => b.tier === "Critical")!
      // averaged within the tier; absent factors (cracked_floor, reuse_bump, ...) are 0
      expect(crit.exposure.find((f) => f.name === "Weakness")!.value).toBe(7) // (8+6)/2
      expect(crit.exposure.find((f) => f.name === "HIBP floor")!.value).toBe(4)
      expect(crit.exposure.find((f) => f.name === "Reuse")!.value).toBe(0) // absent => 0, NOT unknown
      expect(crit.impact.find((f) => f.name === "Privilege")!.value).toBe(8) // (7+9)/2
      expect(crit.impactKnown).toBe(true)
    })

    it("greys the Impact group for a tier with no enriched accounts", () => {
      const bars = axisFactorBars([bdAcct("High", false, { weakness_score: 6 })])
      const high = bars.find((b) => b.tier === "High")!
      expect(high.impactKnown).toBe(false) // no enriched account in this tier
      expect(high.exposure.find((f) => f.name === "Weakness")!.value).toBe(6)
    })

    it("omits empty tiers", () => {
      const bars = axisFactorBars([bdAcct("Critical", true, { weakness_score: 5 })])
      expect(bars.some((b) => b.tier === "Low")).toBe(false)
    })
  })
  ```

- [ ] **Step 2: Run; verify RED.**
  ```
  cd web; npx vitest run insights.test.ts
  ```
  Expected: `axisFactorBars` is not exported (compile/red).

- [ ] **Step 3: Implement `axisFactorBars`.** In `web/src/insights.ts`, delete `riskFactorsRadar` (and the `RadarDatum`/`RadarSeries` interfaces if `grep -r "RadarSeries\|RadarDatum" web/src` shows no other live reader after Charts.tsx loses `RiskRadar` in C-Charts — if still referenced, defer their removal to C8). Add:
  ```ts
  export interface AxisFactor { name: string; value: number; color: string }
  export interface TierFactorBars {
    tier: string
    color: string
    exposure: AxisFactor[]
    impact: AxisFactor[]
    impactKnown: boolean // false when no account in this tier is enriched (impact greyed)
  }

  // Coalesce a possibly-absent (omitempty) breakdown key to 0. Missing = 0, never "unknown".
  const bdv = (a: Account, k: keyof NonNullable<Account["score_breakdown"]>): number => {
    const v = a.score_breakdown?.[k]
    return typeof v === "number" ? v : 0
  }

  const EXP_FACTORS: [string, keyof NonNullable<Account["score_breakdown"]>, string][] = [
    ["Weakness", "weakness_score", "#fbbf24"],
    ["HIBP floor", "hibp_floor", "#fb7185"],
    ["Cracked floor", "cracked_floor", "#f472b6"],
    ["Reuse", "reuse_bump", "#a78bfa"],
    ["Roastable", "roastable_bump", "#38bdf8"],
  ]
  const IMP_FACTORS: [string, keyof NonNullable<Account["score_breakdown"]>, string][] = [
    ["Privilege", "privilege_sub_score", "#22d3ee"],
    ["DA path", "da_component", "#fb7185"],
    ["Domain", "domain_modifier", "#a3e635"],
  ]

  // axisFactorBars: per-tier averaged breakdown SUB-SCORES (already in score-points,
  // commensurable within an axis). Replaces the misleading rescaled radar. The Impact
  // group is greyed when no account in the tier was BloodHound-enriched.
  export function axisFactorBars(accts: Account[]): TierFactorBars[] {
    const tiers: [string, string][] = [
      ["Critical", "#fb7185"],
      ["High", "#fbbf24"],
      ["Medium", "#a3e635"],
      ["Low", "#22d3ee"],
    ]
    const out: TierFactorBars[] = []
    for (const [tier, color] of tiers) {
      const group = accts.filter((a) => a.risk_level === tier && a.score_breakdown)
      if (group.length === 0) continue
      const enriched = group.filter((a) => a.impact_known)
      const avg = (rows: Account[], k: keyof NonNullable<Account["score_breakdown"]>) =>
        rows.length ? Math.round((rows.reduce((s, a) => s + bdv(a, k), 0) / rows.length) * 100) / 100 : 0
      out.push({
        tier,
        color,
        exposure: EXP_FACTORS.map(([name, k, c]) => ({ name, value: avg(group, k), color: c })),
        impact: IMP_FACTORS.map(([name, k, c]) => ({ name, value: avg(enriched, k), color: c })),
        impactKnown: enriched.length > 0,
      })
    }
    return out
  }
  ```

- [ ] **Step 4: Run; verify GREEN.**
  ```
  npx vitest run insights.test.ts && npx tsc --noEmit
  ```
  (If `RiskRadar` in `Charts.tsx` and `riskFactorsRadar` import in `Insights.tsx` now fail tsc, those are wired in C-Charts/Insights below; to keep this commit green, in the SAME commit replace the `Insights.tsx` radar `ChartCard` to call `axisFactorBars` + the new chart — i.e. do C2's presentational wiring here, since it is the natural unit. See Step 5.)

- [ ] **Step 5: Wire the new chart into `Charts.tsx` + `Insights.tsx` (presentational, class-based, frontend-design skill).**
  - In `web/src/components/Charts.tsx` add a grouped-bar component using the already-imported recharts primitives (one `<Bar>` per factor sharing an x-category of the axis, or a small multiples layout — implementer's call via frontend-design). Signature: `export function AxisFactorBars({ data }: { data: TierFactorBars[] })`. Greyed Impact group when `impactKnown === false` (render with muted fill + an "Impact unknown for this tier" caption via a CSS class, NOT inline spacing). Reuse `ChartCard`, `TOOLTIP`, `AXIS`.
  - In `web/src/components/Insights.tsx`: replace the `const radarSeries = riskFactorsRadar(accounts)` line and the "Risk factor contribution (radar)" `ChartCard` (lines ~24, ~89–95) with `const axisBars = axisFactorBars(accounts)` and a `ChartCard title="Risk factor contribution by tier"` rendering `<AxisFactorBars data={axisBars} />`, keeping the existing empty-state fallback (`axisBars.length ? ... : <div className="chart-empty">…</div>`). Update the import on line 3.

- [ ] **Step 6: Gate + commit (tsc/vitest/build).**
  ```
  npx tsc --noEmit && npx vitest run && npm run build
  ```
  ```
  git commit -am "feat(ui-v2): replace misleading radar with per-axis sub-score bars (#C2, D1)"
  ```

- [ ] **Step 7: Playwright verification (after build-and-run rebuild+restart).** Rebuild the embed binary and restart, then drive the live UI:
  - `bash .claude/skills/build-and-run/scripts/build.sh` then `powershell -File .claude/skills/build-and-run/scripts/restart.ps1`; confirm `/api/version` commit matches `git rev-parse --short HEAD`.
  - Playwright MCP: navigate `http://127.0.0.1:8443`, unlock as lead, open the audit with v2 sample data, go to Insights. Assert the "Risk factor contribution by tier" card renders the grouped bars (snapshot shows Exposure factors and, for an enriched tier, Impact factors), a tier with no enrichment shows the greyed Impact group + caption, the **browser console has 0 errors/0 warnings**, and screenshot the chart.

---

### Task C3 — `matrix.ts`: axis tiers, coverage stats, Exposure×Impact matrix (pure logic)

**Why:** The matrix heatmap (C4), the coverage banner (C4), the table columns (C5), the drawer (C5), and the worklist (C6) all need the same small primitives: map an axis score to a tier (B's cutoffs), classify coverage, and count accounts into the Exposure×Impact grid with an explicit Unknown column. Centralize them in one tested module so the cutoffs live once and are pinned by a test against B's golden numbers (D2/D3/D6).

**Files:**
- Create: `web/src/matrix.ts`
- Create: `web/src/matrix.test.ts`

#### Steps

- [ ] **Step 1: Write the failing test.** Create `web/src/matrix.test.ts`:
  ```ts
  import { describe, it, expect } from "vitest"
  import type { Account } from "./api"
  import { axisTier, coverageStats, exposureImpactMatrix, isProvisional, IMPACT_UNKNOWN } from "./matrix"

  const a = (p: Partial<Account>): Account =>
    ({
      username: "u", domain: "D", cracked: false, password_length: 0, risk_level: "Low",
      risk_score: 0, risk_vector: "", hibp_breached: false, hibp_breach_count: 0,
      da_domains: "None", controlled_object_count: 0, shared_with: 0, enabled: true,
      meets_policy: true, complexity: "", exposure_score: 0, impact_score: null,
      impact_known: false, ...p,
    } as Account)

  describe("axisTier (mirrors B cutoffs: >=8 C, >=6 H, >=4 M, else L)", () => {
    it("maps boundaries", () => {
      expect(axisTier(8)).toBe("Critical")
      expect(axisTier(6)).toBe("High")
      expect(axisTier(4)).toBe("Medium")
      expect(axisTier(3.9)).toBe("Low")
      expect(axisTier(0)).toBe("Low")
    })
  })

  describe("isProvisional", () => {
    it("true exactly when impact_known is false", () => {
      expect(isProvisional(a({ impact_known: false }))).toBe(true)
      expect(isProvisional(a({ impact_known: true, impact_score: 5 }))).toBe(false)
    })
  })

  describe("coverageStats", () => {
    it("counts enriched (coverage full) over total; absent coverage => none", () => {
      const s = coverageStats([
        a({ coverage: "full" }), a({ coverage: "none" }), a({}), // absent => none
      ])
      expect(s.enriched).toBe(1)
      expect(s.total).toBe(3)
      expect(s.partial).toBe(true) // <100%
    })
    it("not partial when all enriched", () => {
      expect(coverageStats([a({ coverage: "full" })]).partial).toBe(false)
    })
  })

  describe("exposureImpactMatrix", () => {
    it("places enriched accounts by (exposure tier, impact tier) and Unknown ones in the Unknown column", () => {
      const m = exposureImpactMatrix([
        a({ exposure_score: 9, impact_score: 9, impact_known: true }),  // Crit x Crit
        a({ exposure_score: 6, impact_score: 4, impact_known: true }),  // High x Med
        a({ exposure_score: 9, impact_score: null, impact_known: false }), // Crit x Unknown
      ])
      expect(m.cell("Critical", "Critical")).toBe(1)
      expect(m.cell("High", "Medium")).toBe(1)
      expect(m.cell("Critical", IMPACT_UNKNOWN)).toBe(1)
      expect(m.total).toBe(3)
    })
  })
  ```

- [ ] **Step 2: Run; verify RED.**
  ```
  cd web; npx vitest run matrix.test.ts
  ```

- [ ] **Step 3: Implement `web/src/matrix.ts`.**
  ```ts
  import type { Account } from "./api"

  export type Tier = "Critical" | "High" | "Medium" | "Low"
  export const TIERS: Tier[] = ["Critical", "High", "Medium", "Low"]
  export const IMPACT_UNKNOWN = "Unknown" as const

  // axisTier mirrors B's per-axis cutoffs (>=8 Critical, >=6 High, >=4 Medium, else Low).
  // Pinned by matrix.test.ts against the same numbers as the Go golden tests.
  export function axisTier(v: number): Tier {
    if (v >= 8) return "Critical"
    if (v >= 6) return "High"
    if (v >= 4) return "Medium"
    return "Low"
  }

  // isProvisional: true exactly when Impact is Unknown (level was derived from Exposure
  // alone). The UI shows a "provisional" badge and never claims a number for Impact.
  export function isProvisional(a: Account): boolean {
    return a.impact_known === false
  }

  // coverageState: absent coverage (omitempty) means no enrichment record => "none".
  export function coverageState(a: Account): "full" | "none" {
    return a.coverage === "full" ? "full" : "none"
  }

  export interface CoverageStats { enriched: number; total: number; partial: boolean }
  export function coverageStats(accts: Account[]): CoverageStats {
    const total = accts.length
    let enriched = 0
    for (const a of accts) if (coverageState(a) === "full") enriched++
    return { enriched, total, partial: total > 0 && enriched < total }
  }

  export type ImpactCol = Tier | typeof IMPACT_UNKNOWN
  export const IMPACT_COLS: ImpactCol[] = [...TIERS, IMPACT_UNKNOWN]

  export interface ExposureImpactMatrix {
    counts: Record<Tier, Record<ImpactCol, number>>
    total: number
    cell: (exp: Tier, imp: ImpactCol) => number
  }

  // exposureImpactMatrix: rows = Exposure tier, cols = Impact tier + an explicit Unknown
  // column for impact_known=false accounts (which cannot be placed in an Impact tier).
  export function exposureImpactMatrix(accts: Account[]): ExposureImpactMatrix {
    const counts = {} as Record<Tier, Record<ImpactCol, number>>
    for (const r of TIERS) {
      counts[r] = {} as Record<ImpactCol, number>
      for (const c of IMPACT_COLS) counts[r][c] = 0
    }
    let total = 0
    for (const a of accts) {
      const expT = axisTier(a.exposure_score)
      const impCol: ImpactCol = a.impact_known && a.impact_score !== null ? axisTier(a.impact_score) : IMPACT_UNKNOWN
      counts[expT][impCol]++
      total++
    }
    return { counts, total, cell: (exp, imp) => counts[exp][imp] }
  }
  ```

- [ ] **Step 4: Run; verify GREEN.**
  ```
  npx vitest run matrix.test.ts && npx tsc --noEmit
  ```

- [ ] **Step 5: Gate + commit.**
  ```
  npx tsc --noEmit && npx vitest run && npm run build
  ```
  ```
  git commit -am "feat(ui-v2): matrix.ts — axis tiers, coverage stats, Exposure×Impact matrix (#C3, D2/D3/D6)"
  ```

---

### Task C4 — Exposure×Impact matrix heatmap + audit coverage banner (Overview)

**Why:** The dashboard must show the two-axis distribution at a glance (the matrix as a heatmap with an explicit Unknown column) and make partial BloodHound coverage visible (the banner the owner asked for, in addition to per-account state). Presentational → implement with `matrix.ts` (C3) + class-based styles, verify live.

**Files:**
- Modify: `web/src/components/Charts.tsx` (add `MatrixHeatmap`)
- Modify: `web/src/components/Dashboard.tsx` (coverage banner + matrix heatmap)
- Modify: `web/src/glossary.ts` (banner/matrix tooltips — can be folded into C7's glossary edit; do here if needed)

#### Steps

- [ ] **Step 1: Add `MatrixHeatmap` to `Charts.tsx` (inline-CSS grid, class-based, frontend-design skill).** A CSS-grid table: rows = Exposure tiers (Critical→Low), columns = Impact tiers + an "Unknown" column; each cell shows the count with a background whose intensity scales with count (use a CSS custom property for the computed intensity — `style={{ "--cell": n/maxN }}` is a *computed* value, allowed by styleguard which only bans literal px/number spacing). Header row/col labels. Signature: `export function MatrixHeatmap({ m }: { m: ExposureImpactMatrix })`. Empty cells render muted; the Unknown column is visually separated (a class, e.g. `matrix-col-unknown`).

- [ ] **Step 2: Add the coverage banner + matrix to `Dashboard.tsx`.**
  - Import `coverageStats`, `exposureImpactMatrix` from `../matrix` and `MatrixHeatmap` from `./Charts`.
  - Compute `const cov = coverageStats(accounts)` and `const eiMatrix = exposureImpactMatrix(accounts)`.
  - Render the banner when `cov.partial`, just under the `view-sub` line: a `<div className="coverage-banner">` reading `BloodHound: {cov.enriched}/{cov.total} accounts enriched — Impact is Unknown for the rest`, with an `InfoTip text={GLOSSARY.coverage}`. (No literal inline spacing — use a CSS class.)
  - Add a new section `Exposure × Impact` with `<MatrixHeatmap m={eiMatrix} />` inside a `panel`, near the existing Charts grid.

- [ ] **Step 3: Gate.**
  ```
  npx tsc --noEmit && npx vitest run && npm run build
  ```

- [ ] **Step 4: Commit.**
  ```
  git commit -am "feat(ui-v2): coverage banner + Exposure×Impact matrix heatmap on Overview (#C4)"
  ```

- [ ] **Step 5: Playwright verification (rebuild+restart first).** Confirm the v2 sample audit is loaded with BOTH an enriched and a no-BloodHound cohort (extend `gen_synthetic.py` if absent — see Sample data note). Then: navigate `http://127.0.0.1:8443`, unlock, open the audit, Overview. Assert: the coverage banner appears with a sensible N/M, the matrix heatmap renders with a populated Unknown column, **console 0 errors/0 warnings**, screenshot Overview.

---

### Task C5 — Accounts table Exposure/Impact columns + AccountDrawer v2 breakdown

**Why:** Operators triage in the accounts table and inspect in the drawer. Both must surface the two axes (Impact as "Unknown" + a provisional badge when `impact_known=false`, never a number/low), and the drawer's score-breakdown cards must read the v2 sub-scores instead of the zeroed v1 fields. Presentational; the drawer's "missing key = 0" coalescing comes from `matrix.ts`'s pattern (D2).

**Files:**
- Modify: `web/src/components/AccountsTable.tsx`
- Modify: `web/src/components/AccountDrawer.tsx`
- Modify: `web/src/glossary.ts` (exposure_axis/impact_axis/provisional — if not already added in C7)

#### Steps

- [ ] **Step 1: AccountsTable — add Exposure + Impact columns + provisional badge.**
  - Add sort columns to `COLS`: `{ key: "exposure", get: (a) => a.exposure_score, defaultDir: "desc" }` and `{ key: "impact", get: (a) => (a.impact_known && a.impact_score !== null ? a.impact_score : -1), defaultDir: "desc" }` (Unknown sorts last on desc via the `-1` sentinel).
  - Add `<SortHeader label="Exposure" colKey="exposure" numeric …info={<InfoTip text={GLOSSARY.exposure_axis} />} />` and `<SortHeader label="Impact" colKey="impact" numeric …info={<InfoTip text={GLOSSARY.impact_axis} />} />` after the existing "Risk" header.
  - Render cells: Exposure `<td className="num">{a.exposure_score.toFixed(1)}</td>`; Impact: when `a.impact_known && a.impact_score !== null` show `{a.impact_score.toFixed(1)}`, else `<span className="badge-provisional" title={GLOSSARY.impact_unknown}>Unknown</span>`.
  - When `isProvisional(a)` (import from `../matrix`), render a small `provisional` badge next to the risk-level badge.
  - Keep the existing `Score` column (de-emphasized per D5) — do not remove it here.

- [ ] **Step 2: AccountDrawer — replace v1 breakdown cards with v2 axis cards + add axis rows.**
  - Add rows to the `rows` array (after "Risk score"): `["Exposure", a.exposure_score.toFixed(1)]`, `["Impact", a.impact_known && a.impact_score !== null ? a.impact_score.toFixed(1) : <span className="badge-provisional">Unknown</span>]`, `["Coverage", coverageState(a) === "full" ? "BloodHound-enriched" : "Not enriched"]`, and (if `a.percentile != null`) `["Triage percentile", `${Math.round((a.percentile ?? 0) * 100)}th`]`.
  - Replace the `{bd && (...)}` Score-Breakdown block. New cards read v2 fields through a local coalescing reader `const v = (k: keyof ScoreBreakdown) => { const x = bd?.[k]; return typeof x === "number" ? x : 0 }`:
    - **Exposure** card (score = `a.exposure_score`): factors `["Weakness", v("weakness_score")]`, `["HIBP floor", v("hibp_floor")]`, `["Cracked floor", v("cracked_floor")]`, `["Reuse", v("reuse_bump")]`, `["Roastable", v("roastable_bump")]`.
    - **Impact** card: if `a.impact_known` show score = `a.impact_score`, factors `["Privilege", v("privilege_sub_score")]`, `["DA path", v("da_component")]`, `["Domain", v("domain_modifier")]`, plus an "Enabled-gated" note when `bd?.enabled_gated`; else render a single muted "Impact Unknown — account not BloodHound-enriched" line (no numbers).
  - Reuse the existing `BreakdownCard` component (its `score`/`factors` signature is unchanged). Remove the v1 `Base`/`Temporal`/`Environmental` cards entirely.

- [ ] **Step 3: Gate.**
  ```
  npx tsc --noEmit && npx vitest run && npm run build
  ```

- [ ] **Step 4: Commit.**
  ```
  git commit -am "feat(ui-v2): Accounts table Exposure/Impact columns + v2 AccountDrawer breakdown (#C5)"
  ```

- [ ] **Step 5: Playwright verification (rebuild+restart first).** Navigate to Accounts. Assert: Exposure and Impact columns render, an Unknown-impact account shows the "Unknown" + provisional badge (not a number), sorting by Impact desc keeps Unknown rows last. Open the drawer on an enriched cracked account: assert the Exposure card shows non-zero sub-scores and the Impact card shows Privilege/DA/Domain (not zeros). Open the drawer on a no-BloodHound account: assert the Impact card shows the "Impact Unknown" line. **Console 0 errors/0 warnings**; screenshot the table + both drawers.

---

### Task C6 — Needs-enrichment worklist + axis ordering (worklist.ts + Actionable.tsx)

**Why:** Triage must segregate `impact_known=false` accounts into a "needs enrichment" section (the UI must never blend them into the impact-sorted list as if low-impact) and order the rest by Level → Impact desc → Exposure desc (percentile-backed), per the spec's Triage section. Pure logic → TDD, then wire the view.

**Files:**
- Modify: `web/src/worklist.ts`
- Modify: `web/src/worklist.test.ts`
- Modify: `web/src/components/Actionable.tsx`

#### Steps

- [ ] **Step 1: Write the failing test.** Append to `web/src/worklist.test.ts`:
  ```ts
  import { segmentWorklist } from "./worklist"

  describe("segmentWorklist", () => {
    it("segregates Unknown-impact accounts and orders the rest by Level -> Impact -> Exposure", () => {
      const seg = segmentWorklist([
        acct({ username: "lowexp", risk_level: "High", impact_known: true, impact_score: 6, exposure_score: 4 }),
        acct({ username: "hiexp", risk_level: "High", impact_known: true, impact_score: 6, exposure_score: 7 }),
        acct({ username: "crit", risk_level: "Critical", impact_known: true, impact_score: 9, exposure_score: 9 }),
        acct({ username: "unk", risk_level: "High", impact_known: false, impact_score: null, exposure_score: 8 }),
      ])
      expect(seg.ranked.map((a) => a.username)).toEqual(["crit", "hiexp", "lowexp"])
      expect(seg.needsEnrichment.map((a) => a.username)).toEqual(["unk"])
    })

    it("uses percentile as the final tie-break when present", () => {
      const seg = segmentWorklist([
        acct({ username: "p1", risk_level: "High", impact_known: true, impact_score: 6, exposure_score: 6, percentile: 0.4 }),
        acct({ username: "p2", risk_level: "High", impact_known: true, impact_score: 6, exposure_score: 6, percentile: 0.9 }),
      ])
      expect(seg.ranked[0].username).toBe("p2") // higher percentile first
    })
  })
  ```
  (Reuse the `acct` helper already at the top of `worklist.test.ts`; extend its defaults with `exposure_score: 0, impact_score: null, impact_known: true` so the cast stays valid.)

- [ ] **Step 2: Run; verify RED.**
  ```
  cd web; npx vitest run worklist.test.ts
  ```

- [ ] **Step 3: Implement `segmentWorklist`.** In `web/src/worklist.ts` add (keep `priorityWorklist` as-is — it still drives the existing Priority worklist):
  ```ts
  import { RISK_RANK } from "./util"

  export interface SegmentedWorklist { ranked: Account[]; needsEnrichment: Account[] }

  // segmentWorklist splits accounts into a needs-enrichment list (impact_known=false —
  // never ordered as if low-impact) and a ranked list ordered Level desc, then Impact
  // desc, then Exposure desc, then within-audit percentile desc (the engine-computed
  // sort key that defeats tier collapse).
  export function segmentWorklist(accounts: Account[]): SegmentedWorklist {
    const needsEnrichment = accounts.filter((a) => a.impact_known === false)
    const ranked = accounts
      .filter((a) => a.impact_known !== false)
      .slice()
      .sort(
        (x, y) =>
          (RISK_RANK[y.risk_level] ?? 0) - (RISK_RANK[x.risk_level] ?? 0) ||
          (y.impact_score ?? 0) - (x.impact_score ?? 0) ||
          y.exposure_score - x.exposure_score ||
          (y.percentile ?? 0) - (x.percentile ?? 0),
      )
    return { ranked, needsEnrichment }
  }
  ```

- [ ] **Step 4: Run; verify GREEN.**
  ```
  npx vitest run worklist.test.ts && npx tsc --noEmit
  ```

- [ ] **Step 5: Wire into `Actionable.tsx` (presentational, frontend-design skill).** Add a `Needs enrichment` section above or beside the Priority worklist: `const seg = segmentWorklist(accounts ?? [])`; render `seg.needsEnrichment` in its own `Section` (tone `med`) with a note "Impact unknown — run BloodHound enrichment to prioritize", showing Exposure + provisional badge per row. Leave the existing `PriorityWorklist` (driven by `priorityWorklist`) in place but consider surfacing Exposure/Impact columns there too (implementer's call). Do not remove existing report sections.

- [ ] **Step 6: Gate + commit.**
  ```
  npx tsc --noEmit && npx vitest run && npm run build
  ```
  ```
  git commit -am "feat(ui-v2): needs-enrichment segregation + axis/percentile worklist ordering (#C6)"
  ```

- [ ] **Step 7: Playwright verification (rebuild+restart first).** Navigate to Actionable. Assert: the Needs-enrichment section lists the no-BloodHound accounts with provisional badges, the prioritized list orders Critical/high-Impact first, **console 0 errors/0 warnings**, screenshot.

---

### Task C7 — KPI updates for the two-axis world (Overview)

**Why:** v1 KPIs assumed a single blended score; some (the "High Privilege / controls >100 objects" KPI) were structural zeros because sub-project A's count was capped at 10 — now reachable. Relabel/fix the KPIs and add glossary terms for the new concepts. Presentational.

**Files:**
- Modify: `web/src/components/Dashboard.tsx` (KPI `Stat` cards)
- Modify: `web/src/glossary.ts` (add the v2 terms used across C4/C5/C6/C7)

#### Steps

- [ ] **Step 1: Add v2 glossary terms.** In `web/src/glossary.ts` add:
  ```ts
    exposure_axis: "Exposure (0–10): how easily this credential is compromised — from the dump, HIBP, and password reuse. Always computed.",
    impact_axis: "Impact (0–10, or Unknown): blast radius if this credential is compromised — from BloodHound. 'Unknown' means this account was not enriched.",
    impact_unknown: "Impact is Unknown because this account has no BloodHound coverage. The level is provisional, computed from Exposure alone.",
    provisional: "Provisional level — Impact is Unknown (no BloodHound coverage), so the level was derived from Exposure alone. Run enrichment to finalize.",
    coverage: "BloodHound coverage: how many accounts were enriched. Un-enriched accounts have Unknown Impact and a provisional level.",
    percentile: "Within-audit triage rank (0–100th) — a sort key, not a score; breaks ties so a large block of Critical accounts still has a strict order.",
  ```

- [ ] **Step 2: Fix/relabel KPI cards in `Dashboard.tsx`.**
  - The "High Privilege" card already exists (`summary.high_controlled`, label "controls > 100 objects", `tip={GLOSSARY.high_controlled}`). Verify it now shows a **non-zero** value with v2 data (A removed the 10-cap); keep the card, ensure it is in the visible grid (it is, in the secondary grid). No code change beyond confirming the value renders; if the KPI was conditionally hidden, ensure it always shows when `summary` is present.
  - Add a two-axis-aware KPI to the primary `stat-grid`: a count of **provisional accounts** (`accounts.filter(isProvisional).length`) labelled "Impact Unknown" with `tip={GLOSSARY.impact_unknown}` — directly surfaces the coverage gap as a number.
  - Relabel the primary grid so the single-score framing is gone where it misleads (e.g. keep "Cracked", "HIBP Breached", "DA Pathways"; these remain valid). Do NOT remove `risk_score`-based displays elsewhere (D5).

- [ ] **Step 3: Gate + commit.**
  ```
  npx tsc --noEmit && npx vitest run && npm run build
  ```
  ```
  git commit -am "feat(ui-v2): two-axis KPIs (reachable High-Privilege + Impact-Unknown count) + glossary (#C7)"
  ```

- [ ] **Step 4: Playwright verification (rebuild+restart first).** Overview: assert the High-Privilege KPI is non-zero on the v2 enriched cohort, the new "Impact Unknown" KPI matches the count of provisional accounts, glossary tooltips open without console noise, **console 0 errors/0 warnings**, screenshot the KPI grid.

---

### Task C8 — Remove dead v1 breakdown fields/code + final sweep

**Why:** Once C2 (radar) and C5 (drawer) no longer read any v1 `ScoreBreakdown` field, and `RiskRadar`/`riskFactorsRadar`/`RadarSeries`/`RadarDatum` are unused, delete them so the dead v1 surface can't silently render zeros again. Then run the full gate + a whole-app Playwright sweep.

**Files:**
- Modify: `web/src/components/Charts.tsx` (remove `RiskRadar`, `RadarDatum`, `RadarSeries`, and the now-unused recharts radar imports `Radar`/`RadarChart`/`PolarGrid`/`PolarAngleAxis`/`PolarRadiusAxis` IF no other chart uses them — `grep` first; `PostureGauge` uses `PolarAngleAxis`, so keep that one)
- Modify: `web/src/insights.ts` (remove `RadarDatum`/`RadarSeries` if not already removed in C2)
- Modify: `web/src/api.ts` (confirm no v1 `ScoreBreakdown` field remains — already done in C1; this is a verification step)

#### Steps

- [ ] **Step 1: Confirm nothing reads v1 fields or the radar.** From `web/`:
  ```
  ```
  Use Grep (not bash) for: `base_score|complexity_factor|length_factor|dictionary_factor|similarity_factor|temporal_score|compliance_factor|expiration_factor|environmental_score|privilege_factor|share_factor|domain_factor|hibp_factor` across `web/src` — expect **zero** hits. Also grep `RiskRadar|riskFactorsRadar|RadarSeries|RadarDatum` — expect only the definitions about to be deleted.

- [ ] **Step 2: Delete the dead radar code.** Remove `RiskRadar` + its `RadarDatum`/`RadarSeries` interfaces from `Charts.tsx`; prune the radar-only recharts imports (keep `PolarAngleAxis` — `PostureGauge` uses it). Remove `RadarDatum`/`RadarSeries` from `insights.ts` if still present.

- [ ] **Step 3: Full gate.**
  ```
  npx tsc --noEmit && npx vitest run && npm run build
  ```
  Expect: clean tsc, all vitest (incl. styleguard) green, build OK.

- [ ] **Step 4: Commit.**
  ```
  git commit -am "chore(ui-v2): remove dead v1 score_breakdown radar + fields (#C8)"
  ```

- [ ] **Step 5: Final whole-app Playwright sweep (rebuild+restart first).** Drive the full lead-gated flow on the v2 sample audit: Overview (banner + matrix + KPIs), Insights (axis-factor bars), Accounts (Exposure/Impact columns + drawers), Actionable (needs-enrichment + ranked). On every view assert the **browser console has 0 errors and 0 warnings** and capture a screenshot. Confirm no view renders a zeroed v1 breakdown.

---

## Self-Review — every C deliverable maps to a task

| # | C deliverable (from the spec) | Task(s) |
|---|---|---|
| 1 | `api.ts` types → v2 (Account axis fields + coverage + percentile; ScoreBreakdown v2; drop dead v1 fields) | **C1** (add/replace), **C8** (confirm removal) |
| 2 | Replace the radar with an honest per-axis factor-contribution chart (decision locked) | **C2** (D1: grouped sub-score bars) |
| 3 | Exposure × Impact surfaced per account + 2D matrix/heatmap + table columns + provisional indicator | **C3** (matrix logic), **C4** (heatmap), **C5** (table columns + drawer) |
| 4 | Coverage banner (audit-level, when enriched/total < 100%) | **C3** (`coverageStats`), **C4** (banner) |
| 5 | Provisional badges — Unknown impact never a number/low + provisional level badge | **C3** (`isProvisional`), **C5** (table + drawer), **C7** (Impact-Unknown KPI) |
| 6 | Needs-enrichment worklist — segregate `impact_known=false`; sort rest by Level → Impact → Exposure (percentile) | **C6** |
| 7 | KPI updates incl. the now-reachable High-Privilege / controls >N KPI | **C7** |
| 8 | Remove the dead v1 breakdown rendering + dead v1 ScoreBreakdown fields | **C1** (stub), **C5** (drawer rewrite), **C8** (delete) |

## Resolved spec ambiguities (recap)
- **D1** Radar replacement = breakdown sub-score grouped bar (NOT a TS leave-one-out — that duplicates the Go engine; a true delta needs a backend endpoint, out of C scope).
- **D2** `omitempty` ⇒ a missing breakdown key is **0**, not "unknown" (typed optional + coalesced); `impact_score: null` is the only genuine Unknown and is never coalesced.
- **D3** `coverage` absent ⇒ `"none"`; `percentile` absent ⇒ `0`.
- **D4** The existing "Exposure" view (cross-domain reuse) is a different concept from the new Exposure axis; not renamed, disambiguated in the glossary.
- **D5** `risk_score`/`risk_level` retained (matrix-derived level stays correct; raw score de-emphasized, not ripped out).
- **D6** Matrix heatmap duplicates only B's 4 tier cutoffs (pinned by a test), not the formula; Unknown is an explicit column.
- **C1 ordering:** api.ts-first transiently breaks the two v1 consumers; resolved by stubbing them to no-ops in C1 and fully implementing in C2/C5, so every commit stays green.
```
