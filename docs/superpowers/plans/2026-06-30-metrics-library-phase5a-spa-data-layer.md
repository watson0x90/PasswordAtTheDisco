# Metrics Library (Phase 5a: SPA data layer) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Give the SPA a typed client + shared hook for the new `GET /api/metrics` bundle, so subsequent increments can migrate each dashboard surface from client-side recompute to rendering the server bundle. This increment is **additive and inert** — it adds types/`api.metrics()`/`useMetrics()` but changes no rendered UI yet.

**Architecture:** A TS `MetricsBundle` interface set (`web/src/metricsBundle.ts`) mirrors the Go `metrics.Metrics` JSON exactly. `api.metrics(domain?)` calls the endpoint. `MetricsProvider` / `useMetrics()` (`web/src/metricsData.tsx`) fetches the org bundle once per active audit, following the existing `AccountsProvider`/`useAccountsData` pattern (`web/src/accountsData.tsx`).

**Tech Stack:** TypeScript, React context, Vite. Gates run in `web/`: `npx tsc --noEmit`, `npx vitest run`, `npm run build`. NEVER `npm install` (node_modules is junctioned).

## Global Constraints

- **No `npm install`/`npm ci`.** Use only `npx tsc --noEmit`, `npx vitest run`, `npm run build`.
- **Type parity with Go.** The TS field names must be the Go JSON tags exactly (snake_case). The `MetricsBundle` shape must match `internal/metrics` (`Metrics` -> summary/matrix/charts/reports/domains).
- **Additive only.** Do not change any existing component's rendering or remove any compute function this increment. `styleguard.test.ts` still applies (no literal px in `.tsx`) — the new files are `.ts`/`.tsx` data-layer, no inline styles.
- **Follow existing patterns.** Mirror `api.report()` (in `web/src/api.ts`) for the client method and `AccountsProvider`/`useAccountsData` (in `web/src/accountsData.tsx`) for the provider/hook, including the `activeId`/`dataVersion` keying from `useAudits()`.
- **Commit messages** end with: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- **Run from worktree root** `C:\base\dev\PasswordAtTheDisco\.claude\worktrees\nav-and-pagination-fixes` (commands that build/test run in `web/`). Do not `cd` to the primary checkout.

**Scope note:** Part of spec `docs/superpowers/specs/2026-06-30-exports-dashboard-parity-design.md`, Phase "SPA renders the bundle". This is increment **5a** (data layer only). The surface-by-surface UI migrations (Overview, Insights, Exposure, Actionable, Domains) — each rendering the bundle, deleting the corresponding TS compute, and verified live with Playwright on :8444 — are subsequent controller-driven increments. The TS compute modules (`insights.ts`/`exposure.ts`/`matrix.ts`/`domainScope.ts`/`domainData.ts`) and their tests stay UNTOUCHED this increment.

---

### Task 1: `MetricsBundle` TypeScript types

Define the TS interfaces mirroring the Go `metrics.Metrics` JSON. Reuse existing `Summary`, `Report`, `ReportAccount` types from `web/src/api.ts` where they already match.

**Files:**
- Create: `web/src/metricsBundle.ts`
- Test: `web/src/metricsBundle.test.ts`

**Interfaces:**
- Consumes: `Summary`, `ReportAccount` from `./api`.
- Produces: `MetricsBundle`, `DomainMetrics`, `Matrix`, `ChartSeries`, `ReportSeries`, and the leaf types (`Slice`, `Bar`, `Point`, `Series`, `AccountRef`, `AxisFactor`, `TierFactorBars`, `GraphNode`, `GraphEdge`, `Graph`, `ExposureHeadline`, `BridgeCluster`, `CrossDomain`, `HIBPTriage`, `WorklistRow`).

- [ ] **Step 1: Write the types**

```ts
// web/src/metricsBundle.ts
// TypeScript mirror of the Go internal/metrics bundle (the GET /api/metrics payload).
// Field names are the Go JSON tags verbatim so the SPA can render the server-computed
// metrics without recomputing. Keep in lockstep with internal/metrics/*.go.
import type { Summary, ReportAccount } from "./api"

export type Tier = "Critical" | "High" | "Medium" | "Low"

export interface Slice { name: string; value: number; color: string }
export interface Bar { name: string; value: number }
export interface Point { x: number; y: number }
export interface Series { name: string; color: string; points: Point[] }

export interface AccountRef {
  username: string
  domain: string
  risk_level: string
  risk_score: number
  hibp_breach_count: number
  has_da: boolean
  controlled_object_count: number
}

export interface AxisFactor { name: string; value: number; color: string }
export interface TierFactorBars {
  tier: string
  color: string
  exposure: AxisFactor[]
  impact: AxisFactor[]
  impact_known: boolean
}

export interface GraphNode { id: string; label: string; size: number; color: string; x: number; y: number }
export interface GraphEdge { source: string; target: string; weight: number; label?: string }
export interface Graph { nodes: GraphNode[]; edges: GraphEdge[] }

export interface Matrix {
  counts: Record<string, Record<string, number>>
  total: number
  max: number
}

export interface ChartSeries {
  risk_distribution: Slice[]
  hibp_split: Slice[]
  expiration_split: Slice[]
  length_buckets: Bar[]
  score_buckets: Bar[]
  sharing_distribution: Bar[]
  controlled_objects_buckets: Bar[]
  similarity_buckets: Bar[]
  da_exposure_by_domain: Bar[]
  complexity_counts: Bar[]
  hibp_vs_risk: Series[]
  password_age_buckets: Bar[]
  password_age_scatter: Series[]
  axis_factor_bars: TierFactorBars[]
  top_riskiest: AccountRef[]
  escalated_by_shared_da: AccountRef[]
  top_controllers: AccountRef[]
  top_controllers_more_over_100: number
}

export interface ExposureHeadline {
  cracked_da: number
  cracked_hibp: number
  cross_domain_groups: number
  domains_spanned: number
}
export interface BridgeCluster {
  domains: string[]
  size: number
  cracked: boolean
  has_da: boolean
  hibp_max: number
  members: ReportAccount[]
}
export interface CrossDomain { clusters: BridgeCluster[]; domains: string[] }
export interface HIBPTriage { tier1: ReportAccount[]; tier2: ReportAccount[] }
export interface WorklistRow { account: AccountRef; priority: number; reasons: string[] }

export interface ReportSeries {
  exposure_headline: ExposureHeadline
  cross_domain: CrossDomain
  hibp_triage: HIBPTriage
  worklist: WorklistRow[]
  reuse_graph: Graph
  similarity_graph: Graph
}

export interface DomainMetrics {
  domain: string
  summary: Summary
  matrix: Matrix
  charts: ChartSeries
}

export interface MetricsBundle {
  summary: Summary
  matrix: Matrix
  charts: ChartSeries
  reports: ReportSeries
  domains: DomainMetrics[]
}
```

- [ ] **Step 2: Write a contract test against the Go golden fixture**

This pins the TS types to the actual Go output: parse the committed Go golden and assert the bundle shape. Vitest runs node-env (can read files).

```ts
// web/src/metricsBundle.test.ts
import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { describe, it, expect } from "vitest"
import type { MetricsBundle } from "./metricsBundle"

// The Go golden is the authoritative server output; the TS types must describe it.
const goldenPath = resolve(__dirname, "../../internal/metrics/testdata/metrics_golden.json")

describe("MetricsBundle matches the Go golden", () => {
  it("parses and has the expected top-level + nested shape", () => {
    const raw = JSON.parse(readFileSync(goldenPath, "utf8")) as MetricsBundle
    // top level
    expect(raw.summary).toBeDefined()
    expect(raw.matrix).toBeDefined()
    expect(raw.charts).toBeDefined()
    expect(raw.reports).toBeDefined()
    expect(Array.isArray(raw.domains)).toBe(true)
    // matrix
    expect(typeof raw.matrix.total).toBe("number")
    expect(typeof raw.matrix.max).toBe("number")
    expect(raw.matrix.counts).toBeTruthy()
    // charts (a representative sample of the 18 fields)
    expect(Array.isArray(raw.charts.risk_distribution)).toBe(true)
    expect(Array.isArray(raw.charts.top_riskiest)).toBe(true)
    expect(typeof raw.charts.top_controllers_more_over_100).toBe("number")
    // reports
    expect(raw.reports.exposure_headline).toBeDefined()
    expect(typeof raw.reports.exposure_headline.cracked_da).toBe("number")
    expect(Array.isArray(raw.reports.worklist)).toBe(true)
    expect(raw.reports.reuse_graph).toBeDefined()
    expect(Array.isArray(raw.reports.reuse_graph.nodes)).toBe(true)
    // per-domain
    expect(raw.domains.length).toBeGreaterThan(0)
    expect(raw.domains[0].domain).toBeTypeOf("string")
    expect(raw.domains[0].charts).toBeDefined()
  })
})
```

- [ ] **Step 3: Run the test**

Run (in `web/`): `npx vitest run src/metricsBundle.test.ts`
Expected: PASS (the Go golden parses into the `MetricsBundle` shape). If a field is missing/misnamed, fix the TS type to match the golden's actual key, then re-run.

- [ ] **Step 4: Type-check + gate + commit**

Run (in `web/`): `npx tsc --noEmit` (clean), `npx vitest run` (all green).
```bash
git add web/src/metricsBundle.ts web/src/metricsBundle.test.ts
git commit -m "$(printf 'feat(web): MetricsBundle types mirroring the Go /api/metrics payload\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 2: `api.metrics()` + `useMetrics()` hook

Add the client method and a shared provider/hook that fetches the org bundle once per active audit. Inert until a component consumes it (next increment).

**Files:**
- Modify: `web/src/api.ts` (add `metrics` method)
- Create: `web/src/metricsData.tsx` (`MetricsProvider` + `useMetrics`)
- Modify: wherever providers are composed (likely `web/src/main.tsx` or `App.tsx` — find the existing `<AccountsProvider>` mount and wrap alongside it)
- Test: `web/src/metricsData.test.ts` (light — see Step 3)

**Interfaces:**
- Consumes: `MetricsBundle` (Task 1), the `request`/`api` helper in `api.ts`, `useAudits()` (`auditsData`), the `AccountsProvider` mount pattern (`accountsData.tsx`).
- Produces: `api.metrics(domain?: string)`, `MetricsProvider`, `useMetrics(): { bundle: MetricsBundle | null; loading: boolean; error: string | null }`.

- [ ] **Step 1: Add the client method**

In `web/src/api.ts`, next to `report:`, add (match the existing `request<T>("/path")` style — confirm the exact helper name/signature in the file):
```ts
  metrics: (domain?: string) =>
    request<MetricsBundle>(domain ? `/metrics?domain=${encodeURIComponent(domain)}` : "/metrics"),
```
Add `import type { MetricsBundle } from "./metricsBundle"` at the top of `api.ts` (or co-locate per the file's import convention).

- [ ] **Step 2: Create the provider/hook**

Mirror `web/src/accountsData.tsx` exactly (read it first). Create `web/src/metricsData.tsx`:
```tsx
import { createContext, useContext, useEffect, useState, type ReactNode } from "react"
import { api } from "./api"
import { useAudits } from "./auditsData"
import type { MetricsBundle } from "./metricsBundle"

interface MetricsState { bundle: MetricsBundle | null; loading: boolean; error: string | null }
const MetricsContext = createContext<MetricsState>({ bundle: null, loading: false, error: null })

// MetricsProvider fetches the org /api/metrics bundle once per active audit
// (keyed on activeId + dataVersion, same as AccountsProvider), so every dashboard
// surface can render the single server-computed copy instead of recomputing.
export function MetricsProvider({ children }: { children: ReactNode }) {
  const { activeId, dataVersion } = useAudits()
  const [state, setState] = useState<MetricsState>({ bundle: null, loading: false, error: null })
  useEffect(() => {
    if (!activeId) {
      setState({ bundle: null, loading: false, error: null })
      return
    }
    let alive = true
    setState((s) => ({ ...s, loading: true, error: null }))
    api
      .metrics()
      .then((b) => alive && setState({ bundle: b, loading: false, error: null }))
      .catch((e) => alive && setState({ bundle: null, loading: false, error: String(e) }))
    return () => {
      alive = false
    }
  }, [activeId, dataVersion])
  return <MetricsContext.Provider value={state}>{children}</MetricsContext.Provider>
}

export function useMetrics(): MetricsState {
  return useContext(MetricsContext)
}
```
(Confirm `useAudits()` exposes `activeId` and `dataVersion` — the explorer reported it does; match the exact field names from `auditsData.tsx`.)

- [ ] **Step 3: Mount the provider + verify**

Find the existing `<AccountsProvider>` in the provider tree (likely `main.tsx`/`App.tsx`) and wrap the app with `<MetricsProvider>` adjacent to it (inside `AuditsProvider`, since it depends on `useAudits`). No component consumes `useMetrics()` yet.

Verification (no jsdom hook test in this repo's node-env vitest): rely on the type-checker + build. Add a tiny `web/src/metricsData.test.ts` that only asserts the module exports exist (pure import, node-env safe):
```ts
import { describe, it, expect } from "vitest"
import { MetricsProvider, useMetrics } from "./metricsData"

describe("metricsData exports", () => {
  it("exposes the provider and hook", () => {
    expect(typeof MetricsProvider).toBe("function")
    expect(typeof useMetrics).toBe("function")
  })
})
```

- [ ] **Step 4: Gate + commit**

Run (in `web/`): `npx tsc --noEmit` (clean), `npx vitest run` (green), `npm run build` (OK).
```bash
git add web/src/api.ts web/src/metricsData.tsx web/src/metricsData.test.ts <provider-mount-file>
git commit -m "$(printf 'feat(web): api.metrics() + useMetrics() provider (inert, no UI change yet)\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

## Self-Review

**Spec coverage (5a slice):** Adds the typed bundle (`MetricsBundle` mirroring Go, pinned to the Go golden by a contract test) and the fetch layer (`api.metrics()` + `MetricsProvider`/`useMetrics`), with zero UI change and no compute removed — a safe, inert foundation. The surface-by-surface UI migrations + TS-compute deletion + Playwright verification are later controller-driven increments (noted in the Scope note).

**Placeholder scan:** No TBD/TODO; complete code in every step. Spots requiring the implementer to confirm an existing name (the `request` helper signature in `api.ts`; `useAudits` field names; the provider-mount file) are explicit "confirm against the file" instructions with the expected shape, not placeholders.

**Type consistency:** `MetricsBundle` (Task 1) is consumed by `api.metrics()` and `useMetrics()` (Task 2). Leaf field names are the Go JSON tags (`risk_distribution`, `top_controllers_more_over_100`, `cracked_da`, `has_da`, `controlled_object_count`, etc.) verified against the Go structs across Phases 1-3. `Summary`/`ReportAccount` are reused from `api.ts` (not redefined). The contract test (Task 1 Step 2) catches any drift from the actual Go golden output.
