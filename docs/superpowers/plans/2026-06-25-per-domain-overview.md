# Per-domain Overview Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the per-domain dashboard (gauge + tabs) with the full Overview dashboard scoped to the selected domain, keeping the existing domain drill-down tables below it.

**Architecture:** The Overview is almost entirely derived client-side from `accounts` (via `posture()`, `insights.ts` chart helpers, the Exposure×Impact matrix, and `kpiCounts`); the only server inputs are `summary` and `report`. We extract the Overview body of `Dashboard()` into a presentational `OverviewView` that takes `accounts`/`summary`/`report` as props, parameterize `Insights` to accept an optional `accounts` prop, add a client-side `domainScope.ts` that builds a domain-scoped `Summary` and `Report`, and rewrite `DomainDetail` to render `<OverviewView/>` + the kept drill-down tables.

**Tech Stack:** React 18 + TypeScript + Vite. Tests: vitest (node-env, pure-logic — no jsdom/component render). Gates (run in `web/`, **NEVER `npm install`** — node_modules is junctioned): `npx tsc --noEmit`, `npx vitest run`, `npm run build`. The `styleguard.test.ts` gate bans literal px/number inline spacing in `.tsx` `style={{}}` — use CSS classes (no new inline styles are introduced by this plan).

**Spec:** `docs/superpowers/specs/2026-06-25-per-domain-overview-design.md`

**Working directory:** all paths are relative to repo root `C:\base\dev\PasswordAtTheDisco\.claude\worktrees\account-detail-page`. Run all `npx`/`npm` commands from the `web/` subdirectory.

**Commit hygiene:** stage explicit paths only — **NEVER `git add -A` / `git add .`** (the working tree holds skip-worktree pinned files and gitignored data that must never be committed).

---

## Decisions locked for implementation (resolving the spec's open points)

- **`OverviewView.summary` prop type is `Summary | null`** (not `Summary`). `Dashboard()` renders the Overview while `summary` is still loading (null) — the secondary stat-grid and PostureCard are already guarded by `summary &&`/`summary ?`. Keeping the prop nullable preserves that behavior exactly. `domainSummary` always returns a non-null `Summary`, so the domain page is unaffected.
- **`breach_impact` is omitted for domains** (no client estimator). This requires widening `Summary.breach_impact` to optional (`breach_impact?: BreachImpact`). `PostureCard` already accepts `BreachImpact | undefined` and renders the breach block only when `breachImpact && verdict !== "No Data"`, so omission cleanly hides that one sub-panel.
- **Org-global page chrome stays on the org Overview only.** The Recalculate/Reports action buttons and `<BackgroundJobsCard/>` are org-level. `OverviewView` exposes an optional `actions` prop for the buttons; `Dashboard()` passes them and renders `<BackgroundJobsCard/>` in its wrapper. The domain page passes no actions and renders no jobs card. The "Data scored {timestamp}" line, coverage banner, and `RecalcSuggestion` stay inside `OverviewView` (they read the scoped `accounts`/`summary` and are correct for a domain).
- **Kept domain drill-downs (verbatim, no tabs):** DA-pathway accounts, Reused passwords (cracked), Shared uncracked hashes, Escalated by Shared-DA, Stale passwords, Password never expires, Kerberoastable. The old gauge, the tab chrome, the Policy/Wordlist strips, and the Accounts tab (quick-wins + all-accounts table) are removed — `OverviewView` replaces the overview content, and the full accounts table remains available in the main Accounts view.
- **`generated_at` for the domain** is copied from the org summary (same scoring run). `Domains()` fetches `api.summary()` (mirroring its existing `api.report()` fetch) and threads it to `DomainDetail`.
- **`domainReport.violation_counts`** is passed through unchanged from the org report (it only affects Insights labels; recomputing per-domain is not worth the risk per the spec's "low-stakes, prefer simplest correct option").

## File Structure

| Action | Path | Responsibility |
|---|---|---|
| Modify | `web/src/api.ts` | widen `Summary.breach_impact` to optional |
| Create | `web/src/domainScope.ts` | `domainSummary`, `domainReport` — pure client builders |
| Create | `web/src/domainScope.test.ts` | vitest for the two builders |
| Modify | `web/src/components/Insights.tsx` | optional `accounts` prop (default context) |
| Modify | `web/src/components/Dashboard.tsx` | extract + export `OverviewView`; `Dashboard()` becomes a thin wrapper |
| Modify | `web/src/components/Domains.tsx` | `Domains()` fetches org summary; `DomainDetail` renders `OverviewView` + kept drill-down tables |

---

## Task 1: Domain-scoped `Summary` builder (`domainSummary`)

Build the client-side `domainSummary(domainAccounts, orgSummary)` that produces a `Summary` for a filtered account set — posture via the existing client `posture()` builder, all counts by filtering, `breach_impact` omitted, `generated_at` copied from the org summary.

**Files:**
- Modify: `web/src/api.ts` (widen `Summary.breach_impact`)
- Create: `web/src/domainScope.ts`
- Test: `web/src/domainScope.test.ts`

- [ ] **Step 1: Widen `Summary.breach_impact` to optional**

In `web/src/api.ts`, in the `Summary` interface (around line 99-100), change the required field to optional so a domain summary can omit it:

```ts
  // Executive breach impact. Optional: domain-scoped summaries omit it (no client
  // estimator), which cleanly hides the PostureCard breach sub-panel for domains.
  breach_impact?: BreachImpact
```

(Only the `breach_impact: BreachImpact` line changes to `breach_impact?: BreachImpact` — leave the comment line above it or replace it with the comment shown.)

- [ ] **Step 2: Write the failing test for `domainSummary`**

Create `web/src/domainScope.test.ts`:

```ts
import { describe, expect, it } from "vitest"
import { domainSummary } from "./domainScope"
import type { Account, Summary } from "./api"

// Minimal Account factory — only the fields the builders read.
function acc(over: Partial<Account>): Account {
  return {
    username: "u", domain: "A.LOCAL", cracked: false, password_length: 0,
    risk_level: "Low", risk_score: 0, exposure_score: 0, impact_score: null,
    impact_known: false, percentile: 0, risk_vector: "", hibp_breached: false,
    hibp_breach_count: 0, da_domains: "", controlled_object_count: 0, shared_with: 0,
    enabled: true, meets_policy: true, complexity: "",
    ...over,
  }
}

const orgSummary = { generated_at: "2026-06-20T10:00:00Z" } as Summary

describe("domainSummary", () => {
  it("counts only the passed (already-domain-filtered) accounts", () => {
    const domainAccounts: Account[] = [
      acc({ username: "a", domain: "A.LOCAL", cracked: true, meets_policy: false, hibp_breached: true, hibp_breach_count: 5 }),
      acc({ username: "b", domain: "A.LOCAL", cracked: true, da_domains: "A.LOCAL", controlled_object_count: 200 }),
      acc({ username: "c", domain: "A.LOCAL", enabled: false, pwd_never_expires: true }),
      acc({ username: "d", domain: "A.LOCAL", days_out_of_compliance: 30 }),
    ]
    const s = domainSummary(domainAccounts, orgSummary)
    expect(s.total_accounts).toBe(4)
    expect(s.cracked).toBe(2)
    expect(s.hibp_breached).toBe(1)
    expect(s.da_pathways).toBe(1)
    expect(s.disabled_accounts).toBe(1)
    expect(s.never_expires).toBe(1)
    expect(s.stale_passwords).toBe(1)
    expect(s.policy_violations).toBe(1) // cracked && !meets_policy
    expect(s.high_controlled).toBe(1)   // controlled_object_count > 100
  })

  it("omits breach_impact and copies generated_at from the org summary", () => {
    const s = domainSummary([acc({})], orgSummary)
    expect(s.breach_impact).toBeUndefined()
    expect(s.generated_at).toBe("2026-06-20T10:00:00Z")
  })

  it("tallies risk_counts by risk_level and attaches a posture", () => {
    const s = domainSummary(
      [acc({ risk_level: "Critical" }), acc({ risk_level: "Critical" }), acc({ risk_level: "Low" })],
      orgSummary,
    )
    expect(s.risk_counts).toEqual({ Critical: 2, Low: 1 })
    expect(s.posture).toBeDefined()
    expect(typeof s.posture.score).toBe("number")
  })

  it("counts dormant_privileged as disabled privileged accounts", () => {
    const s = domainSummary(
      [
        acc({ enabled: false, controls_tier0: true }),       // dormant privileged
        acc({ enabled: false }),                              // disabled, not privileged
        acc({ enabled: true, controls_tier0: true }),         // privileged but enabled
      ],
      orgSummary,
    )
    expect(s.dormant_privileged).toBe(1)
  })
})
```

- [ ] **Step 3: Run the test to verify it fails**

Run (from `web/`): `npx vitest run src/domainScope.test.ts`
Expected: FAIL — cannot resolve `./domainScope` / `domainSummary is not exported`.

- [ ] **Step 4: Implement `domainSummary`**

Create `web/src/domainScope.ts`:

```ts
import type { Account, Summary } from "./api"
import { escalatedBySharedDA, neverExpiresCount, posture } from "./insights"
import { hasDA } from "./util"

// A domain-scoped account is "privileged" if it controls Tier-0, has a DA pathway,
// or is a high-privilege controller (>100 controlled objects). Used for the
// dormant-privileged (disabled + privileged) count surfaced in the posture card.
function isPrivileged(a: Account): boolean {
  return !!a.controls_tier0 || hasDA(a.da_domains) || (a.controlled_object_count ?? 0) > 100
}

// domainSummary builds a Summary for an already-domain-filtered account set so the
// per-domain page can render the same Overview as the org view. Counts mirror the
// Go model.Summary semantics surfaced in the Dashboard KPIs; posture reuses the
// client posture() builder (kept in sync with the Go authoritative posture). It is
// intentionally NOT the server summary — breach_impact is omitted (no client
// estimator) and generated_at is copied from the org summary (same scoring run).
export function domainSummary(domainAccounts: Account[], orgSummary: Summary): Summary {
  const riskCounts: Record<string, number> = {}
  for (const a of domainAccounts) {
    riskCounts[a.risk_level] = (riskCounts[a.risk_level] ?? 0) + 1
  }
  return {
    total_accounts: domainAccounts.length,
    cracked: domainAccounts.filter((a) => a.cracked).length,
    hibp_breached: domainAccounts.filter((a) => a.hibp_breached).length,
    da_pathways: domainAccounts.filter((a) => hasDA(a.da_domains)).length,
    risk_counts: riskCounts,
    posture: posture(domainAccounts),
    generated_at: orgSummary.generated_at,
    disabled_accounts: domainAccounts.filter((a) => !a.enabled).length,
    never_expires: neverExpiresCount(domainAccounts),
    stale_passwords: domainAccounts.filter((a) => (a.days_out_of_compliance ?? 0) > 0).length,
    escalated_by_shared_da: escalatedBySharedDA(domainAccounts).length,
    escalated_by_mass_reuse: domainAccounts.filter((a) => a.escalated_by_mass_reuse).length,
    policy_violations: domainAccounts.filter((a) => a.cracked && !a.meets_policy).length,
    high_controlled: domainAccounts.filter((a) => (a.controlled_object_count ?? 0) > 100).length,
    dormant_privileged: domainAccounts.filter((a) => !a.enabled && isPrivileged(a)).length,
    // breach_impact intentionally omitted — see header comment.
  }
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run (from `web/`): `npx vitest run src/domainScope.test.ts`
Expected: PASS (4 tests in the `domainSummary` describe).

- [ ] **Step 6: Typecheck**

Run (from `web/`): `npx tsc --noEmit`
Expected: no errors. (Confirms the `breach_impact?` widening did not break any existing consumer.)

- [ ] **Step 7: Commit**

```bash
git add web/src/api.ts web/src/domainScope.ts web/src/domainScope.test.ts
git commit -m "feat(domains): client-side domainSummary builder for scoped Overview"
```

---

## Task 2: Domain-scoped `Report` builder (`domainReport`)

Add `domainReport(orgReport, domain)` to `domainScope.ts`: filter the per-account report lists to the domain, and keep reuse groups that have at least one member in the domain (so cross-domain clusters the domain participates in stay visible).

**Files:**
- Modify: `web/src/domainScope.ts`
- Test: `web/src/domainScope.test.ts`

- [ ] **Step 1: Write the failing test for `domainReport`**

Append to `web/src/domainScope.test.ts` (add `domainReport` to the existing import, and `Report`, `ReportAccount`, `ReuseGroup` to the type import from `./api`):

```ts
import { domainReport, domainSummary } from "./domainScope"
import type { Account, Report, ReportAccount, ReuseGroup, Summary } from "./api"

function ra(username: string, domain: string): ReportAccount {
  return {
    username, domain, cracked: true, risk_level: "High", risk_score: 5,
    hibp_breach_count: 0, shared_with: 0, controlled_object_count: 0, enabled: true,
  }
}

function group(id: number, memberDomains: string[]): ReuseGroup {
  return {
    group_id: id, size: memberDomains.length, cracked: true, hibp_breach_count: 0,
    has_da_pathway: false, domains: new Set(memberDomains).size,
    members: memberDomains.map((d, i) => ra(`m${id}_${i}`, d)),
  }
}

function emptyReport(over: Partial<Report>): Report {
  return {
    total_accounts: 0, cracked_count: 0, uncracked_count: 0, da_pathways: [], cracked: [],
    cracked_reuse: [], uncracked_reuse: [], hibp_exposed: [], weak_passwords: [],
    violation_counts: { common: 0, dictionary: 0, forbidden: 0, keyboard: 0 },
    escalated_by_shared_da: [], high_controlled: [], never_expires: [], stale_passwords: [],
    kerberoastable: [], asrep_roastable: [],
    ...over,
  }
}

describe("domainReport", () => {
  it("returns null when the org report is null", () => {
    expect(domainReport(null, "A.LOCAL")).toBeNull()
  })

  it("filters per-account lists to the domain", () => {
    const org = emptyReport({
      da_pathways: [ra("a", "A.LOCAL"), ra("b", "B.LOCAL")],
      cracked: [ra("a", "A.LOCAL"), ra("c", "A.LOCAL"), ra("d", "B.LOCAL")],
      hibp_exposed: [ra("d", "B.LOCAL")],
    })
    const d = domainReport(org, "A.LOCAL")!
    expect(d.da_pathways.map((x) => x.username)).toEqual(["a"])
    expect(d.cracked.map((x) => x.username)).toEqual(["a", "c"])
    expect(d.hibp_exposed).toEqual([])
  })

  it("keeps reuse groups with at least one member in the domain", () => {
    const org = emptyReport({
      cracked_reuse: [group(1, ["A.LOCAL", "B.LOCAL"]), group(2, ["B.LOCAL", "C.LOCAL"])],
    })
    const d = domainReport(org, "A.LOCAL")!
    expect(d.cracked_reuse.map((g) => g.group_id)).toEqual([1])
  })

  it("derives total/cracked/uncracked counts from the filtered domain accounts", () => {
    const org = emptyReport({ total_accounts: 99, cracked_count: 50, uncracked_count: 49 })
    const domainAccounts: Account[] = [
      { username: "a", domain: "A.LOCAL", cracked: true } as Account,
      { username: "b", domain: "A.LOCAL", cracked: false } as Account,
    ]
    const d = domainReport(org, "A.LOCAL", domainAccounts)!
    expect(d.total_accounts).toBe(2)
    expect(d.cracked_count).toBe(1)
    expect(d.uncracked_count).toBe(1)
  })

  it("passes violation_counts through unchanged", () => {
    const org = emptyReport({ violation_counts: { common: 3, dictionary: 2, forbidden: 1, keyboard: 0 } })
    const d = domainReport(org, "A.LOCAL")!
    expect(d.violation_counts).toEqual({ common: 3, dictionary: 2, forbidden: 1, keyboard: 0 })
  })
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run (from `web/`): `npx vitest run src/domainScope.test.ts`
Expected: FAIL — `domainReport is not exported`.

- [ ] **Step 3: Implement `domainReport`**

Append to `web/src/domainScope.ts` (and add `Report, ReportAccount, ReuseGroup` to the existing type import from `./api`):

```ts
import type { Account, Report, ReportAccount, ReuseGroup, Summary } from "./api"

const inDomain = (domain: string) => (x: ReportAccount) => x.domain === domain
const groupTouchesDomain = (domain: string) => (g: ReuseGroup) =>
  g.members.some((m) => m.domain === domain)

// domainReport scopes an org Report to a single domain for the per-domain Overview's
// report-driven panels (the cross-domain reuse graph + Insights). Per-account lists
// are filtered to the domain; reuse groups are kept when ANY member is in the domain
// (so cross-domain clusters the domain participates in remain visible). violation_counts
// is passed through (labels only — low-stakes). total/cracked/uncracked come from the
// filtered domain accounts when provided, else fall back to the org report's totals.
export function domainReport(
  orgReport: Report | null,
  domain: string,
  domainAccounts?: Account[],
): Report | null {
  if (!orgReport) return null
  const keep = inDomain(domain)
  const keepGroup = groupTouchesDomain(domain)
  const crackedCount = domainAccounts?.filter((a) => a.cracked).length
  return {
    total_accounts: domainAccounts ? domainAccounts.length : orgReport.total_accounts,
    cracked_count: crackedCount ?? orgReport.cracked_count,
    uncracked_count: domainAccounts ? domainAccounts.length - (crackedCount ?? 0) : orgReport.uncracked_count,
    da_pathways: orgReport.da_pathways.filter(keep),
    cracked: orgReport.cracked.filter(keep),
    cracked_reuse: orgReport.cracked_reuse.filter(keepGroup),
    uncracked_reuse: orgReport.uncracked_reuse.filter(keepGroup),
    hibp_exposed: orgReport.hibp_exposed.filter(keep),
    weak_passwords: orgReport.weak_passwords.filter(keep),
    violation_counts: orgReport.violation_counts,
    escalated_by_shared_da: orgReport.escalated_by_shared_da.filter(keep),
    high_controlled: orgReport.high_controlled.filter(keep),
    never_expires: orgReport.never_expires.filter(keep),
    stale_passwords: orgReport.stale_passwords.filter(keep),
    kerberoastable: orgReport.kerberoastable.filter(keep),
    asrep_roastable: orgReport.asrep_roastable.filter(keep),
  }
}
```

Note: merge the two `import type … from "./api"` lines into one (`import type { Account, Report, ReportAccount, ReuseGroup, Summary } from "./api"`) — don't leave a duplicate import.

- [ ] **Step 4: Run the test to verify it passes**

Run (from `web/`): `npx vitest run src/domainScope.test.ts`
Expected: PASS (all `domainSummary` + `domainReport` tests).

- [ ] **Step 5: Typecheck**

Run (from `web/`): `npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add web/src/domainScope.ts web/src/domainScope.test.ts
git commit -m "feat(domains): client-side domainReport builder (domain-scoped report)"
```

---

## Task 3: Parameterize `Insights` with an optional `accounts` prop

`Insights` reads `accounts` from context. Add an optional `accounts` prop; when provided it is used, otherwise it falls back to context. Existing call sites (no `accounts` prop) are unaffected.

**Files:**
- Modify: `web/src/components/Insights.tsx:11-18`

- [ ] **Step 1: Change the component signature to accept an optional `accounts` prop**

In `web/src/components/Insights.tsx`, replace the signature and the context destructure (lines 11-13):

```tsx
export function Insights({ report, accounts: accountsProp }: { report: Report | null; accounts?: Account[] }) {
  const { activeId } = useAudits()
  const { accounts: ctxAccounts, error } = useAccountsData()
  const accounts = accountsProp ?? ctxAccounts
```

Add `Account` to the api type import at the top of the file (line 9):

```tsx
import type { Account, Report } from "../api"
```

The rest of the component body is unchanged — every `accounts` reference now resolves to the prop-or-context value. (Note: the `if (!accounts) …` guard still works because context `accounts` can be null; when a prop is passed it is always a concrete array.)

- [ ] **Step 2: Typecheck**

Run (from `web/`): `npx tsc --noEmit`
Expected: no errors. The existing `<Insights report={report} />` call site in `Dashboard.tsx` still compiles (the new prop is optional).

- [ ] **Step 3: Run the full vitest suite (no regressions)**

Run (from `web/`): `npx vitest run`
Expected: PASS (all existing tests + the new `domainScope` tests).

- [ ] **Step 4: Commit**

```bash
git add web/src/components/Insights.tsx
git commit -m "refactor(insights): optional accounts prop (defaults to context)"
```

---

## Task 4: Extract and export `OverviewView` from `Dashboard`

Extract the Overview render body of `Dashboard()` into a presentational, exported `OverviewView` that takes `accounts`/`summary`/`report` (+ optional `title`/`subtitle`/`actions`) as props. `Dashboard()` becomes a thin wrapper: it reads context + fetches `summary`/`report` exactly as today, and renders `<OverviewView … />` with the org-level action buttons and `<BackgroundJobsCard/>`. This is a **behavior-preserving refactor** of the org Overview.

**Files:**
- Modify: `web/src/components/Dashboard.tsx`

- [ ] **Step 1: Add the `OverviewView` component**

In `web/src/components/Dashboard.tsx`, add a `ReactNode` import and insert the exported `OverviewView` component (place it directly after the `Dashboard` function, before the `PostureCard` section). Update the React import on line 1:

```tsx
import { useEffect, useState, type ReactNode } from "react"
```

Then add:

```tsx
// OverviewView is the presentational Overview dashboard. It is shared by the org
// Dashboard (its default render) and the per-domain page (fed domain-scoped
// accounts/summary/report). Everything here is derived from the props — no context,
// no fetching — so the same panels render identically for org and domain. Org-global
// chrome (Recalc/Reports buttons, the background-jobs card) lives in the Dashboard
// wrapper, passed in via `actions`.
export function OverviewView({
  accounts,
  summary,
  report,
  title = "Overview",
  subtitle = "Where do we stand? Org-wide posture at a glance.",
  actions,
}: {
  accounts: Account[]
  summary: Summary | null
  report: Report | null
  title?: string
  subtitle?: string
  actions?: ReactNode
}) {
  const { total, cracked, breached, da } = kpiCounts(summary, accounts)
  const crackPct = total ? Math.round((cracked / total) * 100) : 0

  const cov = coverageStats(accounts)
  const eiMatrix = exposureImpactMatrix(accounts)
  const impactUnknown = accounts.filter(isProvisional).length

  return (
    <>
      <div className="view-head">
        <div className="section-label">{title}</div>
        <div className="export-actions">
          {summary?.generated_at && <span className="muted data-ts">Data scored {new Date(summary.generated_at).toLocaleString()}</span>}
          {actions}
        </div>
      </div>
      <div className="view-sub">{subtitle}</div>
      {cov.partial && (
        <div className="coverage-banner" role="status">
          <span className="coverage-banner-dot" aria-hidden="true" />
          <span className="coverage-banner-text">
            <b>BloodHound: {cov.enriched}/{cov.total} accounts enriched</b> — Impact is Unknown for the rest.
          </span>
          <InfoTip text={GLOSSARY.coverage} />
        </div>
      )}
      <RecalcSuggestion />
      <div className="stat-grid">
        <Stat label="Accounts" value={total} delay={0} />
        <Stat label="Cracked" value={cracked} sub={`${crackPct}% of accounts`} delay={0.06} />
        <Stat label="HIBP Breached" value={breached} tip={GLOSSARY.hibp} accent delay={0.12} />
        <Stat label="DA Pathways" value={da} tip={GLOSSARY.da_pathway} crit delay={0.18} />
        <Stat label="Impact Unknown" value={impactUnknown} sub="no BloodHound coverage" tip={GLOSSARY.impact_unknown} accent delay={0.24} />
      </div>

      <ExposureHeadline accounts={accounts} report={report} />
      {summary && (
        <div className="stat-grid stat-grid-secondary">
          <Stat label="Disabled" value={summary.disabled_accounts} delay={0} />
          <Stat label="Never Expires" value={summary.never_expires} sub="password set to never expire" delay={0.06} />
          <Stat label="Stale Passwords" value={summary.stale_passwords} sub="past max age policy" accent delay={0.12} />
          <Stat label="Policy Violations" value={summary.policy_violations} sub="cracked & failing policy" accent delay={0.18} />
          <Stat label="Escalated (Shared-DA)" value={summary.escalated_by_shared_da} sub="shares hash with a DA" tip={GLOSSARY.escalated_shared_da} crit delay={0.24} />
          <Stat label="High Privilege" value={summary.high_controlled} sub="controls > 100 objects" tip={GLOSSARY.high_controlled} crit delay={0.3} />
        </div>
      )}

      <div className="section-label">Security Posture</div>
      {summary ? (
        <PostureCard
          posture={summary.posture}
          breachImpact={summary.breach_impact}
          dormantPrivileged={summary.dormant_privileged}
          enabledCount={summary.total_accounts - summary.disabled_accounts}
        />
      ) : (
        <div className="panel"><div className="center-state"><div className="spinner">scoring</div></div></div>
      )}

      <div className="section-label">Exposure × Impact <InfoTip text={GLOSSARY.exposure_impact_matrix} /></div>
      <div className="panel matrix-panel">
        <MatrixHeatmap m={eiMatrix} />
      </div>

      <div className="section-label">Charts</div>
      <div className="chart-grid">
        <ChartCard title="Risk distribution">
          <Donut data={riskDistribution(accounts)} />
        </ChartCard>
        <ChartCard title="HIBP exposure">
          <Donut data={hibpSplit(accounts)} />
        </ChartCard>
        <ChartCard title="Password length (cracked)">
          <Bars data={lengthBuckets(accounts)} color="#818cf8" />
        </ChartCard>
      </div>

      <Insights report={report} accounts={accounts} />
    </>
  )
}
```

- [ ] **Step 2: Reduce `Dashboard()` to a wrapper that renders `OverviewView`**

In `web/src/components/Dashboard.tsx`, replace the body of `Dashboard()` from the `const { total, cracked, breached, da } = kpiCounts(...)` line (currently line 81) through the end of its `return (…)` block (currently the `</>` + `)` ending at line 166) with:

```tsx
  return (
    <>
      <OverviewView
        accounts={accounts}
        summary={summary}
        report={report}
        actions={
          <>
            <RecalcControl hasScored={!!summary?.generated_at} />
            <button className="btn" onClick={() => nav("reports")}>Reports &amp; export →</button>
          </>
        }
      />
      <BackgroundJobsCard />
    </>
  )
```

Leave everything above (lines 45-79: the hooks, the `summary`/`report` effects, and the loading/empty guards) unchanged. The locals `cov`, `eiMatrix`, `impactUnknown`, `crackPct` that previously lived in `Dashboard()` now live in `OverviewView` — they must NOT remain in `Dashboard()` (delete them as part of replacing the body).

- [ ] **Step 3: Typecheck**

Run (from `web/`): `npx tsc --noEmit`
Expected: no errors, and **no unused-symbol errors** — every import (`kpiCounts`, `coverageStats`, `exposureImpactMatrix`, `isProvisional`, all chart components, `Stat`, `InfoTip`, `GLOSSARY`, etc.) is still referenced, now from inside `OverviewView` in the same module. `nav` is still used in the wrapper's `actions`.

- [ ] **Step 4: Build to confirm the refactor is sound**

Run (from `web/`): `npm run build`
Expected: build succeeds (Vite + tsc), no errors.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/Dashboard.tsx
git commit -m "refactor(dashboard): extract presentational OverviewView (org behavior unchanged)"
```

---

## Task 5: Rewrite `DomainDetail` to render the scoped Overview + kept tables

`Domains()` fetches the org `summary` (mirroring its existing `report` fetch) and threads it into `DomainDetail`. `DomainDetail` builds `domainSummary`/`domainReport`, renders `<OverviewView … title={domain} />`, and keeps the DA-pathway / reuse-cluster / escalated / stale / never-expires / Kerberoastable drill-down tables below it. The gauge, tabs, Policy/Wordlist strips, and Accounts tab are removed.

**Files:**
- Modify: `web/src/components/Domains.tsx`

- [ ] **Step 1: Update imports and fetch the org summary in `Domains()`**

In `web/src/components/Domains.tsx`:

Replace the import block (lines 1-13) with this (drops the now-unused `posture`, `riskDistribution`, `hibpSplit`, `PostureGauge`, `Donut`, `ChartCard`, `AccountsTable`, `domainPolicy`, `domainWordlist`, `domainQuickWins`; adds `Summary`, `OverviewView`, `domainReport`, `domainSummary`):

```tsx
import { useEffect, useMemo, useState } from "react"
import { api, ApiError, type Account, type Report, type ReportAccount, type ReuseGroup, type Summary } from "../api"
import { useAccountsData } from "../accountsData"
import { useAudits } from "../auditsData"
import { hasDA, RISK_CLASS, RISK_RANK } from "../util"
import { OverviewView } from "./Dashboard"
import { domainReport, domainSummary } from "../domainScope"
import { AccountLink } from "./AccountLink"
import { useSortablePaged, type SortColumn } from "../sortPage"
import { SortHeader } from "./SortHeader"
import { Pager } from "./Pager"
import { domainDAPaths, domainReuseClusters } from "../domainData"
```

In `Domains()`, add an org-summary state + fetch next to the existing report fetch. After the `report`/`reportErr` state (line 31-32) add:

```tsx
  const [summary, setSummary] = useState<Summary | null>(null)
```

Extend the existing report effect (lines 39-44) to also fetch the summary:

```tsx
  useEffect(() => {
    let alive = true
    setReport(null); setReportErr(""); setSummary(null)
    api.report().then((r) => alive && setReport(r)).catch((e) => alive && setReportErr(e instanceof ApiError ? e.message : "report unavailable"))
    api.summary().then((s) => alive && setSummary(s)).catch(() => {})
    return () => { alive = false }
  }, [activeId, dataVersion])
```

Pass `summary` into `DomainDetail` — update the render call (line 59):

```tsx
    if (domainAccts.length) return <DomainDetail domain={selected} accounts={domainAccts} report={report} reportErr={reportErr} summary={summary} onBack={() => setSelected(null)} />
```

(The `RATING_COLOR` const on line 15 is now unused — delete it.)

- [ ] **Step 2: Replace the `DomainDetail` component body**

Replace the entire `DomainDetail` function (currently lines 107-362) with:

```tsx
function DomainDetail({ domain, accounts, report, reportErr, summary, onBack }: { domain: string; accounts: Account[]; report: Report | null; reportErr: string; summary: Summary | null; onBack: () => void }) {
  const dSummary = useMemo(() => (summary ? domainSummary(accounts, summary) : null), [accounts, summary])
  const dReport = useMemo(() => domainReport(report, domain, accounts), [report, domain, accounts])

  const clusters = useMemo(
    () => (report ? domainReuseClusters(report, domain) : { cracked: [], uncracked: [] }),
    [report, domain],
  )
  const daPaths = useMemo(() => (report ? domainDAPaths(report, domain) : []), [report, domain])

  const daCols: SortColumn<ReportAccount>[] = [
    { key: "username", get: (a) => a.username },
    { key: "risk", get: (a) => RISK_RANK[a.risk_level] ?? 0, defaultDir: "desc" },
    { key: "score", get: (a) => a.risk_score, defaultDir: "desc" },
    { key: "hibp", get: (a) => a.hibp_breach_count, defaultDir: "desc" },
    { key: "da", get: (a) => a.da_domains ?? "" },
    { key: "controlled", get: (a) => a.controlled_object_count, defaultDir: "desc" },
  ]
  const detailCols: SortColumn<Account>[] = [
    { key: "username", get: (a) => a.username },
    { key: "risk", get: (a) => RISK_RANK[a.risk_level] ?? 0, defaultDir: "desc" },
    { key: "score", get: (a) => a.risk_score, defaultDir: "desc" },
    { key: "hibp", get: (a) => a.hibp_breach_count, defaultDir: "desc" },
    { key: "shared", get: (a) => a.shared_with, defaultDir: "desc" },
    { key: "days", get: (a) => a.days_out_of_compliance ?? 0, defaultDir: "desc" },
    { key: "controlled", get: (a) => a.controlled_object_count ?? 0, defaultDir: "desc" },
    { key: "enabled", get: (a) => !!a.enabled },
    { key: "da", get: (a) => a.da_domains ?? "" },
  ]
  const escalatedRows = useMemo(() => accounts.filter((a) => a.escalated_by_shared_da), [accounts])
  const staleRows = useMemo(() => accounts.filter((a) => (a.days_out_of_compliance ?? 0) > 0), [accounts])
  const neverExpiresRows = useMemo(() => accounts.filter((a) => a.pwd_never_expires === true), [accounts])
  const kerberoastRows = useMemo(() => accounts.filter((a) => a.has_spn === true), [accounts])

  const daPage = useSortablePaged(daPaths, daCols, { defaultSort: { key: "score", dir: "desc" } })
  const escalatedPage = useSortablePaged(escalatedRows, detailCols, { defaultSort: { key: "score", dir: "desc" } })
  const stalePage = useSortablePaged(staleRows, detailCols, { defaultSort: { key: "days", dir: "desc" } })
  const neverExpiresPage = useSortablePaged(neverExpiresRows, detailCols, { defaultSort: { key: "score", dir: "desc" } })
  const kerberoastPage = useSortablePaged(kerberoastRows, detailCols, { defaultSort: { key: "score", dir: "desc" } })

  return (
    <>
      <button className="link-btn domain-back" onClick={onBack}>← All domains</button>

      <OverviewView accounts={accounts} summary={dSummary} report={dReport} title={domain} subtitle="Where does this domain stand?" />

      <div className="section-label">Domain drill-down</div>
      {reportErr && <div className="hint">{reportErr} — cluster/DA panels need the report.</div>}

      <div className="section-label sub">DA-pathway accounts</div>
      <div className="panel">
        {daPaths.length === 0 ? (
          <div className="muted">No BloodHound DA pathways in this domain.</div>
        ) : (
          <>
            <table className="accounts compact"><thead><tr>
              <SortHeader label="Username" colKey="username" sort={daPage.sort} onSort={daPage.setSort} />
              <SortHeader label="Risk" colKey="risk" sort={daPage.sort} onSort={daPage.setSort} />
              <SortHeader label="Score" colKey="score" numeric sort={daPage.sort} onSort={daPage.setSort} />
              <SortHeader label="HIBP" colKey="hibp" numeric sort={daPage.sort} onSort={daPage.setSort} />
              <SortHeader label="DA domains" colKey="da" sort={daPage.sort} onSort={daPage.setSort} />
              <SortHeader label="Controlled" colKey="controlled" numeric sort={daPage.sort} onSort={daPage.setSort} />
            </tr></thead>
              <tbody>{daPage.rows.map((a) => (<tr key={a.username}><td><AccountLink username={a.username} domain={a.domain} /></td><td><span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span></td><td className="num">{a.risk_score.toFixed(1)}</td><td className="num">{a.hibp_breach_count || "—"}</td><td className="muted">{a.da_domains ?? "—"}</td><td className="num">{a.controlled_object_count || "—"}</td></tr>))}</tbody>
            </table>
            <Pager page={daPage} />
          </>
        )}
      </div>

      <ReuseClusters title="Reused passwords (cracked)" groups={clusters.cracked} lateral={false} />
      <ReuseClusters title="Shared uncracked hashes (lateral movement)" groups={clusters.uncracked} lateral={true} />

      <div className="section-label sub">Escalated by Shared-DA</div>
      <div className="panel">
        {escalatedRows.length === 0 ? (
          <div className="muted">No accounts escalated via hash-sharing with a DA.</div>
        ) : (
          <>
            <table className="accounts compact"><thead><tr>
              <SortHeader label="Username" colKey="username" sort={escalatedPage.sort} onSort={escalatedPage.setSort} />
              <SortHeader label="Risk" colKey="risk" sort={escalatedPage.sort} onSort={escalatedPage.setSort} />
              <SortHeader label="Score" colKey="score" numeric sort={escalatedPage.sort} onSort={escalatedPage.setSort} />
              <SortHeader label="Shared" colKey="shared" numeric sort={escalatedPage.sort} onSort={escalatedPage.setSort} />
            </tr></thead>
              <tbody>{escalatedPage.rows.map((a) => (
                <tr key={a.username}><td><AccountLink username={a.username} domain={a.domain} /></td><td><span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span></td><td className="num">{a.risk_score.toFixed(1)}</td><td className="num">{a.shared_with}</td></tr>
              ))}</tbody>
            </table>
            <Pager page={escalatedPage} />
          </>
        )}
      </div>

      <div className="section-label sub">Stale passwords (past max age)</div>
      <div className="panel">
        {staleRows.length === 0 ? (
          <div className="muted">No stale passwords in this domain.</div>
        ) : (
          <>
            <table className="accounts compact"><thead><tr>
              <SortHeader label="Username" colKey="username" sort={stalePage.sort} onSort={stalePage.setSort} />
              <SortHeader label="Risk" colKey="risk" sort={stalePage.sort} onSort={stalePage.setSort} />
              <SortHeader label="Score" colKey="score" numeric sort={stalePage.sort} onSort={stalePage.setSort} />
              <SortHeader label="Days overdue" colKey="days" numeric sort={stalePage.sort} onSort={stalePage.setSort} />
              <SortHeader label="Enabled" colKey="enabled" sort={stalePage.sort} onSort={stalePage.setSort} />
            </tr></thead>
              <tbody>{stalePage.rows.map((a) => (
                <tr key={a.username}><td><AccountLink username={a.username} domain={a.domain} /></td><td><span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span></td><td className="num">{a.risk_score.toFixed(1)}</td><td className="num">{a.days_out_of_compliance}d</td><td>{a.enabled ? "Yes" : <span className="muted">No</span>}</td></tr>
              ))}</tbody>
            </table>
            <Pager page={stalePage} />
          </>
        )}
      </div>

      <div className="section-label sub">Password never expires</div>
      <div className="panel">
        {neverExpiresRows.length === 0 ? (
          <div className="muted">No accounts with non-expiring passwords.</div>
        ) : (
          <>
            <table className="accounts compact"><thead><tr>
              <SortHeader label="Username" colKey="username" sort={neverExpiresPage.sort} onSort={neverExpiresPage.setSort} />
              <SortHeader label="Risk" colKey="risk" sort={neverExpiresPage.sort} onSort={neverExpiresPage.setSort} />
              <SortHeader label="Score" colKey="score" numeric sort={neverExpiresPage.sort} onSort={neverExpiresPage.setSort} />
              <SortHeader label="HIBP" colKey="hibp" numeric sort={neverExpiresPage.sort} onSort={neverExpiresPage.setSort} />
              <SortHeader label="Enabled" colKey="enabled" sort={neverExpiresPage.sort} onSort={neverExpiresPage.setSort} />
            </tr></thead>
              <tbody>{neverExpiresPage.rows.map((a) => (
                <tr key={a.username}><td><AccountLink username={a.username} domain={a.domain} /></td><td><span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span></td><td className="num">{a.risk_score.toFixed(1)}</td><td className="num">{a.hibp_breached ? a.hibp_breach_count.toLocaleString() : "—"}</td><td>{a.enabled ? "Yes" : <span className="muted">No</span>}</td></tr>
              ))}</tbody>
            </table>
            <Pager page={neverExpiresPage} />
          </>
        )}
      </div>

      <div className="section-label sub">Kerberoastable accounts</div>
      <div className="panel">
        {kerberoastRows.length === 0 ? (
          <div className="muted">No Kerberoastable accounts in this domain.</div>
        ) : (
          <>
            <table className="accounts compact"><thead><tr>
              <SortHeader label="Username" colKey="username" sort={kerberoastPage.sort} onSort={kerberoastPage.setSort} />
              <SortHeader label="Risk" colKey="risk" sort={kerberoastPage.sort} onSort={kerberoastPage.setSort} />
              <SortHeader label="Score" colKey="score" numeric sort={kerberoastPage.sort} onSort={kerberoastPage.setSort} />
              <SortHeader label="DA" colKey="da" sort={kerberoastPage.sort} onSort={kerberoastPage.setSort} />
              <SortHeader label="Controlled" colKey="controlled" numeric sort={kerberoastPage.sort} onSort={kerberoastPage.setSort} />
            </tr></thead>
              <tbody>{kerberoastPage.rows.map((a) => (
                <tr key={a.username}><td><AccountLink username={a.username} domain={a.domain} /></td><td><span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span></td><td className="num">{a.risk_score.toFixed(1)}</td><td>{hasDA(a.da_domains) ? <span className="badge crit">{a.da_domains}</span> : "—"}</td><td className="num">{a.controlled_object_count || "—"}</td></tr>
              ))}</tbody>
            </table>
            <Pager page={kerberoastPage} />
          </>
        )}
      </div>
    </>
  )
}
```

- [ ] **Step 3: Remove the now-unused `StatMini` helper**

`StatMini` (the function at the old lines 364-371) was only used by the removed Overview tab. Delete the entire `StatMini` function from `web/src/components/Domains.tsx`. Keep `ReuseClusters`, `FragmentRow`, and `DStat` (still used by the domain landing grid + reuse tables).

- [ ] **Step 4: Typecheck (catches every leftover unused import/symbol)**

Run (from `web/`): `npx tsc --noEmit`
Expected: no errors. If tsc reports an unused import or symbol (e.g. a leftover `posture`, `Donut`, `domainPolicy`, `RATING_COLOR`, `StatMini`, or `tab`/`TABS` reference), remove it. There must be no remaining reference to the removed gauge/tabs/strips/accounts-tab code.

- [ ] **Step 5: Run the full vitest suite**

Run (from `web/`): `npx vitest run`
Expected: PASS — including `styleguard.test.ts` (no new inline `style={{}}` spacing was introduced).

- [ ] **Step 6: Build**

Run (from `web/`): `npm run build`
Expected: build succeeds.

- [ ] **Step 7: Commit**

```bash
git add web/src/components/Domains.tsx
git commit -m "feat(domains): per-domain page renders scoped Overview + kept drill-down tables"
```

---

## Task 6: Live verification (Playwright on the enriched dev seed)

Verify the org Overview is unchanged and the per-domain page shows the scoped Overview + the kept tables, with a clean console. Use the **disposable `:8444` dev instance** with the enriched BloodHound sample seed — **never the live `:8443` server** (real sensitive data).

**Files:** none (verification only).

- [ ] **Step 1: Build the binary and (re)start the `:8444` dev instance**

Use the `build-and-run` project skill for the CGO-free embed build + restart, targeting the disposable `:8444` instance with the `.devdata` store. After restart, unlock the store in the browser with the dev passphrase `devstorepass123` (the in-memory unlock is lost on restart; the enriched audit persists in `.devdata`). Confirm the footer version matches the freshly built binary (guards against an orphaned stale `:8444` holding the port — if mismatched, kill only the stale `:8444` PID, never `:8443`).

- [ ] **Step 2: Verify the org Overview is unchanged**

Drive `http://127.0.0.1:8444` with Playwright. On the **Overview** view assert all panels still render: the 5 primary KPI tiles, the secondary 6-tile grid, the two-axis PostureCard (with the breach-impact sub-panel present for the org), the Exposure×Impact matrix, the 3 Overview charts, the Insights charts, and the Top-10 Riskiest table. Assert the browser console has **no 4xx/error noise**.

- [ ] **Step 3: Verify the per-domain page**

Navigate to **Domains**, confirm the landing grid of domain cards is unchanged, and select a domain (e.g. `WRAITH.CORP`). Assert:
- The page header shows the domain name as the title and "Where does this domain stand?" as the subtitle.
- The scoped Overview renders: KPI tiles, PostureCard (the breach-impact sub-panel is **absent** for the domain), the Exposure×Impact matrix, the charts, Insights, and Top-10 — and the numbers reflect **only that domain** (e.g. the "Accounts" KPI equals the domain's account count, smaller than the org total).
- Below the Overview, the **Domain drill-down** section shows the kept tables: DA-pathway accounts, Reused passwords (cracked), Shared uncracked hashes, Escalated by Shared-DA, Stale passwords, Password never expires, Kerberoastable.
- The old gauge, the Overview/Risk/Compliance/Accounts **tabs**, and the Policy/Wordlist strips are **gone**.
- `← All domains` returns to the landing grid.
- The browser console is clean (no 4xx/errors) throughout.

- [ ] **Step 4: Screenshot the domain page for the review record**

Take a Playwright screenshot of the selected-domain page (scoped Overview + drill-down) for the branch review.

- [ ] **Step 5: Final gates (from `web/`) and Go gate (from repo root)**

Run (from `web/`): `npx tsc --noEmit` && `npx vitest run` && `npm run build` — all must pass.
Run (from repo root): `gofmt -l cmd internal` (must be empty), `go build ./...`, `go vet ./...`, `go test ./...` — all must pass (no Go change is expected; this confirms the worktree is still green).

- [ ] **Step 6: Commit any verification artifacts (if applicable)**

If a screenshot or note is kept under `docs/`, stage it explicitly and commit:

```bash
git add docs/superpowers/plans/2026-06-25-per-domain-overview.md
git commit -m "docs(domains): per-domain Overview plan + verification notes"
```

(If there is nothing new to commit, skip this step.)

---

## Self-Review

**Spec coverage:**
- Reusable `OverviewView` extracted from `Dashboard()` with `accounts`/`summary`/`report` props → Task 4. ✅
- `Insights` optional `accounts` prop (default context) → Task 3. ✅
- `domainSummary` (posture + counts, breach_impact omitted, generated_at from org) → Task 1. ✅
- `domainReport` (per-account list filtering, reuse-group membership, violation_counts pass-through, total/cracked/uncracked from domain accounts, null→null) → Task 2. ✅
- `DomainDetail` renders `<OverviewView title={domain}/>` + keeps DA/shared-DA/stale/never-expires/Kerberoastable/reuse tables; gauge+tabs removed → Task 5. ✅
- Org summary threaded from `Domains()` for `generated_at` → Task 5 Step 1. ✅
- Tests: vitest on both builders → Tasks 1-2; Playwright on org Overview (unchanged) + domain page → Task 6. ✅
- breach-impact omitted (follow-up) → Task 1 (widen optional) + decision note. ✅
- Don't regress org Overview → Task 4 (behavior-preserving) + Task 6 Step 2 (Playwright). ✅

**Placeholder scan:** No TBD/TODO/"handle edge cases"/"similar to Task N" — all code blocks are complete and self-contained. ✅

**Type consistency:** `domainSummary(domainAccounts, orgSummary): Summary`, `domainReport(orgReport, domain, domainAccounts?): Report | null`, `OverviewView({accounts, summary: Summary|null, report, title?, subtitle?, actions?})`, `Insights({report, accounts?})`, `DomainDetail({domain, accounts, report, reportErr, summary, onBack})` — names/signatures match across all tasks. `breach_impact?` widening (Task 1) is consumed by `OverviewView`'s `PostureCard breachImpact={summary.breach_impact}` (Task 4) and omitted by `domainSummary` (Task 1). ✅
