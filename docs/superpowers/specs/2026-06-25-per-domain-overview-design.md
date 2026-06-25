# Per-domain page = scoped Overview + domain drill-downs — design

**Date:** 2026-06-25
**Owner:** watson0x90
**Status:** approved (brainstorm) → ready for implementation plan

## Goal

Replace the current per-domain dashboard (gauge + tabs + a few charts) with the **full
Overview dashboard scoped to the selected domain**, and **keep** the existing
domain-specific drill-down tables below it. Picking a domain on the Domains landing
should feel exactly like the Overview — same panels, same look — just for that domain.

## Why

The Domains landing (the 3 domain cards) is fine and stays as-is. The page *after*
selecting a domain is weak and inconsistent with the rest of the app: a one-off gauge +
tabbed layout that doesn't match the Overview the operator already knows. Making it the
Overview-for-this-domain gives a consistent mental model and surfaces the domain's
posture, charts, matrix, and riskiest accounts the same way the org view does.

## Scope (settled in brainstorm)

Per-domain page contains, top to bottom:
1. `← All domains` back + the domain name as the title.
2. **The Overview, scoped to the domain**: KPI tiles, the two-axis posture card,
   Exposure × Impact matrix, all charts, Insights, Top-10 riskiest.
3. **The current domain drill-down tables, kept**: DA pathways, Shared-DA, stale
   passwords, never-expires, Kerberoastable, and reuse clusters — appended below the
   Overview content (their current implementation, unchanged).

Out of scope: the Domains landing (unchanged); the org Overview behaviour (unchanged);
the charts themselves (untouched — they already accept data).

## Architecture

The Overview's panels are almost all derived from `accounts` client-side (`posture()`,
every chart via `insights.ts`, the Exposure×Impact matrix, the KPI counts). The only
server-sourced inputs are the `summary` (posture + counts + breach-impact) and the
`report`. So the work is: **parameterize the Overview to take its inputs as props**,
then feed it domain-scoped versions.

### 1. Reusable `OverviewView`

Extract the body of `Dashboard()` (`web/src/components/Dashboard.tsx`) into a
presentational component:

```tsx
function OverviewView({ accounts, summary, report, title, subtitle }: {
  accounts: Account[]
  summary: Summary
  report: Report | null
  title?: string      // default "Overview"
  subtitle?: string   // default "Where do we stand? Org-wide posture at a glance."
}): JSX.Element
```

`Dashboard()` becomes a thin wrapper: it reads `accounts` from context, fetches
`summary`/`report` from the server as today, and renders `<OverviewView … />` (the org
Overview — behaviour unchanged).

`Insights` (`web/src/components/Insights.tsx`) currently reads `accounts` from context.
Add an optional `accounts` prop; when provided it uses that, else falls back to context.
`OverviewView` passes its `accounts` through to `Insights`. (`ExposureHeadline` already
takes `accounts`/`report` as props — no change.)

### 2. Client-side domain summary

`web/src/insights.ts` (or a small new `web/src/domainScope.ts`):

```ts
function domainSummary(domainAccounts: Account[], orgSummary: Summary): Summary
```

- `posture` → `posture(domainAccounts)` (existing client builder).
- Counts (`disabled_accounts`, `never_expires`, `stale_passwords`, `policy_violations`,
  `escalated_by_shared_da`, `high_controlled`, `dormant_privileged`, `total_accounts`,
  `cracked`, `hibp_breached`, `da_pathways`) → derived by filtering `domainAccounts`
  (mirror the existing `insights.ts` count helpers; reuse `escalatedBySharedDA`,
  `neverExpiresCount`, etc. where they exist).
- `breach_impact` → **omit** (`undefined`). The posture card already renders the
  breach-impact sub-panel only `if (breachImpact && verdict !== "No Data")`, so omitting
  it cleanly hides that one sub-panel for domains. (Porting the Go estimator is a
  possible follow-up; not in this scope.)
- `generated_at` → copy from `orgSummary.generated_at`.

### 3. Client-side domain report

```ts
function domainReport(orgReport: Report | null, domain: string): Report | null
```

- The per-account lists (`da_pathways`, `cracked`, `hibp_exposed`, `weak_passwords`,
  `escalated_by_shared_da`, `high_controlled`) are `ReportAccount[]` — filter each to
  `a.domain === domain`.
- `cracked_reuse` / `uncracked_reuse` (`ReuseGroup[]`) — keep groups that have at least
  one member in `domain` (so the domain's reuse, including cross-domain clusters it
  participates in, is shown; the cross-domain reuse graph stays meaningful).
- `violation_counts` — recompute from the filtered `weak_passwords`/domain accounts, or
  reuse the existing client violation tally if one exists; otherwise pass the org counts
  through (only affects Insights labels, low-stakes — decide during implementation).
- `total_accounts`/`cracked_count`/`uncracked_count` → from `domainAccounts`.
- If `orgReport` is null, return null (the report-dependent panels already no-op on null).

### 4. DomainDetail rewrite

`web/src/components/Domains.tsx` `DomainDetail`:

```tsx
function DomainDetail({ domain, accounts, report, reportErr, onBack }) {
  const domainAccounts = useMemo(() => accounts.filter((a) => a.domain === domain), [accounts, domain])
  const summary = useMemo(() => domainSummary(domainAccounts, /* org summary */), [domainAccounts])
  const dReport = useMemo(() => domainReport(report, domain), [report, domain])
  return (
    <div>
      <button className="link-btn domain-back" onClick={onBack}>← All domains</button>
      <OverviewView accounts={domainAccounts} summary={summary} report={dReport}
                    title={domain} subtitle="Where does this domain stand?" />
      {/* existing domain drill-down tables — DA pathways, Shared-DA, stale,
          never-expires, Kerberoastable, reuse clusters — KEPT, unchanged */}
    </div>
  )
}
```

`DomainDetail` needs the org `summary` for `domainSummary`'s `generated_at` and any
pass-through; thread it in from `Domains()` (which can fetch/pass `api.summary()` like
Dashboard does) — or accept that `generated_at` falls back to "now". Decide in the plan.

The existing drill-down JSX (the tabbed tables) is retained verbatim below the
`OverviewView`; the old gauge + tab chrome is removed (the Overview replaces it).

## Data flow

```
Domains() ── api.report(), api.summary() (org) ──▶ DomainDetail(domain, accounts, report, summary)
                                                      │
                       domainAccounts = accounts.filter(domain)
                       summary = domainSummary(domainAccounts, orgSummary)   (client)
                       report  = domainReport(report, domain)                (client)
                                                      ▼
                       <OverviewView accounts summary report title=domain />  (shared with org Overview)
                       + existing domain drill-down tables (kept)
```

## Risks / decisions

- **Don't regress the org Overview.** The refactor must be behaviour-preserving for
  `Dashboard()` — verified by an unchanged org Overview render. Strong regression risk;
  Playwright-verify both the org Overview and the new domain page.
- **Report scoping is the fiddly bit** — getting `domainReport` right (lists vs reuse
  groups vs violation counts). Where a field is low-stakes (violation_counts labels),
  prefer the simplest correct option.
- **breach-impact omitted** for domains (no client estimator). Acceptable; flagged.
- **Insights parameterization** must default to context so existing call sites are
  unaffected.

## Testing

- **TS (vitest, pure-logic):** `domainSummary` (posture + counts for a filtered set),
  `domainReport` (list filtering, reuse-group membership). These are pure functions.
- **Playwright (`:8444` enriched seed):** (a) the **org Overview** still renders all
  panels unchanged; (b) selecting a domain shows the **scoped Overview** (KPI tiles /
  posture / matrix / charts / Top-10 reflect only that domain) **plus** the kept
  drill-down tables; (c) `← All domains` returns to the landing; (d) console clean.
- Gates: `gofmt`/`go build/vet/test` (no Go change expected unless a per-domain endpoint
  is added — not planned); `npx tsc --noEmit`, `npx vitest run`, `npm run build`.

## File summary

| Action | Path | Responsibility |
|---|---|---|
| Modify | `web/src/components/Dashboard.tsx` | extract `OverviewView`; `Dashboard()` becomes a thin wrapper |
| Modify | `web/src/components/Insights.tsx` | optional `accounts` prop (default context) |
| Create | `web/src/domainScope.ts` | `domainSummary`, `domainReport` (+ tests) |
| Create | `web/src/domainScope.test.ts` | vitest for the two builders |
| Modify | `web/src/components/Domains.tsx` | `DomainDetail` renders `OverviewView` + keeps drill-down tables |
| Maybe modify | `web/src/api.ts` | only if a `Summary`/`Report` field needs widening; none expected |
