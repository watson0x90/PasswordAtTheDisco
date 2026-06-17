# Exposure dashboards (CISO + blue-team views) — design

- **Date:** 2026-06-17
- **Status:** Approved (brainstorm), pending implementation plan
- **Owner:** watson0x90

## Problem

When examining audit data, the app shows findings **by category** (a HIBP list, a
reuse list, a DA list) but not the **threat-scenario intersections** a CISO or
blue-team analyst actually reasons about. A panel review (blue-team + CISO lenses)
found the highest-value signals are unsurfaced:
- **cracked ∩ DA-pathway** — the single highest-severity number in an AD audit (an
  account whose password is known AND can escalate to Domain Admin), shown nowhere.
- **cracked ∩ HIBP-breached** — confirmed, publicly-circulating credentials, not
  separated from "breached but not cracked".
- **cross-domain credential reuse** — which two domains share a password (lateral
  movement); the data exists (`ReuseGroup.members[].domain`) but you can't see a
  domain-pair view.

Also confirmed during this work: the Go scoring engine is a **faithful port** of
the legacy Python scorer (every formula/constant matches), with one **intentional**
difference — `floorBase()` floors a *cracked* account's risk at ≥2.0 (legacy had no
floor). The owner chose to **keep** it; it must be **documented as intentional**.

## Decisions (from brainstorm)
- A new top-level **Exposure** tab (all authenticated roles; the worklist reveal
  stays lead-only + audit-logged). The **Overview** gains a blast-radius headline strip.
- Build the two named views (**cross-domain credential bridges**, **HIBP urgency
  triage**) + the **headline intersections** (exec strip + a blast-radius worklist).
- All client-side from existing endpoints — **no backend/API changes**.
- Disabled-but-cracked accounts are **shown** (marked), not hidden.

## Architecture

### Data — pure derivations (`web/src/exposure.ts`, unit-tested)
All from `Account[]` (`useAccountsData`) + `Report` (`api.report()`), both already
available client-side. `Report` provides `cracked_reuse`/`uncracked_reuse`
(`ReuseGroup{ size, domains, has_da_pathway, hibp_breach_count, cracked,
members: ReportAccount[] }`), `hibp_exposed: ReportAccount[]`, `da_pathways`.
`ReportAccount` carries `domain, cracked, risk_level, risk_score, hibp_breach_count,
shared_with, da_domains?, enabled?`. `hasDA(s)` (from `../util`) tests a non-empty
DA-domains string.

1. **`exposureHeadline(accounts: Account[], report: Report)`** →
   `{ crackedDA: number, crackedHibp: number, crossDomainGroups: number, domainsSpanned: number }`
   - `crackedDA` = `accounts.filter(a => a.cracked && hasDA(a.da_domains)).length`
   - `crackedHibp` = `accounts.filter(a => a.cracked && a.hibp_breached).length`
   - `crossDomainGroups` = count of reuse groups (cracked+uncracked) whose members
     span ≥2 distinct domains; `domainsSpanned` = size of the union of those groups' domains.

2. **`crossDomainBridges(report: Report)`** →
   `{ matrix: Record<string, Record<string, number>>, clusters: BridgeCluster[], domains: string[] }`
   - Over `[...cracked_reuse, ...uncracked_reuse]`, for each group compute the set of
     distinct member domains; if ≥2, for each unordered domain pair (A<B) increment
     `matrix[A][B]`, and push a `BridgeCluster { domains: string[], size, cracked:
     boolean, hasDA: boolean, hibpMax: number, members: ReportAccount[] }`.
   - `clusters` sorted by blast radius desc: `size * domains.length`, DA groups first.
   - `domains` = sorted union of all domains appearing in any bridged group (for the
     matrix axes).

3. **`hibpTriage(report: Report)`** →
   `{ tier1: ReportAccount[], tier2: ReportAccount[] }`
   - `tier1` = `hibp_exposed.filter(a => a.cracked)` (cracked + breached);
     `tier2` = `hibp_exposed.filter(a => !a.cracked)`. Both sorted by
     `hibp_breach_count` desc, then `risk_score` desc.

4. **`blastRadius(accounts: Account[])`** → `WorklistRow[]` where
   `WorklistRow = { account: Account, priority: number, reasons: string[] }`:
   - `priority = (hasDA(a.da_domains)?3:0) + (a.hibp_breached?2:0) + (a.cracked?1:0) + (a.shared_with>0?1:0)`
   - `reasons` = compact badges: `"DA"` (+ `a.da_domains`), `"HIBP "+count`,
     `"Shared "+n`, `"Cracked"`, and `"disabled"` when `!a.enabled`.
   - Filter to `priority > 0`; sort by priority desc, then `risk_score` desc.
     Disabled-but-cracked rows are included and marked (not hidden).

### Components
- **`web/src/components/Exposure.tsx`** (`export function Exposure()`) — the tab.
  Uses `useAccountsData()` + a local `api.report()` fetch keyed on
  `[activeId, dataVersion]` (mirroring Actionable's freshness). Lead/loading guards
  like the other data views. Renders, top to bottom:
  - `<ExposureHeadline />` (recap of the 3 metrics).
  - **Cross-domain credential bridges**: a colored `<table>` heatmap (cell intensity
    by `matrix[A][B]`, click filters the cluster list) + the ranked `clusters` list
    (each row: domains spanned · size · cracked/uncracked · DA badge · HIBP-max;
    expandable to members `username · domain · risk` — redacted, like the Domains
    reuse panel). Empty state when no group spans ≥2 domains.
  - **HIBP urgency triage**: two sub-sections — Tier 1 (cracked+breached, crit tone,
    "reset now") and Tier 2 (breached, not cracked, high tone, "rotate next cycle"),
    each an `table.accounts compact` (user · domain · risk · HIBP# · shared).
  - **Blast-radius worklist**: a ranked `table.accounts` (rank · account · reason
    badges · risk · the lead-gated reveal cell reusing the existing
    `api.revealSecret` flow + 45s auto-hide). Disabled rows marked.
- **`web/src/components/ExposureHeadline.tsx`** (`export function ExposureHeadline({ accounts, report })` or self-fetching) — the 3-metric strip (cracked∩DA crit · cracked∩HIBP high · cross-domain shared mid), rendered on **Overview** (`Dashboard.tsx`) and atop Exposure. Each metric is a big number + a one-line "what it means". The cracked∩DA tile links to the Exposure worklist; the cross-domain tile links to the bridges view.
- Heatmap is a plain colored table (no graph library, no new dep). Tiers/worklist reuse existing `table.accounts`/`badge`/`muted`/`c-crit`/`c-high`/`c-low` classes. Small CSS for the heatmap cells + headline tiles in `styles.css`.

### Wiring
- `AppShell.tsx`: add `"exposure"` to the `View` union + a TAB entry (between Domains and Compare).
- `App.tsx`: lazy import + `case "exposure": return <Exposure />`.
- `Dashboard.tsx`: render `<ExposureHeadline ... />` near the top (above or beside the posture row).

### Scoring-floor documentation (separate, tiny)
- Add a comment to `internal/risk/risk.go` `floorBase()` stating it's an intentional
  divergence from the Python v1 (a cracked password always carries baseline risk),
  and a one-line note in `docs/architecture.md`. No code/behavior change.

## Error handling / redaction
- No active audit / non-lead-where-relevant / report-load-failure → graceful empty
  or notice states (mirror Actionable/Domains). The Exposure views render redacted
  aggregates only; the **only** cleartext path is the worklist reveal, which is the
  existing lead-gated, audit-logged, one-account-at-a-time `revealSecret` — no new
  secret surface. Reuse-cluster members render `username · domain · risk_level` only
  (no hash, no cleartext), exactly like the Domains reuse panel.

## Testing
- **vitest (node-env pure helpers):** `exposure.test.ts` covers all four derivations —
  `exposureHeadline` counts (cracked∩DA, cracked∩HIBP, cross-domain group/union);
  `crossDomainBridges` (matrix pair counts, ≥2-domain filter, cluster sort + DA/HIBP
  tags); `hibpTriage` (tier split + sort); `blastRadius` (priority formula, reasons,
  disabled marking, priority>0 filter, sort order).
- **React components** (`Exposure.tsx`, `ExposureHeadline.tsx`) guarded by
  `tsc --noEmit` + `npm run build` + a live run with the synthetic data
  (`tools/gen_synthetic.py`, which has cross-domain reuse + HIBP-likely + DA cases).

## Non-goals
- No backend/API changes (all client-side from `/api/accounts` + `/api/report`).
- No graph/charting library (heatmap is a colored table).
- No change to scoring (only documenting the existing intentional floor).
- No change to the redaction/security model; reveal stays lead-only + audit-logged.

## Rough file touch-list
- New: `web/src/exposure.ts` (+ `exposure.test.ts`), `web/src/components/Exposure.tsx`,
  `web/src/components/ExposureHeadline.tsx`.
- Modify: `web/src/components/AppShell.tsx` (View + TAB), `web/src/App.tsx` (route),
  `web/src/components/Dashboard.tsx` (headline strip), `web/src/styles.css`.
- Modify: `internal/risk/risk.go` (floorBase comment), `docs/architecture.md` (note).
- README "What's new" note.
