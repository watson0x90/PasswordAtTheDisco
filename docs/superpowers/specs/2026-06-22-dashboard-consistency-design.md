# Dashboard Consistency (sub-project E) — Design

> **Sub-project E** of the "scoring & dashboard completeness" effort (C→D→E→B). C & D merged.
> Frontend-only (no Go change except strengthening one existing golden test's TS mirror).
> From the 2026-06-22 completeness sweep (Tier-2 #7, #10, #8).

**Goal:** Remove dashboard drift and a misleading visual: stop the Insights cross-domain graph
from fabricating edges (#7), make the primary KPIs read the authoritative server counts (#10),
tidy the posture "target" caption (#8), and root-cause the post-rescore client-refresh staleness.

---

## 1. Decisions locked during brainstorming

- **#7** Rebuild the Insights "Cross-domain credential reuse" graph from the **Report's real reuse
  groups** (`cracked_reuse`/`uncracked_reuse`) — edges only between domains that genuinely share a
  credential — matching the accurate `exposure.ts:crossDomainBridges`. (Not remove, not relabel.)
- **#10** Source the four primary Overview KPIs from `Summary` (the authoritative server counts the
  report/export use), falling back to the client `accounts` count only while `Summary` is loading.
- **#8** (re-scoped — NOT real drift): the TS `posture()` thresholds (`>=85 Strong / >=70 Fair`)
  and likelihood bands **already match Go `PostureScore`** and are golden-pinned. The only fix is
  the Dashboard's confusing **"target >= 75"** caption (a goalpost that matches no band) + extend the
  golden to also pin the **Rating string** (not just the score), so a future threshold change can't
  drift silently.
- **Refresh:** root-cause why C's live test showed a stale drawer vector after a rescore (the server
  was correct immediately) — fix the client refresh, or document it as a benign timing artifact.

---

## 2. Scope

**In scope (E):** the four items above. Frontend-only; the only Go-adjacent change is strengthening
`insights.test.ts` (and optionally the Go `TestPostureScoreGolden` assertion) to cover the Rating.

**Out of scope:** the scoring model gaps (sub-project F); the coverage tab (B); any new backend
endpoint. **Accepted debt (documented, not fixed):** the TS level-matrix mirror in `matrix.ts`
(already test-pinned); the bulk-enricher `ControlsTier0=false` under-report (an F concern).

---

## 3. Architecture (item by item)

### #7 — Cross-domain reuse graph from real reuse groups
`web/src/insights.ts:crossDomainReuseGraph` currently links *any* two domains that each contain a
`shared_with>0` account (its own comment admits "approximate … a better approach uses the Report's
reuse groups"). Replace the heuristic with the accurate construction:
- New signature: `crossDomainReuseGraph(report: Report, accts: Account[])`.
  - **Edges** from `[...report.cracked_reuse, ...report.uncracked_reuse]`: for each group whose
    `members` span ≥2 distinct `domain`s, add an undirected edge between **each unordered pair** of
    those domains, accumulating weight across groups (e.g. `+group.size`, or count of bridging groups
    — pick one and label it honestly, e.g. `"N shared accounts"` / `"N reuse groups"`). A group's
    `has_da_pathway` can tint the edge if cheap. This mirrors `exposure.ts:crossDomainBridges`.
  - **Nodes**: the domains that appear in ≥1 cross-domain edge (drop isolated domains). Keep the
    existing node sizing/coloring from `accts` domain stats (total count, critical count) so the
    visual is unchanged except for *correct* edges.
- Update the caller `web/src/components/Insights.tsx:27` (`crossDomainReuseGraph(accounts)`) to pass
  the Report. Confirm `Insights` has the `report` (the Dashboard already fetches it — thread it as a
  prop, or have Insights fetch `api.report()` like the Dashboard does; prefer threading the existing
  one to avoid a duplicate fetch). The empty-state ("requires ≥2 domains with shared credentials")
  now becomes accurate (no edges when no real cross-domain group exists).

### #10 — Primary KPIs from Summary
`web/src/components/Dashboard.tsx:64-67` computes `total/cracked/breached/da` from `accounts`.
Change each to prefer the authoritative `Summary` count, falling back to the client value only when
`summary` is null (still loading):
```ts
const total    = summary?.total_accounts ?? accounts.length
const cracked  = summary?.cracked ?? accounts.filter((a) => a.cracked).length
const breached = summary?.hibp_breached ?? accounts.filter((a) => a.hibp_breached).length
const da       = summary?.da_pathways ?? accounts.filter((a) => hasDA(a.da_domains)).length
```
`crackPct` derives from the chosen `total`/`cracked`. This makes the headline numbers match the
report/export and removes the client-predicate-vs-Go-counter drift. (The `riskDistribution` donut
may also re-derive from accounts; leave it — it's a distribution, not a single authoritative count,
and `Summary.risk_counts` is a separate optional alignment we can defer.)

### #8 — Posture caption + golden (small)
- Dashboard caption "Security health · higher is better · target ≥ 75" → change `75` to align with a
  real band so it stops being a third number, e.g. **"target ≥ 85 (Strong)"** (or reword to "aim for
  Strong"). One-line copy change in `Dashboard.tsx`.
- Strengthen the TS golden `web/src/insights.test.ts` (and, if cheap, the Go `TestPostureScoreGolden`)
  to assert the **Rating** string for each fixture, not only the numeric score — so the Strong/Fair/
  Weak thresholds are pinned across Go↔TS and can't drift silently.

### Post-rescore refresh (investigate → fix or document)
Use **systematic-debugging**. In C's live test, after a rescore the open SPA's AccountDrawer showed
the *old* `risk_vector` until a hard reload, though `/api/accounts` already returned the new value.
Trace: `JobsProvider` calls `bumpData()` on rescore `running→done` (jobs.tsx); `useAccountsData`
should refetch on the bumped `dataVersion`; the drawer reads from the in-memory `accounts`. Find why
the refetched data didn't reach the open drawer (stale captured prop? `useAccountsData` not keyed on
`dataVersion`? a memoization?). **Then either** fix the refresh path so an open view reflects a
completed rescore without a manual reload, **or** — if it's a benign race (the user reopened faster
than the 1.5s poll caught `done`) — document it and add a tiny "data updated — refresh" affordance.
Keep the fix minimal and root-caused; do not refactor the data layer.

---

## 4. Files

- **Modify** `web/src/insights.ts` — `crossDomainReuseGraph(report, accts)` rebuilt from reuse groups.
- **Modify** `web/src/insights.test.ts` — new pure-logic test for the real-reuse-group edges; extend the posture golden to assert Rating.
- **Modify** `web/src/components/Insights.tsx` — pass the Report to the graph.
- **Modify** `web/src/components/Dashboard.tsx` — Summary-sourced KPIs (#10) + the posture caption (#8).
- **Possibly Modify** `web/src/jobs.tsx` / `web/src/accountsData` (or wherever `useAccountsData` lives) — the refresh fix, IF the investigation finds a real gap.
- **Possibly Modify** `internal/model/model_test.go` — assert Rating in `TestPostureScoreGolden` (cheap Go-side pin).

No new endpoints.

## 5. Testing

- **#7:** pure-logic test — a Report with one reuse group spanning CORP+EU yields exactly one
  CORP–EU edge; a group within a single domain yields NO cross-domain edge; two domains that each
  have shared accounts but share NO group yield NO edge (the exact bug the heuristic had). Assert the
  fabricated-edge case is gone.
- **#10:** pure-logic helper (or a small `kpiCounts(summary, accounts)` function) test — prefers
  Summary when present, falls back to the client count when null; covers the predicate-drift scenario.
- **#8:** the extended golden asserts Rating for each fixture across `insights.test.ts` (and Go).
- **Refresh:** if a fix lands, a pure-logic test for the corrected refresh trigger; if documented,
  note it in the report.
- **Gates:** `cd web && npx tsc --noEmit && npx vitest run && npm run build`; `go build/test ./...`
  stays green. **Playwright (live):** open the Insights graph — confirm edges only between domains
  that actually share a credential (cross-check the Exposure bridges panel); confirm the KPIs match
  the report; recalc and confirm the drawer/accounts refresh (if the refresh fix landed); console clean.

## 6. Definition of done (E)

The Insights cross-domain graph shows only real shared-credential links (agrees with the Exposure
bridges panel); the Overview KPIs read the authoritative Summary counts (match the report/export);
the posture caption no longer cites a phantom "75" and the Rating is golden-pinned Go↔TS; and the
post-rescore refresh is either fixed or documented as benign. Gates green, console clean.
