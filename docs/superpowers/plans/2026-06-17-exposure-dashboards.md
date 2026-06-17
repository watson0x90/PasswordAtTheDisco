# Exposure Dashboards Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add a threat-scenario "Exposure" tab (cross-domain credential bridges, HIBP urgency triage, blast-radius worklist) + an Overview headline strip, all from existing data.

**Architecture:** Pure derivations in `web/src/exposure.ts` (unit-tested) over the already-available `Account[]` + `Report`; thin React components render them. No backend/API changes. Plus a doc-only note that the cracked-risk floor is intentional.

**Tech Stack:** React/TS (vitest node-env — pure-helper tests; NO jsdom). No new deps.

**Branch:** `feature/exposure-dashboards` (off main).
**Spec:** `docs/superpowers/specs/2026-06-17-exposure-dashboards-design.md`
**Gates:** `cd web && npx tsc --noEmit && npm run build && npx vitest run`; `gofmt -l cmd internal && go build ./... && go test ./...`; `govulncheck ./...`.

---

## Task 1: Pure derivations (`web/src/exposure.ts`)

**Files:** Create `web/src/exposure.ts`, `web/src/exposure.test.ts`.

- [ ] **Step 1: Write the failing test** `web/src/exposure.test.ts`:
```ts
import { describe, it, expect } from "vitest"
import { exposureHeadline, crossDomainBridges, hibpTriage, blastRadius } from "./exposure"
import type { Account, Report, ReportAccount, ReuseGroup } from "./api"

const acct = (o: Partial<Account>): Account => ({
  username: "u", domain: "A", cracked: false, password_length: 0, risk_level: "Low",
  risk_score: 0, risk_vector: "", hibp_breached: false, hibp_breach_count: 0,
  da_domains: "None", controlled_object_count: 0, shared_with: 0, enabled: true,
  meets_policy: true, complexity: "", ...o,
})
const ra = (o: Partial<ReportAccount>): ReportAccount => ({
  username: "u", domain: "A", cracked: false, risk_level: "Low", risk_score: 0,
  hibp_breach_count: 0, shared_with: 0, ...o,
})
const grp = (o: Partial<ReuseGroup>): ReuseGroup => ({
  group_id: 1, size: 2, cracked: false, hibp_breach_count: 0, has_da_pathway: false,
  domains: 1, members: [], ...o,
})
const report = (o: Partial<Report>): Report => ({
  total_accounts: 0, cracked_count: 0, uncracked_count: 0, da_pathways: [], cracked: [],
  cracked_reuse: [], uncracked_reuse: [], hibp_exposed: [], weak_passwords: [],
  violation_counts: { common: 0, dictionary: 0, forbidden: 0, keyboard: 0 }, ...o,
})

describe("exposureHeadline", () => {
  it("counts cracked∩DA, cracked∩HIBP, cross-domain groups + domains spanned", () => {
    const accts = [
      acct({ cracked: true, da_domains: "CORP" }),       // cracked∩DA
      acct({ cracked: true, hibp_breached: true }),       // cracked∩HIBP
      acct({ cracked: true, da_domains: "CORP", hibp_breached: true }), // both
      acct({ cracked: false, da_domains: "CORP" }),       // not cracked -> neither
    ]
    const rep = report({
      cracked_reuse: [grp({ members: [ra({ domain: "A" }), ra({ domain: "B" })] })], // spans A,B
      uncracked_reuse: [grp({ members: [ra({ domain: "B" }), ra({ domain: "C" })] })], // spans B,C
    })
    const h = exposureHeadline(accts, rep)
    expect(h.crackedDA).toBe(2)
    expect(h.crackedHibp).toBe(2)
    expect(h.crossDomainGroups).toBe(2)
    expect(h.domainsSpanned).toBe(3) // A,B,C
  })
})

describe("crossDomainBridges", () => {
  it("matrix counts clusters per domain pair; single-domain groups excluded", () => {
    const rep = report({
      cracked_reuse: [
        grp({ group_id: 1, size: 5, has_da_pathway: true, members: [ra({ domain: "CORP" }), ra({ domain: "DMZ" })] }),
        grp({ group_id: 2, size: 9, members: [ra({ domain: "CORP" })] }), // single domain -> excluded
      ],
      uncracked_reuse: [grp({ group_id: 3, size: 3, members: [ra({ domain: "CORP" }), ra({ domain: "DMZ" })] })],
    })
    const { matrix, clusters, domains } = crossDomainBridges(rep)
    expect(matrix["CORP"]["DMZ"]).toBe(2) // two clusters bridge CORP↔DMZ
    expect(clusters.length).toBe(2)
    expect(clusters[0].hasDA).toBe(true)  // DA cluster sorts first
    expect(domains).toEqual(["CORP", "DMZ"])
  })
})

describe("hibpTriage", () => {
  it("splits cracked vs not, sorted by breach count desc", () => {
    const rep = report({
      hibp_exposed: [
        ra({ username: "a", cracked: true, hibp_breach_count: 10 }),
        ra({ username: "b", cracked: true, hibp_breach_count: 99 }),
        ra({ username: "c", cracked: false, hibp_breach_count: 5 }),
      ],
    })
    const { tier1, tier2 } = hibpTriage(rep)
    expect(tier1.map((a) => a.username)).toEqual(["b", "a"]) // cracked, by count desc
    expect(tier2.map((a) => a.username)).toEqual(["c"])
  })
})

describe("blastRadius", () => {
  it("scores priority, builds reasons, includes+marks disabled, sorts desc", () => {
    const rows = blastRadius([
      acct({ username: "low", cracked: false }),                          // priority 0 -> excluded
      acct({ username: "mid", cracked: true, shared_with: 3 }),           // 1+1 = 2
      acct({ username: "top", cracked: true, da_domains: "CORP", hibp_breached: true, hibp_breach_count: 40 }), // 3+2+1 = 6
      acct({ username: "dis", cracked: true, enabled: false }),           // 1, marked disabled
    ])
    expect(rows.map((r) => r.account.username)).toEqual(["top", "mid", "dis"]) // "low" excluded, sorted desc
    expect(rows[0].reasons).toContain("DA")
    expect(rows[0].reasons).toContain("HIBP 40")
    expect(rows.find((r) => r.account.username === "dis")!.reasons).toContain("disabled")
  })
})
```

- [ ] **Step 2: Run, expect FAIL:** `cd web && npx vitest run exposure.test.ts` (module not found).

- [ ] **Step 3: Implement `web/src/exposure.ts`:**
```ts
import type { Account, Report, ReportAccount, ReuseGroup } from "./api"
import { hasDA } from "./util"

export interface BridgeCluster {
  domains: string[]
  size: number
  cracked: boolean
  hasDA: boolean
  hibpMax: number
  members: ReportAccount[]
}
export interface CrossDomain {
  matrix: Record<string, Record<string, number>>
  clusters: BridgeCluster[]
  domains: string[]
}
export interface WorklistRow {
  account: Account
  priority: number
  reasons: string[]
}

// exposureHeadline — the three exec "blast radius" numbers.
export function exposureHeadline(
  accounts: Account[],
  report: Report,
): { crackedDA: number; crackedHibp: number; crossDomainGroups: number; domainsSpanned: number } {
  let crackedDA = 0
  let crackedHibp = 0
  for (const a of accounts) {
    if (a.cracked && hasDA(a.da_domains)) crackedDA++
    if (a.cracked && a.hibp_breached) crackedHibp++
  }
  const spanned = new Set<string>()
  let crossDomainGroups = 0
  for (const g of [...report.cracked_reuse, ...report.uncracked_reuse]) {
    const doms = new Set(g.members.map((m) => m.domain))
    if (doms.size >= 2) {
      crossDomainGroups++
      doms.forEach((d) => spanned.add(d))
    }
  }
  return { crackedDA, crackedHibp, crossDomainGroups, domainsSpanned: spanned.size }
}

// crossDomainBridges — domain×domain shared-credential matrix + ranked clusters.
export function crossDomainBridges(report: Report): CrossDomain {
  const matrix: Record<string, Record<string, number>> = {}
  const clusters: BridgeCluster[] = []
  const domains = new Set<string>()
  for (const g of [...report.cracked_reuse, ...report.uncracked_reuse]) {
    const doms = [...new Set(g.members.map((m) => m.domain))].sort()
    if (doms.length < 2) continue
    doms.forEach((d) => domains.add(d))
    for (let i = 0; i < doms.length; i++) {
      for (let j = i + 1; j < doms.length; j++) {
        const a = doms[i]
        const b = doms[j]
        matrix[a] = matrix[a] || {}
        matrix[a][b] = (matrix[a][b] || 0) + 1
      }
    }
    clusters.push({
      domains: doms, size: g.size, cracked: g.cracked, hasDA: g.has_da_pathway,
      hibpMax: g.hibp_breach_count, members: g.members,
    })
  }
  clusters.sort(
    (x, y) =>
      (y.hasDA ? 1 : 0) - (x.hasDA ? 1 : 0) ||
      y.size * y.domains.length - x.size * x.domains.length,
  )
  return { matrix, clusters, domains: [...domains].sort() }
}

// hibpTriage — Tier 1 (cracked+breached) vs Tier 2 (breached, not cracked).
export function hibpTriage(report: Report): { tier1: ReportAccount[]; tier2: ReportAccount[] } {
  const bySeverity = (a: ReportAccount, b: ReportAccount) =>
    b.hibp_breach_count - a.hibp_breach_count || b.risk_score - a.risk_score
  return {
    tier1: report.hibp_exposed.filter((a) => a.cracked).sort(bySeverity),
    tier2: report.hibp_exposed.filter((a) => !a.cracked).sort(bySeverity),
  }
}

// blastRadius — ranked remediation worklist with reason badges.
export function blastRadius(accounts: Account[]): WorklistRow[] {
  const rows: WorklistRow[] = []
  for (const a of accounts) {
    const reasons: string[] = []
    let priority = 0
    if (hasDA(a.da_domains)) { priority += 3; reasons.push("DA") }
    if (a.hibp_breached) { priority += 2; reasons.push(`HIBP ${a.hibp_breach_count.toLocaleString()}`) }
    if (a.cracked) { priority += 1; reasons.push("Cracked") }
    if (a.shared_with > 0) { priority += 1; reasons.push(`Shared ${a.shared_with}`) }
    if (!a.enabled) reasons.push("disabled")
    if (priority > 0) rows.push({ account: a, priority, reasons })
  }
  rows.sort((x, y) => y.priority - x.priority || y.account.risk_score - x.account.risk_score)
  return rows
}
```

- [ ] **Step 4: Run, expect PASS:** `cd web && npx vitest run exposure.test.ts && npx tsc --noEmit`.

- [ ] **Step 5: Commit:**
```bash
git add web/src/exposure.ts web/src/exposure.test.ts
git commit -m "feat(web): pure Exposure derivations (headline, cross-domain bridges, HIBP triage, blast-radius)"
```

---

## Task 2: `ExposureHeadline` strip + render on Overview

**Files:** Create `web/src/components/ExposureHeadline.tsx`; Modify `web/src/components/Dashboard.tsx`, `web/src/styles.css`.

- [ ] **Step 1: Create `ExposureHeadline.tsx`** — takes the already-fetched data so it adds no fetch:
```tsx
import type { Account, Report } from "../api"
import { exposureHeadline } from "../exposure"
import { useNav } from "../nav"

export function ExposureHeadline({ accounts, report }: { accounts: Account[]; report: Report | null }) {
  const nav = useNav()
  if (!report) return null
  const h = exposureHeadline(accounts, report)
  return (
    <div className="exposure-strip">
      <button className="exp-tile crit" onClick={() => nav("exposure")} title="View the blast-radius worklist">
        <div className="exp-n">{h.crackedDA.toLocaleString()}</div>
        <div className="exp-l">Cracked <b>&amp;</b> Domain-Admin path</div>
      </button>
      <button className="exp-tile high" onClick={() => nav("exposure")} title="View HIBP urgency triage">
        <div className="exp-n">{h.crackedHibp.toLocaleString()}</div>
        <div className="exp-l">Cracked <b>&amp;</b> in public breaches</div>
      </button>
      <button className="exp-tile mid" onClick={() => nav("exposure")} title="View cross-domain credential bridges">
        <div className="exp-n">{h.crossDomainGroups.toLocaleString()}</div>
        <div className="exp-l">Passwords shared across domains{h.domainsSpanned ? ` (${h.domainsSpanned} domains)` : ""}</div>
      </button>
    </div>
  )
}
```
Confirm `useNav()` returns a `nav(view)` function and `"exposure"` is a valid `View` (Task 3 adds it to the union — if tsc complains here, add the View member first or do Task 3's union edit before this).

- [ ] **Step 2: Render it on Overview** in `Dashboard.tsx`. The `Dashboard()` component already has `accounts` (from `useAccountsData`) and `summary` and fetches nothing new for the strip — but it needs the `Report`. Add a report fetch keyed on `[activeId, dataVersion]` (mirror Actionable): `const [report, setReport] = useState<Report | null>(null); useEffect(() => { let alive = true; api.report().then((r) => alive && setReport(r)).catch(() => {}); return () => { alive = false } }, [activeId, dataVersion])` (pull `dataVersion` from `useAudits()` — Dashboard already calls it). Then render `<ExposureHeadline accounts={accounts} report={report} />` right after the `<div className="stat-grid">…</div>` block (around line 67-73), inside the main return. Import `ExposureHeadline`, `type Report`, `api`, `useState`, `useEffect` as needed (most already imported).

- [ ] **Step 3: CSS** — append to `web/src/styles.css`:
```css
.exposure-strip { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 12px 0; }
.exp-tile { background: #0c1320; border: 1px solid #2c3566; border-radius: 10px; padding: 14px; text-align: center; cursor: pointer; color: inherit; }
.exp-tile:hover { border-color: #3b4a7a; }
.exp-n { font-size: 30px; font-weight: 700; }
.exp-tile.crit .exp-n { color: #fb7185; } .exp-tile.high .exp-n { color: #fbbf24; } .exp-tile.mid .exp-n { color: #7dd3fc; }
.exp-l { font-size: 12px; color: #8a96b2; margin-top: 4px; }
@media (max-width: 720px) { .exposure-strip { grid-template-columns: 1fr; } }
```

- [ ] **Step 4: Verify:** `cd web && npx tsc --noEmit && npm run build && npx vitest run`. (If `"exposure"` View isn't recognized yet, add it to the `View` union in AppShell.tsx now — see Task 3 Step 3.)

- [ ] **Step 5: Commit:**
```bash
git add web/src/components/ExposureHeadline.tsx web/src/components/Dashboard.tsx web/src/styles.css
git commit -m "feat(web): blast-radius headline strip on Overview"
```

---

## Task 3: `Exposure` page (bridges + HIBP tiers + worklist) + route + nav

**Files:** Create `web/src/components/Exposure.tsx`; Modify `web/src/components/AppShell.tsx`, `web/src/App.tsx`, `web/src/styles.css`.

- [ ] **Step 1: Create `web/src/components/Exposure.tsx`** (`export function Exposure()`). Read `Actionable.tsx` (report fetch + Section pattern), `Domains.tsx` `ReuseClusters`/`FragmentRow` (expandable member rows), and `AccountsTable.tsx` (the lead-gated reveal: `api.revealSecret(username)` → `revealed` map → 45s `setTimeout(hide)`), to mirror conventions. The component:
  - Hooks: `const { me } = useAuth()`; `const { accounts, error } = useAccountsData()`; `const { activeId, dataVersion } = useAudits()`; `const nav = useNav()`; local `report`/`reportErr` fetched via `api.report()` on `[activeId, dataVersion]` (mirror Actionable). `const isLead = me?.role === "lead"`.
  - Guards: no `activeId` → prompt; `accounts === null && !error` → spinner; otherwise render.
  - Derive: `const bridges = report ? crossDomainBridges(report) : { matrix:{}, clusters:[], domains:[] }`; `const triage = report ? hibpTriage(report) : { tier1:[], tier2:[] }`; `const work = blastRadius(accounts ?? [])`.
  - **Headline recap:** `<ExposureHeadline accounts={accounts ?? []} report={report} />`.
  - **Cross-domain bridges section** (`section-label` "Cross-domain credential bridges"): if `bridges.domains.length < 2` → empty state "No credentials are shared across domains." Else: a heatmap `<table className="bridge-matrix">` with `bridges.domains` as both axes; cell `bridges.matrix[rowDom]?.[colDom] ?? 0` for `col > row`, class by intensity (0 → `m0`, 1-2 → `m1`, 3-6 → `m2`, ≥7 → `m3`); clicking a non-zero cell sets a `pairFilter` state `[rowDom,colDom]`. Below it, the `bridges.clusters` list (filtered to clusters whose `domains` include both of `pairFilter` when set): each row shows `domains.join(" ↔ ")` · `size` accounts · `cracked ? "cracked" : "uncracked"` · DA badge if `hasDA` · `hibpMax` if >0; expandable to members (`m.username · m.domain · m.risk_level`, redacted — reuse the FragmentRow expand pattern with a per-cluster `open` index).
  - **HIBP triage section** (`section-label` "HIBP urgency triage"): a Tier-1 sub-block ("Cracked + breached — reset now", crit tone) rendering `triage.tier1` as `table.accounts compact` (User · Domain · Risk · HIBP# · Shared) and a Tier-2 sub-block ("Breached, not cracked — rotate next cycle", high tone) rendering `triage.tier2`. Empty states per tier.
  - **Blast-radius worklist section** (`section-label` "Fix these first"): `table.accounts` with columns # · Account (mark `!enabled` with a "disabled" badge) · Why (the `reasons` as `badge` spans) · Risk · (lead-only) Secret. The Secret cell reuses the reveal pattern: a `revealed: Record<string,string>` + `revealing` state; `reveal(u)` calls `api.revealSecret(u)` then `window.setTimeout(() => hide(u), 45000)`; cracked rows show a "reveal" button (lead only), uncracked show "uncracked". Show a `meta-line` audit warning when lead. (This duplicates ~15 lines of reveal logic from AccountsTable; that's acceptable for one more table — do NOT refactor AccountsTable.)
  - Imports: react hooks; `api, ApiError, type Report, type ReportAccount` (../api); `useAccountsData` (../accountsData); `useAudits` (../auditsData); `useAuth` (../auth); `useNav` (../nav); `crossDomainBridges, hibpTriage, blastRadius` (../exposure); `ExposureHeadline` (./ExposureHeadline); `RISK_CLASS` (../util). Keep the file focused.

- [ ] **Step 2: CSS** — append to `styles.css`:
```css
.bridge-matrix { border-collapse: collapse; font-size: 11px; }
.bridge-matrix th, .bridge-matrix td { border: 1px solid #161d30; padding: 4px 9px; text-align: center; }
.bridge-matrix th { color: #566076; } .bridge-matrix td.rowh { color: #a5b4fc; text-align: left; }
.bridge-matrix td.m0 { color: #566076; } .bridge-matrix td.m1 { background: #3f1d2b; cursor: pointer; }
.bridge-matrix td.m2 { background: #7f1d1d; color: #fecaca; cursor: pointer; } .bridge-matrix td.m3 { background: #b91c1c; color: #fff; font-weight: 700; cursor: pointer; }
.tier-head { border-left: 3px solid #fb7185; padding-left: 10px; margin: 10px 0 6px; }
.tier-head.t2 { border-left-color: #fbbf24; }
```

- [ ] **Step 3: Nav + route.** In `AppShell.tsx`: add `"exposure"` to the `View` union and `{ id: "exposure", label: "Exposure" }` to the `TABS` array (between Domains and Compare). In `App.tsx`: add `const Exposure = lazy(() => import("./components/Exposure").then((m) => ({ default: m.Exposure })))` and `case "exposure": return <Exposure />` in `viewFor`.

- [ ] **Step 4: Verify:** `cd web && npx tsc --noEmit && npm run build && npx vitest run`. Clean / 37+ tests pass. The Exposure tab renders; clicking a heatmap cell filters clusters; the worklist reveal is lead-gated.

- [ ] **Step 5: Commit:**
```bash
git add web/src/components/Exposure.tsx web/src/components/AppShell.tsx web/src/App.tsx web/src/styles.css
git commit -m "feat(web): Exposure tab — cross-domain bridges, HIBP triage, blast-radius worklist"
```

---

## Task 4: Document the intentional cracked-risk floor + README

**Files:** Modify `internal/risk/risk.go`, `docs/architecture.md`, `README.md`.

- [ ] **Step 1: Comment `floorBase`** in `internal/risk/risk.go` — find the `floorBase` function and add/extend its doc comment to state it's an **intentional divergence from the Python v1**: a cracked password always carries baseline risk (≥2.0) regardless of strength, because the fact of being cracked is itself a signal; legacy had no floor. (Comment only — no behavior change. Run `gofmt -l internal/risk` after.)

- [ ] **Step 2: Architecture note** — in `docs/architecture.md`, add a short line under the scoring section (or near where scoring is described): "Scoring is a faithful port of the Python v1 with one intentional change — a cracked account's base risk is floored at ≥2.0 (`risk.floorBase`); the v1 had no floor, letting a strong-but-cracked password score ~0." (If `docs/architecture.md` has no scoring section, add a one-line `### Scoring parity` note.)

- [ ] **Step 3: README "What's new"** — add under the 2.7 section (or a 2.7.x bullet): the new **Exposure** tab (cross-domain credential bridges · HIBP cracked/uncracked triage · blast-radius worklist) + the Overview headline strip (cracked∩DA · cracked∩HIBP · cross-domain shared).

- [ ] **Step 4: Verify + commit:**
```bash
gofmt -l internal/risk && go build ./...
git add internal/risk/risk.go docs/architecture.md README.md
git commit -m "docs: document intentional cracked-risk floor; note Exposure dashboards"
```

---

## Task 5: Full gate + rebuild + live verify

- [ ] **Step 1: Full gate:**
```bash
gofmt -l cmd internal && go build ./... && go vet ./... && go test ./...
cd web && npx tsc --noEmit && npm run build && npx vitest run
cd .. && govulncheck ./...
```
All green.

- [ ] **Step 2: Rebuild stamped binary + restart** (cp dist → embed → ldflags build → stop/start with `PATD_AUDIT_LOG`). Live-verify with the synthetic data (`tools/gen_synthetic.py` → upload the three `*_dump.txt` + `cracks.txt`): the Overview headline strip shows non-zero cracked∩HIBP + cross-domain numbers; the **Exposure** tab shows the CORP↔EU↔LAB heatmap (the synthetic "Autumn#Service24" cluster bridges all three domains) + the HIBP Tier 1/Tier 2 split + the blast-radius worklist ranked with reason badges. (Auth steps may need the operator.)

---

## Self-review (done during planning)
- **Spec coverage:** `exposure.ts` 4 derivations (T1) · headline strip on Overview (T2) · Exposure tab with bridges/HIBP/worklist + route/nav (T3) · floorBase doc + README (T4) · gate/deploy (T5). Every spec section maps to a task.
- **Type consistency:** `exposureHeadline`/`crossDomainBridges`/`hibpTriage`/`blastRadius` signatures + `BridgeCluster`/`CrossDomain`/`WorklistRow` types used identically in T1 (defined+tested) and T2/T3 (consumed). `"exposure"` View id added in T2/T3 and used by `ExposureHeadline` nav + the route. Reuses real fields: `Account.{cracked,da_domains,hibp_breached,hibp_breach_count,shared_with,enabled,risk_score}`, `ReuseGroup.{members,size,cracked,has_da_pathway,hibp_breach_count}`, `ReportAccount.{domain,cracked,hibp_breach_count,risk_score}`.
- **Tests:** pure-helper TDD for all four derivations (node-env, no DOM); React components guarded by tsc/build + the T5 live run.
- **No placeholders.** Reveal-logic duplication in the worklist is called out as intentional (one table, no AccountsTable refactor).
