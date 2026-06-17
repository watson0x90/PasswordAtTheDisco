# Domains Investigative Page + Unified Jobs Status — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the Domains detail page into an investigative drill-down, and surface all background-job status (HIBP + BloodHound enrichment) through one always-visible widget.

**Architecture:** Frontend-only; both features consume existing endpoints. Part 1 extracts a reusable `AccountsTable`, adds pure per-domain derivations (`domainData.ts`), and rewrites `DomainDetail`. Part 2 adds a single `JobsProvider` poller feeding a header pill, an Overview card, and the (migrated) Upload/BloodHound status.

**Tech Stack:** React + TypeScript, vitest, existing `Charts.tsx`. No backend/API changes, no new deps.

**Spec:** `docs/superpowers/specs/2026-06-17-domains-and-jobs-design.md`
**Branch:** `feature/upload-ux`.

**Web gate (run from `web/`, never `npm install`):** `npx tsc --noEmit && npm run build && npx vitest run`. Full repo gate before finishing: also `gofmt -l cmd internal && go build ./... && go test ./...` (unchanged, must stay green).

**Testing philosophy (IMPORTANT):** the web project has **no jsdom / `@testing-library`** — vitest runs in the **node** environment and every existing test (`api/enrich/format/insights/upload/violations.test.ts`) tests **pure logic** only. Do **NOT** add test deps (supply-chain rule). So: extract the testable logic into **pure exported functions** and unit-test those; React components/providers are guarded by **`tsc` + `npm run build` + the Task 8 live run**, not by render tests.

---

## File Structure
- `web/src/components/AccountsTable.tsx` — NEW. The sortable/virtualized table + reveal + drawer, over a passed `Account[]`. (Task 1)
- `web/src/components/Accounts.tsx` — MODIFY. Keep toolbar/filter; render `<AccountsTable>`. (Task 1)
- `web/src/domainData.ts` — NEW. Pure per-domain derivations. (Task 2)
- `web/src/components/Domains.tsx` — MODIFY. Rewrite `DomainDetail`. (Task 3)
- `web/src/jobs.tsx` — NEW. `JobsProvider` + `useJobs`. (Task 4)
- `web/src/App.tsx` — MODIFY. Mount `JobsProvider`. (Task 4)
- `web/src/components/JobPill.tsx` — NEW. Header pill + popover. (Task 5)
- `web/src/components/AppShell.tsx` — MODIFY. Render `<JobPill>`. (Task 5)
- `web/src/components/Dashboard.tsx` — MODIFY. Overview "Background jobs" card. (Task 6)
- `web/src/components/Ingest.tsx`, `web/src/components/BloodHound.tsx` — MODIFY. Use `useJobs`. (Task 7)
- `web/src/styles.css` — MODIFY. Pill/popover/domain panels. (Tasks 3,5)

---

## Task 1: Extract `AccountsTable` (behavior-preserving)

**Files:** Create `web/src/components/AccountsTable.tsx`; Modify `web/src/components/Accounts.tsx`; Test `web/src/accountsTable.test.ts`.

The table body + reveal + virtualization + `WeakCell` + `AccountDrawer` move verbatim out of `Accounts.tsx` into `AccountsTable`. `Accounts.tsx` keeps the search/filter-pills/count toolbar and the loading/error states, computes `filtered`, and renders `<AccountsTable accounts={filtered} />`. The component itself is guarded by tsc/build/live (no render test — node env); the one piece of real logic, the virtualization window math, is extracted into a **pure exported `tableWindow`** and unit-tested.

- [ ] **Step 1: Write the failing test** `web/src/accountsTable.test.ts`:
```ts
import { describe, it, expect } from "vitest"
import { tableWindow } from "./components/AccountsTable"

describe("tableWindow", () => {
  it("renders all rows below the virtualization threshold", () => {
    expect(tableWindow(50, 0, 560)).toEqual({ virtual: false, start: 0, end: 50 })
  })
  it("windows rows above the threshold", () => {
    const w = tableWindow(10000, 3800, 560) // ROW_H=38, OVERSCAN=10
    expect(w.virtual).toBe(true)
    expect(w.start).toBe(90)  // floor(3800/38)=100, -10 overscan
    expect(w.end).toBe(125)   // ceil((3800+560)/38)=115, +10 overscan
    expect(w.start).toBeLessThan(w.end)
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd web && npx vitest run accountsTable.test.ts`
Expected: FAIL — `tableWindow` not exported.

- [ ] **Step 3: Create `AccountsTable.tsx`** by moving code out of `Accounts.tsx`.

`AccountsTable({ accounts }: { accounts: Account[] })` owns everything currently below the toolbar in `Accounts.tsx`:
- imports: `useEffect, useMemo, useRef, useState, type ReactNode` from react; `api, ApiError, type Account` from `../api`; `useAuth` from `../auth`; `RISK_CLASS, hasDA, weaknessTags` from `../util`.
- the constants `VIRT_THRESHOLD`, `ROW_H`, `OVERSCAN`.
- state: `revealed, revealing, revealError, selected, scrollRef, scrollTop, viewH` and the two effects (ResizeObserver; reset-scroll). Change the reset-scroll effect dep from `[query, risk]` to `[accounts]` (reset when the parent passes a new list).
- functions: `copy`, `reveal`, `hide`.
- **Extract the window math** into a pure exported function (so it's unit-testable in the node env), and use it:
```ts
const VIRT_THRESHOLD = 200
const ROW_H = 38
const OVERSCAN = 10

// tableWindow computes the slice of rows to render (windowing/virtualization).
export function tableWindow(total: number, scrollTop: number, viewH: number): { virtual: boolean; start: number; end: number } {
  const virtual = total > VIRT_THRESHOLD
  if (!virtual) return { virtual: false, start: 0, end: total }
  const start = Math.max(0, Math.floor(scrollTop / ROW_H) - OVERSCAN)
  const end = Math.min(total, Math.ceil((scrollTop + viewH) / ROW_H) + OVERSCAN)
  return { virtual, start, end }
}
```
  In the component: `const { virtual, start, end } = tableWindow(total, scrollTop, viewH)`, then `const visible = accounts.slice(start, end)` and `const cols = isLead ? 10 : 9`.
- render: `revealError` notice + the `<div className="table-wrap…">` + `<table className="accounts">` exactly as today, plus the lead `meta-line` and the `{selected && <AccountDrawer …/>}`.
- Move `WeakCell` and `AccountDrawer` into this file (unexported).
- `isLead = useAuth().me?.role === "lead"` stays.

Export `function AccountsTable(...)` and `tableWindow`.

- [ ] **Step 4: Rewrite `Accounts.tsx`** to keep only the toolbar + data plumbing:
```tsx
import { useMemo, useState } from "react"
import { useAccountsData } from "../accountsData"
import { RISK_CLASS } from "../util"
import { AccountsTable } from "./AccountsTable"

const FILTERS = ["All", "Critical", "High", "Medium", "Low"] as const

export function Accounts() {
  const { accounts, error: loadError } = useAccountsData()
  const [query, setQuery] = useState("")
  const [risk, setRisk] = useState<string>("All")

  const filtered = useMemo(() => {
    if (!accounts) return []
    const needle = query.trim().toLowerCase()
    return accounts.filter((a) => {
      if (risk !== "All" && a.risk_level !== risk) return false
      if (needle && !`${a.username} ${a.domain}`.toLowerCase().includes(needle)) return false
      return true
    })
  }, [accounts, query, risk])

  if (loadError && !accounts) return <div className="center-state">{loadError}</div>
  if (!accounts) return <div className="center-state"><div className="spinner">loading</div></div>

  return (
    <>
      <div className="section-label">Accounts</div>
      <div className="toolbar">
        <input className="search" placeholder="search username or domain…" value={query}
               spellCheck={false} onChange={(e) => setQuery(e.target.value)} />
        <div className="filter-pills">
          {FILTERS.map((f) => {
            const active = f === risk
            const cls = active ? `pill active ${f !== "All" ? RISK_CLASS[f] : ""}` : "pill"
            return <button key={f} className={cls} onClick={() => setRisk(f)}>{f}</button>
          })}
        </div>
        <div className="toolbar-count">{filtered.length.toLocaleString()} / {accounts.length.toLocaleString()}</div>
      </div>
      <AccountsTable accounts={filtered} />
    </>
  )
}
```

- [ ] **Step 5: Verify** `cd web && npx vitest run && npx tsc --noEmit && npm run build`. All green; the Accounts page renders identically (manual check deferred to Task 8 live run).

- [ ] **Step 6: Commit**
```bash
git add web/src/components/AccountsTable.tsx web/src/components/Accounts.tsx web/src/accountsTable.test.ts
git commit -m "refactor(web): extract reusable AccountsTable from Accounts page"
```

---

## Task 2: Pure per-domain derivations (`domainData.ts`)

**Files:** Create `web/src/domainData.ts`; Test `web/src/domainData.test.ts`.

- [ ] **Step 1: Write the failing test** `web/src/domainData.test.ts`:
```ts
import { describe, it, expect } from "vitest"
import { domainReuseClusters, domainDAPaths, domainQuickWins, domainPolicy, domainWordlist } from "./domainData"
import type { Account, Report, ReuseGroup, ReportAccount } from "./api"

const ra = (o: Partial<ReportAccount>): ReportAccount => ({
  username: "u", domain: "A", cracked: true, risk_level: "Low", risk_score: 1,
  hibp_breach_count: 0, shared_with: 0, ...o,
})
const grp = (o: Partial<ReuseGroup>): ReuseGroup => ({
  group_id: 1, size: 2, cracked: true, hibp_breach_count: 0, has_da_pathway: false,
  domains: 1, members: [], ...o,
})
const acct = (o: Partial<Account>): Account => ({
  username: "u", domain: "A", cracked: true, password_length: 6, risk_level: "Low",
  risk_score: 1, risk_vector: "", hibp_breached: false, hibp_breach_count: 0,
  da_domains: "None", controlled_object_count: 0, shared_with: 0, enabled: true,
  meets_policy: true, complexity: "ok", ...o,
})
const report = (o: Partial<Report>): Report => ({
  total_accounts: 0, cracked_count: 0, uncracked_count: 0, da_pathways: [], cracked: [],
  cracked_reuse: [], uncracked_reuse: [], hibp_exposed: [], weak_passwords: [],
  violation_counts: { common: 0, dictionary: 0, forbidden: 0, keyboard: 0 }, ...o,
})

describe("domainData", () => {
  it("reuse clusters include only groups touching the domain, sorted by size", () => {
    const rep = report({
      cracked_reuse: [
        grp({ group_id: 1, size: 5, members: [ra({ domain: "A" }), ra({ domain: "B" })] }),
        grp({ group_id: 2, size: 9, members: [ra({ domain: "B" })] }),
        grp({ group_id: 3, size: 3, members: [ra({ domain: "A" })] }),
      ],
    })
    const { cracked } = domainReuseClusters(rep, "A")
    expect(cracked.map((g) => g.group_id)).toEqual([1, 3]) // group 2 (B only) excluded; sorted 5,3
  })
  it("DA paths filter to the domain, sorted by risk", () => {
    const rep = report({ da_pathways: [ra({ domain: "A", username: "x", risk_score: 2 }), ra({ domain: "B" }), ra({ domain: "A", username: "y", risk_score: 9 })] })
    expect(domainDAPaths(rep, "A").map((a) => a.username)).toEqual(["y", "x"])
  })
  it("quick wins = top-N cracked by risk", () => {
    const accts = [acct({ username: "a", risk_score: 3 }), acct({ username: "b", risk_score: 8 }), acct({ username: "c", cracked: false, risk_score: 99 })]
    expect(domainQuickWins(accts, 10).map((a) => a.username)).toEqual(["b", "a"]) // uncracked excluded
  })
  it("policy + wordlist counts", () => {
    const accts = [
      acct({ cracked: true, meets_policy: false, is_common: true }),
      acct({ cracked: true, meets_policy: true, keyboard_pattern_count: 2 }),
      acct({ cracked: false, enabled: false }),
    ]
    expect(domainPolicy(accts)).toEqual({ meets: 1, fails: 1, disabled: 1 })
    expect(domainWordlist(accts)).toEqual({ common: 1, dictionary: 0, banned: 0, keyboard: 1 })
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd web && npx vitest run domainData.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `web/src/domainData.ts`** (note: `domainQuickWins`/`domainPolicy`/`domainWordlist` take **already domain-filtered** accounts):
```ts
import type { Account, Report, ReuseGroup, ReportAccount } from "./api"

// Reuse clusters that include at least one account in `domain` (a cluster may
// span domains; it's listed under each domain it touches). Sorted by size desc.
export function domainReuseClusters(report: Report, domain: string): { cracked: ReuseGroup[]; uncracked: ReuseGroup[] } {
  const touches = (g: ReuseGroup) => g.members.some((m) => m.domain === domain)
  const bySize = (a: ReuseGroup, b: ReuseGroup) => b.size - a.size
  return {
    cracked: report.cracked_reuse.filter(touches).sort(bySize),
    uncracked: report.uncracked_reuse.filter(touches).sort(bySize),
  }
}

// DA-pathway accounts in this domain, highest risk first.
export function domainDAPaths(report: Report, domain: string): ReportAccount[] {
  return report.da_pathways.filter((a) => a.domain === domain).sort((a, b) => b.risk_score - a.risk_score)
}

// Top-N cracked accounts by risk score (the remediation shortlist).
export function domainQuickWins(domainAccts: Account[], n: number): Account[] {
  return domainAccts.filter((a) => a.cracked).sort((a, b) => b.risk_score - a.risk_score).slice(0, n)
}

// Policy compliance over the domain's accounts.
export function domainPolicy(domainAccts: Account[]): { meets: number; fails: number; disabled: number } {
  let meets = 0, fails = 0, disabled = 0
  for (const a of domainAccts) {
    if (!a.enabled) disabled++
    if (a.cracked) a.meets_policy ? meets++ : fails++
  }
  return { meets, fails, disabled }
}

// Wordlist-weakness counts over the domain's cracked accounts.
export function domainWordlist(domainAccts: Account[]): { common: number; dictionary: number; banned: number; keyboard: number } {
  let common = 0, dictionary = 0, banned = 0, keyboard = 0
  for (const a of domainAccts) {
    if (!a.cracked) continue
    if (a.is_common) common++
    if (a.is_dictionary_word) dictionary++
    if ((a.banned_word_count ?? 0) > 0) banned++
    if ((a.keyboard_pattern_count ?? 0) > 0) keyboard++
  }
  return { common, dictionary, banned, keyboard }
}
```
Note the test calls `domainPolicy(accts)`/`domainWordlist(accts)` with a mixed list — they operate on whatever list is passed (the caller passes domain-filtered accounts; the test passes all-domain-A accounts, equivalent).

- [ ] **Step 4: Run to verify it passes**

Run: `cd web && npx vitest run domainData.test.ts && npx tsc --noEmit`
Expected: PASS, clean.

- [ ] **Step 5: Commit**
```bash
git add web/src/domainData.ts web/src/domainData.test.ts
git commit -m "feat(web): pure per-domain derivations (reuse clusters, DA, quick-wins, policy, wordlist)"
```

---

## Task 3: Rewrite `DomainDetail` (investigative page)

**Files:** Modify `web/src/components/Domains.tsx`; Modify `web/src/styles.css`.

The list view (`Domains()` grid of domain cards) is unchanged. Rewrite `DomainDetail` to fetch the report and render the new panels. The report is fetched locally (no shared hook exists; mirror `accountsData`'s fetch shape).

- [ ] **Step 1: Add report fetching + the new panels to `DomainDetail`.** Replace the existing `DomainDetail` with:
```tsx
import { useEffect, useState } from "react"
import { api, ApiError, type Account, type Report, type ReportAccount, type ReuseGroup } from "../api"
import { useAccountsData } from "../accountsData"
import { useNav } from "../nav"
import { hasDA } from "../util"
import { posture, riskDistribution, hibpSplit } from "../insights"
import { ChartCard, Donut, PostureGauge } from "./Charts"
import { AccountsTable } from "./AccountsTable"
import { domainReuseClusters, domainDAPaths, domainQuickWins, domainPolicy, domainWordlist } from "../domainData"

const QUICK_WINS_N = 10
const RATING_COLOR: Record<string, string> = { Strong: "#34d399", Fair: "#fbbf24", Weak: "#fb7185", "No Data": "#8a96b2" }

function DomainDetail({ domain, accounts, onBack }: { domain: string; accounts: Account[]; onBack: () => void }) {
  const [report, setReport] = useState<Report | null>(null)
  const [reportErr, setReportErr] = useState("")
  useEffect(() => {
    let alive = true
    api.report().then((r) => alive && setReport(r)).catch((e) => alive && setReportErr(e instanceof ApiError ? e.message : "report unavailable"))
    return () => { alive = false }
  }, [domain])

  const p = posture(accounts)
  const pol = domainPolicy(accounts)
  const wl = domainWordlist(accounts)
  const quick = domainQuickWins(accounts, QUICK_WINS_N)
  const clusters = report ? domainReuseClusters(report, domain) : { cracked: [], uncracked: [] }
  const daPaths = report ? domainDAPaths(report, domain) : []

  const total = accounts.length
  const cracked = accounts.filter((a) => a.cracked).length
  const breached = accounts.filter((a) => a.hibp_breached).length
  const critical = accounts.filter((a) => a.risk_level === "Critical").length
  const da = accounts.filter((a) => hasDA(a.da_domains)).length

  return (
    <>
      <button className="link-btn domain-back" onClick={onBack}>← All domains</button>
      <div className="section-label">{domain}</div>

      <div className="panel posture-panel">
        <div className="posture-gauge-wrap"><PostureGauge score={p.score} color={RATING_COLOR[p.rating]} rating={p.rating} /></div>
        <div className="domain-detail-stats">
          <DStat label="Accounts" value={total} />
          <DStat label="Cracked" value={cracked} />
          <DStat label="Breached" value={breached} tone="high" />
          <DStat label="Critical" value={critical} tone="crit" />
          <DStat label="DA Paths" value={da} tone="crit" />
        </div>
      </div>

      <div className="domain-strips">
        <div className="panel strip">
          <div className="strip-title">Policy</div>
          <div className="strip-stats"><DStat label="Meets" value={pol.meets} /><DStat label="Fails" value={pol.fails} tone="high" /><DStat label="Disabled" value={pol.disabled} /></div>
        </div>
        <div className="panel strip">
          <div className="strip-title">Wordlist hits</div>
          <div className="strip-stats"><DStat label="Common" value={wl.common} tone="high" /><DStat label="Dictionary" value={wl.dictionary} /><DStat label="Forbidden" value={wl.banned} tone="high" /><DStat label="Keyboard" value={wl.keyboard} /></div>
        </div>
      </div>

      <div className="chart-grid">
        <ChartCard title="Risk distribution"><Donut data={riskDistribution(accounts)} /></ChartCard>
        <ChartCard title="HIBP exposure"><Donut data={hibpSplit(accounts)} /></ChartCard>
      </div>

      {reportErr && <div className="hint">{reportErr} — cluster/DA panels need the report.</div>}

      <ReuseClusters title="Reused passwords (cracked)" groups={clusters.cracked} lateral={false} />
      <ReuseClusters title="Shared uncracked hashes (lateral movement)" groups={clusters.uncracked} lateral={true} />

      <div className="section-label sub">DA-pathway accounts</div>
      <div className="panel">
        {daPaths.length === 0 ? (
          <div className="muted">No BloodHound DA pathways in this domain (run enrichment from Setup → Integrations → BloodHound).</div>
        ) : (
          <table className="accounts compact"><thead><tr><th>Username</th><th>Risk</th><th className="num">HIBP</th><th>DA domains</th></tr></thead>
            <tbody>{daPaths.map((a) => (<tr key={a.username}><td>{a.username}</td><td>{a.risk_level}</td><td className="num">{a.hibp_breach_count || "—"}</td><td className="muted">{a.da_domains ?? "—"}</td></tr>))}</tbody>
          </table>
        )}
      </div>

      <div className="section-label sub">Quick wins — top {QUICK_WINS_N} weakest cracked</div>
      <AccountsTable accounts={quick} />

      <div className="section-label sub">All accounts</div>
      <AccountsTable accounts={accounts} />
    </>
  )
}

function ReuseClusters({ title, groups, lateral }: { title: string; groups: ReuseGroup[]; lateral: boolean }) {
  const [open, setOpen] = useState<number | null>(null)
  return (
    <>
      <div className="section-label sub">{title}</div>
      <div className="panel">
        {groups.length === 0 ? (
          <div className="muted">{lateral ? "No shared uncracked hashes." : "No reused cracked passwords."}</div>
        ) : (
          <table className="accounts compact">
            <thead><tr><th className="num">Accounts</th><th className="num">Domains</th><th>DA?</th><th className="num">HIBP</th>{!lateral && <th className="num">Len</th>}<th></th></tr></thead>
            <tbody>{groups.map((g) => (
              <FragmentRow key={g.group_id} g={g} lateral={lateral} open={open === g.group_id} onToggle={() => setOpen(open === g.group_id ? null : g.group_id)} />
            ))}</tbody>
          </table>
        )}
      </div>
    </>
  )
}

function FragmentRow({ g, lateral, open, onToggle }: { g: ReuseGroup; lateral: boolean; open: boolean; onToggle: () => void }) {
  return (
    <>
      <tr>
        <td className="num">{g.size}</td>
        <td className="num">{g.domains}</td>
        <td>{g.has_da_pathway ? <span className="badge crit">DA</span> : <span className="muted">—</span>}</td>
        <td className="num">{g.hibp_breach_count || "—"}</td>
        {!lateral && <td className="num">{g.password_length ?? "—"}</td>}
        <td><button className="link-btn" onClick={onToggle}>{open ? "hide" : `members (${g.members.length})`}</button></td>
      </tr>
      {open && g.members.map((m: ReportAccount, i) => (
        <tr key={i} className="member-row"><td></td><td colSpan={lateral ? 4 : 5} className="muted">{m.username} · {m.domain} · {m.risk_level}</td></tr>
      ))}
    </>
  )
}

function DStat({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return <div className="dstat"><div className={tone ? `dstat-v c-${tone}` : "dstat-v"}>{value.toLocaleString()}</div><div className="dstat-l">{label}</div></div>
}
```
Keep the existing `Domains()` list component + its `DStat`-less imports intact; remove the now-unused imports (`complexityCounts`, `lengthBuckets`, `Bars`, `HBars`) from the top of `Domains.tsx` if they're no longer referenced (run tsc to confirm). If `Domains.tsx` already defines a top-level `DStat`, reuse it (don't double-declare) — keep ONE `DStat`.

- [ ] **Step 2: Add minimal CSS** to `web/src/styles.css` (append):
```css
.domain-strips { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 10px 0; }
.domain-strips .strip-title { font-size: 11px; letter-spacing: 1px; text-transform: uppercase; color: #566076; margin-bottom: 8px; }
.domain-strips .strip-stats { display: flex; gap: 18px; }
.section-label.sub { margin-top: 18px; font-size: 12px; }
table.accounts.compact td, table.accounts.compact th { padding: 6px 10px; }
.member-row td { font-size: 11px; }
@media (max-width: 720px) { .domain-strips { grid-template-columns: 1fr; } }
```

- [ ] **Step 3: Verify** `cd web && npx tsc --noEmit && npm run build && npx vitest run`. Clean / all pass.

- [ ] **Step 4: Commit**
```bash
git add web/src/components/Domains.tsx web/src/styles.css
git commit -m "feat(web): investigative domain detail — accounts, reuse clusters, DA, quick-wins, policy/wordlist"
```

---

## Task 4: `JobsProvider` + `useJobs`

**Files:** Create `web/src/jobs.tsx`; Modify `web/src/App.tsx`; Test `web/src/jobs.test.ts`.

The provider (React) is guarded by tsc/build/live; the pure derivations (`hibpRunning`, `computeAnyRunning`) are exported and unit-tested.

- [ ] **Step 1: Write the failing test** `web/src/jobs.test.ts`:
```ts
import { describe, it, expect } from "vitest"
import { hibpRunning, computeAnyRunning } from "./jobs"
import type { EnrichJob, PwnedJob } from "./api"

const ej = (phase: string): EnrichJob => ({ phase: phase as EnrichJob["phase"], processed: 0, total: 0, enriched: 0, elapsed_sec: 0 })
const pj = (phase: string): PwnedJob => ({ phase: phase as PwnedJob["phase"], resume: false, elapsed_sec: 0, bytes_now: 0, est_total: 0, rate_bps: 0, index_scanned: 0, index_entries: 0, data_file: "" })

describe("jobs derivations", () => {
  it("hibpRunning true only for downloading/indexing", () => {
    expect(hibpRunning("downloading")).toBe(true)
    expect(hibpRunning("indexing")).toBe(true)
    expect(hibpRunning("idle")).toBe(false)
    expect(hibpRunning(undefined)).toBe(false)
  })
  it("computeAnyRunning across enrich + hibp", () => {
    expect(computeAnyRunning(null, null)).toBe(false)
    expect(computeAnyRunning(ej("running"), pj("idle"))).toBe(true)
    expect(computeAnyRunning(ej("done"), pj("indexing"))).toBe(true)
    expect(computeAnyRunning(ej("done"), pj("done"))).toBe(false)
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd web && npx vitest run jobs.test.ts`
Expected: FAIL — `./jobs` not found.

- [ ] **Step 3: Implement `web/src/jobs.tsx`:**
```tsx
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react"
import { api, type EnrichJob, type PwnedJob } from "./api"
import { useAuth } from "./auth"

interface JobsState {
  enrich: EnrichJob | null
  hibp: PwnedJob | null
  anyRunning: boolean
  refresh: () => void
}

const Ctx = createContext<JobsState | null>(null)

// hibpRunning reports whether the HIBP corpus job is mid-flight.
export const hibpRunning = (p?: string) => p === "downloading" || p === "indexing"

// computeAnyRunning is true when either background job is in progress.
export function computeAnyRunning(enrich: EnrichJob | null, hibp: PwnedJob | null): boolean {
  return enrich?.phase === "running" || hibpRunning(hibp?.phase)
}

// JobsProvider polls the two background-job endpoints (BloodHound enrichment +
// HIBP download/index) and shares their state. Both endpoints are lead-only, so
// it polls only for leads. Cadence: 5s idle, 1.5s while a job runs.
export function JobsProvider({ children }: { children: ReactNode }) {
  const { me } = useAuth()
  const isLead = me?.role === "lead"
  const [enrich, setEnrich] = useState<EnrichJob | null>(null)
  const [hibp, setHibp] = useState<PwnedJob | null>(null)
  const [tick, setTick] = useState(0)
  const refresh = () => setTick((t) => t + 1)

  const anyRunning = computeAnyRunning(enrich, hibp)
  const runningRef = useRef(anyRunning)
  runningRef.current = anyRunning

  useEffect(() => {
    if (!isLead) {
      setEnrich(null)
      setHibp(null)
      return
    }
    let alive = true
    let timer: number | undefined
    const poll = async () => {
      try {
        const [e, h] = await Promise.all([api.enrichJob(), api.pwnedJob()])
        if (!alive) return
        setEnrich(e)
        setHibp(h)
      } catch {
        /* transient (locked/network): keep last state */
      }
      if (!alive) return
      timer = window.setTimeout(poll, runningRef.current ? 1500 : 5000)
    }
    void poll()
    return () => {
      alive = false
      if (timer) window.clearTimeout(timer)
    }
  }, [isLead, tick])

  return <Ctx.Provider value={{ enrich, hibp, anyRunning, refresh }}>{children}</Ctx.Provider>
}

export function useJobs(): JobsState {
  const c = useContext(Ctx)
  if (!c) throw new Error("useJobs must be used within JobsProvider")
  return c
}
```

- [ ] **Step 4: Mount the provider** in `web/src/App.tsx` — wrap `AppShell` (it's inside `AuthProvider`, so `useAuth` works). Add `import { JobsProvider } from "./jobs"` and change the `Routed` return to:
```tsx
    <NavProvider value={setView}>
      <AuditsProvider>
        <AccountsProvider>
          <JobsProvider>
            <AppShell view={view} onNav={setView}>
              <Suspense fallback={<div className="center-state"><div className="spinner">loading</div></div>}>
                {viewFor(view)}
              </Suspense>
            </AppShell>
          </JobsProvider>
        </AccountsProvider>
      </AuditsProvider>
    </NavProvider>
```

- [ ] **Step 5: Verify** `cd web && npx vitest run jobs.test.ts && npx tsc --noEmit && npm run build`. PASS / clean.

- [ ] **Step 6: Commit**
```bash
git add web/src/jobs.tsx web/src/App.tsx web/src/jobs.test.ts
git commit -m "feat(web): JobsProvider — single poller for enrichment + HIBP job status (lead-only, adaptive cadence)"
```

---

## Task 5: Header `JobPill` + popover

**Files:** Create `web/src/components/JobPill.tsx`; Modify `web/src/components/AppShell.tsx`; Modify `web/src/styles.css`; Test `web/src/jobPill.test.ts`.

The pill component is guarded by tsc/build/live; its label logic is a pure exported `jobPillLabel` and unit-tested.

- [ ] **Step 1: Write the failing test** `web/src/jobPill.test.ts`:
```ts
import { describe, it, expect } from "vitest"
import { jobPillLabel } from "./components/JobPill"
import type { EnrichJob, PwnedJob } from "./api"

const ej = (phase: string, processed = 0, total = 0): EnrichJob => ({ phase: phase as EnrichJob["phase"], processed, total, enriched: 0, elapsed_sec: 0 })
const pj = (phase: string): PwnedJob => ({ phase: phase as PwnedJob["phase"], resume: false, elapsed_sec: 0, bytes_now: 0, est_total: 0, rate_bps: 0, index_scanned: 0, index_entries: 0, data_file: "" })

describe("jobPillLabel", () => {
  it("empty when nothing runs", () => {
    expect(jobPillLabel(ej("idle"), pj("idle"))).toBe("")
  })
  it("enrichment progress", () => {
    expect(jobPillLabel(ej("running", 42, 120), pj("idle"))).toBe("Enriching… 42/120")
  })
  it("HIBP phase", () => {
    expect(jobPillLabel(ej("idle"), pj("indexing"))).toBe("HIBP indexing…")
  })
  it("both running -> 2 jobs", () => {
    expect(jobPillLabel(ej("running", 1, 2), pj("downloading"))).toBe("2 jobs")
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd web && npx vitest run jobPill.test.ts`
Expected: FAIL — not found.

- [ ] **Step 3: Implement `web/src/components/JobPill.tsx`:**
```tsx
import { useState } from "react"
import { api, ApiError, type EnrichJob, type PwnedJob } from "../api"
import { useAuth } from "../auth"
import { useJobs } from "../jobs"

// jobPillLabel renders the compact pill text for the current job state ("" = hide).
export function jobPillLabel(enrich: EnrichJob | null, hibp: PwnedJob | null): string {
  const e = enrich?.phase === "running"
  const h = hibp?.phase === "downloading" || hibp?.phase === "indexing"
  if (e && h) return "2 jobs"
  if (e) return `Enriching… ${enrich!.processed}/${enrich!.total}`
  if (h) return `HIBP ${hibp!.phase}…`
  return ""
}

export function JobPill() {
  const { me } = useAuth()
  const { enrich, hibp, anyRunning } = useJobs()
  const [open, setOpen] = useState(false)
  const [err, setErr] = useState("")
  if (!anyRunning) return null

  const enrichRunning = enrich?.phase === "running"
  const hibpRunning = hibp?.phase === "downloading" || hibp?.phase === "indexing"
  const label = jobPillLabel(enrich, hibp)

  async function cancelEnrich() {
    if (!me) return
    setErr("")
    try { await api.enrichCancel(me.csrf_token) } catch (e) { setErr(e instanceof ApiError ? e.message : "cancel failed") }
  }
  async function cancelHibp() {
    if (!me) return
    setErr("")
    try { await api.pwnedCancel(me.csrf_token) } catch (e) { setErr(e instanceof ApiError ? e.message : "cancel failed") }
  }

  return (
    <div className="jobpill-wrap">
      <button className="jobpill" onClick={() => setOpen((o) => !o)} title="Background jobs">
        <span className="spin">⟳</span> {label}
      </button>
      {open && (
        <div className="jobpop" role="dialog" aria-label="Background jobs">
          {enrichRunning && (
            <div className="jobpop-row">
              <span>BloodHound enrichment — {enrich!.processed}/{enrich!.total} ({enrich!.enriched} enriched)</span>
              <button className="link-btn" onClick={() => void cancelEnrich()}>cancel</button>
            </div>
          )}
          {hibpRunning && (
            <div className="jobpop-row">
              <span>HIBP corpus — {hibp!.phase}</span>
              <button className="link-btn" onClick={() => void cancelHibp()}>cancel</button>
            </div>
          )}
          {err && <div className="error">{err}</div>}
        </div>
      )}
    </div>
  )
}
```

- [ ] **Step 4: Render it in `AppShell`** — in `web/src/components/AppShell.tsx`, add `import { JobPill } from "./JobPill"` and place `<JobPill />` as the first child of the `topbar-right` div (before `<AuditSwitcher />`):
```tsx
          <div className="topbar-right">
            <JobPill />
            <AuditSwitcher />
```

- [ ] **Step 5: Add CSS** to `web/src/styles.css` (append):
```css
.jobpill-wrap { position: relative; }
.jobpill { display: inline-flex; align-items: center; gap: 6px; background: #0e7490; color: #e0f2fe; border: none; border-radius: 14px; padding: 4px 11px; font-size: 12px; font-weight: 600; cursor: pointer; }
.jobpill .spin { display: inline-block; animation: jobspin 1.1s linear infinite; }
@keyframes jobspin { to { transform: rotate(360deg); } }
.jobpop { position: absolute; right: 0; top: 30px; z-index: 40; background: #0c1320; border: 1px solid #242e46; border-radius: 10px; padding: 10px; min-width: 280px; box-shadow: 0 8px 24px rgba(0,0,0,.4); }
.jobpop-row { display: flex; justify-content: space-between; gap: 12px; color: #c7d2fe; font-size: 12px; margin: 4px 0; }
```

- [ ] **Step 6: Verify + commit**

Run: `cd web && npx vitest run && npx tsc --noEmit && npm run build`
```bash
git add web/src/components/JobPill.tsx web/src/components/AppShell.tsx web/src/styles.css web/src/jobPill.test.ts
git commit -m "feat(web): always-visible header job pill + cancel popover"
```

---

## Task 6: Overview "Background jobs" card

**Files:** Modify `web/src/components/Dashboard.tsx`.

- [ ] **Step 1: Add a jobs card** to the Overview/Dashboard view. Open `Dashboard.tsx`, add `import { useJobs } from "../jobs"` and render a small card (place near the top of the dashboard's returned JSX, following the existing card/panel markup conventions in that file — match the surrounding `className`s):
```tsx
function BackgroundJobsCard() {
  const { enrich, hibp } = useJobs()
  const enrichLabel =
    !enrich || enrich.phase === "idle" ? "idle"
    : enrich.phase === "running" ? `running ${enrich.processed}/${enrich.total}`
    : enrich.phase === "done" ? `done — enriched ${enrich.enriched}/${enrich.total}`
    : enrich.phase
  const hibpLabel = !hibp || hibp.phase === "idle" ? "idle" : hibp.phase
  return (
    <div className="panel jobs-card">
      <div className="section-label">Background jobs</div>
      <div className="jobs-card-row"><span>BloodHound enrichment</span><span className="muted">{enrichLabel}</span></div>
      <div className="jobs-card-row"><span>HIBP corpus</span><span className="muted">{hibpLabel}</span></div>
    </div>
  )
}
```
Render `<BackgroundJobsCard />` within the Dashboard's layout (e.g. alongside the existing summary cards). Add CSS to `styles.css`:
```css
.jobs-card-row { display: flex; justify-content: space-between; padding: 4px 0; font-size: 13px; }
```

- [ ] **Step 2: Verify** `cd web && npx tsc --noEmit && npm run build && npx vitest run`. Clean / pass.

- [ ] **Step 3: Commit**
```bash
git add web/src/components/Dashboard.tsx web/src/styles.css
git commit -m "feat(web): Overview Background-jobs card"
```

---

## Task 7: Migrate Upload + BloodHound enrichment status to `useJobs` (DRY)

**Files:** Modify `web/src/components/Ingest.tsx`; Modify `web/src/components/BloodHound.tsx`.

Remove the per-component `enrichJob` state + `setInterval` pollers added in the enrichment feature; read the shared `useJobs().enrich` instead. The manual "Run BloodHound enrichment" button stays (it calls `api.enrich`; the provider reflects the running job within ~1.5s).

- [ ] **Step 1: `Ingest.tsx`** — remove `const [enrichJob, setEnrichJob] = useState…`, the polling `useEffect`, the `setEnrichJob(null)` in the audit-reset effect, and the two `setEnrichJob(await api.enrichJob())` priming calls. Add `import { useJobs } from "../jobs"`, `const { enrich: enrichJob } = useJobs()`, and keep the existing render block that displays `enrichJob` (it now reads the shared value). Drop the now-unused `EnrichJob` import if nothing else uses it.

- [ ] **Step 2: `BloodHound.tsx`** — remove the `enrichJob` state, the mount fetch `useEffect`, and the polling `useEffect`; keep `enrichErr` + `runEnrich` (the button handler). Add `const { enrich: enrichJob } = useJobs()` (import `useJobs` from `"../jobs"`). After `runEnrich` calls `api.enrich(csrf)`, also call the provider's `refresh()` (`const { enrich: enrichJob, refresh } = useJobs()`; call `refresh()` after a successful start) so the running state appears promptly. The status-line render block stays.

- [ ] **Step 3: Verify** `cd web && npx vitest run && npx tsc --noEmit && npm run build`. The existing `enrich.test.ts` (api wrapper) still passes; tsc clean (no unused vars).

- [ ] **Step 4: Commit**
```bash
git add web/src/components/Ingest.tsx web/src/components/BloodHound.tsx
git commit -m "refactor(web): single enrichment poller — Upload + BloodHound read useJobs"
```

---

## Task 8: README + full gate + live verification

- [ ] **Step 1: README note** — append to the "What's new in 2.5" section in `README.md`:
```markdown
- **Domain drill-down + job visibility.** Each domain now opens an investigative
  page (accounts table, password-reuse clusters, BloodHound DA-pathway accounts,
  quick-win remediation list, policy + wordlist breakdowns). A header **jobs pill**
  shows live HIBP / BloodHound-enrichment progress from anywhere, with an Overview
  "Background jobs" card.
```
Commit: `git add README.md && git commit -m "docs: domain drill-down + job-status visibility"`

- [ ] **Step 2: Full gate**
```bash
cd web && npx tsc --noEmit && npm run build && npx vitest run
cd .. && gofmt -l cmd internal && go build ./... && go vet ./... && go test ./...
```
All green.

- [ ] **Step 3: Rebuild embedded binary + live run**
```bash
rm -rf internal/webui/dist && cp -r web/dist internal/webui/dist
CGO_ENABLED=0 go build -tags embed -trimpath -ldflags="-s -w" -o patd.exe ./cmd/patd
```
Restart the server, unlock, load the synthetic data (`sample_data/synthetic/`): open a domain → confirm the accounts table, a reuse cluster (the cross-domain "Autumn#Service24" group), and the DA panel render; trigger enrichment → confirm the header pill appears with progress and the Overview card updates. (Auth-gated live click-through may need the operator.)

---

## Self-Review (completed during planning)
- **Spec coverage:** AccountsTable extraction (T1) · domainData derivations (T2) · DomainDetail rewrite with all panels (T3) · JobsProvider (T4) · header pill+popover (T5) · Overview card (T6) · poller migration/DRY (T7) · README + gate (T8). Every spec bullet maps to a task.
- **Type consistency:** `EnrichJob`/`PwnedJob`/`Report`/`ReuseGroup`/`ReportAccount`/`Account` used per their actual api.ts definitions; `useJobs()` returns `{enrich, hibp, anyRunning, refresh}` consistently across T4–T7; `domainData` signatures match their tests.
- **Placeholder scan:** no TBD/vague steps; all tests are node-env pure-logic `.ts` (no DOM deps) with real assertions, matching the repo's existing test style.
- **Testing reality:** the web project has no jsdom/`@testing-library` and must not gain them. Every new test targets a **pure exported helper** (`tableWindow`, `domain*`, `hibpRunning`/`computeAnyRunning`, `jobPillLabel`); the React components/providers (`AccountsTable`, `DomainDetail`, `JobsProvider`, `JobPill`, the Overview card, the migrated pollers) are guarded by `tsc --noEmit` + `npm run build` + the Task 8 live run.
- **Risk note:** T1 and T7 are behavior-preserving refactors — tsc/build + the T8 live run are the guard.
