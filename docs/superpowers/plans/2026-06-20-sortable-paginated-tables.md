# Sortable + Paginated Tables Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add column sorting and page-based pagination to the data tables across the app via a shared hook + two shared controls.

**Architecture:** A pure, unit-tested core (`compareValues`, `sortRows`, `paginate`, `pageWindow`) plus a thin React hook (`useSortablePaged`) drives two presentational components (`<SortHeader>`, `<Pager>`). Each table keeps its bespoke row rendering and supplies a type-aware `SortColumn[]`. Frontend-only; no backend change.

**Tech Stack:** React 18 + TypeScript + Vite. Tests: node-env vitest (pure logic only — no jsdom/testing-library). Gates run in `web/`, project-local bins only, NEVER `npm install`: `npx tsc --noEmit`, `npx vitest run` (incl. `styleguard.test.ts`), `npm run build`.

**Spec:** `docs/superpowers/specs/2026-06-20-sortable-paginated-tables-design.md`

**Conventions that bite:**
- `styleguard.test.ts` FAILS on literal inline spacing styles in `.tsx` (e.g. `style={{ marginTop: 8 }}`). Use CSS classes only.
- vitest is node-env: only test pure functions (no React rendering).
- Hooks must be called unconditionally at the top of a component (React rules) — never inside a `{cond && ...}` JSX block or a loop.

---

## File Structure

- **Create** `web/src/sortPage.ts` — pure core (`compareValues`, `sortRows`, `paginate`, `pageWindow`) + the `useSortablePaged` hook + types (`SortDir`, `SortColumn<T>`, `SortState`, `Page<T>`). No JSX, lives at `src/` top level like `util.ts`.
- **Create** `web/src/sortPage.test.ts` — node-env unit tests for the pure functions.
- **Create** `web/src/components/SortHeader.tsx` — sortable `<th>`.
- **Create** `web/src/components/Pager.tsx` — pagination bar.
- **Modify** `web/src/util.ts` — add `RISK_RANK`.
- **Modify** `web/src/styles.css` — `.th-sort*`, `.pager*` classes.
- **Modify** `web/src/components/AccountsTable.tsx` — apply hook, remove virtualization.
- **Modify** the `tableWindow` unit test (delete it) — find with `grep -rl tableWindow web/src`.
- **Modify** `web/src/components/Activity.tsx`, `Domains.tsx`, `Operators.tsx`, `Actionable.tsx`, `Compare.tsx` — apply hook per table.

---

## Task 1: Pure sort/paginate core + hook

**Files:**
- Create: `web/src/sortPage.ts`
- Create: `web/src/sortPage.test.ts`
- Modify: `web/src/util.ts` (add `RISK_RANK`)

- [ ] **Step 1: Write the failing tests**

Create `web/src/sortPage.test.ts`:

```ts
import { describe, it, expect } from "vitest"
import { compareValues, sortRows, paginate, pageWindow, type SortColumn } from "./sortPage"

describe("compareValues", () => {
  it("orders numbers numerically", () => {
    expect(compareValues(2, 10)).toBeLessThan(0)
    expect(compareValues(10, 2)).toBeGreaterThan(0)
    expect(compareValues(5, 5)).toBe(0)
  })
  it("orders strings via localeCompare", () => {
    expect(compareValues("apple", "banana")).toBeLessThan(0)
  })
  it("orders booleans false < true", () => {
    expect(compareValues(false, true)).toBeLessThan(0)
  })
})

interface Row { name: string; n: number; risk: number | null }
const rows: Row[] = [
  { name: "charlie", n: 3, risk: 2 },
  { name: "alice", n: 1, risk: null },
  { name: "bob", n: 2, risk: 4 },
]
const nameCol: SortColumn<Row> = { key: "name", get: (r) => r.name }
const nCol: SortColumn<Row> = { key: "n", get: (r) => r.n }
const riskCol: SortColumn<Row> = { key: "risk", get: (r) => r.risk }

describe("sortRows", () => {
  it("sorts ascending by string", () => {
    expect(sortRows(rows, nameCol, "asc").map((r) => r.name)).toEqual(["alice", "bob", "charlie"])
  })
  it("sorts descending by number", () => {
    expect(sortRows(rows, nCol, "desc").map((r) => r.n)).toEqual([3, 2, 1])
  })
  it("puts null last in BOTH directions", () => {
    expect(sortRows(rows, riskCol, "asc").map((r) => r.risk)).toEqual([2, 4, null])
    expect(sortRows(rows, riskCol, "desc").map((r) => r.risk)).toEqual([4, 2, null])
  })
  it("is stable for equal keys (preserves input order)", () => {
    const eq: Row[] = [
      { name: "x", n: 1, risk: 1 },
      { name: "y", n: 1, risk: 1 },
      { name: "z", n: 1, risk: 1 },
    ]
    expect(sortRows(eq, nCol, "asc").map((r) => r.name)).toEqual(["x", "y", "z"])
  })
  it("returns rows unchanged when column is undefined", () => {
    expect(sortRows(rows, undefined, "asc")).toEqual(rows)
  })
})

describe("paginate", () => {
  const data = Array.from({ length: 23 }, (_, i) => i + 1) // 1..23
  it("slices the right page", () => {
    const { slice, info } = paginate(data, 2, 10)
    expect(slice).toEqual([11, 12, 13, 14, 15, 16, 17, 18, 19, 20])
    expect(info).toMatchObject({ page: 2, pageCount: 3, total: 23, start: 11, end: 20 })
  })
  it("clamps an out-of-range page to the last page", () => {
    const { info } = paginate(data, 99, 10)
    expect(info.page).toBe(3)
    expect(info.start).toBe(21)
    expect(info.end).toBe(23)
  })
  it("handles an empty list", () => {
    const { slice, info } = paginate([], 1, 10)
    expect(slice).toEqual([])
    expect(info).toMatchObject({ page: 1, pageCount: 1, total: 0, start: 0, end: 0 })
  })
})

describe("pageWindow", () => {
  it("lists all pages when few", () => {
    expect(pageWindow(1, 5)).toEqual([1, 2, 3, 4, 5])
  })
  it("windows with gaps around the current page", () => {
    expect(pageWindow(6, 20)).toEqual([1, "…", 4, 5, 6, 7, 8, "…", 20])
  })
  it("no leading gap near the start", () => {
    expect(pageWindow(2, 20)).toEqual([1, 2, 3, 4, "…", 20])
  })
})
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd web && npx vitest run src/sortPage.test.ts`
Expected: FAIL — `Cannot find module './sortPage'`.

- [ ] **Step 3: Implement the core**

Create `web/src/sortPage.ts`:

```ts
import { useEffect, useMemo, useState } from "react"

export type SortDir = "asc" | "desc"

// A sortable column: how to extract a comparable primitive from a row, and the
// natural starting direction when this column is first clicked (text -> asc,
// numbers -> typically "desc" so callers pass defaultDir: "desc").
export interface SortColumn<T> {
  key: string
  get: (row: T) => string | number | boolean | null | undefined
  defaultDir?: SortDir
}

export interface SortState {
  key: string
  dir: SortDir
}

type Primitive = string | number | boolean | null | undefined

// Type-aware compare for non-null values. Numbers numerically, booleans
// false<true, everything else by localeCompare. Always ascending; the caller
// applies direction. null/undefined are handled by sortRows (always last).
export function compareValues(a: Primitive, b: Primitive): number {
  if (typeof a === "number" && typeof b === "number") return a - b
  if (typeof a === "boolean" && typeof b === "boolean") return a === b ? 0 : a ? 1 : -1
  return String(a).localeCompare(String(b))
}

// Stable, direction-aware sort. null/undefined sort LAST regardless of dir.
export function sortRows<T>(rows: T[], col: SortColumn<T> | undefined, dir: SortDir): T[] {
  if (!col) return rows
  const decorated = rows.map((row, i) => ({ row, i, v: col.get(row) }))
  decorated.sort((x, y) => {
    const xn = x.v === null || x.v === undefined
    const yn = y.v === null || y.v === undefined
    if (xn || yn) {
      if (xn && yn) return x.i - y.i
      return xn ? 1 : -1 // nulls last in both directions
    }
    const c = compareValues(x.v, y.v)
    if (c !== 0) return dir === "asc" ? c : -c
    return x.i - y.i // stable
  })
  return decorated.map((d) => d.row)
}

export interface Pagination {
  page: number
  pageSize: number
  total: number
  pageCount: number
  start: number // 1-based index of first shown row (0 when empty)
  end: number // 1-based index of last shown row
}

// Pure page math + slice. Clamps page into [1, pageCount].
export function paginate<T>(rows: T[], page: number, pageSize: number): { slice: T[]; info: Pagination } {
  const total = rows.length
  const pageCount = Math.max(1, Math.ceil(total / pageSize))
  const clamped = Math.min(Math.max(1, page), pageCount)
  const from = (clamped - 1) * pageSize
  const slice = rows.slice(from, from + pageSize)
  return {
    slice,
    info: { page: clamped, pageSize, total, pageCount, start: total === 0 ? 0 : from + 1, end: from + slice.length },
  }
}

// Page-number strip: current ±2, with first/last anchors and "…" gaps.
export function pageWindow(current: number, pageCount: number): (number | "…")[] {
  if (pageCount <= 7) return Array.from({ length: pageCount }, (_, i) => i + 1)
  const out: (number | "…")[] = [1]
  const lo = Math.max(2, current - 2)
  const hi = Math.min(pageCount - 1, current + 2)
  if (lo > 2) out.push("…")
  for (let p = lo; p <= hi; p++) out.push(p)
  if (hi < pageCount - 1) out.push("…")
  out.push(pageCount)
  return out
}

export interface Page<T> extends Pagination {
  rows: T[]
  sort: SortState
  setSort: (key: string) => void
  setPage: (p: number) => void
  setPageSize: (n: number) => void
}

// useSortablePaged: sort + paginate an already-filtered row set. State is local
// to the calling component. Page resets to 1 when the input identity changes,
// when the sort changes, or when the page size changes.
export function useSortablePaged<T>(
  rows: T[],
  cols: SortColumn<T>[],
  opts: { defaultSort: SortState; pageSize?: number },
): Page<T> {
  const [sort, setSortState] = useState<SortState>(opts.defaultSort)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSizeState] = useState(opts.pageSize ?? 50)

  useEffect(() => {
    setPage(1)
  }, [rows])

  const col = cols.find((c) => c.key === sort.key)
  const sorted = useMemo(() => sortRows(rows, col, sort.dir), [rows, col, sort.dir])
  const { slice, info } = useMemo(() => paginate(sorted, page, pageSize), [sorted, page, pageSize])

  function setSort(key: string) {
    setSortState((prev) => {
      if (prev.key === key) return { key, dir: prev.dir === "asc" ? "desc" : "asc" }
      const c = cols.find((x) => x.key === key)
      return { key, dir: c?.defaultDir ?? "asc" }
    })
    setPage(1)
  }
  function setPageSize(n: number) {
    setPageSizeState(n)
    setPage(1)
  }

  return { rows: slice, sort, setSort, setPage, setPageSize, ...info }
}
```

- [ ] **Step 4: Add `RISK_RANK` to util.ts**

In `web/src/util.ts`, next to the existing `RISK_CLASS` export, add:

```ts
// Severity rank for sorting (Critical highest). Mirrors RISK_CLASS keys.
export const RISK_RANK: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1 }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd web && npx vitest run src/sortPage.test.ts`
Expected: PASS (all describe blocks green).

- [ ] **Step 6: Typecheck**

Run: `cd web && npx tsc --noEmit`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add web/src/sortPage.ts web/src/sortPage.test.ts web/src/util.ts
git commit -m "feat(web): sort/paginate core (compareValues/sortRows/paginate/pageWindow) + useSortablePaged + RISK_RANK"
```

---

## Task 2: Shared controls — `<SortHeader>` + `<Pager>` + CSS

**Files:**
- Create: `web/src/components/SortHeader.tsx`
- Create: `web/src/components/Pager.tsx`
- Modify: `web/src/styles.css`

- [ ] **Step 1: Create `SortHeader.tsx`**

```tsx
import type { ReactNode } from "react"
import type { SortState } from "../sortPage"

// A clickable column header. `info` renders after the label (e.g. an <InfoTip>)
// OUTSIDE the button so the tooltip stays independently interactive.
export function SortHeader({
  label,
  colKey,
  sort,
  onSort,
  numeric,
  info,
}: {
  label: string
  colKey: string
  sort: SortState
  onSort: (key: string) => void
  numeric?: boolean
  info?: ReactNode
}) {
  const active = sort.key === colKey
  const indicator = active ? (sort.dir === "asc" ? "▲" : "▼") : "↕"
  return (
    <th className={numeric ? "num" : undefined} aria-sort={active ? (sort.dir === "asc" ? "ascending" : "descending") : "none"}>
      <button type="button" className={active ? "th-sort active" : "th-sort"} onClick={() => onSort(colKey)}>
        {label}
        <span className="th-sort-ind">{indicator}</span>
      </button>
      {info}
    </th>
  )
}
```

- [ ] **Step 2: Create `Pager.tsx`**

```tsx
import { pageWindow, type Page } from "../sortPage"

// The pagination bar. Always shows the count + a Rows size selector; the
// Prev/Next/number strip is omitted when there is only one page.
export function Pager<T>({ page, sizes = [25, 50, 100] }: { page: Page<T>; sizes?: number[] }) {
  const nums = pageWindow(page.page, page.pageCount)
  return (
    <div className="pager">
      <div className="pager-info">
        <span>
          Showing {page.start.toLocaleString()}–{page.end.toLocaleString()} of {page.total.toLocaleString()}
        </span>
        <label className="pager-size">
          Rows:
          <select className="search" value={page.pageSize} onChange={(e) => page.setPageSize(Number(e.target.value))}>
            {sizes.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
      </div>
      {page.pageCount > 1 && (
        <div className="pager-nav">
          <button className="pager-btn" disabled={page.page <= 1} onClick={() => page.setPage(page.page - 1)}>
            ‹ Prev
          </button>
          {nums.map((n, i) =>
            n === "…" ? (
              <span key={`gap-${i}`} className="pager-gap">
                …
              </span>
            ) : (
              <button key={n} className={n === page.page ? "pager-num active" : "pager-num"} onClick={() => page.setPage(n as number)}>
                {n}
              </button>
            ),
          )}
          <button className="pager-btn" disabled={page.page >= page.pageCount} onClick={() => page.setPage(page.page + 1)}>
            Next ›
          </button>
        </div>
      )}
    </div>
  )
}
```

- [ ] **Step 3: Add CSS**

Append to `web/src/styles.css` (use existing color vars; values mirror nearby rules — no inline styles needed anywhere):

```css
/* Sortable headers + pager */
.th-sort {
  background: none;
  border: none;
  padding: 0;
  font: inherit;
  color: inherit;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 5px;
}
.th-sort:hover { color: var(--accent); }
.th-sort.active { color: var(--accent); }
.th-sort-ind { font-size: 9px; color: var(--faint); }
.th-sort.active .th-sort-ind { color: var(--accent); }

.pager {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 12px;
  font-size: 13px;
  color: var(--dim);
}
.pager-info { display: flex; align-items: center; gap: 14px; }
.pager-size { display: flex; align-items: center; gap: 6px; }
.pager-size .search { width: auto; padding: 4px 8px; }
.pager-nav { display: flex; align-items: center; gap: 4px; }
.pager-btn,
.pager-num {
  background: none;
  border: 1px solid var(--hairline);
  border-radius: 7px;
  color: var(--dim);
  font: inherit;
  padding: 4px 9px;
  cursor: pointer;
}
.pager-btn:disabled { opacity: 0.4; cursor: default; }
.pager-num.active { background: var(--accent); border-color: var(--accent); color: #fff; }
.pager-gap { padding: 0 4px; color: var(--faint); }
```

- [ ] **Step 4: Typecheck + build + styleguard**

Run: `cd web && npx tsc --noEmit && npx vitest run && npm run build`
Expected: tsc clean; vitest green (incl. `styleguard.test.ts` — no inline styles were added); build succeeds.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/SortHeader.tsx web/src/components/Pager.tsx web/src/styles.css
git commit -m "feat(web): shared SortHeader + Pager controls + styles"
```

---

## Task 3: Accounts table — apply hook, remove virtualization

**Files:**
- Modify: `web/src/components/AccountsTable.tsx`
- Delete: the `tableWindow` unit test (locate with `grep -rl tableWindow web/src`)

**Context:** `AccountsTable({ accounts }: { accounts: Account[] })` currently virtualizes via `tableWindow`/`VIRT_THRESHOLD`/`ROW_H`/`OVERSCAN` + scroll state. Replace all of that with `useSortablePaged`. The reveal machinery (`revealed`, `revealing`, `revealError`, `reveal`, `hide`, `copy`, the 45s timers) and the `WeakCell`/`AccountLink`/`InfoTip`/`GLOSSARY` imports stay.

- [ ] **Step 1: Remove virtualization, add hook**

At the top of `AccountsTable.tsx`:
- Delete the exported `tableWindow` function and the `VIRT_THRESHOLD`, `ROW_H`, `OVERSCAN` constants.
- Add imports: `import { useSortablePaged, type SortColumn } from "../sortPage"`, `import { SortHeader } from "./SortHeader"`, `import { Pager } from "./Pager"`, and add `RISK_RANK` + `weaknessTags` to the existing `../util` import (`weaknessTags` already exists in util; verify).
- Remove `useEffect`/`useRef` usage tied to scrolling (`scrollRef`, `scrollTop`, `viewH`, the `ResizeObserver` effect, and the "reset scroll on accounts change" effect). Keep the timers cleanup effect.

Add the column config inside the component (after the reveal state):

```ts
const COLS: SortColumn<Account>[] = [
  { key: "username", get: (a) => a.username },
  { key: "domain", get: (a) => a.domain },
  { key: "risk", get: (a) => RISK_RANK[a.risk_level] ?? 0, defaultDir: "desc" },
  { key: "score", get: (a) => a.risk_score, defaultDir: "desc" },
  { key: "hibp", get: (a) => a.hibp_breach_count, defaultDir: "desc" },
  { key: "policy", get: (a) => (!a.cracked ? null : a.meets_policy ? 1 : 0) },
  { key: "weak", get: (a) => weaknessTags(a).length, defaultDir: "desc" },
  { key: "shared", get: (a) => a.shared_with, defaultDir: "desc" },
  { key: "da", get: (a) => a.da_domains ?? "" },
]
const page = useSortablePaged(accounts, COLS, { defaultSort: { key: "score", dir: "desc" } })
```

- [ ] **Step 2: Replace the header row + body + remove the scroll container**

- Change the outer scroll `<div className={virtual ? "table-wrap virtual" : "table-wrap"} ...>` to a plain `<div className="table-wrap">` (drop the `ref`, `onScroll`, and the virtual class).
- Replace each sortable `<th>` with a `<SortHeader>`, preserving the existing InfoTips via the `info` prop. The header becomes:

```tsx
<thead>
  <tr>
    <SortHeader label="Username" colKey="username" sort={page.sort} onSort={page.setSort} />
    <SortHeader label="Domain" colKey="domain" sort={page.sort} onSort={page.setSort} />
    <SortHeader label="Risk" colKey="risk" sort={page.sort} onSort={page.setSort} />
    <SortHeader label="Score" colKey="score" numeric sort={page.sort} onSort={page.setSort} info={<InfoTip text={GLOSSARY.risk_score} />} />
    <SortHeader label="HIBP" colKey="hibp" numeric sort={page.sort} onSort={page.setSort} info={<InfoTip text={GLOSSARY.hibp_count} />} />
    <SortHeader label="Policy" colKey="policy" sort={page.sort} onSort={page.setSort} />
    <SortHeader label="Weak" colKey="weak" sort={page.sort} onSort={page.setSort} info={<InfoTip text={GLOSSARY.weak_categories} />} />
    <SortHeader label="Shared" colKey="shared" numeric sort={page.sort} onSort={page.setSort} info={<InfoTip text={GLOSSARY.shared_with} />} />
    <SortHeader label="DA Pathway" colKey="da" sort={page.sort} onSort={page.setSort} info={<InfoTip text={GLOSSARY.da_pathway} />} />
    {isLead && <th>Secret</th>}
  </tr>
</thead>
```

- Replace the virtualized body (the `visible.map` plus the two spacer `<tr>`s) with a direct map over `page.rows`, keeping every existing `<td>` cell exactly as-is (the username `<AccountLink>` + disabled badge, domain, risk badge, score, hibp, policy, `<WeakCell a={a} />`, shared, DA, and the lead-only Secret reveal cell). Row key: `key={`${a.domain}/${a.username}`}`.
- Delete the now-unused `total`/`virtual`/`start`/`end`/`visible`/`cols` locals.

- [ ] **Step 3: Add the Pager**

Immediately after the closing `</div>` of `.table-wrap`, add:

```tsx
<Pager page={page} />
```

Keep the existing lead-only `.meta-line` reveal-audit notice after it.

- [ ] **Step 4: Delete the `tableWindow` test**

Run `grep -rl tableWindow web/src` to find the test file (e.g. `web/src/accountsTable.test.ts` or similar). Remove the `tableWindow` import and its `describe`/`it` blocks. If that leaves the file empty, delete the file.

- [ ] **Step 5: Typecheck, test, build**

Run: `cd web && npx tsc --noEmit && npx vitest run && npm run build`
Expected: tsc clean (no unused symbols — confirm `useEffect`/`useRef` are still imported only if still used; remove from the import if not); vitest green (incl. styleguard); build succeeds.

- [ ] **Step 6: Commit**

```bash
git add web/src/components/AccountsTable.tsx web/src
git commit -m "feat(web): Accounts table sortable + paginated; drop virtualization"
```

---

## Task 4: Activity (audit log) — client-side sort + paginate

**Files:**
- Modify: `web/src/components/Activity.tsx`

**Context:** `Activity` fetches `events: AuditEvent[]` (≤200) via `api.auditLog(...)`. Keep the server query and all filters unchanged. Sort + paginate the returned `events` client-side.

- [ ] **Step 1: Add imports + column config + hook**

Add imports:
```ts
import { useSortablePaged, type SortColumn } from "../sortPage"
import { SortHeader } from "./SortHeader"
import { Pager } from "./Pager"
```

After `events` is in scope (inside the component body, before `return`), add:
```ts
const COLS: SortColumn<AuditEvent>[] = [
  { key: "time", get: (e) => e.time, defaultDir: "desc" },
  { key: "actor", get: (e) => e.actor ?? "" },
  { key: "action", get: (e) => e.action },
  { key: "target", get: (e) => e.target ?? "" },
  { key: "source", get: (e) => e.source ?? "" },
  { key: "result", get: (e) => e.result },
]
const page = useSortablePaged(events, COLS, { defaultSort: { key: "time", dir: "desc" }, pageSize: 50 })
```

- [ ] **Step 2: Replace headers + body + add Pager**

Replace the `<thead>` row with `<SortHeader>` cells:
```tsx
<thead>
  <tr>
    <SortHeader label="When" colKey="time" sort={page.sort} onSort={page.setSort} />
    <SortHeader label="Operator" colKey="actor" sort={page.sort} onSort={page.setSort} />
    <SortHeader label="Action" colKey="action" sort={page.sort} onSort={page.setSort} />
    <SortHeader label="Target" colKey="target" sort={page.sort} onSort={page.setSort} />
    <SortHeader label="Source" colKey="source" sort={page.sort} onSort={page.setSort} />
    <SortHeader label="Result" colKey="result" sort={page.sort} onSort={page.setSort} />
  </tr>
</thead>
```

Change the body map from `events.map((e, i) => ...)` to `page.rows.map((e, i) => ...)` (cells unchanged). Add `<Pager page={page} />` after the closing `</div>` of the `.table-wrap`. The existing `.act-count` chip can stay (it shows the loaded total).

- [ ] **Step 3: Typecheck, test, build**

Run: `cd web && npx tsc --noEmit && npx vitest run && npm run build`
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add web/src/components/Activity.tsx
git commit -m "feat(web): Activity audit log sortable + paginated (client-side over loaded set)"
```

---

## Task 5: Domains detail + reuse tables

**Files:**
- Modify: `web/src/components/Domains.tsx`

**Context:** `DomainDetail` renders five inline `accounts compact` tables (DA-pathway, Escalated-by-Shared-DA under the `risk` tab; Stale, Never-expires, Kerberoastable under the `compliance` tab) plus a `ReuseClusters` component (used twice). Hooks must be unconditional, but these tables are inside `{tab === "..."}` JSX — so **lift each table's row array to a `useMemo` and call `useSortablePaged` at the top of `DomainDetail`** (not inside the conditional JSX), then render using the page objects.

- [ ] **Step 1: Add imports**

```ts
import { useMemo } from "react" // add to existing react import if not present
import { useSortablePaged, type SortColumn } from "../sortPage"
import { SortHeader } from "./SortHeader"
import { Pager } from "./Pager"
import { RISK_RANK } from "../util" // add to existing ../util import
```

- [ ] **Step 2: Lift row arrays + hooks to the top of `DomainDetail`**

The current inline filters become memos near the other top-of-component derivations. Use the SAME filter/sort the JSX uses today:

```ts
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

const daPage = useSortablePaged(daPaths, detailCols, { defaultSort: { key: "score", dir: "desc" } })
const escalatedPage = useSortablePaged(escalatedRows, detailCols, { defaultSort: { key: "score", dir: "desc" } })
const stalePage = useSortablePaged(staleRows, detailCols, { defaultSort: { key: "days", dir: "desc" } })
const neverExpiresPage = useSortablePaged(neverExpiresRows, detailCols, { defaultSort: { key: "score", dir: "desc" } })
const kerberoastPage = useSortablePaged(kerberoastRows, detailCols, { defaultSort: { key: "score", dir: "desc" } })
```

(`daPaths` already exists as a top-of-component const; if it is currently computed inline, lift it to a memo too. One shared `detailCols` covers every detail table — each table only renders headers for the columns it shows.)

- [ ] **Step 3: Convert each detail table**

For each of the five tables, (a) replace its sortable `<th>`s with `<SortHeader>` bound to that table's page object, (b) map over `<table'sPage>.rows` instead of the inline `accounts.filter(...).slice(...)`, keeping every `<td>` exactly as today, and (c) add `<Pager page={...} />` after the `</table>`. Example — the **Stale** table becomes:

```tsx
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
```

Apply the same transformation to:
- **DA-pathway accounts** (`daPage`, cols: username/risk/score/hibp/da/controlled — its DA column header label "DA domains" → `colKey="da"`, Controlled → `colKey="controlled"`).
- **Escalated by Shared-DA** (`escalatedPage`, cols: username/risk/score/shared).
- **Password never expires** (`neverExpiresPage`, cols: username/risk/score/hibp/enabled).
- **Kerberoastable** (`kerberoastPage`, cols: username/risk/score/da/controlled — the "DA" column uses `colKey="da"`).

Keep each table's empty-state guard (`{x === 0 ? <div className="muted">…</div> : <table>…</table>}`) — wrap the `<table> + <Pager>` together in the non-empty branch (a fragment).

- [ ] **Step 4: ReuseClusters — sortable + paged**

In the `ReuseClusters` component, add a hook over `groups`. `ReuseGroup` (from `../api`) fields used by `FragmentRow`: `size` (Accounts), `domains` (count), `has_da_pathway` (bool), `hibp_breach_count`, `password_length` (Len, cracked only). Add `import type { ReuseGroup } from "../api"` if not already imported (it is — `ReuseGroup` is already referenced in this file). Define:

```ts
const reuseCols: SortColumn<ReuseGroup>[] = [
  { key: "accounts", get: (g) => g.size, defaultDir: "desc" },
  { key: "domains", get: (g) => g.domains, defaultDir: "desc" },
  { key: "hibp", get: (g) => g.hibp_breach_count, defaultDir: "desc" },
  { key: "len", get: (g) => g.password_length ?? 0, defaultDir: "desc" },
]
const page = useSortablePaged(groups, reuseCols, { defaultSort: { key: "accounts", dir: "desc" } })
```

Replace the header cells with `<SortHeader … numeric>` — `Accounts`→`colKey="accounts"`, `Domains`→`colKey="domains"`, `HIBP`→`colKey="hibp"`, and (only when `!lateral`) `Len`→`colKey="len"`. Leave `<th>DA?</th>` and the trailing expander `<th></th>` as plain `<th>`. Map `page.rows` into `FragmentRow` instead of `groups`, and add `<Pager page={page} />` after the `</table>`.

- [ ] **Step 5: Typecheck, test, build**

Run: `cd web && npx tsc --noEmit && npx vitest run && npm run build`
Expected: all green. Watch for unused-import / unused-local errors from the lifted filters.

- [ ] **Step 6: Commit**

```bash
git add web/src/components/Domains.tsx
git commit -m "feat(web): Domains detail + reuse tables sortable + paginated"
```

---

## Task 6: Operators table — sortable + paged

**Files:**
- Modify: `web/src/components/Operators.tsx`

**Context:** Renders `ops` (operator rows) in an `ops-table`. Columns: Operator, Role, Last login, Status, Actions. Make the first four sortable; Actions stays plain.

- [ ] **Step 1: Imports + hook**

```ts
import { useSortablePaged, type SortColumn } from "../sortPage"
import { SortHeader } from "./SortHeader"
import { Pager } from "./Pager"
```

After `ops` is in scope, add (use `(typeof ops)[number]` if the element type isn't already imported):

```ts
const COLS: SortColumn<(typeof ops)[number]>[] = [
  { key: "username", get: (u) => u.username },
  { key: "role", get: (u) => u.role },
  { key: "last_login", get: (u) => u.last_login ?? "", defaultDir: "desc" },
  { key: "status", get: (u) => (u.locked ? 2 : u.disabled ? 1 : 0), defaultDir: "desc" },
]
const page = useSortablePaged(ops, COLS, { defaultSort: { key: "username", dir: "asc" }, pageSize: 50 })
```

- [ ] **Step 2: Headers + body + Pager**

Replace the four sortable `<th>`s with `<SortHeader>` (keep `<th className="ops-actions-col">Actions</th>` plain). Change `ops.map((u) => ...)` to `page.rows.map((u) => ...)` (row body unchanged). Add `<Pager page={page} />` after the `</div>` closing the `.table-wrap`.

- [ ] **Step 3: Typecheck, test, build**

Run: `cd web && npx tsc --noEmit && npx vitest run && npm run build`
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add web/src/components/Operators.tsx
git commit -m "feat(web): Operators table sortable + paginated"
```

---

## Task 7: Actionable — worklist + category tables

**Files:**
- Modify: `web/src/components/Actionable.tsx`

**Context:** Two table renderers: `PriorityWorklist` (its own `worklist` array with a `TOP`/show-all cap) and the shared `AccountTable` helper (`rows: ReportAccount[]`, also `TOP`/show-all). Replace both caps with pagination + add sorting.

- [ ] **Step 1: Imports**

```ts
import { useSortablePaged, type SortColumn } from "../sortPage"
import { SortHeader } from "./SortHeader"
import { Pager } from "./Pager"
import { RISK_RANK } from "../util" // add to existing ../util import
```

- [ ] **Step 2: PriorityWorklist**

Replace `showAllWork`/`shown`/the `worklist.length > TOP` block. Decorate with rank to preserve priority order as the default:

```ts
const ranked = worklist.map((item, i) => ({ item, rank: i }))
const COLS: SortColumn<(typeof ranked)[number]>[] = [
  { key: "priority", get: (r) => r.rank },
  { key: "account", get: (r) => r.item.account.username },
  { key: "domain", get: (r) => r.item.account.domain },
  { key: "risk", get: (r) => RISK_RANK[r.item.account.risk_level] ?? 0, defaultDir: "desc" },
]
const page = useSortablePaged(ranked, COLS, { defaultSort: { key: "priority", dir: "asc" }, pageSize: 50 })
```

Header row (Why / Recommended action stay plain):
```tsx
<tr>
  <SortHeader label="Account" colKey="account" sort={page.sort} onSort={page.setSort} />
  <SortHeader label="Domain" colKey="domain" sort={page.sort} onSort={page.setSort} />
  <SortHeader label="Risk" colKey="risk" sort={page.sort} onSort={page.setSort} />
  <th>Why</th>
  <th>Recommended action</th>
</tr>
```

Body: `page.rows.map(({ item, rank }) => { const a = item.account; return (<tr key={`${a.domain}/${a.username}/${rank}`}>…existing cells…</tr>) })`. Replace the `.meta-line` show-all block with `<Pager page={page} />` (outside the `.table-wrap`, after it).

- [ ] **Step 3: AccountTable helper**

Replace `showAll`/`shown`/the `rows.length > TOP` block:

```ts
const COLS: SortColumn<ReportAccount>[] = [
  { key: "username", get: (a) => a.username },
  { key: "domain", get: (a) => a.domain },
  { key: "risk", get: (a) => RISK_RANK[a.risk_level] ?? 0, defaultDir: "desc" },
  { key: "score", get: (a) => a.risk_score, defaultDir: "desc" },
  { key: "shared", get: (a) => a.shared_with, defaultDir: "desc" },
]
const page = useSortablePaged(rows, COLS, { defaultSort: { key: "score", dir: "desc" }, pageSize: 50 })
```

Header (the `{metricHead}` column stays a plain `<th>`):
```tsx
<tr>
  <SortHeader label="Username" colKey="username" sort={page.sort} onSort={page.setSort} />
  <SortHeader label="Domain" colKey="domain" sort={page.sort} onSort={page.setSort} />
  <SortHeader label="Risk" colKey="risk" sort={page.sort} onSort={page.setSort} />
  <SortHeader label="Score" colKey="score" numeric sort={page.sort} onSort={page.setSort} />
  {sharedCol && <SortHeader label="Shared" colKey="shared" numeric sort={page.sort} onSort={page.setSort} />}
  <th>{metricHead}</th>
</tr>
```

Body: `page.rows.map((a, i) => …existing cells…)`. Replace the `.meta-line` show-all block with `<Pager page={page} />`.

- [ ] **Step 4: Remove now-dead `TOP` usages**

If `TOP` is no longer referenced anywhere in the file after both edits, delete its declaration. If still used elsewhere, leave it.

- [ ] **Step 5: Typecheck, test, build**

Run: `cd web && npx tsc --noEmit && npx vitest run && npm run build`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add web/src/components/Actionable.tsx
git commit -m "feat(web): Actionable worklist + category tables sortable + paginated"
```

---

## Task 8: Compare cohorts — pager (no sorting)

**Files:**
- Modify: `web/src/components/Compare.tsx`

**Context:** `CohortCard` renders `items: DiffAccount[]` as `.cohort-row` divs with a "show top 50 / show all" toggle (`showAll`/`shown`). Cohorts are already ordered by the diff — add pagination only (no column sorting).

- [ ] **Step 1: Imports + paging hook**

```ts
import { useSortablePaged, type SortColumn } from "../sortPage"
import { Pager } from "./Pager"
```

In `CohortCard`, remove `const [showAll, setShowAll] = useState(false)` and `const shown = ...`. Add a paging-only hook (a single constant sort column = stable, preserves diff order):

```ts
const PAGE_COLS: SortColumn<DiffAccount>[] = [{ key: "n", get: () => 0 }]
const page = useSortablePaged(items, PAGE_COLS, { defaultSort: { key: "n", dir: "asc" }, pageSize: 50 })
```

- [ ] **Step 2: Render page rows + Pager**

Change `shown.map((x, i) => ...)` to `page.rows.map((x, i) => ...)` (row markup unchanged, incl. the `AccountLink`). Replace the `items.length > 50` show-all button block with `<Pager page={page} />` (placed after the `.cohort-list` div, inside the card). Keep the `items.length === 0 ? <div className="chart-empty">none</div> : …` guard.

- [ ] **Step 3: Typecheck, test, build**

Run: `cd web && npx tsc --noEmit && npx vitest run && npm run build`
Expected: all green (confirm `useState` import is still used elsewhere in the file; if not, drop it).

- [ ] **Step 4: Commit**

```bash
git add web/src/components/Compare.tsx
git commit -m "feat(web): Compare cohorts paginated (pager replaces show-all toggle)"
```

---

## Task 9: Full gate + live verification + finish

**Files:** none (verification + release)

- [ ] **Step 1: Full backend + frontend gates**

```bash
cd /c/base/dev/PasswordAtTheDisco
gofmt -l cmd internal     # expect empty
go build ./... && go vet ./... && go test ./...   # expect all ok
govulncheck ./...         # expect "No vulnerabilities found."
( cd web && npx tsc --noEmit && npx vitest run && npm run build )   # all green incl. styleguard
```

- [ ] **Step 2: Rebuild embedded binary + restart on :8443**

```bash
# stop running patd first (binary lock), then:
bash .claude/skills/build-and-run/scripts/build.sh
```
Then restart via PowerShell: `& .claude\skills\build-and-run\scripts\restart.ps1` and confirm the version stamp matches the new commit.

- [ ] **Step 3: Live Playwright verification**

Login (`watson`/`discotime`), unlock (`disco-vault-2026`), then on **Accounts**, **Activity**, a **Domains** detail table, **Operators**, **Actionable**, and a **Compare** cohort:
- Click a sortable header → indicator (▲/▼) appears and row order flips; click again → reverses.
- Risk column sorts Critical→Low (not alphabetical).
- Change page and page size → slice updates; "Showing X–Y of N" is correct.
- Apply a filter/search on Accounts → returns to page 1.
- Account-drawer links still open from the paged rows.
- Assert the browser console has no 4xx/error noise.

- [ ] **Step 4: Finish the branch**

Use **superpowers:finishing-a-development-branch**: verify tests pass, merge to `main`, tag **v2.14.0**, rebuild + restart on :8443. (Pushing stays deferred per the user's standing preference unless they say otherwise.)

---

## Self-Review notes (for the controller)

- **Spec coverage:** core+hook (T1), controls+CSS (T2), Accounts incl. virtualization removal + retired tableWindow test (T3), Activity client-side (T4), Domains 5 detail + reuse (T5), Operators (T6), Actionable worklist + category, TOP cap replaced (T7), Compare cohorts pager-only (T8), gates+Playwright+v2.14.0 finish (T9). Top-10 Riskiest intentionally untouched. ✓
- **Type consistency:** `SortColumn<T>`, `SortState`, `Page<T>`, `useSortablePaged`, `compareValues`, `sortRows`, `paginate`, `pageWindow`, `RISK_RANK` used identically across tasks. `<SortHeader>` props (`label/colKey/sort/onSort/numeric/info`) and `<Pager>` props (`page/sizes`) consistent. ✓
- **Known follow-up the implementer must resolve from live code:** the reuse-cluster `ReuseGroup` field names in T5 Step 4 (read `FragmentRow`), and locating the `tableWindow` test file in T3 Step 4.
