# Sortable + Paginated Tables — Design

**Date:** 2026-06-20
**Topic:** Add column sorting and page-based pagination to the data tables across the app, via a shared logic hook + two shared presentational controls. Frontend-only; no backend change.
**Sequence:** Spec 1 of 2. A follow-up spec covers a global search surface (accounts + a safe password-in-use NTLM probe + audit search). This spec is independent and ships on its own (target **v2.14.0**).

## Problem

The app's tables are static: no column sorting anywhere, and large tables either virtualize into one long scroll (Accounts, ~2,000 rows) or silently cap (Actionable's "showing N of M"; Activity's most-recent-200). Operators can't reorder by the column they care about, and there's no paged way to walk a big result set. We want familiar sortable headers + a page navigator across the tables.

## Decision

Introduce a **shared sorting/pagination hook** (`useSortablePaged`) plus two small presentational components (`<SortHeader>`, `<Pager>`). Each table keeps its own bespoke row rendering and wires up which columns are sortable and how they compare. Apply across Accounts, Activity (client-side over the loaded set), the Domains detail + reuse tables, Operators, Actionable, and Compare cohorts (pager only). Approved via brainstorming.

**Not in scope:** any backend/API change; server-side audit pagination (the roadmap's explicit trigger to move to a real store — deferred); Insights → Top-10 Riskiest (a fixed, already-sorted widget); the global search surface (Spec 2).

## Architecture

### A. Shared logic — `web/src/sortPage.ts` (new)

A framework-light hook plus a comparator helper. No JSX, so it lives at `src/` top level like `util.ts`/`insights.ts` and is unit-testable in the node-env vitest setup.

```ts
export type SortDir = "asc" | "desc"

// A column's identity + how to compare two rows on it. `get` extracts a
// sortable primitive; comparison is type-aware (see compareValues).
export interface SortColumn<T> {
  key: string
  get: (row: T) => string | number | boolean | null | undefined
  // optional natural starting direction when this column is first clicked
  // (default "asc" for text, "desc" for numbers — callers can override)
  defaultDir?: SortDir
}

export interface SortState { key: string; dir: SortDir }

export interface Page<T> {
  rows: T[]            // the current page slice
  sort: SortState
  setSort: (key: string) => void   // toggles dir if same key, else switches
  page: number                     // 1-based
  setPage: (p: number) => void
  pageSize: number
  setPageSize: (n: number) => void
  total: number                    // length of the (sorted) input
  pageCount: number
  start: number                    // 1-based index of first row shown (0 if empty)
  end: number                      // 1-based index of last row shown
}

export function useSortablePaged<T>(
  rows: T[],
  cols: SortColumn<T>[],
  opts: { defaultSort: SortState; pageSize?: number },
): Page<T>
```

Behavior:
- **Type-aware compare** (`compareValues(a, b)`, exported for tests): numbers numerically; booleans (false < true); strings via `localeCompare`; `null`/`undefined` sort last regardless of direction. The `dir` flips the result for non-null comparisons.
- **Risk severity rank**: callers pass `get: (a) => RISK_RANK[a.risk_level]` so risk sorts Critical(4) > High(3) > Medium(2) > Low(1), never alphabetically. `RISK_RANK` is added to `web/src/util.ts` next to `RISK_CLASS`.
- **setSort(key)**: if `key === sort.key`, flip `dir`; else set `{ key, dir: column.defaultDir ?? (numeric ? "desc" : "asc") }`. Changing sort **resets page to 1**.
- **Reset to page 1** whenever the input `rows` identity changes (search/filter upstream) — via a `useEffect` on `rows` (and on `sort`/`pageSize`). Sorting is `useMemo`'d on `[rows, sort, cols]`; the page slice is `useMemo`'d on `[sorted, page, pageSize]`.
- **Stable sort**: `compareValues` returning 0 falls back to original index order (decorate-sort-undecorate) so equal keys keep input order.
- **Clamp**: if `page > pageCount` after a data change, clamp to `pageCount` (min 1).

### B. Shared controls

**`web/src/components/SortHeader.tsx` (new)** — a sortable `<th>`:
```tsx
<SortHeader label="Score" colKey="score" sort={p.sort} onSort={p.setSort} numeric />
```
Renders `<th>` (adds `className="num"` when `numeric`) with a `<button className="th-sort">` containing the label + an indicator (`▲`/`▼` for the active column, a dim neutral glyph otherwise). Sets `aria-sort` (`ascending`/`descending`/`none`) on the `<th>` for accessibility. No inline spacing styles — uses CSS classes (`.th-sort`, `.th-sort-ind`).

**`web/src/components/Pager.tsx` (new)** — the navigator bar:
```tsx
<Pager page={p} sizes={[25, 50, 100]} />   // p is the Page<T> from the hook
```
Renders one row (class `.pager`): left = `Showing {start}–{end} of {total}` + a `Rows: <select>` size selector; right = `‹ Prev  1 2 … Next ›` with a windowed page-number strip (current ± 2, with `…` gaps and first/last). When `pageCount <= 1`, the Prev/Next/number strip is omitted but the count + size selector remain. All styled with `.pager*` CSS classes.

### C. New CSS (`web/src/styles.css`)

Add `.th-sort` (transparent button, inherits header font, pointer, hover color), `.th-sort-ind` (small dim glyph), `.pager` (flex row, `justify-content: space-between`, wraps on narrow), `.pager-size`, `.pager-nav`, `.pager-btn`, `.pager-num` (+ `.active`), `.pager-gap`. No literal inline spacing anywhere (styleguard).

## Per-table application

For each table: import `useSortablePaged`, define its `SortColumn[]`, render `<SortHeader>` for sortable columns (plain `<th>` for non-sortable), map over `page.rows`, and render `<Pager page={page} />` after the table.

### Accounts — `web/src/components/AccountsTable.tsx`
- Columns sortable: **Username** (str), **Domain** (str), **Risk** (rank), **Score** (num), **HIBP** (`hibp_breach_count` num), **Shared** (`shared_with` num), **DA Pathway** (`da_domains` str), **Policy** (by `meets_policy` bool, uncracked last), **Weak** (by weakness-tag count). Not sortable: **Secret** (lead column).
- Default sort: `{ key: "score", dir: "desc" }` (preserves today's risk-ordered feel).
- **Remove virtualization**: delete `tableWindow`, `VIRT_THRESHOLD`, `ROW_H`, `OVERSCAN`, the scroll/`viewH`/`scrollTop` state + `ResizeObserver`, and the spacer rows. Render `page.rows` directly. Reveal state (`revealed`/`revealing`/`revealError`) and the 45s auto-hide timers stay. `WeakCell` import stays.
- The parent `Accounts.tsx` still does search/risk/signal filtering and passes the filtered `Account[]`; the hook lives inside `AccountsTable`, so changing filters (new array identity) resets to page 1.

### Activity — `web/src/components/Activity.tsx`
- Sortable client-side over the loaded events (`AuditEvent[]`, ≤200): **When** (`time` — note string ISO; compare as string is chronological for ISO-8601, acceptable), **Operator** (`actor`), **Action**, **Target**, **Source**, **Result**.
- Default: `{ key: "time", dir: "desc" }` (newest first, current behavior).
- The server query (q/action/result/from/to, limit 200) is unchanged. Hook sits over the returned `events`. No server-side paging.

### Domains — `web/src/components/Domains.tsx`
- The five per-domain detail tables (kerberoastable / AS-REP / stale / never-expires / escalated) share the column shape **Username, Risk, Score** + table-specific numeric extras (HIBP, Shared, Days overdue, Controlled, Enabled). Each gets sortable headers + a `<Pager>`; default `{ key: "score", dir: "desc" }`.
- The **reuse-clusters** table (Accounts, Domains, DA?, HIBP, Len) gets sortable headers + pager; default `{ key: "accounts", dir: "desc" }`.
- Pager appears only when a table's row count exceeds the page size (handled by the `pageCount <= 1` rule in `<Pager>`).
- These are `accounts compact` tables; reuse the same `<SortHeader>`/`<Pager>`. If repetition is heavy, a small local helper inside `Domains.tsx` may wrap the common detail-table render, but that's an implementation detail, not required by this spec.

### Operators — `web/src/components/Operators.tsx`
- Sortable: **Operator**, **Role**, **Last login** (time), **Status**. Not sortable: **Actions**.
- Default: `{ key: "username", dir: "asc" }`. Pager present but its nav hides until rows exceed page size (usually the case for operators).

### Actionable — `web/src/components/Actionable.tsx`
- Priority Worklist table (Account, Domain, Risk, …): sortable **Account**, **Domain**, **Risk**, **Score**; **Why** / **Recommended action** not sortable. Default = current priority order, expressed as `{ key: "priority", dir: "asc" }` where `get` returns the item's original index (a no-op sort that preserves order until the user clicks a header). **Replace the existing `TOP`/"showing N of M" cap** with `<Pager>` over the full worklist.
- The category tables and reuse-group tables get sortable headers + pager with sensible defaults (`score` desc; reuse by member count). Where a table renders `ReportAccount`, sort columns map to those fields.

### Compare cohorts — `web/src/components/Compare.tsx`
- `CohortCard`'s member list is a list of `.cohort-row` divs, not a columnar table. **Replace the "show top 50 / show all" toggle with `<Pager>`** over `items` (default page size 50; this matches the prior top-50 default). **No sorting** — cohorts are already ordered by the diff. The hook is still usable with a single no-op sort column (`{ key: "n", get: (_, i) => i }`) purely for paging, or a thin paging-only path; either is fine.

## Data flow

`rows` (already-filtered in the parent) → `useSortablePaged(rows, cols, { defaultSort })` → `{ rows: pageSlice, sort, setSort, page, setPage, pageSize, setPageSize, total, pageCount, start, end }` → table renders `<SortHeader>` cells bound to `sort`/`setSort` and maps `pageSlice`; `<Pager>` binds the page/size controls. All state is local to each table component; nothing is persisted across navigation.

## Security / redaction

Unchanged. This is pure client-side presentation over data the views already hold (redacted accounts, the audit log that already excludes cleartext, operator metadata). No new endpoint, no new field exposure, no change to the lead-gated reveal.

## Testing

- **Unit (`web/src/sortPage.test.ts`, node-env vitest):**
  - `compareValues`: numbers, booleans, strings (localeCompare), null/undefined-last in both directions.
  - Risk-rank sort orders Critical > High > Medium > Low (and reverse on `desc`).
  - Stable sort: equal keys preserve input order.
  - `useSortablePaged` page math: `pageCount`, `start`/`end`, the page slice for a given `page`/`pageSize`; `setSort` toggles dir on same key and resets page to 1; changing `pageSize` clamps an out-of-range page. (Hook tested via a tiny harness or by extracting the pure paging math into a testable function `paginate(sorted, page, size)` that the hook calls — preferred, keeps the unit pure.)
- **Retire** the existing `tableWindow` virtualization test (the function is removed). Any other suite stays green.
- **Gates:** `npx tsc --noEmit`, `npx vitest run` (incl. `styleguard.test.ts` — class-based styling only, no inline spacing), `npm run build`. Backend gates unaffected but still run (`go build/vet/test`, `gofmt`, `govulncheck`).
- **Live Playwright:** on Accounts, Activity, a Domains detail table, Operators, Actionable, and a Compare cohort — click headers to sort (indicator + order flip), change page + page size, confirm filters reset to page 1, and confirm the account-drawer links still open. Assert no 4xx/console errors.

## Out of scope
- Backend/API changes; server-side audit pagination (deferred to the persistence revisit).
- The global search surface and password-in-use probe (Spec 2).
- Persisting sort/page across navigation or in the URL (YAGNI; revisit if requested).
- Insights → Top-10 Riskiest (fixed widget).
