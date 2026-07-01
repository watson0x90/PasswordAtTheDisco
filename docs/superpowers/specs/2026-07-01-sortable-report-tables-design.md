# Sortable + non-overflowing exported HTML report tables — Design

**Status:** Approved (2026-07-01)

## Goal
Fix the table overflow in the exported HTML reports (content spilling past the right page edge) and make
every column click-to-sort, via a small self-contained inline script — while keeping the reports
standalone and safe to open/email anywhere.

## Context (what renders these)
`internal/report/report.go` produces the self-contained HTML reports, each with inline CSS and (today) NO
`<script>`:
- `report.HTML` / `report.HTMLCleartext` → the `reportHTML` template (shared; the Cleartext flag adds a
  banner + Password column). Its accounts table has ~11 columns.
- `report.AccountsHTML` → `focusedAccountsTemplate` (+ shared `focusedCSS`) — cracked & hibp focused reports.
- `report.WeakPasswordsHTML` → `weakTemplate` — weak-passwords report.
- `report.ReuseGroupsHTML` → `reuseTemplate` — password-reuse groups.
Current CSS: `.wrap{max-width:1000px}`, `table{width:100%}`, `td{…;white-space:nowrap}`.

## Root cause of the overflow
`td { white-space: nowrap }` forces every cell to its full width; a wide account table's min-content width
exceeds the 1000px `.wrap`, and no container has `overflow-x`, so the table spills past the page's right
edge instead of being contained.

## Design

### 1. Overflow fix — scroll container
Wrap each report `<table>` in a horizontally-scrollable container (`<div class="table-wrap">…</div>` with
`.table-wrap{overflow-x:auto}`, or equivalently `overflow-x:auto` on the `.panel` that holds a table). A
too-wide table then scrolls **within** the panel; rows stay single-line and readable (keep
`white-space:nowrap`); nothing else reflows. Applies to the accounts table in `reportHTML` and every
focused table.

### 2. Sortable columns — inline vanilla JS
A shared, self-contained inline `<script>` (~40 lines; NO network, NO external `src`) at the end of each
report:
- Attaches a click handler to each `<th>`. Click sorts the table's `<tbody>` rows by that column; click
  again toggles ascending/descending; a ▲/▼ indicator shows the active column + direction.
- **Type-aware per column, auto-detected from cell text:** if a column's cells all parse as finite
  numbers → numeric compare (score, HIBP count, shared, controlled, etc.); else if they match the risk set
  → **severity rank** (Critical=4 > High=3 > Medium=2 > Low=1); else case-insensitive text compare. Cell
  sort value = the cell's `textContent` (works through the badge spans).
- Tables use a proper `<thead>` (header row) + `<tbody>` (data rows) so the header never participates in
  the sort. (This requires adding `<thead>`/`<tbody>` tags to the four templates' tables.)
- `th{cursor:pointer;user-select:none}` + the arrow indicator, via the shared CSS.

### 3. Graceful degradation
Tables render in their existing default order (the Go side already emits, e.g., HIBP-breach-desc for the
hibp report). If a viewer strips/blocks inline scripts, the report is fully readable and pre-ordered — the
script only *enables* re-sorting. No external dependency, no network, no fetch.

### 4. DRY — shared script + CSS across templates
Define the sort CSS and the sort `<script>` ONCE (shared Go consts / a shared associated template block)
and inject them into all four templates (`reportHTML`, `focusedAccountsTemplate`, `weakTemplate`,
`reuseTemplate`) — not copied per template. `report.HTMLCleartext` inherits it automatically (same
`reportHTML` template).

### 5. Scope boundary — model-bundle SVGs stay script-free
The sort script lives only in the report **document**. The model-bundle chart/graph **SVGs**
(`ChartSVGs`, `svgNetworkGraph`, etc.) MUST remain strictly script-free — that constraint is unchanged.

## The one deliberate constraint change
The report HTML was previously asserted to contain **no** `<script>`. Adding the sort script relaxes that
for the report *document* only. The pinning tests that assert `!strings.Contains(out, "<script")` on report
output (`TestHTMLGraphsAndScatter`, `TestHTMLCleartextAndRedacted`, and any focused/weak/reuse HTML test)
are **intentionally updated** to instead assert:
- the report contains the controlled inline sort script (e.g. a stable marker like a `data-sortable`
  table attribute or a known function name), AND
- it has **no external script reference** (`src=` / `http`) and no network fetch, AND
- the embedded chart **SVGs still contain no `<script>`** (the SVG-level no-script guard stays).
This is the approved relaxation — the reports gain exactly one self-contained sort script.

## Testing
For each report generator (`HTML`, `HTMLCleartext`, `AccountsHTML`, `WeakPasswordsHTML`, `ReuseGroupsHTML`),
assert the output has: the `overflow-x` scroll wrapper around the table; `<thead>` + `<tbody>` structure;
the inline sort script present; NO external `src=`/`http(s)://` (except the SVG `xmlns` namespace);
`th{cursor:pointer}`; and the risk-severity handling reachable in the script. Add a focused assertion that
the risk column can sort by severity (verify the rank map / a marker). Re-assert the model-bundle SVGs
(`ChartSVGs` output / `svgNetworkGraph`) contain no `<script>`. Confirm the all-reports zip's HTML entries
carry the sorter (they're generated by the same functions).

## Constraints (carry-over)
- CGO-free stdlib only; the sort script is plain inline JS (no build step, no deps). NEVER `npm install`.
- Self-contained: inline CSS + one inline `<script>`, no external assets, no network. `html.EscapeString`
  discipline on user-influenced values is unchanged.
- Stage explicit paths. Commit trailer EXACTLY: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
