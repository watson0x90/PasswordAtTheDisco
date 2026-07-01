# Sortable + non-overflowing HTML report tables — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Fix the table overflow in the exported HTML reports and make their data-table columns click-to-sort, via one shared self-contained inline script.

**Architecture:** Add a shared `sortableCSS` + `sortableJS` and inject them into all report templates in `internal/report/report.go`; wrap each data table in an `overflow-x:auto` scroll container and give it `<thead>`/`<tbody>` + a `data-sortable` marker (the Exposure×Impact matrix stays a fixed grid, unmarked). Update the report-HTML no-script pinning tests to allow exactly this one inline script.

**Tech Stack:** Go stdlib `html/template`; plain inline vanilla JS (no build step, no deps).

**Spec:** `docs/superpowers/specs/2026-07-01-sortable-report-tables-design.md`.

## Global Constraints
- Self-contained reports: inline CSS + exactly ONE inline `<script>` (the sorter); NO external `src`, NO network. The model-bundle chart **SVGs stay strictly script-free** (the sorter lives in the report document, never in an SVG).
- The Exposure×Impact **matrix table** (`reportHTML`, the `Exposure \ Impact` header) is a fixed grid — do NOT make it sortable (no `data-sortable`); wrapping it in the scroll container is fine.
- `html.EscapeString` discipline on user-influenced values is unchanged. Stage explicit paths. Commit trailer EXACTLY: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

## File Structure
- `internal/report/report.go` (modify) — add `sortableCSS`/`sortableJS`; inject into the 4 templates; wrap the data tables (`table-wrap` + `<thead>`/`<tbody>` + `data-sortable`).
- `internal/report/report_test.go` (modify) — update the 3 no-`<script>` assertions to the precise relaxation; add sortable/overflow presence assertions.

## Templates + tables (exact, from report.go)
- `reportHTML` (const, ~line 414): 3 tables — per-domain rollup (~492, `<th>Domain</th>…`), **Exposure×Impact matrix (~498 — NOT sortable)**, accounts (~514, `<th>Username</th><th>Domain</th>{{if .Cleartext}}<th>Password</th>{{end}}…`). CSS block has `th{…}` (~445) and `td{…;white-space:nowrap}` (~446).
- `focusedAccountsTemplate` (~582): accounts table (~590). Uses `focusedCSS` (~545; `th` ~555, `td` ~556).
- `weakTemplate` (~669): table (~681). `focusedCSS`.
- `reuseTemplate` (~708): one small members table per group (~720). `focusedCSS`.

---

### Task 1: Shared sorter + overflow fix across all report templates

**Files:** Modify `internal/report/report.go`; Test `internal/report/report_test.go`.

**Interfaces:** No exported signatures change — `report.HTML`/`HTMLCleartext`/`AccountsHTML`/`WeakPasswordsHTML`/`ReuseGroupsHTML` produce the same documents, now with sortable non-overflowing tables.

- [ ] **Step 1: Write the failing test** — add to `report_test.go`:
```go
func TestReportTablesSortableAndScrollable(t *testing.T) {
	// alice+bob share an NT hash so ReuseGroupsHTML renders a group table (else the
	// reuse report has no tables and the sortable/thead assertions can't apply).
	const shared = "AAAA1111AAAA1111AAAA1111AAAA1111"
	accts := []model.Account{
		{Username: "alice", Domain: "CORP", NTHash: shared, Cracked: true, RiskLevel: "Critical", RiskScore: 9, HIBPBreached: true, HIBPBreachCount: 5, Complexity: "mixedalphanum", MeetsPolicy: false},
		{Username: "bob", Domain: "CORP", NTHash: shared, Cracked: false, RiskLevel: "Low", RiskScore: 2},
	}
	when := time.Unix(1_700_000_000, 0)
	var full, focused, weak, reuse bytes.Buffer
	if err := HTML(&full, "Eng", when, accts); err != nil { t.Fatal(err) }
	if err := AccountsHTML(&focused, "Eng — Cracked", "cracked accounts", when, accts); err != nil { t.Fatal(err) }
	if err := WeakPasswordsHTML(&weak, "Eng", when, accts); err != nil { t.Fatal(err) }
	if err := ReuseGroupsHTML(&reuse, "Eng — reuse", when, model.BuildReport(accts)); err != nil { t.Fatal(err) }
	for name, out := range map[string]string{"full": full.String(), "focused": focused.String(), "weak": weak.String(), "reuse": reuse.String()} {
		if !strings.Contains(out, "class=\"table-wrap\"") { t.Errorf("%s: missing overflow scroll wrapper", name) }
		if !strings.Contains(out, "data-sortable") { t.Errorf("%s: missing sortable table marker", name) }
		if !strings.Contains(out, "<thead>") || !strings.Contains(out, "<tbody>") { t.Errorf("%s: missing thead/tbody", name) }
		if strings.Count(out, "<script") != 1 { t.Errorf("%s: want exactly one inline sort script, got %d", name, strings.Count(out, "<script")) }
		if strings.Contains(out, "<script src") || strings.Contains(out, "src=\"http") { t.Errorf("%s: report must not load an external script", name) }
	}
	// The Exposure×Impact matrix must NOT be sortable (fixed grid): its header row is
	// not inside a data-sortable table.
	if strings.Contains(full.String(), "Exposure") {
		// crude but sufficient: the matrix header 'Exposure \\ Impact' cell must not sit in a sortable table.
		idx := strings.Index(full.String(), "Exposure")
		seg := full.String()[maxInt(0, idx-400):idx]
		if strings.Contains(seg, "data-sortable") && strings.Contains(seg, "Exposure \\ Impact") {
			t.Error("matrix table must not be data-sortable")
		}
	}
}

func maxInt(a, b int) int { if a > b { return a }; return b }
```

- [ ] **Step 2: Run, verify FAIL** — `go test ./internal/report/ -run TestReportTablesSortableAndScrollable` → FAIL (no `table-wrap`/`data-sortable`/`thead`).

- [ ] **Step 3: Implement in `report.go`**
  1. Add shared constants:
```go
// sortableCSS styles sortable headers + the horizontal-scroll wrapper. Injected into
// every report's <style>.
const sortableCSS = `.table-wrap{overflow-x:auto}
table[data-sortable] th{cursor:pointer;user-select:none}
.arw{font-size:10px;opacity:.8}`

// sortableJS is a self-contained inline click-to-sort for any table[data-sortable].
// No network, no external src. Type-aware: numeric / risk-severity / text. Degrades
// gracefully (tables render in their emitted order if scripts are blocked).
const sortableJS = `<script>
(function(){
  var RISK={critical:4,high:3,medium:2,low:1};
  function val(td){var s=(td.textContent||"").trim();return (s==="—"||s==="-")?"":s;}
  function kind(vs){var num=true,rk=true,any=false;for(var i=0;i<vs.length;i++){var v=vs[i];if(v==="")continue;any=true;if(!isFinite(Number(v.replace(/[,%]/g,""))))num=false;if(!(v.toLowerCase() in RISK))rk=false;}return !any?"text":(num?"num":(rk?"risk":"text"));}
  function sort(tb,ci,dir){var rows=[].slice.call(tb.rows);var t=kind(rows.map(function(r){return val(r.cells[ci]);}));rows.sort(function(a,b){var x=val(a.cells[ci]),y=val(b.cells[ci]),c;if(t==="num"){c=(Number(x.replace(/[,%]/g,""))||0)-(Number(y.replace(/[,%]/g,""))||0);}else if(t==="risk"){c=(RISK[x.toLowerCase()]||0)-(RISK[y.toLowerCase()]||0);}else{var lx=x.toLowerCase(),ly=y.toLowerCase();c=lx<ly?-1:(lx>ly?1:0);}return dir==="asc"?c:-c;});rows.forEach(function(r){tb.appendChild(r);});}
  [].forEach.call(document.querySelectorAll("table[data-sortable]"),function(tbl){var tb=tbl.tBodies[0];if(!tb||!tbl.tHead)return;var ths=tbl.tHead.rows[0].cells;[].forEach.call(ths,function(th,idx){th.addEventListener("click",function(){var dir=th.getAttribute("data-dir")==="asc"?"desc":"asc";[].forEach.call(ths,function(o){o.removeAttribute("data-dir");var a=o.querySelector(".arw");if(a)a.remove();});th.setAttribute("data-dir",dir);var s=document.createElement("span");s.className="arw";s.textContent=dir==="asc"?" ▲":" ▼";th.appendChild(s);sort(tb,idx,dir);});});});
})();
</script>`
```
  2. Inject `sortableCSS` into each `<style>` block (the `reportHTML` inline CSS and `focusedCSS`), and `sortableJS` just before each `</body>`. (Concatenate the consts into the template source strings, or via a shared associated template — either is fine; the output must contain them.)
  3. For every DATA table (per-domain rollup, accounts in `reportHTML`; the tables in `focusedAccountsTemplate`, `weakTemplate`, `reuseTemplate`) change `<div class="panel"><table>` + the header `<tr><th>…</th></tr>` + `{{range}}<tr>…</tr>{{end}}` + `</table></div>` into:
     `<div class="panel"><div class="table-wrap"><table data-sortable><thead><tr><th>…</th></tr></thead><tbody>{{range}}<tr>…</tr>{{end}}</tbody></table></div></div>`.
     Leave the header cells/data cells exactly as they are.
  4. For the **Exposure×Impact matrix** table (`reportHTML`, `Exposure \ Impact` header): wrap it in `<div class="table-wrap">` for consistency but do NOT add `data-sortable` and do NOT add `<thead>`/`<tbody>` (it's a fixed grid; leaving it unmarked keeps it out of the sorter).

- [ ] **Step 4: Update the relaxed no-`<script>` pinning tests.** Grep `report_test.go` (and any other test) for `strings.Contains(out, "<script")` / `Contains(ctOut, "<script")` assertions on report-HTML output and change them:
  - The two "Self-contained requirement: no `<script>` tags ever" checks (`TestHTMLGraphsAndScatter` ~line 263 and ~line 494): replace `if strings.Contains(out, "<script") { … }` with:
```go
		// The report now carries exactly ONE self-contained inline sort script — no
		// external src, and (count==1) the chart SVGs remain script-free.
		if strings.Count(out, "<script") != 1 {
			t.Errorf("want exactly one inline sort script, got %d", strings.Count(out, "<script"))
		}
		if strings.Contains(out, "<script src") || strings.Contains(out, "src=\"http") {
			t.Error("report must not load an external script")
		}
```
  - The XSS escaping check in `TestHTMLCleartextAndRedacted` (~line 677, currently `if strings.Contains(ctOut, "<script") { …hostile password not escaped… }`): the report now legitimately has the sort `<script>`, so change it to assert the PASSWORD'S markup is not live (the positive `&lt;script&gt;alert(1)&lt;/script&gt;` escaped-form assertion nearby stays):
```go
		if strings.Contains(ctOut, "<script>alert(1)") {
			t.Errorf("HTMLCleartext: hostile password rendered as a LIVE <script> — not escaped")
		}
```

- [ ] **Step 5: Run** — `gofmt -l internal/report` (empty), `go vet ./internal/report/...`, `go test ./internal/report/...` → all green (the updated pinning tests + the new sortable test + the existing bundle/SVG tests). Also run the full `go test ./...` (the all-reports/httpapi tests generate these same reports — confirm nothing asserts no-`<script>` on report HTML there; if it does, apply the same relaxation).
- [ ] **Step 6: Commit** `internal/report/report.go internal/report/report_test.go` — `feat(report): sortable columns + overflow-x scroll in exported HTML reports`.

---

## Verification (controller, after the task)
Rebuild embed binary + `dev_seed` :8444. `GET /api/export/html` and `GET /api/export/cracked.html` → open in a browser (Playwright): confirm wide tables scroll within their panel (no page overflow), clicking a header sorts (asc/desc toggle + arrow), the Risk column sorts by severity, and the Exposure×Impact matrix is NOT sortable. Confirm no console errors and no network requests from the report. Also unzip `GET /api/export/all.zip` and confirm the HTML entries carry the sorter. Tear down :8444.
