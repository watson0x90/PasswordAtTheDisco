# Console Nav Restructure + Report Data-Gap Fixes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse 13 flat nav tabs into 6 + two lead-only dropdowns (Setup/Admin), fold Insights into Overview, merge HIBP+BloodHound into one Integrations page, and close four export↔dashboard data gaps (disabled-account flag, `risk_vector` in CSV, `controlled_objects` + `complexity`/`meets_policy` in the HTML reports).

**Architecture:** Part 1 is frontend-only (AppShell nav, App routes, a new thin Integrations composer, Insights embedded in Dashboard). Part 2 adds redacted-safe fields/columns to the report builders and surfaces a "disabled" badge in the account lists. No security-model change — every new field is already redacted-safe.

**Tech Stack:** React + Vite (TypeScript), Go `html/template` self-contained reports, vitest, Playwright. Gates: `gofmt -l cmd internal` empty, `go build ./... && go vet ./... && go test ./...`, `cd web && npx tsc --noEmit && npm run build && npx vitest run`, `govulncheck ./...`.

**Spec:** `docs/superpowers/specs/2026-06-16-nav-restructure-and-gap-fixes-design.md`

---

## File Structure

- `web/src/components/Integrations.tsx` — **new**, composes `<PwnedPasswords/>` + `<BloodHound/>`.
- `web/src/components/Dashboard.tsx` — renders `<Insights/>` as a trailing section.
- `web/src/components/AppShell.tsx` — `View` union, `TABS`, lead-only `NavDropdown` (Setup/Admin).
- `web/src/App.tsx` — route table (drop insights/pwned/bhe; add integrations).
- `web/src/styles.css` — nav-dropdown + disabled-badge styles.
- `internal/model/report.go` — `ReportAccount.Enabled`.
- `web/src/api.ts` — `ReportAccount.enabled`.
- `internal/report/report.go` — CSV `risk_vector`; HTML tables gain Controlled/Complexity/Policy columns + disabled marker.
- `web/src/components/Accounts.tsx`, `web/src/components/Actionable.tsx` — disabled badge in the account lists.

---

# PART 1 — NAV RESTRUCTURE

## Task 1: Integrations page (compose HIBP + BloodHound)

**Files:**
- Create: `web/src/components/Integrations.tsx`

- [ ] **Step 1: Create the component**

```tsx
import { PwnedPasswords } from "./PwnedPasswords"
import { BloodHound } from "./BloodHound"

// Integrations is the merged HIBP + BloodHound configuration page (Setup ▾ → Integrations).
// It composes the two existing pages as stacked sections — no behavior change to either.
export function Integrations() {
  return (
    <>
      <PwnedPasswords />
      <BloodHound />
    </>
  )
}
```

- [ ] **Step 2: Verify it typechecks**

Run: `cd web && npx tsc --noEmit`
Expected: no errors. (The component is exported but not yet routed — that's fine.)

- [ ] **Step 3: Commit**

```bash
git add web/src/components/Integrations.tsx
git commit -m "feat(web): Integrations page composing HIBP + BloodHound"
```

---

## Task 2: Overview absorbs Insights

**Files:**
- Modify: `web/src/components/Dashboard.tsx`

- [ ] **Step 1: Import Insights**

At the top of `web/src/components/Dashboard.tsx`, add to the imports:

```tsx
import { Insights } from "./Insights"
```

- [ ] **Step 2: Render it as a trailing section**

In `Dashboard`'s `return (...)`, the JSX ends with the Charts grid then `</>`:

```tsx
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
    </>
```

Insert `<Insights />` between the closing chart-grid `</div>` and `</>`:

```tsx
        <ChartCard title="Password length (cracked)">
          <Bars data={lengthBuckets(accounts)} color="#818cf8" />
        </ChartCard>
      </div>

      <Insights />
    </>
```

(`Insights` renders its own `section-label "Insights"` + chart grids, and uses the same `useAccountsData`/`useAudits` hooks Dashboard already gates on, so it renders correctly when embedded.)

- [ ] **Step 3: Verify typecheck + build**

Run: `cd web && npx tsc --noEmit && npm run build`
Expected: clean tsc; build succeeds. (Insights is still routable until Task 3 — both render fine.)

- [ ] **Step 4: Commit**

```bash
git add web/src/components/Dashboard.tsx
git commit -m "feat(web): fold Insights charts into the Overview dashboard"
```

---

## Task 3: AppShell nav restructure + route cleanup (atomic)

This task changes the `View` union, the tab set, and the routes together — they're type-coupled and must change in one commit so the project compiles.

**Files:**
- Modify: `web/src/components/AppShell.tsx`
- Modify: `web/src/App.tsx`
- Modify: `web/src/styles.css`

- [ ] **Step 1: Rewrite the View type + TABS + lead nav in AppShell.tsx**

Replace the `View` type (line 7), the `TABS` const (lines 9-17), and the `tabs` computation (lines 30-41) with:

```tsx
export type View =
  | "overview" | "actionable" | "accounts" | "domains" | "compare" | "reports"
  | "ingest" | "policies" | "integrations" | "operators" | "activity"

const TABS: { id: View; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "actionable", label: "Actionable" },
  { id: "accounts", label: "Accounts" },
  { id: "domains", label: "Domains" },
  { id: "compare", label: "Compare" },
  { id: "reports", label: "Reports" },
]

// Lead-only groups, shown as Setup ▾ / Admin ▾ dropdowns.
const SETUP_ITEMS: { id: View; label: string }[] = [
  { id: "ingest", label: "Upload" },
  { id: "policies", label: "Policies" },
  { id: "integrations", label: "Integrations" },
]
const ADMIN_ITEMS: { id: View; label: string }[] = [
  { id: "operators", label: "Operators" },
  { id: "activity", label: "Activity" },
]
```

Delete the old `const tabs = me?.role === "lead" ? [...] : TABS` block entirely.

- [ ] **Step 2: Replace the nav render**

The current nav render (lines 50-56) maps `tabs`:

```tsx
          <nav className="nav">
            {tabs.map((t) => (
              <button key={t.id} className={t.id === view ? "nav-tab active" : "nav-tab"} onClick={() => onNav(t.id)}>
                {t.label}
              </button>
            ))}
          </nav>
```

Replace it with the base tabs + the two lead-only dropdowns:

```tsx
          <nav className="nav">
            {TABS.map((t) => (
              <button key={t.id} className={t.id === view ? "nav-tab active" : "nav-tab"} onClick={() => onNav(t.id)}>
                {t.label}
              </button>
            ))}
            {me?.role === "lead" && (
              <>
                <NavDropdown label="Setup" items={SETUP_ITEMS} view={view} onNav={onNav} />
                <NavDropdown label="Admin" items={ADMIN_ITEMS} view={view} onNav={onNav} />
              </>
            )}
          </nav>
```

- [ ] **Step 3: Add the NavDropdown component**

In `AppShell.tsx`, after the `AppShell` function's closing brace (next to the existing `AuditSwitcher` definition), add:

```tsx
function NavDropdown({
  label,
  items,
  view,
  onNav,
}: {
  label: string
  items: { id: View; label: string }[]
  view: View
  onNav: (v: View) => void
}) {
  const [open, setOpen] = useState(false)
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false)
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [open])
  const active = items.some((i) => i.id === view)
  return (
    <div className="nav-dd">
      <button
        className={active ? "nav-tab active" : "nav-tab"}
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="menu"
        aria-expanded={open}
      >
        {label} ▾
      </button>
      {open && (
        <>
          <div className="audit-backdrop" onClick={() => setOpen(false)} />
          <div className="nav-dd-menu">
            {items.map((i) => (
              <button
                key={i.id}
                className={i.id === view ? "nav-dd-item active" : "nav-dd-item"}
                onClick={() => {
                  onNav(i.id)
                  setOpen(false)
                }}
              >
                {i.label}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
```

(`useState`/`useEffect` are already imported in AppShell; `audit-backdrop` CSS already exists.)

- [ ] **Step 4: Update App.tsx routes**

In `web/src/App.tsx`:

Remove these imports:
```tsx
import { PwnedPasswords } from "./components/PwnedPasswords"
import { BloodHound } from "./components/BloodHound"
```
and the lazy Insights import line:
```tsx
const Insights = lazy(() => import("./components/Insights").then((m) => ({ default: m.Insights })))
```

Add this import (next to the other component imports):
```tsx
import { Integrations } from "./components/Integrations"
```

In `viewFor`, delete these three cases:
```tsx
    case "insights":
      return <Insights />
    ...
    case "pwned":
      return <PwnedPasswords />
    case "bhe":
      return <BloodHound />
```
and add:
```tsx
    case "integrations":
      return <Integrations />
```

- [ ] **Step 5: Repoint any stragglers**

Run: `cd web && grep -rn '"insights"\|"pwned"\|"bhe"' src/ || true`
For each hit that is a `nav(...)` / view-id usage (e.g. a self-navigation inside `PwnedPasswords.tsx` or `BloodHound.tsx` that points at `"pwned"`/`"bhe"`), repoint it to `"integrations"`. Leave unrelated string matches (e.g. API paths like `/api/pwned/...`, or the `pwned`-prefixed action names) untouched.

- [ ] **Step 6: Add CSS**

In `web/src/styles.css`, near the topbar/nav styles (search for `.nav-tab`), add:

```css
.nav-dd { position: relative; display: inline-flex; }
.nav-dd-menu {
  position: absolute;
  top: calc(100% + 6px);
  left: 0;
  z-index: 60;
  min-width: 160px;
  background: var(--glass-strong);
  border: 1px solid var(--glass-border);
  border-radius: 10px;
  padding: 6px;
  box-shadow: 0 18px 50px -20px rgba(0, 0, 0, 0.85);
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.nav-dd-item {
  text-align: left;
  font-family: var(--sans);
  font-size: 13px;
  color: var(--dim);
  background: transparent;
  border: 1px solid transparent;
  border-radius: 8px;
  padding: 7px 12px;
  cursor: pointer;
}
.nav-dd-item:hover { color: var(--text); background: rgba(255, 255, 255, 0.05); }
.nav-dd-item.active { color: #fff; background: rgba(99, 102, 241, 0.18); border-color: rgba(129, 140, 248, 0.32); }
```

- [ ] **Step 7: Verify typecheck + build**

Run: `cd web && npx tsc --noEmit && npm run build`
Expected: clean tsc (no remaining references to the removed `insights`/`pwned`/`bhe` View members); build succeeds.

- [ ] **Step 8: Commit**

```bash
git add web/src/components/AppShell.tsx web/src/App.tsx web/src/styles.css
git commit -m "feat(web): group lead-only tabs under Setup/Admin dropdowns; drop Insights/HIBP/BloodHound top tabs"
```

---

# PART 2 — DATA-GAP FIXES

## Task 4: `enabled` on ReportAccount

**Files:**
- Modify: `internal/model/report.go`
- Modify: `web/src/api.ts`
- Test: `internal/model/report_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/model/report_test.go`:

```go
func TestReportAccountCarriesEnabled(t *testing.T) {
	rep := BuildReport([]Account{
		{Username: "live", Domain: "C", Cracked: true, Enabled: true, RiskScore: 5},
		{Username: "off", Domain: "C", Cracked: true, Enabled: false, RiskScore: 4},
	})
	byName := map[string]bool{}
	for _, a := range rep.Cracked {
		byName[a.Username] = a.Enabled
	}
	if !byName["live"] || byName["off"] {
		t.Fatalf("Enabled not propagated to ReportAccount: %+v", byName)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/model/ -run TestReportAccountCarriesEnabled`
Expected: FAIL — `ReportAccount` has no field `Enabled` (compile error).

- [ ] **Step 3: Add the field + mapping**

In `internal/model/report.go`, add to the `ReportAccount` struct (after `DADomains`):

```go
	Enabled bool `json:"enabled"`
```

In `toReportAccount`, add to the returned literal:

```go
		Enabled: a.Enabled,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/model/ -run TestReportAccountCarriesEnabled`
Expected: PASS. Then `go test ./internal/model/`.

- [ ] **Step 5: Add the TS field**

In `web/src/api.ts`, add to the `ReportAccount` interface (after `da_domains?: string`):

```ts
  enabled?: boolean
```

Run: `cd web && npx tsc --noEmit` — expect clean.

- [ ] **Step 6: gofmt + commit**

```bash
gofmt -w internal/model/report.go internal/model/report_test.go
git add internal/model/report.go internal/model/report_test.go web/src/api.ts
git commit -m "feat(model): ReportAccount.enabled (surface disabled accounts in reports)"
```

---

## Task 5: `risk_vector` column in the accounts CSV

**Files:**
- Modify: `internal/report/report.go` (`CSV`)
- Test: `internal/report/report_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/report/report_test.go`:

```go
func TestCSVHasRiskVector(t *testing.T) {
	var b bytes.Buffer
	if err := CSV(&b, []model.Account{
		{Username: "a", Domain: "C", Cracked: true, RiskLevel: "High", RiskScore: 7, RiskVector: "CRACKED/SHARED-DA"},
	}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	header := strings.SplitN(out, "\n", 2)[0]
	if !strings.Contains(header, "risk_vector") {
		t.Fatalf("CSV header missing risk_vector: %s", header)
	}
	if !strings.Contains(out, "CRACKED/SHARED-DA") {
		t.Fatalf("CSV missing the risk vector value:\n%s", out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/report/ -run TestCSVHasRiskVector`
Expected: FAIL — no `risk_vector` column.

- [ ] **Step 3: Add the column**

In `internal/report/report.go`, in `CSV`, the header slice currently is:

```go
	header := []string{
		"domain", "username", "enabled", "status", "password_length", "complexity",
		"meets_policy", "risk_level", "risk_score", "hibp_found", "hibp_breach_count",
		"reused", "shared_with", "tier0_pathway", "tier0_pathway_domains", "controlled_objects",
		"common_password", "dictionary_word", "forbidden_words", "keyboard_patterns",
	}
```

Insert `"risk_vector"` immediately after `"risk_score"`:

```go
		"meets_policy", "risk_level", "risk_score", "risk_vector", "hibp_found", "hibp_breach_count",
```

The row slice currently has, on the line after the risk_score field:

```go
			yesNo(a.MeetsPolicy), csvSafe(a.RiskLevel), strconv.FormatFloat(a.RiskScore, 'f', 1, 64),
			yesNo(a.HIBPBreached), strconv.Itoa(a.HIBPBreachCount),
```

Insert `csvSafe(a.RiskVector)` right after the RiskScore formatting (matching the header position):

```go
			yesNo(a.MeetsPolicy), csvSafe(a.RiskLevel), strconv.FormatFloat(a.RiskScore, 'f', 1, 64), csvSafe(a.RiskVector),
			yesNo(a.HIBPBreached), strconv.Itoa(a.HIBPBreachCount),
```

- [ ] **Step 4: Run tests to verify**

Run: `go test ./internal/report/ -run TestCSVHasRiskVector` → PASS
Run: `go test ./internal/report/` (the existing `TestCSVAccountsSummary` uses `strings.Contains` adjacency checks that are unaffected by the inserted column) → ok

- [ ] **Step 5: gofmt + commit**

```bash
gofmt -w internal/report/report.go internal/report/report_test.go
git add internal/report/report.go internal/report/report_test.go
git commit -m "feat(report): restore risk_vector column to the accounts CSV"
```

---

## Task 6: HTML reports — Controlled + Complexity/Policy columns + disabled marker

**Files:**
- Modify: `internal/report/report.go` (the `HTML`, `AccountsHTML`/`focusedAccountsTemplate`, `WeakPasswordsHTML`/`weakTemplate`, and `ReuseGroupsHTML`/group templates)
- Test: `internal/report/report_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/report/report_test.go`:

```go
func TestFocusedHTMLHasGapColumns(t *testing.T) {
	accts := []model.Account{
		{Username: "alice", Domain: "CORP", Cracked: true, Complexity: "mixedalphaspecialnum",
			MeetsPolicy: true, Controlled: 12, Enabled: false, RiskLevel: "Critical", RiskScore: 9,
			BannedWordCount: 1},
	}
	when := time.Unix(1_700_000_000, 0)

	var acc, weak bytes.Buffer
	if err := AccountsHTML(&acc, "Eng", "cracked accounts", when, accts); err != nil {
		t.Fatal(err)
	}
	if err := WeakPasswordsHTML(&weak, "Eng", when, accts); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"accounts": acc.String(), "weak": weak.String()} {
		for _, want := range []string{"Complexity", "Policy", "Controlled", "12", "disabled"} {
			if !strings.Contains(out, want) {
				t.Fatalf("%s HTML missing %q", name, want)
			}
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/report/ -run TestFocusedHTMLHasGapColumns`
Expected: FAIL (no Complexity/Policy/Controlled/disabled in the focused templates yet).

- [ ] **Step 3: Update the full HTML report accounts table**

In `internal/report/report.go`, the full-report accounts table header (the line beginning `<tr><th>Username</th><th>Domain</th><th>Risk</th><th>Score</th><th>HIBP</th>...`) ends `...<th>Shared</th><th>DA</th><th>Weaknesses</th></tr>`. Add a `<th>Controlled</th>` before `<th>Weaknesses</th>`:

```
<tr><th>Username</th><th>Domain</th><th>Risk</th><th>Score</th><th>HIBP</th><th>Complexity</th><th>Policy</th><th>Shared</th><th>DA</th><th>Controlled</th><th>Weaknesses</th></tr>
```

In that row, the username cell is `<td>{{.Username}}</td>`. Change it to add the disabled marker:

```
<td>{{.Username}}{{if not .Enabled}}<span class="muted"> · disabled</span>{{end}}</td>
```

And add a Controlled cell immediately before the Weaknesses `<td>` (the Weaknesses cell is the `<td>{{if .IsCommon}}...` line):

```
<td>{{if gt .Controlled 0}}{{.Controlled}}{{else}}<span class="muted">0</span>{{end}}</td>
```

- [ ] **Step 4: Update the focused AccountsHTML table**

The `focusedAccountsTemplate` header is:

```
<tr><th>Username</th><th>Domain</th><th>Status</th><th>Risk</th><th>Score</th><th>Length</th><th>HIBP</th><th>Shared</th><th>Tier-0 pathway</th><th>Weaknesses</th></tr>
```

Replace it with (adds Complexity, Policy after Length; Controlled after Shared):

```
<tr><th>Username</th><th>Domain</th><th>Status</th><th>Risk</th><th>Score</th><th>Length</th><th>Complexity</th><th>Policy</th><th>HIBP</th><th>Shared</th><th>Controlled</th><th>Tier-0 pathway</th><th>Weaknesses</th></tr>
```

Username cell → add disabled marker:
```
<td>{{.Username}}{{if not .Enabled}}<span class="muted"> · disabled</span>{{end}}</td>
```

After the Length cell (`<td>{{if .Cracked}}{{.PasswordLength}}...`), insert Complexity + Policy cells:
```
<td class="muted">{{if .Cracked}}{{.Complexity}}{{else}}—{{end}}</td>
<td>{{if .Cracked}}{{if .MeetsPolicy}}<span style="color:#a3e635">meets</span>{{else}}<span style="color:#fbbf24">fails</span>{{end}}{{else}}<span class="muted">—</span>{{end}}</td>
```

After the Shared cell (`<td>{{if gt .SharedWith 0}}...`), insert the Controlled cell:
```
<td>{{if gt .Controlled 0}}{{.Controlled}}{{else}}<span class="muted">0</span>{{end}}</td>
```

Update the empty-row colspan from `colspan="10"` to `colspan="13"`:
```
{{if not .Accounts}}<tr><td colspan="13" class="empty">none</td></tr>{{end}}
```

- [ ] **Step 5: Update the WeakPasswordsHTML table**

The `weakTemplate` accounts header is:

```
<tr><th>Username</th><th>Domain</th><th>Risk</th><th>Score</th><th>Weaknesses</th></tr>
```

Replace with (adds Complexity, Policy, Controlled before Weaknesses):

```
<tr><th>Username</th><th>Domain</th><th>Risk</th><th>Score</th><th>Complexity</th><th>Policy</th><th>Controlled</th><th>Weaknesses</th></tr>
```

Username cell → disabled marker:
```
<td>{{.Username}}{{if not .Enabled}}<span class="muted"> · disabled</span>{{end}}</td>
```

After the Score cell (`<td>{{f1 .RiskScore}}</td>`), insert Complexity + Policy + Controlled cells:
```
<td class="muted">{{if .Cracked}}{{.Complexity}}{{else}}—{{end}}</td>
<td>{{if .Cracked}}{{if .MeetsPolicy}}<span style="color:#a3e635">meets</span>{{else}}<span style="color:#fbbf24">fails</span>{{end}}{{else}}<span class="muted">—</span>{{end}}</td>
<td>{{if gt .Controlled 0}}{{.Controlled}}{{else}}<span class="muted">0</span>{{end}}</td>
```

Update the empty-row colspan from `colspan="5"` to `colspan="8"`:
```
{{if not .Accounts}}<tr><td colspan="8" class="empty">none</td></tr>{{end}}
```

- [ ] **Step 6: Add the disabled marker to ReuseGroupsHTML members**

In the reuse-group member table (header `<table><tr><th>Username</th><th>Domain</th><th>Risk</th><th>Score</th><th>Tier-0 pathway</th></tr>`), the member username cell is `<td>{{.Username}}</td>`. Change it to:
```
<td>{{.Username}}{{if not .Enabled}}<span class="muted"> · disabled</span>{{end}}</td>
```
(Members are `ReportAccount`, which now has `Enabled` from Task 4.)

- [ ] **Step 7: Run the gap test + the existing report tests**

Run: `go test ./internal/report/`
Expected: ok — `TestFocusedHTMLHasGapColumns` passes AND the existing `TestWeakPasswordsHTML` / `TestFocusedHTMLRedactsAndRenders` (with their no-leak assertions) still pass.

- [ ] **Step 8: gofmt + commit**

```bash
gofmt -w internal/report/report.go internal/report/report_test.go
git add internal/report/report.go internal/report/report_test.go
git commit -m "feat(report): controlled_objects + complexity/policy columns + disabled marker in HTML reports"
```

---

## Task 7: Disabled badge in the Accounts table + Actionable worklists

**Files:**
- Modify: `web/src/components/Accounts.tsx`
- Modify: `web/src/components/Actionable.tsx`
- Modify: `web/src/styles.css`

- [ ] **Step 1: Add the badge in the Accounts table**

In `web/src/components/Accounts.tsx`, the username cell renders the account-name button:

```tsx
                <td>
                  <button className="link-btn acct-name" onClick={() => setSelected(a)} title="Account details">
                    {a.username}
                  </button>
                </td>
```

Add a disabled badge after the button (the `Account` type already has `enabled`):

```tsx
                <td>
                  <button className="link-btn acct-name" onClick={() => setSelected(a)} title="Account details">
                    {a.username}
                  </button>
                  {!a.enabled && <span className="badge-disabled" title="account disabled in AD">disabled</span>}
                </td>
```

- [ ] **Step 2: Add the badge in the Actionable worklists**

In `web/src/components/Actionable.tsx`, the `AccountTable` sub-component renders each row's username cell as `<td>{a.username}</td>`. Change it to:

```tsx
              <td>
                {a.username}
                {a.enabled === false && <span className="badge-disabled" title="account disabled in AD">disabled</span>}
              </td>
```

(Use `a.enabled === false` because `ReportAccount.enabled` is typed `enabled?: boolean`; only show the badge when explicitly false.)

- [ ] **Step 3: Add the CSS**

In `web/src/styles.css`, after the `.badge.wtag` block (or near the other badges), add:

```css
.badge-disabled {
  display: inline-block;
  font-size: 10px;
  color: var(--faint);
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid var(--glass-border);
  border-radius: 999px;
  padding: 1px 7px;
  margin-left: 7px;
  vertical-align: middle;
}
```

- [ ] **Step 4: Verify typecheck + build + vitest**

Run: `cd web && npx tsc --noEmit && npm run build && npx vitest run`
Expected: clean tsc; build ok; vitest green.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/Accounts.tsx web/src/components/Actionable.tsx web/src/styles.css
git commit -m "feat(web): flag disabled accounts with a badge in Accounts + Actionable"
```

---

# PART 3 — VERIFICATION

## Task 8: Full gate + embedded rebuild + live verification

**Files:** none (verification + release)

- [ ] **Step 1: Backend gate**

Run:
```bash
gofmt -l cmd internal
go build ./... && go vet ./... && go test ./...
govulncheck ./...
```
Expected: gofmt prints nothing; all packages `ok`; "No vulnerabilities found."

- [ ] **Step 2: Frontend gate**

Run: `cd web && npx tsc --noEmit && npm run build && npx vitest run`
Expected: clean tsc; build succeeds; vitest green.

- [ ] **Step 3: Rebuild embedded binary + restart**

Run:
```bash
taskkill //F //IM patd.exe 2>/dev/null; sleep 1
rm -rf internal/webui/dist && cp -r web/dist internal/webui/dist
CGO_ENABLED=0 go build -tags embed -trimpath -ldflags="-s -w" -o patd.exe ./cmd/patd
PATD_ADDR=127.0.0.1:8443 PATD_INGEST_TOKEN=tok PATD_USERS_FILE=users.json PATD_AUDIT_LOG=audit.log \
  PATD_HIBP=PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt PATD_LISTS=lists \
  PATD_BHE=config/bloodhound.json PATD_DATA=data ./patd.exe > server.log 2>&1 &
sleep 3
```

- [ ] **Step 4: Browser checks (Playwright)**

Log in as lead (`watson`/`discotime`), unlock (`disco-vault-2026`), open the lab audit, and verify:
- The top bar shows `Overview · Actionable · Accounts · Domains · Compare · Reports` plus `Setup ▾` and `Admin ▾`.
- `Setup ▾` opens and lists Upload / Policies / Integrations; clicking **Integrations** shows both the HIBP and BloodHound panels on one page.
- `Admin ▾` opens and lists Operators / Activity.
- **Overview** scrolls to the Insights charts (Risk score distribution / Account sharing / HIBP-vs-risk / complexity / DA-by-domain) below the summary.
- **Accounts** and **Actionable** render a `disabled` badge on any disabled account (if the lab data has one; otherwise confirm enabled accounts have no badge).
Screenshot the new top bar + the Integrations page.

- [ ] **Step 5: Export spot-check**

```bash
# (reuse an authenticated session jar; see prior sessions)
curl -s -b $JAR http://127.0.0.1:8443/api/export/csv | head -1        # header must contain risk_vector
curl -s -b $JAR http://127.0.0.1:8443/api/export/weak.html | grep -c 'Controlled'   # >= 1
```
Confirm `risk_vector` is in the CSV header and `Controlled` / `Complexity` / `Policy` appear in the weak HTML; re-confirm no cleartext/matched-word leak (grep a known forbidden word — must be absent).

- [ ] **Step 6: README + commit**

Add a short "What's new in 2.4" note to `README.md` (nav consolidation: Setup/Admin dropdowns, Integrations page, Insights in Overview; report gap fixes). Commit:
```bash
git add README.md
git commit -m "docs: note nav consolidation + report gap fixes"
```

- [ ] **Step 7: Hand back to the controller**

Report completion; the controller will run the final whole-branch review and finishing-a-development-branch.

---

## Self-Review notes

- **Spec coverage:** nav pattern + Setup/Admin dropdowns (T3), Insights→Overview (T2), Integrations merge (T1), App route cleanup + straggler repoint (T3); gap fixes — disabled flag (T4 model + T6 HTML + T7 web), risk_vector CSV (T5), controlled_objects HTML (T6), complexity/policy focused HTML (T6). All spec sections mapped.
- **Type consistency:** `ReportAccount.Enabled` (Go) ↔ `ReportAccount.enabled` (TS); the `View` union members used in `TABS`/`SETUP_ITEMS`/`ADMIN_ITEMS`/`viewFor` all exist in the new union (`integrations` added; `insights`/`pwned`/`bhe` removed everywhere). `WeakPasswordsHTML(w, name, generated, accounts)` and `AccountsHTML(w, name, subtitle, generated, accounts)` signatures match their existing callers/tests.
- **Non-goals honored:** no CSV `tier0_pathway_domains` rename; no `/api/domains`; no PwnedPasswords/BloodHound rewrite; no aggregate controlled-objects stat.
- **Atomicity:** Task 3 changes the `View` union + routes + nav together (type-coupled) so the project compiles at the commit boundary; Tasks 1 and 2 are independently compilable precursors.
