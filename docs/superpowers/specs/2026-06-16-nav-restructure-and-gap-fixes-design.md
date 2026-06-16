# Console nav restructure + report data-gap fixes — design

- **Date:** 2026-06-16
- **Status:** Approved (brainstorm), pending implementation plan
- **Owner:** watson0x90

## Problem

Two findings from an information-architecture + export/dashboard parity review:

1. **Nav sprawl.** The console has **13 flat top-level tabs**. Several are redundant
   (Overview / Domains-detail / Insights render the same chart functions; HIBP and
   BloodHound are near-identical config pages; Actionable and Reports show the same
   data). New operators face a wall of tabs.
2. **Export ↔ dashboard gaps.** A few fields appear in exports but not in the on-screen
   views (or vice-versa): `enabled` is only in the Account drawer + CSV (never in a
   list, so a *disabled* cracked account looks like a live finding); `risk_vector` is in
   the drawer but was dropped from the CSV; `controlled_objects` is in the CSV + drawer
   but no HTML report; the focused HTML exports lack the `complexity` / `meets_policy`
   columns the full HTML + CSV have.

## Part 1 — Nav restructure

### Decisions
- **Pattern:** keep the horizontal top bar; group the lead-only tabs behind two
  dropdown menus (chosen over a two-tier sub-tab bar or a sidebar).
- **Top bar (all roles):** `Overview · Actionable · Accounts · Domains · Compare · Reports`
- **`Setup ▾` (lead-only):** Upload · Policies · **Integrations**
- **`Admin ▾` (lead-only):** Operators · Activity
- **Insights** folds into **Overview** (no longer its own tab).
- **Integrations** is a new page that composes the existing **HIBP** + **BloodHound**
  pages as two stacked sections.

### Components

**`web/src/components/AppShell.tsx`**
- `View` type: remove `insights`, `pwned`, `bhe`; add `integrations`. Final union:
  `overview | actionable | domains | accounts | compare | reports | ingest | policies | integrations | operators | activity`.
- Base `TABS` (all roles), in order: `overview` "Overview", `actionable` "Actionable",
  `accounts` "Accounts", `domains` "Domains", `compare` "Compare", `reports` "Reports".
- Lead-only nav becomes two dropdown groups (data-driven):
  - `Setup`: `[{ingest,"Upload"}, {policies,"Policies"}, {integrations,"Integrations"}]`
  - `Admin`: `[{operators,"Operators"}, {activity,"Activity"}]`
- A new `NavDropdown` sub-component (in AppShell), modeled on the existing
  `AuditSwitcher` dropdown: a trigger button (`Setup ▾` / `Admin ▾`), a click-backdrop,
  an Escape-to-close handler, and a menu listing the group's items. The trigger shows
  the **active** styling when the current `view` is one of its items. Selecting an item
  calls `onNav(id)` and closes the menu. Non-lead users see neither dropdown.

**`web/src/App.tsx`**
- Remove the `insights`, `pwned`, `bhe` cases from `viewFor`; add
  `case "integrations": return <Integrations />`.
- Remove the standalone lazy/`viewFor` wiring for Insights as a *route* (the component
  is still imported by Dashboard). Remove `PwnedPasswords` / `BloodHound` direct routes;
  they are now reached only through `<Integrations />`.
- **Repoint stragglers:** grep `web/src` for any `nav("insights")` / `nav("pwned")` /
  `nav("bhe")` (or equivalent) calls and the removed `View` literals, and update them
  (e.g. HIBP/BloodHound self-navigation → `"integrations"`). The build's `tsc` will flag
  remaining references to the dropped union members.

**Overview absorbs Insights — `web/src/components/Dashboard.tsx`**
- After the existing charts section, render a `section-label` (e.g. "Analytics") and the
  Insights charts. Insights manages its own data via `useAccountsData` (same source as
  Dashboard), so it renders correctly when embedded. `Insights.tsx` is unchanged as a
  component; it simply has no nav route anymore.

**Integrations — `web/src/components/Integrations.tsx` (new)**
- Thin composition: renders `<PwnedPasswords />` then `<BloodHound />` stacked (each
  already carries its own section label). No rewrite of either component. Lead-only by
  virtue of the nav gating (Setup ▾ is lead-only); the underlying components keep their
  own behavior.

### Testing (Part 1)
- `tsc --noEmit` + `npm run build` clean.
- Playwright (lead session): the bar shows the 6 base tabs + `Setup ▾` + `Admin ▾`; each
  dropdown opens and navigates; **Overview** shows the analytics charts; **Integrations**
  shows both the HIBP and BloodHound panels. As a non-lead, the dropdowns are absent.
- No backend change; `go test` unaffected.

## Part 2 — Report data-gap fixes

### 1. Flag disabled accounts
- `internal/model/report.go`: `ReportAccount` gains `Enabled bool json:"enabled"`;
  `toReportAccount` sets `Enabled: a.Enabled`.
- `web/src/api.ts`: `ReportAccount` interface gains `enabled: boolean`.
- A muted **"disabled" badge** renders next to the username when `!enabled` in:
  - `web/src/components/Accounts.tsx` table (the `Account` type already has `enabled`),
  - `web/src/components/Actionable.tsx` `AccountTable` rows (uses `ReportAccount`),
  - the HTML report account tables: `HTML`, `AccountsHTML`, `WeakPasswordsHTML`, and the
    `ReuseGroupsHTML` member tables (all render rows that now know `Enabled` —
    `model.Account` for the report templates, `ReportAccount` for reuse members) — via a
    small inline marker, e.g. `{{if not .Enabled}}<span class="muted"> · disabled</span>{{end}}`.
- CSS: a reusable muted badge class (or reuse existing `.muted`).

### 2. Restore `risk_vector` to the CSV
- `internal/report/report.go` `CSV`: add a `risk_vector` column header (after
  `risk_score`) and emit `csvSafe(a.RiskVector)` in the matching row position. Additive;
  applies to the accounts CSV and the focused CSVs (shared function). `model.Account`
  already carries `RiskVector`.

### 3. `controlled_objects` in HTML reports
- Add a **"Controlled"** column (`{{.Controlled}}`) to the accounts tables in `HTML`
  (full report), `AccountsHTML` (cracked/hibp), and `WeakPasswordsHTML`.

### 4. `complexity` + `meets_policy` in focused HTML
- Add **"Complexity"** and **"Policy"** columns to `AccountsHTML` and
  `WeakPasswordsHTML`, mirroring the full `HTML` report's rendering (complexity shown
  when cracked; policy "meets"/"fails" when cracked, "—" otherwise). The full `HTML`
  already has these.

### Resulting focused-HTML column order (for reference)
- `AccountsHTML`: Username (+disabled) · Domain · Status · Risk · Score · Length ·
  Complexity · Policy · HIBP · Shared · Controlled · Tier-0 pathway · Weaknesses.
- `WeakPasswordsHTML`: Username (+disabled) · Domain · Risk · Score · Complexity ·
  Policy · Controlled · Weaknesses.

### Testing (Part 2)
- `internal/model`: `ReportAccount`/`BuildReport` carries `enabled` (extend a test).
- `internal/report`: assert the CSV header contains `risk_vector`; assert
  `AccountsHTML` / `WeakPasswordsHTML` contain `Controlled` + Complexity/Policy columns
  and a disabled marker for a disabled account. **Preserve the existing no-leak
  assertions** (no password / NT hash / matched word in any export).
- Frontend: `tsc`; Playwright confirms the disabled badge renders in the Accounts table
  and Actionable.

## Non-goals
- Do **not** rename the CSV `tier0_pathway_domains` column (it shipped in v2.2; renaming
  breaks the released format). The API/UI continue to use `da_domains`.
- No new aggregate stat/chart for controlled objects.
- No backend `/api/domains` endpoint — the Domains view stays client-computed.
- No rewrite of the PwnedPasswords or BloodHound components — Integrations only composes
  them.
- No change to the security/redaction model; all new fields (`enabled`, `risk_vector`,
  `controlled_objects`, `complexity`, `meets_policy`) are already redacted-safe metadata.

## Rough file touch-list
- `web/src/components/AppShell.tsx` (View type, TABS, NavDropdown), `web/src/App.tsx`
  (routes), `web/src/components/Dashboard.tsx` (embed Insights),
  `web/src/components/Integrations.tsx` (new), `web/src/components/Accounts.tsx`
  (disabled badge), `web/src/components/Actionable.tsx` (disabled badge),
  `web/src/api.ts` (ReportAccount.enabled), `web/src/styles.css` (nav dropdown + disabled
  badge).
- `internal/model/report.go` (ReportAccount.Enabled), `internal/report/report.go`
  (CSV risk_vector; HTML/AccountsHTML/WeakPasswordsHTML columns + disabled marker),
  `internal/report/report_test.go`, `internal/model/report_test.go`.
