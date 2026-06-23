# Enrichment Coverage (sub-project B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A read-only "Enrichment coverage" section on the Integrations page listing the accounts BloodHound did NOT enrich — with a why-diagnosis and a CSV export — reachable by analysts (read-only).

**Architecture:** Frontend-only. Derive the un-enriched set client-side from `useAccountsData()` via the shared `isProvisional` predicate; diagnose "why" from `/api/ingests`; export a client-side CSV of the non-secret list. Make `Integrations` role-aware (analysts see ONLY the coverage section) and reachable by analysts in the nav.

**Tech Stack:** React 18 + TS (`web/src/coverage.ts`, `web/src/components/{EnrichmentCoverage,Integrations,AppShell}.tsx`); pure-logic vitest. No Go change, no new endpoints.

**Spec:** `docs/superpowers/specs/2026-06-22-enrichment-coverage-design.md`

**Branch discipline (every task):** confirm `git branch --show-current` == `feature/enrichment-coverage-B`; NEVER `git checkout`/`git switch`. Web rule: NEVER `npm install`/`npm ci`; `npx tsc --noEmit`/`npx vitest run` only. styleguard: className only. No `--no-verify`.

---

## File Structure

- **Create** `web/src/coverage.ts` — pure helpers: `unenrichedAccounts`, `coverageWhy`, `coverageCsv`.
- **Create** `web/src/coverage.test.ts` — pure-logic tests.
- **Create** `web/src/components/EnrichmentCoverage.tsx` — the section (why-banner + table + CSV).
- **Modify** `web/src/components/Integrations.tsx` — role-aware composition.
- **Modify** `web/src/components/AppShell.tsx` — analyst-reachable Integrations nav entry (desktop `<nav>` + responsive `NavMenu`).

---

## Task 1: Pure coverage helpers

**Files:**
- Create: `web/src/coverage.ts`
- Test: `web/src/coverage.test.ts`

- [ ] **Step 1: Write the failing test.**

```ts
// web/src/coverage.test.ts
import { describe, it, expect } from "vitest"
import type { Account } from "./api"
import { unenrichedAccounts, coverageWhy, coverageCsv } from "./coverage"

const a = (p: Partial<Account>): Account => ({
  username: "u", domain: "CORP", cracked: false, risk_level: "Low", exposure_score: 0,
  impact_score: null, impact_known: false, da_domains: "None", hibp_breached: false,
  ...p,
} as Account)

describe("unenrichedAccounts", () => {
  it("selects exactly the Impact-Unknown (isProvisional) accounts", () => {
    const accts = [a({ username: "x", impact_known: false, impact_score: null }), a({ username: "y", impact_known: true, impact_score: 5 })]
    expect(unenrichedAccounts(accts).map((x) => x.username)).toEqual(["x"])
  })
})

describe("coverageWhy", () => {
  it("all enriched", () => {
    expect(coverageWhy({ unenrichedCount: 0, totalCount: 10, enrichRan: true }).kind).toBe("all-covered")
  })
  it("never run", () => {
    expect(coverageWhy({ unenrichedCount: 4, totalCount: 10, enrichRan: false }).kind).toBe("never-run")
  })
  it("ran but unmatched", () => {
    expect(coverageWhy({ unenrichedCount: 4, totalCount: 10, enrichRan: true }).kind).toBe("ran-unmatched")
  })
})

describe("coverageCsv", () => {
  it("emits a header + one row per account with NO secret fields", () => {
    const csv = coverageCsv([a({ username: "svc", domain: "CORP", cracked: true, risk_level: "High" })] as Account[])
    const lines = csv.trim().split("\n")
    expect(lines[0]).toBe("Username,Domain,Cracked,Exposure level")
    expect(lines[1]).toBe("svc,CORP,yes,High")
    // never leak password/hash even if present on the object
    expect(csv).not.toMatch(/password|nthash|hash/i)
  })
  it("escapes commas/quotes in fields", () => {
    const csv = coverageCsv([a({ username: 'a,b"c', domain: "CORP", risk_level: "Low" })] as Account[])
    expect(csv.split("\n")[1]).toContain('"a,b""c"')
  })
})
```

- [ ] **Step 2: Run to verify failure**

Run: `cd web && npx vitest run coverage` → FAIL (module not found).

- [ ] **Step 3: Implement `web/src/coverage.ts`.**

```ts
import type { Account } from "./api"
import { isProvisional } from "./matrix"

// unenrichedAccounts: the accounts with Unknown Impact (no BloodHound coverage),
// using the SAME predicate as the Overview "Impact Unknown" KPI so counts can't drift.
export function unenrichedAccounts(accounts: Account[]): Account[] {
  return accounts.filter(isProvisional)
}

export type CoverageWhy =
  | { kind: "all-covered"; total: number }
  | { kind: "never-run"; count: number }
  | { kind: "ran-unmatched"; count: number }

// coverageWhy diagnoses the audit-level reason from the un-enriched count + whether a
// BloodHound enrichment has ever run on this audit (an "enrich" ingest event exists).
export function coverageWhy(o: { unenrichedCount: number; totalCount: number; enrichRan: boolean }): CoverageWhy {
  if (o.unenrichedCount === 0) return { kind: "all-covered", total: o.totalCount }
  if (!o.enrichRan) return { kind: "never-run", count: o.unenrichedCount }
  return { kind: "ran-unmatched", count: o.unenrichedCount }
}

// csvField escapes a value for CSV (RFC4180-ish): wrap in quotes + double internal quotes
// when it contains a comma, quote, or newline.
function csvField(s: string): string {
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

// coverageCsv builds a CSV of the un-enriched accounts. NON-SECRET columns only --
// never password or NT hash (they aren't even on the redacted Account; this asserts intent).
export function coverageCsv(accounts: Account[]): string {
  const header = "Username,Domain,Cracked,Exposure level"
  const rows = accounts.map((a) =>
    [csvField(a.username), csvField(a.domain), a.cracked ? "yes" : "no", csvField(a.risk_level)].join(","),
  )
  return [header, ...rows].join("\n") + "\n"
}
```

- [ ] **Step 4: Run to verify pass + commit**

Run: `cd web && npx tsc --noEmit && npx vitest run coverage` → PASS
```bash
test "$(git branch --show-current)" = "feature/enrichment-coverage-B"
git add web/src/coverage.ts web/src/coverage.test.ts
git commit -m "feat(web): pure coverage helpers (unenriched set, why-diagnosis, CSV)"
```

---

## Task 2: EnrichmentCoverage component

**Files:**
- Create: `web/src/components/EnrichmentCoverage.tsx`

- [ ] **Step 1: Implement the component.** (No new pure logic beyond Task 1; component test is covered by Task 1's helpers + the Task 5 Playwright pass.)

```tsx
import { useEffect, useMemo, useState } from "react"
import { api, type Account, type IngestEvent } from "../api"
import { useAccountsData } from "../accountsData"
import { unenrichedAccounts, coverageWhy, coverageCsv } from "../coverage"

// EnrichmentCoverage: read-only list of accounts BloodHound did NOT enrich, with a
// why-diagnosis (from ingest history) and a client-side CSV export. Visible to all
// operators (the Integrations page makes this section analyst-reachable).
export function EnrichmentCoverage() {
  const { accounts } = useAccountsData()
  const [ingests, setIngests] = useState<IngestEvent[] | null>(null)
  useEffect(() => {
    let alive = true
    api.ingests().then((evs) => { if (alive) setIngests(evs) }).catch(() => { if (alive) setIngests([]) })
    return () => { alive = false }
  }, [])

  const unenriched = useMemo(() => (accounts ? unenrichedAccounts(accounts) : []), [accounts])
  const enrichRan = useMemo(() => (ingests ?? []).some((e) => e.kind === "enrich"), [ingests])
  const why = coverageWhy({ unenrichedCount: unenriched.length, totalCount: accounts?.length ?? 0, enrichRan })

  function downloadCsv() {
    const blob = new Blob([coverageCsv(unenriched)], { type: "text/csv" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = "unenriched-accounts.csv"
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  if (!accounts) return <div className="center-state"><div className="spinner">loading</div></div>
  if (accounts.length === 0) return <div className="ops-page"><div className="section-label">Enrichment coverage</div><div className="panel"><p className="ingest-note">No accounts loaded yet.</p></div></div>

  return (
    <div className="ops-page">
      <div className="section-label">Enrichment coverage</div>
      <div className="panel">
        <CoverageBanner why={why} />
        {unenriched.length > 0 && (
          <>
            <div className="pwned-actions">
              <button className="btn" onClick={downloadCsv}>Export CSV</button>
            </div>
            <table className="accounts-table">
              <thead>
                <tr><th>Username</th><th>Domain</th><th>Cracked</th><th>Exposure level</th></tr>
              </thead>
              <tbody>
                {unenriched.map((a, i) => (
                  <tr key={`${a.username}|${a.domain}|${i}`}>
                    <td>{a.username}</td>
                    <td>{a.domain}</td>
                    <td>{a.cracked ? "yes" : <span className="muted">—</span>}</td>
                    <td><span className={`badge ${a.risk_level}`}>{a.risk_level}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
    </div>
  )
}

function CoverageBanner({ why }: { why: ReturnType<typeof coverageWhy> }) {
  if (why.kind === "all-covered") {
    return <div className="coverage-banner" role="status"><span className="coverage-banner-dot" aria-hidden="true" /><span className="coverage-banner-text">All {why.total} accounts are BloodHound-enriched. ✓</span></div>
  }
  const msg = why.kind === "never-run"
    ? `BloodHound hasn't been run on this audit yet — ${why.count} accounts have Unknown Impact. Run enrichment (lead) or upload BloodHound user data to populate it.`
    : `BloodHound ran, but ${why.count} accounts didn't match. Check their SAM/UPN names or re-collect them in BloodHound.`
  return <div className="coverage-banner" role="status"><span className="coverage-banner-dot" aria-hidden="true" /><span className="coverage-banner-text">{msg}</span></div>
}
```
> Implementer: confirm the badge class for `risk_level` matches how other tables color level badges (e.g. the Accounts table uses `RISK_CLASS[a.risk_level]` from `../util`, not the raw level as a class). Use the SAME mechanism the existing tables use (`RISK_CLASS`) so colors are consistent — adjust the `<span className=...>` accordingly. Reuse existing table/panel/banner classes; no inline spacing styles.

- [ ] **Step 2: Typecheck + commit**

Run: `cd web && npx tsc --noEmit` → clean
```bash
test "$(git branch --show-current)" = "feature/enrichment-coverage-B"
git add web/src/components/EnrichmentCoverage.tsx
git commit -m "feat(web): EnrichmentCoverage section (why-banner + un-enriched table + CSV)"
```

---

## Task 3: Role-aware Integrations page

**Files:**
- Modify: `web/src/components/Integrations.tsx`

- [ ] **Step 1: Make Integrations role-aware.** Replace the body so leads see all three sections and analysts see ONLY the coverage section:

```tsx
import { PwnedPasswords } from "./PwnedPasswords"
import { BloodHound } from "./BloodHound"
import { EnrichmentCoverage } from "./EnrichmentCoverage"
import { useAuth } from "../auth"

// Integrations: HIBP + BloodHound config (lead) + Enrichment coverage (all operators).
// Analysts reach this page for the read-only coverage view only; the lead-only HIBP/
// BloodHound config components are not rendered for them.
export function Integrations() {
  const { me } = useAuth()
  const isLead = me?.role === "lead"
  return (
    <>
      {isLead && <PwnedPasswords />}
      {isLead && <BloodHound />}
      <EnrichmentCoverage />
    </>
  )
}
```

- [ ] **Step 2: Typecheck + commit**

Run: `cd web && npx tsc --noEmit && npx vitest run` → clean + green
```bash
test "$(git branch --show-current)" = "feature/enrichment-coverage-B"
git add web/src/components/Integrations.tsx
git commit -m "feat(web): Integrations is role-aware (analysts see only Enrichment coverage)"
```

---

## Task 4: Analyst-reachable Integrations nav entry

**Files:**
- Modify: `web/src/components/AppShell.tsx` (desktop `<nav>` ~lines 57-69; and the responsive `NavMenu` ~lines 195-230)

- [ ] **Step 1: Add the analyst entry to the desktop nav.** In the `<nav className="nav">` block, AFTER the `TABS.map(...)` and the lead-only `Setup`/`Admin` dropdowns, add an analyst-only Integrations tab (leads already have it under Setup):

```tsx
            {me?.role === "analyst" && (
              <button
                className={view === "integrations" ? "nav-tab active" : "nav-tab"}
                onClick={() => onNav("integrations")}
              >
                Integrations
              </button>
            )}
```

- [ ] **Step 2: Add it to the responsive `NavMenu`.** Read `NavMenu` (same file, ~line 195 where it builds `groups` and pushes `Setup`/`Admin` for leads). Add an analyst-only entry so the ☰ menu also exposes Integrations for analysts — mirror however the existing groups/items are pushed (e.g. push a group `{ label: "Integrations", items: [{ id: "integrations", label: "Integrations" }] }` when `me?.role === "analyst"`, or add it to the primary items list for analysts). Match the existing NavMenu structure exactly.

- [ ] **Step 3: Verify routing.** The `integrations` view already routes to `<Integrations />` in `web/src/App.tsx` (confirm) and `"integrations"` is in the `View` union (AppShell.tsx). No routing change needed — only the entry points.

- [ ] **Step 4: Typecheck + commit**

Run: `cd web && npx tsc --noEmit && npx vitest run` → clean + green
```bash
test "$(git branch --show-current)" = "feature/enrichment-coverage-B"
git add web/src/components/AppShell.tsx
git commit -m "feat(web): analysts can reach the Integrations page (read-only coverage)"
```

---

## Task 5: Whole-of-B verification

**Files:** none (verification only)

- [ ] **Step 1: Frontend gates.** `cd web && npx tsc --noEmit && npx vitest run && npm run build` → clean.
- [ ] **Step 2: Backend gates (no Go change, confirm nothing regressed).** `go build ./... && go test ./...` → green.
- [ ] **Step 3: Live (build-and-run + Playwright at `http://127.0.0.1:8443`).**
  - As **lead**: open Integrations → see HIBP + BloodHound config + the **Enrichment coverage** section; the why-banner matches the audit's enrichment state; the un-enriched table lists the Impact-Unknown accounts; **Export CSV** downloads a file with Username/Domain/Cracked/Exposure-level and **no secrets**; the count matches the Overview "Impact Unknown" KPI.
  - As **analyst** (log in as `analyst`/`analystpw`): the nav shows an **Integrations** entry; opening it shows **ONLY** the Enrichment coverage section (NO HIBP/BloodHound config, no "requires lead" stubs); the coverage list + CSV work; the analyst never triggers a lead-only call (assert console has no 403/4xx noise).
  - Assert the browser console has no 4xx/error noise in both roles.
- [ ] **Step 4: Confirm CSV has no secrets** (open the downloaded file or assert in the live check the rows are username/domain/cracked/level only). No commit; proceed to the final whole-branch review, then finishing-a-development-branch.

---

## Self-Review notes (for the controller)

- **Spec coverage:** §3.1 unenriched predicate (`isProvisional`) → Task 1; §3.2 why-banner → Task 1+2; §3.3 table → Task 2; §3.4 client CSV → Task 1+2; §3.5 role-aware page + nav → Tasks 3+4; §6 testing → Tasks 1 + 5.
- **Security:** the CSV + table show only `username/domain/cracked/risk_level` — all already in the redacted `/api/accounts` payload; no password/NT hash. Analysts gain only the `integrations` route + the read-only coverage section; they call only `/api/accounts` + `/api/ingests` (already analyst-permitted). The lead-only `/api/bhe/*` config endpoints + their UI are NOT rendered for analysts.
- **Type consistency:** `unenrichedAccounts`/`coverageWhy`/`coverageCsv` defined in Task 1, consumed in Task 2; `isProvisional` reused (no new predicate). The badge class mechanism must match existing tables (`RISK_CLASS`) — flagged in Task 2.
- **Placeholder honesty:** Task 2 flags the `risk_level` badge class + Task 4 flags the `NavMenu` structure as verify-against-real-code (match the existing mechanism, don't invent).
- No new endpoints; never npm install; styleguard (className only).
