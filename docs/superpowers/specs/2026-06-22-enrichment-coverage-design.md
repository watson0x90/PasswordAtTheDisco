# Enrichment Coverage (sub-project B) — Design

> **Sub-project B of 2** in the "data-freshness / coverage tools" effort.
> **Sub-project A** (Recalculate scoring) is built and merged to `main`; B is independent of it.

**Goal:** Give operators a read-only **Enrichment coverage** view — the accounts BloodHound
did *not* enrich — with a diagnosis of *why* and a CSV export, so they can go collect that
data or fix the name/collection mismatch on their end.

**Problem it solves:** Today the only signal for un-enriched accounts is the aggregate
"Impact Unknown" KPI on the Overview (a number) and a segregated block on the Actionable
page. There is no dedicated, exportable, *diagnosable* list an operator can take back to
BloodHound to close the coverage gap.

---

## 1. Decisions locked during brainstorming

- **Placement:** a new **stacked section** ("Enrichment coverage") at the bottom of the
  Integrations page — matching today's stacked layout (HIBP + BloodHound sections). **Not**
  tabs, **not** a new top-level nav item.
- **Content:** a **why-banner** (diagnosis) + a **table** of un-enriched accounts + a
  client-side **CSV export**.
- **Access:** visible to **all operators** (analyst + lead), read-only. This requires
  **un-gating the Integrations route for analysts** (it is lead-only today) — done carefully
  so analysts see *only* the coverage section, never the lead-only HIBP/BloodHound config.
- **Backend:** **none.** Everything is derived client-side from existing endpoints
  (`/api/accounts`, `/api/ingests`), both already analyst-callable.

---

## 2. Scope

**In scope (B):**
- A `EnrichmentCoverage` React component: why-banner + table + CSV export, computed from the
  in-memory accounts + ingest history.
- Making `Integrations.tsx` **role-aware**: leads see HIBP + BloodHound + Coverage; analysts
  see **only** Coverage.
- A **minimal nav change** so analysts can reach the `integrations` route (leads keep it
  under Setup ▾, unchanged).
- Pure-logic helpers (un-enriched predicate reuse, why-banner state, CSV rows) + tests.

**Out of scope:** any change to how enrichment runs or how coverage is computed; tabs; a new
backend endpoint; server-side CSV; recording *per-account* match-failure reasons (the
why-banner infers a single audit-level reason from ingest history — see §5).

**Noted debt (deliberately deferred):**
- **Per-account "why unmatched".** The server does not record, per account, *why* BloodHound
  didn't match it (name mismatch vs absent vs uncollected domain). B infers one audit-level
  reason from whether enrichment ran at all. Per-account reasons would need backend work
  (record the normalized lookup key + miss) — a future enhancement.

---

## 3. Architecture

### 3.1 The un-enriched predicate (single source of truth)
Un-enriched = **Impact is Unknown** = `matrix.isProvisional(account)` (which is
`impact_known === false`). The Overview "Impact Unknown" KPI and the Actionable
"no BloodHound coverage" block already use this exact predicate, so reusing it guarantees the
coverage count can never drift from those surfaces. The component filters
`useAccountsData().accounts` with `isProvisional`.

### 3.2 The "why" diagnosis (audit-level, from ingest history)
The why-banner reads `/api/ingests` (already analyst-callable) and branches:
- **0 un-enriched** → success: "All N accounts are enriched. ✓"
- **un-enriched > 0 AND no `enrich` ingest event** → "BloodHound hasn't been run on this
  audit yet — run enrichment (lead) or upload BloodHound user data to populate Impact."
- **un-enriched > 0 AND an `enrich` event exists** → "BloodHound ran, but N accounts didn't
  match. Check their SAM/UPN names or re-collect them in BloodHound."

(The `enrich` ingest event is the same signal `BloodHound.tsx` already uses for its
"Last enriched" stamp, so the two are consistent.)

### 3.3 The table
Columns, all **non-secret** and already present in the redacted `/api/accounts` payload —
**never** password or NT hash:
- **Username**, **Domain**, **Cracked** (yes/—), **Exposure level** (`risk_level`, which for
  un-enriched accounts is the provisional Exposure-only level).
Default sort: cracked-first, then by `exposure_score` descending (most exposed un-enriched
accounts first — those are the ones worth chasing coverage for). Reuse existing table styling
(`worklist`/`accounts-table` classes); a plain sorted table is sufficient — search/sort
controls only if they reuse existing helpers cheaply.

### 3.4 CSV export (client-side)
A button builds a CSV string from the same non-secret columns (Username, Domain, Cracked,
Exposure level) and triggers a Blob download (`text/csv`), filename like
`unenriched-<auditName>.csv`. No network call, no secrets. The CSV row builder is a pure
function (tested). If a client-side download helper already exists in the codebase, reuse it;
otherwise a small local `download(filename, text)` is fine.

### 3.5 Access model change (the careful part)
- **`Integrations.tsx` becomes role-aware:** `me?.role === "lead"` → render `<PwnedPasswords/>`
  + `<BloodHound/>` + `<EnrichmentCoverage/>` (today's two plus the new one). Else (analyst)
  → render **only** `<EnrichmentCoverage/>`. Analysts never see the HIBP/BloodHound config
  components (no "requires lead" stubs, no credential UI).
- **Nav:** make the `integrations` view reachable by analysts. Leads keep it in the lead-only
  **Setup ▾** dropdown (unchanged). For analysts, surface a single **"Integrations"** entry
  in their nav (the exact host — appended to the analyst primary `TABS`, or a standalone
  item — is an implementation detail for the plan; the requirement is: exactly one
  analyst-reachable entry point, no duplicate entry for leads).
- **Security invariant:** this change exposes only the `integrations` *route* + the read-only
  coverage section to analysts. The lead-only `/api/bhe/*` config endpoints are untouched;
  `EnrichmentCoverage` calls only `/api/accounts` + `/api/ingests` (both already
  analyst-permitted, redacted, unlocked-gated). No new data is exposed to analysts that they
  could not already fetch.

---

## 4. Components & files (frontend-only)

- **Create** `web/src/coverage.ts` — pure helpers: `unenrichedAccounts(accounts)` (filter via
  `isProvisional`), `coverageWhy({ unenrichedCount, totalCount, enrichRan })` →
  a discriminated banner state, `coverageCsv(rows)` → CSV string.
- **Create** `web/src/coverage.test.ts` — pure-logic tests for the three helpers.
- **Create** `web/src/components/EnrichmentCoverage.tsx` — the section: reads
  `useAccountsData()` + `api.ingests()`, renders the why-banner + table + CSV button. Reuses
  existing classes (`section-label`, `panel`, `coverage-banner*`, `btn`, table styles); no
  inline spacing styles (styleguard).
- **Modify** `web/src/components/Integrations.tsx` — role-aware composition (§3.5).
- **Modify** `web/src/components/AppShell.tsx` (+ `nav` plumbing) — analyst-reachable
  Integrations entry (§3.5).

No Go changes. No new endpoints.

## 5. Error handling, edge cases

- **No active audit / locked / empty audit:** `useAccountsData` yields no accounts → the
  section shows a neutral empty state ("No accounts loaded yet."), not an error. `api.ingests()`
  failure is swallowed (treated as "enrichment not run") like `BloodHound.tsx` does.
- **All enriched:** success banner, no table, and the CSV button is **hidden** (nothing to
  export).
- **Large audits:** the full redacted account list is already in the browser (the Dashboard
  does whole-set client analysis today), so client-side filtering/CSV is consistent and fine.

## 6. Testing

- **Pure logic (`coverage.test.ts`):** `unenrichedAccounts` selects exactly the
  `impact_known === false` accounts (and matches an `isProvisional` reference set);
  `coverageWhy` returns the right state for each branch (all-covered / never-run /
  ran-unmatched); `coverageCsv` emits the right header + rows and **contains no password/hash
  fields** (assert the secret fields never appear even if present on the input object).
- **Playwright (live):** as an **analyst**, navigate to Integrations → see **only** the
  Coverage section (no HIBP/BloodHound config); as a **lead**, see all three; the table lists
  the un-enriched accounts, the why-banner matches the enrichment state, CSV downloads; assert
  the **console has no 4xx/error noise** (esp. that analysts don't trigger a lead-only call).
- **Gates:** `cd web && npx tsc --noEmit && npx vitest run && npm run build`; the Go gates stay
  green (no Go changes, but run `go build/test ./...` to confirm nothing regressed).

## 7. Definition of done (B)

An analyst can open Integrations and see *only* a read-only **Enrichment coverage** section: a
banner diagnosing why accounts are un-enriched, a table of those accounts (no secrets), and a
CSV export to take to BloodHound. A lead sees the same section beneath the existing HIBP and
BloodHound config. Counts match the Overview "Impact Unknown" KPI. No backend changes, no new
endpoints, gates green, console clean.
