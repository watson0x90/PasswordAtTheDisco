# Domains investigative page + unified Jobs status — design

- **Date:** 2026-06-17
- **Status:** Approved (brainstorm), pending implementation plan
- **Owner:** watson0x90
- **Branch:** `feature/upload-ux` (folded in with the enrichment work)

Two independent, frontend-only features. No backend/API changes — both consume
existing endpoints. Captured in one spec (two parts); built together on the branch.

---

## Part 1 — Domains investigative page

### Problem
The domain detail view (`web/src/components/Domains.tsx` → `DomainDetail`) only
re-renders the same charts as Overview (posture gauge, risk donut, HIBP donut,
length bars, complexity bars). It shows **no accounts** and **no domain-specific
risk structure** — you can't investigate a domain, only glance at it.

### Data (all existing — no backend work)
- `useAccountsData()` → full `Account[]` (already used by the page). Fields
  available: `username, domain, cracked, password_length, risk_level, risk_score,
  risk_vector, hibp_breached, hibp_breach_count, da_domains, controlled_object_count,
  shared_with, enabled, meets_policy, complexity, is_common, is_dictionary_word,
  banned_word_count, keyboard_pattern_count`.
- `api.report()` → `Report` (already used by Reports.tsx). Relevant fields:
  `da_pathways: ReportAccount[]`, `cracked_reuse: ReuseGroup[]`,
  `uncracked_reuse: ReuseGroup[]`, `weak_passwords: ReportAccount[]`.
  `ReuseGroup` = `{group_id, size, cracked, password_length?, hibp_breach_count,
  has_da_pathway, domains, truncated?, members: ReportAccount[]}` — the NT hash is
  **never** exposed (redacted server-side).

### Components

**1. Extract a reusable `AccountsTable` (`web/src/components/AccountsTable.tsx`).**
The sortable/filterable/paginated table body currently inlined in `Accounts.tsx`
is extracted into `AccountsTable({ accounts, storageKey? })` that operates on a
passed `Account[]`. `Accounts.tsx` is refactored to render `<AccountsTable
accounts={filtered} />` (its filter-pills/search/“N of M” chrome stay in
`Accounts.tsx`; only the table body + sort/pagination move). The domain page
renders `<AccountsTable accounts={domainAccts} />`. DRY: one table, two callers.
Reveal (lead-gated secret) behaves identically since it keys on username.

**2. `DomainDetail` (rewritten in `Domains.tsx`, helpers in `web/src/domainData.ts`).**
A new pure-derivation module `domainData.ts` exports functions that take the
selected `domain`, the `Account[]`, and the `Report`, and return the per-domain
slices (unit-testable, no React):
- `domainReuseClusters(report, domain)` → `{ cracked: ReuseGroup[], uncracked:
  ReuseGroup[] }` — groups from `cracked_reuse`/`uncracked_reuse` whose `members`
  include an account in `domain` (a group can span domains; it's included if it
  touches this one). Sorted by `size` desc.
- `domainDAPaths(report, domain)` → `ReportAccount[]` — `da_pathways` filtered to
  the domain, sorted by `controlled`/risk.
- `domainQuickWins(accounts, domain, n)` → top-N cracked accounts in the domain by
  `risk_score` desc (the remediation shortlist).
- `domainPolicy(accounts)` → `{ meets, fails, disabled }` counts.
- `domainWordlist(accounts)` → `{ common, dictionary, banned, keyboard }` counts
  (sum of the boolean/count signals over cracked accounts).

`DomainDetail` layout (top → bottom):
- Header: `← All domains`, domain name.
- **Posture panel** (existing gauge + the 5 stat tiles) — kept.
- **Stat strips:** a compact **policy** strip (Meets / Fails / Disabled) and a
  **wordlist** strip (Common / Dictionary / Forbidden / Keyboard) using the
  existing `DStat` tiles.
- **Charts row (slimmed):** risk distribution donut + HIBP donut (drop the
  length+complexity duplication; they live on Overview).
- **Reuse clusters** panel — two tables (cracked / uncracked-lateral): columns
  size · domains-spanned · DA? · HIBP-max · pw-length (cracked only). Each row
  expandable to its members (username · domain · risk) — reuse the redacted
  `ReportAccount` rows; no hash, no cleartext.
- **DA-pathway accounts** panel — table (username · risk · controlled-objects ·
  da-domains). Empty-state: “No BloodHound DA pathways in this domain (run
  enrichment from Integrations → BloodHound).”
- **Quick wins** panel — top-N weakest cracked accounts (username · risk · length
  · signals). Lead-gated reveal available via the same row affordance as Accounts.
- **Accounts table** — `<AccountsTable accounts={domainAccts} />` (the full list).

### Error / empty states
- `Report` load failure: the report-derived panels show a one-line “report
  unavailable” notice; the accounts table + posture (from `useAccountsData`) still
  render (the two data sources are independent).
- A domain with no cracked accounts: reuse/quick-wins/wordlist panels show empty
  states; the page still renders.

### Testing
- vitest `domainData.test.ts`: cluster filtering includes only groups touching the
  domain; a cross-domain group appears in both domains' views; DA filtering;
  quick-wins ordering + cap; policy/wordlist counts.
- vitest `AccountsTable.test.tsx`: sort by a column, the existing Accounts tests
  still pass after the extraction (no behavior change).
- Playwright: open a domain → see accounts table + a reuse cluster + DA panel.

---

## Part 2 — Unified Jobs/Activity status

### Problem
Background-job status (HIBP download/index; BloodHound enrichment) is scattered:
HIBP on Integrations→HIBP, enrichment on Upload + Integrations→BloodHound. There's
no always-visible signal that *something is processing*, so operators can't find
it (the trigger for this work).

### Architecture: one poller, many consumers

**`JobsProvider` (`web/src/jobs.tsx`) — React context.** Polls both
`api.pwnedJob()` (`/api/pwned/job`) and `api.enrichJob()` (`/api/enrich/job`) and
exposes the combined state via a `useJobs()` hook:
```ts
interface JobsState {
  enrich: EnrichJob | null
  hibp: PwnedJob | null
  anyRunning: boolean   // enrich.phase==="running" || hibp.phase ∈ {downloading,indexing}
}
```
- **Lead-only:** both endpoints are lead-gated (403 for analysts). The provider
  polls only when `me?.role === "lead"`; otherwise it stays null and `anyRunning`
  is false (pill/panel never render for analysts).
- **Adaptive cadence:** poll every **5000 ms** when nothing is running; **1500 ms**
  while `anyRunning`. A poll error (e.g. 423 locked, transient) keeps the last
  state and does not spam — on 401/403 it stops.
- Mounted once high in the tree (in `AppShell`, inside the authenticated area) so
  every page shares the single poller.

**Header pill (`web/src/components/JobPill.tsx`)** — rendered in `AppShell`'s
`topbar`. Visible only when `anyRunning`. Shows the active job(s): e.g.
`⟳ Enriching… 42/120` or `⟳ HIBP indexing…` (if both run, show a compact
`⟳ 2 jobs`). Click toggles a **detail popover** listing each active job: label,
phase, progress (`processed/total` or HIBP bytes/%), elapsed, error, and a
**Cancel** button where supported (enrichment → `api.enrichCancel`; HIBP →
`api.pwnedCancel`). The popover closes on outside-click / Esc.

**Overview panel (`web/src/components/Dashboard.tsx`)** — a “Background jobs” card
reading `useJobs()`: one row per integration (BloodHound enrichment, HIBP corpus)
showing current phase + last-run summary (idle/done/failed/running with progress),
each linking to its Integrations section. Always present on Overview (shows
idle/last state, not only when running).

**Migrate existing pollers (DRY).** `Ingest.tsx` and `BloodHound.tsx` currently
poll `/api/enrich/job` themselves (added in the enrichment feature). Repoint both
to `useJobs()` and delete their local `setInterval` pollers + `enrichJob` state.
The manual “Run BloodHound enrichment” button stays (calls `api.enrich`; the
provider then reflects the running job). Net: a single enrichment poller app-wide.

### Error handling
- Provider swallows transient poll errors (keep last state); stops polling on
  auth loss (401/403) and when the store locks (the pill simply stops updating;
  next successful poll resumes).
- Cancel failures surface inline in the popover; the next poll reconciles state.

### Testing
- vitest `jobs.test.tsx`: with mocked `api.pwnedJob`/`api.enrichJob`, the provider
  exposes `anyRunning` true when either runs; `false` + no polling for non-lead;
  cadence switches idle↔running (assert via fake timers + call counts).
- vitest `JobPill.test.tsx`: hidden when nothing runs; renders progress when a job
  runs; popover lists active jobs.
- Playwright: trigger enrichment → pill appears with progress → completes → pill
  hides; Overview card reflects state.

---

## Non-goals
- No backend/API changes (both features consume existing endpoints).
- No new background job types; no persistence of job history (jobs are in-memory;
  the Activity audit-log view already covers durable history).
- No change to the redaction/security model — reuse clusters use the already-
  redacted `ReuseGroup`/`ReportAccount` (no NT hash, no cleartext); reveal stays
  lead-gated + audit-logged exactly as today.
- Domains: no new charts library; reuse `Charts.tsx`.

## Rough file touch-list
- **Part 1:** `web/src/components/AccountsTable.tsx` (new, extracted),
  `web/src/components/Accounts.tsx` (use it), `web/src/domainData.ts` (new, pure),
  `web/src/components/Domains.tsx` (rewritten `DomainDetail`),
  `web/src/components/Domains.css`/`styles.css` (panels), tests
  `domainData.test.ts` + `AccountsTable.test.tsx`.
- **Part 2:** `web/src/jobs.tsx` (new provider+hook),
  `web/src/components/JobPill.tsx` (new), `web/src/components/AppShell.tsx`
  (mount provider + pill), `web/src/components/Dashboard.tsx` (Overview card),
  `web/src/components/Ingest.tsx` + `web/src/components/BloodHound.tsx` (migrate to
  `useJobs`), `web/src/styles.css` (pill/popover), tests `jobs.test.tsx` +
  `JobPill.test.tsx`. (`api.enrich*` and `api.pwnedCancel` already exist — no api.ts
  additions needed.)
- README “What's new” note.
