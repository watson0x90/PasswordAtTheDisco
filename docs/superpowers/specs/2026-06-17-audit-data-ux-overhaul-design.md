# Audit-data UX overhaul — design

- **Date:** 2026-06-17
- **Status:** Approved (brainstorm), pending implementation plan
- **Owner:** watson0x90
- **Builds on:** the v2.6.x audit-fix work (`store.Mutate` exists; this changes the enrichment cadence it introduced).

## Problem

A UI/UX panel reviewed a real operator's "create an audit with my own data" session. Findings:

1. **Data is invisible after upload (the serious one).** Three uncoordinated caches —
   `AccountsProvider` (feeds Accounts, Domains, Overview's empty-state gate),
   `Dashboard`'s own `/api/summary` fetch, and the per-page `/api/report` fetch —
   each refetch **only on audit *switch*** (`activeId` change). Uploading into the
   already-active audit doesn't change `activeId`, so those views stay
   stale/empty. Actionable works by accident (it refetches `/api/report` on
   mount). The "View results →" button is a band-aid (refreshes one cache, only on
   click). → Overview shows "0 accounts / getting started", Accounts + Domains are
   blank, while Actionable has full data.
2. **Enrichment runs too often.** `kickEnrich` fires after *every* dump upload AND
   every apply-cracks, plus a pending re-kick → 2–3+ runs for a normal sequence.
   Operator wants "once, then ad-hoc".
3. **The Upload page is overloaded + a dead end.** It does four jobs at once (load
   dump · apply cracks · ingest history · enrichment status) and, after a
   successful upload, leaves the operator on the same page with no proof the data
   landed. Enrichment status is grey `.hint` text (indistinguishable from
   file-size labels). Cracks show a blank domain (correct backend — cracks match
   by NT hash across all domains — but a meaningless cell).
4. **No per-domain visibility or deletion.** Only whole-audit delete exists; no
   view of "what's loaded per domain", no way to remove one domain's data.

## Decisions (from brainstorm)

- **Split "doing" from "managing":** Upload stays a focused action page; a new
  **Audit Data** page owns the audit's state (per-domain status, enrichment
  control, deletion, history). *(Approved visually.)*
- **Enrichment cadence:** auto-run **once** when an audit first gets data, then
  **manual** only (a "Run enrichment" button). No auto-run on later uploads/cracks.
- **Post-upload:** stay on Upload; data goes **live everywhere instantly** (no
  button, no stale screens); the ✓ confirmation links to the Audit Data page.
- **Deletion:** per-**domain** delete. (Undoing an applied crack file is a
  non-goal — re-upload corrected data or delete the audit.)

## Architecture

### 1. Data freshness — one coordinated "audit data changed" signal
Add `dataVersion: number` + `bumpData: () => void` to **`AuditsProvider`**
(`web/src/auditsData.tsx`) — the single coordination point. `bumpData` increments
the version. Every audit-scoped data fetch keys on it:
- `AccountsProvider` (`accountsData.tsx`) — fetch deps become `[activeId, dataVersion]`; its `refresh()` delegates to `bumpData()`.
- `Dashboard` summary fetch — deps include `dataVersion`.
- The `/api/report` fetch (Actionable + the lifted Domains report + the new Audit Data page) — deps include `dataVersion`.

Producers call `bumpData()` after any mutation: a successful dump upload,
apply-cracks, per-domain delete, and **enrichment completion** (the `JobsProvider`
calls `bumpData()` when `enrich.phase` transitions to `done`, so newly-enriched
DA data appears without a manual refresh). Net: the moment an upload/enrich
finishes, Overview/Accounts/Domains/Actionable are all live.

### 2. Upload page — slimmed to actions (`web/src/components/Ingest.tsx`)
Keep only **Step 1 (load dump)** and **Step 2 (apply cracks)** + the ✓ result line
("4,210 accounts loaded — **View audit data →**" / "View results →"). On success,
call `bumpData()` (data live) — no navigation. **Remove** the ingest-history panel
and the enrichment-status block from this page (they move to Audit Data).

### 3. New "Audit Data" page (`web/src/components/AuditData.tsx`)
Nav: **Setup ▾ → Audit Data** (between Upload and Policies). Lead-only. Contents:
- **Per-domain status table**, derived **client-side** from the accounts list
  (`useAccountsData`) + ingest history (`/api/ingests`) — no heavy new endpoint:
  - Domain · Accounts · Cracked · **Enriched** · Loaded-when · **🗑 delete**.
  - **Enriched** uses per-domain freshness: compare the domain's latest `dump`
    ingest time vs the audit's latest `enrich` ingest time → **✓ fresh** (enriched
    after last load), **⚠ stale** (loaded after last enrichment — needs a re-run),
    or **✗ not run**.
- **Enrichment card** (first-class) — current job status from `useJobs().enrich`
  (phase/progress/elapsed/error) + **Run enrichment** (`POST /api/enrich`) and
  **Cancel**. Disabled when BHE isn't configured (link to Integrations).
- **Ingest history** table (moved here) — When · File · Kind · Domain · Result · By.
  Cracks render **Domain = "all domains"**; a `domain_delete` event renders e.g.
  "removed CORP.LOCAL (−312)".

### 4. Per-domain delete
- New endpoint `DELETE /api/domains/{domain}` (`requireAuth + requireCSRF +
  requireUnlocked`, **lead-only**) → `store.ReplaceDomain(auditID, domain, nil)`
  (the store already filters out the domain's accounts on an empty replace and
  re-runs `RecomputeSharing`/`EscalateSharedWithDA`) → `RecordIngest` a
  `{Kind:"domain_delete", Domain:domain, AccountsLoaded:<removed count>, By}`
  event → audit-log `domain_delete`.
- Frontend: the 🗑 on each row opens a confirm ("Delete CORP.LOCAL — N accounts —
  from this audit?"), then `api.deleteDomain(domain, csrf)` → `bumpData()`.

### 5. Enrichment cadence (`internal/httpapi/server.go`, `internal/enrich/job.go`)
- **`handleAudit`:** auto-kick enrichment **only when the audit went from empty →
  has-data** with this upload (check `len(currentAccounts) == 0` *before*
  `ReplaceDomain`). Otherwise no auto-run.
- **`handleApplyCracks`:** no auto-kick (manual only).
- **Remove the pending re-kick** (`Manager.pending`/`maybeRekick`) added during the
  v2.6 fix — under "auto once then manual" it's unnecessary. **Keep `store.Mutate`**
  (the data-loss fix) — the manual re-run and the per-domain delete both rely on
  re-reading current state.
- **Enrich job records completion** as an ingest event on `PhaseDone`:
  `{Kind:"enrich", AccountsLoaded:<enriched count>, By:"system", At:done}` — this
  powers the per-domain freshness column and a history entry. (No `Domain`.)

### 6. Nav cleanup
The top-bar `AuditSwitcher` loses its delete (`×`) button — open/create only.
Whole-audit delete stays in **Admin → Manage Audits**.

## Backend surface (summary)
- New: `DELETE /api/domains/{domain}` (lead). 
- `model.IngestEvent.Kind` gains recognized values `"domain_delete"` and
  `"enrich"` (Kind is already a free string; no schema migration).
- `enrich.Manager`: drop `pending`/`maybeRekick`; the job calls `RecordIngest` on
  done (so the Manager needs the store's `RecordIngest`, which it already has via
  the store reference).
- `handleAudit`: empty-before check to gate the one-time auto-enrich.
No store schema change; no new external dependency.

## Data flow (happy path)
Create audit → Upload domain A dump → `ReplaceDomain` + (audit was empty →)
auto-enrich kicks once + `bumpData()` → Accounts/Domains/Overview live immediately;
JobPill shows enrichment; on done → enrich ingest event + `bumpData()` → DA data
appears. Operator opens **Audit Data** → sees A's row (accounts/cracked/enriched
✓), history, enrichment card. Uploads domain B → live, but B shows **⚠ stale**
(loaded after last enrich) → operator clicks **Run enrichment** → both fresh.
Wrong domain? 🗑 delete → gone + re-scored.

## Error handling
- Delete on a missing domain (already gone / audit switched) → 409, surfaced in the
  confirm dialog; the next `bumpData` reconciles.
- Enrichment with BHE unconfigured → the card shows "not configured" + a link;
  `POST /api/enrich` already 503s cleanly.
- `bumpData` after a failed mutation is not called (only on success), so a failed
  upload doesn't blank/refetch needlessly.

## Testing
- **Frontend (node-env pure helpers + tsc/build):** a pure `perDomainStatus(accounts,
  ingests)` derivation (counts + enriched-freshness) with unit tests; the freshness
  wiring + new page guarded by `tsc`/`build`/live.
- **Go:** `DELETE /api/domains/{domain}` (lead-only; removes the domain's accounts;
  records the event; 409 on unknown); `handleAudit` auto-enrich fires on
  empty→data and NOT on a second upload; apply-cracks does NOT auto-enrich; the
  enrich job records an `enrich` ingest event on done. The `store.Mutate`
  data-loss test stays green (no-data-loss now holds via `Mutate` alone — the
  removed `maybeRekick` was only about *enriching* the mid-run domain, not
  preserving it); update `TestEnrichDoesNotClobberMidRunUpload` to drop the
  re-kick wait (it still asserts both domains survive + alice stays enriched).

## Non-goals
- No undo of an applied crack file (re-upload or delete the audit).
- No new per-domain *counts* endpoint (derive client-side from accounts+ingests).
- No change to the redaction/security model — the Audit Data page shows redacted
  per-domain aggregates + the metadata-only ingest history; reveal stays lead-only
  + audit-logged on the Accounts table.
- No store schema migration.

## Rough file touch-list
- `web/src/auditsData.tsx` (dataVersion + bumpData), `web/src/accountsData.tsx`
  (key on dataVersion), `web/src/components/Dashboard.tsx` (summary keys on
  dataVersion), `web/src/components/Actionable.tsx` + `web/src/components/Domains.tsx`
  (report keys on dataVersion), `web/src/jobs.tsx` (bumpData on enrich done).
- `web/src/components/Ingest.tsx` (slim to actions + bumpData), **new**
  `web/src/components/AuditData.tsx`, `web/src/auditData.ts` (pure `perDomainStatus`
  + test), `web/src/components/AppShell.tsx` (nav entry; switcher loses delete),
  `web/src/App.tsx` (route the new view), `web/src/api.ts` (`deleteDomain`),
  `web/src/styles.css`.
- `internal/httpapi/server.go` (`DELETE /api/domains/{domain}`, auto-enrich gating,
  drop apply-cracks auto-kick), `internal/enrich/job.go` (drop pending/maybeRekick,
  record enrich event), `internal/httpapi/server_test.go`, `internal/enrich/job_test.go`.
- README "What's new" note.
