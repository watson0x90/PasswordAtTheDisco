# Decoupled BloodHound enrichment — design

- **Date:** 2026-06-16
- **Status:** Approved (brainstorm), pending implementation plan
- **Owner:** watson0x90
- **Branch:** `feature/upload-ux` (folded in before merge)

## Problem

A large dump upload appears to **hang** in the UI with no sign anything is
happening. The server log is conclusive:

```
2026/06/16 21:18:22  POST /api/upload  32m22.916s
```

The request did not fail — the server spent **32 minutes** scoring while the UI
sat on "Processing on server…". Root cause is in the scoring engine, not the
upload plumbing: for **every account**, `Engine.ProcessDomain` →
`BloodhoundEnricher.Enrich` → `Client.GetUserData()` fires **four sequential
HTTP calls** to BloodHound (`GetDomains` + `GetUser` + `GetUserControllables` +
`GetUserFull`), and `GetDomains()` is re-fetched for every account. No caching,
no concurrency. A real AD dump (where many accounts share a hash, or a cracked
file) triggers `~4 × N` blocking round-trips → tens of minutes.

A second, smaller bug surfaced while reproducing: when the store is locked
(e.g. auto-locked after idle) an upload of a large body returns 423 on an
**unread** multipart body, so Go resets the TCP connection instead of delivering
the 423. The browser sees `ERR_CONNECTION_RESET` ("network error"), not a
readable "session locked".

## Decisions (from brainstorm)

- **Decouple upload from enrichment.** Upload streams → parses → **HIBP-scores**
  → stores, and returns in seconds. BloodHound enrichment (the network-heavy
  part) becomes a **separate background job**.
- **Auto-start + manual re-run.** Upload auto-kicks the enrichment job; a menu
  action re-runs it on demand (after BHE data changes, or after applying cracks).
- **Concurrency:** bounded worker pool, **default 8, configurable**; conservative
  so it does not overwhelm the lab BHE.
- **HIBP stays inline** in the upload (local disk lookup, fast, not the
  bottleneck) — accounts are fully risk-scored immediately after upload; only the
  DA-pathway/privilege enrichment fills in when the job completes.
- **Atomic persistence:** the job re-scores and writes once at the end (same as
  apply-cracks), so accounts flip to enriched all at once; cancel discards.
- **Fold in the locked/large-upload fix.**
- **Scale:** dumps "vary widely" — design must handle the worst case (hundreds of
  thousands of accounts) gracefully, never assuming small input.

## Architecture: prefetch-then-rescore

The slow network work is isolated into one explicit, observable, cancelable,
**concurrent prefetch** phase. The scoring engine itself never makes a network
call — it reads a prefetched in-memory map, exactly how the engine tests already
inject a `fakeEnricher`.

```
Upload (sync, seconds)            Enrichment job (async, observable)
──────────────────────           ─────────────────────────────────
stream → parse → HIBP score       load audit accounts
  → store (no BHE)                  → prefetch BHE concurrently (≈8 workers,
returns 200 immediately               GetDomains once, memoized per username)
  │                                 → build map[normalizedUser]Enrichment
  └── auto-kick enrichment job ───▶ → RescoreWith(accounts, mapEnricher)
                                    → Replace (one encrypted write)
                                   status polled by UI throughout; cancel = discard
```

Why this shape: all slowness lives in one phase; `GetDomains` is fetched once;
the engine hot loop stays synchronous/deterministic/fast; persistence is atomic
(clean cancel, no partial state); reuses the existing `Enricher` interface.

*Rejected alternative — incremental batch persistence* (accounts "light up"
progressively): many encrypted-store writes, partial states, messy
cancel/rollback. The progress bar already conveys the work; not worth the churn.

## Components

### 1. `internal/bloodhound` — cache domains
`GetUserData` fetches the collected-domains list once per job instead of per
account. Add a small **TTL cache** for `GetDomains()` on `*Client` (e.g. 60s):
the first call hits BHE, subsequent calls within the window return the cached
slice. This removes ~25% of all calls (the most wasteful, identical-every-time
one) and is safe for hot-swap. The per-user calls (`GetUser`,
`GetUserControllables`, `GetUserFull`) remain — they are inherently per-user and
are handled by concurrency.

### 2. `internal/engine` — score with an explicit enricher
Today `ProcessDomain`/`Rescore` read `e.Enricher` implicitly. Make the enricher
**explicit per call** so upload can score without BHE and the job can score with
a prefetched map:

- Add `Engine.RescoreWith(accts []model.Account, enr Enricher) []model.Account`
  — like `Rescore` but uses the passed enricher (nil = no enrichment).
- Upload scores with **no enricher** (base + HIBP only).
- The existing implicit-`e.Enricher` path is preserved for the CLI ingest route
  (unchanged) — or routed through the explicit form; the plan will pick the
  least-invasive seam. The hot loop and scoring math do not change.

`normalizeUsername(username, domain)` keying is unchanged: the job's prefetch
normalizes the same way, so the map enricher keys line up with what the engine
looks up (identical to the `fakeEnricher` tests).

### 3. `internal/enrich` — the job manager
New package mirroring `internal/pwned/job.go` (`Manager` + `JobStatus`):

- `Start(auditID string) error` — refuses if a job is already running; launches a
  goroutine.
- `Status() JobStatus` — phase, counts, elapsed, error; polled by the UI.
- `Cancel() error` — cooperative cancel via context; in-flight workers stop, the
  result is discarded (no `Replace`).

Goroutine flow: load the audit's accounts → concurrent prefetch (bounded pool,
default 8) building `map[normalizedUser]Enrichment`, **memoized** so a repeated
username is fetched once → `engine.RescoreWith(accts, mapEnricher)` →
`store.Replace(auditID, …)`. Per-user BHE errors degrade to empty enrichment for
that user (job continues); a total BHE outage (e.g. `GetDomains` fails) fails the
job cleanly with an error message — **accounts keep their base/HIBP scores**
either way (the upload already persisted them).

The job holds the server's auto-lock open while running (see §Error handling).

#### `JobStatus` JSON (mirrors `pwned.JobStatus`)
```json
{
  "phase": "idle|running|done|failed|cancelled",
  "audit_id": "…",
  "processed": 0,
  "total": 0,
  "started_at": "RFC3339",
  "elapsed_sec": 0,
  "enriched": 0,
  "errors": 0,
  "error": ""
}
```

### 4. `internal/httpapi` — endpoints + auto-start
- `POST /api/enrich` — start enrichment for the **active** audit
  (requireAuth + requireCSRF + requireUnlocked, **lead-only**). 409 if a job is
  already running.
- `GET  /api/enrich/job` — poll `Status()` (requireAuth, lead-only). Returns
  `{phase:"idle"}` when nothing has run.
- `POST /api/enrich/cancel` — cooperative cancel (requireAuth + requireCSRF,
  lead-only).
- **Auto-start:** at the end of `handleAudit` (after `RecordIngest`), kick the
  job for that audit, non-blocking. **Apply-cracks behaves the same way** — it
  re-scores **without** inline BHE (otherwise a large cracked file reintroduces
  the identical hang) and then auto-kicks the enrichment job, so newly-cracked
  accounts get DA-pathway scoring.
- Audit-log start/cancel (action `enrich_start` / `enrich_cancel`), no secrets.

### 5. Web UI
- **Upload page (`Ingest.tsx`):** after a dump upload, show the auto-started
  enrichment job's progress (poll `GET /api/enrich/job`) as a third state below
  the existing two-phase bar — "Enriching with BloodHound… N/total". Accounts are
  already viewable (HIBP-scored) via "View results →".
- **Integrations → BloodHound page:** a **"Run BloodHound enrichment on this
  audit"** button (the manual re-trigger) + the same job-progress/cancel display.
  Disabled when BHE is not configured/connected or no active audit.
- **api.ts:** `enrich()`, `enrichJob()`, `enrichCancel()` + an `EnrichJob` type
  mirroring `JobStatus`.

### Locked / large-upload UX fix
- The UI already knows lock state (`me.store_unlocked`). **Gate the upload
  controls** on unlocked state and show "Session locked — unlock and retry"
  instead of letting a large POST die as `ERR_CONNECTION_RESET`.
- Defensive server side: the upload handlers already run behind
  `requireUnlocked`; document that a locked upload may reset the connection and
  rely on the client gate to prevent it. (No attempt to buffer/drain a 512 MiB
  body server-side.)

## Data flow & concurrency

- Prefetch pool size from the BloodHound config (`config/bloodhound.json` →
  `enrich_concurrency`), default **8**, clamped to a sane range (1–32). It lives
  with the other BHE settings since it governs load on the BHE API.
- Memoization: a `sync.Map` (or guarded map) of normalized-username → result;
  duplicate usernames across the dump are fetched once.
- Progress: workers increment `processed` atomically; `Status()` reads a
  consistent snapshot. `total` = distinct usernames to enrich.
- Cancellation: a `context.Context` cancel; workers check between calls; the job
  ends in `cancelled` without persisting.

## Error handling

- **BHE unreachable / `GetDomains` fails:** job → `failed` with a readable error;
  accounts retain base+HIBP scores. UI shows the error and offers re-run.
- **Per-user BHE error/timeout:** that user gets empty enrichment; `errors++`;
  job continues and still persists. Surfaced as "enriched X, Y errors".
- **Cancel:** no `Replace`; phase `cancelled`.
- **Auto-lock interplay:** the running job increments the server `inFlight`
  counter (and touches `lastActivity`) so the idle auto-lock cannot fire mid-job
  — `shouldAutoLock` only locks when `inFlight == 0`. The job releases on
  completion/cancel/failure (defer, panic-safe).
- **Store swapped/deleted mid-job:** `Replace` returns "audit no longer exists";
  job → `failed`, no crash.
- **Double-start:** `POST /api/enrich` 409 while a job runs; `Start` is guarded.

## Testing

- **engine:** `RescoreWith` uses the passed enricher (map vs nil); upload-style
  scoring with nil enricher leaves DA fields empty but HIBP populated; existing
  `ProcessDomain` tests stay green.
- **bloodhound:** `GetDomains` TTL cache returns cached value within the window
  and refetches after expiry (httptest server counting requests); `GetUserData`
  makes **one** domains call across N user lookups.
- **enrich (job):** with a fake enricher + in-memory store — `Start` runs to
  `done`, `processed==total`, accounts gain enrichment after the job; memoization
  fetches a duplicate username once (call counter); per-user error degrades to
  empty + `errors++` + still persists; `Cancel` ends `cancelled` without
  persisting; double-`Start` errors.
- **httpapi:** `POST /api/enrich` lead-only (analyst 403), 409 when running;
  `GET /api/enrich/job` shape; auto-start fires after `handleAudit`; the job
  keeps the store from auto-locking (extend the existing auto-lock test).
- **web:** vitest for the `enrich*` api wrappers (mock fetch) + the Upload-page
  enrichment-progress polling; the upload control is disabled when locked.
  Playwright: upload → auto-started enrichment progress → accounts enriched;
  manual re-run from the BloodHound page.

## Non-goals

- No incremental/streaming persistence of partial enrichment.
- No resumable/checkpointed enrichment across restarts (a job is in-memory; a
  restart mid-job just means re-running it).
- No change to the HIBP index/lookup mechanism (it stays inline; optimizing the
  disk-seek path is out of scope).
- No change to the redaction/security model; `JobStatus` is metadata only (no
  passwords/hashes).
- No multi-audit concurrent enrichment — one job at a time (per server), matching
  the HIBP downloader.

## Rough file touch-list

- `internal/bloodhound/bloodhound.go` (+`_test.go`) — `GetDomains` TTL cache.
- `internal/engine/engine.go` (+`_test.go`) — `RescoreWith`, explicit enricher.
- `internal/enrich/job.go` (+`_test.go`) — new job manager (mirror `pwned`).
- `internal/httpapi/server.go` (+`_test.go`) — 3 endpoints, auto-start in
  `handleAudit`, `inFlight` during the job, audit logging.
- `cmd/patd/main.go` — wire the enrich manager; `enrich_concurrency` config.
- `web/src/api.ts` — `enrich`/`enrichJob`/`enrichCancel` + `EnrichJob` type.
- `web/src/components/Ingest.tsx` — enrichment-progress state + locked gate.
- `web/src/components/Integrations.tsx` (BloodHound section) — re-run button +
  progress.
- `README.md` — "What's new" note.
