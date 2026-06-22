# Recalculate Scoring (sub-project A) — Design

> **Sub-project A of 2** in a small "data-freshness / coverage tools" effort.
> **Sub-project B** (an *unenriched-accounts* tab on the Integrations page) is specified
> separately and is independent of A.

**Goal:** Give operators a **Recalculate scoring** action that re-runs scoring over the
active audit using the *current* policy + wordlists + HIBP data — so config or data
changes actually propagate to existing accounts — **without re-fetching BloodHound**, and
then nudges the operator to re-run BloodHound enrichment to refresh the Impact side.

**Problem it solves:** Editing a password policy or the forbidden-words list updates the
config but leaves every already-scored account stale; there is no way to re-score short of
re-uploading the dump.

---

## 1. Decisions locked during brainstorming

- **Recompute scope:** recompute the **Exposure** axis (password weakness/complexity,
  current policy, current wordlists, HIBP, reuse, roastable) and re-derive **Level +
  within-audit percentile + cross-domain sharing/escalation**, while **preserving each
  account's existing BloodHound Impact** (no network). On completion, **suggest** the
  operator re-run the BloodHound **Enrich** job to refresh Impact.
- **Execution:** a **background job** with progress + a "last recalculated" stamp,
  mirroring the existing `enrich.Manager` / `pwned.Manager`.
- **Build shape:** two sub-projects; this is A.

---

## 2. Scope

**In scope (A):**
- A **stored enricher** that rebuilds an `engine.Enrichment` from an account's persisted
  fields, so re-scoring re-derives the *same* Impact without hitting BloodHound.
- Persisting `ControlsTier0` on `model.Account` (currently used in scoring but not saved),
  so the rebuild-from-stored is faithful.
- A `rescore.Manager` background job over the active audit (`Store.Mutate` +
  `Engine.RescoreWith`).
- Endpoints `POST /api/rescore`, `GET /api/rescore/job`, `POST /api/rescore/cancel`.
- UI: a **Recalculate scoring** action (+ progress + last-recalculated stamp) on the
  Overview; **nudges** on the Policies and Forbidden-words editors; a **completion
  suggestion** to re-run Enrich; `JobsProvider` integration.

**Out of scope:** the unenriched-accounts tab (B); any change to how BloodHound
enrichment itself runs; auto-recalc on every config edit (recalc stays an explicit action).

---

## 3. Architecture

### 3.1 Stored enricher (preserve Impact without network)
The engine scores an account by consulting an `engine.Enricher`:
`Enrich(username string) engine.Enrichment`, keyed via
`enrichVia(enr, username, domain) = enr.Enrich(NormalizeUsername(username, domain))`.
The existing `enrich.Manager` serves a prefetched `mapEnricher` (BHE results in memory).

A **stored enricher** builds the same `map[NormalizeUsername]engine.Enrichment` from the
**already-stored accounts** instead of a fresh prefetch. For each account:
- If `Coverage == "full"` (enriched): reconstruct the full `Enrichment` from the persisted
  fields — `DADomains` (split the stored joined string back to `[]string`),
  `ControlledObjects` (`&Controlled`), `ControlsTier0` (§3.2), `Enabled`, `HasSPN`,
  `DontReqPreauth`, `PwdNeverExpires`, `PwdLastSet`, and `Enriched: true`.
- Else (`Coverage` absent/`"none"`): return `Enrichment{Enriched: false}` — preserving the
  account's **Impact-Unknown** state.

`Engine.RescoreWith(accts, storedEnricher(accts))` then recomputes Exposure from the
current policy/wordlists/HIBP and re-derives Impact from these *same* stored inputs → Impact
is unchanged; Exposure (and Level/percentile/sharing) reflect the new config/data.

Location: the stored enricher lives in `internal/rescore` (the new package, §3.3) since it
is rescore-specific; it depends only on `engine` + `model`.

### 3.2 `ControlsTier0` persistence
`ControlsTier0` (a Tier-0 control Impact signal) currently flows enrichment → `risk.Context`
but is **not** persisted on `model.Account`, so a rebuild-from-stored would drop it. A adds
`ControlsTier0 bool` to `model.Account` (JSON `controls_tier0,omitempty`), and the engine's
`scoreCracked`/`scoreUncracked` set it from `enrData.ControlsTier0` (the same place they set
the other enrichment fields). Pre-existing audits lack it until their next Enrich — which is
exactly the re-enrich the recalc already suggests. It is redaction-safe (a boolean signal,
not a credential) and must survive `Account.Redacted()`.

### 3.3 `rescore.Manager` (background job)
A new `internal/rescore` package with a `Manager` that mirrors `internal/enrich`'s job
manager (which itself mirrors `internal/pwned`): at most one job per server,
`idle → running → done/failed/cancelled`, a processed/total account count, `StartedAt` /
`ElapsedSec`, an `Error`/`Message`, a cancel `context`, and the `ActivityHook` that holds the
idle auto-lock open during a run. `Start(auditID)` runs in a goroutine:

1. `accts, _ := store.Accounts(auditID, true)` (unredacted — needs `Password`/`NTHash`).
2. `rescored := eng.RescoreWith(accts, storedEnricher(accts))`.
3. `store.Mutate(auditID, func(_) []model.Account { return rescored })` — `Mutate` already
   re-runs `RecomputeSharing` → `EscalateSharedWithDA` → `ComputePercentiles` and bumps
   `UpdatedAt`.
4. Log an `IngestEvent{Kind: "rescore", ...}` (metadata only) so the UI can show a "last
   recalculated" stamp, same as enrich's `"enrich"` event.

Progress is coarse (running → done with a final count); fine-grained per-item progress isn't
needed since there's no network latency. Wired in `cmd/patd/main.go` next to `enrichMgr`,
exposed on `httpapi.Server` as `Rescore *rescore.Manager` (may be nil).

### 3.4 Endpoints (mirror `/api/enrich`)
| Method & path | Auth | Behaviour |
|---|---|---|
| `POST /api/rescore` | `requireAuth` + `requireCSRF` + `requireUnlocked`, **lead** | start the job for the session's active audit; 409 if one is already running; audited. |
| `GET /api/rescore/job` | `requireAuth` | the `JobStatus` snapshot the UI polls. |
| `POST /api/rescore/cancel` | `requireAuth` + `requireCSRF`, **lead** | cancel a running job. |

---

## 4. UI

- **Recalculate scoring action** on the **Overview** (lead-only), near the "Data scored …"
  line: a button that `POST`s `/api/rescore`, a progress state while running, and a
  **"Last recalculated …"** stamp from the `rescore` `IngestEvent`. Disabled with a clear
  note when no audit is active or the store is locked.
- **`JobsProvider`** (the existing lead-only background-job poller) gains the rescore job
  alongside enrich/pwned, so progress is reflected app-wide.
- **Editor nudges:** after a successful save on **Policies** and **Forbidden-words**, show
  "Saved — *recalculate scoring* to apply this to existing accounts," with a button that
  starts the job. (Editing config no longer silently leaves stale scores.)
- **Completion suggestion:** when a rescore finishes, surface "Recalculated N accounts —
  BloodHound Impact was preserved; *re-run Enrichment* to refresh it," linking to the
  Integrations Enrich action. This is the requested "suggest re-enrich."

---

## 5. Observability, errors, security

- **Audit:** `POST /api/rescore` logs a `rescore_start` audit event (actor, audit id);
  the job logs an `IngestEvent{Kind:"rescore"}` on success (account count, time — never any
  credential). Cancel logs `rescore_cancel`.
- **Errors:** 409 if a job is already running; 423/locked and "no active audit" surfaced
  cleanly (mirroring enrich). A job failure sets `phase=failed` + an `Error` message.
- **Security:** start/cancel are **lead-only** (re-scoring rewrites the audit, like
  enrich/upload). Recompute reads unredacted accounts in-process only; nothing new leaves
  the process. No cleartext or NT hash in any event.

---

## 6. Testing

- **Stored enricher** (`internal/rescore`): for an enriched account it reconstructs the
  Enrichment (DA/controlled/tier0/roastable/coverage) so `RescoreWith` yields the **same**
  `ImpactScore`/`ImpactKnown`; for a `Coverage:"none"` account it returns Impact-Unknown.
- **Recompute behavior** (engine/store): with a stored enricher, changing the policy (e.g.
  min-length) or the forbidden-words list **shifts Exposure + Level** for affected accounts
  while **Impact is unchanged**; percentile + cross-domain sharing re-run via `Mutate`.
- **`ControlsTier0`** round-trips through the store and survives `Redacted()`; the stored
  enricher reads it back.
- **Manager:** one-job-at-a-time (second `Start` errors), cancel transitions to cancelled,
  `done` carries the count, a `rescore` `IngestEvent` is logged.
- **Handlers:** lead-gating + CSRF on start/cancel; `GET /job` lifecycle; 409 when running.
- **Web:** pure-logic tests for the editor-nudge + completion-suggestion state; Playwright
  live — edit a forbidden word, click Recalculate, watch progress → done, confirm a changed
  score and the "re-run Enrichment" suggestion; assert the console is clean.
- All gates stay green (`gofmt`, `go build/vet/test`, `govulncheck`; `tsc`, `vitest`, web build).

---

## 7. Definition of done (A)

A lead edits a policy or the forbidden-words list, is nudged to recalculate, clicks
**Recalculate scoring**, watches a background job run to completion (with a "last
recalculated" stamp), sees affected accounts' **Exposure/Level change while BloodHound
Impact is unchanged**, and is then prompted to re-run Enrichment — all lead-gated, audited,
and with the gates green. **B** (the unenriched-accounts tab) is built next.
