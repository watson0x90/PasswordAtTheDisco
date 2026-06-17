# Audit-Data UX Overhaul — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make uploaded data appear instantly everywhere, split Upload (actions) from a new Audit Data page (state), add per-domain delete, and make enrichment run once-then-manual.

**Architecture:** A single `dataVersion` nonce in `AuditsProvider` that all audit-scoped fetches key on (accounts/summary/report) and all mutations bump — fixing the blank-screen bug. Upload slims to two forms; a new `AuditData` page owns per-domain status (derived client-side), enrichment control, deletion, and history. Backend adds `DELETE /api/domains/{domain}`, gates auto-enrich to the first-data moment, and records an `enrich` ingest event on completion.

**Tech Stack:** Go 1.26 stdlib, React/TS (vitest node-env — pure-helper tests only; NO jsdom/testing-library). No new deps.

**Branch:** `feature/audit-data-ux` (off main, which has `store.Mutate`).
**Spec:** `docs/superpowers/specs/2026-06-17-audit-data-ux-overhaul-design.md`
**Gates:** `gofmt -l cmd internal && go build ./... && go vet ./... && go test ./...`; `cd web && npx tsc --noEmit && npm run build && npx vitest run`; `govulncheck ./...`.

---

## Task 1: `DELETE /api/domains/{domain}` (per-domain delete)

**Files:** Modify `internal/httpapi/server.go`, `web/src/api.ts`; Test `internal/httpapi/server_test.go`.

The store already supports the delete: `ReplaceDomain(auditID, domain, nil)` filters out that domain's accounts, re-runs sharing/escalation, persists. This task adds the HTTP handler + records a `domain_delete` ingest event + the TS client method.

- [ ] **Step 1: Write the failing Go test** in `internal/httpapi/server_test.go` (mirror the existing enrich/upload test harness — build a `Server`, seed a store with two domains, a lead session):
```go
func TestDeleteDomain(t *testing.T) {
	srv := newUnlockedLeadServer(t) // adapt: the helper/pattern used by TestUploadStreamsAndRecordsIngest
	id := srv.activeAuditID(t)       // the seeded active audit
	mustReplaceDomain(t, srv, id, "A", 3) // seed 3 accounts in domain A
	mustReplaceDomain(t, srv, id, "B", 2) // seed 2 in domain B

	// analyst -> 403
	if code, _ := srv.do(t, "DELETE", "/api/domains/A", analystSession, nil); code != http.StatusForbidden {
		t.Fatalf("analyst DELETE = %d, want 403", code)
	}
	// lead deletes domain A
	code, _ := srv.do(t, "DELETE", "/api/domains/A", leadSession, nil)
	if code != http.StatusOK {
		t.Fatalf("lead DELETE = %d, want 200", code)
	}
	accts, _ := srv.Store.Accounts(id, false)
	for _, a := range accts {
		if a.Domain == "A" {
			t.Fatal("domain A accounts still present after delete")
		}
	}
	if len(accts) != 2 {
		t.Fatalf("after delete: %d accounts, want 2 (domain B kept)", len(accts))
	}
	// a domain_delete ingest event was recorded
	ev, _ := srv.Store.Ingests(id)
	found := false
	for _, e := range ev {
		if e.Kind == "domain_delete" && e.Domain == "A" {
			found = true
		}
	}
	if !found {
		t.Fatal("no domain_delete ingest event recorded")
	}
}
```
If the test file has no `newUnlockedLeadServer`/`do`/`mustReplaceDomain` helpers, follow the EXACT scaffolding the existing tests use (e.g. `TestUploadStreamsAndRecordsIngest`, `TestEnrichEndpoints`) — build the server, seed via `srv.Store.ReplaceDomain`, set sessions, and invoke the handler through `httptest`. Reuse that pattern; do not invent new infra.

- [ ] **Step 2: Run, expect FAIL:** `go test ./internal/httpapi/ -run TestDeleteDomain` (route/handler undefined).

- [ ] **Step 3: Register the route** next to the upload routes in `server.go`:
```go
	mux.Handle("DELETE /api/domains/{domain}", s.requireAuth(s.requireCSRF(s.requireUnlocked(http.HandlerFunc(s.handleDeleteDomain)))))
```

- [ ] **Step 4: Implement the handler** (lead-only; mirror `handleApplyCracks`'s session/active-audit pattern):
```go
// handleDeleteDomain removes one domain's accounts from the active audit (lead only).
func (s *Server) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	domain := r.PathValue("domain")
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain is required"})
		return
	}
	auditID, ok := s.activeAudit(w, sess)
	if !ok {
		return
	}
	before, err := s.Store.Accounts(auditID, false)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "selected audit no longer exists"})
		return
	}
	removed := 0
	for _, a := range before {
		if a.Domain == domain {
			removed++
		}
	}
	if removed == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no accounts for domain " + domain})
		return
	}
	if err := s.Store.ReplaceDomain(auditID, domain, nil); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "selected audit no longer exists"})
		return
	}
	if err := s.Store.RecordIngest(auditID, model.IngestEvent{
		Filename: domain, Kind: "domain_delete", Domain: domain,
		AccountsLoaded: removed, At: time.Now().UTC(), By: sess.Username,
	}); err != nil {
		log.Printf("record domain_delete ingest (%s): %v", domain, err)
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "domain_delete", Target: domain, Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]int{"removed": removed})
}
```

- [ ] **Step 5: Add the TS client** in `web/src/api.ts`:
```ts
  deleteDomain: (domain: string, csrf: string) =>
    request<{ removed: number }>(`/domains/${encodeURIComponent(domain)}`, {
      method: "DELETE",
      headers: { "X-CSRF-Token": csrf },
    }),
```
Also extend the `IngestEvent.kind` union (in api.ts) to `"dump" | "cracks" | "domain_delete" | "enrich"`.

- [ ] **Step 6: Run, expect PASS:** `go test ./internal/httpapi/ -run TestDeleteDomain -v`, then `go test ./internal/httpapi/ -count=1`, `gofmt -l internal/httpapi`, `cd web && npx tsc --noEmit`.

- [ ] **Step 7: Commit:**
```bash
git add internal/httpapi/server.go internal/httpapi/server_test.go web/src/api.ts
git commit -m "feat(api): DELETE /api/domains/{domain} (per-domain delete + ingest event)"
```

---

## Task 2: Enrichment cadence — auto-once-on-first-data, drop re-kick, record completion

**Files:** Modify `internal/httpapi/server.go`, `internal/enrich/job.go`; Test `internal/httpapi/server_test.go`, `internal/enrich/job_test.go`.

- [ ] **Step 1: Write the failing test** (auto-enrich fires on empty→data, NOT on a second upload) in `server_test.go`. Use a test enricher + `enrich.Manager`. Assert that uploading to an EMPTY audit starts enrichment, and a SECOND upload does not start a new run (the manager only ran once). Adapt to the harness:
```go
func TestAutoEnrichOnlyOnFirstData(t *testing.T) {
	srv := newUnlockedLeadServer(t)
	srv.Engine.SwapEnricher(fakeTestEnricher{}) // existing fake from TestEnrichEndpoints
	srv.Enrich = enrich.NewManager(srv.Engine, srv.Store)
	id := srv.activeAuditID(t)

	// 1st upload into the empty audit -> auto-enrich starts
	srv.uploadDump(t, leadSession, "A", 2) // helper that POSTs a domain dump (adapt to harness)
	srv.Enrich.Wait()
	if srv.Enrich.Status().Phase == enrich.PhaseIdle {
		t.Fatal("expected auto-enrich after first data load")
	}
	runs1 := srv.Enrich.Status() // capture started_at
	// 2nd upload (audit already has data) -> must NOT auto-start a new run
	srv.uploadDump(t, leadSession, "B", 2)
	srv.Enrich.Wait()
	if srv.Enrich.Status().StartedAt != runs1.StartedAt {
		t.Fatal("second upload should NOT auto-start enrichment")
	}
}
```
(If a precise "did it run again" assertion is awkward, instead assert behaviorally: count enricher invocations via the fake — first upload triggers lookups, second upload triggers none beyond the first run. Use whichever the harness makes clean.)

- [ ] **Step 2: Run, expect FAIL** (current code auto-kicks on every upload).

- [ ] **Step 3: Gate the auto-enrich in `handleAudit`.** Find where `handleAudit` computes `accts := s.Engine.ProcessDomainNoEnrich(...)` then `ReplaceDomain` then `RecordIngest` then `s.kickEnrich(auditID)`. Replace the unconditional `kickEnrich` with an empty-before check:
```go
	// Auto-enrich ONCE, only when this upload is the first data in the audit.
	wasEmpty := true
	if existing, err := s.Store.Accounts(auditID, false); err == nil && len(existing) > 0 {
		wasEmpty = false
	}
```
Place this BEFORE `s.Store.ReplaceDomain(...)`. Then after `RecordIngest`, replace `s.kickEnrich(auditID)` with:
```go
	if wasEmpty {
		s.kickEnrich(auditID)
	}
```

- [ ] **Step 4: Remove the apply-cracks auto-kick.** In `handleApplyCracks`, delete the `s.kickEnrich(auditID)` line (cracks no longer auto-enrich; the Audit Data page's manual button covers it).

- [ ] **Step 5: Drop the pending re-kick** in `internal/enrich/job.go`: remove the `pending bool` field, the `maybeRekick` method, the `m.maybeRekick(id)` call in `run`, and the `m.pending = true`/`m.pending = false` lines in `Start` (Start reverts to: error if running, else proceed). Keep everything else (`store.Mutate`, the concurrency, etc.).

- [ ] **Step 6: Record an `enrich` ingest event on completion.** In `run`, on the success path (after the `store.Mutate` succeeds, before/at `m.finish(PhaseDone, "")`), record an event:
```go
	_ = m.store.RecordIngest(id, model.IngestEvent{
		Kind: "enrich", AccountsLoaded: m.enriched, At: time.Now().UTC(), By: "system",
	})
	m.finish(PhaseDone, "")
```
(`m.enriched` is the count of accounts that got BHE data — already tracked. Add `"time"` and the `model` import if needed; `model` is already imported.)

- [ ] **Step 7: Update `TestEnrichDoesNotClobberMidRunUpload`** in `job_test.go` — remove the re-kick polling loop + the second `m.Wait()`; keep the single `m.Wait()` after `close(gate)`. The assertions (both domains survive, alice stays enriched) still pass via `store.Mutate` alone. Also confirm `TestEnrichJobDoubleStart` still passes (Start still errors while running).

- [ ] **Step 8: Run, expect PASS:** `go test ./internal/enrich/ ./internal/httpapi/ -count=1`, `gofmt -l internal/enrich internal/httpapi`, `go vet ./...`, `go build ./...`.

- [ ] **Step 9: Commit:**
```bash
git add internal/httpapi/server.go internal/enrich/job.go internal/httpapi/server_test.go internal/enrich/job_test.go
git commit -m "feat(enrich): auto-run once on first data only; manual thereafter; record enrich completion event"
```

---

## Task 3: Data freshness — `dataVersion` nonce so all views go live after a mutation

**Files:** Modify `web/src/auditsData.tsx`, `web/src/accountsData.tsx`, `web/src/components/Dashboard.tsx`, `web/src/components/Actionable.tsx`, `web/src/components/Domains.tsx`, `web/src/jobs.tsx`.

(React wiring — guarded by tsc/build; no render test.)

- [ ] **Step 1: Add `dataVersion` + `bumpData` to `AuditsProvider`** (`auditsData.tsx`):
  - Add to the `AuditsState` interface: `dataVersion: number` and `bumpData: () => void`.
  - In the provider: `const [dataVersion, setDataVersion] = useState(0)` and `const bumpData = useCallback(() => setDataVersion((v) => v + 1), [])`.
  - Add both to the context value object.
  - Bump on audit switch too so a fresh audit starts clean: not required (activeId already drives that), so leave as-is.

- [ ] **Step 2: Key `AccountsProvider` on `dataVersion`** (`accountsData.tsx`): replace its internal `nonce`/`refresh` with the shared signal. Import `useAudits`; read `dataVersion`. Change the fetch `useEffect` deps from `[activeId, nonce]` to `[activeId, dataVersion]`. Keep the exported `refresh` on the context but implement it as `bumpData` (so existing callers of `useAccountsData().refresh()` still work): `const { activeId, dataVersion, bumpData } = useAudits()` and `refresh: bumpData` in the value. Remove the local `nonce` state.

- [ ] **Step 3: Key the Dashboard summary on `dataVersion`** (`Dashboard.tsx`): the summary `useEffect` currently deps `[activeId]`. Add `dataVersion`: pull `const { activeId, dataVersion } = useAudits()` (it already calls `useAudits()`), and change the deps to `[activeId, dataVersion]`. (The "getting started" gate reads `accounts` from `useAccountsData`, which now refreshes via dataVersion — so it clears once data exists.)

- [ ] **Step 4: Key Actionable + Domains report fetches on `dataVersion`** — in `Actionable.tsx` and `Domains.tsx`, the `api.report()` `useEffect` deps include `activeId`; add `dataVersion` from `useAudits()` so the report refetches after a mutation. (Domains lifted its report fetch to the `Domains()` parent in a prior task — add `dataVersion` to that effect's deps.)

- [ ] **Step 5: Bump on enrichment completion** (`jobs.tsx`): the `JobsProvider` should bump data when enrichment finishes so DA-enriched accounts refresh. Add (inside the provider): track the previous enrich phase and call `bumpData()` on the transition into `"done"`:
```tsx
  const { bumpData } = useAudits()
  const prevEnrich = useRef<string | undefined>(undefined)
  useEffect(() => {
    if (prevEnrich.current === "running" && enrich?.phase === "done") bumpData()
    prevEnrich.current = enrich?.phase
  }, [enrich?.phase, bumpData])
```
Import `useAudits` from `./auditsData` and `useRef`. (JobsProvider is mounted inside AuditsProvider in App.tsx, so `useAudits()` works.)

- [ ] **Step 6: Verify:** `cd web && npx tsc --noEmit && npm run build && npx vitest run`. tsc clean (no orphaned `nonce`), build OK, tests pass.

- [ ] **Step 7: Commit:**
```bash
git add web/src/auditsData.tsx web/src/accountsData.tsx web/src/components/Dashboard.tsx web/src/components/Actionable.tsx web/src/components/Domains.tsx web/src/jobs.tsx
git commit -m "fix(web): shared dataVersion so uploads/enrichment make all views live (no stale blanks)"
```

---

## Task 4: Slim the Upload page

**Files:** Modify `web/src/components/Ingest.tsx`.

- [ ] **Step 1: Remove the moved sections + refresh on success.** Read `Ingest.tsx`. Then:
  - Delete the **ingest-history panel** (the "This audit — ingest history" section + its table + the `history`/`loadHistory` state/effect + the `api.ingests()` usage).
  - Delete the **enrichment status block** (`{enrichJob && enrichJob.phase !== "idle" && (...)}`) and the `const { enrich: enrichJob } = useJobs()` line (no longer used here).
  - In `onSubmit` and `onApply` success paths, replace `void loadHistory()` with `bumpData()` from `useAudits()` (so data goes live). Add `const { bumpData } = useAudits()` (and import `useAudits`); remove now-unused imports (`useJobs`, `IngestEvent`, `api.ingests`, etc. — tsc will flag).
  - Update the ✓ result line for the dump: change the "View results →" button to ALSO offer the Audit Data page — keep "View results →" (nav to overview) and add a secondary link/button "View audit data →" (nav to the new `audit-data` view; the view id is added in Task 5/6). For now wire it to `nav("audit-data")`.

- [ ] **Step 2: Verify:** `cd web && npx tsc --noEmit && npm run build && npx vitest run`. (The `audit-data` View type is added in Task 6; if tsc complains that `"audit-data"` isn't a valid View yet, either do Task 6's View-type addition first or temporarily nav to `"overview"` and switch in Task 6. Prefer: add the `audit-data` View id to AppShell's `View` union now as a tiny forward-declare so this compiles.)

- [ ] **Step 3: Commit:**
```bash
git add web/src/components/Ingest.tsx
git commit -m "feat(web): slim Upload to the two action forms; data goes live on success"
```

---

## Task 5: New Audit Data page + pure per-domain derivation

**Files:** Create `web/src/auditData.ts`, `web/src/components/AuditData.tsx`; Test `web/src/auditData.test.ts`; Modify `web/src/styles.css`.

- [ ] **Step 1: Write the failing test** `web/src/auditData.test.ts` for the pure derivation:
```ts
import { describe, it, expect } from "vitest"
import { perDomainStatus } from "./auditData"
import type { Account, IngestEvent } from "./api"

const acct = (o: Partial<Account>): Account => ({
  username: "u", domain: "A", cracked: false, password_length: 0, risk_level: "Low",
  risk_score: 0, risk_vector: "", hibp_breached: false, hibp_breach_count: 0,
  da_domains: "None", controlled_object_count: 0, shared_with: 0, enabled: true,
  meets_policy: true, complexity: "", ...o,
})
const ev = (o: Partial<IngestEvent>): IngestEvent => ({ filename: "f", kind: "dump", at: "2026-06-17T00:00:00Z", by: "x", ...o })

describe("perDomainStatus", () => {
  it("counts accounts + cracked per domain", () => {
    const rows = perDomainStatus(
      [acct({ domain: "A", cracked: true }), acct({ domain: "A" }), acct({ domain: "B", cracked: true })],
      [ev({ kind: "dump", domain: "A", at: "2026-06-17T01:00:00Z" }), ev({ kind: "dump", domain: "B", at: "2026-06-17T02:00:00Z" })],
    )
    const a = rows.find((r) => r.domain === "A")!
    expect(a.accounts).toBe(2)
    expect(a.cracked).toBe(1)
  })
  it("enrichment freshness: none / fresh / stale", () => {
    const accts = [acct({ domain: "A" }), acct({ domain: "B" })]
    // no enrich event -> none
    expect(perDomainStatus(accts, [ev({ kind: "dump", domain: "A", at: "2026-06-17T01:00:00Z" })]).find((r) => r.domain === "A")!.enriched).toBe("none")
    // enrich AFTER load -> fresh; load AFTER enrich -> stale
    const evs: IngestEvent[] = [
      ev({ kind: "dump", domain: "A", at: "2026-06-17T01:00:00Z" }),
      ev({ kind: "enrich", at: "2026-06-17T03:00:00Z" }),
      ev({ kind: "dump", domain: "B", at: "2026-06-17T05:00:00Z" }), // loaded after enrich
    ]
    const rows = perDomainStatus(accts, evs)
    expect(rows.find((r) => r.domain === "A")!.enriched).toBe("fresh")
    expect(rows.find((r) => r.domain === "B")!.enriched).toBe("stale")
  })
})
```

- [ ] **Step 2: Run, expect FAIL** (module not found).

- [ ] **Step 3: Implement `web/src/auditData.ts`:**
```ts
import type { Account, IngestEvent } from "./api"

export interface DomainRow {
  domain: string
  accounts: number
  cracked: number
  enriched: "fresh" | "stale" | "none"
  loadedAt?: string
}

// perDomainStatus derives the Audit Data table rows from the live accounts list
// + the ingest history. Enrichment freshness compares each domain's latest dump
// load time against the audit's latest enrichment time.
export function perDomainStatus(accounts: Account[], ingests: IngestEvent[]): DomainRow[] {
  const lastEnrich = ingests
    .filter((e) => e.kind === "enrich")
    .map((e) => e.at)
    .sort()
    .pop()
  const loadedAt = new Map<string, string>()
  for (const e of ingests) {
    if (e.kind === "dump" && e.domain) {
      const prev = loadedAt.get(e.domain)
      if (!prev || e.at > prev) loadedAt.set(e.domain, e.at)
    }
  }
  const byDomain = new Map<string, DomainRow>()
  for (const a of accounts) {
    let row = byDomain.get(a.domain)
    if (!row) {
      row = { domain: a.domain, accounts: 0, cracked: 0, enriched: "none", loadedAt: loadedAt.get(a.domain) }
      byDomain.set(a.domain, row)
    }
    row.accounts++
    if (a.cracked) row.cracked++
  }
  for (const row of byDomain.values()) {
    if (!lastEnrich) row.enriched = "none"
    else if (row.loadedAt && row.loadedAt > lastEnrich) row.enriched = "stale"
    else row.enriched = "fresh"
  }
  return [...byDomain.values()].sort((a, b) => b.accounts - a.accounts)
}
```

- [ ] **Step 4: Run, expect PASS:** `cd web && npx vitest run auditData.test.ts && npx tsc --noEmit`.

- [ ] **Step 5: Build `web/src/components/AuditData.tsx`.** A lead-only page using `useAccountsData()` (accounts), `api.ingests()` (history, fetched on mount + `dataVersion`), `useJobs()` (enrichment status), `useAuth()` (csrf), `useNav()`. Structure:
  - Guard: non-lead → "requires the lead role"; no active audit → prompt.
  - **Per-domain table** from `perDomainStatus(accounts, ingests)`: columns Domain · Accounts · Cracked · Enriched (✓ fresh / ⚠ stale / ✗ not run, colored) · Loaded (`fmtWhen(loadedAt)`) · a 🗑 delete button per row that `confirm("Delete <domain> — <n> accounts — from this audit?")` then `await api.deleteDomain(domain, me.csrf_token)` → `bumpData()` (and re-fetch ingests). Show a delete error inline.
  - **Enrichment card**: read `useJobs().enrich`; show phase/progress/elapsed/error as a first-class panel (not `.hint`); a **Run enrichment** button (`api.enrich(csrf)` then `bumpData`/refresh) disabled while running or when BHE not configured (you can gate on the enrich start returning 503 → show "BloodHound not configured — Integrations →"); a **Cancel** when running (`api.enrichCancel`).
  - **Ingest history** table (moved from Ingest): When · File · Kind · Domain · Result · By. Render `kind === "cracks"` domain as "all domains"; `kind === "domain_delete"` as e.g. `−{accounts_loaded} removed`; `kind === "enrich"` as `enriched {accounts_loaded}`.
  - Use existing classes (`section-label`, `panel`, `table.accounts compact`, `dstat`, `hint`, `error`, `btn`). Add any small CSS to `styles.css` (e.g. a `.enrich-card` if useful).
  Keep the file focused; reuse `fmtWhen`/`fmtBytes` from `../format`.

- [ ] **Step 6: Verify:** `cd web && npx tsc --noEmit && npm run build && npx vitest run`. Clean / pass.

- [ ] **Step 7: Commit:**
```bash
git add web/src/auditData.ts web/src/auditData.test.ts web/src/components/AuditData.tsx web/src/styles.css
git commit -m "feat(web): Audit Data page — per-domain status, enrichment control, delete, history"
```

---

## Task 6: Wire the route + nav; remove switcher delete

**Files:** Modify `web/src/components/AppShell.tsx`, `web/src/App.tsx`.

- [ ] **Step 1: Add the `audit-data` view.** In `AppShell.tsx`: add `"audit-data"` to the `View` union (if not added in Task 4) and add `{ id: "audit-data", label: "Audit Data" }` to `SETUP_ITEMS` (between Upload and Policies).

- [ ] **Step 2: Route it** in `App.tsx`: add a lazy import `const AuditData = lazy(() => import("./components/AuditData").then((m) => ({ default: m.AuditData })))` and a `case "audit-data": return <AuditData />` in `viewFor`.

- [ ] **Step 3: Remove the switcher delete.** In `AppShell.tsx`'s `AuditSwitcher`, remove the per-audit delete affordance (the `confirm(...) && void remove(...)` button at ~line 224) — keep open + create. (Whole-audit delete remains in `ManageAudits.tsx`.)

- [ ] **Step 4: Verify:** `cd web && npx tsc --noEmit && npm run build && npx vitest run`. The new page renders under Setup → Audit Data; the Upload "View audit data →" link resolves.

- [ ] **Step 5: Commit:**
```bash
git add web/src/components/AppShell.tsx web/src/App.tsx
git commit -m "feat(web): route + nav for Audit Data; remove delete from the audit switcher"
```

---

## Task 7: README + full gate + rebuild + live verify

- [ ] **Step 1: README "What's new" note** (append under 2.6 or a new 2.7 stub): the Upload/Audit-Data split, instant data after upload, per-domain delete, once-then-manual enrichment.

- [ ] **Step 2: Full gate:**
```bash
gofmt -l cmd internal && go build ./... && go vet ./... && go test ./...
cd web && npx tsc --noEmit && npm run build && npx vitest run
cd .. && govulncheck ./...
```

- [ ] **Step 3: Rebuild stamped binary + restart** (mirror the prior deploy: cp dist → embed → ldflags build → stop/start with `PATD_AUDIT_LOG`). Live-verify with the synthetic data (`tools/gen_synthetic.py` → `sample_data/synthetic/`): create an audit, upload `CORP.LOCAL_dump.txt` → **Overview/Accounts/Domains populate immediately** (no blank); apply `cracks.txt` → cracked counts update live; upload a 2nd domain → it shows ⚠ stale on Audit Data; **Run enrichment** → fresh; delete a domain → gone. (Auth steps may need the operator.)

- [ ] **Step 4: Commit README** if not already.

---

## Self-review (done during planning)
- **Spec coverage:** data freshness (T3) · slim Upload (T4) · Audit Data page + per-domain derivation (T5) · per-domain delete (T1) · enrichment cadence + completion event (T2) · nav cleanup (T6) · README/gate/deploy (T7). Every spec section maps to a task.
- **Type/signature consistency:** `dataVersion`/`bumpData` on `AuditsState` used identically across T3–T5; `IngestEvent.kind` union extended in T1 and consumed in T5; `perDomainStatus(accounts, ingests) → DomainRow[]` matches its test; `DELETE /api/domains/{domain}` + `api.deleteDomain(domain, csrf)` consistent T1↔T5; the `audit-data` View id added in T4/T6 and used by Upload's link + the route.
- **Tests:** Go TDD for the delete endpoint + cadence; pure-helper TDD for `perDomainStatus`; React wiring/page guarded by tsc/build + the T7 live run (node-env vitest, no DOM deps).
- **Ordering note:** T4 forward-declares the `audit-data` View id so it compiles before T6 formally adds the nav entry/route.
