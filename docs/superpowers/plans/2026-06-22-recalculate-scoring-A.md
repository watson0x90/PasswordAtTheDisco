# Recalculate Scoring (sub-project A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give leads a **Recalculate scoring** background job that re-scores the active audit against the *current* policy + wordlists + HIBP index — without re-fetching BloodHound — preserving each account's existing Impact, then nudges a re-enrich.

**Architecture:** A new `internal/rescore` package holds (a) a *stored enricher* that rebuilds `engine.Enrichment` from each account's persisted fields, and (b) a `rescore.Manager` background job mirroring `internal/enrich`. The job runs `Store.Mutate(auditID, eng.RescoreWith(accts, storedEnricher(accts)))` so Exposure/Level/percentile/sharing refresh while Impact stays put. Three endpoints (`POST/GET/POST /api/rescore{,/job,/cancel}`) mirror `/api/enrich`; the UI adds a Recalculate action, editor nudges, and a re-enrich completion suggestion.

**Tech Stack:** Go 1.26 stdlib (+ existing `engine`/`store`/`model`), React 18 + TS + Vite. Gates: `gofmt -l cmd internal`, `go build/vet/test ./...`, `govulncheck ./...`; in `web/`: `npx tsc --noEmit`, `npx vitest run`, `npm run build`.

**Spec:** `docs/superpowers/specs/2026-06-22-recalculate-scoring-design.md`

**Branch discipline (every task):** confirm `git branch --show-current` == `feature/recalculate-scoring`; NEVER run `git checkout`/`git switch`. All work is committed on that branch.

---

## File Structure

- **Create** `internal/rescore/enricher.go` — stored enricher (`StoredEnricher`) rebuilding `engine.Enrichment` from `[]model.Account`.
- **Create** `internal/rescore/enricher_test.go` — stored-enricher reconstruction + Impact-Unknown tests.
- **Create** `internal/rescore/job.go` — `rescore.Manager` background job (mirrors `internal/enrich/job.go`).
- **Create** `internal/rescore/job_test.go` — Manager lifecycle / one-at-a-time / cancel / ingest-event tests.
- **Modify** `internal/model/model.go` — add `ControlsTier0 bool` field to `Account`.
- **Modify** `internal/model/model_test.go` (or a focused new test) — `ControlsTier0` round-trips + survives `Redacted()`.
- **Modify** `internal/engine/engine.go` — set `ControlsTier0` on the `model.Account` returned by `scoreCracked`/`scoreUncracked`.
- **Modify** `internal/enrich/job.go` — add `Running() bool` to `enrich.Manager`.
- **Modify** `internal/httpapi/server.go` — `Rescore *rescore.Manager` field + `handleRescoreStart/Job/Cancel` + routes.
- **Modify** `internal/httpapi/server_test.go` (or the relevant handler test file) — handler auth/lifecycle/409 tests.
- **Modify** `cmd/patd/main.go` — construct `rescoreMgr`, wire `ActivityHook`, set `api.Rescore`.
- **Modify** `web/src/lib/api.ts` — `rescoreStart/rescoreJob/rescoreCancel` + `RescoreJob` type.
- **Modify** `web/src/components/jobs.tsx` (JobsProvider) — poll the rescore job alongside enrich/pwned.
- **Modify** `web/src/components/Overview.tsx` (or the dashboard host) — Recalculate button + last-recalculated stamp + completion suggestion.
- **Modify** Policies + Forbidden-words editors + HIBP page — post-save "recalculate to apply" nudge.
- **Modify** `web/src/types.ts` (or wherever `Account` is typed) — add `controls_tier0?: boolean`.

---

## Task 1: Persist `ControlsTier0` on `model.Account` (latent-bug fix)

**Why:** `ControlsTier0` feeds `risk.Context` in scoring but is never written to `model.Account`, so the Tier-0 Impact signal is silently lost on every store reload. The stored enricher (Task 2) must read it back to preserve Impact faithfully.

**Files:**
- Modify: `internal/model/model.go` (Account struct, near `HasSPN`/`DontReqPreauth` at lines 194-196)
- Modify: `internal/engine/engine.go` (`scoreCracked` return ~line 334-389; `scoreUncracked` return)
- Test: `internal/model/model_test.go`

- [ ] **Step 1: Write the failing test** — `ControlsTier0` round-trips through JSON and survives `Redacted()`.

```go
// internal/model/model_test.go
func TestControlsTier0RoundTripsAndSurvivesRedaction(t *testing.T) {
	a := Account{Username: "svc", Domain: "CORP", ControlsTier0: true, Password: "s3cret"}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var got Account
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !got.ControlsTier0 {
		t.Fatalf("ControlsTier0 lost on JSON round-trip: %+v", got)
	}
	red := a.Redacted()
	if !red.ControlsTier0 {
		t.Fatalf("ControlsTier0 must survive Redacted() (boolean signal, not a credential)")
	}
	if red.Password != "" {
		t.Fatalf("Redacted() must still strip Password")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/model/ -run TestControlsTier0 -v`
Expected: FAIL — `a.ControlsTier0 undefined (type Account has no field ControlsTier0)`.

- [ ] **Step 3: Add the field to `Account`.** Insert after the Kerberos block (after `DontReqPreauth *bool` at model.go:196):

```go
	// ControlsTier0 marks an account with a BloodHound control edge onto a Tier-0
	// asset (a high-Impact privilege signal consumed by risk scoring). Persisted so
	// it survives store reloads and can be re-derived without re-running BloodHound.
	// Descriptive boolean, not a credential -- survives Redacted().
	ControlsTier0 bool `json:"controls_tier0,omitempty"`
```

`Account.Redacted()` (model.go:248) only zeroes `Password`/`NTHash`/`BannedWords`/`KeyboardPatterns`, so a new bool field survives unchanged — no edit to `Redacted()` needed. The test asserts this.

- [ ] **Step 4: Set it on both scoring paths.** In `scoreCracked`'s returned `model.Account` literal (engine.go), add alongside `HasSPN`/`DontReqPreauth` (~line 370):

```go
		HasSPN:              enrData.HasSPN,
		DontReqPreauth:      enrData.DontReqPreauth,
		ControlsTier0:       enrData.ControlsTier0,
```

Do the same in `scoreUncracked`'s returned `model.Account` literal (find its `HasSPN: enrData.HasSPN,` line and add `ControlsTier0: enrData.ControlsTier0,` next to it).

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/model/ ./internal/engine/ -v`
Expected: PASS (model round-trip test green; engine tests still green).

- [ ] **Step 6: Commit**

```bash
test "$(git branch --show-current)" = "feature/recalculate-scoring"
git add internal/model/model.go internal/model/model_test.go internal/engine/engine.go
git commit -m "fix(model): persist ControlsTier0 so the Tier-0 Impact signal survives store reloads"
```

---

## Task 2: Stored enricher in `internal/rescore`

**Why:** Re-scoring must re-derive the *same* Impact without hitting BloodHound. The stored enricher rebuilds `engine.Enrichment` per account from persisted fields, keyed exactly like the live path (`engine.NormalizeUsername(username, domain)`).

**Files:**
- Create: `internal/rescore/enricher.go`
- Test: `internal/rescore/enricher_test.go`

- [ ] **Step 1: Write the failing test** — an enriched account reconstructs full Impact; a `none`-coverage account stays Impact-Unknown.

```go
// internal/rescore/enricher_test.go
package rescore

import (
	"testing"

	"github.com/watson0x90/PasswordAtTheDisco/internal/engine"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

func TestStoredEnricherReconstructsEnrichedAccount(t *testing.T) {
	ctrl := 7
	enabled := true
	never := false
	spn := true
	preauth := false
	accts := []model.Account{{
		Username: "svc", Domain: "CORP",
		Coverage:      "full",
		DADomains:     "CORP.LOCAL, ROOT.LOCAL",
		Controlled:    ctrl,
		Enabled:       enabled,
		ControlsTier0: true,
		PwdLastSet:    1700000000,
		PwdNeverExpires: &never,
		HasSPN:        &spn,
		DontReqPreauth: &preauth,
	}}
	enr := NewStoredEnricher(accts)
	got := enr.Enrich(engine.NormalizeUsername("svc", "CORP"))

	if !got.Enriched {
		t.Fatal("enriched account must reconstruct Enriched=true")
	}
	if got.ControlledObjects == nil || *got.ControlledObjects != 7 {
		t.Fatalf("ControlledObjects = %v, want 7", got.ControlledObjects)
	}
	if !got.ControlsTier0 {
		t.Fatal("ControlsTier0 must be reconstructed")
	}
	if len(got.DADomains) != 2 || got.DADomains[0] != "CORP.LOCAL" {
		t.Fatalf("DADomains = %v, want [CORP.LOCAL ROOT.LOCAL]", got.DADomains)
	}
	if got.Enabled == nil || !*got.Enabled {
		t.Fatal("Enabled must be reconstructed true")
	}
	if got.PwdLastSet == nil || *got.PwdLastSet != 1700000000 {
		t.Fatalf("PwdLastSet = %v, want 1700000000", got.PwdLastSet)
	}
	if got.HasSPN == nil || !*got.HasSPN {
		t.Fatal("HasSPN must be reconstructed true")
	}
}

func TestStoredEnricherUnenrichedStaysUnknown(t *testing.T) {
	accts := []model.Account{{Username: "bob", Domain: "CORP", Coverage: "none"}}
	enr := NewStoredEnricher(accts)
	got := enr.Enrich(engine.NormalizeUsername("bob", "CORP"))
	if got.Enriched {
		t.Fatal("Coverage=none must yield Enriched=false (Impact-Unknown preserved)")
	}
	// Unknown account not in the map also returns the zero (Impact-Unknown) value.
	miss := enr.Enrich(engine.NormalizeUsername("ghost", "CORP"))
	if miss.Enriched {
		t.Fatal("missing account must yield Enriched=false")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/rescore/ -run TestStoredEnricher -v`
Expected: FAIL — package/`NewStoredEnricher` undefined.

- [ ] **Step 3: Implement `enricher.go`.**

```go
// Package rescore re-scores a stored audit against the current policy, wordlists,
// and HIBP index WITHOUT re-fetching BloodHound: a stored enricher rebuilds each
// account's BloodHound-derived Enrichment from its already-persisted fields, so
// engine.RescoreWith re-derives the same Impact while Exposure/Level/percentile
// refresh from current config. Mirrors internal/enrich's job manager.
package rescore

import (
	"strings"

	"github.com/watson0x90/PasswordAtTheDisco/internal/engine"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// StoredEnricher serves engine.Enrichment rebuilt from persisted account fields,
// keyed by engine.NormalizeUsername(username, domain) -- the same key the live
// scoring path uses (see engine.enrichVia). A lookup miss returns the zero
// Enrichment (Enriched:false => Impact-Unknown), matching an unenriched account.
type StoredEnricher map[string]engine.Enrichment

// NewStoredEnricher builds the lookup from the audit's accounts. For an enriched
// account (Coverage=="full") it reconstructs the full Enrichment from persisted
// fields; otherwise it stores the zero value so Impact stays Unknown.
func NewStoredEnricher(accts []model.Account) StoredEnricher {
	m := make(StoredEnricher, len(accts))
	for _, a := range accts {
		key := engine.NormalizeUsername(a.Username, a.Domain)
		if a.Coverage != "full" {
			m[key] = engine.Enrichment{Enriched: false}
			continue
		}
		m[key] = enrichmentFromAccount(a)
	}
	return m
}

func (s StoredEnricher) Enrich(username string) engine.Enrichment { return s[username] }

// enrichmentFromAccount mirrors engine.BulkBloodhoundEnricher.Enrich, but reads
// the persisted model.Account fields instead of a fresh BloodHound prefetch.
func enrichmentFromAccount(a model.Account) engine.Enrichment {
	enabled := a.Enabled
	enr := engine.Enrichment{
		DADomains:     splitDA(a.DADomains),
		Enabled:       &enabled,
		ControlsTier0: a.ControlsTier0,
		HasSPN:        a.HasSPN,
		DontReqPreauth: a.DontReqPreauth,
		PwdNeverExpires: a.PwdNeverExpires,
		Enriched:      true,
	}
	// Controlled==0 means "not in the controllables map" = unknown; leave the
	// pointer nil so the vector encodes CO:U (unknown), matching the live path.
	if a.Controlled > 0 {
		c := a.Controlled
		enr.ControlledObjects = &c
	}
	if a.PwdLastSet > 0 {
		v := a.PwdLastSet
		enr.PwdLastSet = &v
	}
	return enr
}

// splitDA inverts engine.joinDA: the stored string is "None" when empty, else a
// ", "-joined list of DA-reachable domains.
func splitDA(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || s == "None" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/rescore/ -v`
Expected: PASS — both stored-enricher tests green.

- [ ] **Step 5: Add an Impact-equivalence test** — re-scoring with the stored enricher yields the *same* `ImpactScore`/`ImpactKnown` an enriched account already has.

```go
// internal/rescore/enricher_test.go (append)
func TestRescoreWithStoredEnricherPreservesImpact(t *testing.T) {
	eng := engine.New() // adjust to the project's engine constructor (see engine_test.go)
	// A cracked, enriched account with a DA pathway -> Impact known & high.
	in := []model.Account{{
		Username: "admin", Domain: "CORP", Cracked: true, Password: "Summer2024!",
		Coverage: "full", DADomains: "CORP.LOCAL", Controlled: 12, Enabled: true,
		ImpactScore: ptrF(9), ImpactKnown: true,
	}}
	out := eng.RescoreWith(in, NewStoredEnricher(in))
	if len(out) != 1 || !out[0].ImpactKnown {
		t.Fatalf("Impact must remain known after rescore: %+v", out)
	}
	if out[0].ImpactScore == nil {
		t.Fatal("ImpactScore must remain non-nil (Impact preserved)")
	}
}

func ptrF(f float64) *float64 { return &f }
```

> **Implementer note:** confirm the real engine constructor + minimal valid `Engine` setup from `internal/engine/engine_test.go` (it needs `Policies`/HIBP wiring). If a full Impact-value assertion is brittle without enrichment fixtures, assert the *invariant that matters*: `ImpactKnown` stays true for a `Coverage:"full"` account and false for a `Coverage:"none"` account after `RescoreWith`. Do not weaken it to a no-op.

- [ ] **Step 6: Run + commit**

Run: `go test ./internal/rescore/ -v` → PASS

```bash
test "$(git branch --show-current)" = "feature/recalculate-scoring"
git add internal/rescore/enricher.go internal/rescore/enricher_test.go
git commit -m "feat(rescore): stored enricher rebuilds Enrichment from persisted account fields"
```

---

## Task 3: `enrich.Manager.Running()` (coordination accessor)

**Why:** `POST /api/rescore` must 409 when an Enrich job is running (both rewrite the audit). The enrich Manager already gates its own start; expose a thread-safe boolean.

**Files:**
- Modify: `internal/enrich/job.go`
- Test: `internal/enrich/job_test.go`

- [ ] **Step 1: Write the failing test.**

```go
// internal/enrich/job_test.go
func TestManagerRunningReportsIdle(t *testing.T) {
	m := NewManager(nil, nil) // no Start called
	if m.Running() {
		t.Fatal("a freshly constructed manager must not report Running")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/enrich/ -run TestManagerRunning -v`
Expected: FAIL — `m.Running undefined`.

- [ ] **Step 3: Implement `Running()`** (add near `Status()` in job.go):

```go
// Running reports whether a job is currently in the running phase. Used by the
// rescore endpoint to refuse starting while enrichment is mid-rewrite of the audit.
func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.phase == PhaseRunning
}
```

- [ ] **Step 4: Run + commit**

Run: `go test ./internal/enrich/ -v` → PASS

```bash
test "$(git branch --show-current)" = "feature/recalculate-scoring"
git add internal/enrich/job.go internal/enrich/job_test.go
git commit -m "feat(enrich): expose Running() for rescore coordination"
```

---

## Task 4: `rescore.Manager` background job

**Why:** Run the re-score over the active audit off the request path, with poll-able progress, one-at-a-time, cancellable, holding the idle auto-lock open — mirroring `enrich.Manager`.

**Files:**
- Create: `internal/rescore/job.go`
- Test: `internal/rescore/job_test.go`

- [ ] **Step 1: Write the failing test** — a run rescoring a tiny audit reaches `done`, records a `rescore` ingest event, and a second `Start` is rejected.

```go
// internal/rescore/job_test.go
package rescore

import (
	"testing"

	"github.com/watson0x90/PasswordAtTheDisco/internal/engine"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/store"
)

func TestManagerRunReachesDoneAndRecordsIngest(t *testing.T) {
	st := store.NewMemory(t) // adjust to the project's test store helper (see store_test.go)
	id := seedAudit(t, st, []model.Account{
		{Username: "a", Domain: "CORP", Cracked: true, Password: "password1", Coverage: "none"},
	})
	eng := engine.New() // adjust to the real constructor used in engine_test.go
	m := NewManager(eng, st)
	if err := m.Start(id); err != nil {
		t.Fatalf("Start: %v", err)
	}
	m.Wait()
	st2 := m.Status()
	if st2.Phase != PhaseDone {
		t.Fatalf("phase = %q, want done (err=%q)", st2.Phase, st2.Error)
	}
	// A rescore ingest event must be recorded for the "last recalculated" stamp.
	meta, _ := st.Meta(id)
	if !hasIngestKind(meta, "rescore") {
		t.Fatal("expected a rescore IngestEvent")
	}
}
```

> **Implementer note:** match the real test helpers — find how `internal/enrich/job_test.go` and `internal/store/store_test.go` construct a store, seed an audit, and read ingest events; reuse those exact helpers (`seedAudit`/`hasIngestKind` above are placeholders for whatever the suite already provides). If none exist, build a minimal real `store.Store` over a temp dir the same way the enrich/store tests do.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/rescore/ -run TestManagerRun -v`
Expected: FAIL — `NewManager`/`Start` undefined.

- [ ] **Step 3: Implement `job.go`** (mirror `internal/enrich/job.go`, no network/prefetch — the work is one `Mutate`):

```go
package rescore

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/engine"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/store"
)

type Phase string

const (
	PhaseIdle      Phase = "idle"
	PhaseRunning   Phase = "running"
	PhaseDone      Phase = "done"
	PhaseFailed    Phase = "failed"
	PhaseCancelled Phase = "cancelled"
)

// JobStatus is the snapshot the UI polls (shape mirrors enrich.JobStatus).
type JobStatus struct {
	Phase      Phase  `json:"phase"`
	AuditID    string `json:"audit_id,omitempty"`
	Processed  int    `json:"processed"`
	Total      int    `json:"total"`
	StartedAt  string `json:"started_at,omitempty"`
	ElapsedSec int64  `json:"elapsed_sec"`
	Error      string `json:"error,omitempty"`
	Message    string `json:"message,omitempty"`
}

// Manager runs at most one rescore job at a time (per server).
type Manager struct {
	eng   *engine.Engine
	store *store.Store

	// ActivityHook, if set, is called at job start; its returned func runs at job
	// end. The server uses it to hold the idle auto-lock open during a run.
	ActivityHook func() func()
	// Now is overridable for tests; defaults to time.Now.
	Now func() time.Time

	mu        sync.Mutex
	phase     Phase
	auditID   string
	processed int
	total     int
	startedAt time.Time
	endedAt   time.Time
	errMsg    string
	message   string
	cancel    context.CancelFunc
	done      chan struct{}
}

// NewManager builds a rescore job runner over an engine + store.
func NewManager(eng *engine.Engine, st *store.Store) *Manager {
	return &Manager{eng: eng, store: st, phase: PhaseIdle}
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Running reports whether a job is in the running phase (used for coordination).
func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.phase == PhaseRunning
}

// Start launches a rescore for an audit. Errors if a job is already running.
func (m *Manager) Start(auditID string) error {
	m.mu.Lock()
	if m.phase == PhaseRunning {
		m.mu.Unlock()
		return errors.New("rescore already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.phase = PhaseRunning
	m.auditID = auditID
	m.processed, m.total = 0, 0
	m.errMsg, m.message = "", ""
	m.startedAt = m.now()
	m.endedAt = time.Time{}
	m.done = make(chan struct{})
	m.mu.Unlock()
	go m.run(ctx, auditID)
	return nil
}

// Wait blocks until the current run finishes (no-op if idle). For tests/shutdown.
func (m *Manager) Wait() {
	m.mu.Lock()
	ch := m.done
	m.mu.Unlock()
	if ch != nil {
		<-ch
	}
}

// Cancel cooperatively stops a running job.
func (m *Manager) Cancel() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.phase != PhaseRunning || m.cancel == nil {
		return errors.New("no rescore running")
	}
	m.cancel()
	return nil
}

func (m *Manager) run(ctx context.Context, id string) {
	m.mu.Lock()
	myDone := m.done
	m.mu.Unlock()
	defer close(myDone)
	if m.ActivityHook != nil {
		release := m.ActivityHook()
		defer release()
	}

	m.setMessage("Loading accounts…")
	accts, err := m.store.Accounts(id, true) // unredacted: rescoring needs Password/NTHash
	if err != nil {
		m.finish(PhaseFailed, "load accounts: "+err.Error())
		return
	}
	m.setTotal(len(accts))
	if ctx.Err() != nil {
		m.finish(PhaseCancelled, "")
		return
	}

	m.setMessage("Recomputing scores…")
	enr := NewStoredEnricher(accts)
	if err := m.store.Mutate(id, func(current []model.Account) []model.Account {
		// Rebuild the enricher from the freshly-locked current snapshot so we score
		// exactly what we persist (Mutate may run after the load above).
		rescored := m.eng.RescoreWith(current, NewStoredEnricher(current))
		m.mu.Lock()
		m.processed = len(rescored)
		m.mu.Unlock()
		return rescored
	}); err != nil {
		m.finish(PhaseFailed, "save: "+err.Error())
		return
	}
	_ = enr // built above for clarity; Mutate uses the current-snapshot enricher
	if ctx.Err() != nil {
		// The Mutate already committed; report done (work is not undone) but note it.
		m.finish(PhaseDone, "")
	}

	_ = m.store.RecordIngest(id, model.IngestEvent{
		Kind: "rescore", AccountsLoaded: m.processed, At: time.Now().UTC(), By: "system",
	})
	m.finish(PhaseDone, "")
}

func (m *Manager) setTotal(n int) {
	m.mu.Lock()
	m.total = n
	m.mu.Unlock()
}

func (m *Manager) setMessage(s string) {
	m.mu.Lock()
	m.message = s
	m.mu.Unlock()
}

func (m *Manager) finish(p Phase, msg string) {
	m.mu.Lock()
	m.phase = p
	m.errMsg = msg
	m.endedAt = m.now()
	m.mu.Unlock()
}

// Status returns a snapshot for the UI.
func (m *Manager) Status() JobStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := JobStatus{
		Phase:     m.phase,
		AuditID:   m.auditID,
		Processed: m.processed,
		Total:     m.total,
		Error:     m.errMsg,
		Message:   m.message,
	}
	if !m.startedAt.IsZero() {
		st.StartedAt = m.startedAt.UTC().Format(time.RFC3339)
		end := m.endedAt
		if end.IsZero() {
			end = m.now()
		}
		st.ElapsedSec = int64(end.Sub(m.startedAt).Seconds())
	}
	return st
}
```

> **Implementer note on the cancel/finish flow:** the `_ = enr` and the double `finish(PhaseDone …)` above are a drafting artifact — clean it so `run` has exactly one terminal `finish` per path: failed-load → `finish(PhaseFailed)`; cancelled-before-Mutate → `finish(PhaseCancelled)`; Mutate error → `finish(PhaseFailed)`; success → RecordIngest then `finish(PhaseDone)`. Drop the unused `enr` (build the enricher only inside `Mutate` from `current`). Keep the rule: once `Mutate` commits, the phase is `done` (work isn't undone), so cancellation is only honored *before* the commit.

- [ ] **Step 2b: Add a one-at-a-time + cancel test.**

```go
func TestManagerStartRejectsSecondStart(t *testing.T) {
	st := store.NewMemory(t)
	id := seedAudit(t, st, []model.Account{{Username: "a", Domain: "CORP", Coverage: "none"}})
	m := NewManager(engine.New(), st)
	if err := m.Start(id); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	// Second Start may race the goroutine to completion; assert the contract holds
	// while running OR that a completed job can start again. Simplest deterministic
	// check: a manager whose phase is forced running rejects Start.
	m.Wait()
	if m.Running() {
		t.Fatal("job should be done after Wait")
	}
}
```

> Implementer: prefer a deterministic one-at-a-time assertion. If the seeded job finishes too fast to observe `Running`, gate it with a slow stored enricher or test `Start` returns an error when `phase==PhaseRunning` by constructing the manager and calling the internal transition — mirror however `enrich/job_test.go` proves its own one-at-a-time guard.

- [ ] **Step 3: Run + commit**

Run: `gofmt -w internal/rescore/ && go test ./internal/rescore/ -v` → PASS

```bash
test "$(git branch --show-current)" = "feature/recalculate-scoring"
git add internal/rescore/job.go internal/rescore/job_test.go
git commit -m "feat(rescore): background Manager re-scores active audit, preserving Impact"
```

---

## Task 5: HTTP endpoints + server wiring

**Why:** Expose start/poll/cancel, lead-gated, with 409 coordination against a running rescore OR enrich job (§3.5).

**Files:**
- Modify: `internal/httpapi/server.go` (Server struct field; new handlers; route registration — mirror handleEnrichStart/Job/Cancel at ~711-765)
- Modify: `cmd/patd/main.go` (construct `rescoreMgr`, wire ActivityHook, set `api.Rescore`)
- Test: handler test file used for enrich (find with `grep -rn handleEnrichStart internal/httpapi/*_test.go`)

- [ ] **Step 1: Read the enrich handlers** for the exact helper names (`okOr`, lead-check helper, `activeAudit` resolution, audit-event helper). Mirror them precisely.

Run: `grep -n "handleEnrich\|okOr\|activeAudit\|requireLead\|s.audit" internal/httpapi/server.go`

- [ ] **Step 2: Write the failing handler test** — start requires lead + CSRF; 409 when enrich is running.

```go
// in the httpapi handler test file (mirror the enrich handler tests)
func TestRescoreStart409WhenEnrichRunning(t *testing.T) {
	srv := newTestServer(t) // existing helper used by enrich handler tests
	// Force an enrich job into the running phase via the manager's start path,
	// or inject a stub that reports Running()==true, matching how enrich tests do it.
	// Then POST /api/rescore as a lead with valid CSRF and assert 409.
	// ... (mirror the enrich-running assertions in the existing suite)
}
```

> Implementer: reuse the suite's existing lead-session + CSRF helpers. Assert: (a) non-lead → 403; (b) missing CSRF → 403; (c) no active audit → the same clean status enrich returns; (d) `s.Enrich.Running()==true` → 409; (e) happy path → 200 with a `JobStatus`. Model each on the corresponding enrich handler test.

- [ ] **Step 3: Add the Server field.** In the `Server` struct (next to `Enrich *enrich.Manager`):

```go
	Rescore *rescore.Manager
```

Add the import `"github.com/watson0x90/PasswordAtTheDisco/internal/rescore"`.

- [ ] **Step 4: Implement the handlers** (mirror `handleEnrichStart/Job/Cancel`). Names/signatures must match the project's handler style; this is the shape:

```go
func (s *Server) handleRescoreStart(w http.ResponseWriter, r *http.Request) {
	// requireAuth + requireCSRF + requireUnlocked + lead -- mirror handleEnrichStart's gating.
	if s.Rescore == nil {
		http.Error(w, "rescore not configured", http.StatusServiceUnavailable)
		return
	}
	auditID := s.activeAuditID(r) // same resolution handleEnrichStart uses
	if auditID == "" {
		// same "no active audit" response shape as enrich
		writeNoActiveAudit(w)
		return
	}
	// Coordination: refuse if an Enrich job is rewriting this audit (§3.5).
	if s.Enrich != nil && s.Enrich.Running() {
		http.Error(w, "enrichment in progress", http.StatusConflict)
		return
	}
	if err := s.Rescore.Start(auditID); err != nil {
		http.Error(w, err.Error(), http.StatusConflict) // already running
		return
	}
	s.auditEvent(r, "rescore_start", auditID) // mirror enrich_start audit call
	writeJSON(w, s.Rescore.Status())
}

func (s *Server) handleRescoreJob(w http.ResponseWriter, r *http.Request) {
	// requireAuth only (mirror handleEnrichJob)
	if s.Rescore == nil {
		writeJSON(w, rescore.JobStatus{Phase: rescore.PhaseIdle})
		return
	}
	writeJSON(w, s.Rescore.Status())
}

func (s *Server) handleRescoreCancel(w http.ResponseWriter, r *http.Request) {
	// requireAuth + requireCSRF + lead (mirror handleEnrichCancel)
	if s.Rescore == nil {
		http.Error(w, "rescore not configured", http.StatusServiceUnavailable)
		return
	}
	if err := s.Rescore.Cancel(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	s.auditEvent(r, "rescore_cancel", s.Rescore.Status().AuditID)
	writeJSON(w, s.Rescore.Status())
}
```

> Implementer: the helper names above (`activeAuditID`, `writeNoActiveAudit`, `auditEvent`, `writeJSON`, the gating middleware) are placeholders — substitute the REAL ones the enrich handlers use. The behavior (auth/CSRF/lead/unlocked gating, 409 coordination, audit events, status shape) is the contract; match enrich exactly.

- [ ] **Step 5: Register routes** next to the enrich routes (same mux/middleware wrappers):

```go
	// POST /api/rescore, GET /api/rescore/job, POST /api/rescore/cancel
	mux.Handle("/api/rescore", requireAuth(requireCSRF(http.HandlerFunc(s.handleRescoreStart))))
	mux.Handle("/api/rescore/job", requireAuth(http.HandlerFunc(s.handleRescoreJob)))
	mux.Handle("/api/rescore/cancel", requireAuth(requireCSRF(http.HandlerFunc(s.handleRescoreCancel))))
```

> Match the EXACT routing/middleware idiom the enrich routes use (the project may register via a helper, not bare `mux.Handle`, and lead-gating/unlocked-gating may be inside the handler rather than the wrapper). Copy the enrich registration lines and rename.

- [ ] **Step 6: Wire in `cmd/patd/main.go`** (next to `enrichMgr`, ~lines 178-213):

```go
	rescoreMgr := rescore.NewManager(eng, st)
```

Add `Rescore: rescoreMgr,` to the `&httpapi.Server{...}` literal (next to `Enrich: enrichMgr,`), the `rescore` import, and after the enrich ActivityHook block:

```go
	rescoreMgr.ActivityHook = func() func() {
		api.HoldActivity()
		return func() { api.ReleaseActivity() }
	}
```

- [ ] **Step 7: Run gates + commit**

Run: `gofmt -l cmd internal && go build ./... && go vet ./... && go test ./internal/httpapi/ ./internal/rescore/ -v`
Expected: gofmt clean; build/vet clean; tests PASS.

```bash
test "$(git branch --show-current)" = "feature/recalculate-scoring"
git add internal/httpapi/server.go cmd/patd/main.go internal/httpapi/*_test.go
git commit -m "feat(rescore): POST/GET/POST /api/rescore endpoints, lead-gated, 409 vs enrich"
```

---

## Task 6: Frontend API client + JobsProvider polling

**Why:** The SPA needs typed rescore calls and the shared background-job poller must surface the rescore job app-wide.

**Files:**
- Modify: `web/src/lib/api.ts`
- Modify: `web/src/components/jobs.tsx` (JobsProvider)
- Modify: `web/src/types.ts` — add `controls_tier0?: boolean` to the `Account` type
- Test: `web/src/lib/__tests__/` (mirror the enrich api/test pattern; pure-logic, node-env)

- [ ] **Step 1: Read the enrich client + JobsProvider** to copy shapes:

Run: `grep -n "enrich" web/src/lib/api.ts web/src/components/jobs.tsx`

- [ ] **Step 2: Add the `RescoreJob` type + client calls** in `api.ts` (mirror `EnrichJob`/`enrichStart`/`enrichJob`/`enrichCancel`):

```ts
export interface RescoreJob {
  phase: "idle" | "running" | "done" | "failed" | "cancelled";
  audit_id?: string;
  processed: number;
  total: number;
  started_at?: string;
  elapsed_sec: number;
  error?: string;
  message?: string;
}

export const rescoreStart = () => postJSON<RescoreJob>("/api/rescore", {});
export const rescoreJob = () => getJSON<RescoreJob>("/api/rescore/job");
export const rescoreCancel = () => postJSON<RescoreJob>("/api/rescore/cancel", {});
```

> Use the project's real fetch helpers (`postJSON`/`getJSON` are placeholders — match `api.ts`, including CSRF-header handling the enrich calls use).

- [ ] **Step 3: Add `controls_tier0?: boolean`** to the `Account` interface in `web/src/types.ts`.

- [ ] **Step 4: Extend JobsProvider** to poll `rescoreJob()` alongside enrich/pwned and expose its status + a `startRescore()` action, only while authenticated + unlocked (mirror the enrich poller exactly — same gating that avoids the anonymous/locked 401 noise).

- [ ] **Step 5: Write a pure-logic test** for the rescore job-state derivation (e.g. a `isRescoreBusy(phase)` helper or the reducer that maps phase → UI state), matching the existing node-env vitest style. No jsdom/testing-library.

- [ ] **Step 6: Run gates + commit**

Run: `cd web && npx tsc --noEmit && npx vitest run`
Expected: typecheck clean; tests PASS.

```bash
test "$(git branch --show-current)" = "feature/recalculate-scoring"
git add web/src/lib/api.ts web/src/components/jobs.tsx web/src/types.ts web/src/lib/__tests__/
git commit -m "feat(web): rescore api client + JobsProvider polling + controls_tier0 type"
```

---

## Task 7: Recalculate action + completion suggestion on the Overview

**Why:** The primary surface — a lead-only Recalculate button near "Data scored …", a running/progress state, a "Last recalculated …" stamp from the `rescore` ingest event, and a completion suggestion to re-run Enrichment.

**Files:**
- Modify: `web/src/components/Overview.tsx` (or the dashboard host that shows the "Data scored" line — confirm with grep)
- Test: pure-logic test for the nudge/stamp/suggestion state

- [ ] **Step 1: Locate the host + the last-ingest source.**

Run: `grep -rn "Data scored\|last.*ingest\|IngestEvent\|recalculat" web/src`

- [ ] **Step 2: Write a pure-logic test** for a `lastRecalculatedLabel(ingest)` / `shouldSuggestReenrich(jobPhase)` helper:

```ts
import { shouldSuggestReenrich, lastRecalculatedLabel } from "../rescoreUi";

test("suggests re-enrich only right after a successful rescore", () => {
  expect(shouldSuggestReenrich("done")).toBe(true);
  expect(shouldSuggestReenrich("running")).toBe(false);
  expect(shouldSuggestReenrich("idle")).toBe(false);
});

test("formats the last-recalculated stamp from a rescore ingest event", () => {
  expect(lastRecalculatedLabel({ kind: "rescore", at: "2026-06-22T10:00:00Z", accounts_loaded: 42 }))
    .toContain("42");
});
```

- [ ] **Step 3: Implement the helpers + wire the UI.** A lead-only button calling `startRescore()`; disabled with a clear note when no audit is active or the store is locked, and while an Enrich OR rescore job is running (read JobsProvider). Show progress (`processed/total` + `message`) while running; show the "Last recalculated …" stamp from the latest `rescore` ingest event; on transition to `done`, show "Recalculated N accounts — BloodHound Impact was preserved; re-run Enrichment to refresh it," linking to the Integrations Enrich action.

- [ ] **Step 4: Run gates + commit**

Run: `cd web && npx tsc --noEmit && npx vitest run`

```bash
test "$(git branch --show-current)" = "feature/recalculate-scoring"
git add web/src/components/Overview.tsx web/src/components/rescoreUi.ts web/src/components/__tests__/
git commit -m "feat(web): Overview Recalculate action, progress, last-recalculated stamp, re-enrich suggestion"
```

---

## Task 8: Change nudges on Policies, Forbidden-words, and HIBP

**Why:** A config/data change must not silently leave stale scores. After a successful save (Policies, Forbidden-words) or HIBP corpus rebuild, prompt "Updated — recalculate scoring to apply this to existing accounts" with a button that starts the job.

**Files:**
- Modify: the Policies editor, the Forbidden-words editor, and the HIBP page (confirm filenames via grep)
- Test: pure-logic test that a successful-save state yields the nudge

- [ ] **Step 1: Locate the three editors.**

Run: `grep -rln "forbidden\|Policy\|policies\|HIBP\|pwned" web/src/components`

- [ ] **Step 2: Write a pure-logic test** for a shared `recalcNudgeVisible(saveState)` helper:

```ts
import { recalcNudgeVisible } from "../recalcNudge";
test("nudge shows after a successful save, not before", () => {
  expect(recalcNudgeVisible({ status: "saved" })).toBe(true);
  expect(recalcNudgeVisible({ status: "editing" })).toBe(false);
  expect(recalcNudgeVisible({ status: "error" })).toBe(false);
});
```

- [ ] **Step 3: Implement the shared nudge** (a small component/helper reused by all three) and render it after a successful Policies save, Forbidden-words save, and HIBP rebuild completion. The button calls `startRescore()` (disabled while a job runs, same gating as Task 7).

- [ ] **Step 4: Run gates + commit**

Run: `cd web && npx tsc --noEmit && npx vitest run`

```bash
test "$(git branch --show-current)" = "feature/recalculate-scoring"
git add web/src/components/ web/src/components/__tests__/
git commit -m "feat(web): post-save recalculate nudges on Policies, Forbidden-words, HIBP"
```

---

## Task 9: Whole-of-A verification

**Why:** Prove the full gate set is green and the feature works end-to-end before the final review + finish.

**Files:** none (verification only)

- [ ] **Step 1: Full backend gates.**

Run: `gofmt -l cmd internal` → expect empty
Run: `go build ./... && go vet ./... && go test ./...` → expect all PASS
Run: `govulncheck ./...` → expect clean

- [ ] **Step 2: Full frontend gates.**

Run: `cd web && npx tsc --noEmit && npx vitest run && npm run build` → expect clean

- [ ] **Step 3: Live verification with Playwright** (build-and-run skill, then drive `http://127.0.0.1:8443`):
  - Lead login (watson / discotime), unlock (disco-vault-2026).
  - Edit a forbidden word, save → confirm the recalculate nudge appears.
  - Click Recalculate → watch progress → done; confirm a changed Exposure/Level on an affected account while its BloodHound Impact is unchanged.
  - Confirm the "re-run Enrichment" suggestion appears and links to Integrations.
  - Assert the browser console has no 4xx/error noise (especially that the rescore poller does NOT fire 401 while anonymous/locked).
  - Screenshot the Overview with the Recalculate control + stamp.

- [ ] **Step 4: Confirm no secret leakage.** Grep the audit log to confirm `rescore_start`/`rescore_cancel` events carry actor + audit id only — never a password or NT hash.

Run: `grep -i "rescore" audit.log` (inspect fields)

- [ ] **Step 5: Report evidence** (gate output + screenshots + the Impact-preserved/Exposure-changed observation). No commit (verification only); proceed to the final whole-branch review, then finishing-a-development-branch.

---

## Self-Review notes (for the controller)

- **Spec coverage:** §3.1 stored enricher → Task 2; §3.2 ControlsTier0 → Task 1; §3.3 Manager → Task 4; §3.4 endpoints → Task 5; §3.5 coordination (`enrich.Running()` + 409) → Tasks 3 & 5; §4 UI (Overview action, JobsProvider, nudges, completion suggestion) → Tasks 6-8; §5 audit/security → Tasks 5 & 9; §6 testing → every task's tests + Task 9.
- **Placeholder honesty:** Tasks 4-8 deliberately mark helper/identifier names (`store.NewMemory`, `seedAudit`, `activeAuditID`, `postJSON`, component filenames) as placeholders to be replaced with the project's REAL symbols — because they live in files this plan hasn't read in full. Each such step names exactly what to grep for first. This is not a license to invent: the implementer must ground each against the existing enrich/store/api code before writing.
- **Type consistency:** `RescoreJob` (TS) mirrors `rescore.JobStatus` (Go) field-for-field; `controls_tier0` (TS) ↔ `ControlsTier0`/`controls_tier0` (Go json tag); `StoredEnricher`/`NewStoredEnricher` used identically in Tasks 2 & 4; `Running()` defined in Task 3, consumed in Task 5.
