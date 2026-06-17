# Decoupled BloodHound Enrichment — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make dump uploads return in seconds (no inline BloodHound), and move BHE enrichment into a fast, concurrent, observable, auto-started + re-triggerable background job.

**Architecture:** Upload streams → parses → HIBP-scores → stores with **no enricher**. A new `internal/enrich` job manager (mirrors `internal/pwned`) does all BHE work in one concurrent **prefetch** phase (client throttle replaced by a concurrency semaphore; domains cached once), builds an in-memory `username→Enrichment` map, then re-scores atomically via `Engine.RescoreWith` + `Store.Replace`. The UI polls a job-status endpoint.

**Tech Stack:** Go 1.26 stdlib (net/http, sync, context), React + TypeScript (vitest), existing `golang.org/x/crypto`. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-06-16-enrichment-performance-design.md`

**Branch:** `feature/upload-ux` (continue committing here).

**Gates (run from repo root unless noted):**
- `gofmt -l cmd internal` → empty
- `go build ./... && go vet ./... && go test ./...`
- `cd web && npx tsc --noEmit && npm run build && npx vitest run`
- `govulncheck ./...` → clean

---

## File Structure

- `internal/bloodhound/bloodhound.go` — replace serial `throttle()` with a concurrency semaphore; add `GetDomains` TTL cache; add `EnrichConcurrency` config field. (Task 1, 2)
- `internal/engine/engine.go` — export `NormalizeUsername`; add `CurrentEnricher()`; thread an explicit `Enricher` through scoring (`processDomainWith`, `ProcessDomainNoEnrich`, `RescoreWith`). (Task 3)
- `internal/enrich/job.go` — NEW package: `Manager`, `JobStatus`, `Start/Status/Cancel/Wait`, concurrent prefetch, `mapEnricher`. (Task 4)
- `internal/httpapi/server.go` — `Enrich` field + activity hook; `POST /api/enrich`, `GET /api/enrich/job`, `POST /api/enrich/cancel`; upload + apply-cracks use no-enrich scoring and auto-kick. (Task 5)
- `cmd/patd/main.go` — construct the enrich manager, wire activity hook + concurrency config. (Task 6)
- `web/src/api.ts` — `enrich/enrichJob/enrichCancel` + `EnrichJob` type. (Task 7)
- `web/src/components/Ingest.tsx` — enrichment-progress polling + locked-upload gate. (Task 7)
- `web/src/components/Integrations.tsx` — "Run BloodHound enrichment" button + progress/cancel. (Task 8)
- `README.md` — "What's new" note. (Task 9)

---

## Task 1: BHE client — replace serial throttle with a concurrency semaphore

**Files:**
- Modify: `internal/bloodhound/bloodhound.go` (`Config`, `Client`, `New`, `throttle`/`doRequest`)
- Test: `internal/bloodhound/bloodhound_test.go`

- [ ] **Step 1: Write the failing test** — concurrent requests run in parallel up to N, and N is bounded.

Add to `internal/bloodhound/bloodhound_test.go`:

```go
func TestClientConcurrencySemaphore(t *testing.T) {
	var cur, max int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&cur, 1)
		for {
			old := atomic.LoadInt32(&max)
			if n <= old || atomic.CompareAndSwapInt32(&max, old, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&cur, -1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	host, port := splitHostPort(t, srv.URL) // helper below
	c := New(Config{Scheme: "http", Host: host, Port: port, EnrichConcurrency: 4})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _, _ = c.get("/api/v2/available-domains") }()
	}
	wg.Wait()
	if got := atomic.LoadInt32(&max); got == 0 || got > 4 {
		t.Fatalf("max concurrent = %d, want 1..4", got)
	}
}

// splitHostPort extracts host + numeric port from an httptest URL.
func splitHostPort(t *testing.T, raw string) (string, int) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname(), p
}
```

Ensure the test file imports: `net/http`, `net/http/httptest`, `net/url`, `strconv`, `sync`, `sync/atomic`, `time`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/bloodhound/ -run TestClientConcurrencySemaphore -v`
Expected: FAIL — compile error (`EnrichConcurrency` unknown field) or `max == 1` (serial throttle still active).

- [ ] **Step 3: Implement the semaphore**

In `internal/bloodhound/bloodhound.go`:

Add to `Config` (after `ReadTimeout`):
```go
	ReadTimeout        int    `json:"read_timeout"`
	EnrichConcurrency  int    `json:"enrich_concurrency"` // max concurrent BHE requests (default 8)
```

In `Client`, replace the throttle fields (`mu`, `lastRequest`, `minInterval`) with a semaphore:
```go
	sem chan struct{} // bounds concurrent in-flight requests
```

In `New`, after computing `controllablesLimit`, clamp concurrency and build the semaphore:
```go
	concurrency := cfg.EnrichConcurrency
	if concurrency <= 0 {
		concurrency = 8
	}
	if concurrency > 32 {
		concurrency = 32
	}
```
and in the returned `&Client{...}` literal, replace `minInterval: 100 * time.Millisecond,` with:
```go
		sem: make(chan struct{}, concurrency),
```

Replace `throttle()` with acquire/release and update `doRequest`:
```go
func (c *Client) acquire() { c.sem <- struct{}{} }
func (c *Client) release() { <-c.sem }

func (c *Client) doRequest(method, uri string, body []byte) (*http.Response, error) {
	c.acquire()
	defer c.release()
	requestDate := time.Now().Format("2006-01-02T15:04:05.000000-07:00")
	// ...unchanged body...
}
```
Remove the now-unused `rand` import if `throttle` was its only user (check; `sign`/elsewhere may still use it — only drop if `go vet` flags it).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/bloodhound/ -run TestClientConcurrencySemaphore -v`
Expected: PASS (`max` between 2 and 4).
Then: `go test ./internal/bloodhound/ -v` (existing tests still green) and `gofmt -l internal/bloodhound`.

- [ ] **Step 5: Commit**

```bash
git add internal/bloodhound/bloodhound.go internal/bloodhound/bloodhound_test.go
git commit -m "perf(bhe): bound client by a concurrency semaphore (was serial 100ms throttle)"
```

---

## Task 2: BHE client — cache GetDomains (TTL)

**Files:**
- Modify: `internal/bloodhound/bloodhound.go` (`Client`, `New`, `GetDomains`)
- Test: `internal/bloodhound/bloodhound_test.go`

- [ ] **Step 1: Write the failing test** — N `GetDomains` calls hit the backend once within the TTL.

```go
func TestGetDomainsCached(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"name":"CORP","collected":true}]}`))
	}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)
	c := New(Config{Scheme: "http", Host: host, Port: port})

	for i := 0; i < 5; i++ {
		ds, err := c.GetDomains()
		if err != nil || len(ds) != 1 {
			t.Fatalf("call %d: ds=%v err=%v", i, ds, err)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("backend hits = %d, want 1 (cached)", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/bloodhound/ -run TestGetDomainsCached -v`
Expected: FAIL — `backend hits = 5`.

- [ ] **Step 3: Implement the cache**

Add fields to `Client`:
```go
	domMu       sync.Mutex
	domCache    []Domain
	domCachedAt time.Time
	domTTL      time.Duration
```

In `New`, set `domTTL: 60 * time.Second,` in the literal.

Rewrite `GetDomains`:
```go
func (c *Client) GetDomains() ([]Domain, error) {
	c.domMu.Lock()
	if c.domCache != nil && time.Since(c.domCachedAt) < c.domTTL {
		ds := c.domCache
		c.domMu.Unlock()
		return ds, nil
	}
	c.domMu.Unlock()

	env, status, err := c.get("/api/v2/available-domains")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("available-domains: status %d", status)
	}
	var ds []Domain
	if err := json.Unmarshal(env.Data, &ds); err != nil {
		return nil, err
	}
	c.domMu.Lock()
	c.domCache = ds
	c.domCachedAt = time.Now()
	c.domMu.Unlock()
	return ds, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/bloodhound/ -run TestGetDomainsCached -v` → PASS
Then: `go test ./internal/bloodhound/ -v` and `gofmt -l internal/bloodhound`.

- [ ] **Step 5: Commit**

```bash
git add internal/bloodhound/bloodhound.go internal/bloodhound/bloodhound_test.go
git commit -m "perf(bhe): cache GetDomains (TTL) so GetUserData stops refetching per account"
```

---

## Task 3: Engine — explicit enricher (NormalizeUsername, CurrentEnricher, ProcessDomainNoEnrich, RescoreWith)

**Files:**
- Modify: `internal/engine/engine.go`
- Test: `internal/engine/engine_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestRescoreWithExplicitEnricher(t *testing.T) {
	e := newTestEngine() // existing test helper used by the other tests
	accts := []model.Account{{
		Username: "alice", Domain: "CORP", NTHash: "H1", Password: "Summer2024!", Cracked: true,
	}}
	// nil enricher -> no DA data
	plain := e.RescoreWith(accts, nil)
	if plain[0].DADomains != "None" {
		t.Fatalf("nil enricher should yield no DA, got %q", plain[0].DADomains)
	}
	// map enricher -> DA data applied
	enr := fakeEnricher{engine.NormalizeUsername("alice", "CORP"): Enrichment{DADomains: []string{"CORP"}}}
	withDA := e.RescoreWith(accts, enr)
	if withDA[0].DADomains != "CORP" {
		t.Fatalf("map enricher should yield DA=CORP, got %q", withDA[0].DADomains)
	}
}

func TestProcessDomainNoEnrichSkipsBHE(t *testing.T) {
	e := newTestEngine()
	e.Enricher = fakeEnricher{engine.NormalizeUsername("bob", "CORP"): Enrichment{DADomains: []string{"CORP"}}}
	out := e.ProcessDomainNoEnrich("CORP", []secretsdump.ParsedAccount{
		{Username: "bob", Domain: "CORP", Hash: "H2", Password: "pw", Cracked: true},
	}, nil)
	if out[0].DADomains != "None" {
		t.Fatalf("ProcessDomainNoEnrich must ignore e.Enricher, got DA=%q", out[0].DADomains)
	}
}
```
Notes: the existing tests construct an engine and a `fakeEnricher` (`engine_test.go` already defines `fakeEnricher map[string]Enrichment`). If there is no `newTestEngine()` helper, inline the same `&Engine{Lists: ..., Policies: ...}` construction the other tests use (copy from `TestProcessDomainCrackedBasics`). `engine.NormalizeUsername` is the same-package exported name added below (in-package tests can also call `normalizeUsername`, but use the exported one to lock its name).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/engine/ -run 'TestRescoreWithExplicitEnricher|TestProcessDomainNoEnrichSkipsBHE' -v`
Expected: FAIL — `RescoreWith`, `ProcessDomainNoEnrich`, `NormalizeUsername` undefined.

- [ ] **Step 3: Implement the explicit-enricher refactor**

In `internal/engine/engine.go`:

(a) Export the normalizer — rename `normalizeUsername` to `NormalizeUsername` and update its one internal caller:
```go
// NormalizeUsername renders "user@DOMAIN" (leaving an already-qualified name as-is).
func NormalizeUsername(username, domain string) string {
	if strings.Contains(username, "@") {
		return username
	}
	return username + "@" + domain
}
```

(b) Add a current-enricher reader and an enrich helper that takes an explicit enricher; remove the old method `func (e *Engine) enrich(...)`:
```go
// CurrentEnricher returns the configured enricher (nil if BHE is off).
func (e *Engine) CurrentEnricher() Enricher {
	e.encMu.RLock()
	defer e.encMu.RUnlock()
	return e.Enricher
}

// enrichVia fetches enrichment from enr (nil = none).
func enrichVia(enr Enricher, username, domain string, wanted bool) Enrichment {
	if !wanted || enr == nil {
		return Enrichment{}
	}
	return enr.Enrich(NormalizeUsername(username, domain))
}
```

(c) Thread an explicit enricher through scoring. Change the loop core of `ProcessDomain` into `processDomainWith`, and make `ProcessDomain` delegate:
```go
// ProcessDomain scores using the engine's currently-configured enricher.
func (e *Engine) ProcessDomain(domain string, cracked, uncracked []secretsdump.ParsedAccount) []model.Account {
	return e.processDomainWith(domain, cracked, uncracked, e.CurrentEnricher())
}

// ProcessDomainNoEnrich scores without any BloodHound enrichment (fast upload path).
func (e *Engine) ProcessDomainNoEnrich(domain string, cracked, uncracked []secretsdump.ParsedAccount) []model.Account {
	return e.processDomainWith(domain, cracked, uncracked, nil)
}

func (e *Engine) processDomainWith(domain string, cracked, uncracked []secretsdump.ParsedAccount, enr Enricher) []model.Account {
	// ...exact body of the old ProcessDomain (lines 95-130), except the two
	// scoring calls pass enr:
	//   out = append(out, e.scoreCracked(domain, a, pwUsers[a.Password]-1, allPasswords, analysisCache, simCache, now, enr))
	//   out = append(out, e.scoreUncracked(domain, a, hashUsers[a.Hash]-1, now, enr))
}
```

(d) Add `enr Enricher` as the last parameter of `scoreCracked` and `scoreUncracked`, and replace their enrichment lookups:
- In `scoreCracked`: change signature to `(..., now time.Time, enr Enricher)` and replace `enr := e.enrich(a.Username, domain, true)` with `enrData := enrichVia(enr, a.Username, domain, true)`, then rename the subsequent `enr.` field reads to `enrData.`. (Watch the local-name clash: the parameter is `enr Enricher`; the enrichment result must be a different name, `enrData`.)
- In `scoreUncracked`: change signature to `(..., now time.Time, enr Enricher)` and replace the `if sharedWith > 0 { enr = e.enrich(a.Username, domain, true) }` block with:
```go
	var enrData Enrichment
	if sharedWith > 0 {
		enrData = enrichVia(enr, a.Username, domain, true)
	}
```
then rename `enr.` field reads in that function to `enrData.`.

(e) Add the rescore variants:
```go
// Rescore re-scores using the engine's current enricher (unchanged behavior).
func (e *Engine) Rescore(accts []model.Account) []model.Account {
	return e.rescoreWith(accts, e.CurrentEnricher())
}

// RescoreWith re-scores using an explicit enricher (nil = none). Used by the
// enrichment job, which supplies a prefetched in-memory map enricher.
func (e *Engine) RescoreWith(accts []model.Account, enr Enricher) []model.Account {
	return e.rescoreWith(accts, enr)
}

func (e *Engine) rescoreWith(accts []model.Account, enr Enricher) []model.Account {
	// ...exact body of the old Rescore (group by domain), except call
	// e.processDomainWith(dom, cracked, uncracked, enr) instead of e.ProcessDomain(...).
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/engine/ -v`
Expected: PASS (new + existing). Then `gofmt -l internal/engine`.

- [ ] **Step 5: Commit**

```bash
git add internal/engine/engine.go internal/engine/engine_test.go
git commit -m "refactor(engine): explicit enricher (NormalizeUsername, ProcessDomainNoEnrich, RescoreWith)"
```

---

## Task 4: New `internal/enrich` job manager

**Files:**
- Create: `internal/enrich/job.go`
- Test: `internal/enrich/job_test.go`

- [ ] **Step 1: Write the failing test**

`internal/enrich/job_test.go`:
```go
package enrich

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/engine"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/store"
)

type countingEnricher struct {
	mu    sync.Mutex
	calls map[string]int
	data  map[string]engine.Enrichment
}

func (c *countingEnricher) Enrich(u string) engine.Enrichment {
	c.mu.Lock()
	c.calls[u]++
	c.mu.Unlock()
	return c.data[u]
}

func newEng(enr engine.Enricher) *engine.Engine {
	e := &engine.Engine{}
	e.SwapEnricher(enr)
	return e
}

func seedStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	s := store.New()
	meta, err := s.CreateAudit("t", "")
	if err != nil {
		t.Fatal(err)
	}
	// two accounts share a username so the job dedups to one lookup.
	accts := []model.Account{
		{Username: "alice", Domain: "CORP", NTHash: "H1", Password: "Summer2024!", Cracked: true},
		{Username: "alice", Domain: "CORP", NTHash: "H1", Password: "Summer2024!", Cracked: true},
	}
	if err := s.ReplaceDomain(meta.ID, "CORP", accts); err != nil {
		t.Fatal(err)
	}
	return s, meta.ID
}

func TestEnrichJobRunsAndDedups(t *testing.T) {
	s, id := seedStore(t)
	key := engine.NormalizeUsername("alice", "CORP")
	enr := &countingEnricher{calls: map[string]int{}, data: map[string]engine.Enrichment{
		key: {DADomains: []string{"CORP"}},
	}}
	m := NewManager(newEng(enr), s)
	if err := m.Start(id); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	st := m.Status()
	if st.Phase != PhaseDone || st.Total != 1 || st.Processed != 1 || st.Enriched != 1 {
		t.Fatalf("status = %+v", st)
	}
	if enr.calls[key] != 1 {
		t.Fatalf("expected 1 dedup'd lookup, got %d", enr.calls[key])
	}
	got, _ := s.Accounts(id, false)
	if got[0].DADomains != "CORP" {
		t.Fatalf("accounts not enriched: DA=%q", got[0].DADomains)
	}
}

func TestEnrichJobFailsWithoutEnricher(t *testing.T) {
	s, id := seedStore(t)
	m := NewManager(newEng(nil), s)
	if err := m.Start(id); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if m.Status().Phase != PhaseFailed {
		t.Fatalf("phase = %s, want failed", m.Status().Phase)
	}
}

func TestEnrichJobDoubleStart(t *testing.T) {
	s, id := seedStore(t)
	block := make(chan struct{})
	enr := &countingEnricher{calls: map[string]int{}, data: map[string]engine.Enrichment{}}
	// make Enrich block so the first job is still running for the second Start.
	slow := slowEnricher{inner: enr, gate: block}
	m := NewManager(newEng(slow), s)
	if err := m.Start(id); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(id); err == nil {
		t.Fatal("second Start should error while running")
	}
	close(block)
	m.Wait()
}

type slowEnricher struct {
	inner engine.Enricher
	gate  chan struct{}
}

func (s slowEnricher) Enrich(u string) engine.Enrichment {
	<-s.gate
	return s.inner.Enrich(u)
}

func TestEnrichJobActivityHook(t *testing.T) {
	s, id := seedStore(t)
	var held atomic.Int32
	enr := &countingEnricher{calls: map[string]int{}, data: map[string]engine.Enrichment{}}
	m := NewManager(newEng(enr), s)
	m.ActivityHook = func() func() {
		held.Add(1)
		return func() { held.Add(-1) }
	}
	if err := m.Start(id); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	// settle the deferred release
	time.Sleep(10 * time.Millisecond)
	if held.Load() != 0 {
		t.Fatalf("activity hook not released, held=%d", held.Load())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/enrich/ -v`
Expected: FAIL — package/types undefined.

- [ ] **Step 3: Implement the manager**

`internal/enrich/job.go`:
```go
// Package enrich runs BloodHound enrichment for an audit as a single background
// job: prefetch BHE for every distinct username concurrently, then re-score the
// stored accounts atomically. Mirrors internal/pwned's job manager.
package enrich

import (
	"context"
	"errors"
	"sort"
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

// JobStatus is the snapshot the UI polls.
type JobStatus struct {
	Phase      Phase  `json:"phase"`
	AuditID    string `json:"audit_id,omitempty"`
	Processed  int    `json:"processed"`
	Total      int    `json:"total"`
	Enriched   int    `json:"enriched"`
	StartedAt  string `json:"started_at,omitempty"`
	ElapsedSec int64  `json:"elapsed_sec"`
	Error      string `json:"error,omitempty"`
}

// mapEnricher serves prefetched enrichment from memory (no network).
type mapEnricher map[string]engine.Enrichment

func (m mapEnricher) Enrich(username string) engine.Enrichment { return m[username] }

// Manager runs at most one enrichment job at a time (per server).
type Manager struct {
	eng   *engine.Engine
	store *store.Store

	// Concurrency sizes the prefetch worker pool (default 8). The BHE client's
	// own semaphore is the hard bound on in-flight requests.
	Concurrency int
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
	enriched  int
	startedAt time.Time
	errMsg    string
	cancel    context.CancelFunc
	done      chan struct{}
}

// NewManager builds an enrichment job runner over an engine + store.
func NewManager(eng *engine.Engine, st *store.Store) *Manager {
	return &Manager{eng: eng, store: st, phase: PhaseIdle}
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Start launches enrichment for an audit. Errors if a job is already running.
func (m *Manager) Start(auditID string) error {
	m.mu.Lock()
	if m.phase == PhaseRunning {
		m.mu.Unlock()
		return errors.New("enrichment already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.phase = PhaseRunning
	m.auditID = auditID
	m.processed, m.total, m.enriched = 0, 0, 0
	m.errMsg = ""
	m.startedAt = m.now()
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
		return errors.New("no enrichment running")
	}
	m.cancel()
	return nil
}

func (m *Manager) run(ctx context.Context, id string) {
	defer m.closeDone()
	if m.ActivityHook != nil {
		release := m.ActivityHook()
		defer release()
	}

	enr := m.eng.CurrentEnricher()
	if enr == nil {
		m.finish(PhaseFailed, "BloodHound enrichment is not configured")
		return
	}
	accts, err := m.store.Accounts(id, true)
	if err != nil {
		m.finish(PhaseFailed, "load accounts: "+err.Error())
		return
	}

	// distinct normalized usernames (deterministic order)
	seen := map[string]struct{}{}
	users := make([]string, 0, len(accts))
	for _, a := range accts {
		u := engine.NormalizeUsername(a.Username, a.Domain)
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			users = append(users, u)
		}
	}
	sort.Strings(users)
	m.setTotal(len(users))

	result := make(map[string]engine.Enrichment, len(users))
	var resMu sync.Mutex
	conc := m.Concurrency
	if conc <= 0 {
		conc = 8
	}
	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				if ctx.Err() != nil {
					return
				}
				e := enr.Enrich(u)
				resMu.Lock()
				result[u] = e
				resMu.Unlock()
				m.tick(hasData(e))
			}
		}()
	}
	for _, u := range users {
		if ctx.Err() != nil {
			break
		}
		jobs <- u
	}
	close(jobs)
	wg.Wait()

	if ctx.Err() != nil {
		m.finish(PhaseCancelled, "")
		return
	}
	rescored := m.eng.RescoreWith(accts, mapEnricher(result))
	if err := m.store.Replace(id, model.Dataset{Accounts: rescored}); err != nil {
		m.finish(PhaseFailed, "save: "+err.Error())
		return
	}
	m.finish(PhaseDone, "")
}

// hasData reports whether an enrichment actually carries BHE data.
func hasData(e engine.Enrichment) bool {
	return e.ControlledObjects != nil || e.Enabled != nil ||
		e.PwdNeverExpires != nil || e.PwdLastSet != nil || len(e.DADomains) > 0
}

func (m *Manager) setTotal(n int) {
	m.mu.Lock()
	m.total = n
	m.mu.Unlock()
}

func (m *Manager) tick(enriched bool) {
	m.mu.Lock()
	m.processed++
	if enriched {
		m.enriched++
	}
	m.mu.Unlock()
}

func (m *Manager) finish(p Phase, msg string) {
	m.mu.Lock()
	m.phase = p
	m.errMsg = msg
	m.mu.Unlock()
}

func (m *Manager) closeDone() {
	m.mu.Lock()
	if m.done != nil {
		close(m.done)
	}
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
		Enriched:  m.enriched,
		Error:     m.errMsg,
	}
	if !m.startedAt.IsZero() {
		st.StartedAt = m.startedAt.UTC().Format(time.RFC3339)
		end := m.now()
		st.ElapsedSec = int64(end.Sub(m.startedAt).Seconds())
	}
	return st
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/enrich/ -v`
Expected: PASS (all four). Then `gofmt -l internal/enrich` and `go vet ./internal/enrich/`.

- [ ] **Step 5: Commit**

```bash
git add internal/enrich/
git commit -m "feat(enrich): background enrichment job (concurrent prefetch -> atomic rescore)"
```

---

## Task 5: API — endpoints, auto-start, activity hook, no-inline-BHE uploads

**Files:**
- Modify: `internal/httpapi/server.go` (Server struct, routes, `handleAudit`, `handleApplyCracks`, new handlers)
- Test: `internal/httpapi/server_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestEnrichEndpointLeadOnlyAndJob(t *testing.T) {
	srv := newUnlockedTestServer(t) // existing helper that yields a lead session + active audit with accounts
	// analyst -> 403
	if code, _ := srv.do(t, "POST", "/api/enrich", analystSession, nil); code != http.StatusForbidden {
		t.Fatalf("analyst POST /api/enrich = %d, want 403", code)
	}
	// lead -> 200 and a job is reported
	if code, _ := srv.do(t, "POST", "/api/enrich", leadSession, nil); code != http.StatusOK {
		t.Fatalf("lead POST /api/enrich = %d, want 200", code)
	}
	code, body := srv.do(t, "GET", "/api/enrich/job", leadSession, nil)
	if code != http.StatusOK || !strings.Contains(body, `"phase"`) {
		t.Fatalf("GET /api/enrich/job = %d %s", code, body)
	}
}
```
Adapt to the existing `server_test.go` harness (session/helper names). If no `newUnlockedTestServer`/`do` helper exists, follow the pattern already used by the upload/ingests tests in that file (they build a `Server`, seed a store, set sessions, and call handlers via `httptest`). Reuse exactly that scaffolding.

Also extend the existing auto-lock test (the one at `server_test.go:~549`) with a variant asserting that while `Enrich` reports `running` and the activity hook is held, `shouldAutoLock(...)`/the lock loop does not fire (inFlight > 0).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/httpapi/ -run TestEnrichEndpoint -v`
Expected: FAIL — routes/handlers undefined.

- [ ] **Step 3: Implement**

(a) Add the field to `Server` (near `Downloads`):
```go
	Enrich        *enrich.Manager // background BloodHound enrichment job (may be nil)
```
Import `"github.com/watson0x90/PasswordAtTheDisco/internal/enrich"`.

(b) Register routes (next to the pwned job routes):
```go
	mux.Handle("POST /api/enrich", s.requireAuth(s.requireCSRF(s.requireUnlocked(http.HandlerFunc(s.handleEnrichStart)))))
	mux.Handle("GET /api/enrich/job", s.requireAuth(http.HandlerFunc(s.handleEnrichJob)))
	mux.Handle("POST /api/enrich/cancel", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleEnrichCancel))))
```

(c) Handlers (mirror `handlePwnedJob`/`handlePwnedCancel`, lead-only):
```go
func (s *Server) handleEnrichStart(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.Enrich == nil || s.Engine == nil || !s.Engine.HasEnricher() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "BloodHound enrichment is not configured"})
		return
	}
	auditID, ok := s.activeAudit(w, sess)
	if !ok {
		return
	}
	if err := s.Enrich.Start(auditID); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "enrich_start", Target: auditID, Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, s.Enrich.Status())
}

func (s *Server) handleEnrichJob(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.Enrich == nil {
		writeJSON(w, http.StatusOK, enrich.JobStatus{Phase: enrich.PhaseIdle})
		return
	}
	writeJSON(w, http.StatusOK, s.Enrich.Status())
}

func (s *Server) handleEnrichCancel(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.Enrich == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "enrichment not configured"})
		return
	}
	err := s.Enrich.Cancel()
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "enrich_cancel", Source: r.RemoteAddr, Result: okOr(err)})
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, s.Enrich.Status())
}
```

(d) Upload no longer enriches inline + auto-kicks. In `handleAudit`, change the scoring call:
```go
	accts := s.Engine.ProcessDomainNoEnrich(domain, cracked, uncracked)
```
and after the existing `RecordIngest` block, before the audit-log line, add:
```go
	s.kickEnrich(auditID)
```

(e) In `handleApplyCracks`, change `rescored := s.Engine.Rescore(accounts)` to:
```go
	rescored := s.Engine.RescoreWith(accounts, nil)
```
and after its `RecordIngest` block add `s.kickEnrich(auditID)`.

(f) Add the helper:
```go
// kickEnrich auto-starts BloodHound enrichment for an audit if BHE is configured.
// Best-effort and non-blocking: an already-running job just returns an error we
// ignore (manual re-run covers it).
func (s *Server) kickEnrich(auditID string) {
	if s.Enrich == nil || s.Engine == nil || !s.Engine.HasEnricher() {
		return
	}
	_ = s.Enrich.Start(auditID)
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/httpapi/ -v`
Expected: PASS. Then `gofmt -l internal/httpapi` and `go vet ./internal/httpapi/`.

- [ ] **Step 5: Commit**

```bash
git add internal/httpapi/server.go internal/httpapi/server_test.go
git commit -m "feat(api): enrich job endpoints; uploads score without inline BHE + auto-kick enrichment"
```

---

## Task 6: Wire the enrich manager in main.go

**Files:**
- Modify: `cmd/patd/main.go`

- [ ] **Step 1: Implement the wiring** (no separate unit test; covered by build + httpapi tests + the live run in Task 10)

After the engine + bloodhound config are available and before building the `httpapi.Server{...}` literal, construct the manager. Locate where the engine is created and where `downloads := pwned.NewManager(...)` is (line ~111).

```go
	enrichMgr := enrich.NewManager(eng, st) // eng = *engine.Engine, st = *store.Store (use the real local names)
	enrichMgr.Concurrency = bhCfg.EnrichConcurrency // bhCfg = the loaded bloodhound.Config; NewManager/Start default to 8 if 0
```
Add to the `httpapi.Server{...}` literal:
```go
		Enrich:        enrichMgr,
```
After the `api := &httpapi.Server{...}` is constructed, wire the activity hook so a running job holds the idle auto-lock open:
```go
	enrichMgr.ActivityHook = func() func() {
		api.HoldActivity() // see Task 6 step 2
		return func() { api.ReleaseActivity() }
	}
```
Import `"github.com/watson0x90/PasswordAtTheDisco/internal/enrich"`.

Note on names: use whatever the file already calls the engine and store locals. If the bloodhound config isn't loaded in `main` (it may be loaded lazily in `handleBHEConfig`), set `enrichMgr.Concurrency = 0` (the manager defaults to 8) and rely on the client semaphore — OR load `bloodhound.LoadConfig(path)` if main already reads it. Keep it minimal: if main has no `bhCfg`, leave `Concurrency` unset (defaults 8).

- [ ] **Step 2: Add the activity-hold helpers to the Server** (`internal/httpapi/server.go`)

```go
// HoldActivity marks a long background op in-flight so the idle auto-lock can't
// fire while it runs; the returned counter is released via ReleaseActivity.
func (s *Server) HoldActivity()    { s.inFlight.Add(1); s.touch() }
func (s *Server) ReleaseActivity() { s.inFlight.Add(-1); s.touch() }
```

- [ ] **Step 3: Build + vet**

Run: `go build ./... && go vet ./...`
Expected: clean.

- [ ] **Step 4: Full backend gate**

Run: `gofmt -l cmd internal && go test ./...`
Expected: gofmt empty; all packages PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/patd/main.go internal/httpapi/server.go
git commit -m "wire(enrich): construct manager, hold auto-lock during a run, set concurrency"
```

---

## Task 7: Web — api wrappers, upload progress, locked gate

**Files:**
- Modify: `web/src/api.ts`
- Modify: `web/src/components/Ingest.tsx`
- Test: `web/src/enrich.test.ts` (new)

- [ ] **Step 1: Write the failing test**

`web/src/enrich.test.ts`:
```ts
import { describe, it, expect, vi, beforeEach } from "vitest"
import { api } from "./api"

describe("enrich api", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn(async () =>
      new Response(JSON.stringify({ phase: "running", processed: 3, total: 10, enriched: 2 }), {
        status: 200, headers: { "Content-Type": "application/json" },
      }),
    ))
  })
  it("enrichJob parses status", async () => {
    const st = await api.enrichJob()
    expect(st.phase).toBe("running")
    expect(st.processed).toBe(3)
    expect(st.total).toBe(10)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run enrich.test.ts`
Expected: FAIL — `api.enrichJob` undefined.

- [ ] **Step 3: Implement api wrappers**

In `web/src/api.ts`, add the type (near `IngestEvent`):
```ts
export interface EnrichJob {
  phase: "idle" | "running" | "done" | "failed" | "cancelled"
  audit_id?: string
  processed: number
  total: number
  enriched: number
  started_at?: string
  elapsed_sec: number
  error?: string
}
```
Add to the `api` object:
```ts
  enrich: (csrf: string) =>
    request<EnrichJob>("/enrich", { method: "POST", headers: { "X-CSRF-Token": csrf } }),
  enrichJob: () => request<EnrichJob>("/enrich/job"),
  enrichCancel: (csrf: string) =>
    request<EnrichJob>("/enrich/cancel", { method: "POST", headers: { "X-CSRF-Token": csrf } }),
```

- [ ] **Step 4: Implement upload-page integration** (`web/src/components/Ingest.tsx`)

Add enrichment-job state + polling, shown after an upload, and gate the upload controls on the unlocked store:

1. Import `EnrichJob` from `../api`.
2. Add state: `const [enrichJob, setEnrichJob] = useState<EnrichJob | null>(null)`.
3. Add a poller that starts after a successful upload/apply and stops at a terminal phase:
```ts
  useEffect(() => {
    if (!enrichJob || enrichJob.phase !== "running") return
    const t = setInterval(async () => {
      try {
        const st = await api.enrichJob()
        setEnrichJob(st)
      } catch { /* keep last */ }
    }, 1500)
    return () => clearInterval(t)
  }, [enrichJob?.phase])
```
4. After `setResult(r); void loadHistory()` in `onSubmit` (and `setApplyResult(r)` in `onApply`), kick a poll: `try { setEnrichJob(await api.enrichJob()) } catch { /* none */ }`.
5. Render below the upload result (and in the apply section): when `enrichJob` is non-null, a small status line:
```tsx
{enrichJob && enrichJob.phase !== "idle" && (
  <div className="hint">
    {enrichJob.phase === "running"
      ? `Enriching with BloodHound… ${enrichJob.processed}/${enrichJob.total}`
      : enrichJob.phase === "done"
        ? `BloodHound enrichment complete — enriched ${enrichJob.enriched}/${enrichJob.total}.`
        : enrichJob.phase === "failed"
          ? `BloodHound enrichment failed: ${enrichJob.error ?? "unknown"}`
          : `BloodHound enrichment ${enrichJob.phase}.`}
  </div>
)}
```
6. **Locked gate:** the page already early-returns for non-lead. Add an early return when the store is locked, using the existing auth/me data (the component reads `me`; the store lock state is on `me.store_unlocked`):
```tsx
  if (me && me.store_unlocked === false) {
    return <div className="center-state">The store is locked. Unlock it (top right) before uploading.</div>
  }
```
(Confirm the `Me` field name is `store_unlocked` — it is, per `api.ts`.)

- [ ] **Step 5: Run tests + typecheck + build**

Run: `cd web && npx vitest run && npx tsc --noEmit && npm run build`
Expected: all PASS / clean.

- [ ] **Step 6: Commit**

```bash
git add web/src/api.ts web/src/components/Ingest.tsx web/src/enrich.test.ts
git commit -m "feat(web): enrich api + upload-page enrichment progress + locked-upload gate"
```

---

## Task 8: Web — "Run BloodHound enrichment" on the Integrations page

**Files:**
- Modify: `web/src/components/Integrations.tsx`

- [ ] **Step 1: Locate the BloodHound section.** Open `web/src/components/Integrations.tsx` and find the BloodHound (BHE) subsection (status/test/config). Identify how it reads `me` (for `csrf_token`) and the active audit (it may use `useAudits()`), mirroring `Ingest.tsx`.

- [ ] **Step 2: Add re-run state + handler.**

```tsx
const [enrichJob, setEnrichJob] = useState<EnrichJob | null>(null)
const [enrichErr, setEnrichErr] = useState("")

useEffect(() => {
  // load any in-progress job on mount
  api.enrichJob().then(setEnrichJob).catch(() => {})
}, [])

useEffect(() => {
  if (!enrichJob || enrichJob.phase !== "running") return
  const t = setInterval(() => { api.enrichJob().then(setEnrichJob).catch(() => {}) }, 1500)
  return () => clearInterval(t)
}, [enrichJob?.phase])

async function runEnrich() {
  if (!me) return
  setEnrichErr("")
  try {
    setEnrichJob(await api.enrich(me.csrf_token))
  } catch (e) {
    setEnrichErr(e instanceof ApiError ? e.message : "could not start enrichment")
  }
}
```
Import `EnrichJob`, `ApiError`, `api`, `useState`, `useEffect` as needed.

- [ ] **Step 3: Render the control** in the BloodHound section (only meaningful when BHE is connected + an audit is active):

```tsx
<div className="field">
  <button type="button" className="btn" onClick={runEnrich}
          disabled={enrichJob?.phase === "running"}>
    {enrichJob?.phase === "running" ? "Enriching…" : "Run BloodHound enrichment on this audit"}
  </button>
  {enrichErr && <div className="error">{enrichErr}</div>}
  {enrichJob && enrichJob.phase !== "idle" && (
    <div className="hint">
      {enrichJob.phase === "running"
        ? `Enriching… ${enrichJob.processed}/${enrichJob.total}`
        : enrichJob.phase === "done"
          ? `Done — enriched ${enrichJob.enriched}/${enrichJob.total}.`
          : enrichJob.phase === "failed"
            ? `Failed: ${enrichJob.error ?? "unknown"}`
            : enrichJob.phase}
    </div>
  )}
</div>
```

- [ ] **Step 4: Typecheck + build**

Run: `cd web && npx tsc --noEmit && npm run build && npx vitest run`
Expected: clean / PASS.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/Integrations.tsx
git commit -m "feat(web): re-run BloodHound enrichment from the Integrations page"
```

---

## Task 9: README note

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add a "What's new" bullet** under the existing 2.5 section:

```markdown
- **Fast uploads + background enrichment.** Dump uploads now return in seconds —
  they parse, HIBP-score, and store immediately. BloodHound DA-pathway enrichment
  runs as a separate background job (concurrent, cancelable) that auto-starts
  after an upload and can be re-run from **Integrations → BloodHound**. Previously
  a large dump could block the request for tens of minutes.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: note fast uploads + background BloodHound enrichment"
```

---

## Task 10: Full gate + live verification

- [ ] **Step 1: Full automated gate**

Run:
```bash
gofmt -l cmd internal
go build ./... && go vet ./... && go test ./...
cd web && npx tsc --noEmit && npm run build && npx vitest run
cd .. && govulncheck ./...
```
Expected: gofmt empty; all Go packages PASS; tsc clean; web build OK; vitest PASS; govulncheck clean.

- [ ] **Step 2: Rebuild the embedded binary + live run**

```bash
cp -r web/dist internal/webui/dist
CGO_ENABLED=0 go build -tags embed -trimpath -ldflags="-s -w" -o patd.exe ./cmd/patd
```
Restart the server, unlock, create a throwaway audit, and upload `sample_data/GHOST.CORP_uncracked.txt`:
- Upload returns immediately with the ✓ result.
- The enrichment status line appears (running → done) without blocking the page.
- `GET /api/enrich/job` returns `done` with `processed == total`.
- Confirm no secrets in the job status (grep the response for `password`/`nt_hash` → none).
- Delete the throwaway audit.

- [ ] **Step 3: Final commit (if dist/binary tracked changes)** — only if `internal/webui/dist` is tracked; otherwise skip. Do **not** commit `patd.exe` (gitignored).

---

## Self-review checklist (completed during planning)

- **Spec coverage:** semaphore (T1) · domains cache (T2) · explicit enricher/no-inline upload (T3, T5) · job manager + prefetch/memoize/cancel/atomic rescore (T4) · endpoints + auto-start + apply-cracks (T5) · auto-lock hold (T4 hook + T6) · wiring/config (T6) · web progress + locked gate (T7) · re-run menu (T8) · README (T9). All spec sections map to a task.
- **Type consistency:** `JobStatus`/`EnrichJob` fields match (phase, audit_id, processed, total, enriched, started_at, elapsed_sec, error). `Enricher`/`mapEnricher`/`RescoreWith`/`ProcessDomainNoEnrich`/`NormalizeUsername`/`CurrentEnricher` names used identically across T3–T6. Routes `/api/enrich`, `/api/enrich/job`, `/api/enrich/cancel` match between T5 and T7/T8.
- **Placeholder scan:** no TBD/"handle errors"-style gaps; the two intentional "use the file's existing local names / test harness" notes (T5 step1, T6) are adaptation guidance, not missing logic. All code blocks are ASCII-clean.
