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
