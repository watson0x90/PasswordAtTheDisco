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

// JobStatus is the snapshot the UI polls (shape mirrors enrich.JobStatus, minus
// the per-user Enriched counter -- rescore has no per-user enrichment step).
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

// Manager runs at most one rescore job at a time (per server). It re-scores the
// active audit against the current policy/wordlists/HIBP using a StoredEnricher
// (no BloodHound network), preserving each account's existing Impact.
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

// Running reports whether a job is in the running phase (used by the rescore
// endpoint and to coordinate with enrichment).
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

// Cancel cooperatively stops a running job (honored only before the Mutate
// commits; once the rescore is written it is not undone).
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
	if err := m.store.Mutate(id, func(current []model.Account) []model.Account {
		rescored := m.eng.RescoreWith(current, NewStoredEnricher(current))
		m.mu.Lock()
		m.processed = len(rescored)
		m.mu.Unlock()
		return rescored
	}); err != nil {
		m.finish(PhaseFailed, "save: "+err.Error())
		return
	}
	// Metadata-only event for the "last recalculated" stamp (never a credential).
	_ = m.store.RecordIngest(id, model.IngestEvent{
		Kind: "rescore", AccountsLoaded: m.processed, At: m.now().UTC(), By: "system",
	})
	// A cancel that lands after the Mutate commits cannot un-write the rescore, so
	// we report Done -- but note it (in message, not error) so a poll right after
	// Cancel isn't confusing.
	if ctx.Err() != nil {
		m.setMessage("cancel received after commit -- rescore was already written")
	} else {
		m.setMessage("")
	}
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
