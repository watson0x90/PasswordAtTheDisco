package enrich

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/engine"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/policy"
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
	e := &engine.Engine{Policies: policy.DefaultSet()}
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

type slowEnricher struct {
	inner engine.Enricher
	gate  chan struct{}
}

func (s slowEnricher) Enrich(u string) engine.Enrichment {
	<-s.gate
	return s.inner.Enrich(u)
}

func TestEnrichJobDoubleStart(t *testing.T) {
	s, id := seedStore(t)
	block := make(chan struct{})
	enr := &countingEnricher{calls: map[string]int{}, data: map[string]engine.Enrichment{}}
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

func TestEnrichJobCancel(t *testing.T) {
	s, id := seedStore(t)
	gate := make(chan struct{})
	enr := &countingEnricher{calls: map[string]int{}, data: map[string]engine.Enrichment{}}
	m := NewManager(newEng(slowEnricher{inner: enr, gate: gate}), s)
	if err := m.Start(id); err != nil {
		t.Fatal(err)
	}
	if err := m.Cancel(); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	close(gate) // let the blocked worker(s) drain
	m.Wait()
	if m.Status().Phase != PhaseCancelled {
		t.Fatalf("phase = %s, want cancelled", m.Status().Phase)
	}
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
	time.Sleep(10 * time.Millisecond)
	if held.Load() != 0 {
		t.Fatalf("activity hook not released, held=%d", held.Load())
	}
}

func TestEnrichDoesNotClobberMidRunUpload(t *testing.T) {
	s, id := seedStore(t)
	gate := make(chan struct{})
	key := engine.NormalizeUsername("alice", "CORP")
	enr := &countingEnricher{calls: map[string]int{}, data: map[string]engine.Enrichment{key: {DADomains: []string{"CORP"}}}}
	m := NewManager(newEng(slowEnricher{inner: enr, gate: gate}), s)
	if err := m.Start(id); err != nil {
		t.Fatal(err)
	}
	// Give the worker goroutine time to block on the gate before we upload EU.
	// This ensures the job's initial snapshot (alice/CORP only) is taken BEFORE
	// bob/EU is added, so the stale-overwrite bug is reliably triggered.
	time.Sleep(20 * time.Millisecond)
	if err := s.ReplaceDomain(id, "EU", []model.Account{{Username: "bob", Domain: "EU", NTHash: "H9"}}); err != nil {
		t.Fatal(err)
	}
	close(gate)
	m.Wait()
	for i := 0; i < 50 && m.Status().Phase == PhaseRunning; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	m.Wait()
	got, _ := s.Accounts(id, false)
	doms := map[string]bool{}
	for _, a := range got {
		doms[a.Domain] = true
	}
	if !doms["CORP"] || !doms["EU"] {
		t.Fatalf("lost a domain: have %v, want CORP+EU", doms)
	}
}
