package rescore

import (
	"strings"
	"testing"

	"github.com/watson0x90/PasswordAtTheDisco/internal/engine"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/policy"
	"github.com/watson0x90/PasswordAtTheDisco/internal/pwanalysis"
	"github.com/watson0x90/PasswordAtTheDisco/internal/store"
)

// newJobEngine builds a minimal functional engine for the job tests (mirror the
// newTestEngine() constructor in enricher_test.go — Policies + Lists, since the
// cracked-account path exercises the wordlist matcher).
func newJobEngine() *engine.Engine {
	return &engine.Engine{
		Lists:    pwanalysis.Lists{CommonPasswords: pwanalysis.NewSet("welcome1")},
		Policies: policy.DefaultSet(),
	}
}

func seedJobStore(t *testing.T, accts []model.Account) (*store.Store, string) {
	t.Helper()
	s := store.New()
	meta, err := s.CreateAudit("t", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceDomain(meta.ID, "CORP", accts); err != nil {
		t.Fatal(err)
	}
	return s, meta.ID
}

func TestRescoreJobReachesDoneAndRecordsIngest(t *testing.T) {
	s, id := seedJobStore(t, []model.Account{
		{Username: "a", Domain: "CORP", NTHash: "H1", Password: "password1", Cracked: true, Coverage: "none"},
	})
	m := NewManager(newJobEngine(), s)
	if err := m.Start(id); err != nil {
		t.Fatalf("Start: %v", err)
	}
	m.Wait()
	st := m.Status()
	if st.Phase != PhaseDone {
		t.Fatalf("phase = %q want done (err=%q)", st.Phase, st.Error)
	}
	if st.Processed != 1 {
		t.Fatalf("processed = %d want 1", st.Processed)
	}
	evs, err := s.Ingests(id)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range evs {
		if e.Kind == "rescore" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a rescore IngestEvent, got %+v", evs)
	}
}

func TestRescoreJobDoubleStartRejected(t *testing.T) {
	s, id := seedJobStore(t, []model.Account{{Username: "a", Domain: "CORP", Coverage: "none"}})
	m := NewManager(newJobEngine(), s)
	// ActivityHook blocks the run goroutine at entry, so the job stays in the
	// running phase deterministically until we release the gate.
	gate := make(chan struct{})
	m.ActivityHook = func() func() { <-gate; return func() {} }
	if err := m.Start(id); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if err := m.Start(id); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second Start must error with 'already running' while running, got %v", err)
	}
	close(gate)
	m.Wait()
}

func TestRescoreJobCancel(t *testing.T) {
	s, id := seedJobStore(t, []model.Account{{Username: "a", Domain: "CORP", Coverage: "none"}})
	m := NewManager(newJobEngine(), s)
	gate := make(chan struct{})
	m.ActivityHook = func() func() { <-gate; return func() {} }
	if err := m.Start(id); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := m.Cancel(); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	close(gate) // unblock run; it must see the cancelled ctx BEFORE Mutate and finish cancelled
	m.Wait()
	if m.Status().Phase != PhaseCancelled {
		t.Fatalf("phase = %s want cancelled", m.Status().Phase)
	}
}
