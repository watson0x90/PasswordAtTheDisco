package store

import (
	"fmt"
	"testing"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/vault"
)

func TestLazyLoadAndEviction(t *testing.T) {
	dir := t.TempDir()
	v, _ := vault.Open(dir)
	s := NewPersistent(v)
	s.cap = 2 // tiny cache to force eviction
	if err := s.Initialize("a-strong-passphrase"); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for i := 0; i < 5; i++ {
		m, err := s.CreateAudit(fmt.Sprintf("Audit %d", i), "")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Replace(m.ID, model.Dataset{Accounts: []model.Account{{Username: fmt.Sprintf("u%d", i), Domain: "D", Cracked: true}}}); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, m.ID)
	}
	// cache is bounded; index holds all
	s.mu.Lock()
	cached, indexed := len(s.cache), len(s.index)
	s.mu.Unlock()
	if cached > s.cap {
		t.Fatalf("cache should be bounded to %d, got %d", s.cap, cached)
	}
	if indexed != 5 {
		t.Fatalf("index should hold all 5, got %d", indexed)
	}
	// every audit is still readable (evicted ones lazily re-decrypt)
	for i, id := range ids {
		accts, err := s.Accounts(id, true)
		if err != nil || len(accts) != 1 || accts[0].Username != fmt.Sprintf("u%d", i) {
			t.Fatalf("audit %d not readable after eviction: %v %+v", i, err, accts)
		}
	}
	// reopen: the persisted index means List works WITHOUT a full migration
	s2 := NewPersistent(mustReopen(t, dir))
	if err := s2.Unlock("a-strong-passphrase"); err != nil {
		t.Fatal(err)
	}
	if len(s2.List()) != 5 {
		t.Fatalf("reopened List = %d, want 5", len(s2.List()))
	}
	if accts, err := s2.Accounts(ids[2], true); err != nil || accts[0].Username != "u2" {
		t.Fatalf("reopen lazy read: %v %+v", err, accts)
	}
}

func sample() model.Dataset {
	return model.Dataset{Accounts: []model.Account{
		{Username: "alice", Domain: "CORP", Password: "Welcome1", Cracked: true,
			RiskLevel: "Critical", HIBPBreached: true, DADomains: "CORP"},
		{Username: "bob", Domain: "CORP", Cracked: false, RiskLevel: "Low", DADomains: "None"},
	}}
}

// seed creates an audit and loads the sample dataset into it, returning its id.
func seed(t *testing.T, s *Store) string {
	t.Helper()
	m, err := s.CreateAudit("test", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Replace(m.ID, sample()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return m.ID
}

func TestAccountsRedactedByDefault(t *testing.T) {
	s := New()
	id := seed(t, s)
	accts, _ := s.Accounts(id, false)
	for _, a := range accts {
		if a.Password != "" {
			t.Fatalf("redacted account leaked a password: %q", a.Password)
		}
	}
}

func TestAccountsWithSecrets(t *testing.T) {
	s := New()
	id := seed(t, s)
	accts, _ := s.Accounts(id, true)
	if accts[0].Password != "Welcome1" {
		t.Fatalf("includeSecrets should keep password, got %q", accts[0].Password)
	}
}

func TestRedactedReadDoesNotMutateStore(t *testing.T) {
	s := New()
	id := seed(t, s)
	_, _ = s.Accounts(id, false) // a redacted read must not zero the stored value
	accts, _ := s.Accounts(id, true)
	if accts[0].Password != "Welcome1" {
		t.Fatalf("redacted read mutated stored password: %q", accts[0].Password)
	}
}

func TestSummary(t *testing.T) {
	s := New()
	id := seed(t, s)
	sum, err := s.Summary(id)
	if err != nil {
		t.Fatal(err)
	}
	if sum.TotalAccounts != 2 || sum.Cracked != 1 || sum.HIBPBreached != 1 || sum.DAPathways != 1 {
		t.Fatalf("unexpected summary: %+v", sum)
	}
	if sum.RiskCounts["Critical"] != 1 || sum.RiskCounts["Low"] != 1 {
		t.Fatalf("unexpected risk counts: %+v", sum.RiskCounts)
	}
}

func TestAuditsIsolatedAndListed(t *testing.T) {
	s := New()
	a, _ := s.CreateAudit("Engagement A", "client A")
	b, _ := s.CreateAudit("Engagement B", "")
	if err := s.Replace(a.ID, sample()); err != nil {
		t.Fatal(err)
	}
	// b stays empty; a has 2 accounts -- isolation
	sa, _ := s.Summary(a.ID)
	sb, _ := s.Summary(b.ID)
	if sa.TotalAccounts != 2 || sb.TotalAccounts != 0 {
		t.Fatalf("audits not isolated: a=%d b=%d", sa.TotalAccounts, sb.TotalAccounts)
	}
	if len(s.List()) != 2 {
		t.Fatalf("List should return 2 audits, got %d", len(s.List()))
	}
	// delete + missing-id errors
	if !s.Delete(b.ID) || s.Has(b.ID) {
		t.Fatal("delete failed")
	}
	if _, err := s.Summary(b.ID); err != ErrNotFound {
		t.Fatalf("deleted audit should be ErrNotFound, got %v", err)
	}
}

func TestPersistentRoundTrip(t *testing.T) {
	dir := t.TempDir()
	v, _ := vault.Open(dir)
	s := NewPersistent(v)
	if s.Unlocked() {
		t.Fatal("persistent store should start locked")
	}
	if err := s.Initialize("a-strong-passphrase"); err != nil { // first run, unlocks
		t.Fatalf("initialize: %v", err)
	}
	m, err := s.CreateAudit("Engagement", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Replace(m.ID, sample()); err != nil {
		t.Fatal(err)
	}

	// Reopen from disk: locked until the correct passphrase, then data is back.
	s2 := NewPersistent(mustReopen(t, dir))
	if s2.Unlocked() {
		t.Fatal("reopened store should be locked")
	}
	if err := s2.Unlock("wrong"); err == nil {
		t.Fatal("wrong passphrase should fail")
	}
	if err := s2.Unlock("a-strong-passphrase"); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	sum, err := s2.Summary(m.ID)
	if err != nil || sum.TotalAccounts != 2 {
		t.Fatalf("data not persisted across reopen: %v %+v", err, sum)
	}
}

func mustReopen(t *testing.T, dir string) *vault.Vault {
	t.Helper()
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestReplaceDomainScoped(t *testing.T) {
	s := New()
	idm, _ := s.CreateAudit("x", "")
	id := idm.ID
	_ = s.Replace(id, sample()) // CORP: alice, bob
	// upsert CORP -> replaces both CORP accounts with one
	if err := s.ReplaceDomain(id, "CORP", []model.Account{{Username: "carol", Domain: "CORP", Cracked: true, RiskLevel: "High"}}); err != nil {
		t.Fatal(err)
	}
	accts, _ := s.Accounts(id, false)
	if len(accts) != 1 || accts[0].Username != "carol" {
		t.Fatalf("ReplaceDomain did not replace CORP set: %+v", accts)
	}
	if err := s.ReplaceDomain("nope", "CORP", nil); err != ErrNotFound {
		t.Fatalf("ReplaceDomain on missing audit should error, got %v", err)
	}
}
