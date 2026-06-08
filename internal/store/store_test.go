package store

import (
	"testing"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/vault"
)

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
