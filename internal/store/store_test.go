package store

import (
	"testing"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
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
	id := s.CreateAudit("test", "").ID
	if err := s.Replace(id, sample()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return id
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
	a := s.CreateAudit("Engagement A", "client A")
	b := s.CreateAudit("Engagement B", "")
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

func TestReplaceDomainScoped(t *testing.T) {
	s := New()
	id := s.CreateAudit("x", "").ID
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
