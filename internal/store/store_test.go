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

func TestAccountsRedactedByDefault(t *testing.T) {
	s := New()
	s.Replace(sample())
	for _, a := range s.Accounts(false) {
		if a.Password != "" {
			t.Fatalf("redacted account leaked a password: %q", a.Password)
		}
	}
}

func TestAccountsWithSecrets(t *testing.T) {
	s := New()
	s.Replace(sample())
	if got := s.Accounts(true)[0].Password; got != "Welcome1" {
		t.Fatalf("includeSecrets should keep password, got %q", got)
	}
}

func TestRedactedReadDoesNotMutateStore(t *testing.T) {
	s := New()
	s.Replace(sample())
	_ = s.Accounts(false) // a redacted read must not zero the stored value
	if got := s.Accounts(true)[0].Password; got != "Welcome1" {
		t.Fatalf("redacted read mutated stored password: %q", got)
	}
}

func TestSummary(t *testing.T) {
	s := New()
	s.Replace(sample())
	sum := s.Summary()
	if sum.TotalAccounts != 2 || sum.Cracked != 1 || sum.HIBPBreached != 1 || sum.DAPathways != 1 {
		t.Fatalf("unexpected summary: %+v", sum)
	}
	if sum.RiskCounts["Critical"] != 1 || sum.RiskCounts["Low"] != 1 {
		t.Fatalf("unexpected risk counts: %+v", sum.RiskCounts)
	}
}
