package model

import (
	"strings"
	"testing"
)

func TestRecomputeSharingCrossDomain(t *testing.T) {
	accts := []Account{
		{Username: "a", Domain: "CORP", Password: "Reused1", Cracked: true},
		{Username: "b", Domain: "LEGACY", Password: "Reused1", Cracked: true}, // different domain, same pw
		{Username: "c", Domain: "CORP", Password: "Unique1", Cracked: true},
	}
	RecomputeSharing(accts)
	if accts[0].SharedWith != 1 || accts[1].SharedWith != 1 {
		t.Fatalf("cross-domain reuse not counted: a=%d b=%d", accts[0].SharedWith, accts[1].SharedWith)
	}
	if accts[2].SharedWith != 0 {
		t.Fatalf("unique password should have 0 shared, got %d", accts[2].SharedWith)
	}
}

func TestEscalateSharedWithDACrossDomain(t *testing.T) {
	accts := []Account{
		{Username: "da", Domain: "PARENT", Password: "Shared1", Cracked: true, DADomains: "PARENT", RiskLevel: "Critical"},
		{Username: "helpdesk", Domain: "SUB", Password: "Shared1", Cracked: true, RiskLevel: "Low"}, // other domain
		{Username: "alice", Domain: "SUB", Password: "Unique1", Cracked: true, RiskLevel: "Low"},
	}
	EscalateSharedWithDA(accts)
	if accts[1].RiskLevel != "Critical" || !strings.Contains(accts[1].RiskVector, "SHARED-DA") {
		t.Fatalf("cross-domain DA reuse not escalated: %+v", accts[1])
	}
	if accts[2].RiskLevel == "Critical" {
		t.Fatal("unique-password account must not be escalated")
	}
	// idempotent: a second pass must not duplicate the marker
	before := accts[1].RiskVector
	EscalateSharedWithDA(accts)
	if accts[1].RiskVector != before {
		t.Fatalf("escalation not idempotent: %q -> %q", before, accts[1].RiskVector)
	}
}
