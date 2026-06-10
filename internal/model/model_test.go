package model

import (
	"strings"
	"testing"
)

func TestPostureScoreGolden(t *testing.T) {
	// Pins the formula; web/src/insights.ts:posture() must match. 2 accounts:
	// 1 Critical cracked+breached non-compliant, 1 Low cracked compliant.
	p := PostureScore([]Account{
		{RiskLevel: "Critical", Cracked: true, HIBPBreached: true, MeetsPolicy: false},
		{RiskLevel: "Low", Cracked: true, MeetsPolicy: true},
	})
	// risk: max(0,100-(1/2)*200)=0 ; strength 0 ; priv 15 ; compliance (2-1)/2*15=7.5
	if p.Score != 22.5 || p.Rating != "Weak" {
		t.Fatalf("posture = %.1f %s, want 22.5 Weak", p.Score, p.Rating)
	}
	if p.Breakdown != (PostureBreakdown{Risk: 0, Strength: 0, Privilege: 15, Compliance: 7.5}) {
		t.Fatalf("breakdown = %+v, want {0 0 15 7.5}", p.Breakdown)
	}

	// Second golden with NON-ZERO risk + strength, so coefficient drift in either
	// (which the all-zero fixture above would miss) is caught. 5 accounts: 1 Crit
	// cracked non-compliant, 1 High cracked compliant, 3 Low uncracked.
	//   risk = (100 - 1/5*200 - 1/5*150)/100*40 = 12 ; strength = 3/5*30 = 18 ;
	//   privilege 15 ; compliance = (5-1)/5*15 = 12  -> score 57 Weak
	p2 := PostureScore([]Account{
		{RiskLevel: "Critical", Cracked: true, MeetsPolicy: false},
		{RiskLevel: "High", Cracked: true, MeetsPolicy: true},
		{RiskLevel: "Low", Cracked: false},
		{RiskLevel: "Low", Cracked: false},
		{RiskLevel: "Low", Cracked: false},
	})
	if p2.Score != 57 || p2.Rating != "Weak" {
		t.Fatalf("posture2 = %.1f %s, want 57 Weak", p2.Score, p2.Rating)
	}
	if p2.Breakdown != (PostureBreakdown{Risk: 12, Strength: 18, Privilege: 15, Compliance: 12}) {
		t.Fatalf("breakdown2 = %+v, want {12 18 15 12}", p2.Breakdown)
	}
}

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
