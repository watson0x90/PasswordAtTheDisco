package model

import "testing"

// hashA/hashB are arbitrary distinct NT hashes; hashDA is shared by a DA-pathway
// account and a normal one (cross-account reuse reaching DA).
const (
	hashA  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	hashB  = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	hashDA = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
)

func TestBuildReport(t *testing.T) {
	accts := []Account{
		// cracked password "Summer2024!" shared by two users across two domains
		{Username: "alice", Domain: "CORP", NTHash: hashA, Password: "Summer2024!", PasswordLength: 11, Cracked: true, RiskScore: 9, HIBPBreachCount: 1500},
		{Username: "bob", Domain: "SUB", NTHash: hashA, Password: "Summer2024!", PasswordLength: 11, Cracked: true, RiskScore: 7, HIBPBreachCount: 1500},
		// uncracked hash shared by three users (no password known)
		{Username: "carol", Domain: "CORP", NTHash: hashB, Cracked: false, RiskScore: 5},
		{Username: "dave", Domain: "CORP", NTHash: hashB, Cracked: false, RiskScore: 5},
		{Username: "erin", Domain: "SUB", NTHash: hashB, Cracked: false, RiskScore: 5},
		// uncracked but in HIBP, and reaches a DA pathway; shared with a DA-less account
		{Username: "svc", Domain: "CORP", NTHash: hashDA, Cracked: false, RiskScore: 8, HIBPBreachCount: 42, DADomains: "CORP"},
		{Username: "temp", Domain: "CORP", NTHash: hashDA, Cracked: false, RiskScore: 6, HIBPBreachCount: 42},
		// a singleton (no reuse) -- must not appear in any reuse group
		{Username: "lonely", Domain: "CORP", NTHash: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD0", Cracked: false, RiskScore: 3},
	}

	rep := BuildReport(accts)

	if rep.TotalAccounts != 8 {
		t.Errorf("TotalAccounts = %d, want 8", rep.TotalAccounts)
	}
	if rep.CrackedCount != 2 {
		t.Errorf("CrackedCount = %d, want 2", rep.CrackedCount)
	}
	if len(rep.Cracked) != 2 {
		t.Errorf("Cracked rows = %d, want 2", len(rep.Cracked))
	}
	// Cracked list sorted by risk desc -> alice (9) first
	if rep.Cracked[0].Username != "alice" {
		t.Errorf("Cracked[0] = %s, want alice", rep.Cracked[0].Username)
	}

	// one cracked reuse group (hashA), one uncracked reuse group of size 3 (hashB),
	// one uncracked reuse group of size 2 (hashDA). The singleton is excluded.
	if len(rep.CrackedReuse) != 1 {
		t.Fatalf("CrackedReuse groups = %d, want 1", len(rep.CrackedReuse))
	}
	cg := rep.CrackedReuse[0]
	if cg.Size != 2 || !cg.Cracked || cg.Domains != 2 || cg.HIBPBreachCount != 1500 {
		t.Errorf("cracked group = %+v, want size2/cracked/2domains/1500hibp", cg)
	}
	if len(cg.Members) != 2 {
		t.Errorf("cracked group members = %d, want 2", len(cg.Members))
	}

	if len(rep.UncrackedReuse) != 2 {
		t.Fatalf("UncrackedReuse groups = %d, want 2", len(rep.UncrackedReuse))
	}
	// sorted by size desc -> hashB group (3) first
	big := rep.UncrackedReuse[0]
	if big.Size != 3 || big.Cracked {
		t.Errorf("biggest uncracked group = %+v, want size3/uncracked", big)
	}
	// the hashDA group reaches a DA pathway
	daGroup := rep.UncrackedReuse[1]
	if !daGroup.HasDAPathway {
		t.Errorf("hashDA group should have HasDAPathway")
	}

	// HIBP-exposed: alice, bob (1500), svc, temp (42) -- sorted by count desc
	if len(rep.HIBPExposed) != 4 {
		t.Errorf("HIBPExposed = %d, want 4", len(rep.HIBPExposed))
	}
	if rep.HIBPExposed[0].HIBPBreachCount != 1500 {
		t.Errorf("HIBPExposed[0] count = %d, want 1500", rep.HIBPExposed[0].HIBPBreachCount)
	}

	// redaction: no ReportAccount carries cleartext (the type has no password field;
	// assert the cracked member still reports a length but the struct exposes no secret)
	for _, m := range cg.Members {
		if m.PasswordLength == 0 {
			t.Errorf("cracked member %s lost its PasswordLength", m.Username)
		}
	}
}

func TestBuildReportViolationCounts(t *testing.T) {
	accts := []Account{
		{Username: "a", Domain: "C", Cracked: true, IsCommon: true, BannedWordCount: 1}, // common + forbidden
		{Username: "b", Domain: "C", Cracked: true, IsDictionaryWord: true},             // dictionary
		{Username: "c", Domain: "C", Cracked: true, KeyboardPatternCount: 2},            // keyboard
		{Username: "d", Domain: "C", Cracked: true},                                     // clean
	}
	vc := BuildReport(accts).ViolationCounts
	if vc.Common != 1 || vc.Dictionary != 1 || vc.Forbidden != 1 || vc.Keyboard != 1 {
		t.Fatalf("violation counts wrong: %+v", vc)
	}
}

func TestBuildReportEmpty(t *testing.T) {
	rep := BuildReport(nil)
	// JSON-friendly: slices are non-nil so the API emits [] not null
	if rep.Cracked == nil || rep.CrackedReuse == nil || rep.UncrackedReuse == nil || rep.HIBPExposed == nil || rep.DAPathways == nil {
		t.Errorf("empty report should have non-nil slices, got %+v", rep)
	}
	if rep.TotalAccounts != 0 || rep.CrackedCount != 0 {
		t.Errorf("empty report counts non-zero: %+v", rep)
	}
}

func TestAggregateTerms(t *testing.T) {
	accts := []Account{
		{BannedWords: []string{"summer", "2021"}, KeyboardPatterns: []string{"qwerty"}},
		{BannedWords: []string{"2021"}},
		{BannedWords: []string{"2021", "2021"}},  // duplicate within one account counts once
		{IsCommon: true, IsDictionaryWord: true}, // common/dictionary must NOT appear as terms
	}
	tr := AggregateTerms(accts, 25)
	if len(tr.Forbidden) != 2 {
		t.Fatalf("want 2 forbidden terms, got %+v", tr.Forbidden)
	}
	// sorted by count desc: 2021 (3) before summer (1)
	if tr.Forbidden[0].Term != "2021" || tr.Forbidden[0].Count != 3 {
		t.Fatalf("top forbidden wrong: %+v", tr.Forbidden[0])
	}
	if len(tr.Keyboard) != 1 || tr.Keyboard[0].Term != "qwerty" || tr.Keyboard[0].Count != 1 {
		t.Fatalf("keyboard wrong: %+v", tr.Keyboard)
	}
}

func TestAggregateTermsTopN(t *testing.T) {
	var accts []Account
	for _, w := range []string{"a", "b", "c", "d"} {
		accts = append(accts, Account{BannedWords: []string{w}})
	}
	if got := len(AggregateTerms(accts, 2).Forbidden); got != 2 {
		t.Fatalf("topN cap failed: got %d", got)
	}
}

func TestReportAccountCarriesEnabled(t *testing.T) {
	rep := BuildReport([]Account{
		{Username: "live", Domain: "C", Cracked: true, Enabled: true, RiskScore: 5},
		{Username: "off", Domain: "C", Cracked: true, Enabled: false, RiskScore: 4},
	})
	byName := map[string]bool{}
	for _, a := range rep.Cracked {
		byName[a.Username] = a.Enabled
	}
	if !byName["live"] || byName["off"] {
		t.Fatalf("Enabled not propagated to ReportAccount: %+v", byName)
	}
}
