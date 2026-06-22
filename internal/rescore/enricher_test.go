package rescore

import (
	"testing"

	"github.com/watson0x90/PasswordAtTheDisco/internal/engine"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/policy"
	"github.com/watson0x90/PasswordAtTheDisco/internal/pwanalysis"
)

func TestStoredEnricherReconstructsEnrichedAccount(t *testing.T) {
	ctrl := 7
	never := false
	spn := true
	preauth := false
	accts := []model.Account{{
		Username: "svc", Domain: "CORP",
		Coverage:        "full",
		DADomains:       "CORP.LOCAL, ROOT.LOCAL",
		Controlled:      ctrl,
		Enabled:         true,
		ControlsTier0:   true,
		PwdLastSet:      1700000000,
		PwdNeverExpires: &never,
		HasSPN:          &spn,
		DontReqPreauth:  &preauth,
	}}
	enr := NewStoredEnricher(accts)
	got := enr.Enrich(engine.NormalizeUsername("svc", "CORP"))

	if !got.Enriched {
		t.Fatal("enriched account must reconstruct Enriched=true")
	}
	if got.ControlledObjects == nil || *got.ControlledObjects != 7 {
		t.Fatalf("ControlledObjects = %v, want 7", got.ControlledObjects)
	}
	if !got.ControlsTier0 {
		t.Fatal("ControlsTier0 must be reconstructed")
	}
	if len(got.DADomains) != 2 || got.DADomains[0] != "CORP.LOCAL" {
		t.Fatalf("DADomains = %v, want [CORP.LOCAL ROOT.LOCAL]", got.DADomains)
	}
	if got.Enabled == nil || !*got.Enabled {
		t.Fatal("Enabled must be reconstructed true")
	}
	if got.PwdLastSet == nil || *got.PwdLastSet != 1700000000 {
		t.Fatalf("PwdLastSet = %v, want 1700000000", got.PwdLastSet)
	}
	if got.HasSPN == nil || !*got.HasSPN {
		t.Fatal("HasSPN must be reconstructed true")
	}
}

func TestStoredEnricherUnenrichedStaysUnknown(t *testing.T) {
	accts := []model.Account{{Username: "bob", Domain: "CORP", Coverage: "none"}}
	enr := NewStoredEnricher(accts)
	got := enr.Enrich(engine.NormalizeUsername("bob", "CORP"))
	if got.Enriched {
		t.Fatal("Coverage=none must yield Enriched=false (Impact-Unknown preserved)")
	}
	miss := enr.Enrich(engine.NormalizeUsername("ghost", "CORP"))
	if miss.Enriched {
		t.Fatal("missing account must yield Enriched=false")
	}
}

// newTestEngine builds a minimal *engine.Engine for equivalence testing,
// mirroring the newEngine() helper in engine_test.go (same package, not exported).
func newTestEngine() *engine.Engine {
	return &engine.Engine{
		Lists:    pwanalysis.Lists{CommonPasswords: pwanalysis.NewSet("welcome1")},
		Policies: policy.DefaultSet(),
	}
}

// TestImpactEquivalenceAfterRescore asserts the core rescore invariant:
//   - Coverage:"full" with DA enrichment => ImpactKnown stays true after RescoreWith.
//   - Coverage:"none" => ImpactKnown stays false (Impact-Unknown preserved).
func TestImpactEquivalenceAfterRescore(t *testing.T) {
	never := false

	in := []model.Account{
		{
			// Cracked, fully enriched with a DA pathway.
			Username:        "svc",
			Domain:          "CORP",
			Password:        "Summer2024!",
			NTHash:          "AABBCC",
			Cracked:         true,
			Coverage:        "full",
			DADomains:       "CORP.LOCAL",
			Controlled:      5,
			Enabled:         true,
			ControlsTier0:   true,
			PwdLastSet:      1700000000,
			PwdNeverExpires: &never,
		},
		{
			// Cracked, no BloodHound enrichment.
			Username: "bob",
			Domain:   "CORP",
			Password: "Summer2024!",
			NTHash:   "DDEEFF",
			Cracked:  true,
			Coverage: "none",
		},
	}

	eng := newTestEngine()
	out := eng.RescoreWith(in, NewStoredEnricher(in))

	byUser := make(map[string]model.Account, len(out))
	for _, a := range out {
		byUser[a.Username] = a
	}

	svc, ok := byUser["svc"]
	if !ok {
		t.Fatal("svc account missing from RescoreWith output")
	}
	if !svc.ImpactKnown {
		t.Errorf("Coverage:full + DA enrichment => ImpactKnown must be true after rescore, got false")
	}
	if svc.ImpactScore == nil {
		t.Errorf("Coverage:full + DA enrichment => ImpactScore must be non-nil after rescore")
	}

	bob, ok := byUser["bob"]
	if !ok {
		t.Fatal("bob account missing from RescoreWith output")
	}
	if bob.ImpactKnown {
		t.Errorf("Coverage:none => ImpactKnown must be false after rescore, got true")
	}
}
