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

func TestStoredEnricherPreservesPropsForPartialCoverage(t *testing.T) {
	// A Coverage:"none" account that nonetheless carries uploaded AD properties
	// (from /api/upload/bheusers) must keep them through a rescore, while Impact
	// stays Unknown (Enriched=false). This is the bheusers-upload-fidelity fix.
	spn := false
	preauth := true
	old := int64(1_600_000_000) // a real, non-zero pwdlastset
	a := model.Account{
		Username:       "svc",
		Domain:         "CORP",
		Coverage:       "none", // NOT DA-graph enriched
		Enabled:        false,  // uploaded: disabled
		Controlled:     50,     // uploaded: controls 50 objects
		PwdLastSet:     old,    // uploaded: an old password
		HasSPN:         &spn,
		DontReqPreauth: &preauth, // uploaded: AS-REP roastable
	}
	enr := NewStoredEnricher([]model.Account{a}).Enrich(engine.NormalizeUsername("svc", "CORP"))

	if enr.Enriched {
		t.Fatal("Coverage=none must yield Enriched=false (Impact stays Unknown)")
	}
	if enr.Enabled == nil || *enr.Enabled {
		t.Errorf("Enabled = %v, want &false (preserved)", enr.Enabled)
	}
	if enr.ControlledObjects == nil || *enr.ControlledObjects != 50 {
		t.Errorf("ControlledObjects = %v, want &50 (preserved)", enr.ControlledObjects)
	}
	if enr.PwdLastSet == nil || *enr.PwdLastSet != old {
		t.Errorf("PwdLastSet = %v, want &%d (preserved)", enr.PwdLastSet, old)
	}
	if enr.DontReqPreauth == nil || !*enr.DontReqPreauth {
		t.Errorf("DontReqPreauth = %v, want &true (preserved)", enr.DontReqPreauth)
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

// TestRescorePreservedPwdLastSetRaisesExposure is the end-to-end payoff of the wipe
// fix: a Coverage:"none" account whose old PwdLastSet was uploaded via /api/upload/bheusers
// must, after a real rescore, score a non-zero AgePenalty and a higher Exposure than an
// otherwise-identical account with no PwdLastSet — while Impact stays Unknown for both.
func TestRescorePreservedPwdLastSetRaisesExposure(t *testing.T) {
	in := []model.Account{
		// Uncracked, partial-coverage, with a years-old uploaded PwdLastSet.
		{Username: "old", Domain: "CORP", NTHash: "AAA", Coverage: "none", PwdLastSet: 1_300_000_000},
		// Identical but no PwdLastSet (age unknown -> no age bump).
		{Username: "fresh", Domain: "CORP", NTHash: "BBB", Coverage: "none"},
	}
	eng := newTestEngine()
	out := eng.RescoreWith(in, NewStoredEnricher(in))

	byUser := make(map[string]model.Account, len(out))
	for _, a := range out {
		byUser[a.Username] = a
	}
	old, fresh := byUser["old"], byUser["fresh"]

	if old.ScoreBreakdown == nil || old.ScoreBreakdown.AgePenalty <= 0 {
		t.Errorf("old account AgePenalty = %v, want > 0 (preserved PwdLastSet must score age)", old.ScoreBreakdown)
	}
	if old.ExposureScore <= fresh.ExposureScore {
		t.Errorf("old Exposure %v must exceed fresh %v (age applied after rescore)", old.ExposureScore, fresh.ExposureScore)
	}
	if old.ImpactKnown || fresh.ImpactKnown {
		t.Errorf("Coverage:none must keep Impact Unknown after rescore (old=%v fresh=%v)", old.ImpactKnown, fresh.ImpactKnown)
	}
}
