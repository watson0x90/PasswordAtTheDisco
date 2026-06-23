package bloodhound

import "testing"

func TestBulkEnricherTier0(t *testing.T) {
	b := NewBulkEnricherFromData(BulkEnrichment{
		Props: map[string]BulkUserProps{"svc@CORP": {ObjectID: "S-1-5-21-1"}},
		Tier0: map[string]bool{"svc@CORP": true},
	})
	if !b.Tier0("svc@CORP") {
		t.Errorf("Tier0(svc@CORP) = false, want true")
	}
	// Key normalization: mixed-case input must still resolve.
	if !b.Tier0("SVC@corp") {
		t.Errorf("Tier0(SVC@corp) = false, want true (case-normalized)")
	}
	if b.Tier0("other@CORP") {
		t.Errorf("Tier0(other@CORP) = true, want false (not in set)")
	}
}
