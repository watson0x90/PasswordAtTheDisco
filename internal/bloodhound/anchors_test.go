package bloodhound

import (
	"strings"
	"testing"
)

// TestTier0AnchorNames verifies the Tier-0 anchor set contains all expected names.
func TestTier0AnchorNames(t *testing.T) {
	got := strings.Join(tier0AnchorNames(), ",")
	for _, w := range []string{"DOMAIN ADMINS", "ENTERPRISE ADMINS", "KRBTGT", "ADMINSDHOLDER", "ADMINISTRATORS"} {
		if !strings.Contains(strings.ToUpper(got), w) {
			t.Errorf("tier0AnchorNames missing %q", w)
		}
	}
}

// TestAnchorSIDCache verifies the per-(domain,anchor) SID cache stores and retrieves
// values, and returns ok=false on a miss.
func TestAnchorSIDCache(t *testing.T) {
	c := &Client{}

	// miss before any set
	if _, ok := c.anchorSID("CORP.LOCAL", "DOMAIN ADMINS"); ok {
		t.Error("expected cache miss before any set")
	}

	// store and retrieve
	c.setAnchorSID("CORP.LOCAL", "DOMAIN ADMINS", "S-1-5-21-123-456-789-512")
	sid, ok := c.anchorSID("CORP.LOCAL", "DOMAIN ADMINS")
	if !ok {
		t.Error("expected cache hit after set")
	}
	if sid != "S-1-5-21-123-456-789-512" {
		t.Errorf("anchorSID = %q, want %q", sid, "S-1-5-21-123-456-789-512")
	}

	// different anchor in same domain — should miss
	if _, ok := c.anchorSID("CORP.LOCAL", "KRBTGT"); ok {
		t.Error("expected cache miss for different anchor")
	}

	// same anchor name, different domain — should miss
	if _, ok := c.anchorSID("OTHER.LOCAL", "DOMAIN ADMINS"); ok {
		t.Error("expected cache miss for different domain")
	}

	// two domains, two anchors — independent
	c.setAnchorSID("OTHER.LOCAL", "ENTERPRISE ADMINS", "S-1-5-21-999-888-777-519")
	sid2, ok2 := c.anchorSID("OTHER.LOCAL", "ENTERPRISE ADMINS")
	if !ok2 || sid2 != "S-1-5-21-999-888-777-519" {
		t.Errorf("second domain anchor: ok=%v sid=%q", ok2, sid2)
	}
	// first entry unchanged
	sid3, ok3 := c.anchorSID("CORP.LOCAL", "DOMAIN ADMINS")
	if !ok3 || sid3 != "S-1-5-21-123-456-789-512" {
		t.Errorf("first entry changed: ok=%v sid=%q", ok3, sid3)
	}
}
