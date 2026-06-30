// internal/metrics/matrix_test.go
package metrics

import (
	"testing"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

func fp(f float64) *float64 { return &f }

func TestAxisTierBoundaries(t *testing.T) {
	cases := []struct {
		v    float64
		want Tier
	}{{8, TierCritical}, {7.99, TierHigh}, {6, TierHigh}, {4, TierMedium}, {3.99, TierLow}, {0, TierLow}}
	for _, c := range cases {
		if got := AxisTier(c.v); got != c.want {
			t.Errorf("AxisTier(%v) = %v, want %v", c.v, got, c.want)
		}
	}
}

// CellLevel must match web/src/matrix.ts LEVEL_MATRIX exactly (and internal/risk).
func TestCellLevelMatchesMatrixTS(t *testing.T) {
	cases := []struct {
		exp  Tier
		imp  string
		want Tier
	}{
		{TierCritical, "Critical", TierCritical}, {TierCritical, "Low", TierMedium}, {TierCritical, ImpactUnknown, TierCritical},
		{TierHigh, "Medium", TierHigh}, {TierHigh, ImpactUnknown, TierHigh},
		{TierMedium, "Low", TierLow}, {TierMedium, ImpactUnknown, TierMedium},
		{TierLow, "Critical", TierHigh}, {TierLow, "Low", TierLow}, {TierLow, ImpactUnknown, TierLow},
	}
	for _, c := range cases {
		if got := CellLevel(c.exp, c.imp); got != c.want {
			t.Errorf("CellLevel(%v,%v) = %v, want %v", c.exp, c.imp, got, c.want)
		}
	}
}

func TestBuildMatrixCountsAndUnknownColumn(t *testing.T) {
	accts := []model.Account{
		{ExposureScore: 9, ImpactKnown: true, ImpactScore: fp(9)}, // Critical x Critical
		{ExposureScore: 9, ImpactKnown: false},                    // Critical x Unknown
		{ExposureScore: 5, ImpactKnown: true, ImpactScore: fp(4)}, // Medium x Medium
		{ExposureScore: 5, ImpactKnown: true, ImpactScore: nil},   // ImpactScore nil -> Unknown despite known flag
	}
	m := BuildMatrix(accts)
	if m.Total != 4 {
		t.Fatalf("total = %d, want 4", m.Total)
	}
	if m.Counts[TierCritical]["Critical"] != 1 {
		t.Errorf("Crit/Crit = %d, want 1", m.Counts[TierCritical]["Critical"])
	}
	if m.Counts[TierCritical][ImpactUnknown] != 1 {
		t.Errorf("Crit/Unknown = %d, want 1", m.Counts[TierCritical][ImpactUnknown])
	}
	if m.Counts[TierMedium][ImpactUnknown] != 1 {
		t.Errorf("Med/Unknown = %d, want 1", m.Counts[TierMedium][ImpactUnknown])
	}
	if m.Max != 1 {
		t.Errorf("max = %d, want 1", m.Max)
	}
}
