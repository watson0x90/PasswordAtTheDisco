package metrics

import "github.com/watson0x90/PasswordAtTheDisco/internal/model"

// Tier is an axis tier (Exposure or Impact). ImpactUnknown is a column-only value
// for accounts with no BloodHound coverage (impact not a number).
type Tier string

const (
	TierCritical Tier = "Critical"
	TierHigh     Tier = "High"
	TierMedium   Tier = "Medium"
	TierLow      Tier = "Low"

	ImpactUnknown = "Unknown"
)

var tierRows = []Tier{TierCritical, TierHigh, TierMedium, TierLow}
var impactCols = []string{string(TierCritical), string(TierHigh), string(TierMedium), string(TierLow), ImpactUnknown}

// AxisTier mirrors internal/risk cutoffs and web/src/matrix.ts axisTier:
// >=8 Critical, >=6 High, >=4 Medium, else Low. Pinned by TestAxisTierBoundaries
// against the same boundary numbers as the Go engine and the TS mirror.
func AxisTier(v float64) Tier {
	switch {
	case v >= 8:
		return TierCritical
	case v >= 6:
		return TierHigh
	case v >= 4:
		return TierMedium
	default:
		return TierLow
	}
}

// levelMatrix is keyed [exposure tier][impact column] and is transcribed verbatim
// from web/src/matrix.ts LEVEL_MATRIX (itself derived from internal/risk levelMatrix).
// The Unknown column = the Exposure tier alone (provisional). Pinned by
// TestCellLevelMatchesMatrixTS.
var levelMatrix = map[Tier]map[string]Tier{
	TierCritical: {"Critical": TierCritical, "High": TierCritical, "Medium": TierHigh, "Low": TierMedium, ImpactUnknown: TierCritical},
	TierHigh:     {"Critical": TierCritical, "High": TierHigh, "Medium": TierHigh, "Low": TierMedium, ImpactUnknown: TierHigh},
	TierMedium:   {"Critical": TierCritical, "High": TierHigh, "Medium": TierMedium, "Low": TierLow, ImpactUnknown: TierMedium},
	TierLow:      {"Critical": TierHigh, "High": TierMedium, "Medium": TierMedium, "Low": TierLow, ImpactUnknown: TierLow},
}

// CellLevel returns the resulting risk Level for an (Exposure tier, Impact column).
func CellLevel(exp Tier, imp string) Tier { return levelMatrix[exp][imp] }

// Matrix is the Exposure×Impact distribution grid plus its largest cell (Max), used
// by the heatmap to normalize intensity.
type Matrix struct {
	Counts map[Tier]map[string]int `json:"counts"`
	Total  int                     `json:"total"`
	Max    int                     `json:"max"`
}

// impactColumn returns the Impact column for an account: a tier when Impact is a
// usable number (ImpactKnown AND ImpactScore non-nil), else ImpactUnknown. Mirrors
// web/src/matrix.ts impactIsKnown.
func impactColumn(a model.Account) string {
	if a.ImpactKnown && a.ImpactScore != nil {
		return string(AxisTier(*a.ImpactScore))
	}
	return ImpactUnknown
}

// BuildMatrix buckets accounts into the Exposure×Impact grid.
func BuildMatrix(accounts []model.Account) Matrix {
	m := Matrix{Counts: map[Tier]map[string]int{}, Total: 0}
	for _, r := range tierRows {
		m.Counts[r] = map[string]int{}
		for _, c := range impactCols {
			m.Counts[r][c] = 0
		}
	}
	for i := range accounts {
		a := accounts[i]
		m.Counts[AxisTier(a.ExposureScore)][impactColumn(a)]++
		m.Total++
	}
	for _, r := range tierRows {
		for _, c := range impactCols {
			if m.Counts[r][c] > m.Max {
				m.Max = m.Counts[r][c]
			}
		}
	}
	return m
}
