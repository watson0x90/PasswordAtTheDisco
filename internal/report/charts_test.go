package report

import (
	"strings"
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/metrics"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

func TestChartSVGs(t *testing.T) {
	accts := []model.Account{
		{Username: "alice", Domain: "A", NTHash: "AAAA0000AAAA0000AAAA0000AAAA0000", Cracked: true, PasswordLength: 8, RiskLevel: "High", RiskScore: 7, HIBPBreached: true, HIBPBreachCount: 3},
		{Username: "bob", Domain: "B", NTHash: "AAAA0000AAAA0000AAAA0000AAAA0000", Cracked: true, PasswordLength: 8, RiskLevel: "High", RiskScore: 7},
	}
	m := metrics.Compute(accts, time.Unix(1_700_000_000, 0))
	svgs := ChartSVGs(m)
	byName := map[string]ChartSVG{}
	for _, c := range svgs {
		byName[c.Name] = c
		if !strings.Contains(c.SVG, "<svg") {
			t.Errorf("%s: not a standalone svg", c.Name)
		}
	}
	if _, ok := byName["risk_distribution"]; !ok {
		t.Error("expected risk_distribution chart")
	}
	if _, ok := byName["reuse_graph"]; !ok {
		t.Error("cross-domain reuse graph expected (alice/A + bob/B share a hash)")
	}
	if !byName["reuse_graph"].Wide {
		t.Error("reuse_graph should be Wide")
	}
	// Empty dataset (password age) must be skipped.
	if _, ok := byName["password_age_scatter"]; ok {
		t.Error("empty password_age_scatter must be skipped")
	}
}
