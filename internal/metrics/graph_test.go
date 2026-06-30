package metrics

import (
	"testing"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

func TestCrossDomainReuseGraphNodesEdges(t *testing.T) {
	rep := model.Report{UncrackedReuse: []model.ReuseGroup{
		{Size: 20, Members: []model.ReportAccount{{Domain: "A"}, {Domain: "B"}}},
	}}
	accts := []model.Account{{Domain: "A"}, {Domain: "B"}}
	g := CrossDomainReuseGraph(rep, accts)
	if len(g.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2", len(g.Nodes))
	}
	if len(g.Edges) != 1 || g.Edges[0].Weight != 2 { // ceil(20/10)=2
		t.Fatalf("edges = %+v", g.Edges)
	}
}

func TestSimilarityNetworkThreshold(t *testing.T) {
	accts := []model.Account{
		{Username: "a", Domain: "D", Cracked: true, SimilarityScore: 0.95, RiskLevel: "High",
			SimilarPeers: []model.SimilarPeer{{Domain: "D", Username: "b", Score: 0.95}}},
		{Username: "b", Domain: "D", Cracked: true, SimilarityScore: 0.9, RiskLevel: "Low"},
		{Username: "c", Domain: "D", Cracked: true, SimilarityScore: 0.5}, // below 0.7 -> excluded
	}
	g := SimilarityNetwork(accts, 60)
	if len(g.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2 (a,b)", len(g.Nodes))
	}
	if len(g.Edges) != 1 {
		t.Fatalf("edges = %d, want 1 (a-b)", len(g.Edges))
	}
}
