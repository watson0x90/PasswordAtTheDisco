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

func TestReuseGraphPopulatesLayout(t *testing.T) {
	// Same 2-domain reuse graph as TestCrossDomainReuseGraphNodesEdges.
	rep := model.Report{UncrackedReuse: []model.ReuseGroup{
		{Size: 20, Members: []model.ReportAccount{{Domain: "A"}, {Domain: "B"}}},
	}}
	accts := []model.Account{{Domain: "A"}, {Domain: "B"}}
	g := CrossDomainReuseGraph(rep, accts)

	// Assert that every node has X and Y in [0,1].
	for _, node := range g.Nodes {
		if node.X < 0 || node.X > 1 || node.Y < 0 || node.Y > 1 {
			t.Errorf("node %q has X=%.4f Y=%.4f, want both in [0,1]", node.ID, node.X, node.Y)
		}
	}

	// Assert that layout ran (not all nodes at 0,0).
	allZero := true
	for _, node := range g.Nodes {
		if node.X != 0 || node.Y != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Errorf("all nodes at (0,0); layout did not run")
	}
}
