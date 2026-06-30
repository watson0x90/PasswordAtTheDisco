package metrics

import (
	"math"
	"testing"
)

func TestLayoutDeterministicAndNormalized(t *testing.T) {
	g := Graph{
		Nodes: []GraphNode{{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}},
		Edges: []GraphEdge{{Source: "a", Target: "b"}, {Source: "c", Target: "d"}},
	}
	p1 := LayoutPositions(g)
	p2 := LayoutPositions(g)
	for i := range p1.Nodes {
		// deterministic: two runs identical
		if p1.Nodes[i].X != p2.Nodes[i].X || p1.Nodes[i].Y != p2.Nodes[i].Y {
			t.Fatalf("node %d not deterministic: %v vs %v", i, p1.Nodes[i], p2.Nodes[i])
		}
		// normalized into [0,1]
		if p1.Nodes[i].X < 0 || p1.Nodes[i].X > 1 || p1.Nodes[i].Y < 0 || p1.Nodes[i].Y > 1 {
			t.Errorf("node %d not normalized: (%v,%v)", i, p1.Nodes[i].X, p1.Nodes[i].Y)
		}
	}
	// connected pair should end closer than the bounding-box diagonal (sanity)
	d := func(a, b GraphNode) float64 { return math.Hypot(a.X-b.X, a.Y-b.Y) }
	ab := d(p1.Nodes[0], p1.Nodes[1])
	if ab > 1.5 {
		t.Errorf("spring did not pull a,b together: dist=%v", ab)
	}
}

func TestLayoutEmptyAndSingle(t *testing.T) {
	if g := LayoutPositions(Graph{}); len(g.Nodes) != 0 {
		t.Error("empty graph should stay empty")
	}
	one := LayoutPositions(Graph{Nodes: []GraphNode{{ID: "x"}}})
	if one.Nodes[0].X != 0.5 || one.Nodes[0].Y != 0.5 {
		t.Errorf("single node should center at (0.5,0.5), got %+v", one.Nodes[0])
	}
}
