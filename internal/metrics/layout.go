package metrics

import "math"

const (
	layoutIterations = 300
	layoutRepulse    = 0.30
	layoutSpring     = 0.10
	layoutSpringLen  = 1.0
	layoutCool0      = 0.10
	layoutEps        = 1e-4
)

func round4(v float64) float64 { return math.Round(v*1e4) / 1e4 }

// LayoutPositions returns a copy of g with deterministic force-directed X/Y in
// [0,1]. Seeded from node index (no RNG, no time), fixed constants and iteration
// count -> byte-identical output across runs (golden-stable).
func LayoutPositions(g Graph) Graph {
	n := len(g.Nodes)
	out := g
	out.Nodes = append([]GraphNode(nil), g.Nodes...)
	out.Edges = g.Edges
	if n == 0 {
		return out
	}
	if n == 1 {
		out.Nodes[0].X, out.Nodes[0].Y = 0.5, 0.5
		return out
	}
	xs := make([]float64, n)
	ys := make([]float64, n)
	for i := 0; i < n; i++ {
		a := 2 * math.Pi * float64(i) / float64(n)
		xs[i], ys[i] = math.Cos(a), math.Sin(a)
	}
	idx := make(map[string]int, n)
	for i := range out.Nodes {
		idx[out.Nodes[i].ID] = i
	}
	type pair struct{ s, t int }
	edges := make([]pair, 0, len(out.Edges))
	for _, e := range out.Edges {
		si, ok1 := idx[e.Source]
		ti, ok2 := idx[e.Target]
		if ok1 && ok2 && si != ti {
			edges = append(edges, pair{si, ti})
		}
	}
	dx := make([]float64, n)
	dy := make([]float64, n)
	for iter := 0; iter < layoutIterations; iter++ {
		for i := 0; i < n; i++ {
			dx[i], dy[i] = 0, 0
		}
		for i := 0; i < n; i++ {
			for j := 0; j < n; j++ {
				if i == j {
					continue
				}
				ddx, ddy := xs[i]-xs[j], ys[i]-ys[j]
				d2 := ddx*ddx + ddy*ddy
				if d2 < layoutEps {
					d2 = layoutEps
				}
				f := layoutRepulse / d2
				dist := math.Sqrt(d2)
				dx[i] += ddx / dist * f
				dy[i] += ddy / dist * f
			}
		}
		for _, e := range edges {
			ddx, ddy := xs[e.t]-xs[e.s], ys[e.t]-ys[e.s]
			dist := math.Sqrt(ddx*ddx+ddy*ddy) + layoutEps
			f := layoutSpring * (dist - layoutSpringLen)
			ux, uy := ddx/dist, ddy/dist
			dx[e.s] += ux * f
			dy[e.s] += uy * f
			dx[e.t] -= ux * f
			dy[e.t] -= uy * f
		}
		step := layoutCool0 * (1 - float64(iter)/float64(layoutIterations))
		for i := 0; i < n; i++ {
			xs[i] += dx[i] * step
			ys[i] += dy[i] * step
		}
	}
	normalize(xs)
	normalize(ys)
	for i := 0; i < n; i++ {
		out.Nodes[i].X = round4(xs[i])
		out.Nodes[i].Y = round4(ys[i])
	}
	return out
}

// normalize min-max scales v into [0,1]; a degenerate axis is centered at 0.5.
func normalize(v []float64) {
	if len(v) == 0 {
		return
	}
	mn, mx := v[0], v[0]
	for _, x := range v {
		if x < mn {
			mn = x
		}
		if x > mx {
			mx = x
		}
	}
	span := mx - mn
	if span < layoutEps {
		for i := range v {
			v[i] = 0.5
		}
		return
	}
	for i := range v {
		v[i] = (v[i] - mn) / span
	}
}

func layout(g *Graph) { *g = LayoutPositions(*g) }
