package metrics

import (
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

type GraphNode struct {
	ID    string  `json:"id"`
	Label string  `json:"label"`
	Size  float64 `json:"size"`
	Color string  `json:"color"`
	X     float64 `json:"x"`
	Y     float64 `json:"y"`
}

type GraphEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Weight int    `json:"weight"`
	Label  string `json:"label,omitempty"`
}

type Graph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// CrossDomainReuseGraph: domains as nodes, edges between domains that share a
// credential (co-occur in a reuse group). Mirrors insights.ts crossDomainReuseGraph.
func CrossDomainReuseGraph(rep model.Report, accounts []model.Account) Graph {
	type ds struct{ total, critical int }
	domainStat := map[string]*ds{}
	for i := range accounts {
		a := accounts[i]
		s := domainStat[a.Domain]
		if s == nil {
			s = &ds{}
			domainStat[a.Domain] = s
		}
		s.total++
		if a.RiskLevel == "Critical" {
			s.critical++
		}
	}
	pairWeight := map[string]int{}
	connected := map[string]bool{}
	groups := append(append([]model.ReuseGroup{}, rep.CrackedReuse...), rep.UncrackedReuse...)
	for _, g := range groups {
		doms := sortedKeys(groupDomains(g))
		if len(doms) < 2 {
			continue
		}
		for i := 0; i < len(doms); i++ {
			for j := i + 1; j < len(doms); j++ {
				key := doms[i] + "|" + doms[j]
				pairWeight[key] += g.Size
				connected[doms[i]] = true
				connected[doms[j]] = true
			}
		}
	}
	g := Graph{Nodes: []GraphNode{}, Edges: []GraphEdge{}}
	if len(pairWeight) == 0 {
		return g
	}
	for _, d := range sortedKeys(connected) {
		s := domainStat[d]
		if s == nil {
			s = &ds{}
		}
		color := "#22d3ee"
		if s.critical > 20 {
			color = "#fb7185"
		} else if s.critical > 5 {
			color = "#fbbf24"
		}
		g.Nodes = append(g.Nodes, GraphNode{ID: d, Label: d, Size: 12 + math.Sqrt(float64(s.total))*2, Color: color})
	}
	keys := make([]string, 0, len(pairWeight))
	for k := range pairWeight {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		w := pairWeight[k]
		src, dst, _ := strings.Cut(k, "|")
		weight := int(math.Ceil(float64(w) / 10))
		if weight < 1 {
			weight = 1
		}
		g.Edges = append(g.Edges, GraphEdge{Source: src, Target: dst, Weight: weight, Label: strconv.Itoa(w) + " shared"})
	}
	layout(&g)
	return g
}

// SimilarityNetwork: cracked accounts with similarity_score>=0.7 as nodes, linked by
// server-computed similar_peers. Mirrors insights.ts similarityNetwork.
func SimilarityNetwork(accounts []model.Account, maxNodes int) Graph {
	g := Graph{Nodes: []GraphNode{}, Edges: []GraphEdge{}}
	cand := []model.Account{}
	for i := range accounts {
		if accounts[i].Cracked && accounts[i].SimilarityScore >= 0.7 {
			cand = append(cand, accounts[i])
		}
	}
	if len(cand) < 2 {
		return g
	}
	sort.SliceStable(cand, func(i, j int) bool {
		if cand[i].SimilarityScore != cand[j].SimilarityScore {
			return cand[i].SimilarityScore > cand[j].SimilarityScore
		}
		return cand[i].Username < cand[j].Username
	})
	if maxNodes < len(cand) {
		cand = cand[:maxNodes]
	}
	idOf := func(a model.Account) string { return a.Domain + "/" + a.Username }
	nodeIDs := map[string]bool{}
	for i := range cand {
		a := cand[i]
		color := "#22d3ee"
		switch a.RiskLevel {
		case "Critical":
			color = "#fb7185"
		case "High":
			color = "#fbbf24"
		case "Medium":
			color = "#a3e635"
		}
		id := idOf(a)
		nodeIDs[id] = true
		g.Nodes = append(g.Nodes, GraphNode{ID: id, Label: a.Username, Size: 10 + a.SimilarityScore*12, Color: color})
	}
	seen := map[string]bool{}
	for i := range cand {
		src := idOf(cand[i])
		for _, p := range cand[i].SimilarPeers {
			dst := p.Domain + "/" + p.Username
			if !nodeIDs[dst] || dst == src {
				continue
			}
			a, b := src, dst
			if b < a {
				a, b = b, a
			}
			key := a + "|" + b
			if seen[key] {
				continue
			}
			seen[key] = true
			w := int(math.Round(p.Score * 3))
			if w < 1 {
				w = 1
			}
			g.Edges = append(g.Edges, GraphEdge{Source: src, Target: dst, Weight: w, Label: strconv.Itoa(int(math.Round(p.Score*100))) + "%"})
		}
	}
	sort.SliceStable(g.Edges, func(i, j int) bool {
		if g.Edges[i].Source != g.Edges[j].Source {
			return g.Edges[i].Source < g.Edges[j].Source
		}
		return g.Edges[i].Target < g.Edges[j].Target
	})
	layout(&g)
	return g
}
