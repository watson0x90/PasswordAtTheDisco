// Package report — inline SVG chart helpers for the self-contained HTML export.
// No <script> tags, no external assets; all output is inline SVG markup.
// Every user-influenced string (label text) is HTML-escaped before emission.
package report

import (
	"fmt"
	"html"
	"html/template"
	"strings"

	"github.com/watson0x90/PasswordAtTheDisco/internal/metrics"
)

// SVG layout constants — all widths in pixels.
const (
	svgW      = 420                          // total canvas width
	svgRowH   = 20                           // height per bar row
	svgLblW   = 120                          // label column width
	svgValW   = 38                           // value-number column width
	svgBarW   = svgW - svgLblW - svgValW - 4 // bar fill area (258 px)
	svgFontSz = 11
)

// svgAccent is the default bar fill used for plain (uncolored) bar series.
const svgAccent = "#22d3ee"

// svgBarChart renders a compact horizontal bar chart from a labeled bar series.
// If accent is empty the default teal is used. Returns empty HTML for an empty
// series so callers can skip the card entirely.
func svgBarChart(bars []metrics.Bar, accent string) template.HTML {
	if len(bars) == 0 {
		return ""
	}
	if accent == "" {
		accent = svgAccent
	}
	max := 1
	for _, b := range bars {
		if b.Value > max {
			max = b.Value
		}
	}
	totalH := len(bars)*svgRowH + 4
	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" style="display:block">`,
		svgW, totalH)
	for i, b := range bars {
		y := i*svgRowH + 2
		bw := b.Value * svgBarW / max
		if bw == 0 && b.Value > 0 {
			bw = 1 // minimum visible pixel
		}
		lbl := html.EscapeString(b.Name)
		// Label — right-aligned inside the label column.
		fmt.Fprintf(&sb,
			`<text x="%d" y="%d" text-anchor="end" font-size="%d" font-family="'Segoe UI',system-ui,sans-serif" fill="#8a96b2">%s</text>`,
			svgLblW-4, y+svgFontSz, svgFontSz, lbl)
		// Bar rect.
		fmt.Fprintf(&sb,
			`<rect x="%d" y="%d" width="%d" height="%d" rx="3" fill="%s" opacity="0.85"/>`,
			svgLblW, y+3, bw, svgRowH-7, accent)
		// Value — immediately right of bar.
		fmt.Fprintf(&sb,
			`<text x="%d" y="%d" font-size="%d" font-family="'Segoe UI',system-ui,sans-serif" fill="#e8edf7">%d</text>`,
			svgLblW+bw+5, y+svgFontSz, svgFontSz, b.Value)
	}
	sb.WriteString(`</svg>`)
	return template.HTML(sb.String())
}

// svgSliceAsBar renders slice data (name + value + per-item color) as a bar chart,
// coloring each bar and its label with the slice's own color. Returns empty HTML
// for an empty series.
func svgSliceAsBar(slices []metrics.Slice) template.HTML {
	if len(slices) == 0 {
		return ""
	}
	max := 1
	for _, s := range slices {
		if s.Value > max {
			max = s.Value
		}
	}
	totalH := len(slices)*svgRowH + 4
	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" style="display:block">`,
		svgW, totalH)
	for i, s := range slices {
		y := i*svgRowH + 2
		bw := s.Value * svgBarW / max
		if bw == 0 && s.Value > 0 {
			bw = 1
		}
		color := html.EscapeString(s.Color)
		if color == "" {
			color = svgAccent
		}
		lbl := html.EscapeString(s.Name)
		// Label in the slice's own color.
		fmt.Fprintf(&sb,
			`<text x="%d" y="%d" text-anchor="end" font-size="%d" font-family="'Segoe UI',system-ui,sans-serif" fill="%s">%s</text>`,
			svgLblW-4, y+svgFontSz, svgFontSz, color, lbl)
		fmt.Fprintf(&sb,
			`<rect x="%d" y="%d" width="%d" height="%d" rx="3" fill="%s" opacity="0.85"/>`,
			svgLblW, y+3, bw, svgRowH-7, color)
		fmt.Fprintf(&sb,
			`<text x="%d" y="%d" font-size="%d" font-family="'Segoe UI',system-ui,sans-serif" fill="#e8edf7">%d</text>`,
			svgLblW+bw+5, y+svgFontSz, svgFontSz, s.Value)
	}
	sb.WriteString(`</svg>`)
	return template.HTML(sb.String())
}

// chartCard wraps an SVG chart in a styled panel div with a heading.
// Returns empty HTML when svg is empty (no data) so callers can skip it.
func chartCard(title string, svg template.HTML) template.HTML {
	if svg == "" {
		return ""
	}
	return template.HTML(fmt.Sprintf(
		`<div class="chart-card"><div class="chart-title">%s</div>%s</div>`,
		html.EscapeString(title), string(svg)))
}

// ---- Scatter plot ----

// scatW, scatH define the scatter plot canvas; scatPad is the uniform inset;
// scatLegH is the extra height reserved for the legend row; scatR is the circle radius.
const (
	scatW    = 420
	scatH    = 200
	scatPad  = 12
	scatLegH = 22
	scatR    = 3
)

// svgScatter renders a small fixed-size scatter plot from a []metrics.Series.
// Each series' points are plotted as colored circles. Axes are min-max normalised;
// degenerate single-value axes are padded by 1 so all points are visible.
// Series Names and Colors are HTML-escaped. Returns empty HTML when there are no
// points across all series.
func svgScatter(series []metrics.Series) template.HTML {
	var minX, maxX, minY, maxY float64
	first := true
	for _, s := range series {
		for _, p := range s.Points {
			if first {
				minX, maxX, minY, maxY = p.X, p.X, p.Y, p.Y
				first = false
			} else {
				if p.X < minX {
					minX = p.X
				}
				if p.X > maxX {
					maxX = p.X
				}
				if p.Y < minY {
					minY = p.Y
				}
				if p.Y > maxY {
					maxY = p.Y
				}
			}
		}
	}
	if first {
		return "" // no points
	}
	if maxX == minX {
		maxX = minX + 1
	}
	if maxY == minY {
		maxY = minY + 1
	}

	plotW := float64(scatW - 2*scatPad)
	plotH := float64(scatH - 2*scatPad - scatLegH)

	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" style="display:block">`,
		scatW, scatH)

	for _, s := range series {
		color := html.EscapeString(s.Color)
		if color == "" {
			color = svgAccent
		}
		for _, p := range s.Points {
			cx := int(float64(scatPad) + (p.X-minX)/(maxX-minX)*plotW)
			cy := int(float64(scatPad) + (1-(p.Y-minY)/(maxY-minY))*plotH)
			fmt.Fprintf(&sb,
				`<circle cx="%d" cy="%d" r="%d" fill="%s" opacity="0.7"/>`,
				cx, cy, scatR, color)
		}
	}

	// Legend row below the plot area.
	legX := scatPad
	legY := scatH - 6
	for _, s := range series {
		color := html.EscapeString(s.Color)
		if color == "" {
			color = svgAccent
		}
		name := html.EscapeString(s.Name)
		fmt.Fprintf(&sb, `<circle cx="%d" cy="%d" r="4" fill="%s"/>`, legX+4, legY, color)
		fmt.Fprintf(&sb,
			`<text x="%d" y="%d" font-size="%d" font-family="'Segoe UI',system-ui,sans-serif" fill="#8a96b2">%s</text>`,
			legX+12, legY+4, svgFontSz, name)
		legX += 90
	}

	sb.WriteString(`</svg>`)
	return template.HTML(sb.String())
}

// ---- Axis-factor bars ----

// axisTierH is the height (px) of each per-tier heading row in svgAxisFactorBars.
// axisSubH is the height of the "Impact" sub-label row within each tier block.
const (
	axisTierH = 22
	axisSubH  = 18
)

// svgAxisFactorBars renders per-tier averaged exposure and impact factor bars.
// Impact bars are greyed out (dimmed fill + muted label) when ImpactKnown is false.
// Factor Names, tier Tier labels, and all Colors are HTML-escaped. Returns empty
// HTML when tiers is empty.
func svgAxisFactorBars(tiers []metrics.TierFactorBars) template.HTML {
	if len(tiers) == 0 {
		return ""
	}

	// Global max across all factor values (exposure + impact) for proportional scaling.
	maxVal := 0.01
	for _, t := range tiers {
		for _, f := range t.Exposure {
			if f.Value > maxVal {
				maxVal = f.Value
			}
		}
		for _, f := range t.Impact {
			if f.Value > maxVal {
				maxVal = f.Value
			}
		}
	}

	// Pre-compute total SVG height: sum over tiers of (heading + exposure rows +
	// impact sub-label + impact rows + separator).
	totalH := 4
	for _, t := range tiers {
		if len(t.Exposure) == 0 && len(t.Impact) == 0 {
			continue
		}
		totalH += axisTierH + len(t.Exposure)*svgRowH + axisSubH + len(t.Impact)*svgRowH + 8
	}
	if totalH == 4 { // every tier had empty factor slices — nothing to draw
		return ""
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" style="display:block">`,
		svgW, totalH)

	y := 4
	for _, t := range tiers {
		if len(t.Exposure) == 0 && len(t.Impact) == 0 {
			continue
		}

		tierColor := html.EscapeString(t.Color)
		if tierColor == "" {
			tierColor = svgAccent
		}

		// Tier heading in tier color.
		fmt.Fprintf(&sb,
			`<text x="4" y="%d" font-size="%d" font-weight="600" font-family="'Segoe UI',system-ui,sans-serif" fill="%s">%s</text>`,
			y+15, svgFontSz, tierColor, html.EscapeString(t.Tier))
		y += axisTierH

		// Exposure factor bars.
		for _, f := range t.Exposure {
			bw := int(f.Value / maxVal * float64(svgBarW))
			if bw == 0 && f.Value > 0 {
				bw = 1
			}
			color := html.EscapeString(f.Color)
			if color == "" {
				color = svgAccent
			}
			lbl := html.EscapeString(f.Name)
			fmt.Fprintf(&sb,
				`<text x="%d" y="%d" text-anchor="end" font-size="%d" font-family="'Segoe UI',system-ui,sans-serif" fill="#8a96b2">%s</text>`,
				svgLblW-4, y+svgFontSz, svgFontSz, lbl)
			fmt.Fprintf(&sb,
				`<rect x="%d" y="%d" width="%d" height="%d" rx="3" fill="%s" opacity="0.85"/>`,
				svgLblW, y+3, bw, svgRowH-7, color)
			fmt.Fprintf(&sb,
				`<text x="%d" y="%d" font-size="%d" font-family="'Segoe UI',system-ui,sans-serif" fill="#e8edf7">%.2f</text>`,
				svgLblW+bw+5, y+svgFontSz, svgFontSz, f.Value)
			y += svgRowH
		}

		// Impact sub-label — dimmed when no enriched accounts exist for this tier.
		impTextColor := "#8a96b2"
		impOpacity := "0.85"
		impSuffix := ""
		if !t.ImpactKnown {
			impTextColor = "#566076"
			impOpacity = "0.35"
			impSuffix = " (no enriched accounts)"
		}
		fmt.Fprintf(&sb,
			`<text x="4" y="%d" font-size="%d" font-family="'Segoe UI',system-ui,sans-serif" fill="%s">Impact%s</text>`,
			y+14, svgFontSz, impTextColor, impSuffix)
		y += axisSubH

		// Impact factor bars.
		for _, f := range t.Impact {
			bw := int(f.Value / maxVal * float64(svgBarW))
			if bw == 0 && f.Value > 0 {
				bw = 1
			}
			color := html.EscapeString(f.Color)
			if color == "" {
				color = svgAccent
			}
			lbl := html.EscapeString(f.Name)
			fmt.Fprintf(&sb,
				`<text x="%d" y="%d" text-anchor="end" font-size="%d" font-family="'Segoe UI',system-ui,sans-serif" fill="%s">%s</text>`,
				svgLblW-4, y+svgFontSz, svgFontSz, impTextColor, lbl)
			fmt.Fprintf(&sb,
				`<rect x="%d" y="%d" width="%d" height="%d" rx="3" fill="%s" opacity="%s"/>`,
				svgLblW, y+3, bw, svgRowH-7, color, impOpacity)
			fmt.Fprintf(&sb,
				`<text x="%d" y="%d" font-size="%d" font-family="'Segoe UI',system-ui,sans-serif" fill="%s">%.2f</text>`,
				svgLblW+bw+5, y+svgFontSz, svgFontSz, impTextColor, f.Value)
			y += svgRowH
		}

		y += 8 // visual separator between tiers
	}

	sb.WriteString(`</svg>`)
	return template.HTML(sb.String())
}

// ---- Network graph ----

// netW, netH define the network graph viewBox dimensions (px).
// netPad is the inset from all four sides so nodes near the boundary remain visible.
// netMinR / netMaxR are the radius bounds used to scale GraphNode.Size values.
const (
	netW    = 540
	netH    = 320
	netPad  = 28
	netMinR = 6.0
	netMaxR = 18.0
)

// svgNetworkGraph renders a network graph whose node positions are pre-computed
// [0,1] coordinates (force-directed layout from metrics/layout.go). Edges are
// rendered as <line> elements beneath nodes, which are <circle> elements. The
// SVG uses a viewBox so it scales to fit its CSS container via width:100%.
//
// Node Labels (which may be usernames or domain names — user-influenced content)
// and all Color fields are HTML-escaped before they reach any SVG attribute or
// <text> element. Returns empty HTML when fewer than 2 nodes are present.
func svgNetworkGraph(g metrics.Graph) template.HTML {
	if len(g.Nodes) < 2 {
		return ""
	}

	// Scale node radii relative to the observed Size range.
	minSz, maxSz := g.Nodes[0].Size, g.Nodes[0].Size
	for _, n := range g.Nodes[1:] {
		if n.Size < minSz {
			minSz = n.Size
		}
		if n.Size > maxSz {
			maxSz = n.Size
		}
	}
	sizeSpan := maxSz - minSz
	circleR := func(sz float64) float64 {
		if sizeSpan < 0.5 {
			return (netMinR + netMaxR) / 2
		}
		return netMinR + (sz-minSz)/sizeSpan*(netMaxR-netMinR)
	}

	// Map [0,1] positions into SVG coordinate space.
	plotW := float64(netW - 2*netPad)
	plotH := float64(netH - 2*netPad)
	type pos struct{ x, y float64 }
	nodePos := make(map[string]pos, len(g.Nodes))
	for _, n := range g.Nodes {
		nodePos[n.ID] = pos{
			x: float64(netPad) + n.X*plotW,
			y: float64(netPad) + n.Y*plotH,
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb,
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" style="display:block;width:100%%">`,
		netW, netH)

	// Edges first so they render beneath nodes.
	for _, e := range g.Edges {
		sp, ok1 := nodePos[e.Source]
		dp, ok2 := nodePos[e.Target]
		if !ok1 || !ok2 {
			continue
		}
		sw := e.Weight
		if sw < 1 {
			sw = 1
		}
		if sw > 4 {
			sw = 4
		}
		fmt.Fprintf(&sb,
			`<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#3a4a66" stroke-width="%d" opacity="0.7"/>`,
			sp.x, sp.y, dp.x, dp.y, sw)
	}

	// Nodes and labels.
	for _, n := range g.Nodes {
		p, ok := nodePos[n.ID]
		if !ok {
			continue
		}
		r := circleR(n.Size)
		color := html.EscapeString(n.Color)
		if color == "" {
			color = svgAccent
		}
		// n.Label is user-influenced (username or domain name) — must be escaped.
		lbl := html.EscapeString(n.Label)
		fmt.Fprintf(&sb,
			`<circle cx="%.1f" cy="%.1f" r="%.1f" fill="%s" opacity="0.85"/>`,
			p.x, p.y, r, color)
		fmt.Fprintf(&sb,
			`<text x="%.1f" y="%.1f" text-anchor="middle" font-size="9" font-family="'Segoe UI',system-ui,sans-serif" fill="#8a96b2">%s</text>`,
			p.x, p.y+r+10, lbl)
	}

	sb.WriteString(`</svg>`)
	return template.HTML(sb.String())
}
