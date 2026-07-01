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
