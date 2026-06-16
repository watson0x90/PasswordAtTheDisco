// Package report renders an audit's REDACTED findings as a CSV or a
// self-contained HTML report. Cleartext passwords are never included.
package report

import (
	"encoding/csv"
	"html/template"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// DiffAccount references one account in an audit comparison (redacted).
type DiffAccount struct {
	Username string `json:"username"`
	Domain   string `json:"domain"`
	RiskA    string `json:"risk_a,omitempty"`
	RiskB    string `json:"risk_b,omitempty"`
}

// Diff is the comparison of two audits (A = earlier, B = later), keyed by
// domain+username. All fields are redacted (no cleartext).
type Diff struct {
	PostureA      float64       `json:"posture_a"`
	PostureB      float64       `json:"posture_b"`
	StillCracked  int           `json:"still_cracked"`
	NewlyCracked  []DiffAccount `json:"newly_cracked"`
	Remediated    []DiffAccount `json:"remediated"`
	NewlyBreached []DiffAccount `json:"newly_breached"`
	Regressed     []DiffAccount `json:"regressed"`
}

var riskRank = map[string]int{"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

// ComputeDiff compares two audits' redacted account sets.
func ComputeDiff(a, b []model.Account) Diff {
	key := func(x model.Account) string { return strings.ToLower(x.Domain + "\\" + x.Username) }
	am := make(map[string]model.Account, len(a))
	for _, x := range a {
		am[key(x)] = x
	}
	bm := make(map[string]model.Account, len(b))
	for _, x := range b {
		bm[key(x)] = x
	}
	// Initialize to non-nil so JSON emits [] not null (the client maps over them).
	d := Diff{
		NewlyCracked:  []DiffAccount{},
		Remediated:    []DiffAccount{},
		NewlyBreached: []DiffAccount{},
		Regressed:     []DiffAccount{},
	}
	d.PostureA = model.PostureScore(a).Score
	d.PostureB = model.PostureScore(b).Score
	ref := func(ax, bx model.Account, name model.Account) DiffAccount {
		return DiffAccount{Username: name.Username, Domain: name.Domain, RiskA: ax.RiskLevel, RiskB: bx.RiskLevel}
	}
	for k, bx := range bm {
		ax, inA := am[k]
		if bx.Cracked {
			if !inA || !ax.Cracked {
				d.NewlyCracked = append(d.NewlyCracked, ref(ax, bx, bx))
			} else {
				d.StillCracked++
			}
		}
		if bx.HIBPBreached && (!inA || !ax.HIBPBreached) {
			d.NewlyBreached = append(d.NewlyBreached, ref(ax, bx, bx))
		}
		if inA && riskRank[bx.RiskLevel] > riskRank[ax.RiskLevel] {
			d.Regressed = append(d.Regressed, ref(ax, bx, bx))
		}
	}
	for k, ax := range am {
		if bx, inB := bm[k]; ax.Cracked && (!inB || !bx.Cracked) {
			d.Remediated = append(d.Remediated, ref(ax, bx, ax))
		}
	}
	return d
}

// CSV writes the accounts as a redacted CSV (no password column).
// CSV writes the redacted per-account summary: one row per account with crack
// status, HIBP exposure, password reuse, and any pathway to a Tier-0 / privileged
// (Domain Admin) account. It never includes a cleartext password or an NT hash.
func CSV(w io.Writer, accounts []model.Account) error {
	cw := csv.NewWriter(w)
	header := []string{
		"domain", "username", "enabled", "status", "password_length", "complexity",
		"meets_policy", "risk_level", "risk_score", "risk_vector", "hibp_found", "hibp_breach_count",
		"reused", "shared_with", "tier0_pathway", "tier0_pathway_domains", "controlled_objects",
		"common_password", "dictionary_word", "forbidden_words", "keyboard_patterns",
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, a := range accounts {
		status := "Uncracked"
		pwLen := "" // password length is only meaningful for a cracked account
		if a.Cracked {
			status = "Cracked"
			pwLen = strconv.Itoa(a.PasswordLength)
		}
		tier0 := a.HasDAPathway() // a path to Domain Admin (Tier 0 / privileged)
		tier0Domains := ""
		if tier0 {
			tier0Domains = a.DADomains
		}
		row := []string{
			csvSafe(a.Domain), csvSafe(a.Username), yesNo(a.Enabled), status, pwLen, csvSafe(a.Complexity),
			yesNo(a.MeetsPolicy), csvSafe(a.RiskLevel), strconv.FormatFloat(a.RiskScore, 'f', 1, 64), csvSafe(a.RiskVector),
			yesNo(a.HIBPBreached), strconv.Itoa(a.HIBPBreachCount),
			yesNo(a.SharedWith > 0), strconv.Itoa(a.SharedWith),
			yesNo(tier0), csvSafe(tier0Domains), strconv.Itoa(a.Controlled),
			// wordlist weakness signals (counts/booleans only -- never the matched word)
			yesNo(a.IsCommon), yesNo(a.IsDictionaryWord), strconv.Itoa(a.BannedWordCount), strconv.Itoa(a.KeyboardPatternCount),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// ReuseGroupsCSV writes one row per shared-password group (cracked and uncracked),
// keyed on a shared NT hash. The hash itself is never emitted; members are listed
// by username only. group_id is opaque but unique across both group types.
func ReuseGroupsCSV(w io.Writer, rep model.Report) error {
	cw := csv.NewWriter(w)
	header := []string{
		"group_id", "type", "size", "domains", "hibp_breach_count", "reaches_tier0", "members",
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	writeGroup := func(g model.ReuseGroup, typ string) error {
		names := make([]string, 0, len(g.Members))
		for _, m := range g.Members {
			names = append(names, m.Username)
		}
		members := strings.Join(names, "; ")
		if g.Truncated { // BuildReport caps members; note the remainder
			members += " (+" + strconv.Itoa(g.Size-len(g.Members)) + " more)"
		}
		return cw.Write([]string{
			strconv.Itoa(g.GroupID), typ, strconv.Itoa(g.Size), strconv.Itoa(g.Domains),
			strconv.Itoa(g.HIBPBreachCount), yesNo(g.HasDAPathway), csvSafe(members),
		})
	}
	for _, g := range rep.CrackedReuse {
		if err := writeGroup(g, "Cracked"); err != nil {
			return err
		}
	}
	for _, g := range rep.UncrackedReuse {
		if err := writeGroup(g, "Uncracked"); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// csvSafe neutralizes spreadsheet formula injection (CWE-1236): a cell that would
// start with =, +, -, @, tab or CR is prefixed with a single quote so Excel/Sheets
// treat it as text. encoding/csv already handles comma/quote/newline quoting.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

type riskRow struct {
	Level string
	Count int
	Pct   int
	Color string
}

type domRow struct {
	Domain                                 string
	Total, Cracked, Breached, Critical, DA int
}

type htmlData struct {
	Name, Generated              string
	Score                        float64
	Rating, Likelihood           string
	BR                           [4]float64
	BRPct                        [4]int
	Total, Cracked, Breached, DA int
	Risk                         []riskRow
	Domains                      []domRow
	Accounts                     []model.Account
}

var riskColor = map[string]string{"Critical": "#fb7185", "High": "#fbbf24", "Medium": "#a3e635", "Low": "#22d3ee"}

// HTML writes a self-contained (inline CSS, no scripts/assets) redacted report.
func HTML(w io.Writer, name string, generated time.Time, accounts []model.Account) error {
	d := htmlData{Name: name, Generated: generated.UTC().Format("2006-01-02 15:04 UTC"), Accounts: accounts}

	riskCounts := map[string]int{}
	doms := map[string]*domRow{}
	for _, a := range accounts {
		d.Total++
		if a.Cracked {
			d.Cracked++
		}
		if a.HIBPBreached {
			d.Breached++
		}
		if a.HasDAPathway() {
			d.DA++
		}
		if a.RiskLevel != "" {
			riskCounts[a.RiskLevel]++
		}
		dr := doms[a.Domain]
		if dr == nil {
			dr = &domRow{Domain: a.Domain}
			doms[a.Domain] = dr
		}
		dr.Total++
		if a.Cracked {
			dr.Cracked++
		}
		if a.HIBPBreached {
			dr.Breached++
		}
		if a.RiskLevel == "Critical" {
			dr.Critical++
		}
		if a.HasDAPathway() {
			dr.DA++
		}
	}

	p := model.PostureScore(accounts)
	d.Score, d.Rating, d.Likelihood = p.Score, p.Rating, p.Likelihood
	d.BR = [4]float64{p.Breakdown.Risk, p.Breakdown.Strength, p.Breakdown.Privilege, p.Breakdown.Compliance}
	d.BRPct = [4]int{int(d.BR[0] / 40 * 100), int(d.BR[1] / 30 * 100), int(d.BR[2] / 15 * 100), int(d.BR[3] / 15 * 100)}

	maxRisk := 1
	for _, c := range riskCounts {
		if c > maxRisk {
			maxRisk = c
		}
	}
	for _, lvl := range []string{"Critical", "High", "Medium", "Low"} {
		if c := riskCounts[lvl]; c > 0 {
			d.Risk = append(d.Risk, riskRow{Level: lvl, Count: c, Pct: c * 100 / maxRisk, Color: riskColor[lvl]})
		}
	}
	for _, dr := range doms {
		d.Domains = append(d.Domains, *dr)
	}
	sort.Slice(d.Domains, func(i, j int) bool {
		return d.Domains[i].Critical > d.Domains[j].Critical || (d.Domains[i].Critical == d.Domains[j].Critical && d.Domains[i].Total > d.Domains[j].Total)
	})

	return htmlTemplate.Execute(w, d)
}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"f1":    func(f float64) string { return strconv.FormatFloat(f, 'f', 1, 64) },
	"color": func(level string) string { return riskColor[level] },
}).Parse(reportHTML))

const reportHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{{.Name}} — Password!AtTheDisco report</title>
<style>
:root{--bg:#0a0e1a;--panel:#121a2e;--line:#242e46;--text:#e8edf7;--dim:#8a96b2;--faint:#566076}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:"Segoe UI",system-ui,sans-serif;font-size:14px;line-height:1.5;padding:32px}
.wrap{max-width:1000px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px}
.sub{color:var(--dim);font-size:13px;margin-bottom:6px}
.redact{display:inline-block;font-size:11px;color:#7dd3fc;border:1px solid #1e4b66;background:rgba(34,211,238,.08);border-radius:6px;padding:2px 9px;margin-bottom:24px}
.label{font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--faint);margin:28px 0 12px;font-weight:600}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px}
.exec{display:flex;gap:32px;align-items:center;flex-wrap:wrap}
.score{font-size:48px;font-weight:700;font-variant-numeric:tabular-nums}
.rating{font-size:13px;letter-spacing:1px;text-transform:uppercase;font-weight:600}
.exec .meta{color:var(--dim);font-size:13px}
.br{flex:1;min-width:260px}
.brrow{display:flex;justify-content:space-between;font-size:12.5px;color:var(--dim);margin:8px 0 4px}
.track{height:8px;background:#0c1320;border-radius:4px;overflow:hidden}
.fill{height:100%;background:linear-gradient(90deg,#0e7490,#22d3ee);border-radius:4px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
.card .v{font-size:30px;font-weight:600;font-variant-numeric:tabular-nums}
.card .k{font-size:12px;color:var(--dim)}
.risk{display:flex;align-items:center;gap:14px;padding:7px 0}
.risk .name{width:90px;font-size:13px}.risk .ct{width:50px;text-align:right;font-variant-numeric:tabular-nums}
.risk .bar{flex:1;height:9px;background:#0c1320;border-radius:5px;overflow:hidden}
.risk .bf{height:100%;border-radius:5px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:left;color:var(--faint);font-size:11px;text-transform:uppercase;letter-spacing:.5px;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:7px 10px;border-bottom:1px solid #1b2236;white-space:nowrap}
.badge{font-size:11px;font-weight:600;padding:2px 9px;border-radius:999px;border:1px solid}
.muted{color:var(--faint)}
.wtag{display:inline-block;font-size:10px;color:#fbbf24;border:1px solid rgba(251,191,36,.4);background:rgba(251,191,36,.1);border-radius:999px;padding:1px 7px;margin:1px 2px 1px 0}
.foot{color:var(--faint);font-size:11px;margin-top:30px;text-align:center}
</style></head>
<body><div class="wrap">
<h1>{{.Name}}</h1>
<div class="sub">Password!AtTheDisco — generated {{.Generated}}</div>
<span class="redact">Redacted report · no cleartext passwords</span>

<div class="label">Security posture</div>
<div class="panel exec">
  <div>
    <div class="score" style="color:{{if ge .Score 85.0}}#34d399{{else if ge .Score 70.0}}#fbbf24{{else}}#fb7185{{end}}">{{f1 .Score}}</div>
    <div class="rating" style="color:{{if ge .Score 85.0}}#34d399{{else if ge .Score 70.0}}#fbbf24{{else}}#fb7185{{end}}">{{.Rating}}</div>
    <div class="meta">breach likelihood: {{.Likelihood}}</div>
  </div>
  <div class="br">
    <div class="brrow"><span>Risk distribution</span><span>{{f1 (index .BR 0)}} / 40</span></div><div class="track"><div class="fill" style="width:{{index .BRPct 0}}%"></div></div>
    <div class="brrow"><span>Password strength</span><span>{{f1 (index .BR 1)}} / 30</span></div><div class="track"><div class="fill" style="width:{{index .BRPct 1}}%"></div></div>
    <div class="brrow"><span>Privilege exposure</span><span>{{f1 (index .BR 2)}} / 15</span></div><div class="track"><div class="fill" style="width:{{index .BRPct 2}}%"></div></div>
    <div class="brrow"><span>Policy compliance</span><span>{{f1 (index .BR 3)}} / 15</span></div><div class="track"><div class="fill" style="width:{{index .BRPct 3}}%"></div></div>
  </div>
</div>

<div class="label">Overview</div>
<div class="cards">
  <div class="card"><div class="v">{{.Total}}</div><div class="k">Accounts</div></div>
  <div class="card"><div class="v">{{.Cracked}}</div><div class="k">Cracked</div></div>
  <div class="card"><div class="v" style="color:#38bdf8">{{.Breached}}</div><div class="k">HIBP breached</div></div>
  <div class="card"><div class="v" style="color:#fb7185">{{.DA}}</div><div class="k">DA pathways</div></div>
</div>

<div class="label">Risk distribution</div>
<div class="panel">
{{range .Risk}}<div class="risk"><span class="name" style="color:{{.Color}}">{{.Level}}</span><span class="bar"><span class="bf" style="width:{{.Pct}}%;background:{{.Color}}"></span></span><span class="ct">{{.Count}}</span></div>{{end}}
</div>

<div class="label">Domains</div>
<div class="panel"><table>
<tr><th>Domain</th><th>Accounts</th><th>Cracked</th><th>Breached</th><th>Critical</th><th>DA paths</th></tr>
{{range .Domains}}<tr><td>{{.Domain}}</td><td>{{.Total}}</td><td>{{.Cracked}}</td><td>{{.Breached}}</td><td style="color:#fb7185">{{.Critical}}</td><td style="color:#fb7185">{{.DA}}</td></tr>{{end}}
</table></div>

<div class="label">Accounts ({{.Total}})</div>
<div class="panel"><table>
<tr><th>Username</th><th>Domain</th><th>Risk</th><th>Score</th><th>HIBP</th><th>Complexity</th><th>Policy</th><th>Shared</th><th>DA</th><th>Weaknesses</th></tr>
{{range .Accounts}}<tr>
<td>{{.Username}}</td><td class="muted">{{.Domain}}</td>
<td><span class="badge" style="color:{{color .RiskLevel}};border-color:{{color .RiskLevel}}">{{.RiskLevel}}</span></td>
<td>{{f1 .RiskScore}}</td>
<td>{{if .HIBPBreached}}<span style="color:#fb7185">{{.HIBPBreachCount}}</span>{{else}}<span class="muted">—</span>{{end}}</td>
<td class="muted">{{if .Cracked}}{{.Complexity}}{{else}}—{{end}}</td>
<td>{{if .Cracked}}{{if .MeetsPolicy}}<span style="color:#a3e635">meets</span>{{else}}<span style="color:#fbbf24">fails</span>{{end}}{{else}}<span class="muted">—</span>{{end}}</td>
<td>{{if gt .SharedWith 0}}{{.SharedWith}}{{else}}<span class="muted">0</span>{{end}}</td>
<td>{{if .HasDAPathway}}<span style="color:#fb7185">{{.DADomains}}</span>{{else}}<span class="muted">—</span>{{end}}</td>
<td>{{if .IsCommon}}<span class="wtag">common</span> {{end}}{{if .IsDictionaryWord}}<span class="wtag">dictionary</span> {{end}}{{if gt .BannedWordCount 0}}<span class="wtag">forbidden</span> {{end}}{{if gt .KeyboardPatternCount 0}}<span class="wtag">keyboard</span> {{end}}{{if not .IsWeak}}<span class="muted">—</span>{{end}}</td>
</tr>{{end}}
</table></div>

<div class="foot">Generated by Password!AtTheDisco · cleartext passwords are never written to disk or included in reports</div>
</div></body></html>`

// ---- focused HTML reports (complement the focused CSVs) ----

var tmplFuncs = template.FuncMap{
	"f1":    func(f float64) string { return strconv.FormatFloat(f, 'f', 1, 64) },
	"color": func(level string) string { return riskColor[level] },
	"tier0": func(s string) bool { return s != "" && s != "None" && s != "Unknown" },
}

// focusedCSS is the inline styling shared by the focused HTML reports (self-
// contained: no external assets or scripts).
const focusedCSS = `:root{--bg:#0a0e1a;--panel:#121a2e;--line:#242e46;--text:#e8edf7;--dim:#8a96b2;--faint:#566076}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:"Segoe UI",system-ui,sans-serif;font-size:14px;line-height:1.5;padding:32px}
.wrap{max-width:1000px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px}
.sub{color:var(--dim);font-size:13px;margin-bottom:6px}
.redact{display:inline-block;font-size:11px;color:#7dd3fc;border:1px solid #1e4b66;background:rgba(34,211,238,.08);border-radius:6px;padding:2px 9px;margin-bottom:24px}
.label{font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--faint);margin:28px 0 12px;font-weight:600}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:left;color:var(--faint);font-size:11px;text-transform:uppercase;letter-spacing:.5px;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:7px 10px;border-bottom:1px solid #1b2236;white-space:nowrap}
.badge{font-size:11px;font-weight:600;padding:2px 9px;border-radius:999px;border:1px solid}
.muted{color:var(--faint)}
.foot{color:var(--faint);font-size:11px;margin-top:30px;text-align:center}
.group{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:12px}
.ghead{font-size:13px;margin-bottom:10px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.gsize{font-family:ui-monospace,monospace;font-weight:700;color:#fb7185}
.gtag{font-size:11px;border:1px solid var(--line);border-radius:999px;padding:2px 8px;color:var(--dim)}
.wtag{display:inline-block;font-size:10px;color:#fbbf24;border:1px solid rgba(251,191,36,.4);background:rgba(251,191,36,.1);border-radius:999px;padding:1px 7px;margin:1px 2px 1px 0}
.empty{color:var(--dim);font-size:13px}`

type focusedData struct {
	Name, Subtitle, Generated string
	Count                     int
	Accounts                  []model.Account
}

// AccountsHTML writes a focused, redacted HTML report listing a single subset of
// accounts (e.g. cracked-only or HIBP-exposed) — the complement of the focused CSV.
func AccountsHTML(w io.Writer, name, subtitle string, generated time.Time, accounts []model.Account) error {
	return focusedAccountsTemplate.Execute(w, focusedData{
		Name: name, Subtitle: subtitle, Generated: generated.UTC().Format("2006-01-02 15:04 UTC"),
		Count: len(accounts), Accounts: accounts,
	})
}

var focusedAccountsTemplate = template.Must(template.New("focused-accounts").Funcs(tmplFuncs).Parse(
	`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{{.Name}} — Password!AtTheDisco</title>
<style>` + focusedCSS + `</style></head>
<body><div class="wrap">
<h1>{{.Name}}</h1>
<div class="sub">Password!AtTheDisco — {{.Subtitle}} · generated {{.Generated}}</div>
<span class="redact">Redacted report · no cleartext passwords or hashes</span>
<div class="label">{{.Count}} account{{if ne .Count 1}}s{{end}}</div>
<div class="panel"><table>
<tr><th>Username</th><th>Domain</th><th>Status</th><th>Risk</th><th>Score</th><th>Length</th><th>HIBP</th><th>Shared</th><th>Tier-0 pathway</th><th>Weaknesses</th></tr>
{{range .Accounts}}<tr>
<td>{{.Username}}</td><td class="muted">{{.Domain}}</td>
<td>{{if .Cracked}}Cracked{{else}}<span class="muted">Uncracked</span>{{end}}</td>
<td><span class="badge" style="color:{{color .RiskLevel}};border-color:{{color .RiskLevel}}">{{.RiskLevel}}</span></td>
<td>{{f1 .RiskScore}}</td>
<td>{{if .Cracked}}{{.PasswordLength}}{{else}}<span class="muted">—</span>{{end}}</td>
<td>{{if .HIBPBreached}}<span style="color:#fb7185">{{.HIBPBreachCount}}</span>{{else}}<span class="muted">—</span>{{end}}</td>
<td>{{if gt .SharedWith 0}}{{.SharedWith}}{{else}}<span class="muted">0</span>{{end}}</td>
<td>{{if .HasDAPathway}}<span style="color:#fb7185">{{.DADomains}}</span>{{else}}<span class="muted">—</span>{{end}}</td>
<td>{{if .IsCommon}}<span class="wtag">common</span> {{end}}{{if .IsDictionaryWord}}<span class="wtag">dictionary</span> {{end}}{{if gt .BannedWordCount 0}}<span class="wtag">forbidden</span> {{end}}{{if gt .KeyboardPatternCount 0}}<span class="wtag">keyboard</span> {{end}}{{if not .IsWeak}}<span class="muted">—</span>{{end}}</td>
</tr>{{end}}
{{if not .Accounts}}<tr><td colspan="10" class="empty">none</td></tr>{{end}}
</table></div>
<div class="foot">Generated by Password!AtTheDisco · cleartext passwords are never written to disk or included in reports</div>
</div></body></html>`))

type catBar struct {
	Label string
	N     int
	Pct   int
}

type weakData struct {
	Name, Generated string
	Count           int
	Bars            []catBar
	Accounts        []model.Account
}

// WeakPasswordsHTML renders the weak-passwords report: a by-category bar chart
// (counts only) over the supplied accounts, then the redacted account table. It
// never emits a matched word -- the actual terms are app-only (the terms endpoint).
func WeakPasswordsHTML(w io.Writer, name string, generated time.Time, accounts []model.Account) error {
	var common, dict, forbidden, keyboard int
	for _, a := range accounts {
		if a.IsCommon {
			common++
		}
		if a.IsDictionaryWord {
			dict++
		}
		if a.BannedWordCount > 0 {
			forbidden++
		}
		if a.KeyboardPatternCount > 0 {
			keyboard++
		}
	}
	bars := []catBar{
		{"Forbidden", forbidden, 0}, {"Common", common, 0},
		{"Dictionary", dict, 0}, {"Keyboard", keyboard, 0},
	}
	max := 1
	for _, b := range bars {
		if b.N > max {
			max = b.N
		}
	}
	for i := range bars {
		bars[i].Pct = bars[i].N * 100 / max
	}
	return weakTemplate.Execute(w, weakData{
		Name: name, Generated: generated.UTC().Format("2006-01-02 15:04 UTC"),
		Count: len(accounts), Bars: bars, Accounts: accounts,
	})
}

const weakCSS = focusedCSS + `
.cbar{display:grid;grid-template-columns:90px 1fr 30px;align-items:center;gap:10px;margin:7px 0;font:12px/1 ui-monospace,monospace}
.cbar .cl{color:#8a96b2;text-align:right}
.cbar .ct2{height:13px;background:#11182b;border-radius:4px;overflow:hidden}
.cbar .cf{height:100%;border-radius:4px;background:linear-gradient(90deg,#0e7490,#22d3ee)}
.cbar .cn{color:#e8edf7;text-align:right}`

var weakTemplate = template.Must(template.New("weak").Funcs(tmplFuncs).Parse(
	`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{{.Name}} — Weak passwords</title>
<style>` + weakCSS + `</style></head>
<body><div class="wrap">
<h1>{{.Name}} — Weak passwords</h1>
<div class="sub">Password!AtTheDisco — wordlist violations · generated {{.Generated}}</div>
<span class="redact">Redacted report · categories &amp; counts only — never the matched word</span>
<div class="label">by violation category</div>
<div class="panel">
{{range .Bars}}<div class="cbar"><span class="cl">{{.Label}}</span><span class="ct2"><span class="cf" style="width:{{.Pct}}%"></span></span><span class="cn">{{.N}}</span></div>{{end}}
</div>
<div class="label">{{.Count}} account{{if ne .Count 1}}s{{end}}</div>
<div class="panel"><table>
<tr><th>Username</th><th>Domain</th><th>Risk</th><th>Score</th><th>Weaknesses</th></tr>
{{range .Accounts}}<tr>
<td>{{.Username}}</td><td class="muted">{{.Domain}}</td>
<td><span class="badge" style="color:{{color .RiskLevel}};border-color:{{color .RiskLevel}}">{{.RiskLevel}}</span></td>
<td>{{f1 .RiskScore}}</td>
<td>{{if .IsCommon}}<span class="wtag">common</span> {{end}}{{if .IsDictionaryWord}}<span class="wtag">dictionary</span> {{end}}{{if gt .BannedWordCount 0}}<span class="wtag">forbidden</span> {{end}}{{if gt .KeyboardPatternCount 0}}<span class="wtag">keyboard</span> {{end}}{{if not .IsWeak}}<span class="muted">—</span>{{end}}</td>
</tr>{{end}}
{{if not .Accounts}}<tr><td colspan="5" class="empty">none</td></tr>{{end}}
</table></div>
<div class="foot">Generated by Password!AtTheDisco · cleartext passwords are never written to disk or included in reports</div>
</div></body></html>`))

type reuseData struct {
	Name, Generated string
	Report          model.Report
}

// ReuseGroupsHTML writes the redacted shared-password-group report (cracked and
// uncracked), the complement of the reuse-groups CSV. The NT hash is never emitted.
func ReuseGroupsHTML(w io.Writer, name string, generated time.Time, rep model.Report) error {
	return reuseTemplate.Execute(w, reuseData{Name: name, Generated: generated.UTC().Format("2006-01-02 15:04 UTC"), Report: rep})
}

var reuseTemplate = template.Must(template.New("reuse").Funcs(tmplFuncs).Parse(
	`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{{.Name}} — Password!AtTheDisco</title>
<style>` + focusedCSS + `</style></head>
<body><div class="wrap">
<h1>{{.Name}}</h1>
<div class="sub">Password!AtTheDisco — password-reuse groups · generated {{.Generated}}</div>
<span class="redact">Redacted report · accounts grouped by shared NT hash; the hash is never shown</span>
{{define "group"}}<div class="group">
<div class="ghead"><span class="gsize">{{.Size}}×</span> accounts share {{if .Cracked}}a cracked{{else}}an uncracked{{end}} password
{{if gt .Domains 1}}<span class="gtag">{{.Domains}} domains</span>{{end}}
{{if gt .HIBPBreachCount 0}}<span class="gtag">HIBP {{.HIBPBreachCount}}</span>{{end}}
{{if .HasDAPathway}}<span class="gtag" style="color:#fb7185;border-color:#fb7185">Tier-0 reachable</span>{{end}}</div>
<table><tr><th>Username</th><th>Domain</th><th>Risk</th><th>Score</th><th>Tier-0 pathway</th></tr>
{{range .Members}}<tr><td>{{.Username}}</td><td class="muted">{{.Domain}}</td>
<td><span class="badge" style="color:{{color .RiskLevel}};border-color:{{color .RiskLevel}}">{{.RiskLevel}}</span></td>
<td>{{f1 .RiskScore}}</td>
<td>{{if tier0 .DADomains}}<span style="color:#fb7185">{{.DADomains}}</span>{{else}}<span class="muted">—</span>{{end}}</td>
</tr>{{end}}
{{if .Truncated}}<tr><td colspan="5" class="muted">… first {{len .Members}} of {{.Size}} members shown</td></tr>{{end}}
</table></div>{{end}}
<div class="label">Shared cracked passwords ({{len .Report.CrackedReuse}})</div>
{{range .Report.CrackedReuse}}{{template "group" .}}{{end}}
{{if not .Report.CrackedReuse}}<div class="panel empty">none — no two accounts share a cracked password</div>{{end}}
<div class="label">Shared uncracked passwords ({{len .Report.UncrackedReuse}})</div>
{{range .Report.UncrackedReuse}}{{template "group" .}}{{end}}
{{if not .Report.UncrackedReuse}}<div class="panel empty">none — no two uncracked accounts share an NT hash</div>{{end}}
<div class="foot">Generated by Password!AtTheDisco · cleartext passwords are never written to disk or included in reports</div>
</div></body></html>`))
