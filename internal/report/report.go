// Package report renders an audit's REDACTED findings as a CSV or a
// self-contained HTML report. Cleartext passwords are never included.
package report

import (
	"encoding/csv"
	"html/template"
	"io"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// CSV writes the accounts as a redacted CSV (no password column).
func CSV(w io.Writer, accounts []model.Account) error {
	cw := csv.NewWriter(w)
	header := []string{
		"username", "domain", "cracked", "password_length", "complexity",
		"risk_level", "risk_score", "risk_vector", "hibp_breached", "hibp_breach_count",
		"da_domains", "controlled_objects", "shared_with", "enabled", "meets_policy",
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, a := range accounts {
		row := []string{
			a.Username, a.Domain, strconv.FormatBool(a.Cracked), strconv.Itoa(a.PasswordLength), a.Complexity,
			a.RiskLevel, strconv.FormatFloat(a.RiskScore, 'f', 1, 64), a.RiskVector,
			strconv.FormatBool(a.HIBPBreached), strconv.Itoa(a.HIBPBreachCount),
			a.DADomains, strconv.Itoa(a.Controlled), strconv.Itoa(a.SharedWith),
			strconv.FormatBool(a.Enabled), strconv.FormatBool(a.MeetsPolicy),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
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

func round1(f float64) float64 { return math.Round(f*10) / 10 }

// HTML writes a self-contained (inline CSS, no scripts/assets) redacted report.
func HTML(w io.Writer, name string, generated time.Time, accounts []model.Account) error {
	d := htmlData{Name: name, Generated: generated.UTC().Format("2006-01-02 15:04 UTC"), Accounts: accounts}

	var crit, high, med, cracked, uncracked, viol int
	riskCounts := map[string]int{}
	doms := map[string]*domRow{}
	for _, a := range accounts {
		d.Total++
		if a.Cracked {
			cracked++
		} else {
			uncracked++
		}
		if a.HIBPBreached {
			d.Breached++
		}
		if a.HasDAPathway() {
			d.DA++
		}
		if a.Cracked && !a.MeetsPolicy {
			viol++
		}
		if a.RiskLevel != "" {
			riskCounts[a.RiskLevel]++
		}
		switch a.RiskLevel {
		case "Critical":
			crit++
		case "High":
			high++
		case "Medium":
			med++
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
	d.Cracked = cracked

	// Security Posture Score (matches the in-app executive score).
	ft := float64(d.Total)
	score, rating, likelihood := 0.0, "No Data", "—"
	if d.Total > 0 {
		risk := math.Max(0, 100-float64(crit)/ft*200-float64(high)/ft*150-float64(med)/ft*50) / 100 * 40
		strength := 0.0
		if cracked+uncracked > 0 {
			strength = float64(uncracked) / float64(cracked+uncracked) * 30
		}
		priv := math.Max(0, 15-float64(d.DA)/ft*100)
		comp := float64(d.Total-viol) / ft * 15
		score = round1(risk + strength + priv + comp)
		rating = "Weak"
		if score >= 85 {
			rating = "Strong"
		} else if score >= 70 {
			rating = "Fair"
		}
		likelihood = "Low"
		if crit > 50 || d.DA > 20 {
			likelihood = "Very High"
		} else if crit > 20 || d.DA > 10 {
			likelihood = "High"
		} else if crit > 5 || d.DA > 3 {
			likelihood = "Medium"
		}
		d.BR = [4]float64{round1(risk), round1(strength), round1(priv), round1(comp)}
		d.BRPct = [4]int{int(risk / 40 * 100), int(strength / 30 * 100), int(priv / 15 * 100), int(comp / 15 * 100)}
	}
	d.Score, d.Rating, d.Likelihood = score, rating, likelihood

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
<tr><th>Username</th><th>Domain</th><th>Risk</th><th>Score</th><th>HIBP</th><th>Complexity</th><th>Policy</th><th>Shared</th><th>DA</th></tr>
{{range .Accounts}}<tr>
<td>{{.Username}}</td><td class="muted">{{.Domain}}</td>
<td><span class="badge" style="color:{{color .RiskLevel}};border-color:{{color .RiskLevel}}">{{.RiskLevel}}</span></td>
<td>{{f1 .RiskScore}}</td>
<td>{{if .HIBPBreached}}<span style="color:#fb7185">{{.HIBPBreachCount}}</span>{{else}}<span class="muted">—</span>{{end}}</td>
<td class="muted">{{if .Cracked}}{{.Complexity}}{{else}}—{{end}}</td>
<td>{{if .Cracked}}{{if .MeetsPolicy}}<span style="color:#a3e635">meets</span>{{else}}<span style="color:#fbbf24">fails</span>{{end}}{{else}}<span class="muted">—</span>{{end}}</td>
<td>{{if gt .SharedWith 0}}{{.SharedWith}}{{else}}<span class="muted">0</span>{{end}}</td>
<td>{{if .HasDAPathway}}<span style="color:#fb7185">{{.DADomains}}</span>{{else}}<span class="muted">—</span>{{end}}</td>
</tr>{{end}}
</table></div>

<div class="foot">Generated by Password!AtTheDisco · cleartext passwords are never written to disk or included in reports</div>
</div></body></html>`
