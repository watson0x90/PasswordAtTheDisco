# Metrics Library (Phase 3: report-derived series + network graphs) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Complete the org-level bundle with the dashboard surfaces that derive from the reuse-grouped `model.Report` (exposure headline, cross-domain bridges, HIBP triage, blast-radius worklist) and the two network graphs (cross-domain reuse + password similarity), each with a deterministic, seeded **force-directed** static layout so HTML exports can draw them without a browser.

**Architecture:** `Compute` builds the redacted `model.Report` once via `model.BuildReport(accounts)` and passes it to a new `buildReportSeries(rep, accounts, now)` that returns a `ReportSeries` attached to the org `Metrics` (under `Reports`). Each series is a faithful Go port of its `web/src/exposure.ts` / `web/src/insights.ts` source. Graph node positions come from a shared, dependency-free, fixed-seed/fixed-iteration force-directed `layout()` so output is byte-identical across runs (golden-stable).

**Tech Stack:** Go (stdlib only: `math`, `sort`), `go test`.

## Global Constraints

- **Go: stdlib-first.** No new external modules. `gofmt -l` empty, `go vet ./...` clean, `go test ./...` green before any commit.
- **Redaction (hard rule).** No cleartext (`Account.Password`), `Account.NTHash`, `Account.BannedWords`, or `Account.KeyboardPatterns` in any series. Report-derived structures reuse `model.ReportAccount` (already redacted). `TestBundleHasNoSensitiveFields` must keep passing.
- **Parity.** Each series matches its `web/src/exposure.ts` / `web/src/insights.ts` source exactly: filters, sort order, tie-breaks, weights, thresholds, colors.
- **Determinism (critical for graphs).** No `time.Now()` / no randomness. The force-directed `layout()` seeds initial node positions from node **index** (deterministic), uses **fixed** force constants and a **fixed** iteration count, so the same nodes/edges always yield identical x/y. Map-derived ordering uses explicit sorts.
- **Additive only.** `ReportSeries` is a new `Metrics.Reports` field; do not rename existing keys. (Per-domain report-derived series are out of scope — see Scope note.)
- **Commit messages** end with: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- **Run all commands from the worktree root** `C:\base\dev\PasswordAtTheDisco\.claude\worktrees\nav-and-pagination-fixes`. Do not `cd` to the primary checkout.

**Scope note:** Part of spec `docs/superpowers/specs/2026-06-30-exports-dashboard-parity-design.md`. This plan does ORG-LEVEL report-derived series + graphs. Per-domain report-derived views (the frontend's `domainScope.domainReport` filters org reuse-groups to those touching a domain — keeping cross-domain clusters) move server-side in the SPA-refactor phase, together with the `/api/metrics` endpoint. `blastRadius` is account-derived (not report-derived) but lives in `exposure.ts`, so it is included here.

**Golden regen note (every task):** after adding fields, run `go test ./internal/metrics/ -run TestMetricsGolden -update`, open `internal/metrics/testdata/metrics_golden.json`, confirm the new keys under `reports`, then run without `-update`. Commit the updated golden with the task. The seed fixture has reuse-relevant accounts (alice/bob share domain A.LOCAL but distinct passwords; no NT hashes set), so most reuse-derived series will be empty arrays — that is expected and still locks structure.

---

### Task 1: Report wiring + `ExposureHeadline`

Build the report once in `Compute`, add the `ReportSeries` scaffold and the `exposureHeadline` port, wire `Reports` into the org `Metrics`.

**Files:**
- Create: `internal/metrics/reportseries.go`
- Modify: `internal/metrics/metrics.go` (build `rep`, add `Reports ReportSeries` to `Metrics`, populate in `Compute`)
- Modify: `internal/metrics/testdata/metrics_golden.json` (regenerate)
- Test: `internal/metrics/reportseries_test.go`

**Interfaces:**
- Consumes: `model.Account` (`Cracked`, `HIBPBreached`, `HasDAPathway()`), `model.Report` (`CrackedReuse`, `UncrackedReuse` — each `[]model.ReuseGroup` with `.Members []model.ReportAccount` having `.Domain`).
- Produces:
  - `type ExposureHeadline struct { CrackedDA int `json:"cracked_da"`; CrackedHIBP int `json:"cracked_hibp"`; CrossDomainGroups int `json:"cross_domain_groups"`; DomainsSpanned int `json:"domains_spanned"` }`
  - `type ReportSeries struct { ExposureHeadline ExposureHeadline `json:"exposure_headline"` }` (later tasks add fields)
  - `func buildReportSeries(rep model.Report, accounts []model.Account) ReportSeries`
  - `func ExposureHeadlineOf(accounts []model.Account, rep model.Report) ExposureHeadline`

**TS source (`web/src/exposure.ts` exposureHeadline):**
```
crackedDA = count(a.cracked && hasDA(a.da_domains))
crackedHibp = count(a.cracked && a.hibp_breached)
for g in [...cracked_reuse, ...uncracked_reuse]:
  doms = distinct(g.members.domain); if doms.size >= 2: crossDomainGroups++; add doms to spanned set
domainsSpanned = spanned.size
```

- [ ] **Step 1: Write the failing test**

```go
// internal/metrics/reportseries_test.go
package metrics

import (
	"testing"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

func TestExposureHeadline(t *testing.T) {
	accts := []model.Account{
		{Cracked: true, DADomains: "A"},                 // crackedDA + (not hibp)
		{Cracked: true, HIBPBreached: true, DADomains: "None"}, // crackedHibp
		{Cracked: false, DADomains: "A"},                // neither (uncracked)
	}
	rep := model.Report{
		CrackedReuse: []model.ReuseGroup{
			{Members: []model.ReportAccount{{Domain: "A"}, {Domain: "B"}}}, // cross-domain (2)
			{Members: []model.ReportAccount{{Domain: "A"}, {Domain: "A"}}}, // single-domain (skip)
		},
		UncrackedReuse: []model.ReuseGroup{
			{Members: []model.ReportAccount{{Domain: "B"}, {Domain: "C"}}}, // cross-domain (2)
		},
	}
	h := ExposureHeadlineOf(accts, rep)
	if h.CrackedDA != 1 {
		t.Errorf("crackedDA = %d, want 1", h.CrackedDA)
	}
	if h.CrackedHIBP != 1 {
		t.Errorf("crackedHibp = %d, want 1", h.CrackedHIBP)
	}
	if h.CrossDomainGroups != 2 {
		t.Errorf("crossDomainGroups = %d, want 2", h.CrossDomainGroups)
	}
	if h.DomainsSpanned != 3 { // A,B from first + B,C from third = {A,B,C}
		t.Errorf("domainsSpanned = %d, want 3", h.DomainsSpanned)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/metrics/ -run TestExposureHeadline -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Create `internal/metrics/reportseries.go`**

```go
package metrics

import "github.com/watson0x90/PasswordAtTheDisco/internal/model"

// ExposureHeadline holds the three executive "blast radius" numbers (cracked&DA,
// cracked&breached, cross-domain reuse) mirroring web/src/exposure.ts exposureHeadline.
type ExposureHeadline struct {
	CrackedDA         int `json:"cracked_da"`
	CrackedHIBP       int `json:"cracked_hibp"`
	CrossDomainGroups int `json:"cross_domain_groups"`
	DomainsSpanned    int `json:"domains_spanned"`
}

// ReportSeries holds the dashboard surfaces derived from the reuse-grouped report.
// (Later tasks add bridges, HIBP triage, worklist, and the two graphs.)
type ReportSeries struct {
	ExposureHeadline ExposureHeadline `json:"exposure_headline"`
}

// groupDomains returns the distinct, member-derived domains of a reuse group.
// Mirrors the TS `new Set(g.members.map(m => m.domain))` (member-derived, so a
// truncated huge group counts only its retained members' domains — same as the API).
func groupDomains(g model.ReuseGroup) map[string]bool {
	doms := map[string]bool{}
	for i := range g.Members {
		doms[g.Members[i].Domain] = true
	}
	return doms
}

// ExposureHeadlineOf computes the exposure headline. accounts gives the cracked&DA
// / cracked&breached counts; rep gives the cross-domain reuse spread.
func ExposureHeadlineOf(accounts []model.Account, rep model.Report) ExposureHeadline {
	var h ExposureHeadline
	for i := range accounts {
		a := accounts[i]
		if a.Cracked && a.HasDAPathway() {
			h.CrackedDA++
		}
		if a.Cracked && a.HIBPBreached {
			h.CrackedHIBP++
		}
	}
	spanned := map[string]bool{}
	groups := append(append([]model.ReuseGroup{}, rep.CrackedReuse...), rep.UncrackedReuse...)
	for _, g := range groups {
		doms := groupDomains(g)
		if len(doms) >= 2 {
			h.CrossDomainGroups++
			for d := range doms {
				spanned[d] = true
			}
		}
	}
	h.DomainsSpanned = len(spanned)
	return h
}

// buildReportSeries assembles the report-derived bundle. (Grows in later tasks.)
func buildReportSeries(rep model.Report, accounts []model.Account) ReportSeries {
	return ReportSeries{
		ExposureHeadline: ExposureHeadlineOf(accounts, rep),
	}
}
```

- [ ] **Step 4: Wire into `metrics.go`**

In `internal/metrics/metrics.go`, add `"github.com/watson0x90/PasswordAtTheDisco/internal/model"` import if not present (it is). Add to the `Metrics` struct (after `Charts`):
```go
	Reports ReportSeries `json:"reports"`
```
Change `Compute` to build the report once and pass it:
```go
func Compute(accounts []model.Account, now time.Time) Metrics {
	rep := model.BuildReport(accounts)
	return Metrics{
		Summary: model.Summarize(accounts, now),
		Matrix:  BuildMatrix(accounts),
		Charts:  buildChartSeries(accounts, now),
		Reports: buildReportSeries(rep, accounts),
		Domains: ComputeByDomain(accounts, now),
	}
}
```

- [ ] **Step 5: Run unit test**

Run: `go test ./internal/metrics/ -run TestExposureHeadline -v`
Expected: PASS.

- [ ] **Step 6: Regenerate + verify golden**

Run: `go test ./internal/metrics/ -run TestMetricsGolden -update`; confirm a `reports.exposure_headline` object appears at org level (the fixture: alice cracked+DA → cracked_da 1; alice cracked+hibp → cracked_hibp 1; no shared NT hashes → cross_domain_groups 0, domains_spanned 0). Run without `-update` → PASS. Confirm `TestBundleHasNoSensitiveFields` passes.

- [ ] **Step 7: Full gate + commit**

Run: `gofmt -l internal/metrics` (empty), `go vet ./...`, `go test ./...`
```bash
git add internal/metrics/reportseries.go internal/metrics/reportseries_test.go internal/metrics/metrics.go internal/metrics/testdata/metrics_golden.json
git commit -m "$(printf 'feat(metrics): report-series scaffold + exposure headline\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 2: cross-domain bridges + HIBP triage

Add `crossDomainBridges` (ranked cross-domain reuse clusters) and `hibpTriage` (tier1 cracked+breached / tier2 breached-only).

**Files:**
- Modify: `internal/metrics/reportseries.go` (2 funcs + types + 2 fields; wire in)
- Modify: `internal/metrics/testdata/metrics_golden.json` (regenerate)
- Test: `internal/metrics/reportseries_test.go`

**Interfaces:**
- Consumes: `model.Report` (`CrackedReuse`/`UncrackedReuse` `[]ReuseGroup` with `.Size`, `.Cracked`, `.HasDAPathway`, `.HIBPBreachCount`, `.Members []ReportAccount`; `HIBPExposed []ReportAccount` with `.Cracked`, `.HIBPBreachCount`, `.RiskScore`).
- Produces:
  - `type BridgeCluster struct { Domains []string `json:"domains"`; Size int `json:"size"`; Cracked bool `json:"cracked"`; HasDA bool `json:"has_da"`; HIBPMax int `json:"hibp_max"`; Members []model.ReportAccount `json:"members"` }`
  - `type CrossDomain struct { Clusters []BridgeCluster `json:"clusters"`; Domains []string `json:"domains"` }`
  - `type HIBPTriage struct { Tier1 []model.ReportAccount `json:"tier1"`; Tier2 []model.ReportAccount `json:"tier2"` }`
  - new `ReportSeries` fields `CrossDomain CrossDomain `json:"cross_domain"`` and `HIBPTriage HIBPTriage `json:"hibp_triage"``
  - `func CrossDomainBridges(rep model.Report) CrossDomain`, `func HIBPTriageOf(rep model.Report) HIBPTriage`

**TS source (`web/src/exposure.ts`):**
```
crossDomainBridges(report):
  for g in [...cracked_reuse, ...uncracked_reuse]:
    doms = sorted(distinct(g.members.domain)); if doms.length < 2: continue
    add doms to domains set
    clusters.push({domains: doms, size: g.size, cracked: g.cracked, hasDA: g.has_da_pathway, hibpMax: g.hibp_breach_count, members: g.members})
  clusters.sort: DA-first ((y.hasDA?1:0)-(x.hasDA?1:0)) then (y.size*y.domains.length - x.size*x.domains.length)
  return {clusters, domains: sorted(domains)}

hibpTriage(report):
  bySeverity = (a,b) => b.hibp_breach_count - a.hibp_breach_count || b.risk_score - a.risk_score
  tier1 = hibp_exposed.filter(cracked).sort(bySeverity)
  tier2 = hibp_exposed.filter(!cracked).sort(bySeverity)
```
**Determinism:** the TS `.sort` is not fully total (ties keep input order). Add a final stable tie-break by `Username` to both the cluster sort and `bySeverity` so Go output is deterministic; document it. Use `sort.SliceStable`.

- [ ] **Step 1: Write the failing tests**

```go
// add to internal/metrics/reportseries_test.go
func TestCrossDomainBridgesRanking(t *testing.T) {
	rep := model.Report{
		CrackedReuse: []model.ReuseGroup{
			{Size: 3, Cracked: true, HasDAPathway: false, Members: []model.ReportAccount{{Domain: "A"}, {Domain: "B"}}},
		},
		UncrackedReuse: []model.ReuseGroup{
			{Size: 2, Cracked: false, HasDAPathway: true, Members: []model.ReportAccount{{Domain: "B"}, {Domain: "C"}}},
			{Size: 9, Cracked: false, Members: []model.ReportAccount{{Domain: "A"}, {Domain: "A"}}}, // single-domain -> skip
		},
	}
	cd := CrossDomainBridges(rep)
	if len(cd.Clusters) != 2 {
		t.Fatalf("clusters = %d, want 2", len(cd.Clusters))
	}
	if !cd.Clusters[0].HasDA { // DA cluster ranks first
		t.Errorf("expected DA cluster first, got %+v", cd.Clusters[0])
	}
	if len(cd.Domains) != 3 { // A,B,C
		t.Errorf("domains = %v, want 3", cd.Domains)
	}
}

func TestHIBPTriageTiers(t *testing.T) {
	rep := model.Report{HIBPExposed: []model.ReportAccount{
		{Username: "a", Cracked: true, HIBPBreachCount: 10, RiskScore: 5},
		{Username: "b", Cracked: true, HIBPBreachCount: 99, RiskScore: 5},
		{Username: "c", Cracked: false, HIBPBreachCount: 3, RiskScore: 9},
	}}
	tr := HIBPTriageOf(rep)
	if len(tr.Tier1) != 2 || tr.Tier1[0].Username != "b" { // sorted by breach desc
		t.Fatalf("tier1 = %+v", tr.Tier1)
	}
	if len(tr.Tier2) != 1 || tr.Tier2[0].Username != "c" {
		t.Fatalf("tier2 = %+v", tr.Tier2)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/metrics/ -run 'TestCrossDomainBridges|TestHIBPTriage' -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement in `reportseries.go`**

```go
import block: add "sort".

type BridgeCluster struct {
	Domains []string             `json:"domains"`
	Size    int                  `json:"size"`
	Cracked bool                 `json:"cracked"`
	HasDA   bool                 `json:"has_da"`
	HIBPMax int                  `json:"hibp_max"`
	Members []model.ReportAccount `json:"members"`
}

type CrossDomain struct {
	Clusters []BridgeCluster `json:"clusters"`
	Domains  []string        `json:"domains"`
}

type HIBPTriage struct {
	Tier1 []model.ReportAccount `json:"tier1"`
	Tier2 []model.ReportAccount `json:"tier2"`
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// CrossDomainBridges ranks cross-domain (>=2 domain) reuse clusters: DA-first, then
// blast radius = size * distinct-domain-count, then first-member username for a
// deterministic tie-break (the TS relied on input order for ties).
func CrossDomainBridges(rep model.Report) CrossDomain {
	clusters := []BridgeCluster{}
	domains := map[string]bool{}
	groups := append(append([]model.ReuseGroup{}, rep.CrackedReuse...), rep.UncrackedReuse...)
	for _, g := range groups {
		doms := sortedKeys(groupDomains(g))
		if len(doms) < 2 {
			continue
		}
		for _, d := range doms {
			domains[d] = true
		}
		clusters = append(clusters, BridgeCluster{
			Domains: doms, Size: g.Size, Cracked: g.Cracked, HasDA: g.HasDAPathway,
			HIBPMax: g.HIBPBreachCount, Members: g.Members,
		})
	}
	sort.SliceStable(clusters, func(i, j int) bool {
		di, dj := boolInt(clusters[i].HasDA), boolInt(clusters[j].HasDA)
		if di != dj {
			return di > dj
		}
		bi := clusters[i].Size * len(clusters[i].Domains)
		bj := clusters[j].Size * len(clusters[j].Domains)
		if bi != bj {
			return bi > bj
		}
		return firstMemberName(clusters[i]) < firstMemberName(clusters[j])
	})
	return CrossDomain{Clusters: clusters, Domains: sortedKeys(domains)}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func firstMemberName(c BridgeCluster) string {
	if len(c.Members) > 0 {
		return c.Members[0].Username
	}
	return ""
}

// HIBPTriageOf splits HIBP-exposed accounts into tier1 (cracked) and tier2
// (not cracked), each sorted by breach count desc, then risk score desc, then
// username asc (deterministic tie-break).
func HIBPTriageOf(rep model.Report) HIBPTriage {
	bySeverity := func(rows []model.ReportAccount) {
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].HIBPBreachCount != rows[j].HIBPBreachCount {
				return rows[i].HIBPBreachCount > rows[j].HIBPBreachCount
			}
			if rows[i].RiskScore != rows[j].RiskScore {
				return rows[i].RiskScore > rows[j].RiskScore
			}
			return rows[i].Username < rows[j].Username
		})
	}
	var t HIBPTriage
	t.Tier1 = []model.ReportAccount{}
	t.Tier2 = []model.ReportAccount{}
	for i := range rep.HIBPExposed {
		a := rep.HIBPExposed[i]
		if a.Cracked {
			t.Tier1 = append(t.Tier1, a)
		} else {
			t.Tier2 = append(t.Tier2, a)
		}
	}
	bySeverity(t.Tier1)
	bySeverity(t.Tier2)
	return t
}
```

Add fields to `ReportSeries`:
```go
	CrossDomain CrossDomain `json:"cross_domain"`
	HIBPTriage  HIBPTriage  `json:"hibp_triage"`
```
Wire in `buildReportSeries`:
```go
		CrossDomain: CrossDomainBridges(rep),
		HIBPTriage:  HIBPTriageOf(rep),
```

- [ ] **Step 4: Run unit tests** — `go test ./internal/metrics/ -run 'TestCrossDomainBridges|TestHIBPTriage' -v` → PASS.

- [ ] **Step 5: Regenerate + verify golden** — `-update`; confirm `reports.cross_domain` and `reports.hibp_triage` appear (fixture: no shared NT hashes → empty clusters/domains; HIBP triage tier1 = alice if cracked+breached). Run without `-update` → PASS; `TestBundleHasNoSensitiveFields` passes.

- [ ] **Step 6: Full gate + commit**

Run: `gofmt -l internal/metrics` (empty), `go vet ./...`, `go test ./...`
```bash
git add internal/metrics/reportseries.go internal/metrics/reportseries_test.go internal/metrics/testdata/metrics_golden.json
git commit -m "$(printf 'feat(metrics): cross-domain bridges + HIBP triage\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 3: blast-radius worklist

Add `blastRadius` — the ranked remediation worklist with reason badges (account-derived).

**Files:**
- Modify: `internal/metrics/reportseries.go` (1 func + types + field; wire in)
- Modify: `internal/metrics/testdata/metrics_golden.json` (regenerate)
- Test: `internal/metrics/reportseries_test.go`

**Interfaces:**
- Consumes: `model.Account` (`HasDAPathway()`, `HIBPBreached`, `HIBPBreachCount`, `Cracked`, `SharedWith`, `Enabled`, `RiskScore`, plus fields for the slim ref).
- Produces:
  - `type WorklistRow struct { Account AccountRef `json:"account"`; Priority int `json:"priority"`; Reasons []string `json:"reasons"` }`
  - new `ReportSeries` field `Worklist []WorklistRow `json:"worklist"``
  - `func BlastRadius(accounts []model.Account) []WorklistRow`

**TS source (`web/src/exposure.ts` blastRadius):**
```
for a in accounts:
  reasons=[]; priority=0
  if hasDA: priority+=3; reasons.push("DA")
  if hibp_breached: priority+=2; reasons.push(`HIBP ${hibp_breach_count.toLocaleString()}`)
  if cracked: priority+=1; reasons.push("Cracked")
  if shared_with>0: priority+=1; reasons.push(`Shared ${shared_with}`)
  if !enabled: reasons.push("disabled")
  if priority>0: rows.push({account, priority, reasons})
rows.sort: priority desc, then account.risk_score desc
```
**Notes:** reuse `AccountRef` + `toRef` from `series.go` (Phase 2) for the slim account. For the HIBP reason string, the TS uses `toLocaleString()` (thousands separators); to keep Go dependency-free and deterministic use a plain decimal (`strconv.Itoa`) — the reason label is descriptive text, exact grouping isn't load-bearing; note this minor formatting divergence. Sort tie-break: add `account.Username` asc after risk for determinism.

- [ ] **Step 1: Write the failing test**

```go
// add to internal/metrics/reportseries_test.go
func TestBlastRadiusPriorityAndReasons(t *testing.T) {
	accts := []model.Account{
		{Username: "danger", DADomains: "A", HIBPBreached: true, HIBPBreachCount: 5, Cracked: true, SharedWith: 2, Enabled: true, RiskScore: 9}, // 3+2+1+1=7
		{Username: "mild", Cracked: true, Enabled: true, RiskScore: 3},                                                                          // 1
		{Username: "clean", Enabled: true, RiskScore: 2},                                                                                        // priority 0 -> excluded
	}
	rows := BlastRadius(accts)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	if rows[0].Account.Username != "danger" || rows[0].Priority != 7 {
		t.Fatalf("row0 = %+v", rows[0])
	}
	if len(rows[0].Reasons) != 4 { // DA, HIBP n, Cracked, Shared n
		t.Errorf("reasons = %v, want 4", rows[0].Reasons)
	}
	if rows[1].Account.Username != "mild" || rows[1].Priority != 1 {
		t.Errorf("row1 = %+v", rows[1])
	}
}
```

- [ ] **Step 2: Run to verify failure** — `go test ./internal/metrics/ -run TestBlastRadius -v` → FAIL.

- [ ] **Step 3: Implement in `reportseries.go`**

```go
import block: add "strconv".

type WorklistRow struct {
	Account  AccountRef `json:"account"`
	Priority int        `json:"priority"`
	Reasons  []string   `json:"reasons"`
}

// BlastRadius is the ranked remediation worklist (mirrors exposure.ts blastRadius):
// DA +3, HIBP +2, Cracked +1, Shared +1; rows with priority>0 only; sorted by
// priority desc, then risk score desc, then username asc (deterministic).
func BlastRadius(accounts []model.Account) []WorklistRow {
	rows := []WorklistRow{}
	for i := range accounts {
		a := accounts[i]
		reasons := []string{}
		priority := 0
		if a.HasDAPathway() {
			priority += 3
			reasons = append(reasons, "DA")
		}
		if a.HIBPBreached {
			priority += 2
			reasons = append(reasons, "HIBP "+strconv.Itoa(a.HIBPBreachCount))
		}
		if a.Cracked {
			priority++
			reasons = append(reasons, "Cracked")
		}
		if a.SharedWith > 0 {
			priority++
			reasons = append(reasons, "Shared "+strconv.Itoa(a.SharedWith))
		}
		if !a.Enabled {
			reasons = append(reasons, "disabled")
		}
		if priority > 0 {
			rows = append(rows, WorklistRow{Account: toRef(a), Priority: priority, Reasons: reasons})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Priority != rows[j].Priority {
			return rows[i].Priority > rows[j].Priority
		}
		if rows[i].Account.RiskScore != rows[j].Account.RiskScore {
			return rows[i].Account.RiskScore > rows[j].Account.RiskScore
		}
		return rows[i].Account.Username < rows[j].Account.Username
	})
	return rows
}
```
Add field to `ReportSeries`: `Worklist []WorklistRow `json:"worklist"``. Wire in `buildReportSeries`: `Worklist: BlastRadius(accounts),`.

- [ ] **Step 4: Run unit test** → PASS.
- [ ] **Step 5: Regenerate + verify golden** — `-update`; confirm `reports.worklist` present (fixture: alice/dave etc. with priorities), redaction guard passes; run without `-update` → PASS.
- [ ] **Step 6: Full gate + commit**

```bash
gofmt -l internal/metrics   # empty
go vet ./... && go test ./...
git add internal/metrics/reportseries.go internal/metrics/reportseries_test.go internal/metrics/testdata/metrics_golden.json
git commit -m "$(printf 'feat(metrics): blast-radius remediation worklist\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 4: network graph DATA (nodes + edges, no layout)

Add `crossDomainReuseGraph` and `similarityNetwork` node/edge data (positions added in Task 5). Ports `web/src/insights.ts`.

**Files:**
- Create: `internal/metrics/graph.go`
- Modify: `internal/metrics/reportseries.go` (2 `ReportSeries` fields; wire in)
- Modify: `internal/metrics/testdata/metrics_golden.json` (regenerate)
- Test: `internal/metrics/graph_test.go`

**Interfaces:**
- Consumes: `model.Report` (reuse groups), `model.Account` (`Domain`, `RiskLevel`, `Cracked`, `SimilarityScore`, `Username`, `SimilarPeers []model.SimilarPeer` with `.Domain`,`.Username`,`.Score`).
- Produces:
  - `type GraphNode struct { ID string `json:"id"`; Label string `json:"label"`; Size float64 `json:"size"`; Color string `json:"color"`; X float64 `json:"x"`; Y float64 `json:"y"` }`
  - `type GraphEdge struct { Source string `json:"source"`; Target string `json:"target"`; Weight int `json:"weight"`; Label string `json:"label,omitempty"` }`
  - `type Graph struct { Nodes []GraphNode `json:"nodes"`; Edges []GraphEdge `json:"edges"` }`
  - new `ReportSeries` fields `ReuseGraph Graph `json:"reuse_graph"`` and `SimilarityGraph Graph `json:"similarity_graph"``
  - `func CrossDomainReuseGraph(rep model.Report, accounts []model.Account) Graph`
  - `func SimilarityNetwork(accounts []model.Account, maxNodes int) Graph`

**TS source (`web/src/insights.ts`):** `crossDomainReuseGraph` (lines 458-492) and `similarityNetwork` (497-534). Port verbatim:
- Reuse graph: domain nodes; pairWeight per cross-domain group += g.size for each domain pair; node size `12 + sqrt(total)*2`; color crit>20 `#fb7185`, crit>5 `#fbbf24`, else `#22d3ee`; edge weight `max(1, ceil(w/10))`, label `"<w> shared"`. Only domains that co-occur are nodes. Empty if no cross-domain pair.
- Similarity: candidates = cracked && similarity_score>=0.7; if <2 → empty; sort by score desc, take maxNodes; node id `domain/username`, label username, size `10 + score*12`, color by risk level; edges from `similar_peers` (score>=... already on peer), only between included nodes, dedup undirected, weight `max(1, round(p.score*3))`, label `"<round(p.score*100)>%"`.
**Determinism:** iterate domain pairs and nodes in sorted order (sort domain keys; the similarity candidate sort is by score desc — add username asc tie-break). Edge lists sorted by (source,target) for stable golden.

(Use `maxNodes = 60` when wiring, matching the dashboard.)

- [ ] **Step 1: Write the failing tests**

```go
// internal/metrics/graph_test.go
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
```

- [ ] **Step 2: Run to verify failure** — `go test ./internal/metrics/ -run 'TestCrossDomainReuseGraph|TestSimilarityNetwork' -v` → FAIL.

- [ ] **Step 3: Create `internal/metrics/graph.go`** — port both functions. (Implementer: transcribe from `web/src/insights.ts` crossDomainReuseGraph & similarityNetwork using the field names above; initialize `X:0,Y:0` for now — Task 5 fills them; build edges then `sort.SliceStable` by `(Source,Target)`; build domain nodes in `sort.Strings` key order; similarity candidates sorted by `SimilarityScore` desc then `Username` asc.) Include `math` import.

```go
package metrics

import (
	"math"
	"sort"
	"strconv"

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
		parts := splitPair(k)
		weight := int(math.Ceil(float64(w) / 10))
		if weight < 1 {
			weight = 1
		}
		g.Edges = append(g.Edges, GraphEdge{Source: parts[0], Target: parts[1], Weight: weight, Label: strconv.Itoa(w) + " shared"})
	}
	return g
}

func splitPair(k string) [2]string {
	for i := 0; i < len(k); i++ {
		if k[i] == '|' {
			return [2]string{k[:i], k[i+1:]}
		}
	}
	return [2]string{k, ""}
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
	return g
}
```
Add `ReportSeries` fields `ReuseGraph Graph `json:"reuse_graph"`` and `SimilarityGraph Graph `json:"similarity_graph"``; wire in `buildReportSeries`:
```go
		ReuseGraph:      CrossDomainReuseGraph(rep, accounts),
		SimilarityGraph: SimilarityNetwork(accounts, 60),
```

- [ ] **Step 4: Run unit tests** → PASS.
- [ ] **Step 5: Regenerate + verify golden** — `-update`; confirm `reports.reuse_graph` / `reports.similarity_graph` present (fixture has no shared hashes / similarity → empty nodes/edges; expected). Run without `-update` → PASS; redaction guard passes (node labels are usernames/domains only).
- [ ] **Step 6: Full gate + commit**

```bash
gofmt -l internal/metrics   # empty
go vet ./... && go test ./...
git add internal/metrics/graph.go internal/metrics/graph_test.go internal/metrics/reportseries.go internal/metrics/testdata/metrics_golden.json
git commit -m "$(printf 'feat(metrics): network graph data (cross-domain reuse + similarity)\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 5: deterministic force-directed layout

Add a seeded, fixed-iteration force-directed `layout()` and apply it to both graphs so each node gets a stable `X`/`Y` for static export rendering.

**Files:**
- Create: `internal/metrics/layout.go`
- Modify: `internal/metrics/graph.go` (call `layout(&g)` before returning each graph)
- Modify: `internal/metrics/testdata/metrics_golden.json` (regenerate)
- Test: `internal/metrics/layout_test.go`

**Interfaces:**
- Consumes: `Graph` (`Nodes` with `ID`, `Edges` with `Source`/`Target`).
- Produces: `func layout(g *Graph)` — mutates `Nodes[i].X/Y` deterministically. Exact, exported helper for tests: `func LayoutPositions(g Graph) Graph` returning a copy with positions filled (so tests don't depend on call order).

**Algorithm (deterministic force-directed):**
- Seed: place node i at angle `2*pi*i/n` on a unit circle: `X = cos, Y = sin` (deterministic, no RNG).
- Constants (fixed): `iterations = 300`, `k_repulse = 0.30`, `k_spring = 0.10`, `springLen = 1.0`, `cool0 = 0.10`, cooling `step = cool0 * (1 - iter/iterations)`.
- Each iteration: for every ordered pair (i,j), repulsion along (i-j) ∝ `k_repulse / dist²` (guard dist with a small epsilon, e.g. 1e-4); for every edge, attraction along the edge ∝ `k_spring * (dist - springLen)`. Accumulate displacement per node, then move each node by `clamp(step) * netForce`.
- After iterations, normalize positions into [0,1]×[0,1] (min-max per axis; if a dimension is degenerate, center at 0.5) so exports can scale to any viewport.
- Determinism: integer-indexed seeding + fixed constants/iteration count + summation in node-index order ⇒ identical output every run. Round X/Y to 4 decimals (`math.Round(v*1e4)/1e4`) to avoid last-ULP golden churn across platforms.

- [ ] **Step 1: Write the failing test**

```go
// internal/metrics/layout_test.go
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
```

- [ ] **Step 2: Run to verify failure** — `go test ./internal/metrics/ -run TestLayout -v` → FAIL (undefined).

- [ ] **Step 3: Create `internal/metrics/layout.go`** — implement the algorithm above. `LayoutPositions(g Graph) Graph` deep-copies nodes, runs the simulation, normalizes + rounds, returns the copy. `layout(g *Graph)` calls it and assigns back (`*g = LayoutPositions(*g)`). Handle n==0 (return as-is) and n==1 (center 0.5,0.5). Build an index map `id->i` once for edges.

```go
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
```

In `graph.go`, before `return g` in BOTH `CrossDomainReuseGraph` and `SimilarityNetwork`, call `layout(&g)`. (For the early `if len(...)==0 { return g }` empty-returns, layout is a no-op, but call it after the nodes are built — i.e. only at the final return, where nodes exist.)

- [ ] **Step 4: Run unit tests** — `go test ./internal/metrics/ -run TestLayout -v` → PASS.
- [ ] **Step 5: Regenerate + verify golden** — `-update`; the fixture graphs are empty (no shared hashes/similarity) so positions won't appear, but the layout code path is covered by `layout_test.go`. Run without `-update` → PASS; full suite green.
- [ ] **Step 6: Full gate + commit**

```bash
gofmt -l internal/metrics   # empty
go vet ./... && go test ./...
git add internal/metrics/layout.go internal/metrics/layout_test.go internal/metrics/graph.go internal/metrics/testdata/metrics_golden.json
git commit -m "$(printf 'feat(metrics): deterministic force-directed graph layout\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

## Self-Review

**Spec coverage (Phase 3 slice):** Org-level report-derived series — exposure headline (Task 1), cross-domain bridges + HIBP triage (Task 2), blast-radius worklist (Task 3) — and the two network graphs with node/edge data (Task 4) plus a deterministic force-directed static layout (Task 5), all attached under `Metrics.Reports`. Per-domain report-derived views and `/api/metrics` are explicitly deferred (Scope note).

**Placeholder scan:** No TBD/TODO; complete Go in every code step. Task 4 Step 3 gives full code for both graph functions; Task 5 gives the full layout. The two documented parity divergences (HIBP-reason uses `strconv.Itoa` not `toLocaleString`; deterministic tie-breaks added where TS relied on input order) are explicit, not placeholders.

**Type consistency:** `ReportSeries` grows additively across tasks (no renames). `AccountRef`/`toRef` reused from Phase 2 `series.go` (Task 3). `Graph`/`GraphNode`/`GraphEdge` defined in Task 4, consumed by Task 5. `groupDomains`/`sortedKeys`/`boolInt` helpers defined once (Tasks 1-2) and reused. `model.ReuseGroup` fields used (`Size`, `Cracked`, `HasDAPathway`, `HIBPBreachCount`, `Members`), `model.ReportAccount` (`Username`, `Domain`, `Cracked`, `HIBPBreachCount`, `RiskScore`), `model.SimilarPeer` (`Domain`, `Username`, `Score`) — implementers must confirm these against `internal/model/report.go` / `model.go` and fix from the compile error if a name differs (e.g. `Domains` on ReuseGroup is an int count, NOT the domain list — the list is derived from `Members` via `groupDomains`).
