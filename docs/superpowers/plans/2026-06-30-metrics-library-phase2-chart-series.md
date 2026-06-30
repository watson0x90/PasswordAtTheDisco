# Metrics Library (Phase 2: account-derived chart series) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the `internal/metrics` bundle with the dashboard chart series that derive purely from `[]model.Account`, so the API, SPA, and exporters render one server-computed copy instead of the SPA recomputing them in `web/src/insights.ts`.

**Architecture:** Add a `ChartSeries` struct to the bundle, computed by a new `buildChartSeries(accounts, now)` and attached to both org `Metrics` and each `DomainMetrics`. Each function is a faithful Go port of the corresponding `web/src/insights.ts` function (same buckets, thresholds, colors, ordering, and filters). The existing golden snapshot test (`internal/metrics/golden_test.go`) regenerates to lock the new fields.

**Tech Stack:** Go (stdlib only: `math`, `sort`, `time`), `go test`.

## Global Constraints

- **Go: stdlib-first.** No new external modules. `gofmt -l` empty, `go vet ./...` clean, `go test ./...` green before any commit.
- **Redaction (hard rule).** No cleartext (`Account.Password`), `Account.NTHash`, `Account.BannedWords`, or `Account.KeyboardPatterns` may appear in any series. The existing `TestBundleHasNoSensitiveFields` guard must keep passing.
- **Parity (the point of this phase).** Each series must match its `web/src/insights.ts` source EXACTLY: identical bucket edges, thresholds, hex colors, sort order, tie-breaks, and inclusion filters (e.g. "cracked only", "value > 0 filtered out"). The TS source for each function is reproduced in its task.
- **Determinism.** No `time.Now()` — the bundle's `now time.Time` is threaded through age-based series. All ordering deterministic (explicit sorts, stable map iteration via fixed key slices).
- **Additive only.** `ChartSeries` is a new field; do not rename or change existing `Metrics`/`DomainMetrics`/`Summary`/`Matrix` JSON keys.
- **Commit messages** end with: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- **Run all commands from the worktree root** `C:\base\dev\PasswordAtTheDisco\.claude\worktrees\nav-and-pagination-fixes`. Do not `cd` to the primary checkout.

**Scope note:** Part of spec `docs/superpowers/specs/2026-06-30-exports-dashboard-parity-design.md`. This plan ports the `[]Account`-pure series from `insights.ts`. Deferred to the next plan (Phase 3): the `Report`-derived series (`exposure.ts`: exposureHeadline, crossDomainBridges, hibpTriage, blastRadius), the network-graph data (crossDomainReuseGraph, similarityNetwork) and their static layout. `neverExpiresCount` is already in `Summary.NeverExpires` and is NOT re-added.

**Golden regen note (applies to every task that wires a series in):** after adding fields to the bundle, run `go test ./internal/metrics/ -run TestMetricsGolden -update`, then open `internal/metrics/testdata/metrics_golden.json` and confirm the new keys are present and sane, then run the test WITHOUT `-update` to confirm it passes. Commit the updated golden with the task.

---

### Task 1: `ChartSeries` scaffold + distribution slices

Add the `ChartSeries` struct with shared output types and the three "pie"/slice series (`riskDistribution`, `hibpSplit`, `expirationSplit`), and wire `ChartSeries` into the org and per-domain bundles.

**Files:**
- Create: `internal/metrics/series.go`
- Modify: `internal/metrics/metrics.go` (add `Charts ChartSeries` field to `Metrics`; populate in `Compute`)
- Modify: `internal/metrics/domain.go` (add `Charts ChartSeries` field to `DomainMetrics`; populate in `ComputeByDomain`)
- Modify: `internal/metrics/testdata/metrics_golden.json` (regenerate)
- Test: `internal/metrics/series_test.go`

**Interfaces:**
- Consumes: `model.Account` (`RiskLevel`, `HIBPBreached`, `PwdNeverExpires *bool`).
- Produces:
  - `type Slice struct { Name string `json:"name"`; Value int `json:"value"`; Color string `json:"color"` }`
  - `type Bar struct { Name string `json:"name"`; Value int `json:"value"` }`
  - `type Point struct { X float64 `json:"x"`; Y float64 `json:"y"` }`
  - `type Series struct { Name string `json:"name"`; Color string `json:"color"`; Points []Point `json:"points"` }`
  - `type ChartSeries struct { RiskDistribution []Slice `json:"risk_distribution"`; HIBPSplit []Slice `json:"hibp_split"`; ExpirationSplit []Slice `json:"expiration_split"` }` (later tasks add fields)
  - `func buildChartSeries(accounts []model.Account, now time.Time) ChartSeries`
  - `func RiskDistribution([]model.Account) []Slice`, `func HIBPSplit([]model.Account) []Slice`, `func ExpirationSplit([]model.Account) []Slice`

**TS source (port verbatim — `web/src/insights.ts`):**
```ts
const RISK_HEX = { Critical: "#fb7185", High: "#fbbf24", Medium: "#a3e635", Low: "#22d3ee" }
riskDistribution: order ["Critical","High","Medium","Low"]; count by risk_level; keep only present; color RISK_HEX[r] || "#818cf8"
hibpSplit: breached count; [{Breached,#fb7185},{Not in HIBP, len-breached,#22d3ee}] filtered value>0
expirationSplit: pwd_never_expires===true -> neverExpires; ===false -> expires; else unknown;
  [{Expires,#34d399},{Never expires,#fb7185},{Unknown,#475569}] filtered value>0
```

- [ ] **Step 1: Write the failing test**

```go
// internal/metrics/series_test.go
package metrics

import (
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

func TestRiskDistributionOrderAndColors(t *testing.T) {
	accts := []model.Account{
		{RiskLevel: "Low"}, {RiskLevel: "Critical"}, {RiskLevel: "Low"}, {RiskLevel: "High"},
	}
	got := RiskDistribution(accts)
	// order Critical, High, Medium(absent->skipped), Low
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	if got[0].Name != "Critical" || got[0].Value != 1 || got[0].Color != "#fb7185" {
		t.Errorf("slot0 = %+v", got[0])
	}
	if got[1].Name != "High" || got[1].Value != 1 {
		t.Errorf("slot1 = %+v", got[1])
	}
	if got[2].Name != "Low" || got[2].Value != 2 || got[2].Color != "#22d3ee" {
		t.Errorf("slot2 = %+v", got[2])
	}
}

func TestHIBPSplitFiltersZero(t *testing.T) {
	accts := []model.Account{{HIBPBreached: true}, {HIBPBreached: true}}
	got := HIBPSplit(accts) // all breached -> "Not in HIBP" slice (value 0) dropped
	if len(got) != 1 || got[0].Name != "Breached" || got[0].Value != 2 {
		t.Fatalf("got = %+v, want single Breached=2", got)
	}
}

func TestExpirationSplitThreeWay(t *testing.T) {
	tr, fa := true, false
	accts := []model.Account{
		{PwdNeverExpires: &tr}, {PwdNeverExpires: &fa}, {PwdNeverExpires: &fa}, {},
	}
	got := ExpirationSplit(accts)
	m := map[string]int{}
	for _, s := range got {
		m[s.Name] = s.Value
	}
	if m["Expires"] != 2 || m["Never expires"] != 1 || m["Unknown"] != 1 {
		t.Fatalf("got = %+v", got)
	}
}

func TestBuildChartSeriesAttachedToBundle(t *testing.T) {
	now := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	m := Compute([]model.Account{{RiskLevel: "Low"}, {RiskLevel: "Critical"}}, now)
	if len(m.Charts.RiskDistribution) != 2 {
		t.Fatalf("org charts not populated: %+v", m.Charts.RiskDistribution)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/metrics/ -run 'TestRiskDistribution|TestHIBPSplit|TestExpirationSplit|TestBuildChartSeries' -v`
Expected: FAIL — symbols undefined.

- [ ] **Step 3: Create `internal/metrics/series.go`**

```go
package metrics

import (
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// Slice is a labeled, colored count for pie/donut charts.
type Slice struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
	Color string `json:"color"`
}

// Bar is a labeled count for bar charts.
type Bar struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

// Point is one (x,y) sample for scatter series.
type Point struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// Series is a named, colored set of scatter points.
type Series struct {
	Name   string  `json:"name"`
	Color  string  `json:"color"`
	Points []Point `json:"points"`
}

// ChartSeries holds the account-derived chart data the dashboards render.
// Ported verbatim from web/src/insights.ts so the SPA and the exporters show
// the same numbers. (Later tasks add more fields.)
type ChartSeries struct {
	RiskDistribution []Slice `json:"risk_distribution"`
	HIBPSplit        []Slice `json:"hibp_split"`
	ExpirationSplit  []Slice `json:"expiration_split"`
}

var riskHex = map[string]string{"Critical": "#fb7185", "High": "#fbbf24", "Medium": "#a3e635", "Low": "#22d3ee"}
var riskOrder = []string{"Critical", "High", "Medium", "Low"}

// RiskDistribution mirrors insights.ts riskDistribution: counts by risk level in
// fixed order, dropping absent levels; default color for unknown levels.
func RiskDistribution(accts []model.Account) []Slice {
	counts := map[string]int{}
	for i := range accts {
		if accts[i].RiskLevel != "" {
			counts[accts[i].RiskLevel]++
		}
	}
	out := []Slice{}
	for _, r := range riskOrder {
		if counts[r] == 0 {
			continue
		}
		c := riskHex[r]
		if c == "" {
			c = "#818cf8"
		}
		out = append(out, Slice{Name: r, Value: counts[r], Color: c})
	}
	return out
}

// HIBPSplit mirrors insights.ts hibpSplit: breached vs not, zero slices dropped.
func HIBPSplit(accts []model.Account) []Slice {
	breached := 0
	for i := range accts {
		if accts[i].HIBPBreached {
			breached++
		}
	}
	cand := []Slice{
		{Name: "Breached", Value: breached, Color: "#fb7185"},
		{Name: "Not in HIBP", Value: len(accts) - breached, Color: "#22d3ee"},
	}
	return dropZeroSlices(cand)
}

// ExpirationSplit mirrors insights.ts expirationSplit: expires / never / unknown,
// zero slices dropped.
func ExpirationSplit(accts []model.Account) []Slice {
	var expires, never, unknown int
	for i := range accts {
		switch {
		case accts[i].PwdNeverExpires != nil && *accts[i].PwdNeverExpires:
			never++
		case accts[i].PwdNeverExpires != nil && !*accts[i].PwdNeverExpires:
			expires++
		default:
			unknown++
		}
	}
	cand := []Slice{
		{Name: "Expires", Value: expires, Color: "#34d399"},
		{Name: "Never expires", Value: never, Color: "#fb7185"},
		{Name: "Unknown", Value: unknown, Color: "#475569"},
	}
	return dropZeroSlices(cand)
}

func dropZeroSlices(in []Slice) []Slice {
	out := []Slice{}
	for _, s := range in {
		if s.Value > 0 {
			out = append(out, s)
		}
	}
	return out
}

// buildChartSeries assembles the account-derived chart series. now is threaded for
// age-based series added in later tasks.
func buildChartSeries(accounts []model.Account, now time.Time) ChartSeries {
	_ = now // used by later tasks (age buckets/scatter)
	return ChartSeries{
		RiskDistribution: RiskDistribution(accounts),
		HIBPSplit:        HIBPSplit(accounts),
		ExpirationSplit:  ExpirationSplit(accounts),
	}
}
```

- [ ] **Step 4: Wire into `metrics.go` and `domain.go`**

In `internal/metrics/metrics.go`, add to the `Metrics` struct (after `Matrix`):
```go
	Charts ChartSeries `json:"charts"`
```
and in `Compute`, add to the returned struct literal:
```go
		Charts: buildChartSeries(accounts, now),
```

In `internal/metrics/domain.go`, add to the `DomainMetrics` struct (after `Matrix`):
```go
	Charts ChartSeries `json:"charts"`
```
and in `ComputeByDomain`, add to the appended `DomainMetrics` literal:
```go
			Charts: buildChartSeries(sub, now),
```

- [ ] **Step 5: Run the unit tests**

Run: `go test ./internal/metrics/ -run 'TestRiskDistribution|TestHIBPSplit|TestExpirationSplit|TestBuildChartSeries' -v`
Expected: PASS.

- [ ] **Step 6: Regenerate + verify golden, run guard**

Run: `go test ./internal/metrics/ -run TestMetricsGolden -update`
Open `internal/metrics/testdata/metrics_golden.json`: confirm a `"charts"` object now exists at org level and inside each `domains[]` entry, with `risk_distribution`, `hibp_split`, `expiration_split`. Spot-check org `risk_distribution` against the fixture (alice Critical, dave+carol High, bob Medium, erin Low → Critical 1, High 2, Medium 1, Low 1).
Run: `go test ./internal/metrics/ -v`
Expected: PASS including `TestMetricsGolden` and `TestBundleHasNoSensitiveFields`.

- [ ] **Step 7: Full gate + commit**

Run: `gofmt -l internal/metrics` (empty), `go vet ./...`, `go test ./...`
```bash
git add internal/metrics/series.go internal/metrics/series_test.go internal/metrics/metrics.go internal/metrics/domain.go internal/metrics/testdata/metrics_golden.json
git commit -m "$(printf 'feat(metrics): chart-series scaffold + distribution slices\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 2: integer-bucket bar series

Add the bucket bars that count accounts into fixed ranges: `lengthBuckets`, `scoreBuckets`, `sharingDistribution`, `controlledObjectsBuckets`, `similarityBuckets`.

**Files:**
- Modify: `internal/metrics/series.go` (add 5 funcs; add 5 fields to `ChartSeries`; call them in `buildChartSeries`)
- Modify: `internal/metrics/testdata/metrics_golden.json` (regenerate)
- Test: `internal/metrics/series_test.go` (add tests)

**Interfaces:**
- Consumes: `model.Account` (`Cracked`, `PasswordLength`, `RiskScore`, `SharedWith`, `Controlled`, `SimilarityScore`).
- Produces (new `ChartSeries` fields + funcs):
  - `LengthBuckets []Bar `json:"length_buckets"`` / `func LengthBuckets([]model.Account) []Bar`
  - `ScoreBuckets []Bar `json:"score_buckets"`` / `func ScoreBuckets([]model.Account) []Bar`
  - `SharingDistribution []Bar `json:"sharing_distribution"`` / `func SharingDistribution([]model.Account) []Bar`
  - `ControlledObjectsBuckets []Bar `json:"controlled_objects_buckets"`` / `func ControlledObjectsBuckets([]model.Account) []Bar`
  - `SimilarityBuckets []Bar `json:"similarity_buckets"`` / `func SimilarityBuckets([]model.Account) []Bar`

**TS source (port verbatim — `web/src/insights.ts`):**
```ts
lengthBuckets: cracked only; labels ["1–7","8–9","10–11","12–13","14–15","16+"];
  n<=7->0, <=9->1, <=11->2, <=13->3, <=15->4, else 5. NOT filtered (all 6 bars returned).
scoreBuckets: all accounts; labels ["0–2","2–4","4–6","6–8","8–10"];
  s>=8->4, >=6->3, >=4->2, >=2->1, else 0. NOT filtered.
sharingDistribution: all; labels ["0","1","2","3–5","6+"];
  n<=0->0, ==1->1, ==2->2, <=5->3, else 4. NOT filtered.
controlledObjectsBuckets: all; labels ["0","1–10","11–50","51–100","101–500","500+"];
  n<=0->0, <=10->1, <=50->2, <=100->3, <=500->4, else 5. FILTERED value>0.
similarityBuckets: all with s=similarity_score (??0); skip s<=0;
  labels ["< 0.5","0.5–0.7","0.7–0.8","0.8–0.9","0.9+"];
  s<0.5->0, <0.7->1, <0.8->2, <0.9->3, else 4. FILTERED value>0.
```

- [ ] **Step 1: Write the failing tests**

```go
// add to internal/metrics/series_test.go
func TestLengthBucketsCrackedOnlyAllSix(t *testing.T) {
	accts := []model.Account{
		{Cracked: true, PasswordLength: 7}, {Cracked: true, PasswordLength: 16},
		{Cracked: false, PasswordLength: 3}, // uncracked excluded
	}
	got := LengthBuckets(accts)
	if len(got) != 6 {
		t.Fatalf("want 6 bars, got %d", len(got))
	}
	if got[0].Name != "1–7" || got[0].Value != 1 {
		t.Errorf("bucket0 = %+v", got[0])
	}
	if got[5].Name != "16+" || got[5].Value != 1 {
		t.Errorf("bucket5 = %+v", got[5])
	}
}

func TestScoreBucketsBoundaries(t *testing.T) {
	accts := []model.Account{{RiskScore: 8}, {RiskScore: 6}, {RiskScore: 4}, {RiskScore: 2}, {RiskScore: 0}}
	got := ScoreBuckets(accts)
	want := []int{1, 1, 1, 1, 1} // 0–2,2–4,4–6,6–8,8–10
	for i, b := range got {
		if b.Value != want[i] {
			t.Errorf("bucket %d (%s) = %d, want %d", i, b.Name, b.Value, want[i])
		}
	}
}

func TestControlledObjectsBucketsFiltersZero(t *testing.T) {
	accts := []model.Account{{Controlled: 0}, {Controlled: 600}}
	got := ControlledObjectsBuckets(accts)
	// "0" bucket has 1 but is value>0 so KEPT; "500+" has 1; the empty middle buckets dropped
	names := map[string]int{}
	for _, b := range got {
		names[b.Name] = b.Value
	}
	if names["0"] != 1 || names["500+"] != 1 {
		t.Fatalf("got = %+v", got)
	}
	if _, ok := names["11–50"]; ok {
		t.Errorf("empty bucket 11–50 should be filtered out")
	}
}

func TestSimilarityBucketsSkipsZeroScores(t *testing.T) {
	accts := []model.Account{{SimilarityScore: 0}, {SimilarityScore: 0.95}, {SimilarityScore: 0.75}}
	got := SimilarityBuckets(accts)
	names := map[string]int{}
	for _, b := range got {
		names[b.Name] = b.Value
	}
	if names["0.9+"] != 1 || names["0.7–0.8"] != 1 {
		t.Fatalf("got = %+v", got)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/metrics/ -run 'TestLengthBuckets|TestScoreBuckets|TestControlledObjectsBuckets|TestSimilarityBuckets' -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement in `series.go`**

Add these funcs:

```go
func LengthBuckets(accts []model.Account) []Bar {
	labels := []string{"1–7", "8–9", "10–11", "12–13", "14–15", "16+"}
	c := make([]int, 6)
	for i := range accts {
		if !accts[i].Cracked {
			continue
		}
		switch n := accts[i].PasswordLength; {
		case n <= 7:
			c[0]++
		case n <= 9:
			c[1]++
		case n <= 11:
			c[2]++
		case n <= 13:
			c[3]++
		case n <= 15:
			c[4]++
		default:
			c[5]++
		}
	}
	return labeledBars(labels, c, false)
}

func ScoreBuckets(accts []model.Account) []Bar {
	labels := []string{"0–2", "2–4", "4–6", "6–8", "8–10"}
	c := make([]int, 5)
	for i := range accts {
		s := accts[i].RiskScore
		switch {
		case s >= 8:
			c[4]++
		case s >= 6:
			c[3]++
		case s >= 4:
			c[2]++
		case s >= 2:
			c[1]++
		default:
			c[0]++
		}
	}
	return labeledBars(labels, c, false)
}

func SharingDistribution(accts []model.Account) []Bar {
	labels := []string{"0", "1", "2", "3–5", "6+"}
	c := make([]int, 5)
	for i := range accts {
		switch n := accts[i].SharedWith; {
		case n <= 0:
			c[0]++
		case n == 1:
			c[1]++
		case n == 2:
			c[2]++
		case n <= 5:
			c[3]++
		default:
			c[4]++
		}
	}
	return labeledBars(labels, c, false)
}

func ControlledObjectsBuckets(accts []model.Account) []Bar {
	labels := []string{"0", "1–10", "11–50", "51–100", "101–500", "500+"}
	c := make([]int, 6)
	for i := range accts {
		switch n := accts[i].Controlled; {
		case n <= 0:
			c[0]++
		case n <= 10:
			c[1]++
		case n <= 50:
			c[2]++
		case n <= 100:
			c[3]++
		case n <= 500:
			c[4]++
		default:
			c[5]++
		}
	}
	return labeledBars(labels, c, true)
}

func SimilarityBuckets(accts []model.Account) []Bar {
	labels := []string{"< 0.5", "0.5–0.7", "0.7–0.8", "0.8–0.9", "0.9+"}
	c := make([]int, 5)
	for i := range accts {
		s := accts[i].SimilarityScore
		if s <= 0 {
			continue
		}
		switch {
		case s < 0.5:
			c[0]++
		case s < 0.7:
			c[1]++
		case s < 0.8:
			c[2]++
		case s < 0.9:
			c[3]++
		default:
			c[4]++
		}
	}
	return labeledBars(labels, c, true)
}

// labeledBars zips labels+counts into Bars; when filterZero is true, drops bars
// whose value is 0 (mirrors the .filter(b=>b.value>0) on the relevant TS series).
func labeledBars(labels []string, counts []int, filterZero bool) []Bar {
	out := make([]Bar, 0, len(labels))
	for i, name := range labels {
		if filterZero && counts[i] == 0 {
			continue
		}
		out = append(out, Bar{Name: name, Value: counts[i]})
	}
	return out
}
```

Add the 5 fields to `ChartSeries`:
```go
	LengthBuckets            []Bar `json:"length_buckets"`
	ScoreBuckets             []Bar `json:"score_buckets"`
	SharingDistribution      []Bar `json:"sharing_distribution"`
	ControlledObjectsBuckets []Bar `json:"controlled_objects_buckets"`
	SimilarityBuckets        []Bar `json:"similarity_buckets"`
```

Add to `buildChartSeries` return literal:
```go
		LengthBuckets:            LengthBuckets(accounts),
		ScoreBuckets:             ScoreBuckets(accounts),
		SharingDistribution:      SharingDistribution(accounts),
		ControlledObjectsBuckets: ControlledObjectsBuckets(accounts),
		SimilarityBuckets:        SimilarityBuckets(accounts),
```

- [ ] **Step 4: Run unit tests**

Run: `go test ./internal/metrics/ -run 'TestLengthBuckets|TestScoreBuckets|TestControlledObjectsBuckets|TestSimilarityBuckets|TestSharing' -v`
Expected: PASS.

- [ ] **Step 5: Regenerate + verify golden**

Run: `go test ./internal/metrics/ -run TestMetricsGolden -update`; confirm the new bucket arrays appear under `charts`; then `go test ./internal/metrics/ -v` → PASS.

- [ ] **Step 6: Full gate + commit**

Run: `gofmt -l internal/metrics` (empty), `go vet ./...`, `go test ./...`
```bash
git add internal/metrics/series.go internal/metrics/series_test.go internal/metrics/testdata/metrics_golden.json
git commit -m "$(printf 'feat(metrics): integer-bucket bar series (length/score/sharing/controlled/similarity)\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 3: keyed bar series (DA-by-domain, complexity)

Add `daExposureByDomain` and `complexityCounts` (both sorted desc by count), plus the complexity-label map.

**Files:**
- Modify: `internal/metrics/series.go` (2 funcs + label map + 2 `ChartSeries` fields + wire in)
- Modify: `internal/metrics/testdata/metrics_golden.json` (regenerate)
- Test: `internal/metrics/series_test.go`

**Interfaces:**
- Consumes: `model.Account` (`HasDAPathway()`, `Domain`, `Cracked`, `Complexity`).
- Produces:
  - `DAExposureByDomain []Bar `json:"da_exposure_by_domain"`` / `func DAExposureByDomain([]model.Account) []Bar`
  - `ComplexityCounts []Bar `json:"complexity_counts"`` / `func ComplexityCounts([]model.Account) []Bar`
  - `func ComplexityLabel(string) string`

**TS source (port verbatim — `web/src/insights.ts`):**
```ts
daExposureByDomain: count hasDA(da_domains) per domain; entries sorted by value desc.
complexityCounts: cracked && complexity -> count per complexity; map key via COMPLEXITY_LABELS; sorted value desc.
COMPLEXITY_LABELS: loweralpha "a–z", upperalpha "A–Z", numeric "0–9", special "!@#",
  loweralphanum "a–z 0–9", upperalphanum "A–Z 0–9", mixedalpha "a–z A–Z",
  loweralphaspecial "a–z !@#", upperalphaspecial "A–Z !@#", specialnum "0–9 !@#",
  mixedalphanum "a–z A–Z 0–9", loweralphaspecialnum "a–z 0–9 !@#",
  mixedalphaspecial "a–z A–Z !@#", upperalphaspecialnum "A–Z 0–9 !@#",
  mixedalphaspecialnum "a–z A–Z 0–9 !@#", none "(none)". Unknown key -> key itself.
```
**Determinism note:** the TS relies on `Object.entries` insertion order before sorting; Go map iteration is random, so after building the count map, collect entries and sort by **value desc, then name asc** (name tie-break makes it deterministic — document this as the Go-side stabilization of the JS insertion-order tie).

- [ ] **Step 1: Write the failing tests**

```go
// add to internal/metrics/series_test.go
func TestDAExposureByDomainSortedDesc(t *testing.T) {
	da := "CORP.LOCAL"
	none := "None"
	accts := []model.Account{
		{Domain: "A", DADomains: da}, {Domain: "B", DADomains: da}, {Domain: "B", DADomains: da},
		{Domain: "C", DADomains: none},
	}
	got := DAExposureByDomain(accts)
	if len(got) != 2 || got[0].Name != "B" || got[0].Value != 2 || got[1].Name != "A" {
		t.Fatalf("got = %+v", got)
	}
}

func TestComplexityCountsLabelsAndSort(t *testing.T) {
	accts := []model.Account{
		{Cracked: true, Complexity: "mixedalphaspecialnum"},
		{Cracked: true, Complexity: "loweralpha"},
		{Cracked: true, Complexity: "loweralpha"},
		{Cracked: false, Complexity: "numeric"}, // excluded
	}
	got := ComplexityCounts(accts)
	if got[0].Name != "a–z" || got[0].Value != 2 {
		t.Fatalf("top = %+v", got)
	}
	if got[1].Name != "a–z A–Z 0–9 !@#" || got[1].Value != 1 {
		t.Errorf("second = %+v", got[1])
	}
}

func TestComplexityLabelUnknownPassThrough(t *testing.T) {
	if ComplexityLabel("weirdkey") != "weirdkey" {
		t.Error("unknown key should pass through")
	}
	if ComplexityLabel("numeric") != "0–9" {
		t.Error("numeric -> 0–9")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/metrics/ -run 'TestDAExposureByDomain|TestComplexity' -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement in `series.go`**

```go
import block: ensure "sort" is imported.

var complexityLabels = map[string]string{
	"loweralpha": "a–z", "upperalpha": "A–Z", "numeric": "0–9", "special": "!@#",
	"loweralphanum": "a–z 0–9", "upperalphanum": "A–Z 0–9", "mixedalpha": "a–z A–Z",
	"loweralphaspecial": "a–z !@#", "upperalphaspecial": "A–Z !@#", "specialnum": "0–9 !@#",
	"mixedalphanum": "a–z A–Z 0–9", "loweralphaspecialnum": "a–z 0–9 !@#",
	"mixedalphaspecial": "a–z A–Z !@#", "upperalphaspecialnum": "A–Z 0–9 !@#",
	"mixedalphaspecialnum": "a–z A–Z 0–9 !@#", "none": "(none)",
}

// ComplexityLabel maps the engine complexity enum to character-class notation;
// unknown keys pass through unchanged (mirrors insights.ts complexityLabel).
func ComplexityLabel(key string) string {
	if v, ok := complexityLabels[key]; ok {
		return v
	}
	return key
}

// DAExposureByDomain counts DA-pathway accounts per domain, sorted by count desc
// then domain name asc (the name tie-break stabilizes Go's random map order; the
// TS relied on JS object insertion order for ties).
func DAExposureByDomain(accts []model.Account) []Bar {
	m := map[string]int{}
	for i := range accts {
		if accts[i].HasDAPathway() {
			m[accts[i].Domain]++
		}
	}
	return sortedBarsFromMap(m)
}

// ComplexityCounts counts cracked accounts per complexity class (labeled), sorted
// by count desc then label asc.
func ComplexityCounts(accts []model.Account) []Bar {
	m := map[string]int{}
	for i := range accts {
		if accts[i].Cracked && accts[i].Complexity != "" {
			m[ComplexityLabel(accts[i].Complexity)]++
		}
	}
	return sortedBarsFromMap(m)
}

func sortedBarsFromMap(m map[string]int) []Bar {
	out := make([]Bar, 0, len(m))
	for name, v := range m {
		out = append(out, Bar{Name: name, Value: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value != out[j].Value {
			return out[i].Value > out[j].Value
		}
		return out[i].Name < out[j].Name
	})
	return out
}
```

Add fields to `ChartSeries`:
```go
	DAExposureByDomain []Bar `json:"da_exposure_by_domain"`
	ComplexityCounts   []Bar `json:"complexity_counts"`
```
Wire in `buildChartSeries`:
```go
		DAExposureByDomain: DAExposureByDomain(accounts),
		ComplexityCounts:   ComplexityCounts(accounts),
```

- [ ] **Step 4: Run unit tests**

Run: `go test ./internal/metrics/ -run 'TestDAExposureByDomain|TestComplexity' -v`
Expected: PASS.

- [ ] **Step 5: Regenerate + verify golden**

Run: `go test ./internal/metrics/ -run TestMetricsGolden -update`; confirm `da_exposure_by_domain` and `complexity_counts` appear; then `go test ./internal/metrics/ -v` → PASS.

- [ ] **Step 6: Full gate + commit**

Run: `gofmt -l internal/metrics` (empty), `go vet ./...`, `go test ./...`
```bash
git add internal/metrics/series.go internal/metrics/series_test.go internal/metrics/testdata/metrics_golden.json
git commit -m "$(printf 'feat(metrics): keyed bar series (DA-by-domain, complexity)\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 4: scatter + age series (now-dependent)

Add `hibpVsRisk` (scatter), `passwordAgeBuckets`, and `passwordAgeScatter`. The two age series use the injected `now`.

**Files:**
- Modify: `internal/metrics/series.go` (3 funcs + 3 fields; wire in `buildChartSeries` using `now`; remove the `_ = now` placeholder)
- Modify: `internal/metrics/testdata/metrics_golden.json` (regenerate)
- Test: `internal/metrics/series_test.go`

**Interfaces:**
- Consumes: `model.Account` (`RiskLevel`, `HIBPBreachCount`, `RiskScore`, `PwdLastSet int64`).
- Produces:
  - `HIBPVsRisk []Series `json:"hibp_vs_risk"`` / `func HIBPVsRisk([]model.Account) []Series`
  - `PasswordAgeBuckets []Bar `json:"password_age_buckets"`` / `func PasswordAgeBuckets([]model.Account, time.Time) []Bar`
  - `PasswordAgeScatter []Series `json:"password_age_scatter"`` / `func PasswordAgeScatter([]model.Account, time.Time) []Series`

**TS source (port verbatim — `web/src/insights.ts`):**
```ts
levels with colors: Critical #fb7185, High #fbbf24, Medium #a3e635, Low #22d3ee (this fixed order).
hibpVsRisk: per level, points {x: log10((hibp_breach_count||0)+1), y: risk_score} for accounts of that level;
  series with 0 points dropped.
passwordAgeBuckets: now=Date.now()/1000; skip pwd_last_set<=0; days=(now-pwd_last_set)/86400;
  labels ["< 30d","30–90d","90–180d","180–365d","1–2y","2y+"];
  <30->0,<90->1,<180->2,<365->3,<730->4,else 5. FILTERED value>0.
passwordAgeScatter: per level, points {x: floor((now-pwd_last_set)/86400), y: risk_score}
  for accounts of that level with pwd_last_set>0; series with 0 points dropped.
```
**now handling:** Go receives `now time.Time`; use `nowUnix := now.Unix()` and `days := (nowUnix - pwdLastSet) / 86400` (integer seconds, matching JS `(now - pwd_last_set)/86400` where now is epoch seconds — for the bucket comparisons use float division to match `days<30` etc.; for the scatter X use `floor` i.e. integer division). To match the TS exactly: buckets use `float64(nowUnix-pls)/86400.0` compared with `< 30` etc.; scatter X uses `float64((nowUnix - pls) / 86400)` (integer division then float).

- [ ] **Step 1: Write the failing tests**

```go
// add to internal/metrics/series_test.go
func TestHIBPVsRiskDropsEmptyLevels(t *testing.T) {
	accts := []model.Account{
		{RiskLevel: "Critical", HIBPBreachCount: 9, RiskScore: 8.5},
		{RiskLevel: "Low", HIBPBreachCount: 0, RiskScore: 1},
	}
	got := HIBPVsRisk(accts)
	if len(got) != 2 {
		t.Fatalf("want Critical+Low series, got %d", len(got))
	}
	if got[0].Name != "Critical" || len(got[0].Points) != 1 {
		t.Fatalf("crit = %+v", got[0])
	}
	// x = log10(9+1) = 1
	if got[0].Points[0].X < 0.999 || got[0].Points[0].X > 1.001 {
		t.Errorf("x = %v, want ~1", got[0].Points[0].X)
	}
}

func TestPasswordAgeBucketsUsesNow(t *testing.T) {
	now := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	day := int64(86400)
	accts := []model.Account{
		{PwdLastSet: now.Unix() - 10*day}, // < 30d
		{PwdLastSet: now.Unix() - 800*day}, // 2y+
		{PwdLastSet: 0},                    // skipped
	}
	got := PasswordAgeBuckets(accts, now)
	names := map[string]int{}
	for _, b := range got {
		names[b.Name] = b.Value
	}
	if names["< 30d"] != 1 || names["2y+"] != 1 {
		t.Fatalf("got = %+v", got)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/metrics/ -run 'TestHIBPVsRisk|TestPasswordAge' -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement in `series.go`**

```go
import block: ensure "math" is imported.

var levelColors = []struct{ name, color string }{
	{"Critical", "#fb7185"}, {"High", "#fbbf24"}, {"Medium", "#a3e635"}, {"Low", "#22d3ee"},
}

// HIBPVsRisk: per-level scatter of log10(hibp_breach_count+1) vs risk_score.
func HIBPVsRisk(accts []model.Account) []Series {
	out := []Series{}
	for _, lc := range levelColors {
		pts := []Point{}
		for i := range accts {
			if accts[i].RiskLevel != lc.name {
				continue
			}
			pts = append(pts, Point{X: math.Log10(float64(accts[i].HIBPBreachCount) + 1), Y: accts[i].RiskScore})
		}
		if len(pts) > 0 {
			out = append(out, Series{Name: lc.name, Color: lc.color, Points: pts})
		}
	}
	return out
}

// PasswordAgeBuckets: days since pwd_last_set bucketed; skips unset; filters empties.
func PasswordAgeBuckets(accts []model.Account, now time.Time) []Bar {
	labels := []string{"< 30d", "30–90d", "90–180d", "180–365d", "1–2y", "2y+"}
	c := make([]int, 6)
	nowUnix := now.Unix()
	for i := range accts {
		pls := accts[i].PwdLastSet
		if pls <= 0 {
			continue
		}
		days := float64(nowUnix-pls) / 86400.0
		switch {
		case days < 30:
			c[0]++
		case days < 90:
			c[1]++
		case days < 180:
			c[2]++
		case days < 365:
			c[3]++
		case days < 730:
			c[4]++
		default:
			c[5]++
		}
	}
	return labeledBars(labels, c, true)
}

// PasswordAgeScatter: per-level scatter of integer days-ago vs risk_score.
func PasswordAgeScatter(accts []model.Account, now time.Time) []Series {
	nowUnix := now.Unix()
	out := []Series{}
	for _, lc := range levelColors {
		pts := []Point{}
		for i := range accts {
			if accts[i].RiskLevel != lc.name || accts[i].PwdLastSet <= 0 {
				continue
			}
			pts = append(pts, Point{X: float64((nowUnix - accts[i].PwdLastSet) / 86400), Y: accts[i].RiskScore})
		}
		if len(pts) > 0 {
			out = append(out, Series{Name: lc.name, Color: lc.color, Points: pts})
		}
	}
	return out
}
```

Add fields to `ChartSeries`:
```go
	HIBPVsRisk         []Series `json:"hibp_vs_risk"`
	PasswordAgeBuckets []Bar    `json:"password_age_buckets"`
	PasswordAgeScatter []Series `json:"password_age_scatter"`
```
In `buildChartSeries`, remove the `_ = now` line and add:
```go
		HIBPVsRisk:         HIBPVsRisk(accounts),
		PasswordAgeBuckets: PasswordAgeBuckets(accounts, now),
		PasswordAgeScatter: PasswordAgeScatter(accounts, now),
```

- [ ] **Step 4: Run unit tests**

Run: `go test ./internal/metrics/ -run 'TestHIBPVsRisk|TestPasswordAge' -v`
Expected: PASS.

- [ ] **Step 5: Regenerate + verify golden**

Run: `go test ./internal/metrics/ -run TestMetricsGolden -update`; confirm `hibp_vs_risk`, `password_age_buckets`, `password_age_scatter` appear (note: the fixture has no `pwd_last_set`, so age series will be empty arrays — that is correct and expected). Then `go test ./internal/metrics/ -v` → PASS.

- [ ] **Step 6: Full gate + commit**

Run: `gofmt -l internal/metrics` (empty), `go vet ./...`, `go test ./...`
```bash
git add internal/metrics/series.go internal/metrics/series_test.go internal/metrics/testdata/metrics_golden.json
git commit -m "$(printf 'feat(metrics): scatter + password-age series (now-injected)\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 5: axis-factor bars (per-tier averaged breakdown)

Add `axisFactorBars` — per risk-tier averaged `ScoreBreakdown` sub-scores, split into Exposure and Impact factor groups, with the Impact group flagged when no account in the tier is enriched.

**Files:**
- Modify: `internal/metrics/series.go` (1 func + types + field + wire in)
- Modify: `internal/metrics/testdata/metrics_golden.json` (regenerate)
- Test: `internal/metrics/series_test.go`

**Interfaces:**
- Consumes: `model.Account` (`RiskLevel`, `ScoreBreakdown *model.ScoreBreakdown`, `ImpactKnown`, `ImpactScore`).
- Produces:
  - `type AxisFactor struct { Name string `json:"name"`; Value float64 `json:"value"`; Color string `json:"color"` }`
  - `type TierFactorBars struct { Tier string `json:"tier"`; Color string `json:"color"`; Exposure []AxisFactor `json:"exposure"`; Impact []AxisFactor `json:"impact"`; ImpactKnown bool `json:"impact_known"` }`
  - `AxisFactorBars []TierFactorBars `json:"axis_factor_bars"`` / `func AxisFactorBars([]model.Account) []TierFactorBars`

**TS source (port verbatim — `web/src/insights.ts`):**
```ts
tiers (this order, with colors): Critical #fb7185, High #fbbf24, Medium #a3e635, Low #22d3ee.
For each tier: group = accounts where risk_level==tier && score_breakdown present. Skip tier if group empty.
enriched = group where impactIsKnown(a) (impact_known && impact_score != null).
avg(rows,k) = rows.length ? round( sum(breakdown[k]||0)/rows.length * 100)/100 : 0   (2-decimal round)
EXP_FACTORS (name,key,color): Weakness/weakness_score/#fbbf24, "HIBP floor"/hibp_floor/#fb7185,
  "Cracked floor"/cracked_floor/#f472b6, Reuse/reuse_bump/#a78bfa, Roastable/roastable_bump/#38bdf8, Age/age_penalty/#2dd4bf
IMP_FACTORS: Privilege/privilege_sub_score/#22d3ee, "DA path"/da_component/#fb7185, Domain/domain_modifier/#a3e635
exposure = EXP_FACTORS mapped to {name, avg(group,key), color}; impact = IMP_FACTORS mapped to {name, avg(enriched,key), color}
impactKnown = enriched.length > 0
```
**Note on breakdown keys:** `model.ScoreBreakdown` fields used: `WeaknessScore, HIBPFloor, CrackedFloor, ReuseBump, RoastableBump, AgePenalty, PrivilegeSubScore, DAComponent, DomainModifier`. Confirm exact Go field names against `internal/model/model.go` `ScoreBreakdown` (the JSON tags are `weakness_score, hibp_floor, cracked_floor, reuse_bump, roastable_bump, age_penalty, privilege_sub_score, da_component, domain_modifier`). A missing/zero breakdown contributes 0.

- [ ] **Step 1: Write the failing test**

```go
// add to internal/metrics/series_test.go
func TestAxisFactorBarsAveragesAndImpactFlag(t *testing.T) {
	sb := func(weak, priv float64) *model.ScoreBreakdown {
		return &model.ScoreBreakdown{WeaknessScore: weak, PrivilegeSubScore: priv}
	}
	accts := []model.Account{
		{RiskLevel: "Critical", ScoreBreakdown: sb(8, 10), ImpactKnown: true, ImpactScore: fp(9)},
		{RiskLevel: "Critical", ScoreBreakdown: sb(6, 0), ImpactKnown: false}, // not enriched
	}
	got := AxisFactorBars(accts)
	if len(got) != 1 || got[0].Tier != "Critical" {
		t.Fatalf("got = %+v", got)
	}
	// Weakness avg over the whole group (8+6)/2 = 7
	var weak float64
	for _, f := range got[0].Exposure {
		if f.Name == "Weakness" {
			weak = f.Value
		}
	}
	if weak != 7 {
		t.Errorf("weakness avg = %v, want 7", weak)
	}
	// Privilege avg over ENRICHED only = 10/1 = 10
	var priv float64
	for _, f := range got[0].Impact {
		if f.Name == "Privilege" {
			priv = f.Value
		}
	}
	if priv != 10 {
		t.Errorf("privilege avg (enriched) = %v, want 10", priv)
	}
	if !got[0].ImpactKnown {
		t.Error("impact_known should be true (one enriched account in tier)")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/metrics/ -run TestAxisFactorBars -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement in `series.go`**

```go
type AxisFactor struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
	Color string  `json:"color"`
}

type TierFactorBars struct {
	Tier        string       `json:"tier"`
	Color       string       `json:"color"`
	Exposure    []AxisFactor `json:"exposure"`
	Impact      []AxisFactor `json:"impact"`
	ImpactKnown bool         `json:"impact_known"`
}

// bdv coalesces a possibly-zero breakdown field to 0 via an accessor.
func bdAvg(rows []model.Account, get func(*model.ScoreBreakdown) float64) float64 {
	if len(rows) == 0 {
		return 0
	}
	var sum float64
	for i := range rows {
		if rows[i].ScoreBreakdown != nil {
			sum += get(rows[i].ScoreBreakdown)
		}
	}
	return math.Round(sum/float64(len(rows))*100) / 100
}

type factorDef struct {
	name  string
	color string
	get   func(*model.ScoreBreakdown) float64
}

var expFactors = []factorDef{
	{"Weakness", "#fbbf24", func(b *model.ScoreBreakdown) float64 { return b.WeaknessScore }},
	{"HIBP floor", "#fb7185", func(b *model.ScoreBreakdown) float64 { return b.HIBPFloor }},
	{"Cracked floor", "#f472b6", func(b *model.ScoreBreakdown) float64 { return b.CrackedFloor }},
	{"Reuse", "#a78bfa", func(b *model.ScoreBreakdown) float64 { return b.ReuseBump }},
	{"Roastable", "#38bdf8", func(b *model.ScoreBreakdown) float64 { return b.RoastableBump }},
	{"Age", "#2dd4bf", func(b *model.ScoreBreakdown) float64 { return b.AgePenalty }},
}
var impFactors = []factorDef{
	{"Privilege", "#22d3ee", func(b *model.ScoreBreakdown) float64 { return b.PrivilegeSubScore }},
	{"DA path", "#fb7185", func(b *model.ScoreBreakdown) float64 { return b.DAComponent }},
	{"Domain", "#a3e635", func(b *model.ScoreBreakdown) float64 { return b.DomainModifier }},
}

// AxisFactorBars: per-tier averaged breakdown sub-scores. Impact group averages
// over enriched accounts only; impact_known=false when none in the tier is enriched.
func AxisFactorBars(accts []model.Account) []TierFactorBars {
	out := []TierFactorBars{}
	for _, lc := range levelColors {
		var group, enriched []model.Account
		for i := range accts {
			if accts[i].RiskLevel == lc.name && accts[i].ScoreBreakdown != nil {
				group = append(group, accts[i])
				if accts[i].ImpactKnown && accts[i].ImpactScore != nil {
					enriched = append(enriched, accts[i])
				}
			}
		}
		if len(group) == 0 {
			continue
		}
		exp := make([]AxisFactor, len(expFactors))
		for i, f := range expFactors {
			exp[i] = AxisFactor{Name: f.name, Value: bdAvg(group, f.get), Color: f.color}
		}
		imp := make([]AxisFactor, len(impFactors))
		for i, f := range impFactors {
			imp[i] = AxisFactor{Name: f.name, Value: bdAvg(enriched, f.get), Color: f.color}
		}
		out = append(out, TierFactorBars{Tier: lc.name, Color: lc.color, Exposure: exp, Impact: imp, ImpactKnown: len(enriched) > 0})
	}
	return out
}
```

Add field to `ChartSeries`:
```go
	AxisFactorBars []TierFactorBars `json:"axis_factor_bars"`
```
Wire in `buildChartSeries`:
```go
		AxisFactorBars: AxisFactorBars(accounts),
```

- [ ] **Step 4: Run unit test**

Run: `go test ./internal/metrics/ -run TestAxisFactorBars -v`
Expected: PASS. If a `ScoreBreakdown` field name is wrong, the compile error names it — fix to match `internal/model/model.go` and re-run.

- [ ] **Step 5: Regenerate + verify golden**

Run: `go test ./internal/metrics/ -run TestMetricsGolden -update`; confirm `axis_factor_bars` present (the fixture accounts have no `score_breakdown`, so this will be an empty array — expected). Then `go test ./internal/metrics/ -v` → PASS.

- [ ] **Step 6: Full gate + commit**

Run: `gofmt -l internal/metrics` (empty), `go vet ./...`, `go test ./...`
```bash
git add internal/metrics/series.go internal/metrics/series_test.go internal/metrics/testdata/metrics_golden.json
git commit -m "$(printf 'feat(metrics): per-tier axis-factor bars\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 6: top-N / escalation account lists

Add the slim ranked account lists the dashboards show: `topRiskiest`, `escalatedBySharedDA`, `topControlled`, and `topControllers` (with its "more over 100" footer count). These return a redaction-safe slim ref, not the full account.

**Files:**
- Modify: `internal/metrics/series.go` (slim type + 4 funcs + fields; wire in with fixed N)
- Modify: `internal/metrics/testdata/metrics_golden.json` (regenerate)
- Test: `internal/metrics/series_test.go`

**Interfaces:**
- Consumes: `model.Account` (`Username`, `Domain`, `RiskLevel`, `RiskScore`, `HIBPBreachCount`, `HasDAPathway()`, `Controlled`, `EscalatedBySharedDA`).
- Produces:
  - `type AccountRef struct { Username string `json:"username"`; Domain string `json:"domain"`; RiskLevel string `json:"risk_level"`; RiskScore float64 `json:"risk_score"`; HIBPBreachCount int `json:"hibp_breach_count"`; HasDA bool `json:"has_da"`; Controlled int `json:"controlled_object_count"` }`
  - `TopRiskiest []AccountRef `json:"top_riskiest"`` / `func TopRiskiest([]model.Account, int) []AccountRef`
  - `EscalatedBySharedDA []AccountRef `json:"escalated_by_shared_da"`` / `func EscalatedBySharedDA([]model.Account) []AccountRef`
  - `TopControllers []AccountRef `json:"top_controllers"`` and `TopControllersMoreOver100 int `json:"top_controllers_more_over_100"`` / `func TopControllers([]model.Account, int) ([]AccountRef, int)`

**TS source (port verbatim — `web/src/insights.ts`):**
```ts
topRiskiest(accts,n): copy, sort risk_score desc, slice n.
escalatedBySharedDA(accts): filter escalated_by_shared_da, sort risk_score desc.
topControllers(accts,n): controllers = filter controlled_object_count>0,
  sort by controlled desc then username asc; rows = slice n;
  moreOver100 = controllers after n with controlled>100, counted.
```
(We fold the dashboard's `topControlled` into `TopControllers` since both rank by controlled-objects; the slim ref carries the controlled count, satisfying both surfaces. Use N=10 when wiring, matching the dashboard's "Top 10".)

- [ ] **Step 1: Write the failing tests**

```go
// add to internal/metrics/series_test.go
func TestTopRiskiestSortedSliced(t *testing.T) {
	accts := []model.Account{
		{Username: "a", RiskScore: 3}, {Username: "b", RiskScore: 9}, {Username: "c", RiskScore: 6},
	}
	got := TopRiskiest(accts, 2)
	if len(got) != 2 || got[0].Username != "b" || got[1].Username != "c" {
		t.Fatalf("got = %+v", got)
	}
}

func TestTopControllersSortAndMoreOver100(t *testing.T) {
	accts := []model.Account{
		{Username: "z", Controlled: 200}, {Username: "y", Controlled: 500},
		{Username: "x", Controlled: 150}, {Username: "w", Controlled: 0},
	}
	rows, more := TopControllers(accts, 2)
	if len(rows) != 2 || rows[0].Username != "y" || rows[1].Username != "z" {
		t.Fatalf("rows = %+v", rows)
	}
	// remaining controllers beyond top-2 with >100: x(150) -> 1
	if more != 1 {
		t.Errorf("more = %d, want 1", more)
	}
}

func TestEscalatedBySharedDAFilteredSorted(t *testing.T) {
	accts := []model.Account{
		{Username: "a", EscalatedBySharedDA: true, RiskScore: 5},
		{Username: "b", EscalatedBySharedDA: false, RiskScore: 9},
		{Username: "c", EscalatedBySharedDA: true, RiskScore: 8},
	}
	got := EscalatedBySharedDA(accts)
	if len(got) != 2 || got[0].Username != "c" || got[1].Username != "a" {
		t.Fatalf("got = %+v", got)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/metrics/ -run 'TestTopRiskiest|TestTopControllers|TestEscalatedBySharedDA' -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement in `series.go`**

```go
type AccountRef struct {
	Username        string  `json:"username"`
	Domain          string  `json:"domain"`
	RiskLevel       string  `json:"risk_level"`
	RiskScore       float64 `json:"risk_score"`
	HIBPBreachCount int     `json:"hibp_breach_count"`
	HasDA           bool    `json:"has_da"`
	Controlled      int     `json:"controlled_object_count"`
}

func toRef(a model.Account) AccountRef {
	return AccountRef{
		Username: a.Username, Domain: a.Domain, RiskLevel: a.RiskLevel, RiskScore: a.RiskScore,
		HIBPBreachCount: a.HIBPBreachCount, HasDA: a.HasDAPathway(), Controlled: a.Controlled,
	}
}

// TopRiskiest: top-n accounts by risk score desc.
func TopRiskiest(accts []model.Account, n int) []AccountRef {
	cp := append([]model.Account(nil), accts...)
	sort.SliceStable(cp, func(i, j int) bool { return cp[i].RiskScore > cp[j].RiskScore })
	if n < len(cp) {
		cp = cp[:n]
	}
	out := make([]AccountRef, len(cp))
	for i := range cp {
		out[i] = toRef(cp[i])
	}
	return out
}

// EscalatedBySharedDA: shared-DA-escalated accounts, risk score desc.
func EscalatedBySharedDA(accts []model.Account) []AccountRef {
	var f []model.Account
	for i := range accts {
		if accts[i].EscalatedBySharedDA {
			f = append(f, accts[i])
		}
	}
	sort.SliceStable(f, func(i, j int) bool { return f[i].RiskScore > f[j].RiskScore })
	out := make([]AccountRef, len(f))
	for i := range f {
		out[i] = toRef(f[i])
	}
	return out
}

// TopControllers: controllers (controlled>0) by count desc then username asc;
// returns the top n plus the count of remaining controllers still over 100.
func TopControllers(accts []model.Account, n int) ([]AccountRef, int) {
	var ctrl []model.Account
	for i := range accts {
		if accts[i].Controlled > 0 {
			ctrl = append(ctrl, accts[i])
		}
	}
	sort.SliceStable(ctrl, func(i, j int) bool {
		if ctrl[i].Controlled != ctrl[j].Controlled {
			return ctrl[i].Controlled > ctrl[j].Controlled
		}
		return ctrl[i].Username < ctrl[j].Username
	})
	top := ctrl
	if n < len(ctrl) {
		top = ctrl[:n]
	}
	rows := make([]AccountRef, len(top))
	for i := range top {
		rows[i] = toRef(top[i])
	}
	more := 0
	if n < len(ctrl) {
		for _, a := range ctrl[n:] {
			if a.Controlled > 100 {
				more++
			}
		}
	}
	return rows, more
}
```

Add fields to `ChartSeries`:
```go
	TopRiskiest               []AccountRef `json:"top_riskiest"`
	EscalatedBySharedDA       []AccountRef `json:"escalated_by_shared_da"`
	TopControllers            []AccountRef `json:"top_controllers"`
	TopControllersMoreOver100 int          `json:"top_controllers_more_over_100"`
```
Wire in `buildChartSeries` (use N=10):
```go
	cs.TopRiskiest = TopRiskiest(accounts, 10)
	cs.EscalatedBySharedDA = EscalatedBySharedDA(accounts)
	cs.TopControllers, cs.TopControllersMoreOver100 = TopControllers(accounts, 10)
```
(Adjust `buildChartSeries` to assign into a named `cs ChartSeries` variable if it currently returns a single composite literal — restructure so the multi-return `TopControllers` can be assigned, then `return cs`.)

- [ ] **Step 4: Run unit tests**

Run: `go test ./internal/metrics/ -run 'TestTopRiskiest|TestTopControllers|TestEscalatedBySharedDA' -v`
Expected: PASS.

- [ ] **Step 5: Regenerate + verify golden + redaction guard**

Run: `go test ./internal/metrics/ -run TestMetricsGolden -update`; confirm `top_riskiest`, `top_controllers`, `escalated_by_shared_da` appear with the fixture usernames (alice, bob, …) and `top_controllers_more_over_100` is present. CRITICAL: run `go test ./internal/metrics/ -run TestBundleHasNoSensitiveFields -v` — the slim `AccountRef` carries usernames/domains (already in standard exports) but NO password/nt_hash; the guard must still pass. Then `go test ./internal/metrics/ -v` → PASS.

- [ ] **Step 6: Full gate + commit**

Run: `gofmt -l internal/metrics` (empty), `go vet ./...`, `go test ./...`
```bash
git add internal/metrics/series.go internal/metrics/series_test.go internal/metrics/testdata/metrics_golden.json
git commit -m "$(printf 'feat(metrics): top-N and shared-DA account lists (slim refs)\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

## Self-Review

**Spec coverage (Phase 2 slice):** Ports every `[]Account`-pure series from `web/src/insights.ts` into the bundle (org + per-domain), attached under `Charts`: distributions (Task 1), integer buckets (Task 2), keyed bars (Task 3), scatter + age (Task 4), axis-factor bars (Task 5), top-N/escalation lists (Task 6). `neverExpiresCount` intentionally omitted (already `Summary.NeverExpires`). The `Report`-derived series, network graphs, and static layout are explicitly deferred to the next plan, and noted in the Scope note.

**Placeholder scan:** No TBD/TODO. Every code step shows complete Go. The one deliberate "remove this line" instruction (the `_ = now` placeholder in Task 1, removed in Task 4) is explicit and tied to the task that consumes `now`. Task 1 Step 4 flags a typo guard explicitly so the implementer uses the correct field line.

**Type consistency:** `Slice`/`Bar`/`Point`/`Series` defined in Task 1, reused in Tasks 2-6. `ChartSeries` grows additively each task (no renames). `buildChartSeries(accounts, now)` defined in Task 1; Task 4 starts using `now`; Task 6 restructures it to a named `cs` var for the multi-return assignment. `AccountRef`/`AxisFactor`/`TierFactorBars`/`factorDef` are self-contained in their tasks. Account field names (`PasswordLength`, `RiskScore`, `SharedWith`, `Controlled`, `SimilarityScore`, `HIBPBreachCount`, `PwdLastSet`, `DADomains`, `Complexity`, `ScoreBreakdown`, `EscalatedBySharedDA`, `HasDAPathway()`) match `internal/model/model.go`; Task 5 explicitly tells the implementer to verify `ScoreBreakdown` field names against the source and fix from the compile error if needed.
