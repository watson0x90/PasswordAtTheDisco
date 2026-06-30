# Metrics Library (Phase 1: foundation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up a reusable Go `internal/metrics` package that computes the org-level and per-domain aggregate bundle (summary counts, authoritative posture, and the Exposure×Impact matrix) from a plain `[]model.Account`, so the API, the SPA, and the exporters can later all read one computation.

**Architecture:** Extract the currently-inline org summary loop out of `store.Summary` into a pure `model.Summarize([]Account) Summary`, then build `internal/metrics` on top of it: `Compute(accounts, now)` returns a `Metrics` (org `Summary` + `Matrix`), and `ComputeByDomain` returns one `DomainMetrics` per domain by running the *same* pure functions over each domain's account subset. Posture reuses the existing single source `model.PostureScore`. A golden snapshot test over a committed fixture locks the bundle against regressions.

**Tech Stack:** Go (stdlib only), `encoding/json` for golden fixtures, `go test`.

## Global Constraints

- **Go: stdlib-first.** No new external modules. `go vet ./...` clean, `gofmt -l cmd internal` empty, `go test ./...` green before any commit.
- **Redaction (hard rule).** Nothing in this package may emit cleartext (`Account.Password`), `Account.NTHash`, `Account.BannedWords`, or `Account.KeyboardPatterns`. The bundle is built from descriptive/score fields only. This phase never touches the unredacted tier.
- **Single source of truth.** Posture must come from `model.PostureScore` — do not re-implement it. The Exposure×Impact level mapping must match `internal/risk` and the boundary cutoffs (≥8 Critical, ≥6 High, ≥4 Medium, else Low) used by `web/src/matrix.ts`.
- **Determinism.** All ordering and bucketing must be deterministic (stable sorts, fixed key order) so golden tests are reproducible. No `time.Now()` inside compute — `now` is passed in.
- **Commit messages** end with: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- **Run all commands from the worktree root** `C:\base\dev\PasswordAtTheDisco\.claude\worktrees\nav-and-pagination-fixes`. Do not `cd` to the primary checkout.

**Scope note:** This is the first of several plans for the spec `docs/superpowers/specs/2026-06-30-exports-dashboard-parity-design.md`. Phase 1 = the bundle foundation (this plan). Later plans add: the chart-series & graph-data ports (Plan 2), the `/api/metrics` endpoint (Plan 3), the SPA refactor to render the bundle (Plan 4), export parity + per-domain artifacts (Plan 5), and the unredacted tier (Plan 6).

---

### Task 1: Extract pure `model.Summarize([]Account) Summary`

The org summary is currently computed inline in `store.Summary` (`internal/store/store.go:685-733`). Extract the per-account loop into a pure function in `model` so it can run over any account slice (whole audit *or* a domain subset). `store.Summary` then calls it.

**Files:**
- Modify: `internal/model/model.go` (add `Summarize`)
- Modify: `internal/store/store.go:685-733` (call `model.Summarize`)
- Test: `internal/model/summarize_test.go` (create)

**Interfaces:**
- Consumes: `model.Account`, `model.Summary`, `model.PostureScore`, `model.EstimateBreachImpact`, `model.CredentialObtainable`.
- Produces: `func Summarize(accounts []Account, generatedAt time.Time) Summary` — the single pure org-summary builder. Later tasks and plans call this over domain subsets.

- [ ] **Step 1: Write the failing test**

```go
// internal/model/summarize_test.go
package model

import (
	"testing"
	"time"
)

func bp(b bool) *bool { return &b }

func TestSummarizeCounts(t *testing.T) {
	gen := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	accts := []Account{
		{Domain: "A", Enabled: true, Cracked: true, MeetsPolicy: false, RiskLevel: "Critical", HIBPBreached: true},
		{Domain: "A", Enabled: true, Cracked: false, MeetsPolicy: true, RiskLevel: "Low"},
		{Domain: "B", Enabled: false, Cracked: true, MeetsPolicy: true, RiskLevel: "High",
			ControlsTier0: true}, // disabled + privileged + obtainable -> dormant_privileged
		{Domain: "B", Enabled: true, Cracked: false, RiskLevel: "Medium", PwdNeverExpires: bp(true),
			DaysOutOfCompliance: 10, Controlled: 200},
	}
	s := Summarize(accts, gen)
	if s.TotalAccounts != 4 {
		t.Fatalf("total = %d, want 4", s.TotalAccounts)
	}
	if s.Cracked != 2 {
		t.Errorf("cracked = %d, want 2", s.Cracked)
	}
	if s.HIBPBreached != 1 {
		t.Errorf("hibp = %d, want 1", s.HIBPBreached)
	}
	if s.DisabledAccounts != 1 {
		t.Errorf("disabled = %d, want 1", s.DisabledAccounts)
	}
	if s.NeverExpires != 1 {
		t.Errorf("never_expires = %d, want 1", s.NeverExpires)
	}
	if s.StalePasswords != 1 {
		t.Errorf("stale = %d, want 1", s.StalePasswords)
	}
	if s.PolicyViolations != 1 { // only the enabled cracked !meets_policy
		t.Errorf("violations = %d, want 1", s.PolicyViolations)
	}
	if s.HighControlled != 1 {
		t.Errorf("high_controlled = %d, want 1", s.HighControlled)
	}
	if s.DormantPrivileged != 1 {
		t.Errorf("dormant = %d, want 1", s.DormantPrivileged)
	}
	if s.RiskCounts["Critical"] != 1 || s.RiskCounts["Low"] != 1 {
		t.Errorf("risk_counts = %v", s.RiskCounts)
	}
	if !s.GeneratedAt.Equal(gen) {
		t.Errorf("generated_at = %v, want %v", s.GeneratedAt, gen)
	}
	if s.Posture.Rating == "" {
		t.Error("posture not populated")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/model/ -run TestSummarizeCounts -v`
Expected: FAIL — `undefined: Summarize`.

- [ ] **Step 3: Add `Summarize` to `internal/model/model.go`**

Add (near `PostureScore`):

```go
// Summarize builds the non-sensitive aggregate Summary over an arbitrary account
// slice. It is the single source for org-level AND per-domain summaries: the store
// calls it over a whole audit; the metrics package calls it over a domain subset.
// generatedAt is passed in (no time.Now here) so callers control reproducibility.
func Summarize(accounts []Account, generatedAt time.Time) Summary {
	sum := Summary{RiskCounts: map[string]int{}, GeneratedAt: generatedAt}
	for i := range accounts {
		acc := accounts[i]
		sum.TotalAccounts++
		if acc.Cracked {
			sum.Cracked++
		}
		if acc.HIBPBreached {
			sum.HIBPBreached++
		}
		if acc.HasDAPathway() {
			sum.DAPathways++
		}
		if acc.RiskLevel != "" {
			sum.RiskCounts[acc.RiskLevel]++
		}
		if !acc.Enabled {
			sum.DisabledAccounts++
		}
		if acc.PwdNeverExpires != nil && *acc.PwdNeverExpires {
			sum.NeverExpires++
		}
		if acc.DaysOutOfCompliance > 0 {
			sum.StalePasswords++
		}
		if acc.EscalatedBySharedDA {
			sum.EscalatedBySharedDA++
		}
		if acc.EscalatedByMassReuse {
			sum.EscalatedByMassReuse++
		}
		if acc.Cracked && !acc.MeetsPolicy {
			sum.PolicyViolations++
		}
		if acc.Controlled > 100 {
			sum.HighControlled++
		}
		if !acc.Enabled && (acc.ControlsTier0 || acc.HasDAPathway()) && CredentialObtainable(acc) {
			sum.DormantPrivileged++
		}
	}
	sum.Posture = PostureScore(accounts)
	sum.BreachImpact = EstimateBreachImpact(sum.Posture)
	return sum
}
```

- [ ] **Step 4: Rewire `store.Summary` to call it**

In `internal/store/store.go`, replace the body of `Summary` (lines ~690-732, the `sum := ...` loop through `return sum, nil`) with:

```go
	return model.Summarize(a.ds.Accounts, a.ds.GeneratedAt), nil
```

(Keep the `a, err := s.ensureLoaded(id)` guard above it unchanged.)

- [ ] **Step 5: Run model + store tests**

Run: `go test ./internal/model/ ./internal/store/ -v`
Expected: PASS (the new test plus all existing store/model tests — `store.Summary` output is byte-identical because the logic moved, not changed).

- [ ] **Step 6: Commit**

```bash
git add internal/model/model.go internal/model/summarize_test.go internal/store/store.go
git commit -m "$(printf 'refactor(model): extract pure Summarize from store.Summary\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 2: `internal/metrics` package + org `Compute`

Create the package and the org-level bundle. Phase 1 `Metrics` = the org `Summary` + the Exposure×Impact `Matrix` (built in Task 3) + the per-domain slice (Task 4). This task wires the package and the `Summary` portion; `Matrix` is a zero value until Task 3.

**Files:**
- Create: `internal/metrics/metrics.go`
- Test: `internal/metrics/metrics_test.go`

**Interfaces:**
- Consumes: `model.Account`, `model.Summary`, `model.Summarize`.
- Produces:
  - `type Metrics struct { Summary model.Summary; Matrix Matrix; Domains []DomainMetrics }`
  - `func Compute(accounts []model.Account, now time.Time) Metrics`

- [ ] **Step 1: Write the failing test**

```go
// internal/metrics/metrics_test.go
package metrics

import (
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

func TestComputeOrgSummary(t *testing.T) {
	now := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	accts := []model.Account{
		{Domain: "A", Enabled: true, Cracked: true, RiskLevel: "High"},
		{Domain: "B", Enabled: true, Cracked: false, RiskLevel: "Low"},
	}
	m := Compute(accts, now)
	if m.Summary.TotalAccounts != 2 {
		t.Fatalf("total = %d, want 2", m.Summary.TotalAccounts)
	}
	if m.Summary.Cracked != 1 {
		t.Errorf("cracked = %d, want 1", m.Summary.Cracked)
	}
	if !m.Summary.GeneratedAt.Equal(now) {
		t.Errorf("generated_at = %v, want %v", m.Summary.GeneratedAt, now)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/metrics/ -run TestComputeOrgSummary -v`
Expected: FAIL — package/symbols undefined.

- [ ] **Step 3: Create `internal/metrics/metrics.go`**

```go
// Package metrics computes the redacted aggregate "dashboard bundle" — org-level
// and per-domain — from a plain []model.Account. It is the single producer of
// derived numbers consumed by the API, the SPA, and the report/CSV/JSON exporters.
// It emits no cleartext, no NT hashes, and no matched wordlist fragments.
package metrics

import (
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// Metrics is the org-level dashboard bundle. (Phase 1: Summary + Matrix + Domains.
// Later plans add chart series and graph data as additional fields.)
type Metrics struct {
	Summary model.Summary   `json:"summary"`
	Matrix  Matrix          `json:"matrix"`
	Domains []DomainMetrics `json:"domains"`
}

// Compute builds the org bundle over the full account set. now is injected (no
// time.Now here) for reproducible output.
func Compute(accounts []model.Account, now time.Time) Metrics {
	return Metrics{
		Summary: model.Summarize(accounts, now),
		Matrix:  BuildMatrix(accounts),
		Domains: ComputeByDomain(accounts, now),
	}
}
```

Note: `BuildMatrix` (Task 3) and `ComputeByDomain` (Task 4) do not exist yet, so this will not compile until those tasks land. To keep this task independently green, temporarily add stubs at the bottom of `metrics.go`:

```go
// --- temporary stubs, replaced in Tasks 3 and 4 ---
type Matrix struct{}

func BuildMatrix(_ []model.Account) Matrix { return Matrix{} }

func ComputeByDomain(_ []model.Account, _ time.Time) []DomainMetrics { return nil }

type DomainMetrics struct{}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/metrics/ -run TestComputeOrgSummary -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/metrics/metrics.go internal/metrics/metrics_test.go
git commit -m "$(printf 'feat(metrics): package skeleton + org Compute (summary)\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 3: Exposure×Impact matrix

Port `web/src/matrix.ts` (`axisTier`, `exposureImpactMatrix`, `LEVEL_MATRIX`/`cellLevel`) to Go, replacing the Task-2 stub. Rows = Exposure tier; columns = the four Impact tiers + an explicit `Unknown` column for `ImpactKnown==false` (or nil `ImpactScore`).

**Files:**
- Create: `internal/metrics/matrix.go`
- Modify: `internal/metrics/metrics.go` (delete the `Matrix`/`BuildMatrix` stubs)
- Test: `internal/metrics/matrix_test.go`

**Interfaces:**
- Consumes: `model.Account` (`ExposureScore float64`, `ImpactScore *float64`, `ImpactKnown bool`).
- Produces:
  - `type Tier string` with consts `TierCritical/High/Medium/Low` and `ImpactUnknown = "Unknown"`.
  - `func AxisTier(v float64) Tier`
  - `func CellLevel(exp Tier, imp string) Tier`
  - `type Matrix struct { Counts map[Tier]map[string]int `json:"counts"`; Total int `json:"total"`; Max int `json:"max"` }`
  - `func BuildMatrix(accounts []model.Account) Matrix`

- [ ] **Step 1: Write the failing test**

```go
// internal/metrics/matrix_test.go
package metrics

import (
	"testing"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

func fp(f float64) *float64 { return &f }

func TestAxisTierBoundaries(t *testing.T) {
	cases := []struct {
		v    float64
		want Tier
	}{{8, TierCritical}, {7.99, TierHigh}, {6, TierHigh}, {4, TierMedium}, {3.99, TierLow}, {0, TierLow}}
	for _, c := range cases {
		if got := AxisTier(c.v); got != c.want {
			t.Errorf("AxisTier(%v) = %v, want %v", c.v, got, c.want)
		}
	}
}

// CellLevel must match web/src/matrix.ts LEVEL_MATRIX exactly (and internal/risk).
func TestCellLevelMatchesMatrixTS(t *testing.T) {
	cases := []struct {
		exp  Tier
		imp  string
		want Tier
	}{
		{TierCritical, "Critical", TierCritical}, {TierCritical, "Low", TierMedium}, {TierCritical, ImpactUnknown, TierCritical},
		{TierHigh, "Medium", TierHigh}, {TierHigh, ImpactUnknown, TierHigh},
		{TierMedium, "Low", TierLow}, {TierMedium, ImpactUnknown, TierMedium},
		{TierLow, "Critical", TierHigh}, {TierLow, "Low", TierLow}, {TierLow, ImpactUnknown, TierLow},
	}
	for _, c := range cases {
		if got := CellLevel(c.exp, c.imp); got != c.want {
			t.Errorf("CellLevel(%v,%v) = %v, want %v", c.exp, c.imp, got, c.want)
		}
	}
}

func TestBuildMatrixCountsAndUnknownColumn(t *testing.T) {
	accts := []model.Account{
		{ExposureScore: 9, ImpactKnown: true, ImpactScore: fp(9)},  // Critical x Critical
		{ExposureScore: 9, ImpactKnown: false},                     // Critical x Unknown
		{ExposureScore: 5, ImpactKnown: true, ImpactScore: fp(4)},  // Medium x Medium
		{ExposureScore: 5, ImpactKnown: true, ImpactScore: nil},    // ImpactScore nil -> Unknown despite known flag
	}
	m := BuildMatrix(accts)
	if m.Total != 4 {
		t.Fatalf("total = %d, want 4", m.Total)
	}
	if m.Counts[TierCritical]["Critical"] != 1 {
		t.Errorf("Crit/Crit = %d, want 1", m.Counts[TierCritical]["Critical"])
	}
	if m.Counts[TierCritical][ImpactUnknown] != 1 {
		t.Errorf("Crit/Unknown = %d, want 1", m.Counts[TierCritical][ImpactUnknown])
	}
	if m.Counts[TierMedium][ImpactUnknown] != 1 {
		t.Errorf("Med/Unknown = %d, want 1", m.Counts[TierMedium][ImpactUnknown])
	}
	if m.Max != 1 {
		t.Errorf("max = %d, want 1", m.Max)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/metrics/ -run 'TestAxisTier|TestCellLevel|TestBuildMatrix' -v`
Expected: FAIL — symbols undefined / stub returns empty `Matrix`.

- [ ] **Step 3: Remove the stubs and create `internal/metrics/matrix.go`**

In `internal/metrics/metrics.go`, delete the temporary `type Matrix struct{}` and `func BuildMatrix(...)` stub lines (leave the `ComputeByDomain`/`DomainMetrics` stubs — Task 4 removes those).

Create `internal/metrics/matrix.go`:

```go
package metrics

import "github.com/watson0x90/PasswordAtTheDisco/internal/model"

// Tier is an axis tier (Exposure or Impact). ImpactUnknown is a column-only value
// for accounts with no BloodHound coverage (impact not a number).
type Tier string

const (
	TierCritical Tier = "Critical"
	TierHigh     Tier = "High"
	TierMedium   Tier = "Medium"
	TierLow      Tier = "Low"

	ImpactUnknown = "Unknown"
)

var tierRows = []Tier{TierCritical, TierHigh, TierMedium, TierLow}
var impactCols = []string{string(TierCritical), string(TierHigh), string(TierMedium), string(TierLow), ImpactUnknown}

// AxisTier mirrors internal/risk cutoffs and web/src/matrix.ts axisTier:
// >=8 Critical, >=6 High, >=4 Medium, else Low. Pinned by TestAxisTierBoundaries
// against the same boundary numbers as the Go engine and the TS mirror.
func AxisTier(v float64) Tier {
	switch {
	case v >= 8:
		return TierCritical
	case v >= 6:
		return TierHigh
	case v >= 4:
		return TierMedium
	default:
		return TierLow
	}
}

// levelMatrix is keyed [exposure tier][impact column] and is transcribed verbatim
// from web/src/matrix.ts LEVEL_MATRIX (itself derived from internal/risk levelMatrix).
// The Unknown column = the Exposure tier alone (provisional). Pinned by
// TestCellLevelMatchesMatrixTS.
var levelMatrix = map[Tier]map[string]Tier{
	TierCritical: {"Critical": TierCritical, "High": TierCritical, "Medium": TierHigh, "Low": TierMedium, ImpactUnknown: TierCritical},
	TierHigh:     {"Critical": TierCritical, "High": TierHigh, "Medium": TierHigh, "Low": TierMedium, ImpactUnknown: TierHigh},
	TierMedium:   {"Critical": TierCritical, "High": TierHigh, "Medium": TierMedium, "Low": TierLow, ImpactUnknown: TierMedium},
	TierLow:      {"Critical": TierHigh, "High": TierMedium, "Medium": TierMedium, "Low": TierLow, ImpactUnknown: TierLow},
}

// CellLevel returns the resulting risk Level for an (Exposure tier, Impact column).
func CellLevel(exp Tier, imp string) Tier { return levelMatrix[exp][imp] }

// Matrix is the Exposure×Impact distribution grid plus its largest cell (Max), used
// by the heatmap to normalize intensity.
type Matrix struct {
	Counts map[Tier]map[string]int `json:"counts"`
	Total  int                     `json:"total"`
	Max    int                     `json:"max"`
}

// impactColumn returns the Impact column for an account: a tier when Impact is a
// usable number (ImpactKnown AND ImpactScore non-nil), else ImpactUnknown. Mirrors
// web/src/matrix.ts impactIsKnown.
func impactColumn(a model.Account) string {
	if a.ImpactKnown && a.ImpactScore != nil {
		return string(AxisTier(*a.ImpactScore))
	}
	return ImpactUnknown
}

// BuildMatrix buckets accounts into the Exposure×Impact grid.
func BuildMatrix(accounts []model.Account) Matrix {
	m := Matrix{Counts: map[Tier]map[string]int{}, Total: 0}
	for _, r := range tierRows {
		m.Counts[r] = map[string]int{}
		for _, c := range impactCols {
			m.Counts[r][c] = 0
		}
	}
	for i := range accounts {
		a := accounts[i]
		m.Counts[AxisTier(a.ExposureScore)][impactColumn(a)]++
		m.Total++
	}
	for _, r := range tierRows {
		for _, c := range impactCols {
			if m.Counts[r][c] > m.Max {
				m.Max = m.Counts[r][c]
			}
		}
	}
	return m
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/metrics/ -v`
Expected: PASS (matrix tests + the Task-2 summary test).

- [ ] **Step 5: Commit**

```bash
git add internal/metrics/matrix.go internal/metrics/matrix_test.go internal/metrics/metrics.go
git commit -m "$(printf 'feat(metrics): Exposure x Impact matrix (parity with matrix.ts)\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 4: Per-domain metrics

Replace the `ComputeByDomain`/`DomainMetrics` stubs with a real per-domain bundle. Each domain's metrics run the **same** `model.Summarize` + `BuildMatrix` over that domain's account subset — this is what makes a domain view and a domain export agree by construction (it replaces the frontend `domainScope.ts`/`domainData.ts` recompute). Domains are emitted in a deterministic order (alphabetical).

**Files:**
- Create: `internal/metrics/domain.go`
- Modify: `internal/metrics/metrics.go` (delete the `ComputeByDomain`/`DomainMetrics` stubs)
- Test: `internal/metrics/domain_test.go`

**Interfaces:**
- Consumes: `model.Account` (`Domain string`), `model.Summarize`, `BuildMatrix`.
- Produces:
  - `type DomainMetrics struct { Domain string `json:"domain"`; Summary model.Summary `json:"summary"`; Matrix Matrix `json:"matrix"` }`
  - `func ComputeByDomain(accounts []model.Account, now time.Time) []DomainMetrics`

- [ ] **Step 1: Write the failing test**

```go
// internal/metrics/domain_test.go
package metrics

import (
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

func TestComputeByDomainSplitsAndMatchesSummarize(t *testing.T) {
	now := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	accts := []model.Account{
		{Domain: "B.LOCAL", Enabled: true, Cracked: true, RiskLevel: "High"},
		{Domain: "A.LOCAL", Enabled: true, Cracked: false, RiskLevel: "Low"},
		{Domain: "A.LOCAL", Enabled: true, Cracked: true, RiskLevel: "Critical"},
	}
	doms := ComputeByDomain(accts, now)
	if len(doms) != 2 {
		t.Fatalf("domains = %d, want 2", len(doms))
	}
	// deterministic alphabetical order
	if doms[0].Domain != "A.LOCAL" || doms[1].Domain != "B.LOCAL" {
		t.Fatalf("order = %q,%q want A.LOCAL,B.LOCAL", doms[0].Domain, doms[1].Domain)
	}
	if doms[0].Summary.TotalAccounts != 2 || doms[1].Summary.TotalAccounts != 1 {
		t.Errorf("totals = %d,%d want 2,1", doms[0].Summary.TotalAccounts, doms[1].Summary.TotalAccounts)
	}
	// per-domain summary must equal Summarize over that subset (single source)
	want := model.Summarize([]model.Account{
		{Domain: "A.LOCAL", Enabled: true, Cracked: false, RiskLevel: "Low"},
		{Domain: "A.LOCAL", Enabled: true, Cracked: true, RiskLevel: "Critical"},
	}, now)
	if doms[0].Summary.Cracked != want.Cracked || doms[0].Summary.Posture.Score != want.Posture.Score {
		t.Errorf("A.LOCAL summary diverges from Summarize")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/metrics/ -run TestComputeByDomain -v`
Expected: FAIL — stub returns nil.

- [ ] **Step 3: Remove stubs and create `internal/metrics/domain.go`**

In `internal/metrics/metrics.go`, delete the temporary `func ComputeByDomain(...)` and `type DomainMetrics struct{}` stub lines.

Create `internal/metrics/domain.go`:

```go
package metrics

import (
	"sort"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// DomainMetrics is the per-domain bundle: the same Summary + Matrix as the org
// bundle, computed over the domain's account subset. Replaces the frontend
// domainScope.ts / domainData.ts recompute so the dashboard, the in-report section,
// and the standalone per-domain export all share one calculation.
type DomainMetrics struct {
	Domain  string        `json:"domain"`
	Summary model.Summary `json:"summary"`
	Matrix  Matrix        `json:"matrix"`
}

// ComputeByDomain groups accounts by Domain and builds one DomainMetrics per domain,
// in deterministic alphabetical domain order.
func ComputeByDomain(accounts []model.Account, now time.Time) []DomainMetrics {
	byDomain := map[string][]model.Account{}
	for i := range accounts {
		d := accounts[i].Domain
		byDomain[d] = append(byDomain[d], accounts[i])
	}
	names := make([]string, 0, len(byDomain))
	for d := range byDomain {
		names = append(names, d)
	}
	sort.Strings(names)
	out := make([]DomainMetrics, 0, len(names))
	for _, d := range names {
		sub := byDomain[d]
		out = append(out, DomainMetrics{
			Domain:  d,
			Summary: model.Summarize(sub, now),
			Matrix:  BuildMatrix(sub),
		})
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/metrics/ -v`
Expected: PASS (all metrics tests).

- [ ] **Step 5: Commit**

```bash
git add internal/metrics/domain.go internal/metrics/domain_test.go internal/metrics/metrics.go
git commit -m "$(printf 'feat(metrics): per-domain bundle reusing the single summarizer\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 5: Golden snapshot regression lock

Lock the whole bundle against a committed fixture so future ports (Plan 2+) can't silently change numbers. The test marshals `Compute` over `testdata/accounts.json` and compares to `testdata/metrics_golden.json`, regenerated with `-update`.

**Files:**
- Create: `internal/metrics/golden_test.go`
- Create: `internal/metrics/testdata/accounts.json` (representative redacted accounts — multi-domain, mixed cracked/enabled/impact-known/disabled-privileged)
- Create: `internal/metrics/testdata/metrics_golden.json` (generated in Step 3)

**Interfaces:**
- Consumes: `Compute`, `model.Account`.
- Produces: a stable golden fixture future plans diff against.

- [ ] **Step 1: Write the golden test**

```go
// internal/metrics/golden_test.go
package metrics

import (
	"encoding/json"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

var update = flag.Bool("update", false, "regenerate golden files")

func TestMetricsGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/accounts.json")
	if err != nil {
		t.Fatalf("read accounts fixture: %v", err)
	}
	var accts []model.Account
	if err := json.Unmarshal(raw, &accts); err != nil {
		t.Fatalf("unmarshal accounts: %v", err)
	}
	now := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	got, err := json.MarshalIndent(Compute(accts, now), "", "  ")
	if err != nil {
		t.Fatalf("marshal metrics: %v", err)
	}
	got = append(got, '\n')
	const goldenPath = "testdata/metrics_golden.json"
	if *update {
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update first): %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("metrics bundle changed vs golden.\nRe-run: go test ./internal/metrics/ -run TestMetricsGolden -update\nthen review the diff before committing.")
	}
}
```

- [ ] **Step 2: Create the accounts fixture**

Create `internal/metrics/testdata/accounts.json` with a representative redacted set (no password/nt_hash fields). Use exactly this content:

```json
[
  {"username":"alice","domain":"A.LOCAL","cracked":true,"password_length":7,"risk_level":"Critical","risk_score":8.5,"hibp_breached":true,"hibp_breach_count":1200,"da_domains":"A.LOCAL","controlled_object_count":150,"shared_with":3,"enabled":true,"coverage":"full","exposure_score":9.0,"impact_score":9.0,"impact_known":true,"percentile":0.0,"meets_policy":false,"controls_tier0":true},
  {"username":"bob","domain":"A.LOCAL","cracked":true,"password_length":12,"risk_level":"Medium","risk_score":4.2,"hibp_breached":false,"da_domains":"None","controlled_object_count":0,"shared_with":0,"enabled":true,"coverage":"full","exposure_score":4.5,"impact_score":4.0,"impact_known":true,"percentile":0.5,"meets_policy":true},
  {"username":"carol","domain":"A.LOCAL","cracked":false,"risk_level":"High","risk_score":6.1,"hibp_breached":false,"da_domains":"None","enabled":true,"coverage":"none","exposure_score":6.2,"impact_known":false,"percentile":0.3,"meets_policy":true},
  {"username":"dave","domain":"B.LOCAL","cracked":true,"password_length":9,"risk_level":"High","risk_score":7.0,"hibp_breached":true,"hibp_breach_count":50,"da_domains":"None","controlled_object_count":250,"shared_with":1,"enabled":false,"coverage":"full","exposure_score":7.5,"impact_score":8.0,"impact_known":true,"percentile":0.2,"meets_policy":true,"controls_tier0":true,"pwd_never_expires":true,"days_out_of_compliance":40},
  {"username":"erin","domain":"B.LOCAL","cracked":false,"risk_level":"Low","risk_score":1.5,"hibp_breached":false,"da_domains":"None","enabled":true,"coverage":"full","exposure_score":1.0,"impact_score":2.0,"impact_known":true,"percentile":0.9,"meets_policy":true}
]
```

- [ ] **Step 3: Generate the golden file**

Run: `go test ./internal/metrics/ -run TestMetricsGolden -update`
Expected: PASS; creates `testdata/metrics_golden.json`. Open it and sanity-check: `summary.total_accounts` = 5, the `matrix.counts` Unknown column has carol (Exposure High → `counts.High.Unknown` = 1), and `domains` lists `A.LOCAL` then `B.LOCAL`.

- [ ] **Step 4: Run the test in verify mode**

Run: `go test ./internal/metrics/ -run TestMetricsGolden -v`
Expected: PASS (got == golden).

- [ ] **Step 5: Full gate + commit**

Run: `gofmt -l internal/metrics internal/model internal/store` (expect empty), then `go vet ./... && go test ./...`
Expected: all PASS.

```bash
git add internal/metrics/golden_test.go internal/metrics/testdata/accounts.json internal/metrics/testdata/metrics_golden.json
git commit -m "$(printf 'test(metrics): golden snapshot regression lock for the bundle\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

## Self-Review

**Spec coverage (Phase 1 slice):** The spec's Phase 1 is "build `internal/metrics` (org + per-domain) with golden parity tests, no consumer change." This plan delivers: the package (Task 2), org summary via the extracted single source (Task 1), the Exposure×Impact matrix with TS-parity tests (Task 3), per-domain bundle reusing the same summarizer (Task 4), and a golden regression lock (Task 5). No consumer (API/SPA/export) is touched — `store.Summary` keeps identical output. The chart-series, graph-data, API, SPA, exports, and unredacted tier are explicitly deferred to Plans 2–6 (documented in the Scope note).

**Placeholder scan:** No TBD/TODO; every code step shows complete code; the only stubs are explicitly temporary and removed in the named follow-up task, with the test that forces their replacement.

**Type consistency:** `Summarize(accounts, generatedAt time.Time) Summary` is defined in Task 1 and consumed unchanged in Tasks 2/4. `Matrix`, `BuildMatrix`, `Tier`, `AxisTier`, `CellLevel`, `ImpactUnknown` are defined in Task 3 and consumed by Task 4's `BuildMatrix` call and the matrix tests. `DomainMetrics`/`ComputeByDomain` defined in Task 4 match the `Compute` call site in Task 2. `Metrics` shape is stable (later plans add fields, not rename). Account field names (`ExposureScore`, `ImpactScore *float64`, `ImpactKnown`, `Controlled`, `ControlsTier0`, `PwdNeverExpires *bool`, `DaysOutOfCompliance`, `HasDAPathway()`) match `internal/model/model.go`.
