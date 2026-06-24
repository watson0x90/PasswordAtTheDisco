# Executive Scoring Rework (Hygiene × Reachability + Tier-0 gate) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended)
> or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Replace the single diluted "Posture" verdict with two orthogonal axes — Credential Hygiene
(average) and Breach Reachability (worst-path) — plus a one-way Tier-0 gate, so the dashboard can never
read "Strong" next to a reachable domain-control path.

**Architecture:** Audit-level rollup only (`internal/model/model.go` + its TS mirror `web/src/insights.ts`).
Per-account engine (`internal/risk`) untouched. Source of truth = Go; TS mirror kept byte-parity by a
golden test. Spec: `docs/superpowers/specs/2026-06-23-posture-reachability-rework-design.md` (v2,
panel-vetted) — read it; this plan implements it exactly.

**Tech Stack:** Go 1.26 stdlib-only; React 18 + TS + Vite; gates `gofmt`/`go vet`/`go test`/`govulncheck`
and `tsc`/`vitest`/`npm run build` (NEVER `npm install` on this box).

**Branch:** all work on `feature/posture-reachability-rework` (already created, spec committed). Every
implementer MUST confirm `git branch --show-current` == that branch and NEVER run `git checkout`/`switch`.

---

## File Structure
- `internal/model/model.go` — the rework: const block, `reachable`/`powi`/`breachReachability`/`reachBand`/
  `gateVerdict` helpers, `PostureScore` (now computes Hygiene + Reachability + Overall + Verdict),
  `EstimateBreachImpact` (reachability-driven), extended `Posture`/`BreachImpact`/`Summary` structs.
- `internal/model/model_test.go` — golden + invariant tests.
- `internal/store/store.go:700-728` — wire the new builder; add `Summary.DormantPrivileged`.
- `internal/report/sanitize.go` + `internal/report/report.go` — new summary fields in export/HTML.
- `internal/report/sanitize_test.go` — export fields + canary still clean.
- `web/src/api.ts` — `Posture`/`Summary` types.
- `web/src/insights.ts` — TS mirror of the Go formula (per-domain subsets).
- `web/src/insights.golden.test.ts` (new) — Go⇄TS parity fixture test.
- `web/src/components/Dashboard.tsx` — the executive card (Verdict headline + two components + copy).
- `web/src/components/Compare.tsx` — two-axis delta; Overall as labeled secondary.
- `web/src/components/help/ChapterScoring.tsx` — explain the two axes + gate.

DRY/YAGNI/TDD, frequent commits. Constants live in ONE named `const` block (Task 1).

---

### Task 1: Constants + struct fields (scaffolding so everything compiles)

**Files:**
- Modify: `internal/model/model.go` (add const block near top; extend `Posture`, `BreachImpact`, `Summary`)

- [ ] **Step 1: Add the named const block** (single source of tunables) above `PostureScore`:

```go
const (
	// Credential Hygiene component weights (sum 100); privilege term removed.
	hygieneRiskWeight       = 45.0
	hygieneStrengthWeight   = 35.0
	hygieneComplianceWeight = 20.0
	hygieneStrongMin        = 85.0
	hygieneFairMin          = 70.0

	// Breach Reachability: per-enabler "exploitable" probabilities and caps.
	reachPDA     = 0.55 // one reachable DA path -> L=0.55 (High); two -> 0.7975 (Very High)
	reachPT0     = 0.70
	reachPCrit   = 0.15
	reachCapCrit = 5 // cap supporting-evidence count so estate SIZE can't auto-pin Very High
	// reuseN deferred (v1): redacted /api/accounts has no reuse-group token -> TS parity; see spec §2.2.

	// Reachability bands on integer-scaled L (L*reachScale), parity-safe.
	reachScale      = 1_000_000
	reachBandMedium = 250_000 // >= -> Medium  (>=25%)
	reachBandHigh   = 500_000 // >= -> High     (>=50%)
	reachBandVeryHi = 750_000 // >= -> Very High (>=75%)
)
```

- [ ] **Step 2: Extend the `Posture` struct** (keep existing JSON keys for back-compat; add new):

```go
type Posture struct {
	Score            float64          `json:"score"`               // = Credential Hygiene (0-100)
	Rating           string           `json:"rating"`              // Strong|Fair|Weak|No Data (hygiene)
	Likelihood       string           `json:"likelihood"`          // back-compat alias = Reachability band
	Breakdown        PostureBreakdown `json:"breakdown"`
	Reachability     string           `json:"reachability"`        // Low|Medium|High|Very High|—
	ReachabilityScore float64         `json:"reachability_score"`  // L in [0,1)
	ReachabilityPct  string           `json:"reachability_pct"`    // band range, e.g. ">75%" (never a point %)
	Overall          float64          `json:"overall"`             // Hygiene*(1-L); trend/sort key only
	Verdict          string           `json:"verdict"`             // Sound|Guarded|Elevated|High Risk|Critical|No Data
	VerdictReason    string           `json:"verdict_reason,omitempty"`
}
```
(Leave `PostureBreakdown` as-is; the `privilege` field stays for back-compat, always set to 0 now.)

- [ ] **Step 3: Add `DormantPrivileged` to `Summary`** (near `EscalatedByMassReuse`, model.go ~574):

```go
	DormantPrivileged int `json:"dormant_privileged"` // disabled but privileged & credential-compromisable
```

- [ ] **Step 4: Build to confirm it compiles**

Run: `go build ./...`
Expected: PASS (structs extended; helpers added next tasks).

- [ ] **Step 5: Commit**

```bash
git add internal/model/model.go
git commit -m "feat(model): const block + Posture/Summary fields for Hygiene×Reachability rework"
```

---

### Task 2: Credential Hygiene (enabled-only, drop privilege, 45/35/20)

**Files:**
- Modify: `internal/model/model.go` (`PostureScore` hygiene portion + a `hygieneRating` helper)
- Test: `internal/model/model_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestHygieneExcludesDisabledAndDropsPrivilege(t *testing.T) {
	// 2 enabled (1 cracked-violator), 8 disabled -> hygiene computed over the 2 enabled only.
	accts := []Account{
		{Enabled: true, RiskLevel: "Low", Cracked: true, MeetsPolicy: false}, // enabled cracked violator
		{Enabled: true, RiskLevel: "Low", Cracked: false, MeetsPolicy: true},  // enabled clean
	}
	for i := 0; i < 8; i++ { // disabled padding must NOT inflate hygiene
		accts = append(accts, Account{Enabled: false, RiskLevel: "Critical", Cracked: true, MeetsPolicy: false})
	}
	p := PostureScore(accts)
	// active=2: risk=45 (no crit/high/med among enabled), strength=(1/2)*35=17.5,
	// compliance=((2-1)/2)*20=10 -> 72.5
	if p.Score < 72.0 || p.Score > 73.0 {
		t.Fatalf("hygiene = %v, want ~72.5 (disabled excluded, privilege dropped)", p.Score)
	}
	if p.Breakdown.Privilege != 0 {
		t.Errorf("privilege breakdown must be 0 (term removed), got %v", p.Breakdown.Privilege)
	}
}

func TestHygieneActiveZero(t *testing.T) {
	accts := []Account{{Enabled: false, RiskLevel: "Low"}}
	p := PostureScore(accts)
	if p.Verdict != "No Data" || p.Score != 0 {
		t.Fatalf("all-disabled -> want No Data/0, got %q/%v", p.Verdict, p.Score)
	}
}
```

- [ ] **Step 2: Run to verify failure** — `go test ./internal/model/ -run TestHygiene -v` → FAIL.

- [ ] **Step 3: Implement the hygiene portion** — rewrite the top of `PostureScore` (replace lines ~34-78):

```go
func PostureScore(accounts []Account) Posture {
	var active, crit, high, med, uncracked, viol int
	for _, a := range accounts {
		if !a.Enabled {
			continue // disabled excluded from hygiene (they padded "Strong")
		}
		active++
		switch a.RiskLevel {
		case "Critical":
			crit++
		case "High":
			high++
		case "Medium":
			med++
		}
		if !a.Cracked {
			uncracked++
		}
		if a.Cracked && !a.MeetsPolicy {
			viol++
		}
	}
	// Reachability is computed over the FULL set (Task 3); compute it first so the gate
	// can fire even when active==0.
	L, _, t0, _, _ := breachReachability(accounts) // (added in Task 3)
	band := reachBand(L)                            // (added in Task 3)

	if active == 0 {
		p := Posture{Score: 0, Rating: "No Data", Reachability: band,
			ReachabilityScore: L, ReachabilityPct: reachPct(band), Likelihood: band}
		p.Verdict, p.VerdictReason = gateVerdict("No Data", band, t0, active) // (Task 4)
		return p
	}
	af := float64(active)
	risk := math.Max(0, 100-float64(crit)/af*200-float64(high)/af*150-float64(med)/af*50) / 100 * hygieneRiskWeight
	strength := float64(uncracked) / af * hygieneStrengthWeight
	compliance := float64(active-viol) / af * hygieneComplianceWeight
	hygiene := round1(risk + strength + compliance)
	rating := hygieneRating(hygiene)

	p := Posture{
		Score:     hygiene,
		Rating:    rating,
		Breakdown: PostureBreakdown{Risk: round1(risk), Strength: round1(strength), Privilege: 0, Compliance: round1(compliance)},
		Reachability: band, ReachabilityScore: L, ReachabilityPct: reachPct(band), Likelihood: band,
	}
	p.Overall = round1(hygiene * (1 - L)) // Task 4 finalizes Verdict; Overall here
	p.Verdict, p.VerdictReason = gateVerdict(rating, band, t0, active) // Task 4
	return p
}

func hygieneRating(h float64) string {
	switch {
	case h >= hygieneStrongMin:
		return "Strong"
	case h >= hygieneFairMin:
		return "Fair"
	default:
		return "Weak"
	}
}
```
NOTE: this references `breachReachability`, `reachBand`, `reachPct`, `gateVerdict` — added in Tasks 3-4.
To keep the build green between tasks, add temporary stubs now returning zero values, OR implement
Tasks 2-4 as one commit. Recommended: stub them here (returning `0,0,0,0,0` / `"Low"` / `""` / `"Low",""`)
and replace in Tasks 3-4. Mark stubs with `// STUB: Task N`.

- [ ] **Step 4: Run** — `go test ./internal/model/ -run TestHygiene -v` → PASS.

- [ ] **Step 5: Commit** — `feat(model): Credential Hygiene over enabled accounts, privilege term removed`.

---

### Task 3: Breach Reachability — reachable() counts, powi, L, bands

**Files:**
- Modify: `internal/model/model.go` (`reachable`, `powi`, `breachReachability`, `reachBand`, `reachPct`)
- Test: `internal/model/model_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestReachabilityBandsAndReachable(t *testing.T) {
	mk := func(da, t0 bool, cracked, enabled bool) Account {
		a := Account{Enabled: enabled, Cracked: cracked, ControlsTier0: t0}
		if da {
			a.DADomains = "CORP.LOCAL" // makes HasDAPathway() true
		}
		return a
	}
	// 0 enablers -> Low
	if b := reachBand(mustL(t)); b != "Low" {
	}
	// 1 reachable DA path -> L=0.55 -> High
	one := []Account{mk(true, false, true, true)}
	L, da, _, _, _ := breachReachability(one)
	if da != 1 || reachBand(L) != "High" {
		t.Fatalf("1 reachable DA: da=%d band=%s L=%.4f, want da=1 High L=0.55", da, reachBand(L), L)
	}
	// 2 reachable DA paths -> L=0.7975 -> Very High
	two := []Account{mk(true, false, true, true), mk(true, false, true, true)}
	L2, _, _, _, _ := breachReachability(two)
	if reachBand(L2) != "Very High" {
		t.Fatalf("2 reachable DA: band=%s L=%.4f, want Very High", reachBand(L2), L2)
	}
	// DA path through a DISABLED account is NOT reachable -> contributes 0, +1 dormant
	dis := []Account{mk(true, false, true, false)}
	Ld, dad, _, _, dorm := breachReachability(dis)
	if dad != 0 || reachBand(Ld) != "Low" || dorm != 1 {
		t.Fatalf("disabled DA: da=%d band=%s dormant=%d, want da=0 Low dormant=1", dad, reachBand(Ld), dorm)
	}
}
```
(`mustL` helper trivial; or drop the first stanza — keep it focused on the three real cases.)

- [ ] **Step 2: Run** → FAIL (helpers undefined / stubbed).

- [ ] **Step 3: Implement** (replace the Task-2 stubs):

```go
// reachable: a privileged object the auditor can actually obtain/authenticate as.
func reachable(a Account) bool {
	return a.Enabled && (a.Cracked || a.EscalatedBySharedDA || a.EscalatedByMassReuse)
}

// powi: integer power by repeated multiply — IDENTICAL in Go and JS (avoids math.Pow/Math.pow
// cross-libm last-ULP drift). Keep web/src/insights.ts powi in lockstep.
func powi(base float64, n int) float64 {
	r := 1.0
	for i := 0; i < n; i++ {
		r *= base
	}
	return r
}

// breachReachability returns L plus the component counts (da, t0Reachable, critN, dormant).
func breachReachability(accts []Account) (L float64, da, t0, critN, dormant int) {
	for i := range accts {
		a := accts[i]
		if reachable(a) {
			if a.HasDAPathway() {
				da++
			}
			if a.ControlsTier0 {
				t0++
			}
		} else if !a.Enabled && (a.ControlsTier0 || a.HasDAPathway()) &&
			(a.Cracked || a.EscalatedBySharedDA || a.EscalatedByMassReuse) {
			dormant++ // disabled landmine
		}
		if a.RiskLevel == "Critical" && !a.HasDAPathway() && !a.ControlsTier0 {
			critN++ // Critical that is not ALREADY the catastrophe (de-dup vs da/t0)
		}
	}
	if critN > reachCapCrit {
		critN = reachCapCrit
	}
	// reuseN deferred (v1) — see spec §2.2.
	L = 1 - powi(1-reachPDA, da)*powi(1-reachPT0, t0)*powi(1-reachPCrit, critN)
	return
}

func reachBand(L float64) string {
	ls := int(L*reachScale + 0.5) // floor(L*scale+0.5); identical to Math.floor(L*scale+0.5) in TS
	switch {
	case ls >= reachBandVeryHi:
		return "Very High"
	case ls >= reachBandHigh:
		return "High"
	case ls >= reachBandMedium:
		return "Medium"
	default:
		return "Low"
	}
}

func reachPct(band string) string {
	switch band {
	case "Very High":
		return ">75%"
	case "High":
		return "50-75%"
	case "Medium":
		return "25-50%"
	default:
		return "<25%"
	}
}
```
NOTE: `breachReachability` returns 5 values; update the Task-2 call site to
`L, _, t0, _, _ := breachReachability(accounts)` (dormant is counted in store.go's own loop — Task 5).
`reuseKey` is the existing unexported helper. Confirm `HasDAPathway()` and `reuseKey` signatures.

- [ ] **Step 4: Run** → `go test ./internal/model/ -run TestReachability -v` PASS.

- [ ] **Step 5: Commit** — `feat(model): Breach Reachability L over reachable enablers (powi, integer bands)`.

---

### Task 4: Verdict gate + reason + Overall

**Files:**
- Modify: `internal/model/model.go` (`gateVerdict`; PostureScore already calls it)
- Test: `internal/model/model_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestGateVerdict(t *testing.T) {
	cases := []struct {
		name, rating, band string
		t0, active         int
		verdict, reason    string
	}{
		{"tier0 caps to critical even if hygiene strong", "Strong", "Low", 1, 100, "Critical", "Tier-0 Reachable"},
		{"very-high L -> critical", "Strong", "Very High", 0, 100, "Critical", "multiple reachable domain-control paths"},
		{"high L -> high risk", "Strong", "High", 0, 100, "High Risk", "a reachable path to domain-control exists"},
		{"strong hygiene, low L -> sound", "Strong", "Low", 0, 100, "Sound", ""},
		{"fair hygiene -> guarded", "Fair", "Low", 0, 100, "Guarded", ""},
		{"weak hygiene -> elevated", "Weak", "Medium", 0, 100, "Elevated", ""},
		{"all disabled, no t0 -> no data", "No Data", "Low", 0, 0, "No Data", ""},
		{"all disabled but reachable tier0 -> critical", "No Data", "Low", 1, 0, "Critical", "Tier-0 Reachable"},
	}
	for _, c := range cases {
		v, r := gateVerdict(c.rating, c.band, c.t0, c.active)
		if v != c.verdict || r != c.reason {
			t.Errorf("%s: got %q/%q want %q/%q", c.name, v, r, c.verdict, c.reason)
		}
	}
}
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Implement**

```go
// gateVerdict: one-register, one-way (only-lowers) headline. Verdict is machine-stable;
// VerdictReason carries the human "why" (SSL-Labs "grade capped because…" pattern).
func gateVerdict(hygieneRating, band string, t0, active int) (verdict, reason string) {
	switch {
	case active == 0 && t0 == 0:
		return "No Data", ""
	case t0 >= 1:
		return "Critical", "Tier-0 Reachable"
	case band == "Very High":
		return "Critical", "multiple reachable domain-control paths"
	case band == "High":
		return "High Risk", "a reachable path to domain-control exists"
	default:
		switch hygieneRating {
		case "Strong":
			return "Sound", ""
		case "Fair":
			return "Guarded", ""
		default:
			return "Elevated", ""
		}
	}
}
```

- [ ] **Step 4: Run** → `go test ./internal/model/ -run TestGateVerdict -v` PASS. Then full `go test ./internal/model/`.

- [ ] **Step 5: Commit** — `feat(model): one-register Verdict gate + reason + gated Overall`.

---

### Task 5: Breach impact rework + store wiring + dormant count

**Files:**
- Modify: `internal/model/model.go` (`EstimateBreachImpact` signature → takes `Posture`)
- Modify: `internal/store/store.go:700-728`
- Test: `internal/model/model_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestBreachImpactReachabilityDriven(t *testing.T) {
	t0 := Posture{Verdict: "Critical", VerdictReason: "Tier-0 Reachable", Reachability: "Very High"}
	if bi := EstimateBreachImpact(t0); bi.EstimatedCost != "$1M – $5M+" || bi.RecoveryTime != "6–12 months" {
		t.Fatalf("tier-0 reachable -> want $1M-$5M+/6-12mo, got %q/%q", bi.EstimatedCost, bi.RecoveryTime)
	}
	vh := Posture{Verdict: "Critical", VerdictReason: "multiple reachable domain-control paths", Reachability: "Very High"}
	if bi := EstimateBreachImpact(vh); bi.EstimatedCost != "$500K – $1M" {
		t.Fatalf("very-high (no tier0) -> want $500K-$1M, got %q", bi.EstimatedCost)
	}
	low := Posture{Verdict: "Sound", Reachability: "Low"}
	if bi := EstimateBreachImpact(low); bi.Probability != "Low" || bi.EstimatedCost != "$50K – $100K" {
		t.Fatalf("low -> want Low/$50K-$100K, got %q/%q", bi.Probability, bi.EstimatedCost)
	}
}
```

- [ ] **Step 2: Run** → FAIL (signature still `(crit, da int)`).

- [ ] **Step 3: Implement** — replace `EstimateBreachImpact`:

```go
// EstimateBreachImpact: reachability-driven (single-source with Posture so $ and verdict agree).
func EstimateBreachImpact(p Posture) BreachImpact {
	var bi BreachImpact
	bi.Probability = p.Reachability
	bi.ProbabilityPct = p.ReachabilityPct
	switch {
	case p.VerdictReason == "Tier-0 Reachable":
		bi.EstimatedCost, bi.RecoveryTime = "$1M – $5M+", "6–12 months"
	case p.Reachability == "Very High":
		bi.EstimatedCost, bi.RecoveryTime = "$500K – $1M", "3–6 months"
	case p.Reachability == "High":
		bi.EstimatedCost, bi.RecoveryTime = "$100K – $500K", "1–3 months"
	default:
		bi.EstimatedCost, bi.RecoveryTime = "$50K – $100K", "2–4 weeks"
	}
	if p.Reachability == "" || p.Reachability == "—" { // No-Data guard
		bi.Probability, bi.ProbabilityPct = "—", ""
	}
	return bi
}
```

- [ ] **Step 4: Wire store.go** — in the existing account loop (after line 718) add the dormant count:

```go
		if !acc.Enabled && (acc.ControlsTier0 || acc.HasDAPathway()) &&
			(acc.Cracked || acc.EscalatedBySharedDA || acc.EscalatedByMassReuse) {
			sum.DormantPrivileged++
		}
```
and replace lines 727-728:
```go
	sum.Posture = model.PostureScore(a.ds.Accounts) // Hygiene + Reachability + Verdict (single source)
	sum.BreachImpact = model.EstimateBreachImpact(sum.Posture)
```

- [ ] **Step 5: Run** — `go test ./...` (update/sweep any other `EstimateBreachImpact(`/`PostureScore` callers
  & their tests, e.g. `internal/report/report.go:257`, `:58-59` use only `.Score` — fine). Expected PASS.

- [ ] **Step 6: Commit** — `feat(model): reachability-driven breach impact + store wiring + dormant count`.

---

### Task 6: Sanitized export + HTML report fields

**Files:**
- Modify: `internal/report/sanitize.go` (summary block), `internal/report/report.go` (HTML rollup)
- Test: `internal/report/sanitize_test.go`

- [ ] **Step 1: Write the failing test** — extend the sanitize summary test to assert the new keys are
  present (`reachability`, `overall`, `verdict`, `verdict_reason`, `dormant_privileged`) AND the existing
  canary byte-scan / forbidden-key tests still pass (no username/hash/cleartext).

```go
func TestSanitizedSummaryHasReachabilityFields(t *testing.T) {
	// build a small DataSet with 1 reachable DCSync account; export sanitized; assert fields.
	// ... (follow the existing sanitize_test setup) ...
	if san.Summary.Verdict != "Critical" || san.Summary.Reachability == "" {
		t.Fatalf("sanitized summary missing reachability/verdict")
	}
}
```

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Implement** — add the fields to the sanitized summary struct (copy from `model.Summary`/
  `Posture`) and to the HTML report's executive block. Keep the allowlist discipline (only the new
  aggregate scalars — no per-account leakage). Mirror `Posture` keys exactly.

- [ ] **Step 4: Run** — `go test ./internal/report/` (incl. canary test) PASS.

- [ ] **Step 5: Commit** — `feat(report): reachability/verdict/dormant in sanitized export + HTML rollup`.

---

### Task 7: TS mirror (insights.ts) of the Go formula

**Files:**
- Modify: `web/src/api.ts` (`Posture` + `Summary` types), `web/src/insights.ts` (the `posture()` mirror)

- [ ] **Step 1: Update `web/src/api.ts` types** — add to `Posture`: `reachability`, `reachability_score`,
  `reachability_pct`, `overall`, `verdict`, `verdict_reason?`; to `Summary`: `dormant_privileged`.

- [ ] **Step 2: Rewrite `insights.ts` `posture()`** to mirror Go EXACTLY (same const values, same
  `powi`, same integer-band logic, enabled-only hygiene, reachable() over the subset). Replace lines 23-59:

```ts
const P_DA = 0.55, P_T0 = 0.70, P_CRIT = 0.15 // reuseN deferred (v1) — see spec §2.2
const CAP_CRIT = 5
const REACH_SCALE = 1_000_000, B_MED = 250_000, B_HIGH = 500_000, B_VHI = 750_000
const W_RISK = 45, W_STR = 35, W_COMP = 20

const powi = (base: number, n: number) => { let r = 1; for (let i = 0; i < n; i++) r *= base; return r }
const reachBand = (L: number) => {
  const ls = Math.floor(L * REACH_SCALE + 0.5)
  return ls >= B_VHI ? "Very High" : ls >= B_HIGH ? "High" : ls >= B_MED ? "Medium" : "Low"
}
const reachPct = (b: string) => b === "Very High" ? ">75%" : b === "High" ? "50-75%" : b === "Medium" ? "25-50%" : "<25%"
const reachable = (a: Account) =>
  !!a.enabled && (!!a.cracked || !!a.escalated_by_shared_da || !!a.escalated_by_mass_reuse)

export function posture(accts: Account[]): Posture {
  // hygiene over enabled only
  let active = 0, crit = 0, high = 0, med = 0, uncracked = 0, viol = 0
  // reachability over the full subset
  let da = 0, t0 = 0, critN = 0
  for (const a of accts) {
    if (reachable(a)) {
      if (hasDA(a.da_domains)) da++
      if (a.controls_tier0) t0++
    }
    if (a.risk_level === "Critical" && !hasDA(a.da_domains) && !a.controls_tier0) critN++
    if (!a.enabled) continue
    active++
    if (a.risk_level === "Critical") crit++; else if (a.risk_level === "High") high++; else if (a.risk_level === "Medium") med++
    if (!a.cracked) uncracked++
    if (a.cracked && !a.meets_policy) viol++
  }
  const cN = Math.min(critN, CAP_CRIT)
  const L = 1 - powi(1 - P_DA, da) * powi(1 - P_T0, t0) * powi(1 - P_CRIT, cN)
  const band = reachBand(L)
  if (!active) return { score: 0, rating: "No Data", breakdown: { risk: 0, strength: 0, privilege: 0, compliance: 0 },
    likelihood: band, reachability: band, reachability_score: L, reachability_pct: reachPct(band),
    overall: 0, verdict: t0 >= 1 ? "Critical" : "No Data", verdict_reason: t0 >= 1 ? "Tier-0 Reachable" : "" }
  const risk = Math.max(0, 100 - (crit / active) * 200 - (high / active) * 150 - (med / active) * 50) / 100 * W_RISK
  const strength = (uncracked / active) * W_STR
  const compliance = ((active - viol) / active) * W_COMP
  const score = r1(risk + strength + compliance)
  const rating: Rating = score >= 85 ? "Strong" : score >= 70 ? "Fair" : "Weak"
  const [verdict, verdict_reason] = gateVerdict(rating, band, t0, active)
  return { score, rating, breakdown: { risk: r1(risk), strength: r1(strength), privilege: 0, compliance: r1(compliance) },
    likelihood: band, reachability: band, reachability_score: L, reachability_pct: reachPct(band),
    overall: r1(score * (1 - L)), verdict, verdict_reason }
}
```
Add a `gateVerdict` TS helper identical to Go's, and extend the `Posture`/`Rating` interfaces (add
`"Sound"|"Guarded"|"Elevated"|"High Risk"|"Critical"|"No Data"` to a `Verdict` type; add the new fields).
NOTE: confirm `Account` (api.ts) carries `controls_tier0`, `escalated_by_shared_da`,
`escalated_by_mass_reuse`, `enabled`, `reuse_group` — they are in the redacted payload; if any is
missing from the type, add it (and verify the Go `Redacted()` keeps it).

- [ ] **Step 3: Typecheck** — `cd web && npx tsc --noEmit` → clean.

- [ ] **Step 4: Commit** — `feat(web): insights.ts mirror of Hygiene×Reachability + api types`.

---

### Task 8: Go⇄TS parity golden test

**Files:**
- Create: `internal/model/testdata/posture_golden.json` (input accounts + expected Posture)
- Modify: `internal/model/model_test.go` (golden test reads the fixture)
- Create: `web/src/insights.golden.test.ts` (reads the SAME fixture, asserts identical output)

- [ ] **Step 1: Write the fixture** — a handful of scenarios (clean estate; 1 reachable DA; 2 reachable
  DA; 1 DCSync; disabled-DA-only; all-disabled), each `{accounts:[...], expect:{score,rating,reachability,overall,verdict,verdict_reason}}`.

- [ ] **Step 2: Go golden test** — load fixture, run `PostureScore`, assert each `expect` (strings &
  rounded numbers). `go test ./internal/model/ -run TestPostureGolden` → PASS (this PINS the Go side).

- [ ] **Step 3: TS golden test** — `import fixture from "../../internal/model/testdata/posture_golden.json"`
  (or copy into `web/src/__fixtures__/`), build `Account[]` from each case, run `posture()`, assert the
  SAME `expect`. `cd web && npx vitest run insights.golden` → PASS. This guarantees byte-parity.

- [ ] **Step 4: Commit** — `test: Go⇄TS posture parity golden fixture`.

---

### Task 9: Dashboard executive card (frontend-design + Playwright)

**Files:**
- Modify: `web/src/components/Dashboard.tsx` (the executive summary card)

REQUIRED SUB-SKILL: invoke **frontend-design** for the card; verify live with **Playwright** MCP.

- [ ] **Step 1:** Replace the single "Posture / Strong 87.6" hero with the §2.5 card:
  - **Headline** = `verdict` (+ ` — ${verdict_reason}` when reason present), color by severity
    (Sound→good … Critical→alarm).
  - **Two component readouts**: Credential Hygiene (`score`/100 + `rating` + enabled-count footnote) and
    Breach Reachability (`reachability` band + `reachability_pct` + "modeled upper bound" tag).
  - **Overall** shown ONLY as a small labeled trend value ("Overall 4/100 — capped by reachable Tier-0
    path"), never a bare hero number.
  - **Relationship sentence** + **gate-reason line** (only when gated) + **priority-action line** in the
    dollar eye-line. **Breach impact** block labeled "modeled / illustrative".
  - **Dormant privileged** line when `summary.dormant_privileged > 0`.
  - Band shows the RANGE only — never a 2-decimal `reachability_score`.

- [ ] **Step 2: Gates** — `cd web && npx tsc --noEmit && npx vitest run && npm run build` (styleguard test
  must pass — use CSS tokens, no literal inline spacing).

- [ ] **Step 3: Live verify (Playwright MCP)** — build+restart per build-and-run; drive
  `http://127.0.0.1:8443`, lead-login, load the audit; assert the card reads **Critical — Tier-0
  Reachable** with Hygiene Strong + Reachability Very High both visible, the explanatory + action copy
  present, and **browser console has no 4xx/errors**; screenshot.

- [ ] **Step 4: Commit** — `feat(web): two-axis executive card with Tier-0 gate + modeled-estimate copy`.

---

### Task 10: Compare/trend two-axis + Help + final sweep

**Files:**
- Modify: `web/src/components/Compare.tsx`, `web/src/components/help/ChapterScoring.tsx`

- [ ] **Step 1: Compare** — lead with the two-axis delta ("Hygiene +6, Reachability unchanged — Tier-0
  path still open"); keep `overall` as a labeled secondary, not the headline diff. Update any
  posture-trend series to track Hygiene and Reachability separately.

- [ ] **Step 2: Help (ChapterScoring.tsx)** — add a section explaining the two axes, the Tier-0 gate
  ("one reachable path to domain-control caps the verdict regardless of hygiene"), and that Reachability
  is a modeled upper bound. Prose only (styleguard-safe).

- [ ] **Step 3: Gates** — `cd web && npx tsc --noEmit && npx vitest run && npm run build`; back in root
  `gofmt -l cmd internal`, `go build/vet/test ./...`, `govulncheck ./...`.

- [ ] **Step 4: Live re-verify** — re-export the sanitized report; confirm `verdict`/`reachability`/
  `overall`/`dormant_privileged` present and the 6,069-account audit reads **Critical — Tier-0 Reachable**,
  Hygiene ~Strong, impact $1M+/6–12mo. Console clean.

- [ ] **Step 5: Commit** — `feat(web): two-axis Compare/trend + Help section for the scoring rework`.

---

## After all tasks
Dispatch a final whole-branch code review (opus). Then superpowers:finishing-a-development-branch →
expect Option 1 (merge to main + push) + tag **v2.28.0** + GitHub release + README "What's new in 2.28".
Rebuild + restart the long-lived `patd.exe`.
