# Scoring Engine v2 — Sub-project B: Two-Axis (Exposure × Impact) Engine — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to execute this plan — dispatch a fresh implementer subagent per task, each doing strict TDD (failing test → run/verify red → minimal impl → run/verify green → commit), followed by a spec-then-quality review before the next task. Do not batch tasks; keep the tree green and shippable after every commit.

**Goal:** Replace the single blended 0–10 risk score with two independent axes — **Exposure** (always computed, from dump+HIBP+reuse) and **Impact** (BloodHound-derived, `Unknown` when not enriched) — plus a derived **Level** from a 2D matrix, an extended breakdown carrying every per-factor input the sub-project C leave-one-out radar needs, a real-count CVSS-like vector with `EXP:`/`IMP:` codes, and audit-level passes for shared-hash-to-DA Impact inheritance and a within-audit percentile rank. Scores **change on purpose**; all golden tests are updated to v2, not preserved at v1.

**Architecture:** The per-account vs audit-level split is the load-bearing rule. `risk.Score` is **per-account** and cannot see other accounts, so it computes Exposure (fully) and Impact **from per-account signals only** (Enabled, true controlled count, ControlsTier0, this account's own DA path, domain). It must NOT compute shared-hash-to-DA (cross-account). Cross-account signals run as **audit-level passes** in `internal/store/store.go` — alongside the existing `RecomputeSharing` / `EscalateSharedWithDA` — over the whole `[]model.Account` after every account is scored: (a) extend shared-DA escalation so an account sharing an NT hash with a DA-reachable/DA-equivalent account inherits **max Impact** and a recomputed Level; (b) `model.ComputePercentiles(accts)` assigns each account a within-audit percentile. Both are idempotent passes, modelled exactly on the existing two. Sub-project A already shipped the ingestion signals (true `env.Count`, `bloodhound.ExtractControlsTier0`, roastable flags, `Enrichment.Enriched`, `model.Account.Coverage`); B consumes them. **Known wiring gap closed here:** A added `bloodhound.ExtractControlsTier0` but did NOT surface it on `Enrichment` — B adds `Enrichment.ControlsTier0` and threads it into `risk.Context`.

**Tech Stack:** Go (stdlib-first; only external dep `golang.org/x/crypto`, unused here), CGO-free static binary, table-driven `testing`. Windows dev box; tests run via `go test ./...` from the repo root. Persist-vs-recompute: scores are **stored** on `model.Account` (computed at ingest/rescore, not on read); reloading an old v1 audit shows stale numbers only until the next rescore — acceptable per the design's score-continuity note (Compare/longitudinal shelved).

---

## File Structure

| File | Responsibility | Change in B |
|---|---|---|
| `internal/risk/risk.go` | The scoring engine | Add Exposure axis (`exposureScore`, `weaknessScore`, `hibpExposureFloor`, `crackedFloor`, bumps); add Impact axis (`impactScore` w/ Enabled gate, privilege from true count + ControlsTier0, DA component, domain modifier, `ImpactKnown`); 2D matrix `LevelFromAxes`; extend `Context`/`Analysis`/`Breakdown`/`Result`; extend `Vector` (real `CO:`, new `EXP:`/`IMP:`); remove dead v1 code (`floorBase`, `finalFloor`, `temporalScore`, `environmentalScore`, `baseScore`'s blended scale, `hibp.Factor` HIBP channel) |
| `internal/risk/risk_test.go` | Engine golden tests | **Rewrite** v1 golden values to v2; new Exposure/Impact/matrix/vector tables |
| `internal/engine/engine.go` | Audit orchestration | Add `Enrichment.ControlsTier0`; set it on live (`ExtractControlsTier0`) + bulk paths; build v2 `risk.Context` (Enabled, roastable, ControlsTier0, coverage) in `scoreCracked`; populate new `model.Account` axis fields in `scoreCracked` **and** `scoreUncracked` |
| `internal/engine/engine_test.go` | Pipeline tests | **Update** golden values to v2; new tests for ControlsTier0 wiring + axis-field population |
| `internal/model/model.go` | API data types | `Account` gains `ExposureScore`, `ImpactScore *float64`, `ImpactKnown`, `Percentile`; extend `ScoreBreakdown` with per-axis sub-scores + radar inputs; add `ComputePercentiles`; extend shared-DA escalation to Impact |
| `internal/model/model_test.go` | model tests | New tests for `ComputePercentiles` + extended `EscalateSharedWithDA` |
| `internal/store/store.go` | Audit persistence | Wire the new percentile pass + extended escalation into the three call-sites (~465, ~484, ~510) |
| `internal/store/store_test.go` | store tests | Multi-account audit test proving percentile + Impact inheritance run at audit level |

---

## Task ordering (each leaves the tree green and shippable)

1. **B1** — Exposure axis in `risk` (single HIBP channel; weakness reweight; floors; bumps; uncracked Exposure).
2. **B2** — Impact axis in `risk` (Enabled gate; privilege from true count + ControlsTier0; DA component; domain modifier; Unknown state).
3. **B3** — 2D matrix Level + Result/Breakdown extension + Vector extension + DA hard-override.
4. **B4** — engine wiring (`Enrichment.ControlsTier0`; v2 `risk.Context`; populate `model.Account` axis fields in both scorers; update engine goldens).
5. **B5** — audit-level passes (`model.ComputePercentiles` + Impact-inheriting shared-DA escalation; wire into store.go).
6. **B6** — rewrite `risk_test.go` v1 goldens to v2 + acceptance gate (remove orphaned v1 code; full build/vet/test/gofmt/govulncheck).

### Gates (run before EVERY commit — never `git commit --no-verify`)

```
gofmt -l cmd internal          # must print nothing
go build ./... && go vet ./... && go test ./...
govulncheck ./...              # must be clean
```

---

## Locked constants (every one pinned by a golden test below)

**Exposure (0–10):**
- weakness weights: `w_len=0.30`, `w_cx=0.20`, `w_dict=0.35`, `w_sim=0.15` (sum 1.0).
- `lengthPenalty` = existing sigmoid `1/(1+e^((len−10)/2))` (verbatim, [0,1]).
- `complexityPenalty` = `(complexityF − 0.2)/0.8`, clamped [0,1]; `complexityF∈[0.2,1.0]` → penalty `[0,1]`. NOTE: in `complexityFactors`, LOWER = stronger (`mixedalphaspecialnum=0.2` strongest, `numeric=1.0` weakest), so the weakest password (cf=1.0) maps to penalty 1.0 and the strongest (cf=0.2) to 0.0. (Corrected during B1 — the earlier `(1.0−cf)/0.8` was sign-inverted.)
- `dictPenalty` = existing additive dictionary term, clamped [0,1].
- `simPenalty` = `similarityFactor(simMax)/0.6` (max raw 0.6 → 1.0), clamped [0,1].
- `hibpExposureFloor(n)`: ≥1e6→9.0, ≥1e5→8.5, ≥1e4→8.0, ≥1e3→7.0, ≥100→6.0, ≥10→5.0, ≥1→4.5, else 0.
- `crackedFloor`: cracked && len<8 → 4.0; cracked → 3.0; else 0.
- `reuseBump`: +0.5 if SharedWith>0 (else 0).
- `roastableBump`: +0.5 if HasSPN || DontReqPreauth (else 0).
- Exposure(cracked) = `min(10, max(weaknessScore, hibpExposureFloor, crackedFloor) + reuseBump + roastableBump)`.
- Exposure(uncracked) = `min(10, hibpExposureFloor + reuseBump + roastableBump)`.

**Impact (0–10 or Unknown):**
- coverage=="none" (not enriched) → Impact **Unknown** (`ImpactKnown=false`); else a number.
- `privilegeSubScore` from true controlled count: >1000→9, >500→8, >100→7, >50→6, >10→5, >0→3, else 0; **ControlsTier0 → 10** (DA-equivalent override).
- `daComponent`: this account's own DA path → 10, else 0.
- `domainModifier`: Critical→+1.0, High→+0.6, Medium→+0.3, else 0.
- `enabledGate`: Enabled==false → cap Impact at 2.0.
- Impact = `enabledGate( min(10, max(privilegeSubScore, daComponent) + domainModifier) )`.

**Matrix tier cutoffs (per axis):** ≥8 Critical, ≥6 High, ≥4 Medium, else Low.

**Level matrix** (rows=Impact, cols=Exposure C/H/M/L) — from the spec table:
| Impact ↓ \ Exposure → | Critical | High | Medium | Low |
|---|---|---|---|---|
| Critical | Critical | Critical | Critical | High |
| High | Critical | High | High | Medium |
| Medium | High | High | Medium | Medium |
| Low | Medium | Medium | Low | Low |
- Impact Unknown → Level from Exposure tier alone, `Provisional=true`.
- Hard override: cracked + confirmed DA path (or DA-equivalent) → Critical.

**Back-compat `RiskScore`:** `ImpactKnown ? round1(0.5·Exposure + 0.5·Impact) : round1(Exposure)`. De-emphasized/legacy.

---

### Task B1 — Exposure axis in `risk`

**Why:** v1 triple-counts HIBP (`floorBase`+`finalFloor`+`hibpF`), nullifies complexity by multiplying it with length (`complexityF*lengthF`), and mis-scales the base (`*(10/4)`, true max 2.6). B1 replaces all of that with a single weighted-sum weakness score, a single HIBP channel, a single cracked floor, and small additive bumps — proving HIBP counts once and complexity is independent of length.

**Files:**
- Modify: `internal/risk/risk.go`
  - `Context` (lines 30–39): add `Enabled bool`, `HasSPN bool`, `DontReqPreauth bool`, `ControlsTier0 bool`, `Coverage string`, `Cracked bool`. (Existing fields stay; `DaysOutOfCompliance`/`PasswordExpires` become unused by scoring but are kept for the vector until B3 removes them — decide there.)
  - Add new funcs: `exposureScore`, `weaknessScore`, `lengthPenalty`, `complexityPenalty`, `dictPenalty`, `simPenalty`, `hibpExposureFloor`, `crackedFloor`. Reuse existing `complexityFactors`, `similarityFactor`, `round1`, `round2`, `math`.
- Test: `internal/risk/risk_test.go` (new `TestExposureWeakness`, `TestExposureHIBPCountedOnce`, `TestExposureComplexityIndependentOfLength`, `TestExposureUncracked`, `TestExposureBumps`).

#### Steps

- [ ] **Step 1: Write failing Exposure tests.** Append to `internal/risk/risk_test.go`:
  ```go
  func TestExposureComplexityIndependentOfLength(t *testing.T) {
  	// Two 16-char passwords, identical length, differing ONLY in complexity.
  	// In v1 the base multiplied complexityF*lengthF, so a long password collapsed
  	// complexity's contribution and these scored identically. In v2 complexity is an
  	// independent weighted term, so the mixed-special password must score strictly
  	// LOWER exposure than the all-lowercase one.
  	lower := Analysis{ComplexityLabel: "loweralpha", PasswordLength: 16}
  	mixed := Analysis{ComplexityLabel: "mixedalphaspecialnum", PasswordLength: 16}
  	c := Context{Cracked: true, Coverage: "none"}
  	eLow := exposureScore(lower, c)
  	eMixed := exposureScore(mixed, c)
  	if !(eLow > eMixed) {
  		t.Fatalf("complexity must matter independent of length: lower=%v mixed=%v", eLow, eMixed)
  	}
  }

  func TestExposureHIBPCountedOnce(t *testing.T) {
  	// A strong, long, unique password whose hash matches HIBP at exactly the 1e5
  	// tier. v1 multiplied/floored HIBP three times; v2 uses a single floor of 8.5.
  	// Exposure must equal exactly the floor (no weakness signal beats it, no bumps).
  	a := strong()
  	got := exposureScore(a, Context{Cracked: true, Coverage: "none", HIBPBreachCount: 100000})
  	if !almost(got, 8.5) {
  		t.Fatalf("HIBP 1e5 exposure = %v, want exactly 8.5 (single channel)", got)
  	}
  	// One breach hit floors at 4.5, not higher.
  	if got := exposureScore(a, Context{Cracked: true, Coverage: "none", HIBPBreachCount: 1}); !almost(got, 4.5) {
  		t.Fatalf("HIBP 1 exposure = %v, want 4.5", got)
  	}
  }

  func TestExposureWeakness(t *testing.T) {
  	// Worst-case weakness: shortest, least complex, every dict signal, max similarity.
  	// All four penalties saturate to 1.0 -> weaknessScore = 10*(0.30+0.20+0.35+0.15) = 10.0.
  	a := Analysis{ComplexityLabel: "numeric", PasswordLength: 1, IsCommon: true,
  		IsDictionaryWord: true, BannedWordsCount: 50, KeyboardPatternsCount: 50, SimilarMax: 1.0}
  	if got := weaknessScore(a); !almost(got, 10.0) {
  		t.Fatalf("saturated weakness = %v, want 10.0", got)
  	}
  	// A perfectly strong long password: lengthPenalty~0, complexityPenalty=0,
  	// dict=0, sim=0 -> weaknessScore ~ 0.
  	if got := weaknessScore(strong()); got > 0.1 {
  		t.Fatalf("strong weakness = %v, want ~0", got)
  	}
  }

  func TestExposureBumps(t *testing.T) {
  	a := strong()
  	base := exposureScore(a, Context{Cracked: true, Coverage: "none"}) // crackedFloor 3.0
  	if !almost(base, 3.0) {
  		t.Fatalf("strong cracked floor = %v, want 3.0", base)
  	}
  	reuse := exposureScore(a, Context{Cracked: true, Coverage: "none", SharedWith: 2})
  	if !almost(reuse, 3.5) {
  		t.Fatalf("reuse bump = %v, want 3.5", reuse)
  	}
  	roast := exposureScore(a, Context{Cracked: true, Coverage: "full", HasSPN: true})
  	if !almost(roast, 3.5) {
  		t.Fatalf("roastable bump = %v, want 3.5", roast)
  	}
  	short := exposureScore(Analysis{ComplexityLabel: "loweralpha", PasswordLength: 5},
  		Context{Cracked: true, Coverage: "none"})
  	if short < 4.0 {
  		t.Fatalf("short cracked floor = %v, want >= 4.0", short)
  	}
  }

  func TestExposureUncracked(t *testing.T) {
  	// Uncracked: no weakness signals (password unknown). Exposure from HIBP floor + bumps only.
  	c := Context{Cracked: false, Coverage: "none", HIBPBreachCount: 1000}
  	if got := exposureScore(Analysis{}, c); !almost(got, 7.0) {
  		t.Fatalf("uncracked HIBP 1e3 = %v, want 7.0", got)
  	}
  	// Uncracked, no HIBP, no bumps -> 0 exposure (unknown password, no signal).
  	if got := exposureScore(Analysis{}, Context{Cracked: false, Coverage: "none"}); !almost(got, 0.0) {
  		t.Fatalf("uncracked no-signal exposure = %v, want 0.0", got)
  	}
  	// Uncracked + reuse + roastable bump still applies.
  	c2 := Context{Cracked: false, Coverage: "full", SharedWith: 3, DontReqPreauth: true}
  	if got := exposureScore(Analysis{}, c2); !almost(got, 1.0) {
  		t.Fatalf("uncracked bumps-only exposure = %v, want 1.0", got)
  	}
  }
  ```

- [ ] **Step 2: Run the tests; verify RED (compile failure — funcs/fields don't exist).**
  ```
  go test ./internal/risk/ -run "TestExposure" -v
  ```
  Expected: build error (`undefined: exposureScore`, `weaknessScore`, unknown `Context` fields). That is the red state.

- [ ] **Step 3: Add the v2 `Context` fields and the Exposure functions.** In `internal/risk/risk.go`, replace the `Context` struct (lines 30–39) with:
  ```go
  // Context holds account/environment signals consumed by scoring. v2: Exposure is
  // always computed; Impact needs Enabled/ControlsTier0/Coverage and is Unknown when
  // coverage == "none". Cracked distinguishes the weakness-bearing path from uncracked.
  type Context struct {
  	Cracked           bool     // true = password known (weakness penalties apply)
  	SharedWith        int      // accounts sharing this password (>0 => reuse bump)
  	DADomains         []string // domains with a Domain Admin pathway (empty = none)
  	ControlledObjects *int     // TRUE controlled-object count (env.Count); nil = unknown
  	ControlsTier0     bool     // controls a Tier-0/DA-equivalent object (DCSync/DA group/AdminSDHolder/KRBTGT)
  	Enabled           bool     // false => Impact capped at 2.0 (can't authenticate)
  	HasSPN            bool     // Kerberoastable (Exposure roastable bump)
  	DontReqPreauth    bool     // AS-REP roastable (Exposure roastable bump)
  	Coverage          string   // "full" | "none"; "none" => Impact Unknown
  	DomainRiskLevel   string   // "Critical"|"High"|"Medium"|"Low"; else unknown
  	HIBPBreachCount   int
  	// Retained for the vector string only (no longer scored); see Vector().
  	DaysOutOfCompliance *int
  	PasswordExpires     string
  }
  ```
  Then add, after `similarityFactor` (after line 202):
  ```go
  // --- Exposure axis (v2): "how easily is this credential compromised?" ---

  // exposureWeights sum to 1.0; each penalty is an INDEPENDENT [0,1] term, so
  // complexity is no longer nullified by length (the v1 product bug).
  const (
  	wLen  = 0.30
  	wCx   = 0.20
  	wDict = 0.35
  	wSim  = 0.15
  )

  // lengthPenalty is the v1 logistic, kept verbatim (higher = shorter = worse), [0,1].
  func lengthPenalty(length int) float64 {
  	return 1.0 / (1.0 + math.Exp(float64(length-10)/2.0))
  }

  // complexityPenalty maps complexityF in [0.2,1.0] -> [0,1]. In complexityFactors
  // LOWER = stronger (0.2 strongest, 1.0 weakest), so the WEAKEST password gets the
  // max penalty 1.0 and the strongest gets 0.0.
  func complexityPenalty(label string) float64 {
  	cf := 1.0
  	if v, ok := complexityFactors[label]; ok {
  		cf = v
  	}
  	p := (cf - 0.2) / 0.8
  	return clamp01(p)
  }

  // dictPenalty is the v1 additive dictionary/common/banned/keyboard term, clamped [0,1].
  func dictPenalty(a Analysis) float64 {
  	var d float64
  	if a.IsCommon {
  		d += 0.7
  	}
  	if a.IsDictionaryWord {
  		d += 0.5
  	}
  	d += math.Min(0.8, 0.2*float64(a.BannedWordsCount))
  	d += math.Min(0.5, 0.1*float64(a.KeyboardPatternsCount))
  	return clamp01(d)
  }

  // simPenalty normalizes the v1 similarity term (raw max 0.6) to [0,1].
  func simPenalty(simMax float64) float64 {
  	return clamp01(similarityFactor(simMax) / 0.6)
  }

  // weaknessScore is the cracked-only weighted sum of bounded penalties, scaled x10.
  func weaknessScore(a Analysis) float64 {
  	return 10.0 * (wLen*lengthPenalty(a.PasswordLength) +
  		wCx*complexityPenalty(a.ComplexityLabel) +
  		wDict*dictPenalty(a) +
  		wSim*simPenalty(a.SimilarMax))
  }

  // hibpExposureFloor is the SINGLE HIBP channel (kills the v1 triple-count).
  func hibpExposureFloor(count int) float64 {
  	switch {
  	case count >= 1000000:
  		return 9.0
  	case count >= 100000:
  		return 8.5
  	case count >= 10000:
  		return 8.0
  	case count >= 1000:
  		return 7.0
  	case count >= 100:
  		return 6.0
  	case count >= 10:
  		return 5.0
  	case count >= 1:
  		return 4.5
  	default:
  		return 0
  	}
  }

  // crackedFloor: cracking is itself exposure, applied ONCE.
  func crackedFloor(a Analysis, cracked bool) float64 {
  	switch {
  	case cracked && a.PasswordLength < 8:
  		return 4.0
  	case cracked:
  		return 3.0
  	default:
  		return 0
  	}
  }

  // exposureScore is the per-account Exposure axis [0,10].
  func exposureScore(a Analysis, c Context) float64 {
  	var floor float64
  	if c.Cracked {
  		floor = math.Max(weaknessScore(a), math.Max(hibpExposureFloor(c.HIBPBreachCount), crackedFloor(a, true)))
  	} else {
  		// Uncracked: password unknown, no weakness signals.
  		floor = hibpExposureFloor(c.HIBPBreachCount)
  	}
  	var bump float64
  	if c.SharedWith > 0 {
  		bump += 0.5
  	}
  	if c.HasSPN || c.DontReqPreauth {
  		bump += 0.5
  	}
  	return math.Min(10.0, floor+bump)
  }

  func clamp01(x float64) float64 {
  	if x < 0 {
  		return 0
  	}
  	if x > 1 {
  		return 1
  	}
  	return x
  }
  ```
  > **Note on `dictPenalty` duplication:** it re-derives the same additive terms the v1 `baseScore` computed. `baseScore` is removed in B6, so this is the single home for the dictionary term after the rewrite — not redundant once v1 is gone. Keep it here.

- [ ] **Step 4: Run the Exposure tests; verify GREEN.**
  ```
  go test ./internal/risk/ -run "TestExposure" -v
  ```
  Expected: PASS. (The whole package will NOT build yet — `Score` still references removed fields once we touch it; we have not yet, so the package still compiles against v1. Confirm `go build ./internal/risk/` is green here.)
  ```
  go build ./internal/risk/ && go vet ./internal/risk/
  ```

- [ ] **Step 5: Gate + commit.**
  ```
  gofmt -l cmd internal
  go build ./... && go vet ./... && go test ./...
  govulncheck ./...
  ```
  Note: `go test ./...` still runs v1 `Score` golden tests (unchanged, still green) since `Score` is untouched in B1. Commit:
  ```
  git commit -am "feat(risk-v2): Exposure axis — single HIBP channel + independent weakness terms (#B1)"
  ```

---

### Task B2 — Impact axis in `risk`

**Why:** v1 had no Impact axis: privilege was a ≤1.5× multiplier on a floored base (password status moved the score more than blast radius — backwards), `Enabled` never reached scoring, the true controlled count was unreachable, and absent BloodHound silently collapsed to neutral (1.0) so "low blast radius" and "unknown blast radius" looked identical. B2 adds a real Impact axis on [0,10] with an explicit `Unknown` state.

**Files:**
- Modify: `internal/risk/risk.go` — add `impactScore`, `privilegeSubScore`, `daComponent`, `domainModifier`, `enabledGate`. (Uses `Context` fields added in B1.)
- Test: `internal/risk/risk_test.go` (new `TestImpactPrivilege`, `TestImpactDAandTier0`, `TestImpactDisabledGate`, `TestImpactUnknown`, `TestImpactDomainModifier`).

#### Steps

- [ ] **Step 1: Write failing Impact tests.** Append to `internal/risk/risk_test.go`:
  ```go
  func TestImpactPrivilege(t *testing.T) {
  	for _, tc := range []struct {
  		n    int
  		want float64
  	}{{0, 0}, {5, 3}, {11, 5}, {51, 6}, {101, 7}, {501, 8}, {1001, 9}} {
  		got, known := impactScore(Context{Coverage: "full", Enabled: true, ControlledObjects: ip(tc.n)})
  		if !known || !almost(got, tc.want) {
  			t.Errorf("controlled=%d -> impact %v (known=%v), want %v", tc.n, got, known, tc.want)
  		}
  	}
  }

  func TestImpactDAandTier0(t *testing.T) {
  	// Own DA path -> 10.
  	got, _ := impactScore(Context{Coverage: "full", Enabled: true, DADomains: []string{"CORP"}})
  	if !almost(got, 10.0) {
  		t.Fatalf("own DA path impact = %v, want 10", got)
  	}
  	// ControlsTier0 (DA-equivalent) -> privilege 10 even with a tiny controlled count.
  	got, _ = impactScore(Context{Coverage: "full", Enabled: true, ControlsTier0: true, ControlledObjects: ip(1)})
  	if !almost(got, 10.0) {
  		t.Fatalf("Tier-0 control impact = %v, want 10", got)
  	}
  }

  func TestImpactDisabledGate(t *testing.T) {
  	// A DA-pathed but DISABLED account cannot authenticate -> Impact capped at 2.0.
  	got, known := impactScore(Context{Coverage: "full", Enabled: false, DADomains: []string{"CORP"}})
  	if !known || !almost(got, 2.0) {
  		t.Fatalf("disabled DA impact = %v (known=%v), want 2.0", got, known)
  	}
  }

  func TestImpactUnknown(t *testing.T) {
  	// coverage "none" -> Impact Unknown (number is meaningless; known=false).
  	_, known := impactScore(Context{Coverage: "none", Enabled: true, ControlledObjects: ip(500)})
  	if known {
  		t.Fatalf("coverage none must yield Unknown impact (known=false)")
  	}
  }

  func TestImpactDomainModifier(t *testing.T) {
  	// privilege 5 (count 11..50) + Critical domain (+1.0) = 6.0.
  	got, _ := impactScore(Context{Coverage: "full", Enabled: true, ControlledObjects: ip(20), DomainRiskLevel: "Critical"})
  	if !almost(got, 6.0) {
  		t.Fatalf("priv5 + Critical domain = %v, want 6.0", got)
  	}
  	// DA path 10 + Critical modifier clamps at 10 (not 11).
  	got, _ = impactScore(Context{Coverage: "full", Enabled: true, DADomains: []string{"CORP"}, DomainRiskLevel: "Critical"})
  	if !almost(got, 10.0) {
  		t.Fatalf("DA + domain clamp = %v, want 10", got)
  	}
  }
  ```

- [ ] **Step 2: Run; verify RED.**
  ```
  go test ./internal/risk/ -run "TestImpact" -v
  ```
  Expected: build error (`undefined: impactScore`).

- [ ] **Step 3: Add the Impact functions.** In `internal/risk/risk.go`, after the Exposure block:
  ```go
  // --- Impact axis (v2): "blast radius if this credential is compromised?" ---

  // privilegeSubScore maps the TRUE controlled-objects count to [0,10]. Control of a
  // Tier-0/DA-equivalent object is the maximum regardless of count.
  func privilegeSubScore(controlled *int, controlsTier0 bool) float64 {
  	if controlsTier0 {
  		return 10
  	}
  	if controlled == nil {
  		return 0
  	}
  	switch oc := *controlled; {
  	case oc > 1000:
  		return 9
  	case oc > 500:
  		return 8
  	case oc > 100:
  		return 7
  	case oc > 50:
  		return 6
  	case oc > 10:
  		return 5
  	case oc > 0:
  		return 3
  	default:
  		return 0
  	}
  }

  // daComponent is 10 when THIS account has its own confirmed DA path, else 0.
  // (Shared-hash-to-DA inheritance is an audit-level pass, not here.)
  func daComponent(daDomains []string) float64 {
  	if len(daDomains) > 0 {
  		return 10
  	}
  	return 0
  }

  func domainModifier(level string) float64 {
  	switch level {
  	case "Critical":
  		return 1.0
  	case "High":
  		return 0.6
  	case "Medium":
  		return 0.3
  	default:
  		return 0
  	}
  }

  // impactScore returns the per-account Impact axis and whether it is known. When
  // coverage == "none" (not BloodHound-enriched) Impact is Unknown (known=false) and
  // the returned number is meaningless.
  func impactScore(c Context) (score float64, known bool) {
  	if c.Coverage == "none" {
  		return 0, false
  	}
  	priv := privilegeSubScore(c.ControlledObjects, c.ControlsTier0)
  	da := daComponent(c.DADomains)
  	imp := math.Min(10.0, math.Max(priv, da)+domainModifier(c.DomainRiskLevel))
  	if !c.Enabled {
  		imp = math.Min(imp, 2.0) // disabled can't authenticate
  	}
  	return imp, true
  }
  ```

- [ ] **Step 4: Run; verify GREEN.**
  ```
  go test ./internal/risk/ -run "TestImpact" -v
  go build ./internal/risk/ && go vet ./internal/risk/
  ```
  Expected: PASS (package still compiles; `Score` not yet rewired).

- [ ] **Step 5: Gate + commit.**
  ```
  gofmt -l cmd internal
  go build ./... && go vet ./... && go test ./...
  govulncheck ./...
  ```
  ```
  git commit -am "feat(risk-v2): Impact axis — Enabled gate, true-count privilege, Tier-0/DA max, Unknown state (#B2)"
  ```

---

### Task B3 — 2D matrix Level + Result/Breakdown + Vector + DA hard-override

**Why:** With both axes built, `Score` must combine them via the 2D matrix (not `max()`, not v1's blended scalar), emit Exposure/Impact/known/Level/Provisional, carry an extended Breakdown with every per-factor input the sub-project C leave-one-out radar needs, and extend the CVSS-like vector (`CO:` from the real count, new `EXP:`/`IMP:`, `IMP:U` for Unknown). The cracked+DA hard override is preserved.

**Files:**
- Modify: `internal/risk/risk.go`
  - Add `tierOf`, `LevelFromAxes`. Keep `ComputeLevel` (used by the uncracked engine path) until B4 decides; mark it legacy.
  - Rewrite `Result` (lines 58–65), `Breakdown` (lines 41–56), and `Score` (lines 67–102).
  - Extend `Vector` (lines 308–323): real `CO:` already from `controlledCode`; add `EXP:`/`IMP:` parts.
- Test: `internal/risk/risk_test.go` (new `TestLevelMatrix`, `TestScoreV2Result`, `TestScoreDAHardOverride`, `TestVectorV2`).

#### Steps

- [ ] **Step 1: Write failing tests.** Append to `internal/risk/risk_test.go`:
  ```go
  func TestLevelMatrix(t *testing.T) {
  	cases := []struct {
  		exp, imp float64
  		want     string
  	}{
  		{9, 9, "Critical"}, {6.5, 9, "Critical"}, {4.5, 9, "Critical"}, {2, 9, "High"}, // Impact Critical row
  		{9, 6.5, "Critical"}, {6.5, 6.5, "High"}, {4.5, 6.5, "High"}, {2, 6.5, "Medium"}, // Impact High row
  		{9, 4.5, "High"}, {6.5, 4.5, "High"}, {4.5, 4.5, "Medium"}, {2, 4.5, "Medium"}, // Impact Medium row
  		{9, 2, "Medium"}, {6.5, 2, "Medium"}, {4.5, 2, "Low"}, {2, 2, "Low"}, // Impact Low row
  	}
  	for _, c := range cases {
  		if got := LevelFromAxes(c.exp, c.imp, true, false); got != c.want {
  			t.Errorf("matrix(exp=%v,imp=%v) = %q, want %q", c.exp, c.imp, got, c.want)
  		}
  	}
  	// Unknown impact -> level from Exposure tier alone.
  	if got := LevelFromAxes(6.5, 0, false, false); got != "High" {
  		t.Errorf("unknown-impact level from exposure(6.5) = %q, want High", got)
  	}
  	if got := LevelFromAxes(2, 0, false, false); got != "Low" {
  		t.Errorf("unknown-impact level from exposure(2) = %q, want Low", got)
  	}
  	// Hard override: cracked + DA -> Critical even with low exposure/impact.
  	if got := LevelFromAxes(2, 2, true, true); got != "Critical" {
  		t.Errorf("DA hard override = %q, want Critical", got)
  	}
  }

  func TestScoreV2Result(t *testing.T) {
  	// Strong cracked, no enrichment: Exposure=crackedFloor 3.0 (Low), Impact Unknown,
  	// Level from Exposure alone (Low), Provisional=true, RiskScore=Exposure (legacy blend).
  	r := Score(strong(), Context{Cracked: true, Coverage: "none"})
  	if !almost(r.Exposure, 3.0) || r.ImpactKnown {
  		t.Fatalf("strong/none: exposure=%v impactKnown=%v, want 3.0/false", r.Exposure, r.ImpactKnown)
  	}
  	if r.Level != "Low" || !r.Provisional {
  		t.Fatalf("strong/none: level=%q provisional=%v, want Low/true", r.Level, r.Provisional)
  	}
  	if !almost(r.Score, 3.0) {
  		t.Fatalf("legacy blend (unknown impact) = %v, want exposure 3.0", r.Score)
  	}
  	// Enriched, privileged: exposure 3.0, impact 7 (count 101), known.
  	// RiskScore = round1(0.5*3.0 + 0.5*7.0) = 5.0.
  	r2 := Score(strong(), Context{Cracked: true, Coverage: "full", Enabled: true, ControlledObjects: ip(101)})
  	if !r2.ImpactKnown || !almost(r2.Impact, 7.0) || r2.Provisional {
  		t.Fatalf("enriched: impact=%v known=%v provisional=%v", r2.Impact, r2.ImpactKnown, r2.Provisional)
  	}
  	if !almost(r2.Score, 5.0) {
  		t.Fatalf("legacy blend = %v, want 5.0", r2.Score)
  	}
  	// Breakdown carries radar inputs (each factor's raw value).
  	if !almost(r2.Breakdown.LengthPenalty, lengthPenalty(20)) {
  		t.Fatalf("breakdown LengthPenalty = %v", r2.Breakdown.LengthPenalty)
  	}
  	if !almost(r2.Breakdown.PrivilegeSubScore, 7.0) {
  		t.Fatalf("breakdown PrivilegeSubScore = %v, want 7.0", r2.Breakdown.PrivilegeSubScore)
  	}
  }

  func TestScoreDAHardOverride(t *testing.T) {
  	// Cracked + own DA path: hard override -> Critical, HasDAPath true.
  	r := Score(strong(), Context{Cracked: true, Coverage: "full", Enabled: true, DADomains: []string{"CORP"}})
  	if !r.HasDAPath || r.Level != "Critical" {
  		t.Fatalf("cracked+DA: hasDA=%v level=%q, want true/Critical", r.HasDAPath, r.Level)
  	}
  }

  func TestVectorV2(t *testing.T) {
  	got := Vector(strong(), Context{Cracked: true, Coverage: "none", PasswordExpires: "Unknown"})
  	// EXP:M? strong cracked exposure=3.0 -> Low tier 'L'; IMP:U (unknown).
  	if want := "C:C1/L:VL/D:N/SM:N/CM:U/EX:U/DA:N/CO:U/S:0/DR:U/HIBP:N/EXP:L/IMP:U"; got != want {
  		t.Errorf("v2 strong vector = %q, want %q", got, want)
  	}
  	// Enriched privileged: CO from real count, IMP tier present.
  	got = Vector(strong(), Context{Cracked: true, Coverage: "full", Enabled: true, ControlledObjects: ip(101),
  		DomainRiskLevel: "Critical", PasswordExpires: "Unknown"})
  	if want := "C:C1/L:VL/D:N/SM:N/CM:U/EX:U/DA:N/CO:H/S:0/DR:C/HIBP:N/EXP:L/IMP:H"; got != want {
  		t.Errorf("v2 enriched vector = %q, want %q", got, want)
  	}
  }
  ```

- [ ] **Step 2: Run; verify RED.**
  ```
  go test ./internal/risk/ -run "TestLevelMatrix|TestScoreV2Result|TestScoreDAHardOverride|TestVectorV2" -v
  ```
  Expected: build errors (`undefined: LevelFromAxes`; `Result` has no `Exposure`/`Impact`/`ImpactKnown`/`Provisional`; `Breakdown` has no `LengthPenalty`/`PrivilegeSubScore`; vector lacks `EXP:`/`IMP:`).

- [ ] **Step 3: Add the matrix + tier helpers.** In `internal/risk/risk.go`, after `ComputeLevel` (line 146) add:
  ```go
  // tierOf maps an axis value [0,10] to its tier index: 0=Critical,1=High,2=Medium,3=Low.
  func tierOf(v float64) int {
  	switch {
  	case v >= 8.0:
  		return 0
  	case v >= 6.0:
  		return 1
  	case v >= 4.0:
  		return 2
  	default:
  		return 3
  	}
  }

  // levelMatrix[impactTier][exposureTier] -> Level. Rows = Impact, cols = Exposure,
  // each Critical(0)/High(1)/Medium(2)/Low(3). Mirrors the design spec table.
  var levelMatrix = [4][4]string{
  	{"Critical", "Critical", "Critical", "High"},   // Impact Critical
  	{"Critical", "High", "High", "Medium"},         // Impact High
  	{"High", "High", "Medium", "Medium"},           // Impact Medium
  	{"Medium", "Medium", "Low", "Low"},             // Impact Low
  }

  // LevelFromAxes derives the overall Level. When impactKnown is false the level is
  // taken from the Exposure tier alone (the caller flags it provisional). A cracked
  // account with a confirmed DA path (daOverride) is always Critical.
  func LevelFromAxes(exposure, impact float64, impactKnown, daOverride bool) string {
  	if daOverride {
  		return "Critical"
  	}
  	if !impactKnown {
  		switch tierOf(exposure) {
  		case 0:
  			return "Critical"
  		case 1:
  			return "High"
  		case 2:
  			return "Medium"
  		default:
  			return "Low"
  		}
  	}
  	return levelMatrix[tierOf(impact)][tierOf(exposure)]
  }
  ```

- [ ] **Step 4: Rewrite `Breakdown`, `Result`, and `Score`.** Replace `Breakdown` (lines 41–56), `Result` (58–65), and `Score` (67–102) with:
  ```go
  // Breakdown is the per-axis score detail plus every raw per-factor input the
  // sub-project C leave-one-out radar needs (Δ_k = Score(all) − Score(factor k neutralized)).
  type Breakdown struct {
  	// Exposure axis
  	ExposureScore     float64 `json:"exposure_score"`
  	WeaknessScore     float64 `json:"weakness_score"`
  	LengthPenalty     float64 `json:"length_penalty"`
  	ComplexityPenalty float64 `json:"complexity_penalty"`
  	DictPenalty       float64 `json:"dict_penalty"`
  	SimPenalty        float64 `json:"sim_penalty"`
  	HIBPFloor         float64 `json:"hibp_floor"`
  	CrackedFloor      float64 `json:"cracked_floor"`
  	ReuseBump         float64 `json:"reuse_bump"`
  	RoastableBump     float64 `json:"roastable_bump"`
  	// Impact axis
  	ImpactScore       float64 `json:"impact_score"`
  	PrivilegeSubScore float64 `json:"privilege_sub_score"`
  	DAComponent       float64 `json:"da_component"`
  	DomainModifier    float64 `json:"domain_modifier"`
  	EnabledGated      bool    `json:"enabled_gated"`
  }

  // Result is the full v2 scoring output for one account.
  type Result struct {
  	Exposure    float64 // 0-10, one decimal
  	Impact      float64 // 0-10, one decimal; meaningless when !ImpactKnown
  	ImpactKnown bool
  	Score       float64 // legacy back-compat blend (de-emphasized)
  	Level       string  // from the 2D matrix
  	Provisional bool    // true when ImpactKnown is false (level from Exposure alone)
  	Vector      string
  	HasDAPath   bool
  	Breakdown   Breakdown
  }

  // Score computes the full v2 risk result. Per-account only: it does NOT compute
  // shared-hash-to-DA (an audit-level pass in internal/store).
  func Score(a Analysis, c Context) Result {
  	exp := round1(exposureScore(a, c))
  	impRaw, known := impactScore(c)
  	imp := round1(impRaw)
  	hasDA := len(c.DADomains) > 0
  	daOverride := c.Cracked && hasDA
  	level := LevelFromAxes(exp, imp, known, daOverride)

  	var legacy float64
  	if known {
  		legacy = round1(0.5*exp + 0.5*imp)
  	} else {
  		legacy = exp
  	}

  	var reuse, roast float64
  	if c.SharedWith > 0 {
  		reuse = 0.5
  	}
  	if c.HasSPN || c.DontReqPreauth {
  		roast = 0.5
  	}

  	return Result{
  		Exposure:    exp,
  		Impact:      imp,
  		ImpactKnown: known,
  		Score:       legacy,
  		Level:       level,
  		Provisional: !known,
  		Vector:      Vector(a, c),
  		HasDAPath:   hasDA,
  		Breakdown: Breakdown{
  			ExposureScore:     exp,
  			WeaknessScore:     round2(weaknessScore(a)),
  			LengthPenalty:     round2(lengthPenalty(a.PasswordLength)),
  			ComplexityPenalty: round2(complexityPenalty(a.ComplexityLabel)),
  			DictPenalty:       round2(dictPenalty(a)),
  			SimPenalty:        round2(simPenalty(a.SimilarMax)),
  			HIBPFloor:         hibpExposureFloor(c.HIBPBreachCount),
  			CrackedFloor:      crackedFloor(a, c.Cracked),
  			ReuseBump:         reuse,
  			RoastableBump:     roast,
  			ImpactScore:       imp,
  			PrivilegeSubScore: privilegeSubScore(c.ControlledObjects, c.ControlsTier0),
  			DAComponent:       daComponent(c.DADomains),
  			DomainModifier:    domainModifier(c.DomainRiskLevel),
  			EnabledGated:      known && !c.Enabled,
  		},
  	}
  }
  ```

- [ ] **Step 5: Extend `Vector` with `EXP:`/`IMP:`.** In `Vector` (lines 308–323), append two parts before the closing `}` of the `parts` slice:
  ```go
  func Vector(a Analysis, c Context) string {
  	parts := []string{
  		"C:" + complexityCode(a.ComplexityLabel),
  		"L:" + lengthCode(a.PasswordLength),
  		"D:" + dictCode(a),
  		"SM:" + similarityCode(a.SimilarMax),
  		"CM:" + complianceCode(c.DaysOutOfCompliance),
  		"EX:" + expireCode(c.PasswordExpires),
  		"DA:" + daCode(c.DADomains),
  		"CO:" + controlledCode(c.ControlledObjects),
  		"S:" + shareCode(c.SharedWith),
  		"DR:" + domainCode(c.DomainRiskLevel),
  		"HIBP:" + hibpCode(c.HIBPBreachCount),
  		"EXP:" + axisCode(exposureScore(a, c)),
  		"IMP:" + impactCode(c),
  	}
  	return strings.Join(parts, "/")
  }

  // axisCode maps an axis value to its tier letter (C/H/M/L).
  func axisCode(v float64) string {
  	switch tierOf(v) {
  	case 0:
  		return "C"
  	case 1:
  		return "H"
  	case 2:
  		return "M"
  	default:
  		return "L"
  	}
  }

  // impactCode is the Impact tier letter, or "U" when Impact is Unknown.
  func impactCode(c Context) string {
  	v, known := impactScore(c)
  	if !known {
  		return "U"
  	}
  	return axisCode(v)
  }
  ```

- [ ] **Step 6: Run the B3 tests; verify GREEN.**
  ```
  go test ./internal/risk/ -run "TestLevelMatrix|TestScoreV2Result|TestScoreDAHardOverride|TestVectorV2" -v
  ```
  Expected: PASS. NOTE: the **old** v1 `Score`/`ComputeLevel`/`Vector` golden tests now FAIL to compile or fail assertions (Result fields renamed). That is expected — they are rewritten in B6. To keep this task's commit green, also do Step 7.

- [ ] **Step 7: Quarantine the v1 golden assertions that reference removed `Result` fields.** The tests `TestScoreFlooring`, `TestScoreDAPathAndRange`, `TestVector` reference `r.Breakdown.BaseScore` / old `Result` shape and the old vector string. Update ONLY the compile-breaking references minimally so the package builds, deferring the full golden refresh to B6 — OR, cleaner: do the full B6 rewrite of these three tests now if the implementer prefers (B6 then just runs the acceptance gate). Either is acceptable; the gate below must pass. (Recommended: rewrite them now per B6 Step 1–2 to avoid a knowingly-weakened intermediate commit.)

- [ ] **Step 8: Gate + commit.**
  ```
  gofmt -l cmd internal
  go build ./... && go vet ./... && go test ./...
  govulncheck ./...
  ```
  ```
  git commit -am "feat(risk-v2): 2D matrix Level + extended Result/Breakdown + EXP:/IMP: vector + DA hard-override (#B3)"
  ```

---

### Task B4 — engine wiring (`ControlsTier0`, v2 Context, model axis fields)

**Why:** A added `bloodhound.ExtractControlsTier0` but never surfaced it on `Enrichment`. B4 closes that gap, builds the v2 `risk.Context` from `Enrichment` (Enabled, roastable, ControlsTier0, coverage, cracked), and populates the new `model.Account` axis fields in BOTH `scoreCracked` and `scoreUncracked`. The uncracked path now also routes through `risk.Score` (v2 handles `Cracked:false` natively), replacing the ad-hoc `uncrackedScore`/`uncrackedVector`.

**Files:**
- Modify: `internal/model/model.go` — add `Account` fields (`ExposureScore`, `ImpactScore *float64`, `ImpactKnown`, `Percentile`) near line 159; extend `ScoreBreakdown` (lines 208–222) with the v2 fields.
- Modify: `internal/engine/engine.go`
  - `Enrichment` struct (lines 35–47): add `ControlsTier0 bool`.
  - `BloodhoundEnricher.Enrich` (lines 564–587): set `ControlsTier0: bloodhound.ExtractControlsTier0(ud)`.
  - `BulkBloodhoundEnricher.Enrich` (lines 597–626): set `ControlsTier0` from the bulk Tier-0 signal if available, else `false` (document the limitation).
  - `scoreCracked` (lines 249–373): build v2 `risk.Context`; populate axis fields + v2 `ScoreBreakdown`.
  - `scoreUncracked` (lines 379–410): route through `risk.Score` with `Cracked:false`; populate axis fields. Remove `uncrackedScore`/`uncrackedVector`/`uncrackedHIBPLevel` (lines 457–519) — they are superseded.
- Test: `internal/engine/engine_test.go` — update v1 goldens; add `TestControlsTier0Wired`, `TestAxisFieldsPopulated`.

#### Steps

- [ ] **Step 1: Add the model fields + breakdown extension (failing model test first).** Append to `internal/model/model_test.go`:
  ```go
  func TestAxisFieldsRedactionSafe(t *testing.T) {
  	imp := 7.0
  	a := Account{ExposureScore: 5.0, ImpactScore: &imp, ImpactKnown: true, Percentile: 0.9, Password: "secret"}
  	r := a.Redacted()
  	if r.Password != "" {
  		t.Fatal("password must be redacted")
  	}
  	if r.ExposureScore != 5.0 || r.ImpactScore == nil || *r.ImpactScore != 7.0 || !r.ImpactKnown || r.Percentile != 0.9 {
  		t.Fatalf("axis fields must survive Redacted(): %+v", r)
  	}
  }
  ```
  Run: `go test ./internal/model/ -run TestAxisFieldsRedactionSafe -v` → RED (fields don't exist).
  Then in `internal/model/model.go`, after the `Coverage` field (line 159) add:
  ```go
  	// v2 two-axis scoring. ExposureScore (always computed). ImpactScore is nil when
  	// Impact is Unknown (no BloodHound enrichment); ImpactKnown mirrors that. Percentile
  	// is the within-audit triage rank [0,1] assigned by ComputePercentiles. All are
  	// descriptive, not credentials — they survive Redacted().
  	ExposureScore float64  `json:"exposure_score"`
  	ImpactScore   *float64 `json:"impact_score"`
  	ImpactKnown   bool     `json:"impact_known"`
  	Percentile    float64  `json:"percentile,omitempty"`
  ```
  And extend `ScoreBreakdown` (after line 221, before the closing `}`):
  ```go
  	// v2 two-axis sub-scores + raw per-factor inputs for the leave-one-out radar.
  	ExposureScore     float64 `json:"exposure_score,omitempty"`
  	WeaknessScore     float64 `json:"weakness_score,omitempty"`
  	LengthPenalty     float64 `json:"length_penalty,omitempty"`
  	ComplexityPenalty float64 `json:"complexity_penalty,omitempty"`
  	DictPenalty       float64 `json:"dict_penalty,omitempty"`
  	SimPenalty        float64 `json:"sim_penalty,omitempty"`
  	HIBPFloor         float64 `json:"hibp_floor,omitempty"`
  	CrackedFloor      float64 `json:"cracked_floor,omitempty"`
  	ReuseBump         float64 `json:"reuse_bump,omitempty"`
  	RoastableBump     float64 `json:"roastable_bump,omitempty"`
  	ImpactScore       float64 `json:"impact_score,omitempty"`
  	PrivilegeSubScore float64 `json:"privilege_sub_score,omitempty"`
  	DAComponent       float64 `json:"da_component,omitempty"`
  	DomainModifier    float64 `json:"domain_modifier,omitempty"`
  	EnabledGated      bool    `json:"enabled_gated,omitempty"`
  ```
  > **Decision (justified):** keep the existing v1 `ScoreBreakdown` fields (`BaseScore`, `ComplexityFactor`, `TemporalScore`, `EnvironmentalScore`, etc.) **for one release** as zero-valued (`omitempty`) back-compat so any persisted v1 audit deserializes and the C frontend's old reads don't panic; the v2 fields are the live ones. They carry no data after B4 (engine stops setting them). A follow-up cleanup removes them once C migrates. This is the lowest-risk migration given persisted JSON.
  Run the model test → GREEN. Gate + commit:
  ```
  git commit -am "feat(model-v2): Account exposure/impact/percentile fields + ScoreBreakdown axis fields (#B4)"
  ```

- [ ] **Step 2: Add `Enrichment.ControlsTier0` + wire both enrichers (failing test first).** Append to `internal/engine/engine_test.go`:
  ```go
  func TestControlsTier0WiredLive(t *testing.T) {
  	// Live BloodhoundEnricher: a controllable named "DOMAIN ADMINS" (a Tier-0 group)
  	// must set Enrichment.ControlsTier0 = true via bloodhound.ExtractControlsTier0.
  	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  		q := r.URL.Query()
  		switch {
  		case r.URL.Path == "/api/v2/available-domains":
  			_, _ = io.WriteString(w, `{"data":[{"name":"CORP.INT","id":"D1","collected":true,"type":"Domain"}]}`)
  		case r.URL.Path == "/api/v2/search" && q.Get("type") == "User":
  			_, _ = io.WriteString(w, `{"data":[{"name":"svc@CORP.INT","objectid":"S-1-5-SVC"}]}`)
  		case r.URL.Path == "/api/v2/search" && q.Get("type") == "Group":
  			_, _ = io.WriteString(w, `{"data":[{"name":"DOMAIN ADMINS@CORP.INT","objectid":"S-1-5-DA"}]}`)
  		case len(r.URL.Path) > len("/controllables") && r.URL.Path[len(r.URL.Path)-len("/controllables"):] == "/controllables":
  			_, _ = io.WriteString(w, `{"count":1,"data":[{"name":"DOMAIN ADMINS@CORP.INT","label":"Group","objectid":"S-1-5-DA"}]}`)
  		case r.URL.Path == "/api/v2/users/S-1-5-SVC":
  			_, _ = io.WriteString(w, `{"data":{"props":{"enabled":true}}}`)
  		case r.URL.Path == "/api/v2/graphs/shortest-path":
  			w.WriteHeader(http.StatusNotFound)
  		default:
  			w.WriteHeader(http.StatusNotFound)
  		}
  	}))
  	defer srv.Close()
  	u, _ := url.Parse(srv.URL)
  	host, portStr, _ := net.SplitHostPort(u.Host)
  	port, _ := strconv.Atoi(portStr)
  	cl := bloodhound.New(bloodhound.Config{Scheme: "http", Host: host, Port: port, TokenID: "tid", TokenKey: "tkey"})
  	enr := BloodhoundEnricher{Client: cl}.Enrich("svc@CORP.INT")
  	if !enr.ControlsTier0 {
  		t.Fatal("ControlsTier0 not surfaced on live path")
  	}
  }
  ```
  > NOTE: the exact controllables JSON above must match whatever `ExtractControlsTier0` reads (`dc.Items[].Name`/`Label`). Confirm against `internal/bloodhound/bloodhound.go` `Controllables[].Items` parsing (added in A) and adjust the JSON keys (`name`/`label`) to the real envelope before running. If the live `/controllables` envelope differs, mirror the shape used by `TestBloodhoundEnricherSurfacesRoastable`.
  Run → RED (`enr.ControlsTier0` undefined). Then in `internal/engine/engine.go`:
  - Add to `Enrichment` (after `Enriched bool`, line 46): `ControlsTier0 bool // controls a Tier-0/DA-equivalent object (from bloodhound.ExtractControlsTier0)`.
  - In `BloodhoundEnricher.Enrich`, set on the returned `Enrichment`: `ControlsTier0: bloodhound.ExtractControlsTier0(ud),`.
  - In `BulkBloodhoundEnricher.Enrich`, set `ControlsTier0: b.Bulk.ControlsTier0(username),` IF the bulk API exposes it; otherwise set `ControlsTier0: false` with a comment:
    ```go
    // BulkBloodhoundEnricher: the 3-query bulk Cypher prefetch does not currently
    // collect Tier-0 control edges, so ControlsTier0 is conservatively false here.
    // The live BloodhoundEnricher path sets it; bulk under-reports Tier-0 by design
    // until the bulk Cypher is extended (tracked separately). False (not true) keeps
    // it conservative: a missed Tier-0 lowers Impact, never falsely inflates it.
    ControlsTier0: false,
    ```
  Run the test → GREEN. Gate + commit:
  ```
  git commit -am "feat(engine-v2): surface ControlsTier0 on Enrichment (live ExtractControlsTier0; bulk=false) (#B4)"
  ```

- [ ] **Step 3: Rewrite `scoreCracked` to build the v2 Context + populate axis fields.** Replace the `rctx`/`ran`/`res` block (lines 293–311) and the returned `model.Account` score fields (lines 329–371). New `rctx`:
  ```go
  	rctx := risk.Context{
  		Cracked:             true,
  		SharedWith:          sharedWith,
  		DADomains:           enrData.DADomains,
  		ControlledObjects:   enrData.ControlledObjects,
  		ControlsTier0:       enrData.ControlsTier0,
  		Enabled:             enabledOrUnknown(enrData.Enabled),
  		HasSPN:              boolOrFalse(enrData.HasSPN),
  		DontReqPreauth:      boolOrFalse(enrData.DontReqPreauth),
  		Coverage:            coverageState(enrData.Enriched),
  		DomainRiskLevel:     pol.DomainRiskLevel,
  		HIBPBreachCount:     count,
  		DaysOutOfCompliance: daysOOC,
  		PasswordExpires:     passwordExpires(enrData.PwdNeverExpires),
  	}
  ```
  (`ran` unchanged.) After `res := risk.Score(ran, rctx)`, compute the impact pointer:
  ```go
  	var impactPtr *float64
  	if res.ImpactKnown {
  		v := res.Impact
  		impactPtr = &v
  	}
  ```
  In the returned `model.Account`, set:
  ```go
  		RiskLevel:     res.Level,
  		RiskScore:     res.Score,
  		RiskVector:    res.Vector,
  		ExposureScore: res.Exposure,
  		ImpactScore:   impactPtr,
  		ImpactKnown:   res.ImpactKnown,
  ```
  and replace the `ScoreBreakdown` literal with the v2 fields:
  ```go
  		ScoreBreakdown: &model.ScoreBreakdown{
  			ExposureScore:     res.Breakdown.ExposureScore,
  			WeaknessScore:     res.Breakdown.WeaknessScore,
  			LengthPenalty:     res.Breakdown.LengthPenalty,
  			ComplexityPenalty: res.Breakdown.ComplexityPenalty,
  			DictPenalty:       res.Breakdown.DictPenalty,
  			SimPenalty:        res.Breakdown.SimPenalty,
  			HIBPFloor:         res.Breakdown.HIBPFloor,
  			CrackedFloor:      res.Breakdown.CrackedFloor,
  			ReuseBump:         res.Breakdown.ReuseBump,
  			RoastableBump:     res.Breakdown.RoastableBump,
  			ImpactScore:       res.Breakdown.ImpactScore,
  			PrivilegeSubScore: res.Breakdown.PrivilegeSubScore,
  			DAComponent:       res.Breakdown.DAComponent,
  			DomainModifier:    res.Breakdown.DomainModifier,
  			EnabledGated:      res.Breakdown.EnabledGated,
  		},
  ```
  Add the helper at the bottom of engine.go (near `derefInt`):
  ```go
  func boolOrFalse(p *bool) bool { return p != nil && *p }
  ```

- [ ] **Step 4: Rewrite `scoreUncracked` to use `risk.Score`.** Replace the body (lines 380–409) so it builds a `risk.Context{Cracked:false, ...}`, calls `risk.Score`, and populates the same axis fields:
  ```go
  func (e *Engine) scoreUncracked(domain string, a secretsdump.ParsedAccount, sharedWith int, now time.Time, enr Enricher) model.Account {
  	count := e.hibpCount(a.Hash)
  	enrData := enrichVia(enr, a.Username, domain)
  	pol := e.Policies.For(domain)
  	rctx := risk.Context{
  		Cracked:           false,
  		SharedWith:        sharedWith,
  		DADomains:         enrData.DADomains,
  		ControlledObjects: enrData.ControlledObjects,
  		ControlsTier0:     enrData.ControlsTier0,
  		Enabled:           enabledOrUnknown(enrData.Enabled),
  		HasSPN:            boolOrFalse(enrData.HasSPN),
  		DontReqPreauth:    boolOrFalse(enrData.DontReqPreauth),
  		Coverage:          coverageState(enrData.Enriched),
  		DomainRiskLevel:   pol.DomainRiskLevel,
  		HIBPBreachCount:   count,
  	}
  	res := risk.Score(risk.Analysis{}, rctx)
  	var impactPtr *float64
  	if res.ImpactKnown {
  		v := res.Impact
  		impactPtr = &v
  	}
  	var pwdLastSet int64
  	if enrData.PwdLastSet != nil {
  		pwdLastSet = *enrData.PwdLastSet
  	}
  	return model.Account{
  		Username:        a.Username,
  		Domain:          domain,
  		NTHash:          strings.ToUpper(a.Hash),
  		Cracked:         false,
  		RiskLevel:       res.Level,
  		RiskScore:       res.Score,
  		RiskVector:      res.Vector,
  		ExposureScore:   res.Exposure,
  		ImpactScore:     impactPtr,
  		ImpactKnown:     res.ImpactKnown,
  		HIBPBreached:    count > 0,
  		HIBPBreachCount: count,
  		DADomains:       joinDA(enrData.DADomains),
  		Controlled:      derefInt(enrData.ControlledObjects),
  		SharedWith:      sharedWith,
  		Enabled:         enabledOrUnknown(enrData.Enabled),
  		Coverage:        coverageState(enrData.Enriched),
  		PwdLastSet:      pwdLastSet,
  		PwdNeverExpires: enrData.PwdNeverExpires,
  		HasSPN:          enrData.HasSPN,
  		DontReqPreauth:  enrData.DontReqPreauth,
  	}
  }
  ```
  Delete `uncrackedScore` (457–477), `uncrackedVector` (479–500), `uncrackedHIBPLevel` (502–519). Remove the now-unused `"math"` and `hibp` imports IF nothing else in engine.go uses them (grep first — `hibp` is used elsewhere? confirm; if `uncrackedScore` was the only `hibp.Factor` user, drop the import). Remove `"fmt"` if `uncrackedVector` was its only user (grep).

- [ ] **Step 5: Update engine golden tests to v2 (document the shift).** In `internal/engine/engine_test.go`:
  - `TestProcessDomainCrackedBasics` (lines 69–76): "Welcome1" is common → v2 weakness is high but no longer floored to 7.0 by HIBP triple-count; with no HIBP and no enrichment, Exposure = max(weaknessScore("welcome1"), crackedFloor) and Impact is Unknown so Level comes from Exposure alone. **Recompute** the expected Level by hand from the v2 formula and assert the new value (likely still High via weakness, but assert Exposure/ImpactKnown explicitly rather than the old `RiskScore>=6.0`). Replace lines 69–76 with assertions on `alice.ExposureScore`, `alice.ImpactKnown == false`, and `alice.RiskLevel`. Document: "v2: HIBP no longer triple-counted; common-pw exposure now from weaknessScore."
  - `TestProcessDomainHIBPAndDAPath` (lines 97–108): DA pathway + cracked → still Critical (hard override preserved). Keep the Critical assertion; add `if !a.ImpactKnown` check (enriched) and `a.ExposureScore > 0`.
  - `TestProcessDomainUncracked` (lines 124–131): **recompute** — v2 uncracked with HIBP 5000 → Exposure = hibpExposureFloor(5000) = 8.0, Impact Unknown (no enrichment), Level from Exposure tier (Critical). Replace `RiskScore == 6.5` with `a.ExposureScore == 8.0`, `a.ImpactKnown == false`, `a.RiskLevel == "Critical"`; and the vector assertion with the new `UNCRACKED`-free vector ending `…/EXP:C/IMP:U` (the uncracked path now uses the standard `risk.Vector`). Document the shift in a comment.
  Add the new wiring test:
  ```go
  func TestAxisFieldsPopulated(t *testing.T) {
  	e := newEngine()
  	e.Enricher = fakeEnricher{
  		"alice@CORP": {Enriched: true, Enabled: bp(true), ControlledObjects: ipv(200)},
  	}
  	a := e.ProcessDomain("CORP", []secretsdump.ParsedAccount{
  		{Username: "alice", Domain: "CORP", Hash: "H1", Password: "Str0ng&Unique!Pass", Cracked: true},
  	}, nil)[0]
  	if a.ExposureScore <= 0 {
  		t.Fatalf("exposure not populated: %v", a.ExposureScore)
  	}
  	if !a.ImpactKnown || a.ImpactScore == nil {
  		t.Fatalf("enriched account must have known impact: known=%v ptr=%v", a.ImpactKnown, a.ImpactScore)
  	}
  	if *a.ImpactScore != 7.0 { // controlled 200 -> privilege 7
  		t.Fatalf("impact = %v, want 7.0", *a.ImpactScore)
  	}
  	if a.ScoreBreakdown == nil || a.ScoreBreakdown.PrivilegeSubScore != 7.0 {
  		t.Fatalf("breakdown PrivilegeSubScore wrong: %+v", a.ScoreBreakdown)
  	}
  }
  ```
  Also update `TestRescoreWithExplicitEnricher` if it asserts any v1 score (it asserts only DADomains — should still pass).

- [ ] **Step 6: Run; verify GREEN.**
  ```
  go test ./internal/engine/ ./internal/model/ -v
  ```
  Expected: PASS.

- [ ] **Step 7: Gate + commit.**
  ```
  gofmt -l cmd internal
  go build ./... && go vet ./... && go test ./...
  govulncheck ./...
  ```
  ```
  git commit -am "feat(engine-v2): build v2 risk.Context, route uncracked via risk.Score, populate axis fields (#B4)"
  ```

---

### Task B5 — audit-level passes (percentile + shared-DA Impact inheritance)

**Why:** Shared-hash-to-DA and within-audit triage rank are **cross-account** signals `risk.Score` cannot see. They must run after every account is scored, over the whole `[]model.Account`, as idempotent passes mirroring `RecomputeSharing`/`EscalateSharedWithDA`. (a) extend the shared-DA escalation so an account sharing an NT hash with a DA-reachable/DA-equivalent account inherits **max Impact** and a recomputed Level; (b) `ComputePercentiles` assigns each account a within-audit percentile rank.

**Files:**
- Modify: `internal/model/model.go` — extend `EscalateSharedWithDA` (lines 286–315) to also set Impact; add `ComputePercentiles`.
- Modify: `internal/store/store.go` — add the two new passes at the three call-sites (after lines 466, 485, 511).
- Test: `internal/model/model_test.go` (new `TestComputePercentiles`, `TestEscalateSharedWithDAImpact`); `internal/store/store_test.go` (multi-account audit pass-through).

#### Steps

- [ ] **Step 1: Write failing model tests.** Append to `internal/model/model_test.go`:
  ```go
  func TestEscalateSharedWithDAImpact(t *testing.T) {
  	imp9 := 9.0
  	accts := []Account{
  		{Username: "da", NTHash: "AAA", DADomains: "CORP.INT", RiskLevel: "Critical",
  			ImpactScore: &imp9, ImpactKnown: true, ExposureScore: 6.0},
  		{Username: "helpdesk", NTHash: "AAA", DADomains: "None", RiskLevel: "Low",
  			ImpactScore: nil, ImpactKnown: false, ExposureScore: 7.0}, // shares DA hash, unenriched
  	}
  	EscalateSharedWithDA(accts)
  	hd := accts[1]
  	if hd.RiskLevel != "Critical" {
  		t.Fatalf("shared-DA helpdesk level = %q, want Critical", hd.RiskLevel)
  	}
  	if !hd.ImpactKnown || hd.ImpactScore == nil || *hd.ImpactScore != 10.0 {
  		t.Fatalf("shared-DA helpdesk must inherit max Impact 10: known=%v ptr=%v", hd.ImpactKnown, hd.ImpactScore)
  	}
  	if !hd.EscalatedBySharedDA {
  		t.Fatal("EscalatedBySharedDA flag not set")
  	}
  }

  func TestComputePercentiles(t *testing.T) {
  	mk := func(score float64) Account { return Account{RiskScore: score} }
  	accts := []Account{mk(2), mk(5), mk(8), mk(8)} // ties share rank
  	ComputePercentiles(accts)
  	// Lowest score -> lowest percentile; highest -> ~1.0. Strictly ordered, [0,1].
  	for i := range accts {
  		if accts[i].Percentile < 0 || accts[i].Percentile > 1 {
  			t.Fatalf("percentile out of range: %v", accts[i].Percentile)
  		}
  	}
  	if !(accts[0].Percentile < accts[1].Percentile && accts[1].Percentile < accts[2].Percentile) {
  		t.Fatalf("percentiles must be monotonic with score: %v", []float64{
  			accts[0].Percentile, accts[1].Percentile, accts[2].Percentile})
  	}
  	if accts[2].Percentile != accts[3].Percentile {
  		t.Fatalf("ties must share a percentile: %v vs %v", accts[2].Percentile, accts[3].Percentile)
  	}
  	// Idempotent: running twice yields identical results.
  	first := accts[2].Percentile
  	ComputePercentiles(accts)
  	if accts[2].Percentile != first {
  		t.Fatal("ComputePercentiles must be idempotent")
  	}
  }
  ```
  Run: `go test ./internal/model/ -run "TestEscalateSharedWithDAImpact|TestComputePercentiles" -v` → RED.

- [ ] **Step 2: Extend `EscalateSharedWithDA` + add `ComputePercentiles`.** In `internal/model/model.go`, inside the escalation loop of `EscalateSharedWithDA` (after `a.EscalatedBySharedDA = true`, line 313) add Impact inheritance + Level recompute:
  ```go
  		// v2: inherit MAX Impact — cracking a hash shared with a DA-reachable account
  		// IS a DA compromise. Force Impact known + 10, then keep Level Critical (already
  		// set above; the matrix at Impact=10 over any Exposure is at least High, and the
  		// shared-DA signal is the flagship lateral-movement escalation -> Critical).
  		max := 10.0
  		a.ImpactScore = &max
  		a.ImpactKnown = true
  ```
  Then append the new pass after `EscalateSharedWithDA`:
  ```go
  // ComputePercentiles assigns each account a within-audit triage percentile in [0,1]
  // from its RiskScore (ties share a rank), so a large block of same-Level accounts
  // still yields a strict order. A SORT KEY, not a displayed score. Idempotent: it
  // depends only on RiskScore, never on a prior Percentile. Empty/one-account sets get 0.
  func ComputePercentiles(accts []Account) {
  	n := len(accts)
  	if n == 0 {
  		return
  	}
  	// rank = count of accounts with a strictly lower RiskScore (ties share it).
  	for i := range accts {
  		lower := 0
  		for j := range accts {
  			if accts[j].RiskScore < accts[i].RiskScore {
  				lower++
  			}
  		}
  		if n <= 1 {
  			accts[i].Percentile = 0
  		} else {
  			accts[i].Percentile = float64(lower) / float64(n-1)
  		}
  	}
  }
  ```
  > **Decision:** percentile is ranked on the legacy blended `RiskScore` (defined for every account, cracked or not, Unknown-impact or not), so it gives one total order across the whole audit. The default worklist sort (Level → Impact desc → Exposure desc, with Unknown-impact segregated) is a frontend/query concern for sub-project C; B only guarantees the monotone percentile sort key.
  >
  > **Performance (use sort, not the O(n²) shown above):** the nested-loop version above is the clearest spec of the semantics, but this tool audits real AD where an audit can be tens of thousands of accounts, so the implementer MUST use an O(n log n) sort-based implementation that preserves identical semantics — ties share a percentile, monotonic in `RiskScore`, idempotent, `[0,1]`. E.g. collect `(score, index)`, `sort.SliceStable` by score, then walk assigning `rank = number of accounts with a strictly lower score` (advance the rank past each run of equal scores so ties share it), `Percentile = rank/(n-1)` (0 when `n<=1`). The `TestComputePercentiles` assertions (ties equal, monotonic, idempotent, in-range) are the contract; verify the sort-based version passes them unchanged.
  Run → GREEN.

- [ ] **Step 3: Wire into store.go (failing store test first).** Append to `internal/store/store_test.go` a test that calls `Replace` (or `Mutate`) with a two-account audit sharing a DA hash and one low-score account, then asserts the loaded accounts have `Percentile` set and the shared account inherited Impact 10. (Mirror the existing store test harness — reuse its `newTestStore`/unlock setup.) Run → RED (passes not wired).
  Then in `internal/store/store.go` add both passes next to each existing pair:
  - after line 466 (`ReplaceDomain`): 
    ```go
    	model.RecomputeSharing(merged)
    	model.EscalateSharedWithDA(merged)
    	model.ComputePercentiles(merged)
    ```
  - after line 485 (`Replace`):
    ```go
    	model.RecomputeSharing(ds.Accounts)
    	model.EscalateSharedWithDA(ds.Accounts)
    	model.ComputePercentiles(ds.Accounts)
    ```
  - after line 511 (`Mutate`):
    ```go
    	model.RecomputeSharing(next)
    	model.EscalateSharedWithDA(next)
    	model.ComputePercentiles(next)
    ```
  > Order matters: `EscalateSharedWithDA` rewrites `RiskScore` (to ≥9.0) for escalated accounts, so `ComputePercentiles` (which ranks on `RiskScore`) must run AFTER it to rank on the post-escalation scores. Run → GREEN.

- [ ] **Step 4: Gate + commit.**
  ```
  gofmt -l cmd internal
  go build ./... && go vet ./... && go test ./...
  govulncheck ./...
  ```
  ```
  git commit -am "feat(store-v2): audit-level shared-DA Impact inheritance + ComputePercentiles passes (#B5)"
  ```

---

### Task B6 — rewrite v1 risk goldens to v2 + acceptance gate

**Why:** `risk_test.go`'s v1 golden tests (`TestComputeLevel`, `TestBaseScore`, `TestTemporalScore`, `TestEnvironmentalScore`, `TestScoreFlooring`, `TestScoreDAPathAndRange`, `TestVector`) pin v1 numbers and removed functions. B6 rewrites them to v2 (with justification comments) and removes all orphaned v1 code so nothing dead is left.

**Files:**
- Modify: `internal/risk/risk_test.go` — delete/rewrite v1 golden tests.
- Modify: `internal/risk/risk.go` — remove orphaned v1 code: `floorBase` (211–232), `finalFloor` (108–129), `temporalScore` (234–250), `environmentalScore` (252–291), `domainFactor` (293–304), `baseScore` (167–189), and the `hibp` import (now unused: `hibp.Factor` is gone from risk). Keep `complexityFactors`, `similarityFactor`, all `*Code` vector helpers, `controlledCode`, `round1/2`. Decide `ComputeLevel`: it is no longer called by the engine (B4 routed uncracked through `risk.Score`); remove it unless a test needs it, OR keep it as a documented legacy export. **Recommendation:** remove `ComputeLevel` and its test; `LevelFromAxes` is the v2 mapping.

#### Steps

- [ ] **Step 1: Delete the v1-only golden tests.** Remove from `internal/risk/risk_test.go`: `TestComputeLevel` (14–30), `TestBaseScore` (32–57), `TestTemporalScore` (71–89), `TestEnvironmentalScore` (91–130), `TestScoreFlooring` (132–151), and the old `TestVector` (171–184). Keep `TestSimilarityTiers` (still valid — `similarityFactor` stays) and `TestShareCode` (still valid — `shareCode` stays). Replace `TestScoreDAPathAndRange` (153–169) with a v2 range/override test:
  ```go
  func TestScoreV2Range(t *testing.T) {
  	r := Score(
  		Analysis{ComplexityLabel: "numeric", PasswordLength: 4, IsCommon: true, IsDictionaryWord: true,
  			BannedWordsCount: 1, KeyboardPatternsCount: 1, SimilarMax: 0.95},
  		Context{Cracked: true, Coverage: "full", Enabled: true, SharedWith: 1000,
  			DADomains: []string{"A"}, ControlledObjects: ip(2000), DomainRiskLevel: "Critical",
  			HIBPBreachCount: 200000},
  	)
  	if r.Exposure < 0 || r.Exposure > 10 || r.Impact < 0 || r.Impact > 10 || r.Score < 0 || r.Score > 10 {
  		t.Fatalf("axes out of range: %+v", r)
  	}
  	if r.Level != "Critical" { // cracked + DA hard override
  		t.Fatalf("level = %q, want Critical", r.Level)
  	}
  }
  ```

- [ ] **Step 2: Remove the orphaned v1 functions.** Delete `finalFloor`, `floorBase`, `temporalScore`, `environmentalScore`, `domainFactor`, `baseScore`, `ComputeLevel` (and its test, already deleted), and the `hibp` import line. Verify nothing else references them:
  ```
  go build ./internal/risk/
  ```
  Fix any remaining reference (e.g. if `Vector` or a `*Code` helper used `domainFactor` — it does not; `domainCode` is separate). Confirm `math`/`strconv`/`strings` imports are still all used.

- [ ] **Step 3: Run the full risk package; verify GREEN.**
  ```
  go test ./internal/risk/ -v
  ```
  Expected: PASS, no `undefined`/`declared and not used`.

- [ ] **Step 4: Verify no orphaned v1 code remains anywhere.** Grep the tree for dead references:
  ```
  go vet ./...
  ```
  And confirm `floorBase`, `finalFloor`, `temporalScore`, `environmentalScore`, `uncrackedScore`, `uncrackedVector`, `uncrackedHIBPLevel` appear in NO non-test `.go` file (use the Grep tool). Any survivor is dead code → remove.

- [ ] **Step 5: Full acceptance gate.**
  ```
  gofmt -l cmd internal
  go build ./... && go vet ./... && go test ./...
  govulncheck ./...
  ```
  All must pass / print nothing. Then commit:
  ```
  git commit -am "refactor(risk-v2): remove orphaned v1 scoring code; rewrite goldens to v2 (#B6)"
  ```

- [ ] **Step 6 (optional, recommended): live smoke.** Per the `build-and-run` skill, rebuild the embed binary, restart `patd.exe`, load the sample audit, and confirm `/healthz` is green and the accounts API returns `exposure_score`/`impact_score`/`impact_known`/`percentile`. (UI rendering of these is sub-project C; here just confirm the JSON shape and no panic.)

---

## Self-Review — spec requirement → task map

| Spec requirement | Where satisfied |
|---|---|
| **Exposure axis** (weighted-sum weakness, ×10, not a product) | B1 (`weaknessScore`, weights 0.30/0.20/0.35/0.15) |
| **HIBP single channel** (kills triple-count) | B1 (`hibpExposureFloor`; `TestExposureHIBPCountedOnce`); B6 removes `floorBase`/`finalFloor`/`hibp.Factor` |
| **Complexity independent of length** | B1 (`complexityPenalty` separate term; `TestExposureComplexityIndependentOfLength`) |
| **Cracked floor (once), reuse bump, roastable bump** | B1 (`crackedFloor`, reuse/roastable bumps; `TestExposureBumps`) |
| **Uncracked Exposure** (HIBP+bumps, no weakness) | B1 (`exposureScore` `Cracked:false` branch; `TestExposureUncracked`) |
| **Impact axis** (privilege from true count, [0,10]) | B2 (`privilegeSubScore`; `TestImpactPrivilege`) |
| **ControlsTier0 → DA-equivalent (10)** | B2 (`privilegeSubScore` Tier-0 override; `TestImpactDAandTier0`) + B4 wiring |
| **Own DA path → Impact 10** | B2 (`daComponent`; `TestImpactDAandTier0`) |
| **Domain modifier (+1.0/+0.6/+0.3)** | B2 (`domainModifier`; `TestImpactDomainModifier`) |
| **Enabled gate (disabled ≤2)** | B2 (`impactScore` gate; `TestImpactDisabledGate`) |
| **Coverage/Unknown** (none → Impact Unknown) | B2 (`impactScore` known=false; `TestImpactUnknown`); B4 sets `Coverage` from `Enriched` |
| **2D matrix Level** | B3 (`levelMatrix`/`LevelFromAxes`; `TestLevelMatrix`) |
| **Provisional when Impact Unknown** (level from Exposure) | B3 (`LevelFromAxes` `!impactKnown` branch; `Result.Provisional`; `TestScoreV2Result`) |
| **DA hard override (cracked+DA → Critical)** | B3 (`daOverride`; `TestScoreDAHardOverride`) |
| **Percentile rank** (within-audit triage) | B5 (`ComputePercentiles`; `TestComputePercentiles`) + store wiring |
| **Shared-hash-to-DA → max Impact + Level** | B5 (extended `EscalateSharedWithDA`; `TestEscalateSharedWithDAImpact`) |
| **Breakdown carries radar leave-one-out inputs** | B3 (`Breakdown` raw per-factor fields); B4 (`model.ScoreBreakdown` extension) |
| **Vector: real `CO:` + `EXP:`/`IMP:` (`IMP:U`)** | B3 (`Vector`+`axisCode`/`impactCode`; `TestVectorV2`) |
| **model.Account fields** (exposure/impact*/known/percentile; coverage exists) | B4 (model fields; `TestAxisFieldsRedactionSafe`) |
| **risk_level from matrix; risk_score back-compat blend** | B3 (`Result.Level`/`Result.Score`); B4 maps into `Account` |
| **Tier-0 wiring gap closed** (`Enrichment.ControlsTier0`) | B4 (live `ExtractControlsTier0`; bulk=false; `TestControlsTier0WiredLive`) |
| **Update existing goldens to v2 (not preserve v1)** | B4 (engine goldens), B6 (risk goldens) — both with shift comments |
| **Remove orphaned v1 code** | B6 (Step 2/4) |

## Spec ambiguities resolved (flagged for review)

1. **Legacy `RiskScore` formula** — spec said "e.g. impact_known ? round1(0.5·exposure+0.5·impact) : exposure". Locked exactly that. Percentile ranks on it because it is the one number defined for every account.
2. **Reuse/roastable bump magnitude** — spec said "small, capped, +0.5". Locked +0.5 each, additive, no per-bump cap beyond the final `min(10,·)`. Documented.
3. **`simPenalty` normalization** — spec said "normalized to [0,1]"; the existing `similarityFactor` maxes at 0.6, so locked `/0.6`. Flagged: this means any similarity ≥0.9 saturates simPenalty to 1.0.
4. **Shared-DA escalated Level** — spec said "inherits MAX Impact and a recomputed Level" while also "mirror how it already forces RiskLevel=Critical". Resolved: force Impact=10 AND keep Level Critical (consistent with the existing flagship-escalation behavior and with the matrix, where Impact=10 is never below High and the shared-DA signal is intentionally the top escalation).
5. **`ScoreBreakdown` v1 fields** — kept as zero-valued `omitempty` back-compat for one release (persisted-JSON safety) rather than deleted; justified in B4 Step 1.
6. **`ComputeLevel` removal** — v2 routes the uncracked path through `risk.Score`, leaving `ComputeLevel` unused; removed in B6 (vs keeping a legacy export). Flagged in case any out-of-scope caller (frontend bundling, CLI) imports it — grep confirmed only the engine used it.
7. **Bulk `ControlsTier0`** — the 3-query bulk Cypher does not collect Tier-0 edges; locked to `false` (conservative under-report) with a tracking note, since inventing a bulk Tier-0 query is out of B's scope.
8. **Percentile of Unknown-impact accounts** — they still receive a percentile (ranked on `RiskScore`=Exposure); the *segregation* of Unknown-impact accounts into the needs-enrichment worklist is a C-side sort concern, not a B percentile concern.
