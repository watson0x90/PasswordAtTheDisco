# Mass-reuse Level escalation (Finding 1) — Design

> Sub-project B of the post-v2.25.0 scoring-audit fixes. A large CRACKED password-reuse cluster
> currently reads as per-account **"Low"** — because the Exposure×Impact matrix caps a low-blast-radius
> account at Medium regardless of Exposure, so "one crack owns 402 accounts" hides on the worklist.
> This adds an escalation pass that raises the **Level** of members of a large cracked-reuse cluster.

## 1. Problem (confirmed against a real 6,069-account export)
A cracked password shared by 402 accounts: each member is Exposure 5.0 (the reuse floor lifted it to
Medium tier) but **risk_level "Low"**, because `levelMatrix[Impact-Low][any Exposure] ≤ Medium` and
Medium-Exposure × Low-Impact = Low. The reuse floor fixed Exposure; the *combined Level* still
collapses. The only existing cluster→Level escalation is `EscalateSharedWithDA` (when a cluster member
is a DA). A large **non-privileged** cracked cluster gets no Level escalation, so it isn't triaged.

## 2. Approach
A new audit-level pass `model.EscalateLargeCrackedReuse(accts)`, mirroring `EscalateSharedWithDA`,
that raises the **Level** (only) of members of a large cracked-reuse cluster — Impact stays honest
(these accounts genuinely have low blast radius; a `/MASS-REUSE` vector tag + a flag explain the
override, exactly as `/SHARED-DA` does).

**Hybrid, scale-aware thresholds** (so the rule isn't locked to one audit size — a 20-of-30 systemic
case escalates, a 25-in-500k blast case also escalates). For a cracked NT hash shared by **N** accounts
in an audit of **total** accounts:
- **High** if `N ≥ 100` **OR** (`N ≥ 5` AND `N ≥ 0.25·total`)
- else **Medium** if `N ≥ 25` **OR** (`N ≥ 5` AND `N ≥ 0.05·total`)
- else unchanged.

The `N ≥ 5` guard on the percentage path stops a 2-of-4 cluster in a tiny test audit from firing while
a 20-of-30 still does. **Cap at High** — Critical stays reserved for DA / cracked-DA / shared-DA. All
five tunables live in one named `const` block at the top of the pass.

Only **cracked** clusters escalate (a known password = an active incident; NTLM is unsalted so every
member of a cracked hash is itself `Cracked`). Large *uncracked* clusters are out of scope — they're
latent, already get the Exposure reuse-floor (Medium tier) and show in the reuse panels.

## 3. The pass
```go
// (named const block — tune here)
const (
    massReuseHighN      = 100
    massReuseMediumN    = 25
    massReuseHighFrac   = 0.25
    massReuseMediumFrac = 0.05
    massReuseMinClusterForFrac = 5 // the fraction path needs at least this many accounts
)

func EscalateLargeCrackedReuse(accts []Account) {
    total := len(accts)
    // count cracked members per reuse hash
    crackedN := map[string]int{}
    for i := range accts {
        if accts[i].Cracked {
            if k := reuseKey(accts[i].NTHash); k != "" {
                crackedN[k]++
            }
        }
    }
    for i := range accts {
        a := &accts[i]
        if !a.Cracked {
            continue
        }
        k := reuseKey(a.NTHash)
        n := crackedN[k]
        target := massReuseTarget(n, total) // "" | "Medium" | "High"
        if target == "" {
            continue
        }
        a.RiskLevel = moreSevereLevel(a.RiskLevel, target)
        a.RiskScore = math.Max(a.RiskScore, levelFloorScore(target)) // Medium->4.0, High->6.0 display floor
        if !strings.Contains(a.RiskVector, "MASS-REUSE") {
            a.RiskVector += "/MASS-REUSE"
        }
        a.EscalatedByMassReuse = true
        // Impact intentionally untouched -- blast radius is honestly low.
    }
}
```
- `massReuseTarget(n, total)`: applies the hybrid rule above (High first, then Medium, else "").
- `moreSevereLevel(cur, target)`: returns the higher-severity of the two (Critical>High>Medium>Low),
  so it never downgrades a member already escalated to Critical by `EscalateSharedWithDA`. Reuses the
  level-rank ordering already encoded in `triageKey` (factor it into a small `levelRank(string) int`
  helper if cleaner).
- `levelFloorScore("Medium")=4.0`, `"High")=6.0` — the tier minimums, so a Medium/High level doesn't
  display alongside a 0.8 RiskScore. Only raises (`math.Max`).
- `reuseKey` is the existing unexported model helper (upper-cased NT hash, excludes empty-password).

**Pipeline insertion** — `EscalateLargeCrackedReuse` runs **after** `EscalateSharedWithDA` and
**before** `ComputePercentiles` at all three `internal/store/store.go` sites (the level-first percentile
must see the escalated levels). i.e. each `RecomputeSharing → EscalateSharedWithDA → ComputePercentiles`
becomes `… → EscalateSharedWithDA → EscalateLargeCrackedReuse → ComputePercentiles`.

## 4. Surfacing the new signal
- **`model.Account`**: new `EscalatedByMassReuse bool \`json:"escalated_by_mass_reuse,omitempty"\``.
- **`model.Summary`**: new `EscalatedByMassReuse int \`json:"escalated_by_mass_reuse"\`` count, computed
  in the Summary builder the same way `EscalatedBySharedDA` is.
- **Sanitized export** (`internal/report/sanitize.go`): add `EscalatedByMassReuse bool
  \`json:"escalated_by_mass_reuse,omitempty"\`` to `SanitizedAccount`, copied from the account — so the
  audit export (how this gap was found) shows it.
- **Account drawer** (`web/src/components/AccountDrawer.tsx` + `web/src/api.ts`): an
  `escalated_by_mass_reuse?: boolean` field and a row mirroring the existing "Escalated (Shared-DA)"
  row, e.g. `["Escalated (Mass-reuse)", a.escalated_by_mass_reuse ? "Yes — one crack compromises this whole reuse cluster" : "—"]`.

Out of scope: a dashboard KPI tile, a dedicated reuse worklist, the Impact axis, uncracked clusters,
the `RO:`-style vector legend entry (the `/MASS-REUSE` suffix is self-describing, matching `/SHARED-DA`).

## 5. Files
- **Go:** `internal/model/model.go` (the pass + `EscalatedByMassReuse` field + `levelRank`/
  `moreSevereLevel`/`levelFloorScore`/`massReuseTarget` helpers + the const block); the Summary builder
  (the count); `internal/store/store.go` (3 pipeline inserts); `internal/report/sanitize.go` (export
  field). Tests: `internal/model/model_test.go` (the pass), `internal/report/sanitize_test.go` (export).
- **Web:** `web/src/api.ts` (`escalated_by_mass_reuse?`), `web/src/components/AccountDrawer.tsx` (row).

No change to the scoring engine, the Exposure/Impact axes, or `EscalateSharedWithDA`.

## 6. Testing
- **The pass (Go):** a hash shared by 25 cracked accounts → all become ≥ Medium + flagged + `/MASS-REUSE`;
  100 cracked → High; 24 cracked (below both absolute and 5% in a large set) → unchanged. The hybrid:
  a 20-of-30 audit (≥0.25·30=7.5 and ≥5) → High; a 2-of-4 audit (< 5 guard) → unchanged.
  `moreSevereLevel` never downgrades (a Critical member stays Critical, still flagged). Impact and
  ImpactScore are untouched. Uncracked members of a cracked hash don't exist (NTLM), but an uncracked
  account in a separate uncracked cluster is never escalated.
- **Ordering (Go):** in the store pipeline, a member that is BOTH shared-DA (→Critical) and in a large
  cracked cluster keeps Critical (shared-DA wins via moreSevere) and carries both flags.
- **Export (Go):** `escalated_by_mass_reuse` appears in the sanitized output for a flagged account and
  the canary leak test still passes.
- **Web:** `tsc`/`vitest`/`build` green; the drawer row renders (no test pins the row set; update if one does).
- **Gates:** `gofmt`, `go build/vet/test`, `govulncheck`; web `tsc`/`vitest`/`build`.
- **Live:** rebuild + Recalculate the 6,069-account audit (or the disposable one); confirm the 402-cracked
  cluster's members now read **High** (was Low), carry `/MASS-REUSE`, Impact still Unknown/Low; export a
  sanitized report and confirm `escalated_by_mass_reuse` is set on the cluster. Console clean.

## 7. Definition of done
Members of a large cracked-reuse cluster escalate to Medium/High (scale-aware thresholds, cap High),
carry a `/MASS-REUSE` tag + `escalated_by_mass_reuse` flag (Go, sanitized export, drawer, Summary count),
with Impact left honest and `EscalateSharedWithDA` Criticals never downgraded. The 402×"Low" blast-radius
blind spot is fixed; the Exposure/Impact axes and existing escalation are unchanged.
