# Quick-Wins Bundle (v2.16) — Design

**Date:** 2026-06-20
**Topic:** Three independent, high-value-per-effort improvements surfaced by the CISO + blue-team review: (A) "newly dangerous" Compare cohorts, (B) a posture trend over all audits on the Overview dashboard, and (C) a batch password-in-use probe. Target release **v2.16.0**.

## Problem

The CISO + blue-team walkthrough found the tool strong at read-and-triage but light on the highest-signal *re-audit deltas*, *longitudinal* reporting, and *bulk* operations:

- **Compare** flags newly-cracked / remediated / regressed / newly-breached, but not what an analyst actually escalates after a re-audit: accounts that became **Critical**, gained a **Domain-Admin pathway**, or newly formed a **shared-password cluster**.
- **Compare is strictly pairwise** — there's no posture-over-time trend, so the board's "are we improving?" question is unanswered even though posture is already computed per audit.
- The **password-in-use probe is one candidate at a time** — you can't sweep a banned-password list or a freshly leaked dump across the whole (cracked + uncracked) population.

## Decision

Ship all three in one release (each is small and they share no data model). Approved via brainstorming. Cohort scope: **newly-Critical + newly-DA-pathway + newly-reused** (all three). Trend lives on the **Overview** dashboard. Batch probe accepts **a pasted list and a file upload** (large dumps).

**Not in scope:** remediation tracking / risk-acceptance state, framework mapping, tamper-evident audit log, machine-readable JSON egress (these are separate, larger efforts from the same review). No change to the redaction model or the lead-gated reveal.

## A. Compare — "newly dangerous" cohorts

### Backend — `internal/report/report.go`
Extend `Diff` with three account-level cohorts (reusing the existing `DiffAccount{Username, Domain, RiskA, RiskB}` shape, initialized non-nil so JSON emits `[]`):

```go
type Diff struct {
	PostureA      float64       `json:"posture_a"`
	PostureB      float64       `json:"posture_b"`
	StillCracked  int           `json:"still_cracked"`
	NewlyCracked  []DiffAccount `json:"newly_cracked"`
	Remediated    []DiffAccount `json:"remediated"`
	NewlyBreached []DiffAccount `json:"newly_breached"`
	Regressed     []DiffAccount `json:"regressed"`
	NewlyCritical []DiffAccount `json:"newly_critical"`  // NEW
	NewlyDA       []DiffAccount `json:"newly_da"`        // NEW
	NewlyReused   []DiffAccount `json:"newly_reused"`    // NEW
}
```

`ComputeDiff(a, b []model.Account)` additions, inside the existing `for k, bx := range bm` loop where `ax, inA := am[k]`:
- **Newly-Critical:** `if bx.RiskLevel == "Critical" && (!inA || ax.RiskLevel != "Critical") { d.NewlyCritical = append(...) }`.
- **Newly-DA:** `if bx.HasDAPathway() && (!inA || !ax.HasDAPathway()) { d.NewlyDA = append(...) }`.
- **Newly-Reused** (group-level → account rows): the `report` package cannot reach `model`'s unexported `emptyNTHash`/`reuseKey`, so define a package-local `const emptyNTHash = "31D6CFE0D16AE931B73C59D7E0C089C0"` in `report.go` and a small helper `func reuseKey(h string) string { h = strings.ToUpper(h); if h == "" || h == emptyNTHash { return "" }; return h }`. Before the main loop, build `groupB := map[string]int{}` and `groupA := map[string]int{}` counting accounts per `reuseKey(NTHash)` (skipping the `""` key) across `b` and `a`. A hash is a *cluster* when its count ≥ 2. In the `bx` loop: `if k := reuseKey(bx.NTHash); k != "" && groupB[k] >= 2 && groupA[k] < 2 { d.NewlyReused = append(d.NewlyReused, ref(ax, bx, bx)) }` — i.e. every member of a hash that is a cluster in B but was not a cluster in A.

The `ref(ax, bx, bx)` helper already produces a redacted `DiffAccount`. **No NT hash ever appears in the output.**

### Backend — `internal/httpapi/server.go` `handleDiff`
Currently loads **redacted** accounts (`Accounts(idA, false)`), which zero `NTHash` — so newly-reused grouping would see no hashes. Change both loads to **full** accounts:

```go
accA, errA := s.Store.Accounts(idA, true) // full: ComputeDiff needs NTHash to group reuse
accB, errB := s.Store.Accounts(idB, true) // the Diff output (DiffAccount) stays redacted
```

This mirrors `handleReport`/`handleProbe` ("need NT hashes to group; report is redacted"). The response body is unchanged in shape except the three new arrays, and remains redacted (DiffAccount carries only username/domain/risk).

### Frontend — `web/src/components/Compare.tsx`
The `DiffResult.diff` type (in `web/src/api.ts`) gains `newly_critical`, `newly_da`, `newly_reused: DiffAccount[]`. Add three `<CohortCard>`s to the existing `chart-grid` in `DiffView` (they already render `DiffAccount[]` with clickable usernames via the shared `accounts` index):
- `<CohortCard title="Newly Critical" tone="crit" items={d.newly_critical} accounts={accounts} />`
- `<CohortCard title="Newly DA-pathway" tone="crit" items={d.newly_da} accounts={accounts} />`
- `<CohortCard title="Newly reused" tone="high" items={d.newly_reused} accounts={accounts} />`

### Tests
`internal/report/report_test.go` — extend the existing diff fixture (or add a case) so that: an account goes Low→Critical (newly-critical), an account gains a DA pathway (newly-da), and two accounts share an `NTHash` in B that didn't form a cluster in A (newly-reused). Assert each new cohort's membership. Existing diff assertions stay green.

## B. Posture trend (Overview)

### Backend — `GET /api/trends`
Route: `mux.Handle("GET /api/trends", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleTrends))))`.

Handler `handleTrends`: list all audits (`s.Store.Audits()` / the existing audit-list call used by `handleListAudits`); for each, load **redacted** accounts (`Accounts(id, false)` — posture + counts derive from redacted fields, no secret needed); compute `model.PostureScore(accts).Score` and counts. Return a JSON array sorted by the audit's `CreatedAt` ascending:

```go
type TrendPoint struct {
	AuditID   string    `json:"audit_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Posture   float64   `json:"posture"`
	Accounts  int       `json:"accounts"`
	Cracked   int       `json:"cracked"`
	Breached  int       `json:"breached"`
	DAPaths   int       `json:"da_pathways"`
	Critical  int       `json:"critical"`
}
```
Counts: `Cracked` = accounts with `Cracked`; `Breached` = `HIBPBreached`; `DAPaths` = `HasDAPathway()`; `Critical` = `RiskLevel == "Critical"`. Empty audits contribute a point with `Posture: 0` (or are included as-is). The active audit need not be selected (this reads across all audits, like the audit list).

Performance: O(audits × accounts) — acceptable for the expected handful of audits; no caching in this iteration.

### Frontend — `web/src/api.ts` + `web/src/components/Dashboard.tsx`
- `api.ts`: `trends: () => request<TrendPoint[]>("/trends")` + the `TrendPoint` interface.
- Dashboard fetches trends once; when `points.length >= 2`, render a **"Security posture over time"** card using the existing chart primitives (`web/src/components/Charts.tsx` — reuse the line/scatter component the dashboard already uses) plotting `posture` over `created_at`, with the cracked count as a secondary series or a small companion line. When `< 2` audits, the card is omitted (a single point isn't a trend). Place it near the existing posture gauge / charts section.

### Tests
Go: `handleTrends` returns points for ≥2 seeded audits, sorted by date, with the right posture/counts and no cleartext/nt_hash in the body. Web: the trend rendering is presentational (no new pure logic) — verified by tsc/build/Playwright.

## C. Batch password-in-use probe

### Backend — `internal/httpapi/server.go`
Build, once per request, an index from the active audit's **full** accounts: `byHash := map[string][]model.Account{}` keyed by `strings.ToUpper(a.NTHash)` (skip `""` and the empty-password hash), storing `a.Redacted()` members. `hibp.NTLMHash` already returns uppercase hex, so each candidate's `hibp.NTLMHash(candidate)` looks up directly against the upper-cased keys (case is normalized on both sides — the single-probe path's `EqualFold` doesn't translate to a map, so the explicit `ToUpper` matters here).

1. **`POST /api/probe` (extended).** Accept either field:
   - `{"password": "..."}` → unchanged response `{count, matches}` (the existing single path stays byte-for-byte compatible).
   - `{"passwords": ["...", ...]}` → batch. Reject empty list or > **2000** candidates (`400`). Body cap raised to `1<<20` (1 MiB) via `MaxBytesReader`. Response:
     ```go
     type BatchProbeResult struct {
         CandidatesChecked int              `json:"candidates_checked"`
         CandidatesMatched int              `json:"candidates_matched"` // candidates with >=1 match
         Accounts          []model.Account  `json:"accounts"`           // deduped union, redacted
         PerCandidate      []CandidateCount `json:"per_candidate"`      // {index,count} per input line
     }
     type CandidateCount struct { Index int `json:"index"`; Count int `json:"count"` }
     ```
     Skip blank/empty candidates (they don't count toward the matched set); `per_candidate` indices align to the input array positions.
2. **`POST /api/probe/file` (new).** Multipart upload of a newline-delimited candidate file (field `file`), gated `requireAuth + requireCSRF + requireUnlocked`, streamed with `bufio.Scanner` so a large leaked dump never fully buffers. Body cap raised (e.g. `64<<20`). Response: `BatchProbeResult` **without** `PerCandidate` (omit for huge files — `nil`/`[]`); `Accounts` is the deduped union, `CandidatesChecked`/`CandidatesMatched` summarize. Trim each line; skip blanks.

Both batch paths audit-log action `password_probe` with `Target: fmt.Sprintf("candidates=%d matches=%d", checked, len(unionAccounts))` (counts only) — **no candidate string is ever logged, stored, or echoed**. Reuse `hibp.NTLMHash`. The deduped union is keyed by `domain\username`.

### Frontend — `web/src/api.ts` + `web/src/components/Search.tsx`
- `api.ts`: `probeBatch: (passwords: string[], csrf) => request<BatchProbeResult>("/probe", {POST, body:{passwords}, X-CSRF-Token})`; and a file variant `probeFile: (file: File, csrf, onProgress?) => uploadForm<BatchProbeResult>("/probe/file", fd, csrf, onProgress)` (reuse the existing `uploadForm` XHR helper used by the upload endpoints). Add the `BatchProbeResult`/`CandidateCount` interfaces.
- `Search.tsx`, *Password in use?* sub-tab: a **Single / List** mode toggle.
  - **Single** = the current input (unchanged).
  - **List** = a textarea (one candidate per line) **and** a file picker. On submit: paste → `api.probeBatch(lines, csrf)`; file → `api.probeFile(file, csrf)`. Render the matched-accounts **union** with `<AccountsTable accounts={result.accounts} />` (clickable → drawer) under a headline (`{candidates_matched} of {candidates_checked} checked passwords are in use — {accounts.length} account(s) affected`), and — when `per_candidate` is present (paste path) — a compact per-line list showing each pasted line's match count (the operator's plaintext stays client-side; the server returns only indices + counts). The textarea/file value is cleared after submit, mirroring the single-probe re-mask behavior. The standing audit notice is unchanged ("never stored or logged; logged with counts only").

### Tests
Go: a batch test ingesting accounts with known `NTHash = NTLMHash(p)` values; `POST /api/probe {"passwords":[hit1, miss, hit2]}` → correct `candidates_checked/matched`, the union accounts present, `per_candidate` counts aligned, **no cleartext/nt_hash in the body**, and the audit log shows `candidates=… matches=…` with none of the candidate strings. A `/probe/file` multipart test with a small newline file → union + summary, no `per_candidate`. Empty list → 400; over-cap list → 400. The existing single-probe test stays green.

## Security / redaction
All three features emit **only redacted accounts** (`Account.Redacted()` — no Password, no NTHash). `handleDiff` and the probe paths read full accounts internally to group by NT hash but never place a hash in any response. The batch probe never logs, stores, or echoes a candidate password — only counts. `/api/trends` exposes posture + counts, no per-account secret. No change to the lead-gated cleartext reveal.

## Testing summary
- **Go:** new `ComputeDiff` cohort assertions; `handleTrends` (sorted, correct counts, redacted); batch `/api/probe` + `/api/probe/file` (matching, union dedup, per-candidate alignment, caps, audit counts-only, no leak). `gofmt`, `go build/vet/test`, `govulncheck`.
- **Web:** type updates compile (`tsc`); `vitest` (incl. styleguard); `npm run build`.
- **Live Playwright:** Compare shows the 3 new cohorts (clickable → drawer); Overview shows the posture-trend chart with ≥2 audits; the Password sub-tab List mode checks a pasted list and an uploaded file and lists the affected accounts; no console 4xx/errors.

## Out of scope
- Remediation/risk-acceptance state, framework mapping, tamper-evident audit log, JSON/SOAR egress, scope-coverage attestation, retention policy (all separate efforts).
- Per-candidate matched-account detail for file uploads (only the union is returned for large dumps).
- Trend caching / a dedicated persisted posture history (recomputed live from audits this iteration).
