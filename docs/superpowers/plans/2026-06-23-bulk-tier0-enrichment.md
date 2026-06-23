# Bulk Tier-0 enrichment (Finding 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The bulk BloodHound enricher (used for large audits) flags `ControlsTier0` for users who control a Tier-0 / DA-equivalent object, using the same definition as the per-user path — so large audits stop silently missing the Tier-0 privilege signal.

**Architecture:** Add a 4th bulk-prefetch Cypher (`FetchTier0Controllers`) whose Tier-0 predicate is built from the existing `bloodhound.tier0Names`; store the resulting `user@DOMAIN` set in the bulk cache; `BulkEnricher.Lookup` returns it; `engine.BulkBloodhoundEnricher.Enrich` sets `ControlsTier0` from it instead of a hard-coded `false`. Conservative on errors/misses (false), so it only adds true-positives.

**Tech Stack:** Go 1.26 stdlib (`encoding/json`, `strings`, `testing`); BloodHound CE Cypher over the project's signed client.

**Spec:** `docs/superpowers/specs/2026-06-23-bulk-tier0-enrichment-design.md`

## File Structure
- `internal/bloodhound/cypher.go` — `tier0NameList()` + `FetchTier0Controllers()` + 3 parse helpers. (Task 1)
- `internal/bloodhound/cypher_test.go` (new) — parser + list-builder tests. (Task 1)
- `internal/bloodhound/bulk_enricher.go` — `BulkEnrichment.Tier0` + `Prefetch` wiring + additive `Tier0(key) bool` accessor + `NewBulkEnricherFromData`. (Task 2)
- `internal/bloodhound/bulk_enricher_test.go` (new) — `Lookup` returns the Tier-0 bool. (Task 2)
- `internal/engine/engine.go` — `BulkBloodhoundEnricher.Enrich` sets `ControlsTier0` from `Lookup`. (Task 3)
- `internal/engine/engine_test.go` — Enrich reflects the injected Tier-0 set. (Task 3)

**Gates (repo root):** `gofmt -l cmd internal` · `go build ./...` · `go vet ./...` · `go test ./...` · `govulncheck ./...`.

**Branch:** `feature/bulk-tier0-enrichment` (already created). Every implementer: confirm `git branch --show-current` == that; NEVER `git checkout`/`switch`/`branch`. Bash tool for git/go.

---

## Task 1: Cypher query + parsers (`FetchTier0Controllers`)

**Files:**
- Modify: `internal/bloodhound/cypher.go` (add near `FetchControllableCounts`, ~line 408)
- Create: `internal/bloodhound/cypher_test.go`

- [ ] **Step 1: Write the failing parser tests**

Create `internal/bloodhound/cypher_test.go`:

```go
package bloodhound

import "testing"

func TestTier0NameList(t *testing.T) {
	got := tier0NameList()
	// Must be a quoted, comma-joined list built from tier0Names (single source of truth).
	for _, name := range tier0Names {
		if !contains(got, "'"+name+"'") {
			t.Errorf("tier0NameList()=%q missing %q", got, name)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestParseTier0Literals(t *testing.T) {
	// BHE-CE "literals" shape: flat list, 2 columns per row (samaccountname, domain).
	lits := []literal{{Value: "svc"}, {Value: "CORP"}, {Value: "alice"}, {Value: "EU.CORP"}}
	got := parseTier0Literals(lits)
	if !got["svc@CORP"] || !got["alice@EU.CORP"] {
		t.Errorf("parseTier0Literals = %v, want svc@CORP and alice@EU.CORP true", got)
	}
	if len(got) != 2 {
		t.Errorf("len=%d, want 2", len(got))
	}
}

func TestParseTier0Rows(t *testing.T) {
	rows := [][]interface{}{{"svc", "CORP"}, {"", "CORP"}} // 2nd row blank sam -> skipped
	got := parseTier0(rows)
	if !got["svc@CORP"] || len(got) != 1 {
		t.Errorf("parseTier0 = %v, want only svc@CORP", got)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/bloodhound/ -run 'TestTier0NameList|TestParseTier0' -v`
Expected: FAIL — `undefined: tier0NameList` / `parseTier0Literals` / `parseTier0`.

- [ ] **Step 3: Add the list builder + the 3 parsers + the query**

In `internal/bloodhound/cypher.go`, add (after `FetchControllableCounts` and its parsers, anywhere in the file):

```go
// tier0NameList builds the Cypher list literal of Tier-0 object-name fragments from
// tier0Names (the single source of truth), e.g. "'DOMAIN ADMINS','ENTERPRISE ADMINS',...".
// tier0Names are hard-coded constants (no user input), so this string-building is injection-safe.
func tier0NameList() string {
	return "'" + strings.Join(tier0Names, "','") + "'"
}

// FetchTier0Controllers returns the set (key "user@DOMAIN") of users who control a
// Tier-0 / DA-equivalent object -- the same definition the per-user ExtractControlsTier0
// uses: a control edge onto an object whose name matches tier0Names, OR onto the domain
// object itself (DCSync). Best-effort: on error returns the error; an empty/unrecognized
// response yields an empty set (conservative -- never a false positive).
func (c *Client) FetchTier0Controllers() (map[string]bool, error) {
	query := `MATCH (u:User)-[r]->(n) WHERE type(r) IN ['GenericAll','GenericWrite','WriteOwner','WriteDacl','Owns','ForceChangePassword','AddMember'] AND (n:Domain OR ANY(t IN [` + tier0NameList() + `] WHERE toUpper(coalesce(n.name,'')) CONTAINS t)) RETURN DISTINCT u.samaccountname, u.domain`
	data, err := c.RunCypher(query)
	if err != nil {
		return nil, fmt.Errorf("FetchTier0Controllers: %w", err)
	}
	var literalsResult struct {
		Literals []literal `json:"literals"`
	}
	if json.Unmarshal(data, &literalsResult) == nil && len(literalsResult.Literals) > 0 {
		return parseTier0Literals(literalsResult.Literals), nil
	}
	var rows [][]interface{}
	if json.Unmarshal(data, &rows) == nil && len(rows) > 0 {
		return parseTier0(rows), nil
	}
	var tabular struct {
		Results []struct {
			Data []json.RawMessage `json:"data"`
		} `json:"results"`
	}
	if json.Unmarshal(data, &tabular) == nil && len(tabular.Results) > 0 {
		return parseTier0FromResults(tabular.Results[0].Data), nil
	}
	log.Printf("bloodhound: FetchTier0Controllers: unrecognized response format")
	return map[string]bool{}, nil
}

func parseTier0Literals(lits []literal) map[string]bool {
	const cols = 2 // samaccountname, domain
	out := map[string]bool{}
	for i := 0; i+cols-1 < len(lits); i += cols {
		sam := toString(lits[i].Value)
		domain := toString(lits[i+1].Value)
		if sam == "" {
			continue
		}
		out[strings.ToLower(sam)+"@"+strings.ToUpper(domain)] = true
	}
	return out
}

func parseTier0(rows [][]interface{}) map[string]bool {
	out := map[string]bool{}
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		sam, _ := row[0].(string)
		domain, _ := row[1].(string)
		if sam == "" {
			continue
		}
		out[strings.ToLower(sam)+"@"+strings.ToUpper(domain)] = true
	}
	return out
}

func parseTier0FromResults(data []json.RawMessage) map[string]bool {
	out := map[string]bool{}
	for _, raw := range data {
		var item struct {
			Row []interface{} `json:"row"`
		}
		if json.Unmarshal(raw, &item) != nil || len(item.Row) < 2 {
			continue
		}
		sam, _ := item.Row[0].(string)
		domain, _ := item.Row[1].(string)
		if sam == "" {
			continue
		}
		out[strings.ToLower(sam)+"@"+strings.ToUpper(domain)] = true
	}
	return out
}
```

(`strings`, `fmt`, `log`, `encoding/json` are already imported in cypher.go; `literal`, `toString` already exist.)

- [ ] **Step 4: Run to verify it passes + gofmt**

Run: `go test ./internal/bloodhound/ -run 'TestTier0NameList|TestParseTier0' -v` → PASS.
Run: `gofmt -l internal/bloodhound/cypher.go internal/bloodhound/cypher_test.go` → nothing.
Run: `go build ./internal/bloodhound/ && go vet ./internal/bloodhound/` → clean.

- [ ] **Step 5: Commit**

```bash
test "$(git branch --show-current)" = "feature/bulk-tier0-enrichment" || { echo "WRONG BRANCH"; exit 1; }
git add internal/bloodhound/cypher.go internal/bloodhound/cypher_test.go
git commit -m "feat(bloodhound): FetchTier0Controllers bulk Cypher (tier0Names-derived) + parsers"
```

---

## Task 2: Bulk cache `Tier0` set + accessor + test seam

**Files:**
- Modify: `internal/bloodhound/bulk_enricher.go` (`BulkEnrichment` struct; `Prefetch`; `Lookup`; add `NewBulkEnricherFromData`)
- Create: `internal/bloodhound/bulk_enricher_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/bloodhound/bulk_enricher_test.go`:

```go
package bloodhound

import "testing"

func TestBulkEnricherTier0(t *testing.T) {
	b := NewBulkEnricherFromData(BulkEnrichment{
		Props: map[string]BulkUserProps{"svc@CORP": {ObjectID: "S-1-5-21-1"}},
		Tier0: map[string]bool{"svc@CORP": true},
	})
	if !b.Tier0("svc@CORP") {
		t.Errorf("Tier0(svc@CORP) = false, want true")
	}
	// Key normalization: mixed-case input must still resolve.
	if !b.Tier0("SVC@corp") {
		t.Errorf("Tier0(SVC@corp) = false, want true (case-normalized)")
	}
	if b.Tier0("other@CORP") {
		t.Errorf("Tier0(other@CORP) = true, want false (not in set)")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/bloodhound/ -run TestBulkEnricherTier0 -v`
Expected: FAIL — `undefined: NewBulkEnricherFromData` / `b.Tier0`.

- [ ] **Step 3: Add the `Tier0` field**

In `internal/bloodhound/bulk_enricher.go`, in the `BulkEnrichment` struct, add a field:

```go
type BulkEnrichment struct {
	Props         map[string]BulkUserProps // key: "user@DOMAIN"
	DAUsers       map[string][]string      // key -> DA domains
	Controllables map[string]int           // key -> controlled object count
	Tier0         map[string]bool          // key -> controls a Tier-0/DA-equivalent object
}
```

- [ ] **Step 4: Wire `FetchTier0Controllers` into `Prefetch`**

In `Prefetch`, after the `ctrl, err := b.client.FetchControllableCounts()` block (before `b.data = BulkEnrichment{...}`), add:

```go
		t0, err := b.client.FetchTier0Controllers()
		if err != nil {
			log.Printf("bloodhound: FetchTier0Controllers failed: %v (Tier-0 control will be empty)", err)
			t0 = map[string]bool{}
		} else {
			log.Printf("bloodhound: fetched Tier-0 controllers: %d users", len(t0))
		}
```

and add `Tier0: t0,` to the `b.data = BulkEnrichment{...}` literal.

- [ ] **Step 5: Add a `Tier0(key) bool` accessor (additive — does NOT change `Lookup`)**

In `internal/bloodhound/bulk_enricher.go`, add a method that mirrors `Lookup`'s key normalization. (We add a focused accessor rather than changing `Lookup`'s signature, so the existing caller keeps building.)

```go
// Tier0 reports whether the user controls a Tier-0 / DA-equivalent object, from the
// bulk Tier-0 prefetch set. Same key normalization as Lookup.
func (b *BulkEnricher) Tier0(key string) bool {
	k := key
	if idx := strings.LastIndex(k, "@"); idx >= 0 {
		k = strings.ToLower(k[:idx]) + "@" + strings.ToUpper(k[idx+1:])
	} else {
		k = strings.ToLower(k)
	}
	return b.data.Tier0[k]
}
```

- [ ] **Step 6: Add the test-seam constructor**

In `internal/bloodhound/bulk_enricher.go`, add:

```go
// NewBulkEnricherFromData builds an enricher whose cache is pre-populated, without a
// Cypher prefetch. Used for seeding/tests; Prefetch is not required (Lookup reads data directly).
func NewBulkEnricherFromData(data BulkEnrichment) *BulkEnricher {
	return &BulkEnricher{data: data}
}
```

- [ ] **Step 7: Run the test + confirm the whole module still builds**

Run: `go test ./internal/bloodhound/ -run TestBulkEnricherTier0 -v` → PASS.
Run: `gofmt -l internal/bloodhound/bulk_enricher.go internal/bloodhound/bulk_enricher_test.go` → nothing.
Run: `go build ./... && go vet ./...` → clean. (`Tier0` is additive and `Lookup` is unchanged, so the engine caller still builds — every commit stays green.)

- [ ] **Step 8: Commit**

```bash
test "$(git branch --show-current)" = "feature/bulk-tier0-enrichment" || { echo "WRONG BRANCH"; exit 1; }
git add internal/bloodhound/bulk_enricher.go internal/bloodhound/bulk_enricher_test.go
git commit -m "feat(bloodhound): bulk cache carries Tier-0 set; Lookup returns it + test seam"
```

---

## Task 3: Engine wiring — `ControlsTier0` from the bulk Tier-0 set

**Files:**
- Modify: `internal/engine/engine.go` (`BulkBloodhoundEnricher.Enrich` ~lines 628-659)
- Test: `internal/engine/engine_test.go`

- [ ] **Step 1: Write the failing engine test**

Add to `internal/engine/engine_test.go` (it already imports `bloodhound` for other tests; confirm and add the import if needed):

```go
func TestBulkEnricherSetsControlsTier0(t *testing.T) {
	bulk := bloodhound.NewBulkEnricherFromData(bloodhound.BulkEnrichment{
		Props: map[string]bloodhound.BulkUserProps{"svc@CORP": {ObjectID: "S-1-5-21-9"}},
		Tier0: map[string]bool{"svc@CORP": true},
	})
	be := BulkBloodhoundEnricher{Bulk: bulk}
	if enr := be.Enrich("svc@CORP"); !enr.ControlsTier0 {
		t.Errorf("ControlsTier0 = false, want true (user in bulk Tier-0 set)")
	}
	if enr := be.Enrich("other@CORP"); enr.ControlsTier0 {
		t.Errorf("ControlsTier0 = true for a user not in the set, want false (conservative)")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/engine/ -run TestBulkEnricherSetsControlsTier0 -v`
Expected: FAIL on the assertion — `ControlsTier0 = false, want true` (the engine still hard-codes `false`; it compiles fine).

- [ ] **Step 3: Set `ControlsTier0` from the bulk Tier-0 accessor**

In `internal/engine/engine.go`, in `BulkBloodhoundEnricher.Enrich`, leave the existing
`props, daDomains, ctrl := b.Bulk.Lookup(username)` line as-is, and in the returned
`Enrichment{...}` literal replace the hard-coded Tier-0 block:

```go
		// BulkBloodhoundEnricher: the 3-query bulk Cypher prefetch does not currently
		// collect Tier-0 control edges, so ControlsTier0 is conservatively false here.
		// The live BloodhoundEnricher path sets it; bulk under-reports Tier-0 by design
		// until the bulk Cypher is extended (tracked separately). False (not true) keeps
		// it conservative: a missed Tier-0 lowers Impact, never falsely inflates it.
		ControlsTier0: false,
```
with:
```go
		// Tier-0 control comes from the 4th bulk prefetch (FetchTier0Controllers), using
		// the same definition as the per-user ExtractControlsTier0. A miss/empty set keeps
		// it false (conservative -- a missed Tier-0 lowers Impact, never falsely inflates).
		ControlsTier0: b.Bulk.Tier0(username),
```

- [ ] **Step 4: Run the engine test + full gates**

Run: `go test ./internal/engine/ -run TestBulkEnricherSetsControlsTier0 -v` → PASS.
Run from repo root: `gofmt -l cmd internal` (empty) · `go build ./...` · `go vet ./...` · `go test ./...` → all green.
Run: `govulncheck ./...` → No vulnerabilities found.

- [ ] **Step 5: Commit**

```bash
test "$(git branch --show-current)" = "feature/bulk-tier0-enrichment" || { echo "WRONG BRANCH"; exit 1; }
git add internal/engine/engine.go internal/engine/engine_test.go
git commit -m "fix(engine): bulk enricher sets ControlsTier0 from the Tier-0 prefetch (large audits flag Tier-0)"
```

---

## Final verification (after all tasks)
- [ ] **Go gate:** `gofmt -l cmd internal` · `go build ./...` · `go vet ./...` · `go test ./...` · `govulncheck ./...`
- [ ] **Live (against the configured BloodHound):** run `go run ./tools/bhdump > out.json` and confirm users controlling a Tier-0 object now report `"controls_tier0": true` (compare to before, which was all-false); if the lab has no Tier-0 control edges, validate `FetchTier0Controllers` returns the expected set against a known node / crafted query result. Optionally: enrich a large audit and confirm its sanitized export shows non-zero `controls_tier0` and `T0:Y` vector tokens. (Note: `bhdump` builds its own Enrichment — confirm it uses the per-user or bulk path; the live check should exercise the **bulk** path. If `bhdump` is per-user, validate via a bulk-enriched audit's rescore instead.)

## Definition of done
Bulk-enriched (large) audits flag `ControlsTier0` for users controlling a Tier-0 / DA-equivalent object, via a 4th bulk Cypher whose predicate is derived from the same `tier0Names` the per-user path uses; errors/misses stay conservatively false; the `T0:` token, the Tier-0 privilege maximum, and the disabled-latent-risk Tier-0 arm now work on bulk audits. Per-user path and scoring formula unchanged; all gates green.
