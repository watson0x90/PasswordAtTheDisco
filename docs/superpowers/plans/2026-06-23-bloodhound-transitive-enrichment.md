# BloodHound Transitive Enrichment Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended)
> or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make the bulk BloodHound enricher use BloodHound's **true transitive** outbound-control count
(`env.Count`) and a unified **reachable** Tier-0/DA shortest-path sweep for the credential-obtainable
candidate set — so a cracked user with 4k transitive controlled objects + a DA path scores **Critical**,
not Low.

**Architecture:** Two-phase — keep the cheap bulk Cypher prefetch as a best-effort baseline for all
users; correct the `cracked ∪ HIBP ∪ roastable` (deduped) candidate set with per-user REST. Spec:
`docs/superpowers/specs/2026-06-23-bloodhound-transitive-enrichment-design.md` — read it; this implements
it. Root cause + reference (`GetUserControllables`→`env.Count`) detailed there.

**Tech Stack:** Go 1.26 stdlib; `internal/bloodhound`, `internal/engine`, `internal/enrich`. **No live
BloodHound** — all tests use a fake client; the user validates on live data. Gates: `gofmt -l cmd
internal`, `go build/vet/test ./...`, `govulncheck`.

**Branch:** `feature/bloodhound-transitive-enrichment` (off main @ v2.28.0, already created). Every
implementer: confirm `git branch --show-current` == that branch; NEVER `git checkout`/`switch`; NEVER
`git add -A` (stage explicit paths — a stray `add -A` already leaked export files once).

---

## File Structure
- `internal/bloodhound/cypher.go` — `controlEdgeTypes()` shared constant; broaden `FetchControllableCounts`
  + `tier0ControllersQuery`.
- `internal/bloodhound/anchors.go` (new) — Tier-0 anchor set + per-(domain,anchor) SID cache +
  `EnrichCandidate` (env.Count + anchor shortest-paths). Keeps `bloodhound.go` from growing further.
- `internal/bloodhound/client_iface.go` (new) — a small `candidateClient` interface (the subset of
  `*Client` methods the enricher needs) so a fake can be injected for tests.
- `internal/bloodhound/bulk_enricher.go` — `BulkEnricher.client` typed as the interface; replace
  `CheckDAForAccounts` with `EnrichCandidates` (dedup set, gate fix, env.Count override, anchor sweep).
- `internal/enrich/job.go` — build the candidate slice with `Roastable`; call `EnrichCandidates`; logging.
- Tests: `internal/bloodhound/anchors_test.go`, `bulk_enricher_test.go` (fake client), `cypher_test.go`.

Constants in ONE block (`internal/bloodhound/anchors.go`): `tier0SweepMin = 100`, the anchor name list,
and `controlEdgeTypes()` (cypher.go).

---

### Task 1: Shared, broadened control-edge type list

**Files:** Modify `internal/bloodhound/cypher.go`; Test `internal/bloodhound/cypher_test.go`

- [ ] **Step 1: Failing test** — assert the shared list contains the broadened set and both queries embed it:

```go
func TestControlEdgeTypesBroadened(t *testing.T) {
	q := controlEdgeTypes()
	for _, want := range []string{"GenericAll", "GenericWrite", "WriteOwner", "WriteDacl", "Owns",
		"ForceChangePassword", "AddMember", "AllExtendedRights", "AddKeyCredentialLink", "AddSelf",
		"WriteSPN", "ReadLAPSPassword", "ReadGMSAPassword", "SyncLAPSPassword"} {
		if !strings.Contains(q, "'"+want+"'") {
			t.Errorf("controlEdgeTypes() missing %q", want)
		}
	}
	if !strings.Contains(controllableCountQuery(), controlEdgeTypes()) {
		t.Error("FetchControllableCounts query must embed controlEdgeTypes()")
	}
	if !strings.Contains(tier0ControllersQuery(), controlEdgeTypes()) {
		t.Error("tier0ControllersQuery must embed controlEdgeTypes()")
	}
}
```

- [ ] **Step 2: Run → FAIL** (`controlEdgeTypes`/`controllableCountQuery` undefined).

- [ ] **Step 3: Implement** — add to `cypher.go`:

```go
// controlEdgeTypes is the Cypher fragment "['GenericAll','GenericWrite',...]" of AD object-control
// relationship types, shared by the controllable-count and Tier-0 queries so they never drift.
func controlEdgeTypes() string {
	return "['GenericAll','GenericWrite','WriteOwner','WriteDacl','Owns','ForceChangePassword'," +
		"'AddMember','AllExtendedRights','AddKeyCredentialLink','AddSelf','WriteSPN'," +
		"'ReadLAPSPassword','ReadGMSAPassword','SyncLAPSPassword']"
}

func controllableCountQuery() string {
	return `MATCH (u:User)-[r]->(n) WHERE type(r) IN ` + controlEdgeTypes() +
		` WITH u, count(n) as cnt WHERE cnt > 0 RETURN u.samaccountname, u.domain, cnt`
}
```
Then in `FetchControllableCounts`, replace the inline `query := ...` with `query := controllableCountQuery()`,
and in `tier0ControllersQuery()` replace its inline `type(r) IN [...]` with `... IN ` + `controlEdgeTypes()` +
` AND (...)` (keep the Tier-0 predicate). Verify the BHE-CE quirk note (no split/trim) still holds — we
only added edge-type literals, which are fine.

- [ ] **Step 4: Run → PASS**; `go test ./internal/bloodhound/`.

- [ ] **Step 5: Commit** — `feat(bloodhound): shared, broadened control-edge type list`.

---

### Task 2: Tier-0 anchors + per-(domain,anchor) SID cache

**Files:** Create `internal/bloodhound/anchors.go`; Test `internal/bloodhound/anchors_test.go`

- [ ] **Step 1: Failing test** — anchor names present; cache stores/retrieves per (domain, anchor):

```go
func TestTier0AnchorNames(t *testing.T) {
	got := strings.Join(tier0AnchorNames(), ",")
	for _, w := range []string{"DOMAIN ADMINS", "ENTERPRISE ADMINS", "KRBTGT", "ADMINSDHOLDER", "ADMINISTRATORS"} {
		if !strings.Contains(strings.ToUpper(got), w) {
			t.Errorf("tier0AnchorNames missing %q", w)
		}
	}
}
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement** `internal/bloodhound/anchors.go`:

```go
package bloodhound

const tier0SweepMin = 100 // env.Count >= this also sweeps the non-DA Tier-0 anchors

// tier0AnchorNames are the Tier-0 / DA-equivalent objects a candidate's traversable control path is
// checked against (per collected domain). DOMAIN ADMINS is the DA anchor (-> DADomains); any anchor -> ControlsTier0.
func tier0AnchorNames() []string {
	return []string{"DOMAIN ADMINS", "ENTERPRISE ADMINS", "KRBTGT", "ADMINSDHOLDER", "ADMINISTRATORS"}
}
// The Domain object (DCSync) anchor is resolved separately (it's a Domain node, not a Group) — see EnrichCandidate.
```
Generalize the SID cache: in `bloodhound.go`, the existing `daGroups map[string]string` + `cachedDAGroup`/
`setDAGroup` are keyed by domain only. Add a sibling `anchorSID(domain, anchorName string) (string, bool)` /
`setAnchorSID` keyed by `domain+"|"+anchorName` (reuse `domMu`; lazily init a `anchorSIDs map[string]string`).
Resolve an anchor's SID via `GetGroup(anchorName+"@"+domain)` (and `GetUserFull`/search for KRBTGT which is a
User; the Domain object via `GetDomains`/search) — cache hits and misses (`""`).

- [ ] **Step 4: Run → PASS.**

- [ ] **Step 5: Commit** — `feat(bloodhound): Tier-0 anchor set + per-anchor SID cache`.

---

### Task 3: `candidateClient` interface (test seam)

**Files:** Create `internal/bloodhound/client_iface.go`; modify `bulk_enricher.go` (field type)

- [ ] **Step 1:** Define the minimal interface the candidate enrichment needs, satisfied by `*Client`:

```go
// candidateClient is the subset of *Client used by per-candidate enrichment, so tests can inject a fake.
type candidateClient interface {
	GetUserControllables(objectID string) (map[string]map[string]int, map[string][]ControllableItem, int, error)
	GetShortestPath(src, dst string) (hasPath, known bool, err error)
	GetGroup(name string) (searchHit, bool, error)
	GetDomains() ([]Domain, error)
	anchorSID(domain, anchorName string) (string, bool)
	setAnchorSID(domain, anchorName, sid string)
}
```
Change `BulkEnricher.client *Client` → `client candidateClient` (the existing `*Client` satisfies it once
the anchor methods from Task 2 exist). `NewBulkEnricher(c *Client)` still takes `*Client`. Add a
`newBulkEnricherWithClient(c candidateClient)` test constructor.

- [ ] **Step 2:** `go build ./...` → PASS (interface satisfied). No behavior change yet.

- [ ] **Step 3: Commit** — `refactor(bloodhound): candidateClient interface seam for testable enrichment`.

---

### Task 4: `EnrichCandidate` — true count + reachable Tier-0/DA (per user)

**Files:** `internal/bloodhound/anchors.go`; Test `internal/bloodhound/anchors_test.go` (fake client)

- [ ] **Step 1: Failing test** with a fake client where a user has `env.Count=4000`, a traversable path to
  the DA group + Domain object, and is checked:

```go
func TestEnrichCandidateTransitive(t *testing.T) {
	fc := newFakeClient() // returns env.Count=4000 for "u-sid"; path to DA group + KRBTGT true
	total, daDomains, t0 := enrichCandidate(fc, "u-sid", []string{"CORP.LOCAL"})
	if total != 4000 { t.Errorf("total=%d want 4000", total) }
	if len(daDomains) != 1 || daDomains[0] != "CORP.LOCAL" { t.Errorf("daDomains=%v want [CORP.LOCAL]", daDomains) }
	if !t0 { t.Error("controlsTier0=false want true (path to a Tier-0 anchor)") }
	// env.Count == 0 -> no reachability calls, no DA, no Tier-0
	total2, da2, t02 := enrichCandidate(fc, "no-control-sid", []string{"CORP.LOCAL"})
	if total2 != 0 || len(da2) != 0 || t02 { t.Errorf("zero-control candidate should get no reachability") }
}
```
(Define a `fakeClient` in the test implementing `candidateClient`: `GetUserControllables` returns the
seeded total; `GetShortestPath` returns seeded path booleans by (src,dst); `GetGroup`/`GetDomains`/anchor
cache resolve anchor SIDs.)

- [ ] **Step 2: Run → FAIL** (`enrichCandidate` undefined).

- [ ] **Step 3: Implement** `enrichCandidate(c candidateClient, objectID string, domains []string) (total int, daDomains []string, controlsTier0 bool)`:
  1. `_, _, total, err := c.GetUserControllables(objectID)`; on err or `total==0`, return `(total,nil,false)`
     — the `env.Count > 0` gate (spec §2.3): no transitive control ⟹ no control-path possible.
  2. For each domain: resolve+cache the DA-group SID (`anchorSID`/`GetGroup("DOMAIN ADMINS@"+domain)`);
     `GetShortestPath(objectID, daSID)` traversable → append domain to `daDomains` AND set `controlsTier0=true`.
  3. If `total >= tier0SweepMin`: for each remaining anchor in `tier0AnchorNames()[1:]` + the Domain object,
     resolve+cache its SID and `GetShortestPath(objectID, anchorSID)`; any traversable path → `controlsTier0=true`.
     (Short-circuit once `controlsTier0` is true to save calls.)
  Resolve anchor SIDs through the cache so repeated candidates don't re-search. Handle indeterminate
  (`known==false`) as "no path" (best-effort, matching `ProcessUserDAPath`).

- [ ] **Step 4: Run → PASS.**

- [ ] **Step 5: Commit** — `feat(bloodhound): enrichCandidate — true env.Count + reachable Tier-0/DA sweep`.

---

### Task 5: `EnrichCandidates` — deduped candidate set + gate fix + cache override

**Files:** `internal/bloodhound/bulk_enricher.go`; Test `internal/bloodhound/bulk_enricher_test.go`

- [ ] **Step 1: Failing test** (fake client + `newBulkEnricherWithClient`): seed `Props` (with objectIDs)
  and bulk maps where the 4k user has first-degree `Controllables=0`; build the candidate input with that
  user cracked; assert after `EnrichCandidates` the bulk cache has `Controllables[key]=4000`,
  `DAUsers[key]` set, `Tier0[key]=true` — i.e. the reported bug is fixed despite first-degree=0. Also
  assert: an account both cracked AND HIBP is enriched once (call count == 1 via a counting fake);
  roastable (hasSPN) non-cracked account is included; a non-candidate is not enriched.

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement** — replace `CheckDAForAccounts` with:

```go
// EnrichCandidates corrects the credential-obtainable subset with true transitive control + reachable
// Tier-0/DA. Candidate = cracked OR HIBP OR roastable (hasSPN/dontReqPreauth), deduped by key.
func (b *BulkEnricher) EnrichCandidates(accounts []struct {
	Key string; Cracked, HIBPHit bool
}) {
	domains := b.collectedDomains() // from GetDomains(), Collected==true (cache once)
	seen := map[string]struct{}{}
	for _, a := range accounts {
		if _, dup := seen[a.Key]; dup { continue }
		p, ok := b.data.Props[normKey(a.Key)]
		if !ok || p.ObjectID == "" { continue }
		roastable := p.HasSPN || p.DontReqPreauth
		if !a.Cracked && !a.HIBPHit && !roastable { continue } // candidate gate (NO first-degree-count gate)
		seen[a.Key] = struct{}{}
		total, da, t0 := enrichCandidate(b.client, p.ObjectID, domains)
		k := normKey(a.Key)
		if total > 0 { b.data.Controllables[k] = total } // override first-degree baseline
		if len(da) > 0 { b.data.DAUsers[k] = appendUnique(b.data.DAUsers[k], da...) }
		if t0 { b.data.Tier0[k] = true }
	}
	log.Printf("bloodhound: enriched %d credential-obtainable candidates (true control + reachable Tier-0/DA)", len(seen))
}
```
`normKey` = the lowercase-sam@UPPER-domain normalization already inlined in `Lookup`/`Tier0` (extract it
to a shared helper). Delete the old first-degree gate (`if _, hasCtrl := b.data.Controllables...`). Keep
`HIBPHit` as `a.HIBPBreached`; drop the separate `Shared` candidate (per spec, shared-only isn't a
candidate). The remaining `CheckDAPathsREST`/`ProcessUserDAPath` helpers may stay (used by `enrichCandidate`'s
DA step indirectly) or be folded in — keep whichever the build needs green.

- [ ] **Step 4: Run → PASS**; `go test ./internal/bloodhound/`.

- [ ] **Step 5: Commit** — `feat(bloodhound): EnrichCandidates — deduped cracked∪HIBP∪roastable, gate fixed, env.Count override`.

---

### Task 6: Wire into the enrich job

**Files:** `internal/enrich/job.go`; Test `internal/enrich/job_test.go`

- [ ] **Step 1:** Update the `relevant` slice build (job.go ~167-189) to the new shape `{Key string;
  Cracked, HIBPHit bool}` (drop `Shared`; roastable is derived inside `EnrichCandidates` from props), and
  call `bbe.Bulk.EnrichCandidates(relevant)` instead of `CheckDAForAccounts`. Update progress messages
  ("Enriching credential-obtainable accounts (true control + reachable Tier-0/DA)…"). Keep the
  RescoreWith/Mutate flow unchanged — corrected bulk maps flow through `Lookup`/`Tier0` automatically.

- [ ] **Step 2:** Extend `job_test.go` (or add one) asserting the enrich job, given a fake bulk enricher
  whose candidate gets `enrichCandidate` → 4000/DA/Tier0, produces an Account with `Controlled==4000`,
  `HasDAPathway()==true`, `ControlsTier0==true`, and a **Critical** RiskLevel after rescore. Run → green.

- [ ] **Step 3: Gates** — `gofmt -l cmd internal`, `go build/vet/test ./...`, `govulncheck`.

- [ ] **Step 4: Commit** — `feat(enrich): use EnrichCandidates (transitive control + reachable Tier-0/DA)`.

---

### Task 7: End-to-end synthetic verification + logging polish

**Files:** none new (uses the disposable `:8444` seed); optional log tweaks

- [ ] **Step 1:** Build (`build-and-run` skill) and run a **synthetic** BloodHound-enabled disposable
  instance (NOT the user's live data) seeded so one cracked user has transitive (group-delegated) control
  of a Tier-0 object + a DA path; enrich; confirm that user scores **Critical** with `Controlled` = the
  true total and a DA path. (If standing up a synthetic BHE graph is impractical locally, rely on the
  Go-level fake-client tests as the gate and hand the live check to the user.)

- [ ] **Step 2:** Confirm the one-line summary log (candidates, controllables fetched, reachability sweeps,
  anchors hit, elapsed) is emitted so cost is visible. No silent caps beyond `env.Count>0` / `tier0SweepMin`.

- [ ] **Step 3: Commit** (if any tweaks) — `chore(bloodhound): enrichment cost logging`.

---

## After all tasks
Dispatch a whole-branch review (opus). Then superpowers:finishing-a-development-branch → merge to main +
tag (next minor, e.g. v2.29.0). **PUSH BLOCKER:** main still carries the sanitized exports in history
(commit 8ff0007) — scrub history (filter-repo/filter-branch) BEFORE any push or GitHub release. The user
validates the fix on their **live** BloodHound (their reported 4k-control/DA user should flip to Critical).

## Self-review notes
- Spec coverage: edge-list (T1), anchors+cache (T2), test seam (T3), true count + reachability (T4),
  candidate dedup + gate fix + override (T5), wiring (T6), verification (T7). ✓
- `env.Count > 0` gate (T4) is the safe reachability bound (no control ⟹ no control-path); DA *membership*
  remains covered by Phase-1 `FetchDAUsers`. ✓
- Per-account scoring engine + executive rollup unchanged — fix only feeds correct inputs. ✓
