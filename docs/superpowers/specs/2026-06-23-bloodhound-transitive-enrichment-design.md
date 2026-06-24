# BloodHound enrichment: transitive outbound-control + reachable Tier-0/DA — Design

> Root-caused via systematic-debugging: a cracked user with **4k outbound controlled objects + a DA
> path reads "Low"** because the bulk enricher counts only **first-degree** control and that same
> under-count **gates the user out of the DA-path check**. One defect, both symptoms. This fixes the
> enrichment to use BloodHound's **true transitive** outbound-control magnitude and a unified reachable
> Tier-0/DA check, for the credential-obtainable candidate set.

## 1. Problem (confirmed in code, not against live data)
The enrich job uses the **bulk Cypher path** for any real-size audit (`internal/enrich/job.go:155`;
per-user REST is only the slow fallback at `:215`).

1. **First-degree-only control count.** `FetchControllableCounts` (`cypher.go:408`) runs
   `MATCH (u:User)-[r]->(n) WHERE type(r) IN [7 control edges] ... count(n)`. This counts only objects a
   user controls via **one direct edge**. BloodHound's "outbound object control" (the 4k) is the
   **transitive / group-delegated** count — control inherited through group membership and multi-hop
   chains. A user whose control is transitive has **zero** first-degree edges → `Controlled = 0`.
2. **Compounding DA-gate.** `CheckDAForAccounts` (`bulk_enricher.go:107`) only runs the DA shortest-path
   REST check for accounts already in `b.data.Controllables` (the broken first-degree map). `Controlled=0`
   → the user is **skipped** → their DA escalation path is never discovered → `DADomains` empty.
3. **Tier-0 transitivity blind spot.** `FetchTier0Controllers` is likewise first-degree; and the per-user
   controllables **sample** (capped at `controllablesLimit=100`) can miss a Tier-0 object among 4k → a
   transitive DCSync/DA-group/KRBTGT/AdminSDHolder controller is missed.

Net: enriched + `Controlled=0` + no DA + no Tier-0 → Impact scores **Low** → the level matrix caps a
cracked, *apparently* low-impact account at **Low**. The matrix is correct on wrong inputs.

The correct magnitude already exists: per-user REST `/controllables` → `env.Count` (`GetUserControllables`,
`bloodhound.go:394`, *"the real magnitude, not capped"*). The bulk path just never calls it.

## 2. Approach — two-phase enrichment (bulk baseline + per-candidate accurate)
Keep the cheap bulk pass as a best-effort baseline for **all** accounts; correct the accounts that matter
with per-candidate REST. Lower-risk than a transitive Cypher we cannot validate against the live graph.

### 2.1 Phase 1 — Bulk prefetch (all users, unchanged shape, broadened)
- `FetchAllUserProps` → props + objectID for every user (gives `hasSPN`/`dontReqPreauth` → roastable).
- `FetchControllableCounts` (first-degree) → cheap baseline `Controlled` for **non-candidates**.
- `FetchTier0Controllers` + `FetchDAUsers` (DA group membership) → baseline Tier-0 + DA-member flags.
- ⟐ **Broaden the control edge list** in `FetchControllableCounts` AND `tier0ControllersQuery` to add:
  `AllExtendedRights, AddKeyCredentialLink, AddSelf, WriteSPN, ReadLAPSPassword, ReadGMSAPassword,
  SyncLAPSPassword` (kept in one shared `controlEdgeTypes()` constant so both queries stay in sync).
  Strictly-more-correct baseline; cheap.

### 2.2 Candidate set (deduped, computed after Phase 1)
`candidates = cracked ∪ hibp_breached ∪ roastable`, where:
- `cracked`, `hibp_breached` come from the **audit** data (password analysis + HIBP correlation),
- `roastable` = `hasSPN || dontReqPreauth` from **Phase-1 props**.
Built as one `map[accountKey]→objectID` (objectID from Phase-1 props) so an account matching multiple
criteria is enriched **once** — membership is idempotent. Accounts with no objectID/props are skipped.

### 2.3 Phase 2 — Per-candidate accurate enrichment
For each candidate (concurrency-limited via the client semaphore):
1. **True transitive Controlled** — `GetUserControllables(objectID)` → `env.Count`; **override** the
   first-degree baseline `Controlled` with this value. This is the magnitude that drives Impact. Run for
   **every** candidate (it's one call and it's what the reported bug is about).
2. **Unified reachable Tier-0/DA sweep** — traversable shortest-path (`GetShortestPath`,
   `only_traversable=true`) from the candidate to a small set of **Tier-0 anchors** per collected domain:
   `{DOMAIN ADMINS, ENTERPRISE ADMINS, the Domain object (DCSync), KRBTGT, ADMINSDHOLDER, ADMINISTRATORS}`.
   - Path to the **DA group** → record the DA domain in `DADomains` (HasDAPathway).
   - Path to **any** anchor → `ControlsTier0 = true`.
   - Anchor objectIDs/SIDs are resolved per domain **once** and cached (extend the existing
     `cachedDAGroup`/`setDAGroup` cache to all anchors); never re-resolved per candidate.
3. ⟐ **Gate the reachability sweep on the TRUE count** — run step 2 only for candidates with
   `env.Count > 0`. Rationale: a traversable *control*-path to DA/Tier-0 requires the user to have some
   transitive outbound control, so `env.Count == 0` ⟹ no control-path is possible (pure DA *membership*
   is already captured by Phase 1's Cypher) — this is a safe gate with no false negatives, and it bounds
   the expensive calls to only candidates that actually control something. This is **not** the old bug:
   the old gate used the *broken first-degree* count (0 for transitive controllers); this gate uses the
   *true transitive* `env.Count` (4,000 for the reported account — it passes). To further bound cost,
   the **DA-group anchor** is always checked when `env.Count > 0`; the **remaining anchors** (KRBTGT,
   AdminSDHolder, Domain, EA, Administrators) are swept only when `env.Count ≥ tier0SweepMin` (default
   100, the existing high-controlled threshold) — the users who realistically control a Tier-0 object.

### 2.4 The gate fix (the core bug)
Candidacy is the §2.2 set — **not** "appears in the first-degree `Controllables` map." This is what lets
a transitive-only controller into both the accurate-count step and the reachability sweep. Remove the
`if _, hasCtrl := b.data.Controllables[a.Key]; !hasCtrl { continue }` gate (`bulk_enricher.go:107`); the
credential-relevance + roastable conditions remain.

## 3. Data flow & wiring
- `internal/bloodhound/cypher.go` — `controlEdgeTypes()` shared constant; broaden `FetchControllableCounts`
  + `tier0ControllersQuery`. Add anchor-SID resolution/caching for the Tier-0 anchor set.
- `internal/bloodhound/bloodhound.go` — a per-candidate `EnrichCandidate(objectID, domains)` helper that
  returns `(controlledTotal int, daDomains []string, controlsTier0 bool)` using `GetUserControllables`
  (env.Count) + the anchor shortest-paths. Reuses `GetShortestPath`, `cachedDAGroup`→generalized anchor cache.
- `internal/bloodhound/bulk_enricher.go` — `CheckDAForAccounts` → generalize to `EnrichCandidates`:
  build the deduped candidate set (§2.2), run Phase-2 per candidate, and write results into the bulk
  cache: override `Controllables[key]` with the true total, append `DAUsers[key]`, set `Tier0[key]`.
  Remove the first-degree gate. `Lookup` then surfaces the corrected `Controlled`/DA/Tier0 at rescore.
- `internal/enrich/job.go` — call the generalized `EnrichCandidates(relevant)` (the `relevant` slice
  already carries Cracked/Shared/HIBP; add `Roastable` from props, or compute roastable inside the
  enricher from `b.data.Props`). Progress messaging updated ("enriching N credential-relevant accounts…").
- `internal/risk` — unchanged; it already consumes `ControlledObjects`/`DADomains`/`ControlsTier0`. The
  fix is purely feeding it correct inputs.

No change to the scoring engine, the two-axis model, or the executive rollup.

## 4. Performance
The bulk Phase 1 is unchanged (3-4 Cypher queries). Phase 2 adds **1 controllables call per candidate**
(~1,200 for the reference audit), then reachability shortest-paths **only for candidates with
`env.Count > 0`** (the subset that actually controls something — typically far smaller than the full
candidate set), with the DA-group anchor always and the remaining anchors only for high-controllers
(`env.Count ≥ tier0SweepMin`). All concurrency-limited by the existing client semaphore; anchor SIDs
cached per domain. Expected wall-clock: a few minutes for a ~6k-account audit — slower than the (broken)
all-Cypher path, which is the accepted price of correctness (the DA-path REST loop already incurs
per-candidate cost today). ⟐ **Log a one-line summary** (candidates, controllables fetched, reachability
sweeps run, anchors hit, elapsed) so the cost is visible. No silent caps beyond the documented
`env.Count > 0` and `tier0SweepMin` gates, which are logged.

## 5. Testing (synthetic only — no live BloodHound)
- **Unit (Go), fake client:** a `fakeBHClient` implementing the client surface (`GetUserControllables`,
  `GetShortestPath`, props, anchor resolution) seeded so that a transitive-only controller returns
  `env.Count=4000`, a traversable path to the DA group + Domain object, and **zero** first-degree edges.
  Assert the enricher yields `Controlled=4000`, `DADomains=[domain]`, `ControlsTier0=true` for that user —
  i.e. the exact reported case now scores correctly. Cover: candidate dedup (cracked∧HIBP → one call);
  the gate fix (transitive-only controller is enriched despite first-degree=0); the `tier0SweepMin` gate
  (low-controller skips the full anchor sweep but still gets DA-group check); roastable inclusion.
- **`NewBulkEnricherFromData`** seam keeps the cache injectable for `Lookup`/`Tier0` assertions.
- **Edge-list test:** `controlEdgeTypes()` contains the broadened set; both queries embed it.
- **Regression:** existing `bloodhound`/`enrich` tests stay green; `parseControllables*`/`parseTier0*`
  unchanged. End-to-end: enrich a synthetic dataset on the disposable `:8444` instance with a crafted
  BloodHound that has a transitive 4k-controller, confirm it scores Critical (NOT via the user's live data).
- **Gates:** `gofmt -l cmd internal`, `go build/vet/test ./...`, `govulncheck`; web unaffected.
- **Live validation:** the user re-enriches their real audit and confirms the reported account now reads
  Critical with the true Controlled count + DA path (I do not touch live data).

## 6. Definition of done
The bulk enricher fetches **true transitive** outbound-control (`env.Count`) and a unified traversable
Tier-0/DA reachability for the deduped **cracked ∪ HIBP ∪ roastable** candidate set; the DA/Tier-0 check
is **no longer gated** on the first-degree count; the first-degree edge list is broadened; Tier-0
transitivity is detected via anchor shortest-paths (magnitude-gated for cost). A cracked user with 4k
transitive controlled objects + a DA path scores **Critical**, not Low. Cost is bounded, logged, and
synthetic-tested; the user validates on live data. Per-account scoring engine and executive rollup
unchanged. Likely ships under its own tag after the pending v2.28.0.

## 7. Open / explicitly out of scope
- Replacing the bulk first-degree Cypher with a **transitive Cypher** (Approach B) — rejected: BHE CE
  Cypher limits + unvalidatable against the live graph. Per-user REST `env.Count` is the proven source.
- Accurate transitive Controlled for **non-candidate** (uncracked, non-HIBP, non-roastable) accounts —
  out of scope; they keep the first-degree baseline and, per the firm reachability rule, don't rank anyway.
- The anchor set is configurable; starting set is the six above. Add/trim during review if the live graph
  shows gaps.
