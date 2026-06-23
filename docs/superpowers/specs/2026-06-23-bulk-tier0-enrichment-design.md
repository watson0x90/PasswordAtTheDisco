# Bulk Tier-0 enrichment (Finding 2) — Design

> Sub-project A of the post-v2.25.0 scoring-audit fixes (surfaced by feeding a sanitized export back
> for review). Fixes a documented gap: the **bulk** BloodHound enricher never flags `ControlsTier0`,
> so large audits silently miss the Tier-0 / DA-equivalent privilege signal.

## 1. The gap
BloodHound enrichment has two paths. The **per-user** `BloodhoundEnricher` computes `ControlsTier0`
via `bloodhound.ExtractControlsTier0` — it checks whether any object the user controls is a Tier-0 /
DA-equivalent object (name matches `tier0Names`: *Domain Admins, Enterprise Admins, Domain
Controllers, KRBTGT, AdminSDHolder*) **or** is the domain object itself (control of the domain ⇒
DCSync). The **bulk** path (`BulkBloodhoundEnricher`, used for large audits) hard-codes
`ControlsTier0: false` (engine.go:659) with a comment that the 3-query bulk prefetch "does not
currently collect Tier-0 control edges … until the bulk Cypher is extended (tracked separately)."

Consequence on a real 6,069-account audit: **0 accounts** flagged `controls_tier0`, despite 21 DA
pathways and accounts controlling up to 71,244 objects. Those accounts score privilege from their
controlled-object **count** (→ ~9) but miss the Tier-0 **maximum** (10), the `T0:` vector token, and
the disabled-latent-risk badge's Tier-0 arm.

## 2. Fix
Add a **4th bulk prefetch query** that returns the set of users controlling a Tier-0 object, reusing
the **exact same** Tier-0 definition the per-user path uses (so bulk and per-user agree). Store it in
the bulk cache; `BulkBloodhoundEnricher.Enrich` sets `ControlsTier0` from the set instead of `false`.

**Conservative-by-construction is preserved:** a query error or a miss yields `false` (never a false
positive), exactly as today — the change only adds *true positives* the bulk path was dropping.

## 3. The query
Mirror `FetchControllableCounts` (same control-edge set), but filter to Tier-0 targets and return the
distinct controlling users (no count — presence is all we need):

```cypher
MATCH (u:User)-[r]->(n)
WHERE type(r) IN ['GenericAll','GenericWrite','WriteOwner','WriteDacl','Owns','ForceChangePassword','AddMember']
  AND (n:Domain OR ANY(t IN [<tier0Names>] WHERE toUpper(coalesce(n.name,'')) CONTAINS t))
RETURN DISTINCT u.samaccountname, u.domain
```
- `n:Domain` captures control of the domain object ⇒ DCSync (the per-user path's domain-object rule).
- `[<tier0Names>]` is built **from the `bloodhound.tier0Names` slice** (the single source of truth) so
  the bulk predicate can never drift from `isTier0Name`. The values are hard-coded constants (no user
  input), so building the Cypher list literal from them is injection-safe.
- Same control-edge set as `FetchControllableCounts`, matching how the per-user `ExtractControlsTier0`
  derives Tier-0-ness from the user's controllable items.

## 4. Architecture / files
- **`internal/bloodhound/cypher.go`** — new `FetchTier0Controllers() (map[string]bool, error)`:
  runs the query via `RunCypher`, and parses the result through the **same 3-format dispatch** as
  `FetchControllableCounts` (BHE-CE `literals`, raw `rows`, and `results[].data` tabular), mapping each
  `(sam, domain)` row to `set[normalizeKey(sam,domain)] = true`. (New parse helpers
  `parseTier0Literals` / `parseTier0` / `parseTier0FromResults`, mirroring the controllables ones but
  emitting a `map[string]bool`.)
- **`internal/bloodhound/bulk_enricher.go`** — add `Tier0 map[string]bool` to `BulkEnrichment`; in
  `Prefetch`, call `FetchTier0Controllers` best-effort (on error log + empty map, like
  `FetchControllableCounts`); extend `Lookup(key) (BulkUserProps, []string, int)` to
  `(BulkUserProps, []string, int, bool)` returning `b.data.Tier0[key]`.
- **`internal/engine/engine.go`** — `BulkBloodhoundEnricher.Enrich`: change the single
  `b.Bulk.Lookup(username)` call to capture the 4th return, and set `ControlsTier0: tier0` (deleting the
  hard-coded `false` + its now-stale comment).

`Lookup` has exactly one caller (engine.go:629), so extending its signature is contained.

## 5. Testing
- **Parser (Go):** feed a synthetic BHE-CE response (each of the 3 formats) describing two users — one
  controlling a Tier-0 object, one not — and assert `FetchTier0Controllers` returns a set containing
  only the first (keyed `user@DOMAIN`). Include a domain-object (`:Domain`) control case.
- **Bulk enricher (Go):** a `BulkEnrichment{Tier0: {"svc@CORP": true}}` → `Lookup("svc@CORP")` returns
  `tier0=true`; a user absent from the set → `false`.
- **Engine (Go):** `BulkBloodhoundEnricher.Enrich` over a bulk cache where the user is in the Tier-0 set
  yields `Enrichment.ControlsTier0 == true`; a user not in the set yields `false` (conservative miss).
- **Agreement:** a fixture where the per-user `ExtractControlsTier0` returns true (a controllable named
  "Domain Admins") and the bulk Tier-0 set contains the same user — both paths agree (documents the
  single-source-of-truth intent).
- **Gates:** `gofmt -l cmd internal`, `go build/vet/test ./...`, `govulncheck`.
- **Live:** against the configured BloodHound, run `tools/bhdump` (or a rescore) before/after and
  confirm Tier-0-controlling users now report `controls_tier0=true` and the `T0:` vector token flips;
  confirm a large audit's sanitized export shows non-zero `controls_tier0`. (If the lab has no Tier-0
  control edges, validate the query returns the expected set on a crafted/known node instead.)

## 6. Out of scope
The per-user path (already correct); the scoring formula (`privilegeSubScore` already maps Tier-0 → 10);
Finding 1 (mass-reuse escalation, sub-project B) and Finding 3 (reuse-floor cliff, deferred).

## 7. Definition of done
Large / bulk-enriched audits flag `ControlsTier0` for users who control a Tier-0 / DA-equivalent object,
using the same definition as the per-user path; the bulk path stays conservative on errors/misses; the
`T0:` vector token, the Tier-0 privilege maximum, and the disabled-latent-risk Tier-0 arm now work on
bulk audits. No change to the per-user path or the scoring formula.
