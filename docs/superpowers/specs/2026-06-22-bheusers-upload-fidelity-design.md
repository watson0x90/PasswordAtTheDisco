# BloodHound user-properties upload fidelity — Design

> A correctness fix + capability extension for the `/api/upload/bheusers` path (uploading a
> SharpHound/BHE **users** JSON export to enrich per-account AD properties without a live Neo4j
> query). Found during the F1 (v2.23.0) live verification.

## 1. The bug (root-caused via systematic-debugging)

Uploading user properties via `/api/upload/bheusers` merges `Enabled` / `PwdLastSet` /
`PwdNeverExpires` / `Controlled` onto matched accounts (`handleUploadBHEUsers` → `Store.Mutate`).
But:

1. **`Store.Mutate` does not re-score** (`store.go:512-514` runs only sharing/escalation/percentile,
   never `risk.Score`). So the merged properties never reach Exposure/Impact — **age never applies**
   from an upload.
2. When the operator later clicks **Recalculate**, the rescore builds a `StoredEnricher`.
   `NewStoredEnricher` (`enricher.go:28`) returns a **blank `Enrichment{Enriched:false}`** for any
   account with `Coverage != "full"`. The engine then sources every enrichment field from that blank
   (`engine.go:451-459`): `Enabled→true`, `PwdLastSet→0`, `Controlled→0` — **silently wiping the
   uploaded properties.**

**Root cause (single, at the source):** `NewStoredEnricher` conflates *"is Impact known?"*
(`Coverage=="full"` — was a BloodHound DA-graph collected) with *"does this account have persisted AD
properties worth preserving across a rescore?"*. A users-export upload legitimately produces a
`Coverage="none"` account **with** real properties; the StoredEnricher discards them.

A secondary limitation surfaced by the same investigation: `handleUploadBHEUsers` never merges
`hasspn` / `dontreqpreauth`, even though SharpHound/BHE user exports carry them — so Kerberoast/AS-REP
scoring can only come from a live Neo4j query, not from an export.

## 2. Decisions (scope confirmed with the user)

Fix all three, as one change:

- **(A) Stop the wipe.** `NewStoredEnricher` reconstructs persisted AD properties for **every**
  account; only the `Enriched` bit (→ Impact-known) is gated on `Coverage=="full"`. A partial-coverage
  account keeps **Impact Unknown** (correct — no DA-graph) while its Exposure-axis signals (age,
  roastability) and its `Enabled`/`Controlled` (the disabled-latent-risk badge inputs) survive a
  rescore and get scored.
- **(B) Carry SPN/AS-REP through the upload.** Extend `bloodhound.ParseUsersExport` + the
  `handleUploadBHEUsers` merge to read `hasspn` / `dontreqpreauth`, so the F1 roastable floor/bump
  apply via a users-export upload — not only a live enrich.
- **(C) Apply scoring after upload.** Surface the existing **`RecalcNudge`** after a successful
  bheusers upload (the same one-click "recalculate to apply" affordance used after policy / forbidden-
  words / HIBP edits), so a lead applies the merged properties without guessing. The upload itself
  still doesn't score (consistent with every other scoring-input change in the app — they nudge,
  they don't auto-score).

**Out of scope:** computing controllables / DA-pathways from a SharpHound graph export (needs the live
graph); any change to the Coverage semantics, the Impact axis, or the scoring weights (F1, unchanged).

## 3. Architecture / changes

### 3.1 Parser — `internal/bloodhound/import.go`
- `ImportedUser` struct: add `HasSPN bool \`json:"hasspn"\`` and `DontReqPreauth bool \`json:"dontreqpreauth"\``.
- `parseSharpHound`: add `HasSPN`/`DontReqPreauth` to the inner `Properties` struct (SharpHound user
  Properties use lowercase `hasspn` / `dontreqpreauth`) and copy into `ImportedUser`.
- `parseArray` (BHE `props` shape): same additions on the `props` struct + copy.
- Simplified array shape: handled automatically by the new struct json tags (it unmarshals directly
  into `ImportedUser`).

### 3.2 Handler merge — `internal/httpapi/server.go` `handleUploadBHEUsers`
In the `Store.Mutate` merge loop, after the existing field merges, add (model.Account `HasSPN` /
`DontReqPreauth` are `*bool`; the export value is authoritative — `false` means "known not roastable"):
```go
spn := imp.HasSPN
next[i].HasSPN = &spn
preauth := imp.DontReqPreauth
next[i].DontReqPreauth = &preauth
```

### 3.3 Rescore preservation — `internal/rescore/enricher.go` (the core fix)
```go
func NewStoredEnricher(accts []model.Account) StoredEnricher {
	m := make(StoredEnricher, len(accts))
	for _, a := range accts {
		key := engine.NormalizeUsername(a.Username, a.Domain)
		m[key] = enrichmentFromAccount(a) // reconstruct for ALL accounts
	}
	return m
}
```
and in `enrichmentFromAccount`, replace the hardcoded `Enriched: true` with:
```go
		Enriched: a.Coverage == "full",
```
Everything else in `enrichmentFromAccount` is unchanged (it already reconstructs DADomains, Enabled,
ControlsTier0, HasSPN, DontReqPreauth, PwdNeverExpires, ControlledObjects, PwdLastSet from the
persisted account).

**Why this is safe / correct:**
- `Coverage="full"` → `Enriched=true` → Impact computed. **Unchanged** from today.
- `Coverage="none"` **with** props → `Enriched=false` → `coverageState(false)="none"` → `impactScore`
  returns `known=false` → **Impact stays Unknown**, but `PwdLastSet`→`ageBump`, `HasSPN`/
  `DontReqPreauth`→`roastableFloor`/`roastableBump`, and `Enabled`/`Controlled` all survive.
- `Coverage="none"` with **no** props (truly unenriched): `enrichmentFromAccount` reads zero fields →
  `Enabled=&a.Enabled` (real unenriched accounts persist `Enabled=true` via `enabledOrUnknown(nil)`),
  `PwdLastSet`/`Controlled` nil → behaviour **identical** to the old blank path
  (`enabledOrUnknown(&true)≡enabledOrUnknown(nil)≡true`).

**Accepted consequence:** a partial-coverage account's risk vector now reflects its known props
(e.g. `CO:` a count, `RO:A`) even though it reads "not enriched" — defensible: we know those props;
we don't know the DA-graph / blast radius, which is exactly what `Coverage`/Impact-Unknown conveys.

### 3.4 Apply-scoring nudge — `web/src/components/BloodHound.tsx`
After a successful `uploadBHEUsers`, set a local `saved`-style flag and render
`<RecalcNudge saved={uploaded} />` (import from `./RecalcNudge`). No new component, no new CSS —
reuses the existing lead-only, hidden-until-saved, hidden-while-rescore-runs nudge. Clears/!re-arms on
a fresh upload the same way the other editors drive it.

## 4. Files
- **Go:** `internal/bloodhound/import.go` (struct + 2 parser shapes); `internal/httpapi/server.go`
  (merge 2 fields); `internal/rescore/enricher.go` (preserve-all + `Enriched` gate).
  Tests: `internal/bloodhound/import_test.go`, `internal/httpapi/server_test.go`,
  `internal/rescore/enricher_test.go`.
- **Web:** `web/src/components/BloodHound.tsx` (render `RecalcNudge` after upload). (`RecalcNudge` /
  `rescoreUi` already exist + are tested.)

No new endpoints, no scoring-weight change, no Impact-axis change.

## 5. Testing
- **Parser (Go):** SharpHound, BHE-`props`, and simplified shapes each parse `hasspn`/`dontreqpreauth`
  into `ImportedUser` (true and false/absent cases).
- **Handler (Go):** a bheusers upload merges `HasSPN`/`DontReqPreauth` onto a matching account
  (`*bool` set to the export value); non-matching accounts untouched.
- **Rescore (Go) — the regression test:** an account `Coverage:"none"` carrying `Enabled:false`,
  an old `PwdLastSet`, `Controlled:50`, `DontReqPreauth:true` → `NewStoredEnricher` reconstructs an
  Enrichment with **`Enriched:false`** but those props present; and after a full rescore the account
  **retains** `Enabled=false` / `Controlled=50` / the old `PwdLastSet`, shows `AgePenalty>0` and
  Exposure ≥ the AS-REP floor, while **`ImpactKnown` stays false**. Keep
  `TestStoredEnricherUnenrichedStaysUnknown` and `TestImpactEquivalenceAfterRescore` green
  (Coverage="none" still ⇒ Impact Unknown).
- **Web:** existing `RecalcNudge`/`rescoreUi` tests cover the nudge; add a focused test only if the
  BloodHound upload→`saved` wiring has non-trivial logic (otherwise none).
- **Gates:** `gofmt -l cmd internal`, `go build/vet/test ./...`, `govulncheck`; `tsc`/`vitest`/`build`.
- **Live (build-and-run + a BloodHound-on disposable instance):** upload a SharpHound users export for
  accounts NOT DA-graph-enriched, click the nudge to Recalculate, confirm in a drawer that age +
  AS-REP (RO:A) score, the disabled-latent-risk badge persists, **Impact still reads Unknown**, and a
  second Recalculate no longer wipes the props. Console clean.

## 6. Definition of done
Uploaded BloodHound user properties (incl. SPN/AS-REP) survive a Recalculate instead of being silently
wiped; they drive the Exposure-axis signals (age, roastability) and the disabled-latent-risk badge,
while Impact correctly stays Unknown for accounts without a DA-graph; and a lead is nudged to
Recalculate after an upload so the change actually applies. Truly-unenriched accounts and the live
BloodHound enrich path are unchanged.
