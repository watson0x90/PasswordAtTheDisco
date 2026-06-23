# BloodHound user-properties upload fidelity — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `/api/upload/bheusers` (SharpHound/BHE *users* export) a faithful enrichment source — uploaded AD properties (now including SPN/AS-REP) survive a Recalculate instead of being silently wiped, drive the Exposure-axis age/roastable signals and the disabled-latent-risk badge while Impact correctly stays Unknown, and a lead is nudged to recalculate after an upload.

**Architecture:** Three small Go changes + one web wiring change. (1) `bloodhound.ParseUsersExport` + `handleUploadBHEUsers` learn `hasspn`/`dontreqpreauth`. (2) `rescore.NewStoredEnricher` reconstructs persisted properties for **every** account, gating only the `Enriched` bit (→ Impact-known) on `Coverage=="full"` — this is the root-cause fix for the wipe. (3) The BloodHound upload UI reuses the existing `RecalcNudge`.

**Tech Stack:** Go 1.26 stdlib (`encoding/json`, `testing`); React 18 + TS + Vite (Vitest).

**Spec:** `docs/superpowers/specs/2026-06-22-bheusers-upload-fidelity-design.md`

## File Structure
- `internal/bloodhound/import.go` — `ImportedUser` struct + the SharpHound / BHE-`props` / simplified parser shapes gain `hasspn`/`dontreqpreauth`. (Task 1)
- `internal/bloodhound/import_test.go` (new) — parser unit tests. (Task 1)
- `internal/httpapi/server.go` — `handleUploadBHEUsers` merge loop sets `HasSPN`/`DontReqPreauth`. (Task 2)
- `internal/httpapi/server_test.go` — handler merge test. (Task 2)
- `internal/rescore/enricher.go` — `NewStoredEnricher` preserve-all + `enrichmentFromAccount` `Enriched` gate. (Task 3)
- `internal/rescore/enricher_test.go` — preservation + Impact-Unknown regression test. (Task 3)
- `web/src/components/BloodHound.tsx` — render `RecalcNudge` after a successful upload. (Task 4)

**Gates (repo root):** `gofmt -l cmd internal` · `go build ./...` · `go vet ./...` · `go test ./...` · `govulncheck ./...`. Web (in `web/`, NEVER `npm install`): `npx tsc --noEmit` · `npx vitest run` · `npm run build`.

**Branch:** `fix/bheusers-upload-fidelity` (already created). Every implementer: run `git branch --show-current`, confirm it equals `fix/bheusers-upload-fidelity`; NEVER `git checkout`/`switch`/`branch`. Use the Bash tool for git/go (POSIX).

---

## Task 1: Parser — carry `hasspn` / `dontreqpreauth` through `ParseUsersExport`

**Files:**
- Modify: `internal/bloodhound/import.go` (`ImportedUser` struct ~line 14; `parseSharpHound` ~line 56; `parseArray` ~line 94)
- Create: `internal/bloodhound/import_test.go`

- [ ] **Step 1: Write the failing parser tests**

Create `internal/bloodhound/import_test.go`:

```go
package bloodhound

import (
	"strings"
	"testing"
)

func TestParseUsersExportRoastableFields(t *testing.T) {
	// SharpHound collection shape: {"data":[{"Properties":{...},"ObjectIdentifier":"..."}]}
	sharp := `{"data":[
		{"Properties":{"samaccountname":"svc1","domain":"corp.local","enabled":true,"hasspn":true,"dontreqpreauth":false},"ObjectIdentifier":"S-1-1"},
		{"Properties":{"samaccountname":"svc2","domain":"corp.local","enabled":true,"hasspn":false,"dontreqpreauth":true},"ObjectIdentifier":"S-1-2"}
	]}`
	got, err := ParseUsersExport(strings.NewReader(sharp))
	if err != nil {
		t.Fatalf("sharphound parse: %v", err)
	}
	if u := got["svc1@CORP.LOCAL"]; !u.HasSPN || u.DontReqPreauth {
		t.Errorf("svc1 sharphound: HasSPN=%v DontReqPreauth=%v, want true/false", u.HasSPN, u.DontReqPreauth)
	}
	if u := got["svc2@CORP.LOCAL"]; u.HasSPN || !u.DontReqPreauth {
		t.Errorf("svc2 sharphound: HasSPN=%v DontReqPreauth=%v, want false/true", u.HasSPN, u.DontReqPreauth)
	}

	// BHE flat shape: [{"props":{...},"objectid":"..."}]
	bhe := `[{"props":{"samaccountname":"svc3","domain":"corp.local","enabled":true,"hasspn":true,"dontreqpreauth":true},"objectid":"S-1-3"}]`
	got, err = ParseUsersExport(strings.NewReader(bhe))
	if err != nil {
		t.Fatalf("bhe parse: %v", err)
	}
	if u := got["svc3@CORP.LOCAL"]; !u.HasSPN || !u.DontReqPreauth {
		t.Errorf("svc3 bhe: HasSPN=%v DontReqPreauth=%v, want true/true", u.HasSPN, u.DontReqPreauth)
	}

	// Simplified shape: [{"username":"...","domain":"...","hasspn":true,...}]
	simple := `[{"username":"svc4","domain":"CORP.LOCAL","enabled":true,"dontreqpreauth":true}]`
	got, err = ParseUsersExport(strings.NewReader(simple))
	if err != nil {
		t.Fatalf("simple parse: %v", err)
	}
	if u := got["svc4@CORP.LOCAL"]; u.HasSPN || !u.DontReqPreauth {
		t.Errorf("svc4 simple: HasSPN=%v DontReqPreauth=%v, want false/true", u.HasSPN, u.DontReqPreauth)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/bloodhound/ -run TestParseUsersExportRoastableFields -v`
Expected: FAIL — compile error `u.HasSPN undefined (type ImportedUser has no field HasSPN)`.

- [ ] **Step 3: Add the two fields to `ImportedUser`**

In `internal/bloodhound/import.go`, in the `ImportedUser` struct, after the `PwdNeverExpires bool ...` line, add:

```go
	HasSPN          bool   `json:"hasspn"`          // Kerberoastable (SPN set)
	DontReqPreauth  bool   `json:"dontreqpreauth"`  // AS-REP roastable (no pre-auth)
```

- [ ] **Step 4: Parse the fields in `parseSharpHound`**

In `parseSharpHound`, add the two fields to the inner anonymous `Properties` struct (after `LastLogon json.Number ...`):

```go
				HasSPN         bool `json:"hasspn"`
				DontReqPreauth bool `json:"dontreqpreauth"`
```

and in the `ImportedUser{...}` literal it builds, after `LastLogon: windowsEpochToUnix(lastLogon),` add:

```go
				HasSPN:         item.Properties.HasSPN,
				DontReqPreauth: item.Properties.DontReqPreauth,
```

- [ ] **Step 5: Parse the fields in `parseArray` (BHE `props` shape)**

In `parseArray`, add to the inner `bhe.Props` anonymous struct (after `LastLogon json.Number ...`):

```go
				HasSPN         bool `json:"hasspn"`
				DontReqPreauth bool `json:"dontreqpreauth"`
```

and in the `ImportedUser{...}` literal there, after `LastLogon: windowsEpochToUnix(lastLogon),` add:

```go
				HasSPN:         bhe.Props.HasSPN,
				DontReqPreauth: bhe.Props.DontReqPreauth,
```

(The simplified shape unmarshals directly into `ImportedUser`, so the new struct json tags cover it — no extra code.)

- [ ] **Step 6: Run to verify it passes + gofmt**

Run: `go test ./internal/bloodhound/ -run TestParseUsersExportRoastableFields -v` → PASS.
Run: `gofmt -l internal/bloodhound/import.go internal/bloodhound/import_test.go` → prints nothing.
Run: `go test ./internal/bloodhound/` → all green (existing tests unaffected).

- [ ] **Step 7: Commit**

```bash
test "$(git branch --show-current)" = "fix/bheusers-upload-fidelity" || { echo "WRONG BRANCH"; exit 1; }
git add internal/bloodhound/import.go internal/bloodhound/import_test.go
git commit -m "feat(bloodhound): parse hasspn/dontreqpreauth from users export (all 3 shapes)"
```

---

## Task 2: Handler — merge `HasSPN`/`DontReqPreauth` onto accounts

**Files:**
- Modify: `internal/httpapi/server.go` (`handleUploadBHEUsers` merge loop ~lines 1784-1792)
- Test: `internal/httpapi/server_test.go`

- [ ] **Step 1: Write the failing handler test**

Add to `internal/httpapi/server_test.go` (mirrors the `cracksReq`/`TestApplyCracksRecordsIngest` pattern: `newServer` → `loginCSRF` → `createAudit` → `Store.Replace` seed → multipart POST → read accounts back). `model.Account.HasSPN`/`DontReqPreauth` are `*bool`.

```go
func TestUploadBHEUsersMergesRoastable(t *testing.T) {
	srv := newServer("secret")
	srv.Engine = &engine.Engine{Policies: policy.DefaultSet()}
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	id := createAudit(t, srv, lc, lcsrf, "BHE Test")

	if err := srv.Store.Replace(id, model.Dataset{
		Name:     "BHE Test",
		Accounts: []model.Account{{Username: "svc", Domain: "CORP", NTHash: "ABC"}},
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}

	body := `[{"username":"svc","domain":"CORP","enabled":true,"hasspn":true,"dontreqpreauth":true}]`
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("bheusers", "users.json")
	_, _ = io.WriteString(fw, body)
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/api/upload/bheusers", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(lc)
	req.Header.Set("X-CSRF-Token", lcsrf)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bheusers upload: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	accts, err := srv.Store.Accounts(id, false)
	if err != nil {
		t.Fatalf("read accounts: %v", err)
	}
	if len(accts) != 1 {
		t.Fatalf("want 1 account, got %d", len(accts))
	}
	a := accts[0]
	if a.HasSPN == nil || !*a.HasSPN {
		t.Errorf("HasSPN = %v, want &true", a.HasSPN)
	}
	if a.DontReqPreauth == nil || !*a.DontReqPreauth {
		t.Errorf("DontReqPreauth = %v, want &true", a.DontReqPreauth)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/httpapi/ -run TestUploadBHEUsersMergesRoastable -v`
Expected: FAIL — `HasSPN = <nil>, want &true` (handler doesn't merge these yet).

- [ ] **Step 3: Merge the two fields in the handler**

In `internal/httpapi/server.go`, in `handleUploadBHEUsers`, inside the `Store.Mutate` loop, after the existing `Controlled` merge block (`if imp.Controllables > 0 { next[i].Controlled = imp.Controllables }`), add:

```go
				spn := imp.HasSPN
				next[i].HasSPN = &spn
				preauth := imp.DontReqPreauth
				next[i].DontReqPreauth = &preauth
```

(The export is authoritative for these flags — `false` legitimately means "known not roastable" — so set them unconditionally for every matched account, unlike `Controllables` where `0` means "unknown".)

- [ ] **Step 4: Run to verify it passes + gates**

Run: `go test ./internal/httpapi/ -run TestUploadBHEUsersMergesRoastable -v` → PASS.
Run: `gofmt -l internal/httpapi/server.go internal/httpapi/server_test.go` → nothing.
Run: `go test ./internal/httpapi/` → all green.

- [ ] **Step 5: Commit**

```bash
test "$(git branch --show-current)" = "fix/bheusers-upload-fidelity" || { echo "WRONG BRANCH"; exit 1; }
git add internal/httpapi/server.go internal/httpapi/server_test.go
git commit -m "feat(httpapi): bheusers upload merges HasSPN/DontReqPreauth onto accounts"
```

---

## Task 3: Rescore — preserve persisted properties (the wipe fix)

**Files:**
- Modify: `internal/rescore/enricher.go` (`NewStoredEnricher` ~lines 24-35; `enrichmentFromAccount` `Enriched` field ~line 58)
- Test: `internal/rescore/enricher_test.go`

- [ ] **Step 1: Write the failing preservation test**

Add to `internal/rescore/enricher_test.go` (the file already imports `engine`, `model`; `ip`/`bp` helpers may not exist here — use literals as shown):

```go
func TestStoredEnricherPreservesPropsForPartialCoverage(t *testing.T) {
	// A Coverage:"none" account that nonetheless carries uploaded AD properties
	// (from /api/upload/bheusers) must keep them through a rescore, while Impact
	// stays Unknown (Enriched=false). This is the bheusers-upload-fidelity fix.
	spn := false
	preauth := true
	old := int64(1_600_000_000) // a real, non-zero pwdlastset
	a := model.Account{
		Username:       "svc",
		Domain:         "CORP",
		Coverage:       "none", // NOT DA-graph enriched
		Enabled:        false,  // uploaded: disabled
		Controlled:     50,     // uploaded: controls 50 objects
		PwdLastSet:     old,    // uploaded: an old password
		HasSPN:         &spn,
		DontReqPreauth: &preauth, // uploaded: AS-REP roastable
	}
	enr := NewStoredEnricher([]model.Account{a}).Enrich(engine.NormalizeUsername("svc", "CORP"))

	if enr.Enriched {
		t.Fatal("Coverage=none must yield Enriched=false (Impact stays Unknown)")
	}
	if enr.Enabled == nil || *enr.Enabled {
		t.Errorf("Enabled = %v, want &false (preserved)", enr.Enabled)
	}
	if enr.ControlledObjects == nil || *enr.ControlledObjects != 50 {
		t.Errorf("ControlledObjects = %v, want &50 (preserved)", enr.ControlledObjects)
	}
	if enr.PwdLastSet == nil || *enr.PwdLastSet != old {
		t.Errorf("PwdLastSet = %v, want &%d (preserved)", enr.PwdLastSet, old)
	}
	if enr.DontReqPreauth == nil || !*enr.DontReqPreauth {
		t.Errorf("DontReqPreauth = %v, want &true (preserved)", enr.DontReqPreauth)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/rescore/ -run TestStoredEnricherPreservesPropsForPartialCoverage -v`
Expected: FAIL — `Enabled = <nil>, want &false` (current `NewStoredEnricher` returns a blank `Enrichment{Enriched:false}` for Coverage!="full", dropping all props).

- [ ] **Step 3: Make `enrichmentFromAccount` gate `Enriched` on Coverage**

In `internal/rescore/enricher.go`, in `enrichmentFromAccount`, change the hardcoded field:

```go
		Enriched:        true,
```

to:

```go
		Enriched:        a.Coverage == "full",
```

- [ ] **Step 4: Make `NewStoredEnricher` reconstruct for every account**

Replace the body of `NewStoredEnricher`:

```go
func NewStoredEnricher(accts []model.Account) StoredEnricher {
	m := make(StoredEnricher, len(accts))
	for _, a := range accts {
		key := engine.NormalizeUsername(a.Username, a.Domain)
		if a.Coverage != "full" {
			m[key] = engine.Enrichment{Enriched: false}
			continue
		}
		m[key] = enrichmentFromAccount(a)
	}
	return m
}
```

with:

```go
func NewStoredEnricher(accts []model.Account) StoredEnricher {
	m := make(StoredEnricher, len(accts))
	for _, a := range accts {
		key := engine.NormalizeUsername(a.Username, a.Domain)
		// Reconstruct persisted AD properties for EVERY account so a rescore does not
		// wipe properties uploaded via /api/upload/bheusers. enrichmentFromAccount sets
		// Enriched = (Coverage=="full"), so Impact stays Unknown for partial-coverage
		// accounts while their Exposure-axis props (age, roastability) and Enabled/
		// Controlled survive.
		m[key] = enrichmentFromAccount(a)
	}
	return m
}
```

Also update the doc-comment above `NewStoredEnricher` (currently says "otherwise it stores the zero value") to: `For every account it reconstructs the persisted AD properties; the Enriched bit (=> Impact-known) is set only when Coverage=="full", so a partial-coverage account keeps Impact Unknown but its uploaded properties survive.`

- [ ] **Step 5: Run the new test + the existing rescore tests**

Run: `go test ./internal/rescore/ -v`
Expected: PASS — the new test passes, and `TestStoredEnricherUnenrichedStaysUnknown` (asserts Coverage="none" ⇒ `Enriched=false`) and `TestImpactEquivalenceAfterRescore` (Coverage="none" ⇒ Impact-Unknown) still pass (the `Enriched` gate preserves both). If `TestStoredEnricherUnenrichedStaysUnknown`'s fixture (a `{Coverage:"none"}` account with zero-value `Enabled:false`) now also exercises the Enabled path, it still only asserts `Enriched`, so it remains green.

- [ ] **Step 6: Full repo gate (catches any engine/store golden touching these paths)**

Run: `gofmt -l cmd internal` (empty) · `go build ./...` · `go vet ./...` · `go test ./...`
Expected: all green. If a store/engine test that rescored a Coverage="none" account asserted `Enabled==true` post-rescore, that account must have had `Enabled:true` persisted (real unenriched default) — re-check, don't weaken; truly-unenriched accounts are unchanged.

- [ ] **Step 7: Commit**

```bash
test "$(git branch --show-current)" = "fix/bheusers-upload-fidelity" || { echo "WRONG BRANCH"; exit 1; }
git add internal/rescore/enricher.go internal/rescore/enricher_test.go
git commit -m "fix(rescore): preserve uploaded AD props on rescore; gate Enriched on Coverage (no more wipe)"
```

---

## Task 4: Web — nudge a recalculate after a bheusers upload

**Files:**
- Modify: `web/src/components/BloodHound.tsx` (the user-data upload sub-component — the one with the `result` state + "Upload user data" button, ~lines 245-277)

- [ ] **Step 1: Add the import**

In `web/src/components/BloodHound.tsx`, near the other component imports, add:

```tsx
import { RecalcNudge } from "./RecalcNudge"
```

- [ ] **Step 2: Render the nudge after a successful upload**

In the upload sub-component's returned JSX, immediately after the `{result && <div className="ingest-ok">✓ {result}</div>}` line, add:

```tsx
      <RecalcNudge saved={!!result} />
```

This mirrors `Policies.tsx` (`<RecalcNudge saved={!!okMsg} />`): `RecalcNudge` is lead-only, hidden until `result` is set (upload succeeded) and while a rescore runs, and provides the one-click "Recalculate scoring →" that applies the merged properties. No new CSS (it uses the existing `coverage-banner` classes).

- [ ] **Step 3: Verify the web gates**

Run (in `web/`): `npx tsc --noEmit` · `npx vitest run` · `npm run build`
Expected: tsc clean, all vitest pass (the existing `rescoreUi`/`RecalcNudge` tests already cover the nudge logic; no test asserts the BloodHound upload card's child set, so none should need changes — if a snapshot does, update it to include the nudge), build succeeds.

- [ ] **Step 4: Commit**

```bash
test "$(git branch --show-current)" = "fix/bheusers-upload-fidelity" || { echo "WRONG BRANCH"; exit 1; }
git add web/src/components/BloodHound.tsx
git commit -m "feat(web): nudge recalculate after a bheusers user-properties upload"
```

---

## Final verification (after all tasks)
- [ ] **Go gate:** `gofmt -l cmd internal` · `go build ./...` · `go vet ./...` · `go test ./...` · `govulncheck ./...`
- [ ] **Web gate (in `web/`):** `npx tsc --noEmit` · `npx vitest run` · `npm run build`
- [ ] **Live (build-and-run + a BloodHound-on disposable instance, or a synthetic users.json):** upload a users export for accounts that are NOT DA-graph-enriched; click the post-upload **Recalculate** nudge; in an account drawer confirm age + AS-REP (vector `RO:A`) now score, the disabled-latent-risk badge persists, **Impact still reads Unknown**, and a *second* Recalculate no longer wipes the props. Browser console clean.

## Definition of done
Uploaded BloodHound user properties (incl. SPN/AS-REP) survive a Recalculate, drive the Exposure-axis age/roastability signals and the disabled-latent-risk badge, while Impact stays Unknown for accounts without a DA-graph; a lead is nudged to recalculate after an upload. Truly-unenriched accounts and the live BloodHound enrich path are unchanged; all gates green.
