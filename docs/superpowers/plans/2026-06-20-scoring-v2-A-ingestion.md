# Scoring Engine v2 — Sub-project A: BloodHound Ingestion Correctness — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to execute this plan — dispatch a fresh implementer subagent per task, each doing strict TDD (failing test → run/verify red → minimal impl → run/verify green → commit), followed by a spec-then-quality review before the next task. Do not batch tasks; keep the tree green and shippable after every commit.

**Goal:** Produce trustworthy per-account Impact signals from BloodHound — the *true* controlled-objects count, Tier-0/DA-equivalent control, live-path roastable flags, and per-account coverage state — without touching any scoring formula.

**Architecture:** This is the ingestion half of the two-axis (Exposure × Impact) rewrite: `internal/bloodhound` learns to surface the API's real `env.Count` and retain controllable object names/labels for Tier-0 detection; `internal/engine` threads roastable flags onto the live enrich path and stamps an `Enriched` coverage bit; `internal/model.Account` gains a redaction-safe `coverage` field. Every change is additive and independently shippable — the `risk` package (sub-project B) is **not** touched, and no score number changes.

**Tech Stack:** Go (stdlib-first; only `golang.org/x/crypto` is an external dep, unused here), CGO-free static binary, table-driven `testing` with `net/http/httptest` for the BHE client. Windows dev box; tests run via `go test ./...` from the repo root.

---

## File Structure

| File | Responsibility | Change in A |
|---|---|---|
| `internal/bloodhound/bloodhound.go` | BHE REST client + per-user enrichment aggregation (`UserData`, extractors) | Add `ControllableTotal` + `Controllables[].Items` (name/label); thread `env.Count`; new `ExtractControlsTier0`; `ExtractControllableCount` returns true total; add roastable fields to `UserProps`; raise default `controllablesLimit` 10→100 |
| `internal/bloodhound/bloodhound_test.go` | httptest-driven client tests (MIRROR existing harness: `newTestClient`, `verifySig`, `splitHostPort`) | New tests for count-from-`Count`, Tier-0 detection, roastable decode |
| `internal/engine/engine.go` | Audit orchestration; `Enrichment`, `BloodhoundEnricher.Enrich`, `BulkBloodhoundEnricher.Enrich`, `scoreCracked`, `scoreUncracked` | Add `Enriched` to `Enrichment`; set roastable + `Enriched` on the live path; set `Enriched` on the bulk path; set `Account.Coverage` in both scorers |
| `internal/engine/engine_test.go` | Pipeline tests (MIRROR existing: `fakeEnricher`, `newEngine`, `bp`/`ipv` helpers) | New tests for coverage="full"/"none" |
| `internal/model/model.go` | API data types; `Account`, `Redacted()` | Add `Coverage string json:"coverage,omitempty"` (redaction-safe; no `Redacted()` change) |
| `internal/model/model_test.go` | model tests | Confirm `Coverage` survives `Redacted()` |

---

## Task ordering (each leaves the tree green and shippable)

1. **Task 1** — real controllables count via `env.Count` (kills the 10-cap).
2. **Task 2** — retain object names/labels + Tier-0 / DA-equivalent detection; raise default limit 10→100.
3. **Task 3** — roastable flags on the LIVE `BloodhoundEnricher.Enrich` path.
4. **Task 4** — per-account coverage state (`Enrichment.Enriched` → `Account.Coverage`).
5. **Task 5** — sub-project A acceptance gate (full build/vet/test/gofmt/govulncheck) + handoff note on `EscalateSharedWithDA`.

### Gates (run before EVERY commit — never `git commit --no-verify`)

```
gofmt -l cmd internal          # must print nothing
go build ./... && go vet ./... && go test ./...
govulncheck ./...              # must be clean
```

---

### Task 1 — Real controllables count via `env.Count`

**Why:** `GetUserControllables` (bloodhound.go:387) parses only the limited item page and `ExtractControllableCount` (bloodhound.go:596) sums it, so the count is capped at `controllablesLimit` (default 10) and the API's true total in `env.Count` is discarded. The privilege tiers in `risk.go` (`>10/>50/>100/...`) are therefore structurally unreachable. Fix: thread `env.Count` out of `GetUserControllables`, store it on `UserData.ControllableTotal`, set it in `GetUserData`, and make `ExtractControllableCount` return the true total (falling back to the summed label map only when the total is 0/absent).

**Files:**
- Modify: `internal/bloodhound/bloodhound.go`
  - `GetUserControllables` signature + body (current lines 385–425) → also return the envelope `Count`.
  - `UserData` struct (current lines 510–516) → add `ControllableTotal int`.
  - `GetUserData` (current lines 521–579, esp. the `byCount, err := c.GetUserControllables(sid)` call at 542) → capture and store the total.
  - `ExtractControllableCount` (current lines 595–607) → return `ControllableTotal` when > 0, else sum the labels.
- Test: `internal/bloodhound/bloodhound_test.go` (new `TestExtractControllableCountUsesTotal`, `TestGetUserDataCountFromEnvelope`; mirror `newTestClient` / `verifySig` / `TestGetUserDataEndToEnd`).

#### Steps

- [ ] **Step 1: Write the failing unit test for `ExtractControllableCount` true-total preference.**
  Add to `internal/bloodhound/bloodhound_test.go`:
  ```go
  func TestExtractControllableCountUsesTotal(t *testing.T) {
  	// True total from env.Count is 5000 even though only a small label sample
  	// (10 items) was paged in. ExtractControllableCount must return 5000.
  	ud := &UserData{
  		ControllableTotal: 5000,
  		Controllables: []DomainControllables{
  			{Domain: "CORP.INT", Labels: map[string]int{"User": 7, "Group": 3}},
  		},
  	}
  	if got := ExtractControllableCount(ud); got != 5000 {
  		t.Errorf("count = %d, want 5000 (true total, not the 10-item sample)", got)
  	}
  	// Fallback: when the total is absent (0), sum the sampled label map.
  	udNoTotal := &UserData{
  		Controllables: []DomainControllables{
  			{Domain: "A.INT", Labels: map[string]int{"User": 3, "Computer": 2}},
  			{Domain: "B.INT", Labels: map[string]int{"Group": 1}},
  		},
  	}
  	if got := ExtractControllableCount(udNoTotal); got != 6 {
  		t.Errorf("fallback count = %d, want 6", got)
  	}
  	if ExtractControllableCount(nil) != 0 {
  		t.Error("nil UserData should yield 0")
  	}
  }
  ```

- [ ] **Step 2: Run it; verify it fails to compile (no `ControllableTotal` field).**
  ```
  go test ./internal/bloodhound/ -run TestExtractControllableCountUsesTotal -v
  ```
  Expected: build failure — `ud.ControllableTotal undefined (type *UserData has no field or method ControllableTotal)`.

- [ ] **Step 3: Minimal implementation — add the field, thread the count, change the extractor.**
  In `internal/bloodhound/bloodhound.go`, change the `GetUserControllables` signature to also return the total. Replace the function (current 385–425) with:
  ```go
  // GetUserControllables returns the objects controllable by a user, grouped as
  // domain -> (controllable label -> count), plus the API's TRUE total controlled
  // count from the envelope (env.Count). The label map is only the sampled page
  // (bounded by controllablesLimit); total is the real magnitude and is not capped.
  func (c *Client) GetUserControllables(objectID string) (byDomain map[string]map[string]int, total int, err error) {
  	out := map[string]map[string]int{}

  	// Single call with the configured limit (avoids double round-trip). limit now
  	// bounds only the display/label sample; env.Count carries the true total.
  	env, status, err := c.get(fmt.Sprintf("/api/v2/base/%s/controllables?skip=0&limit=%d&type=list", objectID, c.controllablesLimit))
  	if err != nil {
  		return nil, 0, err
  	}
  	if status != http.StatusOK || env.Count == 0 {
  		return out, 0, nil
  	}

  	var items []struct {
  		Label string `json:"label"`
  		Name  string `json:"name"`
  	}
  	if err := json.Unmarshal(env.Data, &items); err != nil {
  		return nil, 0, err
  	}
  	for _, it := range items {
  		domain := domainFromName(it.Name)
  		if domain == "LOCALDOMAIN" || domain == "Unknown" || domain == "INT" {
  			if comp, ok, _ := c.GetComputer(it.Name); ok {
  				if d := c.computerDomain(comp.ObjectID); d != "" {
  					domain = d
  				}
  			}
  		}
  		if out[domain] == nil {
  			out[domain] = map[string]int{}
  		}
  		label := it.Label
  		if label == "" {
  			label = "Unknown"
  		}
  		out[domain][label]++
  	}
  	return out, env.Count, nil
  }
  ```
  Add `ControllableTotal int` to the `UserData` struct (current 510–516):
  ```go
  // UserData is the aggregated BHE enrichment for a single user.
  type UserData struct {
  	Username      string
  	ObjectID      string
  	Props         UserProps
  	Controllables []DomainControllables
  	// ControllableTotal is the API's TRUE count of controlled objects (env.Count),
  	// independent of the sampled label map. 0 means absent/unknown.
  	ControllableTotal int
  }
  ```
  In `GetUserData` (current line 542) update the call + store the total:
  ```go
  	byCount, total, err := c.GetUserControllables(sid)
  	if err != nil {
  		return nil, err
  	}
  ```
  and after `ud := &UserData{Username: user.Name, ObjectID: sid, Props: props}` (current line 554) set:
  ```go
  	ud.ControllableTotal = total
  ```
  Replace `ExtractControllableCount` (current 595–607) with:
  ```go
  // ExtractControllableCount returns the TRUE number of controlled objects: the
  // API's env.Count (ControllableTotal) when present, falling back to the summed
  // sampled label map only when the total is 0/absent.
  func ExtractControllableCount(ud *UserData) int {
  	if ud == nil {
  		return 0
  	}
  	if ud.ControllableTotal > 0 {
  		return ud.ControllableTotal
  	}
  	total := 0
  	for _, dc := range ud.Controllables {
  		for _, n := range dc.Labels {
  			total += n
  		}
  	}
  	return total
  }
  ```

- [ ] **Step 4: Run the new test + the existing extractor test; verify green.**
  ```
  go test ./internal/bloodhound/ -run "TestExtractControllableCountUsesTotal|TestExtractHelpers|TestGetUserDataEndToEnd" -v
  ```
  Expected: PASS. Note `TestExtractHelpers` (current line 113) sets no `ControllableTotal`, so it still exercises the label-sum fallback and must still expect 6. `TestGetUserDataEndToEnd` (line 70) returns `{"count":2,...}`, so `ExtractControllableCount` now returns the total 2 — same assertion, still passes.

- [ ] **Step 5: Add the end-to-end httptest proving total > sample, mirroring `TestGetUserDataEndToEnd`.**
  Add to `internal/bloodhound/bloodhound_test.go`:
  ```go
  func TestGetUserDataCountFromEnvelope(t *testing.T) {
  	// Mock returns count:5000 but only a 2-item data page. The true total (5000)
  	// must survive — proving the >10 cap is gone.
  	c, srv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
  		verifySig(t, r)
  		q := r.URL.Query()
  		switch {
  		case r.URL.Path == "/api/v2/available-domains":
  			_, _ = io.WriteString(w, `{"data":[{"name":"CORP.INT","id":"D1","collected":true,"type":"Domain"}]}`)
  		case r.URL.Path == "/api/v2/search" && q.Get("type") == "User":
  			_, _ = io.WriteString(w, `{"data":[{"name":"alice@CORP.INT","objectid":"S-1-5-USER"}]}`)
  		case r.URL.Path == "/api/v2/search" && q.Get("type") == "Group":
  			_, _ = io.WriteString(w, `{"data":[{"name":"DOMAIN ADMINS@CORP.INT","objectid":"S-1-5-DA"}]}`)
  		case len(r.URL.Path) > len("/controllables") && r.URL.Path[len(r.URL.Path)-len("/controllables"):] == "/controllables":
  			_, _ = io.WriteString(w, `{"count":5000,"data":[{"label":"User","name":"bob@CORP.INT"},{"label":"User","name":"carol@CORP.INT"}]}`)
  		case r.URL.Path == "/api/v2/users/S-1-5-USER":
  			_, _ = io.WriteString(w, `{"data":{"props":{"enabled":true,"pwdneverexpires":false,"pwdlastset":133000000000000000}}}`)
  		case r.URL.Path == "/api/v2/graphs/shortest-path":
  			w.WriteHeader(http.StatusNotFound) // no DA path needed for this test
  		default:
  			t.Errorf("unexpected request: %s", r.URL.RequestURI())
  			w.WriteHeader(http.StatusNotFound)
  		}
  	})
  	defer srv.Close()

  	ud, err := c.GetUserData("alice@CORP.INT")
  	if err != nil {
  		t.Fatal(err)
  	}
  	if ud == nil {
  		t.Fatal("GetUserData returned nil")
  	}
  	if ud.ControllableTotal != 5000 {
  		t.Errorf("ControllableTotal = %d, want 5000", ud.ControllableTotal)
  	}
  	if got := ExtractControllableCount(ud); got != 5000 {
  		t.Errorf("ExtractControllableCount = %d, want 5000 (not the 2-item sample)", got)
  	}
  }
  ```

- [ ] **Step 6: Run the full bloodhound + engine packages; verify green (engine calls the changed signature).**
  `engine.go:555` (`BloodhoundEnricher.Enrich`) calls `ExtractControllableCount` only, not `GetUserControllables` directly, so no engine change is needed for the signature — but confirm there are no other callers:
  ```
  go build ./... && go test ./internal/bloodhound/ ./internal/engine/ -v
  ```
  Expected: PASS. (If `go build` flags any other caller of `GetUserControllables`, update it to the 3-return form; per current code, `GetUserData` is the only caller.)

- [ ] **Step 7: Run the full gate suite, then commit.**
  ```
  gofmt -l cmd internal
  go build ./... && go vet ./... && go test ./...
  govulncheck ./...
  git add internal/bloodhound/bloodhound.go internal/bloodhound/bloodhound_test.go
  git commit -m "feat(bloodhound): surface true controlled-objects count via env.Count (kills the 10-cap)"
  ```

**Proves:** `ExtractControllableCount` returns the API's true total (5000) from `env.Count`, not the capped sample — the privilege tiers (`>10/>100/...`) are now reachable; the label-sum fallback still works when the total is absent.

---

### Task 2 — Retain object names + Tier-0 / DA-equivalent detection

**Why:** `GetUserControllables` drops each controllable's `Name` after deriving its domain (current loop at 406–423). To detect control of a Tier-0 / DA-equivalent object we must retain the sampled object names + labels. Add a `ControlsTier0 bool` signal extracted by a new exported `ExtractControlsTier0(ud)`, matching DA-sensitive names by case-insensitive heuristic (DOMAIN ADMINS, ENTERPRISE ADMINS, ADMINISTRATORS, DOMAIN CONTROLLERS, KRBTGT, ADMINSDHOLDER) or control of the domain object itself (DCSync-implying). **Best-effort from the sampled page only** — `env.Count` still gives the true magnitude (Task 1) but the *names* are limited to the `controllablesLimit` page. **Recommendation (apply in this task):** raise the default `controllablesLimit` from 10 to 100 so the sample is large enough for meaningful Tier-0/sensitivity detection in one call (no deep pagination; perf posture unchanged).

**Files:**
- Modify: `internal/bloodhound/bloodhound.go`
  - `DomainControllables` struct (current 502–508) → add `Items []ControllableItem`.
  - New exported `ControllableItem struct { Label, Name string }`.
  - `GetUserControllables` loop (current 406–423) → also append each item's `{Label, Name}` to a per-domain slice; return it so `GetUserData` can attach.
  - `GetUserData` (current 562–566) → attach the retained items onto each `DomainControllables`.
  - New `ExtractControlsTier0(ud *UserData) bool` + an unexported `isTier0Name(name string) bool` helper.
  - `New` constructor default (current 107–110) → `controllablesLimit = 100`.
- Test: `internal/bloodhound/bloodhound_test.go` (new `TestExtractControlsTier0`, `TestControllablesLimitDefault`).

> **Design note (carry into B/C):** because Tier-0 detection reads only the sampled page, a user controlling 5000 objects whose DA-group edge is *outside* the first 100 sampled may not flag `ControlsTier0` — but their huge `env.Count` already drives a high privilege sub-score in B, and a literal DA-path edge (via `ProcessUserDAPath`) is the authoritative DA signal. Tier-0-by-name is a best-effort *additive* signal, never a gate. Raising the limit to 100 widens the sample at one-call cost.

#### Steps

- [ ] **Step 1: Write the failing test for `ExtractControlsTier0`.**
  Add to `internal/bloodhound/bloodhound_test.go`:
  ```go
  func TestExtractControlsTier0(t *testing.T) {
  	// Controlling the Domain Admins group is DA-equivalent.
  	udTier0 := &UserData{Controllables: []DomainControllables{
  		{Domain: "CORP.LOCAL", Items: []ControllableItem{
  			{Label: "Group", Name: "DOMAIN ADMINS@CORP.LOCAL"},
  			{Label: "User", Name: "bob@CORP.LOCAL"},
  		}},
  	}}
  	if !ExtractControlsTier0(udTier0) {
  		t.Error("control of DOMAIN ADMINS group must be Tier-0")
  	}
  	// Controlling only ordinary users is NOT Tier-0.
  	udOrdinary := &UserData{Controllables: []DomainControllables{
  		{Domain: "CORP.LOCAL", Items: []ControllableItem{
  			{Label: "User", Name: "carol@CORP.LOCAL"},
  			{Label: "User", Name: "dave@CORP.LOCAL"},
  		}},
  	}}
  	if ExtractControlsTier0(udOrdinary) {
  		t.Error("control of ordinary users must not be Tier-0")
  	}
  	// Case-insensitive + other sensitive names.
  	for _, name := range []string{"krbtgt@corp.local", "Enterprise Admins@CORP.LOCAL", "AdminSDHolder@CORP.LOCAL", "DOMAIN CONTROLLERS@CORP.LOCAL"} {
  		ud := &UserData{Controllables: []DomainControllables{
  			{Domain: "CORP.LOCAL", Items: []ControllableItem{{Label: "Group", Name: name}}},
  		}}
  		if !ExtractControlsTier0(ud) {
  			t.Errorf("name %q should be Tier-0", name)
  		}
  	}
  	if ExtractControlsTier0(nil) {
  		t.Error("nil UserData must not be Tier-0")
  	}
  }
  ```

- [ ] **Step 2: Run it; verify it fails to compile (no `Items`/`ControllableItem`/`ExtractControlsTier0`).**
  ```
  go test ./internal/bloodhound/ -run TestExtractControlsTier0 -v
  ```
  Expected: build failure — `undefined: ControllableItem` and `undefined: ExtractControlsTier0`.

- [ ] **Step 3: Minimal implementation — retain items + add the extractor.**
  In `internal/bloodhound/bloodhound.go`, add the item type and extend `DomainControllables` (current 502–508):
  ```go
  // ControllableItem is one sampled controllable object (label + name). Retained so
  // Tier-0 / DA-equivalent control can be detected by name heuristic. The sample is
  // bounded by controllablesLimit; env.Count (ControllableTotal) gives the true count.
  type ControllableItem struct {
  	Label string
  	Name  string
  }

  // DomainControllables holds, for one domain, the user's controllable-object
  // label counts and whether they have a Domain Admin pathway there.
  type DomainControllables struct {
  	Domain    string
  	Labels    map[string]int
  	Items     []ControllableItem // the sampled controllable objects (bounded by controllablesLimit)
  	HasDAPath *bool              // nil = unknown
  }
  ```
  Change `GetUserControllables` to also collect per-domain items. Replace its return type and loop so it returns the items map too. Final form (supersedes Task 1's body):
  ```go
  // GetUserControllables returns the objects controllable by a user, grouped as
  // domain -> (controllable label -> count) plus domain -> sampled items, plus the
  // API's TRUE total (env.Count). The label/item sample is bounded by
  // controllablesLimit; total is the real magnitude and is not capped.
  func (c *Client) GetUserControllables(objectID string) (byDomain map[string]map[string]int, items map[string][]ControllableItem, total int, err error) {
  	out := map[string]map[string]int{}
  	itemsOut := map[string][]ControllableItem{}

  	env, status, err := c.get(fmt.Sprintf("/api/v2/base/%s/controllables?skip=0&limit=%d&type=list", objectID, c.controllablesLimit))
  	if err != nil {
  		return nil, nil, 0, err
  	}
  	if status != http.StatusOK || env.Count == 0 {
  		return out, itemsOut, 0, nil
  	}

  	var rawItems []struct {
  		Label string `json:"label"`
  		Name  string `json:"name"`
  	}
  	if err := json.Unmarshal(env.Data, &rawItems); err != nil {
  		return nil, nil, 0, err
  	}
  	for _, it := range rawItems {
  		domain := domainFromName(it.Name)
  		if domain == "LOCALDOMAIN" || domain == "Unknown" || domain == "INT" {
  			if comp, ok, _ := c.GetComputer(it.Name); ok {
  				if d := c.computerDomain(comp.ObjectID); d != "" {
  					domain = d
  				}
  			}
  		}
  		if out[domain] == nil {
  			out[domain] = map[string]int{}
  		}
  		label := it.Label
  		if label == "" {
  			label = "Unknown"
  		}
  		out[domain][label]++
  		itemsOut[domain] = append(itemsOut[domain], ControllableItem{Label: label, Name: it.Name})
  	}
  	return out, itemsOut, env.Count, nil
  }
  ```
  Update `GetUserData`'s call (Task 1 left it as `byCount, total, err := ...`) to:
  ```go
  	byCount, ctrlItems, total, err := c.GetUserControllables(sid)
  	if err != nil {
  		return nil, err
  	}
  ```
  and attach items when building each `DomainControllables` (current loop 563–566):
  ```go
  	for _, d := range domainsSorted {
  		idx[d] = len(ud.Controllables)
  		ud.Controllables = append(ud.Controllables, DomainControllables{Domain: d, Labels: byCount[d], Items: ctrlItems[d]})
  	}
  ```
  Add the extractor + helper near `ExtractControllableCount`:
  ```go
  // tier0Names are case-insensitive name fragments whose control is DA-equivalent.
  var tier0Names = []string{
  	"DOMAIN ADMINS",
  	"ENTERPRISE ADMINS",
  	"ADMINISTRATORS",
  	"DOMAIN CONTROLLERS",
  	"KRBTGT",
  	"ADMINSDHOLDER",
  }

  // isTier0Name reports whether an object name matches a Tier-0 / DA-equivalent
  // object by case-insensitive substring (best-effort name heuristic).
  func isTier0Name(name string) bool {
  	u := strings.ToUpper(name)
  	for _, t := range tier0Names {
  		if strings.Contains(u, t) {
  			return true
  		}
  	}
  	return false
  }

  // ExtractControlsTier0 reports whether the user controls a Tier-0 / DA-equivalent
  // object (Domain Admins, Enterprise Admins, Administrators, Domain Controllers,
  // KRBTGT, AdminSDHolder, or the domain object — DCSync). Best-effort over the
  // SAMPLED controllables page (bounded by controllablesLimit); a true magnitude
  // still comes from ExtractControllableCount and the literal DA path from
  // ExtractDADomains. Never a gate — an additive Impact signal.
  func ExtractControlsTier0(ud *UserData) bool {
  	if ud == nil {
  		return false
  	}
  	for _, dc := range ud.Controllables {
  		for _, it := range dc.Items {
  			if isTier0Name(it.Name) {
  				return true
  			}
  			// Control of the domain object itself implies DCSync (DA-equivalent).
  			if it.Label == "Domain" {
  				return true
  			}
  		}
  	}
  	return false
  }
  ```

- [ ] **Step 4: Run the Tier-0 test; verify green.**
  ```
  go test ./internal/bloodhound/ -run TestExtractControlsTier0 -v
  ```
  Expected: PASS.

- [ ] **Step 5: Write + run the default-limit test, then bump the default 10→100.**
  Add to `internal/bloodhound/bloodhound_test.go`:
  ```go
  func TestControllablesLimitDefault(t *testing.T) {
  	// An unset ControllablesLimit defaults to 100 so the Tier-0/sensitivity sample
  	// is wide enough in a single call (env.Count still gives the true magnitude).
  	c := New(Config{Scheme: "http", Host: "h", Port: 1, TokenID: "t", TokenKey: "k"})
  	if c.controllablesLimit != 100 {
  		t.Errorf("default controllablesLimit = %d, want 100", c.controllablesLimit)
  	}
  	// An explicit value is honored.
  	c2 := New(Config{ControllablesLimit: 25})
  	if c2.controllablesLimit != 25 {
  		t.Errorf("explicit controllablesLimit = %d, want 25", c2.controllablesLimit)
  	}
  }
  ```
  Run; expect failure (`= 10, want 100`):
  ```
  go test ./internal/bloodhound/ -run TestControllablesLimitDefault -v
  ```
  Then change the constructor default (current 107–110):
  ```go
  	controllablesLimit := cfg.ControllablesLimit
  	if controllablesLimit == 0 {
  		controllablesLimit = 100 // wider sample for Tier-0/sensitivity; env.Count gives true magnitude
  	}
  ```
  Re-run; expect PASS.

- [ ] **Step 6: Run the full bloodhound + engine packages; verify green (signature changed again).**
  ```
  go build ./... && go test ./internal/bloodhound/ ./internal/engine/ -v
  ```
  Expected: PASS. `GetUserData` is still the only caller of `GetUserControllables`.

- [ ] **Step 7: Full gate suite, then commit.**
  ```
  gofmt -l cmd internal
  go build ./... && go vet ./... && go test ./...
  govulncheck ./...
  git add internal/bloodhound/bloodhound.go internal/bloodhound/bloodhound_test.go
  git commit -m "feat(bloodhound): retain controllable names for Tier-0/DA-equivalent detection; widen default sample to 100"
  ```

**Proves:** `ExtractControlsTier0` flags control of a `Group` named "DOMAIN ADMINS@CORP.LOCAL" (and KRBTGT/EA/Administrators/DCs/AdminSDHolder, case-insensitively, plus a controlled `Domain` object) as DA-equivalent, while control of only ordinary users is false; the default sample is now 100.

---

### Task 3 — Roastable flags on the LIVE `BloodhoundEnricher.Enrich` path

**Why:** `UserProps` (bloodhound.go:338–348) lacks `hasspn` / `dontreqpreauth`, and the live `BloodhoundEnricher.Enrich` (engine.go:550–568) never sets `HasSPN` / `DontReqPreauth` on the returned `Enrichment` — only the bulk path (engine.go:578–598) does. So a single-user (non-bulk) lookup silently drops the roastable signal that B's Exposure bump depends on. Fix: add the two fields to `UserProps` (decoded automatically by `GetUserFull`, which already unmarshals the props JSON), and set them in `BloodhoundEnricher.Enrich` the same way the bulk path does.

**Files:**
- Modify: `internal/bloodhound/bloodhound.go` — `UserProps` struct (current 338–348) → add `HasSPN bool json:"hasspn"`, `DontReqPreauth bool json:"dontreqpreauth"`.
- Modify: `internal/engine/engine.go` — `BloodhoundEnricher.Enrich` (current 550–568) → set `HasSPN` / `DontReqPreauth` from `ud.Props`.
- Test: `internal/bloodhound/bloodhound_test.go` (new `TestUserPropsRoastableDecode`); `internal/engine/engine_test.go` (new `TestBloodhoundEnricherSurfacesRoastable`).

#### Steps

- [ ] **Step 1: Write the failing decode test for `UserProps`.**
  Add to `internal/bloodhound/bloodhound_test.go` (note: `encoding/json` import is needed — add it if not already present):
  ```go
  func TestUserPropsRoastableDecode(t *testing.T) {
  	var p UserProps
  	if err := json.Unmarshal([]byte(`{"hasspn":true,"dontreqpreauth":true,"enabled":true}`), &p); err != nil {
  		t.Fatal(err)
  	}
  	if !p.HasSPN || !p.DontReqPreauth {
  		t.Errorf("roastable flags not decoded: hasspn=%v dontreqpreauth=%v", p.HasSPN, p.DontReqPreauth)
  	}
  }
  ```

- [ ] **Step 2: Run it; verify it fails to compile (no `HasSPN`/`DontReqPreauth` on `UserProps`).**
  ```
  go test ./internal/bloodhound/ -run TestUserPropsRoastableDecode -v
  ```
  Expected: build failure — `p.HasSPN undefined (type UserProps has no field or method HasSPN)`. (If `encoding/json` is now an unused-vs-used concern, it is already imported at bloodhound_test.go — verify; the test file currently imports only `io,net,...`; add `"encoding/json"` to its import block.)

- [ ] **Step 3: Minimal implementation — add the two fields to `UserProps`.**
  In `internal/bloodhound/bloodhound.go`, extend `UserProps` (current 338–348):
  ```go
  // UserProps holds the user properties relevant to the audit.
  type UserProps struct {
  	PwdLastSet         json.Number `json:"pwdlastset"`
  	PwdNeverExpires    bool        `json:"pwdneverexpires"`
  	Enabled            bool        `json:"enabled"`
  	WhenCreated        json.Number `json:"whencreated"`
  	DistinguishedName  string      `json:"distinguishedname"`
  	LastLogon          json.Number `json:"lastlogon"`
  	LastLogonTimestamp json.Number `json:"lastlogontimestamp"`
  	PasswordCantChange bool        `json:"passwordcantchange"`
  	HasSPN             bool        `json:"hasspn"`         // Kerberoastable — SPN set
  	DontReqPreauth     bool        `json:"dontreqpreauth"` // AS-REP roastable
  }
  ```

- [ ] **Step 4: Run the decode test; verify green.**
  ```
  go test ./internal/bloodhound/ -run TestUserPropsRoastableDecode -v
  ```
  Expected: PASS.

- [ ] **Step 5: Write the failing engine test for the live path surfacing roastable flags.**
  Add to `internal/engine/engine_test.go`. This drives `BloodhoundEnricher.Enrich` against an httptest BHE server returning roastable props (mirror the `TestGetUserDataEndToEnd` mock shape; build the client like `bloodhound`'s `newTestClient`). Add imports `"net/http"`, `"net/http/httptest"`, `"net"`, `"net/url"`, `"strconv"`, `"io"`, and `"github.com/watson0x90/PasswordAtTheDisco/internal/bloodhound"` to the test file's import block:
  ```go
  func TestBloodhoundEnricherSurfacesRoastable(t *testing.T) {
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
  			_, _ = io.WriteString(w, `{"count":0,"data":[]}`)
  		case r.URL.Path == "/api/v2/users/S-1-5-SVC":
  			_, _ = io.WriteString(w, `{"data":{"props":{"enabled":true,"pwdneverexpires":false,"hasspn":true,"dontreqpreauth":true,"pwdlastset":133000000000000000}}}`)
  		case r.URL.Path == "/api/v2/graphs/shortest-path":
  			w.WriteHeader(http.StatusNotFound)
  		default:
  			t.Errorf("unexpected request: %s", r.URL.RequestURI())
  			w.WriteHeader(http.StatusNotFound)
  		}
  	}))
  	defer srv.Close()

  	u, _ := url.Parse(srv.URL)
  	host, portStr, _ := net.SplitHostPort(u.Host)
  	port, _ := strconv.Atoi(portStr)
  	cl := bloodhound.New(bloodhound.Config{Scheme: "http", Host: host, Port: port, TokenID: "tid", TokenKey: "tkey"})

  	enr := BloodhoundEnricher{Client: cl}.Enrich("svc@CORP.INT")
  	if enr.HasSPN == nil || !*enr.HasSPN {
  		t.Errorf("HasSPN not surfaced on live path: %v", enr.HasSPN)
  	}
  	if enr.DontReqPreauth == nil || !*enr.DontReqPreauth {
  		t.Errorf("DontReqPreauth not surfaced on live path: %v", enr.DontReqPreauth)
  	}
  }
  ```

- [ ] **Step 6: Run it; verify it fails (live path doesn't set the flags yet).**
  ```
  go test ./internal/engine/ -run TestBloodhoundEnricherSurfacesRoastable -v
  ```
  Expected: FAIL — `HasSPN not surfaced on live path: <nil>` (the field is still nil because `BloodhoundEnricher.Enrich` never sets it).

- [ ] **Step 7: Minimal implementation — set roastable on the live path.**
  In `internal/engine/engine.go`, replace `BloodhoundEnricher.Enrich` (current 550–568) with:
  ```go
  // Enrich fetches and flattens a user's BloodHound enrichment.
  func (b BloodhoundEnricher) Enrich(username string) Enrichment {
  	ud, err := b.Client.GetUserData(username)
  	if err != nil || ud == nil {
  		return Enrichment{}
  	}
  	count := bloodhound.ExtractControllableCount(ud)
  	enabled := ud.Props.Enabled
  	never := ud.Props.PwdNeverExpires
  	hasSPN := ud.Props.HasSPN
  	dontReqPreauth := ud.Props.DontReqPreauth
  	enr := Enrichment{
  		DADomains:         bloodhound.ExtractDADomains(ud),
  		ControlledObjects: &count,
  		PwdNeverExpires:   &never,
  		Enabled:           &enabled,
  		HasSPN:            &hasSPN,
  		DontReqPreauth:    &dontReqPreauth,
  	}
  	if v, err := ud.Props.PwdLastSet.Int64(); err == nil && v > 0 {
  		enr.PwdLastSet = &v
  	}
  	return enr
  }
  ```

- [ ] **Step 8: Run both new tests; verify green.**
  ```
  go test ./internal/bloodhound/ -run TestUserPropsRoastableDecode -v
  go test ./internal/engine/ -run TestBloodhoundEnricherSurfacesRoastable -v
  ```
  Expected: PASS.

- [ ] **Step 9: Full gate suite, then commit.**
  ```
  gofmt -l cmd internal
  go build ./... && go vet ./... && go test ./...
  govulncheck ./...
  git add internal/bloodhound/bloodhound.go internal/bloodhound/bloodhound_test.go internal/engine/engine.go internal/engine/engine_test.go
  git commit -m "feat(bloodhound,engine): decode roastable flags + surface HasSPN/DontReqPreauth on the live BHE path"
  ```

**Proves:** A `UserProps` JSON with `"hasspn":true` decodes, and the per-user `BloodhoundEnricher.Enrich` now surfaces `HasSPN`/`DontReqPreauth` on the returned `Enrichment` — closing the live-vs-bulk parity gap so B's roastable Exposure bump fires regardless of enrich path.

---

### Task 4 — Per-account coverage state

**Why:** Without enrichment the entire Impact side silently collapses to neutral, so "we don't know the blast radius" and "the blast radius is low" look identical (spec problem #8). Add an explicit coverage signal: `Enrichment.Enriched` (true when the enricher actually returned BloodHound data) flows into `model.Account.Coverage` ("full"/"none"). B/C consume it to drive the `Unknown` Impact state and the coverage banner. **No scoring number changes** — `Coverage` is purely a new descriptive field.

- Live path (`BloodhoundEnricher.Enrich`): `Enriched=false` on the `err != nil || ud == nil` early return (current 552–554); `Enriched=true` on the success path.
- Bulk path (`BulkBloodhoundEnricher.Enrich`): `b.Bulk.Lookup` returns `(BulkUserProps, []string, int)`; a **miss** yields the zero `BulkUserProps{}` whose `ObjectID` is empty (set only from a real Cypher row). So `Enriched = props.ObjectID != ""`.
- `scoreCracked` (engine.go:318) and `scoreUncracked` (engine.go:385): set `Coverage` from `enrData.Enriched` ("full" if true, else "none").
- `model.Account` (model.go:136–200): add `Coverage string json:"coverage,omitempty"`. **Redaction-safe** — `Redacted()` (model.go:229–236) clears only credentials; `Coverage` is descriptive, no change needed there. Confirm with a test.

**Files:**
- Modify: `internal/engine/engine.go` — `Enrichment` struct (current 35–43); `BloodhoundEnricher.Enrich` (post-Task-3 body); `BulkBloodhoundEnricher.Enrich` (current 578–598); `scoreCracked` (current 318 return literal); `scoreUncracked` (current 385 return literal).
- Modify: `internal/model/model.go` — `Account` struct (after current line 155 `Enabled` or near `RiskLevel`).
- Test: `internal/engine/engine_test.go` (new `TestCoverageFromEnriched`); `internal/model/model_test.go` (new `TestCoverageSurvivesRedaction`).

#### Steps

- [ ] **Step 1: Write the failing engine test for coverage mapping.**
  Add to `internal/engine/engine_test.go`. Uses the existing `fakeEnricher` / `newEngine` / `bp`/`ipv` helpers; the fake must return `Enriched:true`:
  ```go
  func TestCoverageFromEnriched(t *testing.T) {
  	e := newEngine()
  	e.Enricher = fakeEnricher{
  		"alice@CORP": {Enriched: true, ControlledObjects: ipv(20), Enabled: bp(true)},
  	}
  	cracked := []secretsdump.ParsedAccount{
  		{Username: "alice", Domain: "CORP", Hash: "H1", Password: "Str0ng&Unique!Pass", Cracked: true},
  		{Username: "ghost", Domain: "CORP", Hash: "H2", Password: "Another!Pass99", Cracked: true}, // no enrichment entry
  	}
  	out := e.ProcessDomain("CORP", cracked, nil)
  	by := map[string]model.Account{}
  	for _, a := range out {
  		by[a.Username] = a
  	}
  	if by["alice"].Coverage != "full" {
  		t.Errorf("alice coverage = %q, want full", by["alice"].Coverage)
  	}
  	if by["ghost"].Coverage != "none" {
  		t.Errorf("ghost (no enrichment) coverage = %q, want none", by["ghost"].Coverage)
  	}
  	// Uncracked path too.
  	e.Enricher = fakeEnricher{"svc@CORP": {Enriched: true, Enabled: bp(true)}}
  	u := e.ProcessDomain("CORP", nil, []secretsdump.ParsedAccount{{Username: "svc", Domain: "CORP", Hash: "UH"}})[0]
  	if u.Coverage != "full" {
  		t.Errorf("uncracked svc coverage = %q, want full", u.Coverage)
  	}
  }
  ```

- [ ] **Step 2: Run it; verify it fails to compile (no `Enriched` field, no `Coverage` field).**
  ```
  go test ./internal/engine/ -run TestCoverageFromEnriched -v
  ```
  Expected: build failure — `unknown field Enriched in struct literal of type Enrichment` and `a.Coverage undefined`.

- [ ] **Step 3: Minimal implementation — add `Enriched`, set it on both enrichers, add `Coverage`, set it in both scorers.**
  In `internal/engine/engine.go`, extend `Enrichment` (current 35–43):
  ```go
  // Enrichment is the BloodHound-derived signal set for one account. A zero value
  // (nil pointers / empty slice) means "unknown".
  type Enrichment struct {
  	DADomains         []string
  	ControlledObjects *int
  	PwdLastSet        *int64 // epoch seconds
  	PwdNeverExpires   *bool
  	Enabled           *bool
  	HasSPN            *bool // Kerberoastable
  	DontReqPreauth    *bool // AS-REP roastable
  	// Enriched is true when the enricher actually returned BloodHound data for the
  	// user (per-account coverage). False on the zero Enrichment{} (user not found,
  	// BHE off, or an error) — drives model.Account.Coverage and B's Unknown Impact.
  	Enriched bool
  }
  ```
  In `BloodhoundEnricher.Enrich` (the Task-3 body) set `Enriched: true` on the success-path literal:
  ```go
  	enr := Enrichment{
  		DADomains:         bloodhound.ExtractDADomains(ud),
  		ControlledObjects: &count,
  		PwdNeverExpires:   &never,
  		Enabled:           &enabled,
  		HasSPN:            &hasSPN,
  		DontReqPreauth:    &dontReqPreauth,
  		Enriched:          true,
  	}
  ```
  (The `err != nil || ud == nil` early return already returns `Enrichment{}` with `Enriched:false` — no change.)
  In `BulkBloodhoundEnricher.Enrich` (current 578–598) set `Enriched` from the lookup hit:
  ```go
  // Enrich returns enrichment data from the pre-fetched bulk cache.
  func (b BulkBloodhoundEnricher) Enrich(username string) Enrichment {
  	props, daDomains, ctrl := b.Bulk.Lookup(username)
  	enabled := props.Enabled
  	never := props.PwdNeverExpires
  	hasSPN := props.HasSPN
  	dontReqPreauth := props.DontReqPreauth
  	var pwdLastSet *int64
  	if props.PwdLastSet > 0 {
  		v := props.PwdLastSet
  		pwdLastSet = &v
  	}
  	return Enrichment{
  		DADomains:         daDomains,
  		ControlledObjects: &ctrl,
  		PwdNeverExpires:   &never,
  		Enabled:           &enabled,
  		PwdLastSet:        pwdLastSet,
  		HasSPN:            &hasSPN,
  		DontReqPreauth:    &dontReqPreauth,
  		// A bulk miss returns the zero BulkUserProps{} (empty ObjectID). A hit is
  		// populated from a real Cypher row, so ObjectID is non-empty.
  		Enriched: props.ObjectID != "",
  	}
  }
  ```
  In `internal/model/model.go`, add the field to `Account` (immediately after `Enabled bool` at current line 155):
  ```go
  	Enabled         bool    `json:"enabled"`
  	// Coverage is the per-account BloodHound coverage state: "full" (enriched) or
  	// "none" (not enriched). Drives B's Unknown-Impact state and the coverage
  	// banner. Descriptive, not a credential — survives Redacted().
  	Coverage        string  `json:"coverage,omitempty"`
  	MeetsPolicy     bool    `json:"meets_policy"`
  ```
  In `internal/engine/engine.go`, add a helper near `enabledOrUnknown` (current 541):
  ```go
  // coverageState maps the per-account Enriched bit to the model coverage string.
  func coverageState(enriched bool) string {
  	if enriched {
  		return "full"
  	}
  	return "none"
  }
  ```
  In `scoreCracked` set `Coverage` in the returned `model.Account` literal — add right after `Enabled: enabledOrUnknown(enrData.Enabled),` (current line 333):
  ```go
  		Enabled:         enabledOrUnknown(enrData.Enabled),
  		Coverage:        coverageState(enrData.Enriched),
  ```
  In `scoreUncracked` likewise after its `Enabled: enabledOrUnknown(enrData.Enabled),` (current line 398):
  ```go
  		Enabled:         enabledOrUnknown(enrData.Enabled),
  		Coverage:        coverageState(enrData.Enriched),
  ```

- [ ] **Step 4: Run the engine coverage test; verify green.**
  ```
  go test ./internal/engine/ -run TestCoverageFromEnriched -v
  ```
  Expected: PASS.

- [ ] **Step 5: Write + run the redaction-safety confirmation test.**
  Add to `internal/model/model_test.go` (create the file if it does not exist — check first with the gate build; if it exists, append):
  ```go
  func TestCoverageSurvivesRedaction(t *testing.T) {
  	a := Account{Username: "alice", Domain: "CORP", Password: "secret", NTHash: "ABC", Coverage: "full"}
  	red := a.Redacted()
  	if red.Coverage != "full" {
  		t.Errorf("Coverage = %q after Redacted(), want full (descriptive, not a credential)", red.Coverage)
  	}
  	if red.Password != "" || red.NTHash != "" {
  		t.Errorf("credentials not cleared: pw=%q hash=%q", red.Password, red.NTHash)
  	}
  }
  ```
  Run:
  ```
  go test ./internal/model/ -run TestCoverageSurvivesRedaction -v
  ```
  Expected: PASS (no `Redacted()` change was needed — `Coverage` is descriptive).

- [ ] **Step 6: Full gate suite, then commit.**
  ```
  gofmt -l cmd internal
  go build ./... && go vet ./... && go test ./...
  govulncheck ./...
  git add internal/engine/engine.go internal/engine/engine_test.go internal/model/model.go internal/model/model_test.go
  git commit -m "feat(engine,model): per-account BloodHound coverage state (Enriched -> Account.Coverage full/none)"
  ```

**Proves:** A fake `Enricher` returning `Enriched:true` yields `Account.Coverage == "full"` (cracked and uncracked); a missing entry / empty enricher yields `"none"`; the bulk path derives the same bit from a lookup hit; and `Coverage` survives `Redacted()` (confirmed not a credential).

---

### Task 5 — Sub-project A acceptance gate + handoff note

**Why:** Confirm the whole package set is green end-to-end and record the deliberate non-change to `EscalateSharedWithDA` (the optional minor #5) as a handoff to B.

**Files:** none modified (verification only). Optionally extend this plan/spec note inline in the commit message.

#### Steps

- [ ] **Step 1: Run the complete acceptance gate from the repo root; capture output.**
  ```
  gofmt -l cmd internal
  go build ./...
  go vet ./...
  go test ./...
  govulncheck ./...
  ```
  Expected: `gofmt -l` prints nothing; build/vet/test all pass; `govulncheck` reports no vulnerabilities. If any step fails, STOP and root-cause (superpowers:systematic-debugging) before proceeding — do not paper over.

- [ ] **Step 2: Confirm the `risk` package was NOT touched (scope guard).**
  ```
  git diff --name-only main...HEAD -- internal/risk/
  ```
  Expected: empty output (diff against the branch base `main`). Sub-project A must not modify `internal/risk` (that is sub-project B). If anything shows here, revert it.

- [ ] **Step 3: Record the `EscalateSharedWithDA` handoff (no code change in A).**
  `EscalateSharedWithDA` (model.go:282–311) already propagates literal DA-path sharing through the shared-hash cluster. The spec's optional minor #5 (also propagating Tier-0/DA-equivalent membership through the same cluster) is **scoring policy** and therefore belongs to sub-project B, which owns the shared-hash-to-DA escalation semantics. A leaves it UNCHANGED and hands off the signal: B can read `ExtractControlsTier0` (Task 2) when deciding cluster propagation. No commit needed for this step — it is documentation; ensure the final review captures it.

- [ ] **Step 4 (optional, if any verification doc/notes were added): commit.**
  If Steps 1–3 produced no file changes, there is nothing to commit — sub-project A is complete at the Task 4 commit. Otherwise:
  ```
  git add -A
  git commit -m "chore(scoring-v2-A): acceptance gate green; document EscalateSharedWithDA handoff to B"
  ```

**Proves:** The four ingestion gaps ship together green under the full gate suite, `internal/risk` is untouched, and the deliberate scope boundary (no `EscalateSharedWithDA` change in A) is recorded.

---

## Self-Review — spec coverage of the four gaps

- **Gap 1 (controllables truncated to ~10 — spec Problem #1 / A bullet 1):** Task 1 threads `env.Count` out of `GetUserControllables`, stores it on `UserData.ControllableTotal`, and makes `ExtractControllableCount` return the true total (label-sum fallback only when absent). The `>10` boundary concern is addressed structurally — the count is no longer the sample size, so the `>10/>100/...` tiers become reachable. Covered.
- **Gap 2 (Tier-0 / sensitivity — A bullet 2):** Task 2 retains each controllable's `{Label,Name}` (`ControllableItem`), adds `ExtractControlsTier0` matching DOMAIN/ENTERPRISE ADMINS, ADMINISTRATORS, DOMAIN CONTROLLERS, KRBTGT, ADMINSDHOLDER (case-insensitive) plus a controlled `Domain` object (DCSync), and raises the default `controllablesLimit` 10→100 as recommended. The best-effort-from-sample limitation is documented. Covered.
- **Gap 3 (roastable on the live path — spec Problem #6 / A bullet 3):** Task 3 adds `HasSPN`/`DontReqPreauth` to `UserProps` (auto-decoded by `GetUserFull`) and sets them in `BloodhoundEnricher.Enrich`, achieving live/bulk parity. Covered.
- **Gap 4 (per-account coverage — spec Problem #8 / A bullet "coverage state"):** Task 4 adds `Enrichment.Enriched` (set true/false on both enrich paths — bulk via `props.ObjectID != ""`) and `model.Account.Coverage` "full"/"none", set in both `scoreCracked` and `scoreUncracked`, confirmed redaction-safe. Covered.
- **Optional #5 (shared-cluster Tier-0 propagation):** Deliberately NOT implemented in A (it is scoring policy owned by B); documented as a handoff in Task 5. `EscalateSharedWithDA` is unchanged. Per the spec's own guidance ("Default: no change in A"). Covered as a non-change.
- **Constraints honored:** Go stdlib-only changes; CGO-free; all tests deterministic and offline (httptest mocks mirror the existing `newTestClient`/`verifySig` harness — no real network); every task leaves the tree green and is individually shippable; `internal/risk` untouched; gates (`gofmt -l`, `go build/vet/test ./...`, `govulncheck`) run before each commit with no `--no-verify`.
