# Account Detail Page (pivot / "expand details") Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an "Expand details" action to the account drawer that opens the account on a full-screen detail page showing a plain-English "why this level" trace plus identity-only relationship sections (reuse group, the DA account(s) behind a Shared-DA escalation, near-duplicate peers, mass-reuse cluster), navigable via a breadcrumb pivot trail with lead-gated inline reveal.

**Architecture:** One new identity-only backend endpoint (`GET /api/accounts/{username}/relationships`) returns the NT-hash reuse group as identities only (never the hash/cleartext). A new full-screen overlay view with a pivot-trail context renders the detail page, reusing the drawer's render units (extracted into a shared module) plus a new pure "why this level" explainer.

**Tech Stack:** Go 1.26 stdlib (`net/http`, `encoding/json`); React 18 + TypeScript + Vite; vitest (node-env, pure-logic only); Playwright MCP for live verification.

**Spec:** `docs/superpowers/specs/2026-06-24-account-detail-pivot-page-design.md`

**Conventions reminder:**
- Gates after each backend task: `gofmt -l cmd internal` (empty), `go build ./...`, `go vet ./...`, `go test ./...`.
- Gates after each frontend task (run in `web/`, **never `npm install`**): `npx tsc --noEmit`, `npx vitest run`. Build (`npm run build`) before the Playwright task.
- The vitest suite is **node-env, pure-logic only** — there is no jsdom/component rendering. So React components are verified by `tsc` + `build` + Playwright, and only pure functions get vitest unit tests.
- `web/src/styles.css` is the single stylesheet. `styleguard.test.ts` fails the build if a `.tsx` `style={{…}}` prop uses a literal px/number for spacing/size — **use CSS classes, never inline literal spacing.**

---

## Task 1: `ReuseGroupPeers` model helper

**Files:**
- Create: `internal/model/relationships.go`
- Test: `internal/model/relationships_test.go`

- [ ] **Step 1: Write the failing test**

`internal/model/relationships_test.go`:
```go
package model

import "testing"

func acct(u, d, hash, risk, da string, cracked, enabled bool) Account {
	return Account{Username: u, Domain: d, NTHash: hash, RiskLevel: risk, DADomains: da, Cracked: cracked, Enabled: enabled}
}

func TestReuseGroupPeers_GroupsSortsAndCounts(t *testing.T) {
	focus := acct("alice", "CORP", "AAA", "Critical", "", true, true)
	accts := []Account{
		focus,
		acct("bob", "CORP", "AAA", "High", "", true, true),
		acct("administrator", "CORP", "AAA", "Critical", "CORP", true, true), // DA peer
		acct("carol", "CORP", "BBB", "Low", "", true, true),                  // different hash
	}
	peers, total, cracked, da := ReuseGroupPeers(accts, focus, 100)
	if total != 2 || cracked != 2 || da != 1 {
		t.Fatalf("totals: got total=%d cracked=%d da=%d, want 2/2/1", total, cracked, da)
	}
	if len(peers) != 2 {
		t.Fatalf("peers: got %d, want 2", len(peers))
	}
	if peers[0].Username != "administrator" || !peers[0].HasDAPath {
		t.Errorf("DA peer must sort first with HasDAPath=true, got %+v", peers[0])
	}
	for _, p := range peers {
		if p.Username == "alice" || p.Username == "carol" {
			t.Errorf("unexpected peer %s (self or different-hash)", p.Username)
		}
	}
}

func TestReuseGroupPeers_BlankHashNeverGroups(t *testing.T) {
	focus := acct("svc", "CORP", "", "Low", "", false, true)
	accts := []Account{focus, acct("svc2", "CORP", "", "Low", "", false, true)}
	peers, total, _, _ := ReuseGroupPeers(accts, focus, 100)
	if total != 0 || len(peers) != 0 {
		t.Fatalf("blank hash must not group: total=%d peers=%d", total, len(peers))
	}
	if peers == nil {
		t.Errorf("peers must be non-nil empty slice for stable JSON []")
	}
}

func TestReuseGroupPeers_CapTruncatesButCountsStayExact(t *testing.T) {
	focus := acct("a0", "CORP", "AAA", "Low", "", true, true)
	accts := []Account{focus}
	for i := 1; i <= 5; i++ {
		accts = append(accts, acct("a"+string(rune('0'+i)), "CORP", "AAA", "Low", "", true, true))
	}
	peers, total, cracked, _ := ReuseGroupPeers(accts, focus, 2)
	if len(peers) != 2 {
		t.Fatalf("cap: got %d peers, want 2", len(peers))
	}
	if total != 5 || cracked != 5 {
		t.Fatalf("counts must be exact pre-cap: total=%d cracked=%d, want 5/5", total, cracked)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/model/ -run TestReuseGroupPeers -v`
Expected: FAIL — `undefined: ReuseGroupPeers` (and `PeerRef`).

- [ ] **Step 3: Write minimal implementation**

`internal/model/relationships.go`:
```go
package model

import "sort"

// PeerRef is an identity-only reference to an account in a relationship list.
// It deliberately carries NO secret material (no NT hash, no password).
type PeerRef struct {
	Username  string `json:"username"`
	Domain    string `json:"domain"`
	RiskLevel string `json:"risk_level"`
	Cracked   bool   `json:"cracked"`
	Enabled   bool   `json:"enabled"`
	HasDAPath bool   `json:"has_da_path"` // flags the DA account(s) behind a Shared-DA escalation
}

// riskRank orders risk levels for sorting (lower = more severe).
func riskRank(level string) int {
	switch level {
	case "Critical":
		return 0
	case "High":
		return 1
	case "Medium":
		return 2
	case "Low":
		return 3
	default:
		return 4
	}
}

// ReuseGroupPeers returns the OTHER accounts sharing focus's NT hash (exact password
// reuse). Accounts with an empty/blank-password NT hash (reuseKey == "") never group.
// Peers are sorted DA-first then by descending risk, and capped at limit (limit <= 0
// means no cap). total/crackedCount/daCount are EXACT (counted before the cap) so a
// caller can show "79 share this password" while listing only the top `limit`. The
// returned slice is always non-nil (so JSON renders [] not null).
func ReuseGroupPeers(accts []Account, focus Account, limit int) (peers []PeerRef, total, crackedCount, daCount int) {
	peers = []PeerRef{}
	key := reuseKey(focus.NTHash)
	if key == "" {
		return peers, 0, 0, 0
	}
	all := []PeerRef{}
	for _, a := range accts {
		if a.Username == focus.Username && a.Domain == focus.Domain {
			continue // exclude self
		}
		if reuseKey(a.NTHash) != key {
			continue
		}
		total++
		if a.Cracked {
			crackedCount++
		}
		da := a.HasDAPathway()
		if da {
			daCount++
		}
		all = append(all, PeerRef{
			Username:  a.Username,
			Domain:    a.Domain,
			RiskLevel: a.RiskLevel,
			Cracked:   a.Cracked,
			Enabled:   a.Enabled,
			HasDAPath: da,
		})
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].HasDAPath != all[j].HasDAPath {
			return all[i].HasDAPath // DA first
		}
		return riskRank(all[i].RiskLevel) < riskRank(all[j].RiskLevel)
	})
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	peers = all
	return peers, total, crackedCount, daCount
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/model/ -run TestReuseGroupPeers -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/model/relationships.go internal/model/relationships_test.go
git commit -m "feat(model): ReuseGroupPeers — identity-only NT-hash reuse group helper"
```

---

## Task 2: `handleAccountRelationships` endpoint

**Files:**
- Modify: `internal/httpapi/server.go` (add route near the reveal route ~line 169; add handler)
- Test: `internal/httpapi/relationships_test.go`

- [ ] **Step 1: Write the failing test**

`internal/httpapi/relationships_test.go`:
```go
package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// reuseDataset: alice/bob/administrator share NT hash AAA; administrator is DA.
// carol has a different hash. Uses only valid model.Account JSON fields
// (handleIngest uses DisallowUnknownFields).
const reuseDataset = `{"accounts":[
 {"username":"alice","domain":"CORP","password":"P@ss1","cracked":true,"risk_level":"Critical","nt_hash":"AAA","enabled":true,"da_domains":""},
 {"username":"bob","domain":"CORP","password":"P@ss1","cracked":true,"risk_level":"High","nt_hash":"AAA","enabled":true,"da_domains":""},
 {"username":"administrator","domain":"CORP","password":"P@ss1","cracked":true,"risk_level":"Critical","nt_hash":"AAA","enabled":true,"da_domains":"CORP"},
 {"username":"carol","domain":"CORP","password":"Other","cracked":true,"risk_level":"Low","nt_hash":"BBB","enabled":true,"da_domains":""}
]}`

func seedReuse(t *testing.T, srv *Server, cookie, csrf string) string {
	t.Helper()
	req := mustReq("POST", "/api/ingest", strings.NewReader(reuseDataset))
	req.Header.Set("Authorization", "Bearer secret")
	rec := recorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body.String())
	}
	var body struct{ AuditID string `json:"audit_id"` }
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return body.AuditID
}

func TestRelationships_ReuseGroupIdentitiesOnly(t *testing.T) {
	srv := newServer("secret")
	cookie, csrf := loginCSRF(t, srv, "lead", "leadpw")
	id := seedReuse(t, srv, cookie.Value, csrf)
	openAudit(t, srv, cookie, csrf, id)

	rec := do(srv, "GET", "/api/accounts/alice/relationships?domain=CORP", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "nt_hash") || strings.Contains(body, "\"password\"") {
		t.Fatalf("response must not leak secrets: %s", body)
	}
	var r struct {
		ReuseGroup struct {
			SharesHash bool `json:"shares_hash"`
			Total      int  `json:"total"`
			DACount    int  `json:"da_count"`
			Members    []struct {
				Username  string `json:"username"`
				HasDAPath bool   `json:"has_da_path"`
			} `json:"members"`
		} `json:"reuse_group"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if !r.ReuseGroup.SharesHash || r.ReuseGroup.Total != 2 || r.ReuseGroup.DACount != 1 {
		t.Fatalf("group: shares=%v total=%d da=%d, want true/2/1", r.ReuseGroup.SharesHash, r.ReuseGroup.Total, r.ReuseGroup.DACount)
	}
	if len(r.ReuseGroup.Members) != 2 || r.ReuseGroup.Members[0].Username != "administrator" || !r.ReuseGroup.Members[0].HasDAPath {
		t.Fatalf("members must be DA-first: %+v", r.ReuseGroup.Members)
	}
}

func TestRelationships_NotFound(t *testing.T) {
	srv := newServer("secret")
	cookie, csrf := loginCSRF(t, srv, "lead", "leadpw")
	id := seedReuse(t, srv, cookie.Value, csrf)
	openAudit(t, srv, cookie, csrf, id)
	rec := do(srv, "GET", "/api/accounts/nobody/relationships?domain=CORP", cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", rec.Code)
	}
}

func TestRelationships_AnalystAllowed(t *testing.T) {
	srv := newServer("secret")
	cookie, csrf := loginCSRF(t, srv, "lead", "leadpw")
	id := seedReuse(t, srv, cookie.Value, csrf)
	openAudit(t, srv, cookie, csrf, id)
	acookie := login(t, srv, "analyst", "analystpw")
	openAudit(t, srv, acookie, csrfFor(t, srv, "analyst", "analystpw"), id)
	rec := do(srv, "GET", "/api/accounts/alice/relationships?domain=CORP", acookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyst got %d, want 200 (identities are not secret): %s", rec.Code, rec.Body.String())
	}
}
```

> **Note on test helpers:** This test references `mustReq`, `recorder`, and `csrfFor`. If they don't already exist in `internal/httpapi/*_test.go`, replace them with the existing equivalents the package already uses — `httptest.NewRequest`, `httptest.NewRecorder`, and `loginCSRF` (which returns `(cookie, csrf)`). Confirm by reading `server_test.go` before writing. The structural assertions (total/da_count/DA-first/no-secrets) are the contract; adapt the plumbing to the existing helpers.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/httpapi/ -run TestRelationships -v`
Expected: FAIL — route not registered (404 for all) / handler undefined.

- [ ] **Step 3: Register the route**

In `internal/httpapi/server.go`, immediately after the reveal route (`GET /api/accounts/{username}/secret`, ~line 169):
```go
	mux.Handle("GET /api/accounts/{username}/relationships", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleAccountRelationships))))
```

- [ ] **Step 4: Write the handler**

Add to `internal/httpapi/server.go` (near `handleReveal`):
```go
// handleAccountRelationships returns the focus account's NT-hash reuse group as
// IDENTITIES ONLY (username/domain/risk/flags) — never the NT hash or cleartext. The
// page derives the reuse group, the Shared-DA peers (has_da_path), and the mass-reuse
// summary from this; near-duplicate peers come from the account's own similar_peers.
func (s *Server) handleAccountRelationships(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	username := r.PathValue("username")
	domain := r.URL.Query().Get("domain")
	id, ok := s.activeAudit(w, sess)
	if !ok {
		return
	}
	accts, err := s.Store.Accounts(id, true) // unredacted: NT hash for grouping only; never returned
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load accounts"})
		return
	}
	var focus model.Account
	found := false
	for _, a := range accts {
		if a.Username == username && (domain == "" || a.Domain == domain) {
			focus, found = a, true
			break
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "account not found"})
		return
	}
	peers, total, crackedCount, daCount := model.ReuseGroupPeers(accts, focus, 100)
	writeJSON(w, http.StatusOK, map[string]any{
		"username": focus.Username,
		"domain":   focus.Domain,
		"reuse_group": map[string]any{
			"shares_hash":   total > 0,
			"total":         total,
			"cracked_count": crackedCount,
			"da_count":      daCount,
			"truncated":     total > len(peers),
			"members":       peers,
		},
	})
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/httpapi/ -run TestRelationships -v`
Expected: PASS (3 tests).

> If `TestRelationships_ReuseGroupIdentitiesOnly` returns 423 (store locked), the test server's store needs unlocking first — add the same unlock step the existing reveal/unlock tests use, then re-run. If `total` is 0, the ingest engine isn't preserving `nt_hash`; verify `model.Dataset`/engine keep it (the live reuse-group exports prove it does).

- [ ] **Step 6: Full backend gate + commit**

```bash
gofmt -l cmd internal && go build ./... && go vet ./... && go test ./...
git add internal/httpapi/server.go internal/httpapi/relationships_test.go
git commit -m "feat(api): GET /api/accounts/{username}/relationships — identity-only reuse group"
```

---

## Task 3: API client types + method

**Files:**
- Modify: `web/src/api.ts` (add types; add `relationships` to the `api` object near `revealSecret` ~line 426)

> No vitest unit test: this is a thin declarative fetch wrapper matching the existing untested `api` methods. Verified by `tsc`.

- [ ] **Step 1: Add types**

In `web/src/api.ts`, near the other exported interfaces:
```ts
export interface PeerRef {
  username: string
  domain: string
  risk_level: string
  cracked: boolean
  enabled: boolean
  has_da_path: boolean
}

export interface Relationships {
  username: string
  domain: string
  reuse_group: {
    shares_hash: boolean
    total: number
    cracked_count: number
    da_count: number
    truncated: boolean
    members: PeerRef[]
  }
}
```

- [ ] **Step 2: Add the method**

In the `api` object (near `revealSecret`):
```ts
  relationships: (username: string, domain?: string) =>
    request<Relationships>(
      `/accounts/${encodeURIComponent(username)}/relationships${domain ? `?domain=${encodeURIComponent(domain)}` : ""}`,
    ),
```

- [ ] **Step 3: Typecheck + commit**

Run (in `web/`): `npx tsc --noEmit`
Expected: no errors.

```bash
git add web/src/api.ts
git commit -m "feat(web/api): relationships() client method + types"
```

---

## Task 4: `explainLevel` pure function

**Files:**
- Create: `web/src/whyLevel.ts`
- Test: `web/src/whyLevel.test.ts`

- [ ] **Step 1: Write the failing test**

`web/src/whyLevel.test.ts`:
```ts
import { describe, expect, it } from "vitest"
import { explainLevel } from "./whyLevel"
import type { Account } from "./api"

function base(over: Partial<Account>): Account {
  return {
    username: "u", domain: "CORP", risk_level: "Low", cracked: true,
    exposure_score: 3, impact_score: 2, shared_with: 0, hibp_breached: false,
    hibp_breach_count: 0, da_domains: "", controls_tier0: false,
    escalated_by_shared_da: false, escalated_by_mass_reuse: false,
    risk_score: 1, risk_vector: "", password_length: 8, complexity: "x",
    enabled: true, pwd_never_expires: false,
  } as Account
}

describe("explainLevel", () => {
  it("headlines Shared-DA", () => {
    const lines = explainLevel(base({ risk_level: "Critical", escalated_by_shared_da: true }))
    expect(lines[0]).toMatch(/Domain-Admin account/i)
  })
  it("headlines own DA path", () => {
    const lines = explainLevel(base({ risk_level: "Critical", da_domains: "CORP" }))
    expect(lines[0]).toMatch(/Domain-Admin attack path/i)
  })
  it("headlines Tier-0 control", () => {
    const lines = explainLevel(base({ risk_level: "High", controls_tier0: true }))
    expect(lines[0]).toMatch(/Tier-0/i)
  })
  it("headlines mass-reuse", () => {
    const lines = explainLevel(base({ risk_level: "High", escalated_by_mass_reuse: true }))
    expect(lines[0]).toMatch(/reuse cluster/i)
  })
  it("falls back to the Exposure x Impact matrix", () => {
    const lines = explainLevel(base({ risk_level: "Medium", exposure_score: 4.8, impact_score: 5 }))
    expect(lines[0]).toMatch(/Exposure .* Impact/i)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run (in `web/`): `npx vitest run whyLevel`
Expected: FAIL — cannot find `./whyLevel`.

- [ ] **Step 3: Write the implementation**

`web/src/whyLevel.ts`:
```ts
import type { Account } from "./api"
import { hasDA } from "./util"

// tierName mirrors the Go risk tierOf thresholds (display-only; not byte-pinned to Go).
function tierName(v: number): string {
  if (v >= 8) return "Critical"
  if (v >= 6) return "High"
  if (v >= 4) return "Medium"
  return "Low"
}

function impactTierLabel(a: Account): string {
  return a.impact_score == null ? "Unknown" : tierName(a.impact_score)
}

function exposureDriver(a: Account): string {
  if (a.hibp_breached) return `Exposure is floored — the password appears in ${a.hibp_breach_count.toLocaleString()} public breaches (HIBP).`
  if (a.cracked) return `Exposure is floored because the password was cracked.`
  if ((a.shared_with ?? 0) >= 50) return `Exposure is floored by a large reuse cluster — ${a.shared_with} other accounts share this password.`
  return `Exposure is ${tierName(a.exposure_score)} (${a.exposure_score.toFixed(1)}/10).`
}

// explainLevel returns ordered plain-English lines deriving the account's level. Line 0
// is the dominant reason (escalation override or the Exposure x Impact matrix cell);
// line 1 adds the dominant Exposure driver for context.
export function explainLevel(a: Account): string[] {
  const lvl = a.risk_level
  const lines: string[] = []
  if (a.escalated_by_shared_da) {
    lines.push(`${lvl} — this account shares a password with a Domain-Admin account; cracking this credential yields Domain Admin.`)
  } else if (hasDA(a.da_domains)) {
    lines.push(`${lvl} — this account has a confirmed Domain-Admin attack path (${a.da_domains}).`)
  } else if (a.controls_tier0) {
    lines.push(`${lvl} — this account controls a Tier-0 / DA-equivalent asset, so Impact is pinned to maximum.`)
  } else if (a.escalated_by_mass_reuse) {
    lines.push(`${lvl} — this account is part of a large cracked password-reuse cluster; cracking one member compromises all of them.`)
  } else {
    lines.push(`${lvl} — derived from Exposure ${tierName(a.exposure_score)} × Impact ${impactTierLabel(a)}.`)
  }
  lines.push(exposureDriver(a))
  return lines
}
```

- [ ] **Step 4: Run test to verify it passes**

Run (in `web/`): `npx vitest run whyLevel`
Expected: PASS (5 tests).

> If `hasDA` is not exported from `web/src/util.ts`, inline the check `a.da_domains !== "" && a.da_domains !== "None" && a.da_domains !== "Unknown"` instead (mirrors Go `HasDAPathway`).

- [ ] **Step 5: Commit**

```bash
git add web/src/whyLevel.ts web/src/whyLevel.test.ts
git commit -m "feat(web): explainLevel — plain-English 'why this level' trace"
```

---

## Task 5: Pivot-trail reducer (pure)

**Files:**
- Create: `web/src/trail.ts`
- Test: `web/src/trail.test.ts`

- [ ] **Step 1: Write the failing test**

`web/src/trail.test.ts`:
```ts
import { describe, expect, it } from "vitest"
import { type Crumb, pushCrumb, popCrumb, jumpCrumb } from "./trail"

const a: Crumb = { username: "alice", domain: "CORP" }
const b: Crumb = { username: "bob", domain: "CORP" }

describe("trail reducer", () => {
  it("pushes a new crumb", () => {
    expect(pushCrumb([a], b)).toEqual([a, b])
  })
  it("ignores a consecutive duplicate of the tail", () => {
    expect(pushCrumb([a, b], { ...b })).toEqual([a, b])
  })
  it("pops the last crumb but never below depth 1", () => {
    expect(popCrumb([a, b])).toEqual([a])
    expect(popCrumb([a])).toEqual([a])
  })
  it("jumps to a depth, truncating deeper crumbs", () => {
    expect(jumpCrumb([a, b], 0)).toEqual([a])
    expect(jumpCrumb([a, b], 5)).toEqual([a, b]) // out of range = no-op
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run (in `web/`): `npx vitest run trail`
Expected: FAIL — cannot find `./trail`.

- [ ] **Step 3: Write the implementation**

`web/src/trail.ts`:
```ts
export type Crumb = { username: string; domain: string }

// pushCrumb appends c unless it equals the current tail (avoids self-pivot dupes).
export function pushCrumb(trail: Crumb[], c: Crumb): Crumb[] {
  const tail = trail[trail.length - 1]
  if (tail && tail.username === c.username && tail.domain === c.domain) return trail
  return [...trail, c]
}

// popCrumb removes the last crumb but keeps the root (depth never drops below 1).
export function popCrumb(trail: Crumb[]): Crumb[] {
  return trail.length > 1 ? trail.slice(0, -1) : trail
}

// jumpCrumb truncates the trail to the crumb at index (inclusive); out-of-range = no-op.
export function jumpCrumb(trail: Crumb[], index: number): Crumb[] {
  return index >= 0 && index < trail.length ? trail.slice(0, index + 1) : trail
}
```

- [ ] **Step 4: Run test to verify it passes**

Run (in `web/`): `npx vitest run trail`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add web/src/trail.ts web/src/trail.test.ts
git commit -m "feat(web): pivot-trail reducer (push/pop/jump, no-dup)"
```

---

## Task 6: Extract shared account-facts render units

**Files:**
- Create: `web/src/components/accountFacts.tsx`
- Modify: `web/src/components/AccountDrawer.tsx` (consume the extracted units)

> Pure refactor — no behavior change to the drawer. Verified by `tsc`, `vitest` (styleguard), `build`. Read `AccountDrawer.tsx` in full before editing.

- [ ] **Step 1: Create the shared module**

`web/src/components/accountFacts.tsx` — move `WeakCell`, `BreakdownCard`, the `rows` builder (as `accountFactRows`), and the breakdown block (as `BreakdownCards`) out of `AccountDrawer.tsx`:
```tsx
import type { ReactNode } from "react"
import type { Account, ScoreBreakdown } from "../api"
import { RISK_CLASS, hasDA, weaknessTags } from "../util"
import { disabledLatentRisk } from "../disabledRisk"
import { impactIsKnown, isProvisional, coverageState } from "../matrix"
import { GLOSSARY } from "../glossary"
import { weaknessSubFactors, policyViolationText } from "../drawerFactors"

export function WeakCell({ a }: { a: Account }) {
  const tags = weaknessTags(a)
  if (!tags.length) return <span className="muted">—</span>
  return (
    <span className="wtags" title="password matched a wordlist">
      {tags.map((t) => (
        <span key={t} className="badge wtag">{t}</span>
      ))}
    </span>
  )
}

function fmtAge(epoch: number | undefined): string {
  if (!epoch || epoch <= 0) return "Unknown"
  const days = Math.floor((Date.now() / 1000 - epoch) / 86400)
  if (days < 1) return "Today"
  if (days < 30) return `${days}d ago`
  if (days < 365) return `${Math.floor(days / 30)}mo ago`
  return `${(days / 365).toFixed(1)}y ago`
}

// accountFactRows is the labelled field list shared by the drawer (quick view) and the
// detail page (full view). Moved verbatim from AccountDrawer so both stay identical.
export function accountFactRows(a: Account): [string, ReactNode][] {
  return [
    ["Domain", a.domain],
    ["Status", a.cracked ? "Cracked" : "Uncracked"],
    ["Risk level", <span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span>],
    ["Exposure", a.exposure_score.toFixed(1)],
    [
      "Impact",
      impactIsKnown(a) ? (
        (a.impact_score as number).toFixed(1)
      ) : (
        <span className="badge-provisional" title={GLOSSARY.impact_unknown}>Unknown</span>
      ),
    ],
    ["Coverage", coverageState(a) === "full" ? "BloodHound-enriched" : "Not enriched"],
    ...(a.percentile != null ? ([["Triage percentile", `${Math.round(a.percentile * 100)}th`]] as [string, ReactNode][]) : []),
    ["Risk score", a.risk_score.toFixed(1)],
    ["Risk vector", <code className="vector">{a.risk_vector || "—"}</code>],
    ["HIBP breaches", a.hibp_breached ? a.hibp_breach_count.toLocaleString() : "—"],
    ["Complexity", a.cracked ? a.complexity : "—"],
    ["Password length", a.cracked ? a.password_length : "—"],
    ["Meets policy", a.cracked ? policyViolationText(a) : "—"],
    ["Weaknesses", !a.cracked ? "—" : weaknessTags(a).length ? <WeakCell a={a} /> : <span className="muted">none</span>],
    ...(a.cracked && a.contains_unicode ? ([["Contains Unicode", "Yes ⚠ — non-ASCII characters"]] as [string, ReactNode][]) : []),
    ["Similarity", a.cracked && (a.similarity_score ?? 0) > 0 ? `${((a.similarity_score ?? 0) * 100).toFixed(0)}% match to another password` : "—"],
    ["Shared with", a.shared_with],
    ["DA pathway", hasDA(a.da_domains) ? a.da_domains : "—"],
    ["Controlled objects", a.controlled_object_count],
    ...(a.controls_tier0 ? ([["Controls Tier-0", "Yes ⚠ — DA-equivalent asset"]] as [string, ReactNode][]) : []),
    ["Password last set", fmtAge(a.pwd_last_set)],
    ["Password never expires", a.pwd_never_expires === true ? "Yes ⚠" : a.pwd_never_expires === false ? "No" : "Unknown"],
    ["Days out of compliance", a.days_out_of_compliance ? `${a.days_out_of_compliance}d overdue` : "—"],
    ["Escalated (Shared-DA)", a.escalated_by_shared_da ? "Yes — shares hash with a DA account" : "—"],
    ["Escalated (Mass-reuse)", a.escalated_by_mass_reuse ? "Yes — one crack compromises this whole reuse cluster" : "—"],
    ["Kerberoastable (SPN)", a.has_spn === true ? "Yes ⚠ — offline crackable via TGS" : "No"],
    ["AS-REP roastable", a.dont_req_preauth === true ? "Yes ⚠ — no pre-auth required" : "No"],
    ["Enabled", a.enabled ? "Yes" : "No"],
    ...(disabledLatentRisk(a)
      ? ([["Latent risk", "Disabled ⚠ — re-enable / Pass-the-Hash persistence path"]] as [string, ReactNode][])
      : []),
  ]
}

function BreakdownCard({ title, score, factors }: { title: string; score: string; factors: [string, number][] }) {
  return (
    <div className="bd-card">
      <div className="bd-card-head">
        <span className="bd-card-title">{title}</span>
        <span className="bd-card-score">{score}</span>
      </div>
      <div className="bd-card-factors">
        {factors.map(([name, value]) => (
          <div className="bd-factor" key={name}>
            <span>{name}</span>
            <span className="mono">{value.toFixed(2)}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// BreakdownCards renders the v2 Exposure/Impact axis cards + escalation notes. Shared by
// the drawer and the detail page. Returns null when there's nothing to show.
export function BreakdownCards({ a }: { a: Account }) {
  const bd = a.score_breakdown
  if (!bd && !isProvisional(a)) return null
  const v = (k: keyof ScoreBreakdown): number => {
    const x = bd?.[k]
    return typeof x === "number" ? x : 0
  }
  return (
    <div className="drawer-breakdown">
      <div className="drawer-section-title">Score breakdown (v2)</div>
      <div className="breakdown-grid">
        {bd && (
          <BreakdownCard
            title="Exposure"
            score={a.exposure_score.toFixed(1)}
            factors={[
              ["Weakness", v("weakness_score")],
              ...weaknessSubFactors(bd).map(([label, val]) => [`· ${label}`, val] as [string, number]),
              ["HIBP floor", v("hibp_floor")],
              ["Cracked floor", v("cracked_floor")],
              ["Reuse", v("reuse_bump")],
              ["Roastable", v("roastable_bump")],
              ["Age", v("age_penalty")],
            ]}
          />
        )}
        {impactIsKnown(a) ? (
          bd && (
            <BreakdownCard
              title="Impact"
              score={(a.impact_score as number).toFixed(1)}
              factors={[
                ["Privilege", v("privilege_sub_score")],
                ["DA path", v("da_component")],
                ["Domain", v("domain_modifier")],
              ]}
            />
          )
        ) : (
          <div className="bd-card impact-unknown-card">
            <div className="bd-card-head">
              <span className="bd-card-title">Impact</span>
              <span className="badge-provisional" title={GLOSSARY.impact_unknown}>Unknown</span>
            </div>
            <p className="impact-unknown-note">
              Impact Unknown — this account was not BloodHound-enriched, so its blast
              radius can't be computed. Run enrichment to finalize the level.
            </p>
          </div>
        )}
      </div>
      {bd?.enabled_gated && <p className="bd-note">Impact was gated because the account is disabled in AD.</p>}
      {a.escalated_by_shared_da && <p className="bd-note">Impact forced to 10 — shares a password with a Domain-Admin account.</p>}
      {a.controls_tier0 && <p className="bd-note">Privilege pinned to 10 — controls a Tier-0 / DA-equivalent asset.</p>}
    </div>
  )
}
```

- [ ] **Step 2: Slim down `AccountDrawer.tsx` to consume the shared units**

Replace the body of `AccountDrawer.tsx` so it imports from `./accountFacts` and renders `accountFactRows(a)` + `<BreakdownCards a={a} />`. Keep the `useEffect` Escape handler, the `drawer` markup, and re-export `WeakCell` from `accountFacts` for any external importers:
```tsx
import { useEffect } from "react"
import type { Account } from "../api"
import { accountFactRows, BreakdownCards, WeakCell } from "./accountFacts"

export { WeakCell }

export function AccountDrawer({ account: a, onClose }: { account: Account; onClose: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose()
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [onClose])

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={`Account ${a.username}`}>
        <div className="drawer-head">
          <span className="drawer-title">{a.username}</span>
          <button className="link-btn" onClick={onClose}>close</button>
        </div>
        <dl className="drawer-fields">
          {accountFactRows(a).map(([k, v]) => (
            <div className="drawer-row" key={k}><dt>{k}</dt><dd>{v}</dd></div>
          ))}
        </dl>
        <BreakdownCards a={a} />
      </aside>
    </>
  )
}
```

> The "Expand details" button is added in Task 9 (it needs `useAccountDetail`, defined in Task 7). Check that no other file imports `WeakCell` from a path that breaks — `grep -rn "WeakCell" web/src`; it is re-exported here so existing imports keep working.

- [ ] **Step 3: Gate + commit**

Run (in `web/`): `npx tsc --noEmit && npx vitest run`
Expected: no type errors; vitest (incl. styleguard) passes.

```bash
git add web/src/components/accountFacts.tsx web/src/components/AccountDrawer.tsx
git commit -m "refactor(web): extract shared account-facts render units (drawer + detail page)"
```

---

## Task 7: Pivot-trail provider + overlay mount

**Files:**
- Create: `web/src/accountDetail.tsx`

> Component (no vitest). Verified by `tsc` here; behavior in Task 10. The `AccountDetail` page it renders is built in Task 8 — to keep this task compiling on its own, create a minimal placeholder `AccountDetail` first if building strictly task-by-task, then flesh it out in Task 8. (Subagent-driven execution builds Task 8 immediately after, so a one-line placeholder is fine.)

- [ ] **Step 1: Write the provider**

`web/src/accountDetail.tsx`:
```tsx
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react"
import type { Account } from "./api"
import { AccountDetail } from "./components/AccountDetail"
import { type Crumb, pushCrumb, popCrumb, jumpCrumb } from "./trail"

interface DetailState {
  open: (a: Account) => void
  pushPeer: (c: Crumb) => void
  back: () => void
  jump: (index: number) => void
  close: () => void
}
const Ctx = createContext<DetailState | null>(null)

// AccountDetailProvider owns the pivot trail and renders the full-screen detail overlay
// when the trail is non-empty. Mounts inside AccountsProvider (reads accounts) and wraps
// AccountDrawerProvider (so the drawer's "Expand details" button can call open()).
export function AccountDetailProvider({ children }: { children: ReactNode }) {
  const [trail, setTrail] = useState<Crumb[]>([])
  const open = useCallback((a: Account) => setTrail([{ username: a.username, domain: a.domain }]), [])
  const pushPeer = useCallback((c: Crumb) => setTrail((t) => pushCrumb(t, c)), [])
  const back = useCallback(() => setTrail((t) => popCrumb(t)), [])
  const jump = useCallback((i: number) => setTrail((t) => jumpCrumb(t, i)), [])
  const close = useCallback(() => setTrail([]), [])
  const value = useMemo(() => ({ open, pushPeer, back, jump, close }), [open, pushPeer, back, jump, close])
  return (
    <Ctx.Provider value={value}>
      {children}
      {trail.length > 0 && (
        <AccountDetail trail={trail} onBack={back} onJump={jump} onPivot={pushPeer} onClose={close} />
      )}
    </Ctx.Provider>
  )
}

export function useAccountDetail(): DetailState {
  const c = useContext(Ctx)
  if (!c) throw new Error("useAccountDetail must be used within AccountDetailProvider")
  return c
}
```

- [ ] **Step 2: Typecheck + commit**

Run (in `web/`): `npx tsc --noEmit`
Expected: fails only if `./components/AccountDetail` doesn't exist yet — build Task 8 in the same iteration, then this compiles. (If executing strictly one task at a time, add a temporary `export function AccountDetail(_: any) { return null }` stub in `web/src/components/AccountDetail.tsx`, then replace it in Task 8.)

```bash
git add web/src/accountDetail.tsx
git commit -m "feat(web): AccountDetailProvider — pivot-trail context + overlay mount"
```

---

## Task 8: The detail page component + styles

**Files:**
- Create/replace: `web/src/components/AccountDetail.tsx`
- Modify: `web/src/styles.css` (append the detail-page classes)

> Component (no vitest); verified by `tsc` + `build` here, behavior in Task 10. Uses CSS classes only (styleguard bans inline literal spacing).

- [ ] **Step 1: Write the page**

`web/src/components/AccountDetail.tsx`:
```tsx
import { useEffect, useState } from "react"
import { api, ApiError, type Account, type PeerRef, type Relationships } from "../api"
import { useAccountsData } from "../accountsData"
import { useAuth } from "../auth"
import { type Crumb } from "../trail"
import { explainLevel } from "../whyLevel"
import { accountFactRows, BreakdownCards } from "./accountFacts"
import { RISK_CLASS } from "../util"

type RevealMap = Record<string, string>
const peerKey = (u: string, d: string) => `${u}@${d}`

export function AccountDetail({
  trail, onBack, onJump, onPivot, onClose,
}: {
  trail: Crumb[]
  onBack: () => void
  onJump: (index: number) => void
  onPivot: (c: Crumb) => void
  onClose: () => void
}) {
  const tail = trail[trail.length - 1]
  const { accounts } = useAccountsData()
  const { me } = useAuth()
  const isLead = me?.role === "lead"
  const account = (accounts ?? []).find((a) => a.username === tail.username && a.domain === tail.domain)

  const [rel, setRel] = useState<Relationships | null>(null)
  const [relErr, setRelErr] = useState("")
  const [revealed, setRevealed] = useState<RevealMap>({})
  const [revealErr, setRevealErr] = useState("")

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose()
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [onClose])

  useEffect(() => {
    let alive = true
    setRel(null)
    setRelErr("")
    setRevealed({})
    api
      .relationships(tail.username, tail.domain)
      .then((r) => alive && setRel(r))
      .catch((e) => alive && setRelErr(e instanceof ApiError ? e.message : "failed to load relationships"))
    return () => {
      alive = false
    }
  }, [tail.username, tail.domain])

  async function reveal(username: string, domain: string) {
    setRevealErr("")
    try {
      const r = await api.revealSecret(username, domain)
      setRevealed((p) => ({ ...p, [peerKey(username, domain)]: r.password }))
    } catch (e) {
      setRevealErr(e instanceof ApiError ? `reveal failed: ${e.message}` : "reveal failed")
    }
  }

  return (
    <div className="detail-overlay" role="dialog" aria-modal="true" aria-label={`Account ${tail.username}`}>
      <div className="detail-head">
        <nav className="detail-crumbs" aria-label="pivot trail">
          <span className="crumb-root">Accounts</span>
          {trail.map((c, i) => (
            <span key={peerKey(c.username, c.domain)} className="crumb-wrap">
              <span className="crumb-sep">›</span>
              {i === trail.length - 1 ? (
                <span className="crumb-current">{c.username}</span>
              ) : (
                <button className="link-btn crumb-link" onClick={() => onJump(i)}>{c.username}</button>
              )}
            </span>
          ))}
        </nav>
        <div className="detail-head-actions">
          {trail.length > 1 && <button className="link-btn" onClick={onBack}>← Back</button>}
          <button className="link-btn" onClick={onClose}>close</button>
        </div>
      </div>

      {!account ? (
        <div className="detail-body">
          <p className="muted">This account isn’t in the current audit’s loaded data.</p>
        </div>
      ) : (
        <div className="detail-body">
          <div className="detail-title-row">
            <span className="detail-title">{account.username}@{account.domain}</span>
            <span className={`badge ${RISK_CLASS[account.risk_level] || ""}`}>{account.risk_level}</span>
            {isLead && account.cracked && (
              peerKey(account.username, account.domain) in revealed ? (
                <code className="revealed">{revealed[peerKey(account.username, account.domain)]}</code>
              ) : (
                <button className="btn-reveal" onClick={() => reveal(account.username, account.domain)}>Reveal</button>
              )
            )}
          </div>

          <section className="detail-why">
            <div className="detail-section-title">Why this level</div>
            {explainLevel(account).map((line, i) => (
              <p key={i} className={i === 0 ? "why-headline" : "why-detail"}>{line}</p>
            ))}
          </section>

          <section className="detail-facts">
            <dl className="drawer-fields">
              {accountFactRows(account).map(([k, v]) => (
                <div className="drawer-row" key={k}><dt>{k}</dt><dd>{v}</dd></div>
              ))}
            </dl>
          </section>

          <BreakdownCards a={account} />

          <RelationshipSections
            account={account}
            rel={rel}
            relErr={relErr}
            isLead={isLead}
            revealed={revealed}
            onReveal={reveal}
            onPivot={onPivot}
          />
          {revealErr && <div className="error">{revealErr}</div>}
        </div>
      )}
    </div>
  )
}

function PeerRow({
  m, isLead, revealed, onReveal, onPivot,
}: {
  m: PeerRef
  isLead: boolean
  revealed: RevealMap
  onReveal: (u: string, d: string) => void
  onPivot: (c: Crumb) => void
}) {
  const key = peerKey(m.username, m.domain)
  return (
    <li className="peer-row">
      <button className="link-btn" onClick={() => onPivot({ username: m.username, domain: m.domain })}>
        {m.username}@{m.domain}
      </button>
      <span className={`badge ${RISK_CLASS[m.risk_level] || ""}`}>{m.risk_level}</span>
      {m.has_da_path && <span className="badge badge-da">DA</span>}
      {!m.enabled && <span className="muted">disabled</span>}
      {isLead && m.cracked && (
        key in revealed ? (
          <code className="revealed">{revealed[key]}</code>
        ) : (
          <button className="btn-reveal" onClick={() => onReveal(m.username, m.domain)}>Reveal</button>
        )
      )}
    </li>
  )
}

function RelationshipSections({
  account, rel, relErr, isLead, revealed, onReveal, onPivot,
}: {
  account: Account
  rel: Relationships | null
  relErr: string
  isLead: boolean
  revealed: RevealMap
  onReveal: (u: string, d: string) => void
  onPivot: (c: Crumb) => void
}) {
  if (relErr) return <div className="error">relationships: {relErr}</div>
  if (!rel) return <div className="muted">Loading relationships…</div>
  const group = rel.reuse_group
  const daMembers = group.members.filter((m) => m.has_da_path)
  const peers = account.similar_peers ?? []
  return (
    <>
      {group.shares_hash && (
        <section className="detail-rel">
          <div className="detail-section-title">Password-reuse group ({group.total})</div>
          <p className="muted">
            {group.cracked_count} cracked · same NT hash
            {group.truncated ? ` · showing first ${group.members.length}` : ""}
          </p>
          <ul className="peer-list">
            {group.members.map((m) => (
              <PeerRow key={peerKey(m.username, m.domain)} m={m} isLead={isLead} revealed={revealed} onReveal={onReveal} onPivot={onPivot} />
            ))}
          </ul>
        </section>
      )}
      {daMembers.length > 0 && (
        <section className="detail-rel rel-da">
          <div className="detail-section-title">⚠ Shares a password with Domain Admin</div>
          <p className="muted">Cracking this credential is equivalent to compromising:</p>
          <ul className="peer-list">
            {daMembers.map((m) => (
              <PeerRow key={`da-${peerKey(m.username, m.domain)}`} m={m} isLead={isLead} revealed={revealed} onReveal={onReveal} onPivot={onPivot} />
            ))}
          </ul>
        </section>
      )}
      {account.escalated_by_mass_reuse && group.shares_hash && (
        <section className="detail-rel">
          <div className="detail-section-title">Mass-reuse cluster</div>
          <p className="muted">
            {group.total + 1} accounts share this password ({group.cracked_count} cracked). Cracking one compromises all.
          </p>
        </section>
      )}
      {peers.length > 0 && (
        <section className="detail-rel">
          <div className="detail-section-title">Near-duplicate passwords</div>
          <ul className="peer-list">
            {peers.map((p) => (
              <li key={`sim-${peerKey(p.username, p.domain)}`} className="peer-row">
                <button className="link-btn" onClick={() => onPivot({ username: p.username, domain: p.domain })}>
                  {p.username}@{p.domain}
                </button>
                <span className="muted">{Math.round(p.score * 100)}% match</span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </>
  )
}
```

- [ ] **Step 2: Append styles**

Append to `web/src/styles.css` (reuse existing tokens; only spacing classes are new). Match the variable names already used in the file — if `--bg`, `--panel`, `--border`, `--muted` differ, substitute the real token names found at the top of `styles.css`:
```css
/* ── Account detail page (pivot / expand-details) ───────────────────── */
.detail-overlay {
  position: fixed;
  inset: 0;
  z-index: 50;
  overflow-y: auto;
  background: var(--bg, #0d1117);
  padding: 1.5rem clamp(1rem, 5vw, 3rem) 3rem;
}
.detail-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 1.25rem;
}
.detail-crumbs { display: flex; align-items: center; flex-wrap: wrap; gap: 0.35rem; }
.crumb-root { color: var(--muted, #8b949e); }
.crumb-sep { color: var(--muted, #8b949e); margin: 0 0.15rem; }
.crumb-current { font-weight: 600; }
.detail-head-actions { display: flex; gap: 0.75rem; }
.detail-body { display: flex; flex-direction: column; gap: 1.25rem; max-width: 70rem; }
.detail-title-row { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
.detail-title { font-size: 1.25rem; font-weight: 700; }
.detail-section-title { font-weight: 600; margin-bottom: 0.5rem; }
.detail-why .why-headline { font-weight: 600; }
.detail-why .why-detail { color: var(--muted, #8b949e); }
.detail-rel { border-top: 1px solid var(--border, #30363d); padding-top: 1rem; }
.detail-rel.rel-da { border-color: #b62324; }
.peer-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 0.4rem; }
.peer-row { display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; }
.badge-da { background: #b62324; color: #fff; }
.btn-reveal { font-size: 0.8rem; padding: 0.1rem 0.5rem; }
```

- [ ] **Step 3: Gate + commit**

Run (in `web/`): `npx tsc --noEmit && npx vitest run`
Expected: no type errors; vitest (incl. styleguard — confirms no inline literal spacing) passes.

```bash
git add web/src/components/AccountDetail.tsx web/src/styles.css
git commit -m "feat(web): account detail page — why-trace + relationship sections + reveal"
```

---

## Task 9: Wire the "Expand details" button + mount the provider

**Files:**
- Modify: `web/src/components/AccountDrawer.tsx` (add the button)
- Modify: `web/src/App.tsx` (mount `AccountDetailProvider`)

- [ ] **Step 1: Add the button to the drawer head**

In `web/src/components/AccountDrawer.tsx`, import the detail hook and add an "Expand details" button that opens the page and closes the drawer:
```tsx
import { useAccountDetail } from "../accountDetail"
```
Replace the `drawer-head` block:
```tsx
        <div className="drawer-head">
          <span className="drawer-title">{a.username}</span>
          <div className="detail-head-actions">
            <button
              className="link-btn"
              onClick={() => {
                openDetail(a)
                onClose()
              }}
            >
              Expand details ⤢
            </button>
            <button className="link-btn" onClick={onClose}>close</button>
          </div>
        </div>
```
And inside the component, before the return, add:
```tsx
  const { open: openDetail } = useAccountDetail()
```

- [ ] **Step 2: Mount `AccountDetailProvider` in the shell**

In `web/src/App.tsx`, import and nest the provider **between** `AccountsProvider` and `AccountDrawerProvider`:
```tsx
import { AccountDetailProvider } from "./accountDetail"
```
```tsx
        <AccountsProvider>
          <AccountDetailProvider>
            <AccountDrawerProvider>
              <JobsProvider>
                <CommandPalette />
                <AppShell view={view} onNav={setView}>
                  <Suspense fallback={<div className="center-state"><div className="spinner">loading</div></div>}>
                    {viewFor(view)}
                  </Suspense>
                </AppShell>
              </JobsProvider>
            </AccountDrawerProvider>
          </AccountDetailProvider>
        </AccountsProvider>
```

- [ ] **Step 3: Gate + commit**

Run (in `web/`): `npx tsc --noEmit && npx vitest run && npm run build`
Expected: clean typecheck, vitest pass, successful production build.

```bash
git add web/src/components/AccountDrawer.tsx web/src/App.tsx
git commit -m "feat(web): wire 'Expand details' button + mount AccountDetailProvider"
```

---

## Task 10: Live verification on the disposable instance + full gates

**Files:** none (verification only).

- [ ] **Step 1: Full backend + frontend gates**

```bash
gofmt -l cmd internal      # expect empty
go build ./... && go vet ./... && go test ./...   # expect all pass
( cd web && npx tsc --noEmit && npx vitest run && npm run build )   # expect clean
```

- [ ] **Step 2: Build the embed binary and stand up the disposable :8444 seed**

```bash
bash .claude/skills/build-and-run/scripts/build.sh
bash tools/dev_seed.sh
```
Expected: `dev_seed.sh` prints "Disposable instance ready" at `http://127.0.0.1:8444` (operator `dev` / `devpass123456`, lead). **Never use the live `:8443` instance.**

- [ ] **Step 3: Drive the flow with Playwright (MCP), assert console is clean**

Verify, via the Playwright MCP against `http://127.0.0.1:8444`:
1. Log in as `dev`; open the **Accounts** tab; click a cracked account name → the drawer opens.
2. Click **"Expand details ⤢"** → the full-screen detail page opens; the drawer is gone.
3. Confirm the page shows: a breadcrumb (`Accounts › <name>`), a **"Why this level"** headline, the score breakdown cards, and a **Password-reuse group** section listing peer accounts (the seed has reuse clusters).
4. Click a peer in the reuse group → the breadcrumb grows (`Accounts › alice › bob`); the page now shows that account.
5. Click **← Back** → the breadcrumb pops to the previous account.
6. As a lead, click **Reveal** on the focused account → cleartext appears.
7. Assert the **browser console shows no 4xx/error noise** (`browser_console_messages` at level "error" since the last navigation = 0). A `423` would mean the seed store is locked — re-run `dev_seed.sh`.

- [ ] **Step 4: Tear down the disposable instance**

```bash
bash tools/dev_seed.sh --stop
```

- [ ] **Step 5: (No code commit — verification task.)** If any gate or flow fails, return to the responsible task; do not mark complete until console is clean and the pivot/back/reveal flow works end to end.

---

## Self-review notes (for the implementer)

- **Spec coverage:** reuse group (Task 1–2, 8), DA-shared peers (Task 1 `daCount`/`has_da_path`, Task 8 `rel-da` section), similar peers (Task 8, from `account.similar_peers`), mass-reuse summary (Task 8), pivot trail + breadcrumb (Tasks 5,7,8), why-trace (Task 4,8), focused+inline reveal (Task 8), identity-only/no-secret guarantee (Task 1–2 + the `nt_hash`/`password` assertion), `requireUnlocked`/analyst-visible (Task 2), no URL routing (overlay, Task 7).
- **Type consistency:** `PeerRef` (Go + TS) and the `relationships` JSON shape match across Task 1/2/3/8; `Crumb` is identical in Tasks 5/7/8; `explainLevel(account): string[]` consistent Task 4/8.
- **Member cap** is `100` (Task 2 handler) — matches the spec; counts stay exact. Adjust in one place if a higher cap is wanted later.
