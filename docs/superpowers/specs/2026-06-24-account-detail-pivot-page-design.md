# Account Detail Page (pivot / "expand details") — design

**Date:** 2026-06-24
**Owner:** watson0x90
**Status:** approved (brainstorm) → ready for implementation plan

## Goal

Add an **"Expand details"** action to the account slide-out that opens the account on
its own full-screen detail page with an *extreme-detail* breakdown answering two
questions for the operator:

1. **Why was this account marked the way it was?** — a plain-English derivation of
   its level (Exposure × Impact, plus any escalation override).
2. **Who does it share a hash/password with?** — the concrete related accounts, so
   the operator has real situational awareness and can **pivot** from account to
   account to follow the thread.

## Why (motivation)

Today the drawer shows `Shared with: 79` as a bare **count** — the operator can see
that reuse exists but not *with whom*, and cannot see *which* Domain-Admin account a
Shared-DA escalation came from. The exact-hash reuse group and the DA linkage are
computed server-side (from NT hashes, which are correctly never sent to the client)
but are not exposed per account. This feature surfaces those relationships as
**identities only** (never the hash or cleartext) and makes them navigable.

## Scope decisions (settled during brainstorm)

- **Relationship sections (all four):** exact hash/password reuse group; the specific
  DA account(s) shared with; near-duplicate password peers (`similar_peers`); and a
  mass-reuse cluster summary. *Key simplification:* the reuse group, the DA peers, and
  the mass-reuse cluster are all the **same set** — accounts sharing the focus
  account's NT hash — so **one** new endpoint answers three of the four; `similar_peers`
  (the fourth) is already on the account object.
- **Navigation:** a **pivot trail with a breadcrumb** (`Accounts › alice › bob`).
  Clicking a related account opens *its* detail and pushes onto the trail; Back pops;
  closing returns to the table where the operator started.
- **Reveal:** lead-only cleartext reveal is available on the page for the **focused
  account and inline next to each peer**, reusing the existing audited `/secret`
  endpoint (each click lead-gated + individually audit-logged). The relationships
  endpoint itself never returns cleartext — reveal is always a separate explicit click.
- **Form factor:** a full-screen in-app overlay ("its own page"), rendered like the
  existing drawer overlay — not a browser route.

## Out of scope (YAGNI)

- **No URL routing / deep-linkable or shareable links.** The SPA has no URL router
  today; adding one is a much larger change than this feature warrants. The detail
  page is transient in-app View state.
- No changes to how reuse grouping or scoring is *computed* — this is a read/display
  feature over data the engine already produces.

## Architecture (Approach A)

One new identity-only backend endpoint + a new full-screen detail view with a
pivot-trail context on the front end. Chosen over (B) shipping opaque reuse-group ids
and grouping client-side — the accounts list is paginated/redacted so the client lacks
full membership — and over (C) enriching the drawer in place, ruled out by the
"own page + pivot trail" requirement and the drawer's narrow modal footprint.

### Data flow

```
drawer ──"Expand details ⤢"──▶ AccountDetailProvider.open(account)
                                   │
AccountDetail page ── re-derives live Account by (username,domain) from accountsData
                   │              (scoring detail + similar_peers come from here)
                   └── GET /api/accounts/{username}/relationships?domain=…   (reuse group + DA flags)
                   └── reveal: existing audited GET /api/accounts/{username}/secret (lead only)

pivot: click a peer ──▶ pushPeer({username,domain})  (breadcrumb grows)
back  ──▶ pop trail        close ──▶ clear trail, return to underlying tab
```

## Backend

### Endpoint

`GET /api/accounts/{username}/relationships?domain=…`

- Wrapped `s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleAccountRelationships)))`.
- **No role gate** — identities (usernames/domains/risk) are not secret; they already
  appear in the redacted accounts table, so analysts get this too. Cleartext stays
  lead-only via the separate reveal endpoint.

### Handler logic (`handleAccountRelationships`)

Mirrors `handleReveal`'s resolution pattern:

1. `sess, _ := sessionFrom(r.Context())`.
2. `username := r.PathValue("username")`; `domain := r.URL.Query().Get("domain")`.
3. `id, ok := s.activeAudit(w, sess)`; return on `!ok`.
4. Resolve focus: `FindByDomain(id, username, domain)` when domain set, else
   `Find(id, username)`. Not found → `404 {"error":"account not found"}`.
5. `accts := s.Store.Accounts(id, true)` — **unredacted** (NT hash needed for grouping;
   never returned in the response).
6. `peers, total, crackedCount, daCount := model.ReuseGroupPeers(accts, focus, 100)`.
7. Emit identities-only JSON (below).

### New model helper (`internal/model/relationships.go`)

```go
type PeerRef struct {
    Username  string `json:"username"`
    Domain    string `json:"domain"`
    RiskLevel string `json:"risk_level"`
    Cracked   bool   `json:"cracked"`
    Enabled   bool   `json:"enabled"`
    HasDAPath bool   `json:"has_da_path"` // flags the DA account(s) behind a Shared-DA escalation
}

// ReuseGroupPeers returns the OTHER accounts sharing focus's NT hash. Accounts with an
// empty/blank-password NT hash (reuseKey == "") never group. Peers are sorted DA-first
// then by descending risk, and capped at limit (limit <= 0 means no cap). total /
// crackedCount / daCount are EXACT (computed before the cap) so the page can show
// "79 share this password" while only listing the top `limit`.
func ReuseGroupPeers(accts []Account, focus Account, limit int) (peers []PeerRef, total, crackedCount, daCount int)
```

Reuses the existing `reuseKey(ntHash)` (NTLM unsalted; blank/`emptyNTHash` excluded)
already used by `RecomputeSharing` and the reuse-group exports. `HasDAPath` is
`peer.HasDAPathway()`.

### Response schema (200)

```json
{
  "username": "alice",
  "domain": "CORP.LOCAL",
  "reuse_group": {
    "shares_hash": true,
    "total": 79,
    "cracked_count": 54,
    "da_count": 1,
    "truncated": false,
    "members": [
      {"username":"administrator","domain":"CORP.LOCAL","risk_level":"Critical","cracked":true,"enabled":true,"has_da_path":true},
      {"username":"bob","domain":"CORP.LOCAL","risk_level":"High","cracked":true,"enabled":true,"has_da_path":false}
    ]
  }
}
```

- `members` is capped (100), **DA-first then by risk**; `total`/`cracked_count`/`da_count`
  are exact; `truncated` is `total > len(members)`.
- No reuse / not cracked / blank hash → `{"shares_hash": false, "total": 0, "members": []}`.
- **Invariant (tested):** the response body contains no `nt_hash` and no `password` field.

### Errors

| Condition | Response |
|---|---|
| store locked | `423` (existing `requireUnlocked`) |
| account not found | `404 {"error":"account not found"}` |
| no active audit | existing `s.activeAudit` handling |
| not authenticated | `401` (existing `requireAuth`) |

## Front end

### New: `web/src/accountDetail.tsx` (pivot-trail provider)

Mirrors `accountDrawer.tsx`. Holds the trail and renders the page overlay.

- State: `trail: { username: string; domain: string }[]`.
- `open(a: Account)` → reset trail to `[{username,domain}]`.
- `pushPeer(ref: {username,domain})` → append (ignore if equal to current tail — no
  consecutive dup).
- `back()` → pop the last entry. At depth 1 (the root account) Back is hidden; the
  only way out is `close()`.
- `close()` → clear trail (returns to the underlying tab, which was never unmounted).
- Renders `<AccountDetail/>` as a full-screen overlay when `trail.length > 0`.
- `useAccountDetail()` hook, throws outside provider (same pattern as the drawer).

The reducer logic (push/back/close, no-consecutive-dup) is extracted as a pure function
for unit testing.

### New: `web/src/components/AccountDetail.tsx` (the page)

- Derives the **live** `Account` for the current trail tail by `(username, domain)` from
  `useAccountsData()` (same live-refresh trick as the drawer); falls back to a "not in
  current audit" message if absent.
- Fetches `api.relationships(username, domain)` on trail-tail change; manages
  loading / locked(423) / error / empty states.
- Layout — three bands:
  1. **Breadcrumb header** — `Accounts › alice › bob › svc-sql`, each crumb clickable
     (jump to that depth); a close (✕) control.
  2. **"Why this level"** — rendered from `explainLevel(account)` (below).
  3. **Breakdown cards** (existing Exposure/Impact cards) + **relationship sections**:
     - *Password-reuse group* — `members` as `PeerLink`s (+ inline reveal for leads),
       with the `total`/`truncated` summary.
     - *Shares a password with Domain Admin* — the `members` where `has_da_path`,
       called out as the Shared-DA justification (only when present).
     - *Near-duplicate passwords* — `account.similar_peers` as `PeerLink`s with match %.
     - *Mass-reuse cluster* — size + cracked-count summary (only when
       `escalated_by_mass_reuse`).

### New: `web/src/whyLevel.ts` (pure, unit-tested)

```ts
export function explainLevel(a: Account): string[]
```
Returns ordered plain-English lines deriving the level, covering branches:
- **Shared-DA** → "Critical — shares a password with Domain-Admin account(s); cracking
  this credential yields DA." (peers named in the relationship section)
- **Own DA path** (`has_da_path`) → "Critical — confirmed Domain-Admin attack path."
- **Controls Tier-0** (`controls_tier0`) → "Impact pinned to maximum — controls a
  Tier-0/DA-equivalent asset."
- **Mass-reuse** (`escalated_by_mass_reuse`) → "Escalated — large cracked reuse cluster;
  cracking one compromises all."
- **Default** → "Level = Exposure <tier> × Impact <tier>" + the dominant Exposure driver
  (cracked floor / HIBP / reuse floor / weakness) and Impact driver (privilege / DA /
  domain). Display-only; mirrors the Go level matrix but parity is not byte-pinned.

### Shared extraction (avoid duplication)

The drawer's field-row list, `BreakdownCard`, and `WeakCell` move to a shared module
(e.g. `web/src/components/accountFacts.tsx`) consumed by both `AccountDrawer` (quick
view) and `AccountDetail` (full view). No behavioral change to the drawer beyond the
added "Expand details ⤢" button in its header (calls `open(account)` then the drawer's
`onClose`).

### `web/src/api.ts`

Add:
```ts
export interface PeerRef { username: string; domain: string; risk_level: string; cracked: boolean; enabled: boolean; has_da_path: boolean }
export interface Relationships {
  username: string; domain: string
  reuse_group: { shares_hash: boolean; total: number; cracked_count: number; da_count: number; truncated: boolean; members: PeerRef[] }
}
// in the api object:
relationships: (username: string, domain?: string) => request<Relationships>(`/accounts/${encodeURIComponent(username)}/relationships${domain ? `?domain=${encodeURIComponent(domain)}` : ""}`)
```

### Wiring

`AccountDetailProvider` wraps the app alongside `AccountDrawerProvider` (in
`App.tsx`/shell). The provider order must let the drawer's "Expand details" button reach
`useAccountDetail()`.

## Security

- Relationships endpoint returns **identities only**; no `nt_hash`, no `password`
  (asserted by test). `requireUnlocked` (NT hashes live in the encrypted store).
- Visible to analysts (usernames are already in the redacted table); **cleartext reveal
  stays lead-only and audit-logged per click** via the unchanged `/secret` endpoint.
- Each inline reveal is an independent audited action — the page does not bulk-reveal.

## Testing

### Go
- `handleAccountRelationships`: reuse group returns DA-flagged identities; **assert no
  `nt_hash`/`password` in the JSON**; not-cracked/blank-hash → empty; locked → 423;
  not-found → 404; no active audit handled; analyst role → 200; truncation + DA-first
  sort with a >100 cluster.
- `ReuseGroupPeers`: grouping on `reuseKey`, blank/`emptyNTHash` excluded, DA-first
  then risk sort, exact totals vs capped members.

### TypeScript (vitest, node-env pure-logic — no component render)
- `explainLevel` — one assertion per branch.
- trail reducer — push / back / close / no-consecutive-dup / crumb-jump.

### Playwright (`:8444` disposable seed; never `:8443`)
- Drawer → "Expand details" → page shows Why + reuse group → pivot to a peer
  (breadcrumb grows) → Back pops → lead reveal works → **browser console clean** (no
  4xx/errors).

## Gates (per CLAUDE.md)

`gofmt -l cmd internal` empty · `go build/vet/test ./...` · `govulncheck` clean ·
(web) `npx tsc --noEmit` · `npx vitest run` · `npm run build` — never `npm install`.

## File summary

| Action | Path | Responsibility |
|---|---|---|
| Create | `internal/model/relationships.go` | `PeerRef`, `ReuseGroupPeers` |
| Create | `internal/model/relationships_test.go` | helper unit tests |
| Modify | `internal/httpapi/server.go` | route + `handleAccountRelationships` |
| Create | `internal/httpapi/relationships_test.go` | handler tests |
| Create | `web/src/accountDetail.tsx` | pivot-trail provider + overlay mount |
| Create | `web/src/components/AccountDetail.tsx` | the detail page |
| Create | `web/src/whyLevel.ts` | `explainLevel` (pure) |
| Create | `web/src/components/accountFacts.tsx` | shared field rows / BreakdownCard / WeakCell |
| Modify | `web/src/components/AccountDrawer.tsx` | "Expand details ⤢" button; consume shared facts |
| Modify | `web/src/accountDrawer.tsx` / `App.tsx` shell | mount `AccountDetailProvider` |
| Modify | `web/src/api.ts` | `relationships()` + types |
| Create | `web/src/whyLevel.test.ts`, trail-reducer test | vitest pure-logic |
