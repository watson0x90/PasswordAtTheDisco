# App-Wide Clickable Usernames Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** Make every audited-account username across the app a clickable link that opens the shared account-detail drawer, including the Compare page (which needs a per-audit accounts endpoint).

**Architecture:** A backend `GET /api/audits/{id}/accounts` read endpoint; a shared `AccountDrawerProvider` (one drawer mount) + `<AccountLink>` component that resolves the full `Account` and opens the drawer; convert all username sites; migrate the two existing local-drawer spots; wire Compare with both audits' accounts.

**Tech Stack:** Go stdlib `net/http`; React 18 + TS + Vite. No new deps.

**Branch:** `feature/clickable-usernames` (off `main`, post-`v2.12.1`).

**Spec:** `docs/superpowers/specs/2026-06-19-clickable-usernames-design.md`

**Gates:** `gofmt -l cmd internal`, `go build/vet/test ./...`; in `web/` `npx tsc --noEmit`, `npx vitest run`, `npm run build` (never `npm install`; styleguard bans literal inline spacing).

---

## Task 1: Backend — `GET /api/audits/{id}/accounts`

**Files:** `internal/httpapi/server.go` (route near `/api/accounts` at :146; handler near `handleAccounts` :1247); `internal/httpapi/server_test.go`.

- [ ] **Step 1 — Failing test** in `server_test.go` (use the existing harness: `newServer`, `loginCSRF`, `do`, `seed`, `openAudit`). `seed` creates an audit with a test account "alice" (it's used by `TestExportEndpoints`). Add:
```go
func TestAuditAccountsEndpoint(t *testing.T) {
	srv := newServer("secret")
	id := seed(t, srv) // creates an audit with accounts incl. a cracked "Welcome1"
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	openAudit(t, srv, lc, lcsrf, id) // unlocks the store for this session
	// fetch THIS audit's accounts by id (not the active-audit path)
	rr := do(srv, "GET", "/api/audits/"+id+"/accounts", lc)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "alice") {
		t.Fatalf("expected account 'alice' in body: %s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "Welcome1") {
		t.Fatalf("LEAKED cleartext in audit-accounts body")
	}
	// unknown id -> 200 with empty array
	rr2 := do(srv, "GET", "/api/audits/nope/accounts", lc)
	if rr2.Code != http.StatusOK || strings.TrimSpace(rr2.Body.String()) != "[]" {
		t.Fatalf("unknown id = %d %q, want 200 []", rr2.Code, rr2.Body.String())
	}
}
```
Confirm `seed`'s account username is "alice" and it sets a cracked password "Welcome1" (read `seed` / `TestExportEndpoints` which asserts `!contains "Welcome1"`); adjust the asserted strings to the real fixture if different.

- [ ] **Step 2 — Run, expect FAIL** (404, route not registered): `go test ./internal/httpapi/ -run TestAuditAccountsEndpoint -v`.

- [ ] **Step 3 — Handler** in `server.go`, next to `handleAccounts` (after :1260):
```go
// handleAuditAccounts returns the redacted accounts for a SPECIFIC audit by id
// (not necessarily the session's active audit) — used by Compare to open the
// account drawer for either compared audit. Same redaction + gating as
// /api/accounts; unknown/empty id yields 200 [].
func (s *Server) handleAuditAccounts(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	accts, err := s.Store.Accounts(id, false)
	if err != nil {
		writeJSON(w, http.StatusOK, []model.Account{})
		return
	}
	writeJSON(w, http.StatusOK, accts)
}
```

- [ ] **Step 4 — Route** next to the `/api/accounts` route (after :146):
```go
	mux.Handle("GET /api/audits/{id}/accounts", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleAuditAccounts))))
```
Confirm a conflicting `/api/audits/{id}/...` route doesn't already shadow this (the existing `/api/audits/{id}/open`, `/diff/{b}` use distinct suffixes, so `{id}/accounts` is unique).

- [ ] **Step 5 — Verify + commit.** `go test ./internal/httpapi/ -run TestAuditAccountsEndpoint -v` (PASS); `go build ./... && go vet ./...`; `gofmt -l cmd internal` empty. Commit:
```
gofmt -w internal/httpapi/server.go internal/httpapi/server_test.go
git add internal/httpapi/server.go internal/httpapi/server_test.go
git commit -m "feat(api): GET /api/audits/{id}/accounts — redacted per-audit accounts (for Compare)"
```

---

## Task 2: Shared drawer provider + AccountLink + api client

**Files:** Create `web/src/accountDrawer.tsx`, `web/src/components/AccountLink.tsx`; Modify `web/src/App.tsx` (mount provider), `web/src/api.ts` (add `auditAccounts`).

- [ ] **Step 1 — Provider** `web/src/accountDrawer.tsx`:
```tsx
import { createContext, useContext, useState, type ReactNode } from "react"
import type { Account } from "./api"
import { AccountDrawer } from "./components/AccountDrawer"

interface DrawerState { openAccount: (a: Account) => void }
const Ctx = createContext<DrawerState | null>(null)

export function AccountDrawerProvider({ children }: { children: ReactNode }) {
  const [selected, setSelected] = useState<Account | null>(null)
  return (
    <Ctx.Provider value={{ openAccount: setSelected }}>
      {children}
      {selected && <AccountDrawer account={selected} onClose={() => setSelected(null)} />}
    </Ctx.Provider>
  )
}

export function useAccountDrawer(): DrawerState {
  const c = useContext(Ctx)
  if (!c) throw new Error("useAccountDrawer must be used within AccountDrawerProvider")
  return c
}
```

- [ ] **Step 2 — AccountLink** `web/src/components/AccountLink.tsx`:
```tsx
import type { Account } from "../api"
import { useAccountsData } from "../accountsData"
import { useAccountDrawer } from "../accountDrawer"

// AccountLink renders a username as a button that opens the shared account drawer.
// It resolves the full Account from `accounts` (when provided, e.g. Compare's
// combined two-audit list) or the active-audit list. Falls back to plain text
// when the account isn't available.
export function AccountLink({ username, domain, accounts }: { username: string; domain: string; accounts?: Account[] }) {
  const { accounts: active } = useAccountsData()
  const { openAccount } = useAccountDrawer()
  const list = accounts ?? active ?? []
  const full = list.find((a) => a.username === username && a.domain === domain)
  if (!full) return <span>{username}</span>
  return (
    <button className="link-btn" onClick={() => openAccount(full)}>
      {username}
    </button>
  )
}
```

- [ ] **Step 3 — Mount the provider** in `web/src/App.tsx`. Read it (~lines 80-88, the `<AccountsProvider>…children…</AccountsProvider>` block). Wrap the children **inside** `AccountsProvider` (so `AccountLink` can read both contexts) with `<AccountDrawerProvider>`:
```tsx
import { AccountDrawerProvider } from "./accountDrawer"
// …
<AccountsProvider>
  <AccountDrawerProvider>
    {/* existing authed tree */}
  </AccountDrawerProvider>
</AccountsProvider>
```
(Match the actual JSX in App.tsx — wrap whatever is currently inside `AccountsProvider`.)

- [ ] **Step 4 — api client** in `web/src/api.ts`, next to `accounts` / `diff`:
```ts
  auditAccounts: (id: string) => request<Account[]>(`/audits/${encodeURIComponent(id)}/accounts`),
```

- [ ] **Step 5 — Verify + commit.** `(cd web && npx tsc --noEmit && npm run build)` — clean (provider/link unused so far is fine; tsc won't error on an unused export). Commit:
```
git add web/src/accountDrawer.tsx web/src/components/AccountLink.tsx web/src/App.tsx web/src/api.ts
git commit -m "feat(web): AccountDrawerProvider + AccountLink + api.auditAccounts"
```

---

## Task 3: Migrate the two existing spots to the shared provider

**Files:** `web/src/components/AccountsTable.tsx`, `web/src/components/Exposure.tsx`.

- [ ] **Step 1 — AccountsTable.** It has `const [selected, setSelected] = useState<Account | null>(null)` (:34), a username `<button onClick={() => setSelected(a)}>{a.username}</button>` (~:123-127), and `{selected && <AccountDrawer account={selected} onClose={() => setSelected(null)} />}` (~:186). Replace the username button with `<AccountLink username={a.username} domain={a.domain} />`; delete the `selected`/`setSelected` state and the `{selected && <AccountDrawer .../>}` mount; remove the now-unused `AccountDrawer` import (keep `WeakCell` if still used by the table body). Add `import { AccountLink } from "./AccountLink"`.

- [ ] **Step 2 — Exposure.** From the prior feature it has `const [selectedAccount, setSelectedAccount] = useState<Account|null>(null)`, an `openAccount(username, domain)` handler, the bridge-member table's `<button onClick={() => openAccount(m.username, m.domain)}>{m.username}</button>`, and `{selectedAccount && <AccountDrawer account={selectedAccount} onClose=… />}`. Replace the member username button with `<AccountLink username={m.username} domain={m.domain} />`; delete `selectedAccount`/`setSelectedAccount`, the `openAccount` handler, and the `{selectedAccount && <AccountDrawer .../>}` mount; remove the now-unused `AccountDrawer` import. Add `import { AccountLink } from "./AccountLink"`. (The HIBP triage table is converted in Task 4.)

- [ ] **Step 3 — Verify + commit.** `(cd web && npx tsc --noEmit && npx vitest run && npm run build)` — green incl. styleguard; confirm no unused symbols (`selected`, `openAccount`, `AccountDrawer` removed where appropriate). Manually confirm in code that AccountsTable still has the full `Account` per row (so the lookup resolves). Commit:
```
git add web/src/components/AccountsTable.tsx web/src/components/Exposure.tsx
git commit -m "refactor(web): Accounts table + Exposure bridge members use shared AccountLink"
```

---

## Task 4: Convert the remaining username sites

**Files:** `web/src/components/Actionable.tsx`, `web/src/components/Exposure.tsx` (triage), `web/src/components/Insights.tsx`, `web/src/components/Domains.tsx`.

For EACH site below: add `import { AccountLink } from "./AccountLink"` (once per file) and replace the username text node with `<AccountLink username={X.username} domain={X.domain} />`. Read the surrounding JSX first to get the exact variable name (`a`, `m`, `item.account`, etc.) and to preserve adjacent markup (badges, `@domain` suffix, `disabled` badge).

- [ ] **Step 1 — Actionable.tsx.** Three sites:
  - Priority Worklist row (~:328) currently `{a.username}@{a.domain}` (or `{item.account.username}…`): replace the username with `<AccountLink username={…} domain={…} />`; keep the existing domain display.
  - Category-table rows (~:431, `ReportAccount` `a`): `{a.username}` → `<AccountLink username={a.username} domain={a.domain} />`.
  - Reuse-group member rows (~:516, `m`): `<td>{m.username}</td>` → `<td><AccountLink username={m.username} domain={m.domain} /></td>`.

- [ ] **Step 2 — Exposure.tsx triage.** The `TriageTable` rows (~:312): `<td>{a.username}</td>` → `<td><AccountLink username={a.username} domain={a.domain} /></td>`.

- [ ] **Step 3 — Insights.tsx.** Top-10 Riskiest (~:154): `<td>{a.username}{!a.enabled && <span className="badge-disabled">disabled</span>}</td>` → keep the disabled badge: `<td><AccountLink username={a.username} domain={a.domain} />{!a.enabled && <span className="badge-disabled">disabled</span>}</td>`.

- [ ] **Step 4 — Domains.tsx.** Find the per-domain detail tables that render raw usernames (Kerberoastable / AS-REP / escalated / never-expires / stale tables — grep `\.username` in Domains.tsx; the "Accounts" tab uses `AccountsTable`, already covered). For each raw username cell, swap to `<AccountLink username={…} domain={…} />`. If Domains renders no raw username outside AccountsTable, note that and skip.

- [ ] **Step 5 — Verify + commit.** `(cd web && npx tsc --noEmit && npx vitest run && npm run build)` — green. Commit:
```
git add web/src/components/Actionable.tsx web/src/components/Exposure.tsx web/src/components/Insights.tsx web/src/components/Domains.tsx
git commit -m "feat(web): clickable usernames in Actionable / Exposure triage / Insights / Domains"
```

---

## Task 5: Compare — fully clickable across both audits

**Files:** `web/src/components/Compare.tsx`.

- [ ] **Step 1 — Fetch both audits' accounts.** In `Compare.tsx`, alongside the existing `api.diff(a, b)` effect, add state `const [acctIndex, setAcctIndex] = useState<Account[]>([])` (import `Account` type + `AccountLink`). When `a` and `b` are set, fetch both and combine (dedupe by `username+domain`, preferring the "current" audit `b` so the drawer shows the latest):
```tsx
useEffect(() => {
  if (!a || !b || a === b) { setAcctIndex([]); return }
  let live = true
  Promise.all([api.auditAccounts(b), api.auditAccounts(a)])
    .then(([cur, base]) => {
      if (!live) return
      const seen = new Set<string>()
      const merged: Account[] = []
      for (const acc of [...cur, ...base]) { // cur first → wins on dupes
        const k = acc.username + " " + acc.domain
        if (!seen.has(k)) { seen.add(k); merged.push(acc) }
      }
      setAcctIndex(merged)
    })
    .catch(() => { if (live) setAcctIndex([]) })
  return () => { live = false }
}, [a, b])
```

- [ ] **Step 2 — Clickable cohort rows.** The cohort row (~:126) `<span>{x.username}</span>` → `<AccountLink username={x.username} domain={x.domain} accounts={acctIndex} />`. (`DiffAccount` has `username` + `domain`; confirm `x.domain` exists — read the `DiffAccount` type in api.ts; if the diff item lacks `domain`, the lookup needs the domain — in that case match on username only by adapting `AccountLink` is NOT wanted, so instead confirm `DiffAccount.domain` exists; the spec assumes it does.)

- [ ] **Step 3 — Verify + commit.** `(cd web && npx tsc --noEmit && npm run build)` — green. Commit:
```
git add web/src/components/Compare.tsx
git commit -m "feat(web): clickable usernames on Compare (both audits' accounts)"
```

---

## Task 6: Gate, rebuild, live verify, finish

- [ ] **Step 1 — Full gate.** `gofmt -l cmd internal`; `go build/vet/test ./...`; `(cd web && npx tsc --noEmit && npx vitest run && npm run build)`; `govulncheck ./...`.
- [ ] **Step 2 — Rebuild** (stop `:8443` first): `bash .claude/skills/build-and-run/scripts/build.sh`; restart `:8443`; unlock (passphrase `disco-vault-2026`).
- [ ] **Step 3 — Playwright verify** on `:8443` (BHE Large Sample): clicking a username on **Actionable** (worklist + a category table), **Exposure** HIBP triage, **Insights** top-risk, **Domains** detail, and **Compare** (pick two audits) each opens the account drawer with that account's detail. Accounts page + Exposure bridge members still work (now via the shared provider). No console errors.
- [ ] **Step 4 — finishing-a-development-branch:** merge `feature/clickable-usernames` → `main`, tag `v2.13.0`, rebuild + restart `:8443`.

---

## Self-review
- **Spec coverage:** per-audit endpoint → Task 1; provider+AccountLink+api → Task 2; migrate two → Task 3; convert sites → Task 4; Compare full → Task 5. All mapped.
- **Type consistency:** `AccountDrawerProvider`/`useAccountDrawer`/`openAccount(Account)` (Task 2) used by `AccountLink` (Task 2) used everywhere (Tasks 3-5); `api.auditAccounts(id): Account[]` (Task 2) used in Compare (Task 5); `handleAuditAccounts` (Task 1) returns redacted `[]model.Account`.
- **Confirm-by-reading:** `seed`'s fixture username/password (Task 1 test); App.tsx's exact `AccountsProvider` children (Task 2 Step 3); each site's variable name + adjacent markup (Task 4); `DiffAccount.domain` exists (Task 5 Step 2); AccountsTable still imports `WeakCell` if its table body uses it (Task 3 Step 1).
