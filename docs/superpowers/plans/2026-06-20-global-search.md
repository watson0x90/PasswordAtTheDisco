# Global Search + Password-in-Use Probe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `⌘/Ctrl-K` command palette + a Search tab for finding accounts/views from anywhere, plus a server-side password-in-use probe that answers "which accounts use this exact password?" via NT-hash matching.

**Architecture:** One new backend endpoint (`POST /api/probe`) hashes the candidate to NTLM and matches stored hashes, returning redacted accounts. The two frontend surfaces (command palette + Search tab) reuse the already-loaded redacted accounts (`useAccountsData`), the shared `AccountDrawer`, and the new sortable `AccountsTable`. A shared, unit-tested `filterAccounts` backs both surfaces' account search.

**Tech Stack:** Go 1.26 stdlib + `golang.org/x/crypto/md4` (already used via `hibp.NTLMHash`). React 18 + TS + Vite. Gates: `gofmt -l cmd internal`, `go build/vet/test ./...`, `govulncheck ./...`; in `web/` (NEVER `npm install`): `npx tsc --noEmit`, `npx vitest run` (incl. `styleguard.test.ts`), `npm run build`.

**Spec:** `docs/superpowers/specs/2026-06-20-global-search-design.md`

**Conventions that bite:**
- `styleguard.test.ts` FAILS on literal inline spacing styles in `.tsx`. CSS classes only.
- vitest is node-env: only test pure functions.
- Hooks called unconditionally, above any early return.
- The probe's candidate password is NEVER logged, stored, or echoed — only the match count is audit-logged.

---

## File Structure

- **Modify** `internal/httpapi/server.go` — add `ProbeResult` type, `handleProbe`, and the `POST /api/probe` route.
- **Modify** `internal/httpapi/server_test.go` — add `TestProbeEndpoint`.
- **Create** `web/src/search.ts` + `web/src/search.test.ts` — `filterAccounts` + unit tests.
- **Modify** `web/src/api.ts` — `ProbeResult` interface + `probe()`.
- **Create** `web/src/components/CommandPalette.tsx` — the ⌘K overlay.
- **Create** `web/src/components/Search.tsx` — the Search tab page.
- **Modify** `web/src/components/AppShell.tsx` — add `"search"` to `View` + `TABS`.
- **Modify** `web/src/App.tsx` — mount `<CommandPalette />`, add the `"search"` route.
- **Modify** `web/src/components/Activity.tsx` — add `password_probe` to the filterable `ACTIONS` list.
- **Modify** `web/src/styles.css` — `.cmdk-*` + `.search-*` classes.

---

## Task 1: Backend — `POST /api/probe`

**Files:**
- Modify: `internal/httpapi/server.go`
- Test: `internal/httpapi/server_test.go`

**Context:** `model.Account` has `NTHash string` (json `nt_hash`). `hibp.NTLMHash(password) string` returns the uppercase-hex NT hash. `s.Store.Accounts(id, includeSecrets bool)` returns full accounts when `includeSecrets=true`, else `acc.Redacted()` (zeroes Password+NTHash). `activeAuditRead(sess)` returns the session's active audit id. Audit logging: `s.Audit.Log(audit.Event{Actor:…, Role:…, Action:…, Target:…, Source:r.RemoteAddr, Result:"ok"})`. `writeJSON(w, code, v)` writes JSON. The existing `/api/pwned/probe` is a DIFFERENT (HIBP corpus) probe — do not touch it; this is `/api/probe` with action `password_probe`.

- [ ] **Step 1: Write the failing test**

Add to `internal/httpapi/server_test.go`:

```go
func TestProbeEndpoint(t *testing.T) {
	var auditBuf bytes.Buffer
	srv := newServerAudit("secret", &auditBuf)

	// Ingest an account whose NT hash is exactly NTLMHash("Welcome1") so the
	// probe can match it. (The default seed account sets no nt_hash.)
	want := hibp.NTLMHash("Welcome1")
	payload := `{"accounts":[{"username":"alice","domain":"CORP","password":"Welcome1",` +
		`"cracked":true,"risk_level":"Critical","nt_hash":"` + want + `"}]}`
	ireq := httptest.NewRequest("POST", "/api/ingest", strings.NewReader(payload))
	ireq.Header.Set("Authorization", "Bearer secret")
	irec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(irec, ireq)
	if irec.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", irec.Code, irec.Body.String())
	}
	var ing struct{ AuditID string `json:"audit_id"` }
	_ = json.Unmarshal(irec.Body.Bytes(), &ing)

	cookie, csrf := loginCSRF(t, srv, "lead", "leadpw")
	openAudit(t, srv, cookie, csrf, ing.AuditID)

	probe := func(pw string) *httptest.ResponseRecorder {
		body := `{"password":` + strconv.Quote(pw) + `}`
		req := httptest.NewRequest("POST", "/api/probe", strings.NewReader(body))
		req.AddCookie(cookie)
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		return rec
	}

	// match
	rec := probe("Welcome1")
	if rec.Code != http.StatusOK {
		t.Fatalf("probe match: %d %s", rec.Code, rec.Body.String())
	}
	bodyStr := rec.Body.String()
	if !strings.Contains(bodyStr, `"count":1`) || !strings.Contains(bodyStr, "alice") {
		t.Errorf("expected one match for alice, got %s", bodyStr)
	}
	if strings.Contains(bodyStr, "Welcome1") || strings.Contains(strings.ToLower(bodyStr), "nt_hash") {
		t.Errorf("probe response leaked a secret: %s", bodyStr)
	}

	// no match
	rec = probe("nope-not-it")
	if !strings.Contains(rec.Body.String(), `"count":0`) {
		t.Errorf("expected count 0, got %s", rec.Body.String())
	}

	// empty candidate rejected
	if rec := probe(""); rec.Code != http.StatusBadRequest {
		t.Errorf("empty probe: want 400, got %d", rec.Code)
	}

	// audit log recorded the action but NOT the candidate
	al := auditBuf.String()
	if !strings.Contains(al, "password_probe") {
		t.Errorf("audit log missing password_probe: %s", al)
	}
	if strings.Contains(al, "Welcome1") {
		t.Errorf("audit log leaked the candidate password: %s", al)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/httpapi/ -run TestProbeEndpoint -v`
Expected: FAIL (404 / route not found, or compile error for missing imports). If `strconv`/`bytes`/`hibp` aren't imported in the test file, add them to its import block.

- [ ] **Step 3: Implement the handler + route**

In `internal/httpapi/server.go`, add the type + handler (place near the other account handlers, e.g. after `handleAuditAccounts`):

```go
// ProbeResult is the response for POST /api/probe: the redacted accounts in the
// active audit whose password matches the supplied candidate, plus the count.
type ProbeResult struct {
	Count   int             `json:"count"`
	Matches []model.Account `json:"matches"`
}

// handleProbe answers "which accounts in the active audit use this exact
// password?" by hashing the operator's candidate to NTLM and matching it against
// the stored NT hashes. The candidate is never stored, logged, or echoed; the
// response carries only redacted accounts. Any authenticated operator may probe;
// every call is audit-logged (password_probe) with the match COUNT only.
func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password required"})
		return
	}
	candidate := hibp.NTLMHash(body.Password)
	full, err := s.Store.Accounts(activeAuditRead(sess), true) // includeSecrets=true to read NTHash
	if err != nil {
		writeJSON(w, http.StatusOK, ProbeResult{Count: 0, Matches: []model.Account{}})
		return
	}
	matches := []model.Account{}
	for _, a := range full {
		if strings.EqualFold(a.NTHash, candidate) {
			matches = append(matches, a.Redacted())
		}
	}
	s.Audit.Log(audit.Event{
		Actor: sess.Username, Role: string(sess.Role),
		Action: "password_probe", Target: fmt.Sprintf("matches=%d", len(matches)),
		Source: r.RemoteAddr, Result: "ok",
	})
	writeJSON(w, http.StatusOK, ProbeResult{Count: len(matches), Matches: matches})
}
```

Add the route next to `/api/accounts` (around the existing accounts routes, ~line 146):

```go
mux.Handle("POST /api/probe", s.requireAuth(s.requireCSRF(s.requireUnlocked(http.HandlerFunc(s.handleProbe)))))
```

Ensure `fmt`, `strings`, `encoding/json`, and the `hibp`, `audit`, `model` packages are imported in `server.go` (most already are — add any missing).

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/httpapi/ -run TestProbeEndpoint -v`
Expected: PASS.

- [ ] **Step 5: Full Go gate**

Run: `gofmt -l cmd internal` (empty) && `go build ./... && go vet ./... && go test ./...` (all ok) && `govulncheck ./...` (no vulns).

- [ ] **Step 6: Commit**

```bash
git add internal/httpapi/server.go internal/httpapi/server_test.go
git commit -m "feat(api): POST /api/probe — password-in-use NTLM match (redacted, audit-logged, never logs candidate)"
```

---

## Task 2: API client `probe()` + shared `filterAccounts`

**Files:**
- Create: `web/src/search.ts`
- Create: `web/src/search.test.ts`
- Modify: `web/src/api.ts`

- [ ] **Step 1: Write the failing test**

Create `web/src/search.test.ts`:

```ts
import { describe, it, expect } from "vitest"
import { filterAccounts } from "./search"
import type { Account } from "./api"

const acct = (username: string, domain: string): Account =>
  ({ username, domain } as Account)

const data: Account[] = [
  acct("administrator", "PHANTOM.CORP"),
  acct("alice", "GHOST.CORP"),
  acct("bob", "PHANTOM.CORP"),
]

describe("filterAccounts", () => {
  it("returns [] for an empty query", () => {
    expect(filterAccounts(data, "")).toEqual([])
    expect(filterAccounts(data, "   ")).toEqual([])
  })
  it("matches username case-insensitively", () => {
    expect(filterAccounts(data, "ADMIN").map((a) => a.username)).toEqual(["administrator"])
  })
  it("matches domain", () => {
    expect(filterAccounts(data, "phantom").map((a) => a.username)).toEqual(["administrator", "bob"])
  })
  it("respects the cap", () => {
    expect(filterAccounts(data, "corp", 1)).toHaveLength(1)
  })
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd web && npx vitest run src/search.test.ts`
Expected: FAIL — cannot find module `./search`.

- [ ] **Step 3: Implement `filterAccounts`**

Create `web/src/search.ts`:

```ts
import type { Account } from "./api"

// filterAccounts returns accounts whose username or domain contains the query
// (case-insensitive substring), capped at `limit`. Empty query yields []. Shared
// by the command palette and the Search tab so both behave identically.
export function filterAccounts(accounts: Account[], query: string, limit = 25): Account[] {
  const q = query.trim().toLowerCase()
  if (!q) return []
  const out: Account[] = []
  for (const a of accounts) {
    if (`${a.username} ${a.domain}`.toLowerCase().includes(q)) {
      out.push(a)
      if (out.length >= limit) break
    }
  }
  return out
}
```

- [ ] **Step 4: Add the API client method**

In `web/src/api.ts`, add the interface (near the other result interfaces) and the method (inside the `api` object, next to `revealSecret`):

```ts
export interface ProbeResult {
  count: number
  matches: Account[]
}
```

```ts
  probe: (password: string, csrf: string) =>
    request<ProbeResult>("/probe", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ password }),
    }),
```

- [ ] **Step 5: Run the test + typecheck**

Run: `cd web && npx vitest run src/search.test.ts && npx tsc --noEmit`
Expected: tests PASS; tsc clean.

- [ ] **Step 6: Commit**

```bash
git add web/src/search.ts web/src/search.test.ts web/src/api.ts
git commit -m "feat(web): filterAccounts helper + api.probe client"
```

---

## Task 3: Command palette (⌘/Ctrl-K)

**Files:**
- Create: `web/src/components/CommandPalette.tsx`
- Modify: `web/src/components/AppShell.tsx` (export the nav lists for reuse)
- Modify: `web/src/App.tsx` (mount the palette)
- Modify: `web/src/styles.css`

**Context:** `useAccountsData()` → `{ accounts: Account[] | null }`. `useAccountDrawer()` → `{ openAccount: (a: Account) => void }`. `useNav()` (from `../nav`) returns `(v: View) => void`. `useAuth()` → `{ me }` with `me.role`. The nav lists `TABS`, `SETUP_ITEMS`, `ADMIN_ITEMS` live in `AppShell.tsx` (currently not exported).

- [ ] **Step 1: Export the nav lists from AppShell**

In `web/src/components/AppShell.tsx`, add `export` to the three list declarations so the palette can reuse them (do NOT duplicate the labels):

```ts
export const TABS: { id: View; label: string }[] = [ /* unchanged contents */ ]
export const SETUP_ITEMS: { id: View; label: string }[] = [ /* unchanged */ ]
export const ADMIN_ITEMS: { id: View; label: string }[] = [ /* unchanged */ ]
```

(Only add the `export` keyword; leave the array contents as they are. `View` is already exported.)

- [ ] **Step 2: Create the palette component**

Create `web/src/components/CommandPalette.tsx`:

```tsx
import { useEffect, useMemo, useRef, useState } from "react"
import type { Account } from "../api"
import { useAccountsData } from "../accountsData"
import { useAccountDrawer } from "../accountDrawer"
import { useNav } from "../nav"
import { useAuth } from "../auth"
import { filterAccounts } from "../search"
import { RISK_CLASS } from "../util"
import { ADMIN_ITEMS, SETUP_ITEMS, TABS, type View } from "./AppShell"

type Row =
  | { kind: "account"; account: Account }
  | { kind: "view"; id: View; label: string }

export function CommandPalette() {
  const { accounts } = useAccountsData()
  const { openAccount } = useAccountDrawer()
  const nav = useNav()
  const { me } = useAuth()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState("")
  const [active, setActive] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  // Global ⌘/Ctrl-K toggles the palette; Esc closes.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) {
        e.preventDefault()
        setOpen((v) => !v)
      } else if (e.key === "Escape") {
        setOpen(false)
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [])

  // Reset + focus when opened.
  useEffect(() => {
    if (open) {
      setQuery("")
      setActive(0)
      // focus after the overlay paints
      const id = window.setTimeout(() => inputRef.current?.focus(), 0)
      return () => window.clearTimeout(id)
    }
  }, [open])

  const navItems = useMemo(() => {
    const lead = me?.role === "lead"
    return [...TABS, ...(lead ? [...SETUP_ITEMS, ...ADMIN_ITEMS] : [])]
  }, [me])

  const rows: Row[] = useMemo(() => {
    const q = query.trim().toLowerCase()
    const acctRows: Row[] = filterAccounts(accounts ?? [], query, 8).map((account) => ({ kind: "account", account }))
    const viewRows: Row[] = q
      ? navItems.filter((t) => t.label.toLowerCase().includes(q)).map((t) => ({ kind: "view", id: t.id, label: t.label }))
      : []
    return [...acctRows, ...viewRows]
  }, [accounts, query, navItems])

  // keep the active index in range as rows change
  useEffect(() => { setActive(0) }, [query])

  function activate(row: Row) {
    setOpen(false)
    if (row.kind === "account") openAccount(row.account)
    else nav(row.id)
  }

  if (!open) return null

  return (
    <div className="cmdk-overlay" onClick={() => setOpen(false)}>
      <div className="cmdk-panel" onClick={(e) => e.stopPropagation()}>
        <input
          ref={inputRef}
          className="cmdk-input"
          placeholder="Search accounts, or jump to a view…"
          value={query}
          spellCheck={false}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") { e.preventDefault(); setActive((i) => Math.min(i + 1, rows.length - 1)) }
            else if (e.key === "ArrowUp") { e.preventDefault(); setActive((i) => Math.max(i - 1, 0)) }
            else if (e.key === "Enter" && rows[active]) { e.preventDefault(); activate(rows[active]) }
          }}
        />
        <div className="cmdk-list">
          {rows.length === 0 ? (
            <div className="cmdk-empty">{query ? "No matches" : "Type to search accounts, or a view name"}</div>
          ) : (
            rows.map((row, i) => (
              <button
                key={row.kind === "account" ? `a/${row.account.domain}/${row.account.username}` : `v/${row.id}`}
                className={i === active ? "cmdk-row active" : "cmdk-row"}
                onMouseEnter={() => setActive(i)}
                onClick={() => activate(row)}
              >
                {row.kind === "account" ? (
                  <>
                    <span className="cmdk-row-main">{row.account.username}</span>
                    <span className="cmdk-row-meta">{row.account.domain}</span>
                    <span className={`badge ${RISK_CLASS[row.account.risk_level] || ""}`}>{row.account.risk_level}</span>
                  </>
                ) : (
                  <>
                    <span className="cmdk-row-main">{row.label}</span>
                    <span className="cmdk-row-meta">view</span>
                  </>
                )}
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
```

- [ ] **Step 3: Mount the palette in App.tsx**

In `web/src/App.tsx`, import it and mount it once inside `<JobsProvider>` as a sibling before `<AppShell>` (it then has nav + accounts + drawer contexts):

```tsx
import { CommandPalette } from "./components/CommandPalette"
```
```tsx
<JobsProvider>
  <CommandPalette />
  <AppShell view={view} onNav={setView}>
    <Suspense fallback={<div className="center-state"><div className="spinner">loading</div></div>}>
      {viewFor(view)}
    </Suspense>
  </AppShell>
</JobsProvider>
```

- [ ] **Step 4: Add CSS**

Append to `web/src/styles.css`:

```css
/* Command palette */
.cmdk-overlay {
  position: fixed;
  inset: 0;
  z-index: 200;
  background: rgba(6, 10, 20, 0.6);
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding-top: 14vh;
}
.cmdk-panel {
  width: 560px;
  max-width: 92vw;
  background: var(--glass-strong);
  border: 1px solid var(--glass-border);
  border-radius: 14px;
  box-shadow: 0 30px 80px -30px rgba(0, 0, 0, 0.85);
  overflow: hidden;
}
.cmdk-input {
  width: 100%;
  border: none;
  border-bottom: 1px solid var(--hairline);
  background: transparent;
  color: var(--text);
  font-family: var(--sans);
  font-size: 15px;
  padding: 16px 18px;
  outline: none;
}
.cmdk-list { max-height: 52vh; overflow-y: auto; padding: 6px; }
.cmdk-empty { padding: 18px; color: var(--faint); font-size: 13px; text-align: center; }
.cmdk-row {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  text-align: left;
  background: none;
  border: none;
  border-radius: 9px;
  padding: 9px 12px;
  cursor: pointer;
  color: var(--text);
  font-family: var(--sans);
  font-size: 13px;
}
.cmdk-row.active { background: rgba(99, 102, 241, 0.18); }
.cmdk-row-main { font-weight: 500; }
.cmdk-row-meta { color: var(--faint); font-size: 12px; margin-left: auto; }
.cmdk-row .badge { margin-left: 8px; }
```

- [ ] **Step 5: Typecheck, test, build**

Run: `cd web && npx tsc --noEmit && npx vitest run && npm run build`
Expected: all green (incl. styleguard — no inline styles added).

- [ ] **Step 6: Commit**

```bash
git add web/src/components/CommandPalette.tsx web/src/components/AppShell.tsx web/src/App.tsx web/src/styles.css
git commit -m "feat(web): ⌘/Ctrl-K command palette (account + view search)"
```

---

## Task 4: Search tab + wiring

**Files:**
- Create: `web/src/components/Search.tsx`
- Modify: `web/src/components/AppShell.tsx` (`View` union + `TABS`)
- Modify: `web/src/App.tsx` (`"search"` route)
- Modify: `web/src/components/Activity.tsx` (`password_probe` in `ACTIONS`)
- Modify: `web/src/styles.css` (probe panel classes)

**Context:** `useAuth()` → `{ me }` with `me.csrf_token`. `api.probe(password, csrf)` → `ProbeResult`. `AccountsTable` is `({ accounts }: { accounts: Account[] })`. `ApiError` is exported from `../api`.

- [ ] **Step 1: Add `"search"` to the View union + TABS**

In `web/src/components/AppShell.tsx`, add `"search"` to the `View` union:

```ts
export type View =
  | "overview" | "actionable" | "accounts" | "domains" | "compare" | "reports"
  | "ingest" | "policies" | "integrations" | "operators" | "activity" | "audits"
  | "audit-data" | "exposure" | "search"
```

and add a tab (place after `reports`):

```ts
  { id: "reports", label: "Reports" },
  { id: "search", label: "Search" },
```

- [ ] **Step 2: Create the Search page**

Create `web/src/components/Search.tsx`:

```tsx
import { useMemo, useState, type FormEvent } from "react"
import { api, ApiError, type Account } from "../api"
import { useAccountsData } from "../accountsData"
import { useAuth } from "../auth"
import { filterAccounts } from "../search"
import { AccountsTable } from "./AccountsTable"

export function Search() {
  const { accounts } = useAccountsData()
  const { me } = useAuth()

  const [query, setQuery] = useState("")
  const matches = useMemo(() => filterAccounts(accounts ?? [], query, 1000), [accounts, query])

  const [candidate, setCandidate] = useState("")
  const [showPw, setShowPw] = useState(false)
  const [busy, setBusy] = useState(false)
  const [probe, setProbe] = useState<{ count: number; matches: Account[] } | null>(null)
  const [probeErr, setProbeErr] = useState("")

  async function runProbe(e: FormEvent) {
    e.preventDefault()
    if (!candidate || !me) return
    setBusy(true)
    setProbeErr("")
    setProbe(null)
    try {
      const r = await api.probe(candidate, me.csrf_token)
      setProbe(r)
    } catch (err) {
      setProbeErr(err instanceof ApiError ? err.message : "probe failed")
    } finally {
      setCandidate("") // never keep the candidate around longer than the request
      setBusy(false)
    }
  }

  return (
    <>
      <div className="section-label">Search</div>
      <div className="view-sub">Find accounts across this audit, or check whether a password is in use.</div>

      <div className="toolbar">
        <input
          className="search"
          placeholder="search username or domain…"
          value={query}
          spellCheck={false}
          onChange={(e) => setQuery(e.target.value)}
        />
        {query && <div className="toolbar-count">{matches.length.toLocaleString()} match(es)</div>}
      </div>
      {query ? (
        <AccountsTable accounts={matches} />
      ) : (
        <div className="center-state">Search this audit's accounts by username or domain.</div>
      )}

      <div className="section-label">Password in use?</div>
      <div className="panel">
        <p className="ingest-note">
          Check whether any account in this audit uses a specific password — even uncracked ones — by matching its
          NT hash. Useful for a leaked or banned credential. <b>The password you enter is never stored or logged</b>;
          each check is recorded in the audit log with the operator, time, and match count only.
        </p>
        <form className="probe-form" onSubmit={runProbe}>
          <input
            className="search"
            type={showPw ? "text" : "password"}
            placeholder="password to check…"
            value={candidate}
            spellCheck={false}
            autoComplete="off"
            onChange={(e) => setCandidate(e.target.value)}
          />
          <button type="button" className="link-btn" onClick={() => setShowPw((v) => !v)}>
            {showPw ? "hide" : "show"}
          </button>
          <button type="submit" className="btn btn-primary" disabled={!candidate || busy}>
            {busy ? "checking…" : "Check"}
          </button>
        </form>

        {probeErr && <div className="error">{probeErr}</div>}
        {probe && (probe.count === 0 ? (
          <div className="probe-result c-low">No accounts in this audit use that password.</div>
        ) : (
          <>
            <div className="probe-result c-crit">
              {probe.count.toLocaleString()} account(s) use this password — rotate them.
            </div>
            <AccountsTable accounts={probe.matches} />
          </>
        ))}
      </div>
    </>
  )
}
```

- [ ] **Step 3: Wire the route in App.tsx**

In `web/src/App.tsx`, import `Search` (direct import, matching the lighter pages) and add the case to `viewFor`:

```tsx
import { Search } from "./components/Search"
```
```tsx
    case "search":
      return <Search />
```
(Add the `case "search":` line inside the `switch (view)` in `viewFor`, before `default:`.)

- [ ] **Step 4: Add `password_probe` to the Activity filter list**

In `web/src/components/Activity.tsx`, add `"password_probe"` to the `ACTIONS` array so the new action is filterable (place it logically, e.g. after `"reveal_violation_terms"`):

```ts
  "login", "logout", "reveal_secret", "reveal_violation_terms", "password_probe", "store_unlock", "store_lock", "store_passphrase_change", "store_rekey",
```

- [ ] **Step 5: Add CSS for the probe panel**

Append to `web/src/styles.css`:

```css
/* Search tab — password-in-use probe */
.probe-form { display: flex; align-items: center; gap: 10px; margin-top: 12px; max-width: 520px; }
.probe-form .search { flex: 1; }
.probe-result { margin-top: 14px; font-size: 14px; font-weight: 500; }
```

- [ ] **Step 6: Typecheck, test, build**

Run: `cd web && npx tsc --noEmit && npx vitest run && npm run build`
Expected: all green (incl. styleguard).

- [ ] **Step 7: Commit**

```bash
git add web/src/components/Search.tsx web/src/components/AppShell.tsx web/src/App.tsx web/src/components/Activity.tsx web/src/styles.css
git commit -m "feat(web): Search tab — account search + password-in-use probe"
```

---

## Task 5: Full gate + live verification + finish

**Files:** none (verification + release)

- [ ] **Step 1: Full backend + frontend gates**

```bash
cd /c/base/dev/PasswordAtTheDisco
gofmt -l cmd internal                                   # expect empty
go build ./... && go vet ./... && go test ./...          # all ok (incl. TestProbeEndpoint)
govulncheck ./...                                        # No vulnerabilities found.
( cd web && npx tsc --noEmit && npx vitest run && npm run build )   # all green incl. styleguard + search.test
```

- [ ] **Step 2: Rebuild embedded binary + restart on :8443**

Stop the running patd first (binary lock), then `bash .claude/skills/build-and-run/scripts/build.sh`, then restart via PowerShell `& .claude\skills\build-and-run\scripts\restart.ps1`; confirm the version stamp matches the new commit.

- [ ] **Step 3: Live Playwright verification**

Login (`watson`/`discotime`), unlock (`disco-vault-2026`):
- Press `Ctrl-K` from several views → palette opens; type part of a username → account rows appear; Enter opens the account drawer; reopen, type a view name (e.g. "operators") → a "view" row → Enter navigates there; Esc closes.
- Open the **Search** tab: type in the account search → the `AccountsTable` filters (sortable/paginated, drawer works).
- In **Password in use?**: enter a known cracked password from the sample → expect a non-zero match list (rows open the drawer); enter a random string → "No accounts… use that password"; confirm the audit notice is visible and the input clears after each check.
- Open **Activity** (lead) → confirm a `password_probe` row was recorded and that its target shows `matches=<N>` with no password.
- Assert the browser console has no 4xx/error noise (the probe POST returns 200).

- [ ] **Step 4: Finish the branch**

Use **superpowers:finishing-a-development-branch**: verify tests pass, merge to `main`, tag **v2.15.0**, rebuild + restart on :8443. (Pushing stays deferred per the user's standing preference unless they say otherwise.)

---

## Self-Review notes (for the controller)

- **Spec coverage:** probe endpoint + audit action + redaction + empty-reject (T1); `api.probe` + `filterAccounts` (T2); command palette accounts+views (T3); Search tab account search + probe panel + `password_probe` filterable (T4); gates+Playwright+v2.15.0 (T5). ✓
- **Type consistency:** `ProbeResult {count, matches}` identical in Go (T1) and TS (T2); `filterAccounts(accounts, query, limit=25)` signature used identically in T2/T3/T4; `useNav()` returns `(v: View) => void`; palette mounts inside JobsProvider (has nav/accounts/drawer contexts). ✓
- **Security:** candidate never logged (T1 asserts the audit log lacks "Welcome1"); response redacted (T1 asserts no cleartext/nt_hash); input cleared after probe (T4). ✓
- **Known adaptation for the implementer:** confirm `fmt`/`strings`/`strconv`/`bytes`/`hibp` import presence in the Go files (add if missing); confirm `RISK_CLASS[risk_level]` keys match the account's `risk_level` values (same usage as AccountsTable).
