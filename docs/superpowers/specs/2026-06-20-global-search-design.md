# Global Search + Password-in-Use Probe — Design

**Date:** 2026-06-20
**Topic:** A global search surface — a `⌘/Ctrl-K` command palette for jumping to accounts/views from anywhere, plus a dedicated Search tab that hosts a **password-in-use probe** ("is this exact password used by any account?") answered server-side via NT-hash matching.
**Sequence:** Spec 2 of 2. Spec 1 (sortable + paginated tables) shipped as v2.14.0. This spec ships on its own (target **v2.15.0**).

## Problem

Account search exists only on the Accounts page (client-side username/domain filter); there's no way to jump to an account from another view, and no command palette. Separately, operators want to answer "does anyone still use *this* password?" (a leaked/banned/just-rotated credential) — including for **uncracked** accounts. The original Python tool could only do this by writing cracked passwords to disk; this rewrite never exposes cleartext, but the server already holds each account's NT hash, so it can answer the question by hashing the operator's candidate and matching — without revealing any stored secret.

## Decision

Build two complementary surfaces plus one backend endpoint (approved via brainstorming):

1. **Command palette** (`⌘/Ctrl-K`) — a from-anywhere overlay that searches the already-loaded active-audit accounts (client-side) and offers view-navigation commands. No backend.
2. **Search tab** — a dedicated page hosting (a) the same account search rendered through the existing `AccountsTable`, and (b) the **password-in-use probe** panel.
3. **`POST /api/probe`** — the only new server code: hashes the candidate to NT, matches against the active audit's stored hashes, returns the **redacted** matching accounts + count. Any operator; every call audit-logged (never the candidate).

**Access decision:** the probe is available to **any authenticated operator** (not lead-gated), with every call recorded in the audit log. Rate-limiting was considered and deferred (the audit trail is the deterrent); revisit if abuse appears.

**Out of scope:** audit-log search (already complete on the lead-only Activity page); fuzzy/typo-tolerant ranking (plain substring is enough); persisting search state; any change to the cleartext-reveal flow.

## Architecture

### A. Backend — `POST /api/probe`

- **Route** (`internal/httpapi/server.go`, near the other `/api/...` routes): `mux.Handle("POST /api/probe", s.requireAuth(s.requireCSRF(s.requireUnlocked(http.HandlerFunc(s.handleProbe)))))`. Same middleware order as other mutating POSTs; CSRF because a sensitive value rides in the body.
- **Handler `handleProbe`:**
  1. `sess, _ := sessionFrom(r.Context())`.
  2. Decode `var body struct{ Password string `json:"password"` }`. On decode error or `body.Password == ""` → `writeJSON(w, 400, {error})`. (Rejecting the empty password also prevents the degenerate empty-password-hash match: only `""` hashes to `31D6CFE0D16AE931B73C59D7E0C089C0`, so no separate hash-value guard is needed.)
  3. `candidate := hibp.NTLMHash(body.Password)` (existing fn: MD4 of UTF-16LE, uppercase hex).
  4. `id := activeAuditRead(sess)`; `full, err := s.Store.Accounts(id, true)` (includeSecrets=true so `NTHash` is populated). On error → `writeJSON(w, 200, ProbeResult{Count:0, Matches:[]})` (graceful-empty, consistent with the `/api/audits/{id}/accounts` pattern).
  5. Build `matches := []model.Account{}`: for each `a` in `full` where `a.NTHash == candidate`, append `a.Redacted()` (zeroes Password + NTHash). Match is exact string equality on the uppercase hex (both `NTLMHash` and stored hashes are uppercase hex; if there's any doubt about stored-hash case, upper-case both sides before comparing).
  6. Audit-log: `s.audit(...)` with action **`password_probe`**, actor = session user, target = a non-sensitive summary (e.g. `"matches=<N>"`), result `ok`. **The candidate password is never passed to the audit call, never logged, never echoed.**
  7. `writeJSON(w, 200, ProbeResult{Count: len(matches), Matches: matches})`.
- **Types** (`internal/httpapi` or inline): `type ProbeResult struct { Count int `json:"count"`; Matches []model.Account `json:"matches"` }`.
- **Audit action constant:** add `password_probe` wherever audit action strings are defined; surface it in the Activity page's `ACTIONS` list (`web/src/components/Activity.tsx`) so it's filterable.
- **No new dependency:** reuses `golang.org/x/crypto/md4` via `hibp.NTLMHash` (already imported).

### B. API client — `web/src/api.ts`

```ts
export interface ProbeResult { count: number; matches: Account[] }
// in the api object, next to revealSecret:
probe: (password: string) => request<ProbeResult>("/probe", { method: "POST", body: { password } }),
```
Attach the CSRF token exactly as the other mutating calls in this file do (follow `revealSecret`/`lock`/`unlock`). The password is sent only in the JSON body.

### C. Shared filter — `web/src/search.ts` (+ `search.test.ts`)

```ts
import type { Account } from "./api"
// Plain case-insensitive substring match on username/domain, capped.
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
Unit-tested (node-env vitest): empty query → `[]`; matches username and domain case-insensitively; respects the cap.

### D. Command palette — `web/src/components/CommandPalette.tsx`

- Mounted once in the authed tree (in `App.tsx`, inside `AccountsProvider` + `AccountDrawerProvider`, with access to the nav setter via `useNav()`).
- **Open/close:** a `window` keydown listener toggles open on `(e.metaKey || e.ctrlKey) && e.key === "k"` (preventDefault); `Esc` closes; clicking the backdrop closes. While open, an input is autofocused.
- **Results** (two groups, recomputed from the query):
  - **Accounts:** `filterAccounts(useAccountsData().accounts ?? [], query)` → rows showing `username` + `domain` + a small risk badge.
  - **Go to view:** the `TABS` (and lead-only Setup/Admin items) whose label includes the query → a "jump to view" row. Lead-only items appear only when `me.role === "lead"`.
- **Keyboard:** ↑/↓ move a highlighted index across the flat result list; Enter activates the highlighted row; mouse hover also highlights, click activates.
  - Account row → `useAccountDrawer().openAccount(account)` then close palette.
  - View row → `nav.setView(id)` (or `onNav(id)`) then close palette.
- **Styling:** new `.cmdk-overlay`, `.cmdk-panel`, `.cmdk-input`, `.cmdk-group`, `.cmdk-row`, `.cmdk-row.active` classes in `styles.css` (class-based only — styleguard bans inline spacing). Reuses the existing `.search` input look where natural.
- Empty query → show a hint ("Type to search accounts, or a view name"); no results → "No matches".

### E. Search tab — `web/src/components/Search.tsx` + `View: "search"`

- Add `"search"` to the `View` union and a `{ id: "search", label: "Search" }` entry in `TABS` (`AppShell.tsx`); add the lazy route in `App.tsx`'s view switch (matching how the other views are lazily imported/rendered).
- **Section A — Find accounts:**
  - A `.search` input (controlled) + a live count.
  - `const matches = useMemo(() => filterAccounts(accounts ?? [], query, 1000), [accounts, query])` (higher cap here than the palette since it's a full page).
  - Render `<AccountsTable accounts={matches} />` (reuses the sortable/paginated table + the account drawer). Empty query → a prompt ("Search across this audit's accounts by username or domain.").
- **Section B — Password in use?:**
  - A `type="password"` input (with a show/hide toggle button) + a "Check" button (disabled while empty or in-flight).
  - On submit: `setBusy(true)`; `const r = await api.probe(candidate)`; on success render the outcome; `catch` → an inline error; `finally` clear the input (`setCandidate("")`) and `setBusy(false)`.
  - **Outcome render:**
    - `r.count === 0` → "No accounts in this audit use that password." (reassuring, e.g. green).
    - `r.count > 0` → "<N> account(s) use this password — rotate them." + `<AccountsTable accounts={r.matches} />` (each row → drawer).
  - **Standing notice** under the input: "Each check is recorded in the audit log — operator, time, and match count. The password you enter is never stored or logged." (class-based styling; mirror the reveal-audit `.meta-line`).
  - The candidate lives only in transient component state and is cleared after each check (like the reveal flow's transient reveal state).

### F. App wiring — `web/src/App.tsx`

- Import + mount `<CommandPalette />` once, inside `AccountDrawerProvider` (so it can open the drawer) and within the nav context (so it can navigate).
- Add the `"search"` case to the lazy view switch, importing `Search` the same way the other views are imported.

## Data flow

- **Palette / Search account lookup:** `useAccountsData()` (shared redacted active-audit set, already in memory) → `filterAccounts` → render → `openAccount` opens the existing `AccountDrawer`. No network.
- **Probe:** Search tab → `api.probe(candidate)` → `POST /api/probe` → `hibp.NTLMHash` → scan `Store.Accounts(activeAudit, true)` for `NTHash == candidate` → `[]Account.Redacted()` → `{count, matches}` → render via `AccountsTable` → drawer. Audit log gains a `password_probe` row.

## Security / redaction

- The candidate password travels only in the POST **body** over loopback to a server that already holds cleartext in memory. It is **never** persisted, logged, echoed, or placed in a URL/query. The audit record stores only the action, actor, time, and match count.
- The probe response contains **redacted** accounts only (`Account.Redacted()` zeroes Password + NTHash) — the same shape `/api/accounts` already returns. No new secret surface; no NT hash leaves the server.
- The probe is an exact-match credential oracle available to any authenticated operator. This is an intentional, audit-logged AD-audit capability (find accounts using a known-bad password). It reveals only *that the supplied password matches*, never a stored password. The empty candidate is rejected (step 2), which also blocks enumerating blank-password accounts via a trivial empty candidate.
- Palette + Search-tab account search operate entirely on the already-redacted client-side set.

## Testing

- **Go (`internal/httpapi/server_test.go`):** `TestProbeEndpoint` — seed an audit with a cracked account (password "Welcome1"); `POST /api/probe {"password":"Welcome1"}` → 200, `count >= 1`, the account present in `matches`, and **no cleartext / no `nt_hash`** anywhere in the response body. Probe a non-matching password → `count: 0`. Probe `{"password":""}` → 400. Assert the audit log gained a `password_probe` entry whose recorded fields do **not** contain the candidate string.
- **Web (`web/src/search.test.ts`, node-env vitest):** `filterAccounts` — empty query → `[]`; matches username and domain case-insensitively; honours the cap. (Palette/probe components are presentational + a thin fetch; verified via tsc/build/Playwright, consistent with the project's pure-logic-only unit testing.)
- **Gates:** `gofmt`, `go build/vet/test`, `govulncheck`; `npx tsc --noEmit`, `npx vitest run` (incl. `styleguard.test.ts`), `npm run build`.
- **Live Playwright:** `⌘/Ctrl-K` opens the palette → typing yields account + view results → Enter on an account opens the drawer; a view command navigates; Esc closes. Search tab: account search renders the table + drawer; the probe with a known cracked password lists the matching accounts (→ drawer) and a wrong password says none; the audit notice is visible. Assert the browser console has no 4xx/error noise (the probe POST returns 200).

## Out of scope

- Audit-log search (exists on Activity).
- Lead-gating or rate-limiting the probe (any-operator + audit-log chosen; rate-limit deferred).
- Fuzzy/ranked search, search history, cross-audit search.
- Any change to the cleartext-reveal flow or redaction model.
