# App-Wide Clickable Usernames — Design

**Date:** 2026-06-19
**Topic:** Make every audited-account username across the app a clickable link that opens the shared account-detail slide-out drawer (as the Accounts page and Exposure bridge members already do).

## Problem

The account-detail `AccountDrawer` (full per-account detail + score breakdown + lead-gated reveal) is reachable only from the Accounts table and the Exposure bridge-member table. Usernames everywhere else (Actionable, Exposure HIBP triage, Insights top-risk, Domains detail, Compare) are dead text. Operators want to click any account name and drill in.

## Decision

Introduce a **shared drawer provider + an `<AccountLink>` component** so any username becomes a drop-in clickable link opening the one shared drawer. Convert all audited-account username render sites; migrate the two existing local-drawer spots to the shared provider. Include the Compare page fully, which requires a small backend addition (a per-audit accounts endpoint). Approved via brainstorming.

**Not converted** (these are not audited accounts): the topbar operator (`me.username`, AppShell), Operators management, and the Activity audit-log actor.

## Architecture

### A. Backend — per-audit accounts endpoint
The Compare page diffs two *specific* audits (not the active one) and there's no way to fetch a non-active audit's accounts. Add:

- **Route:** `GET /api/audits/{id}/accounts` → `s.requireAuth(s.requireUnlocked(handleAuditAccounts))` (mirrors `/api/accounts` gating exactly; `internal/httpapi/server.go:146`).
- **Handler `handleAuditAccounts`:** read `id := r.PathValue("id")`; return `Store.Accounts(id, false)` (the **redacted** account set — same redaction the active-audit `/api/accounts` uses). On `ErrNotFound` (unknown/empty audit) return `200` with `[]model.Account{}` (consistent with the graceful-empty read pattern; no 404 needed). No new data exposure — same redacted shape as `/api/accounts`.
- **Test** (`internal/httpapi/server_test.go`): seed an audit, assert `GET /api/audits/{id}/accounts` returns its redacted accounts (200, no cleartext/NT-hash in the body), and that an unknown id returns `200 []`.

### B. Frontend — shared drawer provider + link component
1. **`web/src/accountDrawer.tsx`** (new) — `AccountDrawerProvider` + `useAccountDrawer()`:
   - Holds `const [selectedAccount, setSelectedAccount] = useState<Account | null>(null)`.
   - Context value: `{ openAccount: (a: Account) => setSelectedAccount(a) }`.
   - Renders `{children}` then `{selectedAccount && <AccountDrawer account={selectedAccount} onClose={() => setSelectedAccount(null)} />}` (imports the shared `AccountDrawer` from `./components/AccountDrawer`).
   - `useAccountDrawer()` returns the context (throws if used outside the provider).
   - **Mount:** in `web/src/App.tsx`, wrap the existing authed tree (inside `AccountsProvider`, ~lines 80-88) with `<AccountDrawerProvider>` so links anywhere can open the drawer.

2. **`web/src/components/AccountLink.tsx`** (new) — `<AccountLink username domain accounts?>`:
   - Resolves the full `Account` (hooks called **unconditionally** at the top — React rules): `const { accounts: active } = useAccountsData(); const list = accounts ?? active ?? []; const full = list.find(a => a.username === username && a.domain === domain)`.
   - If `full`: render `<button className="link-btn" onClick={() => openAccount(full)}>{username}</button>` (from `useAccountDrawer()`).
   - Else: render `<span>{username}</span>` (plain text — graceful when the account isn't in the available list).
   - The optional `accounts` prop lets a caller (Compare) supply a different/combined account list to search; default is the shared active-audit list.
   - Note: calling `useAccountsData()` is fine here because `AccountLink` is always rendered inside `AccountsProvider`.

### C. Convert the username render sites
Swap the username text for `<AccountLink username={x.username} domain={x.domain} />` at each audited-account site (active-audit lookup — no `accounts` prop):
- **Actionable.tsx** — Priority Worklist row (~328, `Account`), category-table rows (~431, `ReportAccount`), reuse-group member rows (~516, `ReportAccount`). (Where the text was `{a.username}@{a.domain}`, render `<AccountLink>` for the username and keep `@{domain}` if desired, or drop the suffix since AccountLink + the Domain column already convey it — keep current visual: username link, domain shown as today.)
- **Exposure.tsx** — HIBP triage `TriageTable` rows (~312, `ReportAccount`). The bridge-member table (~161) **migrates** from the local `openAccount`/`selectedAccount` to `<AccountLink>` (remove Exposure's local `selectedAccount` state + its `AccountDrawer` mount + the `openAccount` handler).
- **Insights.tsx** — Top-10 Riskiest table (~154).
- **Domains.tsx** — the per-domain detail tables that render usernames (Kerberoastable / AS-REP / escalated / never-expires / stale, etc.). The "Accounts" tab uses `AccountsTable` (covered by D).

### D. Migrate the existing two
- **AccountsTable.tsx** — replace the local `const [selected, setSelected] = useState<Account|null>(null)` + the username `<button onClick={() => setSelected(a)}>` + the `{selected && <AccountDrawer .../>}` mount with `<AccountLink username={a.username} domain={a.domain} />` (it already has the full `Account`, so the lookup resolves trivially). Remove the now-unused `AccountDrawer` import + `selected` state from AccountsTable.
- **Exposure.tsx** — as in C (remove local drawer state, use `<AccountLink>`).

### E. Compare — include fully
- **`api.ts`:** add `auditAccounts: (id) => request<Account[]>(\`/audits/${encodeURIComponent(id)}/accounts\`)`.
- **Compare.tsx:** when the two audit ids (`a`, `b`) are chosen, fetch both `api.auditAccounts(a)` + `api.auditAccounts(b)`, combine into one `Account[]`, and pass it as `<AccountLink accounts={combined} username=… domain=… />` for the cohort rows (~126). De-dupe by `username+domain` (prefer the "current"/`b` audit's row when both exist, so the drawer shows the latest state). Handle load/error gracefully (links fall back to plain text until loaded).

## Data flow
Active-audit sites: `useAccountsData()` (shared `AccountsProvider`) → `AccountLink` lookup → `openAccount(full)` → one `<AccountDrawer>`. Compare: `api.auditAccounts(a/b)` → combined list → `AccountLink accounts={…}` → same drawer. The drawer's reveal stays the existing lead-gated `api.revealSecret` path.

## Security / redaction
Unchanged. The new endpoint returns the **same redacted** `Account` set as `/api/accounts` (no cleartext, no NT hash) and is gated identically (`requireAuth + requireUnlocked`). `AccountLink` and the drawer render only redacted fields; reveal stays lead-gated. No new secret surface.

## Testing
- **Go:** `handleAuditAccounts` test (redacted accounts for an id; empty for unknown id; no cleartext in body). The existing suite stays green.
- **Web:** no new pure logic worth unit-testing (presentational + a thin lookup). `tsc` + `vitest` (incl. `styleguard.test.ts` — class-based styling only) + `npm run build` stay green. Live Playwright check: clicking a username on Actionable / Exposure triage / Insights / Domains / Compare opens the drawer with that account; Accounts page + Exposure bridge members still work (now via the shared provider); no console errors.

## Out of scope
- Operator/Activity usernames (not audited accounts).
- Any change to the drawer's contents or the reveal flow.
- Backend scoring/persistence changes (the new endpoint is a read of existing redacted data).
