# Bridge-Card Member Table + Shared Account Drawer — Design

**Date:** 2026-06-19
**Topic:** In Exposure → Cross-domain credential bridges, render each bridge's expanded members as a **table** whose accounts are **clickable**, opening the same slide-out **account detail drawer** used on the Accounts page.

## Problem

The bridge cards (shipped in v2.12.0) expand to a flat list of member rows (`username · domain · risk_level` as plain text). It's hard to scan and the accounts aren't actionable — you can't drill into one. The Accounts page already has a rich slide-out drawer (`AccountDrawer`) with full per-account detail + score breakdown; the bridge members should use it.

## Decision

1. **Extract the slide-out drawer into a shared component** so both Accounts and Exposure use the identical panel (no duplication, guaranteed visual parity).
2. **Render bridge members as a table** with columns: **Username · Domain · Risk · Score · HIBP · Shared**.
3. **Make each member's username clickable** — it opens the shared drawer for that account.

Approved via brainstorming. Frontend only; no backend/data/API change.

## Architecture

### A. Extract `AccountDrawer` → `web/src/components/AccountDrawer.tsx` (new file)
Currently `AccountDrawer` (and its helpers `BreakdownCard` + `WeakCell`) are private functions inside `AccountsTable.tsx`. `AccountDrawer` is already self-contained (`props: { account: Account; onClose: () => void }`), depends only on `../util` (`RISK_CLASS`, `hasDA`, `weaknessTags`), `../api` (`Account` type), and React.

- New `AccountDrawer.tsx` **exports** `AccountDrawer` and `WeakCell` (both are used by `AccountsTable`); keeps `BreakdownCard` internal.
- `AccountsTable.tsx`: delete the local `AccountDrawer`, `BreakdownCard`, and `WeakCell` definitions; add `import { AccountDrawer, WeakCell } from "./AccountDrawer"`. No behavior change on the Accounts page.
- No circular dependency: `AccountsTable → AccountDrawer → util` (the drawer never imports `AccountsTable`).

### B. Bridge member table (`web/src/components/Exposure.tsx`)
Replace the expanded-members block inside each bridge card (currently `.bridge-members` with `.member-row` divs over `c.members`) with a `<table className="member-table">`:

| Column | Source (`ReportAccount`) | Render |
|---|---|---|
| Username | `m.username` | a `link-btn` button → opens the drawer |
| Domain | `m.domain` | text |
| Risk | `m.risk_level` | `<span className={"badge " + RISK_CLASS[m.risk_level]}>` |
| Score | `m.risk_score` | `.toFixed(1)` |
| HIBP | `m.hibp_breach_count` | `.toLocaleString()` or `—` if 0 |
| Shared | `m.shared_with` | number |

`ReportAccount` already carries all six fields. Header row + rows styled like the Accounts table (reuse existing table CSS where possible; add a small `.member-table` rule for compact sizing).

### C. Clickable → shared drawer (Exposure.tsx)
- Exposure already loads the full `accounts` list (`useAccountsData`). Members are `ReportAccount` (a redacted subset).
- Add state `const [selectedAccount, setSelectedAccount] = useState<Account | null>(null)`.
- On a username click, resolve the full account:
  `const full = accounts?.find((acc) => acc.username === m.username && acc.domain === m.domain)`
  then `if (full) setSelectedAccount(full)`. (Members are accounts in the active audit, so the lookup succeeds; if it ever doesn't, the row simply isn't clickable / no-ops — guard on `full`.)
- Render `{selectedAccount && <AccountDrawer account={selectedAccount} onClose={() => setSelectedAccount(null)} />}` near the end of the Exposure return.
- Import `AccountDrawer` from `./AccountDrawer`, `RISK_CLASS` from `../util` (for the badge), and the `Account` type (already imported).

## Data flow
`report.cracked_reuse/uncracked_reuse` → `crossDomainBridges` → `BridgeCluster.members: ReportAccount[]` → member table (6 columns) → click → match against `accounts: Account[]` (from `/api/accounts`) → `AccountDrawer(account)`. The drawer's reveal stays the existing lead-gated `api.revealSecret` path (unchanged — it lives in the drawer/table, not duplicated).

## Security / redaction
Unchanged. The member table shows only redacted `ReportAccount` fields. The drawer shows the same redacted `Account` already used on the Accounts page, with the same lead-gated reveal. No new cleartext surface.

## Testing
- No new pure logic to unit-test (presentational). `exposure.ts` is untouched.
- The existing test suite (incl. `styleguard.test.ts` — use CSS classes, no literal inline spacing) must stay green after the extraction.
- Component behavior verified via `tsc` + `npm run build` + a live Playwright check: a bridge card expands to the 6-column table; clicking a username slides out the drawer with that account's detail + score breakdown; Esc/backdrop closes it; no console errors. No jsdom/testing-library added.

## Out of scope
- Any change to the Accounts page behavior (the drawer move is a pure refactor there).
- Backend/scoring/persistence.
- Adding reveal to the member table itself (the drawer carries the existing reveal).
