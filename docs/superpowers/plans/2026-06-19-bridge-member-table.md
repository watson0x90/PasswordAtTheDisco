# Bridge Member Table + Shared Account Drawer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** Render Exposure bridge-card members as a 6-column table whose usernames open the same slide-out account drawer used on the Accounts page.

**Architecture:** Extract the existing `AccountDrawer` (a private function in `AccountsTable.tsx`) into a shared `AccountDrawer.tsx`, then reuse it in `Exposure.tsx` where bridge members become a table. Frontend only; no backend/data/test-logic change.

**Tech Stack:** React 18 + TS + Vite. No new deps.

**Branch:** `feature/bridge-member-table` (off `main`, post-`v2.12.0`).

**Spec:** `docs/superpowers/specs/2026-06-19-bridge-member-table-design.md`

**Gates:** in `web/`: `npx tsc --noEmit`, `npx vitest run`, `npm run build` (never `npm install`; styleguard bans literal inline spacing).

---

## Task 1: Extract `AccountDrawer` into a shared component (pure refactor)

**Files:** Create `web/src/components/AccountDrawer.tsx`; Modify `web/src/components/AccountsTable.tsx` (remove the 3 local functions, add an import).

Context: In `AccountsTable.tsx` today: `WeakCell` (lines ~193-206), `AccountDrawer` (~207-295), `BreakdownCard` (~297-314) are private functions. `AccountDrawer` props are `{ account: Account; onClose: () => void }`; it depends only on `react` (`useEffect`, `ReactNode`), `../util` (`RISK_CLASS`, `hasDA`, `weaknessTags`), `../api` (`Account`), and on `WeakCell` + `BreakdownCard`. `WeakCell` is also used by the table body (line ~147), so it must remain importable by `AccountsTable`.

- [ ] **Step 1 — Create `web/src/components/AccountDrawer.tsx`.** Move the three functions **verbatim** from `AccountsTable.tsx` into the new file, in this order: `WeakCell`, `AccountDrawer`, `BreakdownCard`. Add the file header imports and export `AccountDrawer` + `WeakCell` (keep `BreakdownCard` un-exported — it's only used internally):
```tsx
import { useEffect, type ReactNode } from "react"
import type { Account } from "../api"
import { RISK_CLASS, hasDA, weaknessTags } from "../util"

export function WeakCell({ a }: { a: Account }) {
  // …verbatim body moved from AccountsTable.tsx…
}

export function AccountDrawer({ account: a, onClose }: { account: Account; onClose: () => void }) {
  // …verbatim body moved from AccountsTable.tsx (uses WeakCell + BreakdownCard above/below)…
}

function BreakdownCard({ title, score, factors }: { title: string; score: number; factors: [string, number][] }) {
  // …verbatim body moved from AccountsTable.tsx…
}
```
Copy the bodies exactly as they are in `AccountsTable.tsx` (the `fmtAge` helper, the `rows` array, the `<aside className="drawer">` markup, the breakdown cards). Do not change any logic or markup.

- [ ] **Step 2 — Update `AccountsTable.tsx`.** Delete the now-moved `WeakCell`, `AccountDrawer`, and `BreakdownCard` function definitions from `AccountsTable.tsx`. Add to its imports:
```tsx
import { AccountDrawer, WeakCell } from "./AccountDrawer"
```
Check the existing `import { ... type ReactNode }` / `useEffect` in `AccountsTable.tsx`: if `ReactNode` or other symbols were only used by the moved functions, remove them from `AccountsTable`'s imports to avoid TS6133 (unused). Keep whatever the remaining `AccountsTable` code still uses (`RISK_CLASS`, `hasDA`, `weaknessTags` are still used by the table body + `WeakCell` import — `weaknessTags` is used at line ~235 inside the drawer which moved, AND possibly in the table; verify and keep imports that are still referenced).

- [ ] **Step 3 — Verify the refactor is behavior-neutral.** `(cd web && npx tsc --noEmit && npx vitest run && npm run build)` — all green, no unused-import errors. The Accounts page is unchanged (same drawer). Commit:
```
git add web/src/components/AccountDrawer.tsx web/src/components/AccountsTable.tsx
git commit -m "refactor(web): extract AccountDrawer + WeakCell into a shared component"
```

---

## Task 2: Bridge member table + clickable drawer (Exposure)

**Files:** Modify `web/src/components/Exposure.tsx` (state, the bridge-card members block, the drawer mount); `web/src/styles.css` (member-table rule).

Context: In `Exposure.tsx`, each bridge card's expanded members currently render as:
```tsx
{open && (
  <div className="bridge-members">
    {c.members.map((m, mi) => (
      <div key={`${m.domain}/${m.username}/${mi}`} className="member-row">
        <span className="muted">{m.username} · {m.domain} · {m.risk_level}</span>
      </div>
    ))}
  </div>
)}
```
`c.members` are `ReportAccount` (`username, domain, cracked, risk_level, risk_score, hibp_breach_count, shared_with`). Exposure has `const { accounts, error } = useAccountsData()` (full `Account[]`).

- [ ] **Step 1 — Imports + state.** In `Exposure.tsx`:
  - Add `import { AccountDrawer } from "./AccountDrawer"`.
  - Ensure `RISK_CLASS` is imported from `../util` (it imports `RISK_CLASS` already — confirm; if not, add it).
  - Add state: `const [selectedAccount, setSelectedAccount] = useState<Account | null>(null)` (the `Account` type is already imported).
  - Add a click handler near the other handlers:
```tsx
  function openAccount(username: string, domain: string) {
    const full = (accounts ?? []).find((acc) => acc.username === username && acc.domain === domain)
    if (full) setSelectedAccount(full)
  }
```

- [ ] **Step 2 — Replace the members block with a table.** Swap the `{open && (<div className="bridge-members">…)}` block for:
```tsx
{open && (
  <div className="bridge-members">
    <table className="member-table">
      <thead>
        <tr><th>Username</th><th>Domain</th><th>Risk</th><th>Score</th><th>HIBP</th><th>Shared</th></tr>
      </thead>
      <tbody>
        {c.members.map((m, mi) => (
          <tr key={`${m.domain}/${m.username}/${mi}`}>
            <td>
              <button className="link-btn" onClick={() => openAccount(m.username, m.domain)}>
                {m.username}
              </button>
            </td>
            <td className="muted">{m.domain}</td>
            <td><span className={`badge ${RISK_CLASS[m.risk_level] || ""}`}>{m.risk_level}</span></td>
            <td className="num">{m.risk_score.toFixed(1)}</td>
            <td className="num">{m.hibp_breach_count > 0 ? m.hibp_breach_count.toLocaleString() : "—"}</td>
            <td className="num">{m.shared_with}</td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
)}
```

- [ ] **Step 3 — Mount the shared drawer.** Just before the final closing `</>` of the Exposure component's return, add:
```tsx
{selectedAccount && <AccountDrawer account={selectedAccount} onClose={() => setSelectedAccount(null)} />}
```

- [ ] **Step 4 — CSS.** In `web/src/styles.css`, add a compact member-table rule (reuse existing tokens; NO literal inline styles in the TSX). Place near the `.bridge-card` rules:
```css
.member-table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 4px; }
.member-table th { text-align: left; color: var(--faint); font-weight: 600; padding: 4px 10px; border-bottom: 1px solid var(--glass-border); }
.member-table td { padding: 5px 10px; border-bottom: 1px solid var(--hairline); }
.member-table td.num { font-family: var(--mono); }
.member-table .link-btn { font-family: var(--mono); }
```
(If the old `.member-row` / `.member-row td` rules are now unused after this change, leave them — they're harmless — unless `tsc`/build flags nothing; do not chase unrelated cleanup.)

- [ ] **Step 5 — Verify + commit.** `(cd web && npx tsc --noEmit && npx vitest run && npm run build)` — all green incl. styleguard (no literal inline spacing). Commit:
```
git add web/src/components/Exposure.tsx web/src/styles.css
git commit -m "feat(ui): bridge-card members as a clickable table opening the shared account drawer"
```

---

## Task 3: Gate, rebuild, live verify, finish

- [ ] **Step 1 — Full gate.** `(cd web && npx tsc --noEmit && npx vitest run && npm run build)`; `go build ./... && go test ./...` (Go untouched but confirm); `govulncheck ./...`.
- [ ] **Step 2 — Rebuild** via `bash .claude/skills/build-and-run/scripts/build.sh` (stop the running `:8443` first so the binary is free), then restart `:8443` via the restart script and unlock (passphrase `disco-vault-2026`).
- [ ] **Step 3 — Playwright verify** on `:8443` (BHE Large Sample audit): Exposure → expand a bridge card → members show as a **6-column table** (Username · Domain · Risk · Score · HIBP · Shared) → click a username → the **account drawer slides out** with full detail + score breakdown → Esc/backdrop closes it. Confirm the Accounts page drawer still works (unchanged). No console errors.
- [ ] **Step 4 — finishing-a-development-branch:** merge `feature/bridge-member-table` → `main`, tag (likely `v2.12.1` — small UI add), rebuild + restart `:8443`.

---

## Self-review
- **Spec coverage:** extract drawer → Task 1; member table 6 cols (Username·Domain·Risk·Score·HIBP·Shared) → Task 2 Step 2; clickable→shared drawer via username+domain match w/ guard → Task 2 Steps 1+3; CSS → Task 2 Step 4; Accounts page unchanged → Task 1 (verbatim move). All spec items mapped.
- **Type consistency:** `AccountDrawer({ account: Account, onClose })` exported in Task 1, consumed in Task 2; `WeakCell` exported + imported by AccountsTable; `ReportAccount` fields (risk_level/risk_score/hibp_breach_count/shared_with) used in the table; `selectedAccount: Account | null`.
- **Confirm-by-reading:** the exact current imports in `AccountsTable.tsx` (which become unused after the move — Task 1 Step 2); that `Exposure.tsx` already imports `RISK_CLASS` + the `Account` type (Task 2 Step 1).
