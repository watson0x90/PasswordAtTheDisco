# Similarity-Breakdown Password Reveal (Lead-Gated) — Design

**Date:** 2026-06-20
**Topic:** Let a lead reveal the cleartext password of the selected account *and* its similar peers directly from the Password Similarity Clusters breakdown — so the actual near-duplicate passwords can be compared — through the existing lead-gated, audit-logged reveal. Makes the reveal **domain-aware** so the exact account is revealed. Target release **v2.17.0** (or folded into the next tag).

## Problem

The similarity breakdown (shipped in v2.16.0) names an account's most-similar peers + scores but never shows the passwords — so an operator can see *that* two passwords are ~90% similar but not *what* the shared pattern is. The user wants to see the actual passwords to understand what's at play. The only safe way is the existing **lead-only, one-at-a-time, audit-logged** reveal — not an auto-computed "common base" (an ungated partial-cleartext leak, explicitly rejected during brainstorming).

A blocking detail: the reveal endpoint (`GET /api/accounts/{username}/secret`) is **username-only** (`Store.Find(id, username)`), but the breakdown identifies accounts by username+**domain**. In a multi-domain audit with a repeated username, a username-only reveal can return the wrong account's password. So reveal must become **domain-aware**.

## Decision

Add a lead-gated reveal to the breakdown (selected account + each peer), reusing the existing `handleReveal` flow (which logs `reveal_secret` and never logs the password). Make the reveal endpoint accept an optional `?domain=` to resolve the exact account; the Accounts table also passes domain (fixing the same latent ambiguity there). Reveal logic stays self-contained in the breakdown component (no refactor of the security-critical Accounts-table reveal). Approved via brainstorming.

**Out of scope:** auto-computed "common base"/shared-stem display (rejected — ungated partial cleartext); any change to the scoring model / controlled-objects weighting (separate decision); a shared `useReveal` hook refactor of AccountsTable (kept self-contained to limit blast radius).

## A. Backend — domain-aware reveal

### `internal/store/store.go`
`Store.Find(id, username)` returns the first account matching `username` (case-insensitive) within an audit. Add a domain-aware variant:

```go
// FindByDomain returns the full (unredacted) account for username+domain within
// an audit. Exact domain match disambiguates a username that repeats across
// domains (which Find cannot).
func (s *Store) FindByDomain(id, username, domain string) (model.Account, bool)
```
Implement it next to `Find`, matching both `Username` and `Domain` case-insensitively over the audit's accounts (reuse `Find`'s existing iteration/locking pattern).

### `internal/httpapi/server.go` — `handleReveal`
After resolving `username := r.PathValue("username")`, read `domain := r.URL.Query().Get("domain")`. Resolve the account:
- if `domain != ""`: `acct, ok := s.Store.FindByDomain(id, username, domain)`
- else: `acct, ok := s.Store.Find(id, username)` (unchanged path).

Set the audit `Target` to `username + "@" + domain` when `domain != ""`, else `username` (the existing value). Everything else in `handleReveal` is unchanged: lead-role check, fail-closed audit on every branch (`ok`/`denied`/`not_found`), the response shape `{username, password}`, and **the password is never written to the audit log**. (Route and middleware unchanged: `s.requireAuth(s.requireUnlocked(handleReveal))` with the lead check inside.)

### Test (`internal/httpapi/server_test.go`)
Seed an audit with the same username `"svc"` in two domains `"CORP"` (password `"AlphaPass1"`) and `"GHOST"` (password `"BetaPass2"`), with `nt_hash` set so they're distinct. As a lead:
- `GET /api/accounts/svc/secret?domain=GHOST` → 200, `password == "BetaPass2"` (the exact account).
- `GET /api/accounts/svc/secret?domain=CORP` → 200, `password == "AlphaPass1"`.
- `GET /api/accounts/svc/secret` (no domain) → 200, returns one of them (back-compat, unchanged behavior — assert 200 + non-empty, not which).
- Assert the audit log contains `reveal_secret` with target `svc@GHOST` and does **not** contain either password string.
- A non-lead (analyst) `GET …?domain=GHOST` → 403/denied (existing gating), audit `denied`.

## B. Client — `web/src/api.ts`
Change `revealSecret` to accept an optional domain:

```ts
  revealSecret: (username: string, domain?: string) =>
    request<{ username: string; password: string }>(
      `/accounts/${encodeURIComponent(username)}/secret${domain ? `?domain=${encodeURIComponent(domain)}` : ""}`,
    ),
```
Backward-compatible: existing call sites that pass only a username are unaffected.

### `web/src/components/AccountsTable.tsx`
Update its reveal call from `api.revealSecret(a.username)` to `api.revealSecret(a.username, a.domain)`. The table already has `a.domain` on each row; no other change to its reveal state/UX. (This fixes the latent same-username-across-domains ambiguity in the table too.)

## C. Frontend — reveal in the breakdown (`web/src/components/SimilarityClusters.tsx`)

`SimilarityBreakdown` currently takes `{ account, accounts }`. Add lead-gated reveal, self-contained in the component:

- **Auth:** `const { me } = useAuth()`; `const isLead = me?.role === "lead"`. Reveal affordances render only when `isLead`.
- **State (self-contained, keyed by `${domain}/${username}`):**
  - `revealed: Record<string, string>` (key → cleartext), `revealing: string` (key in flight), `revealErr: string`.
  - `reveal(username, domain)`: `setRevealing(key)`; `const r = await api.revealSecret(username, domain)`; `setRevealed(prev => ({...prev, [key]: r.password}))`; push a `window.setTimeout(() => hide(key), 45000)` into a `useRef<number[]>` timers list; `catch` → `setRevealErr`; `finally` → `setRevealing("")`.
  - `hide(key)`: delete the key from `revealed`.
  - `copy(text)`: `navigator.clipboard.writeText(text)` (best-effort try/catch), mirroring AccountsTable.
  - Cleanup: `useEffect(() => () => timers.current.forEach(clearTimeout), [])`.
- **Render — selected account header (lead only):** a small reveal control next to the username. Not revealed → a `reveal-btn` ("reveal"); in flight → "…"; revealed → `<span class="secret"><span class="mono-pw">{pw}</span><button class="link-btn" copy><button class="link-btn" hide></span>` (same classes as AccountsTable so the existing `.secret`/`.mono-pw` wrap styling applies — including the recent word-break fix).
- **Render — each peer row (lead only):** the existing `<AccountLink/>` + score, plus the same reveal control for `(p.username, p.domain)`. So a lead can reveal the selected account and a peer side-by-side and read the two passwords.
- `{revealErr && <div className="error">{revealErr}</div>}` near the list.
- **Note copy:** change the standing note from "Passwords are never shown." to: *"Revealing a password is lead-only and recorded in the audit log — never the password itself."* (For non-leads it still effectively never shows.)

Hooks rule: `SimilarityBreakdown` already early-returns when `!account`; move the new hooks (`useAuth`, the reveal `useState`s, the timers `useRef`, the cleanup `useEffect`) **above** that early return so they're unconditional.

## Data flow
Lead clicks reveal in the breakdown → `api.revealSecret(username, domain)` → `GET /accounts/{username}/secret?domain=…` → `handleReveal` (lead check + audit `reveal_secret` for `username@domain`) → `FindByDomain` → `{username, password}` → shown inline (mono), auto-hidden after 45s. The redacted account set, `similar_peers`, and graph are unchanged — the cleartext exists only transiently in the reveal state, exactly like the Accounts table.

## Security / redaction
- Reveal remains **lead-only** and **audit-logged** (every attempt, allowed or denied; password never logged). Adding `?domain=` only disambiguates *which* account — it does not widen what's exposed or who can see it.
- No "common base" / partial-cleartext is ever computed or shown; revealing shows whole passwords through the existing gate, one click at a time, auto-hidden.
- Non-lead operators get no reveal affordance (server also enforces the lead check, so the client gate is defense-in-depth).
- The cleartext lives only in transient component state (cleared on hide / 45s timeout / unmount), never persisted — identical to the Accounts-table reveal.

## Testing
- **Go:** the `handleReveal?domain=` test above (exact account by domain, back-compat without domain, audit target `username@domain` with no password, non-lead denied). `gofmt`, `go build/vet/test`, `govulncheck`.
- **Web:** reveal UI is presentational + a thin fetch — `tsc` + `vitest` (incl. styleguard — class-based only, the reveal reuses `.secret`/`.mono-pw`/`.reveal-btn`/`.link-btn`) + `npm run build`.
- **Live Playwright (as lead `watson`):** in the similarity breakdown, reveal the selected account → cleartext shows; reveal a peer → its cleartext shows; the two passwords are visibly similar; copy/hide work; auto-hide after 45s (or hide manually); Activity shows `reveal_secret` rows with `username@domain` targets and no password. Confirm a domain-aware reveal returns the right account. No console 4xx/errors.

## Out of scope
- Auto common-base/shared-stem display.
- Scoring-model / controlled-objects changes.
- Refactoring AccountsTable's reveal into a shared hook (kept self-contained).
- Adding reveal anywhere else (only the similarity breakdown gains it here).
