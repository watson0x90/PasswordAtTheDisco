# Exposure "blast radius" — top object-controllers table — Design

> Sub-project C of the v2.29.0 "get Tier-0 right" release. Adds a sorted table of the accounts that
> control the most AD objects to the **Exposure** tab — the visible **justification** for a Tier-0/Critical
> verdict ("here are the accounts behind it, ranked by how much each can take over"). Pairs with the
> verdict graduation (B) and the transitive-enrichment fix (A).

## 1. Problem / goal
When the verdict reads "Critical — N reachable Tier-0 controllers," the operator (and the audited org)
needs to *see those accounts and what each owns* — or the finding isn't actionable or believable. Today the
controlled-object data exists per-account but there's no ranked view of "who can take over the most."

## 2. Design
A new section on the **Exposure** tab: **"Blast radius — accounts controlling the most objects."**
- **Data:** the already-loaded redacted account set (no new endpoint). Filter `controlled_object_count > 0`,
  sort **descending** by `controlled_object_count`.
- **Rows:** top **25**; a footer line "+N more accounts control >100 objects" (count of the remaining
  `controlled_object_count > 100` accounts not shown), so nothing is silently truncated.
- **Columns:**
  1. **#** (rank)
  2. **Account** — the username (operator-visible; not a secret). Row is **clickable → opens the existing
     `AccountDrawer`** for full detail (and the lead-gated cleartext reveal lives there, unchanged — this
     table introduces no new reveal surface and shows no password/hash).
  3. **Domain**
  4. **Controlled objects** — `controlled_object_count`, thousands-separated (e.g. `16,778`), right-aligned.
  5. **Risk** — level badge, colour-tokened (Critical/High/Medium/Low), matching the app's level colours.
  6. **Flags** — small badges that draw the eye to the dangerous ones:
     - `T0` when `controls_tier0`
     - `DA` when it has a DA pathway (`hasDA(da_domains)`)
     - `Crk` when `cracked`
     - `RCH` (Reachable) when `enabled && (cracked || hibp_breached || escalated_by_shared_da ||
       escalated_by_mass_reuse)` — i.e. the credential is *obtainable*. This is the same "reachable"
       predicate the scoring uses; extract a shared `isReachable(a)` helper in `web/src/insights.ts` (or
       `util.ts`) and use it both here and anywhere the band/verdict logic needs it, so the table and the
       verdict can never disagree about what "reachable" means.
- **Empty state:** if no account has `controlled_object_count > 0` (no BloodHound enrichment, or none
  control objects): a muted line "No controlled-object data — run BloodHound enrichment to populate."
- **Sorting/format:** descending by count; ties broken by risk level then username for stability.

## 3. Why this placement
The Exposure tab already hosts the blast-radius / worklist views. This table is the **evidence layer**
under the executive verdict: the card says *"7 reachable Tier-0 controllers"* → the operator scrolls here
and sees the seven, ranked, each with its object count and flags. It also surfaces **latent crown jewels**
(high control, *not* cracked/HIBP → no `RCH` flag) so the org sees what to harden *before* they're
compromised — consistent with the "uncracked-not-HIBP doesn't rank against you, but is still worth seeing"
stance.

## 4. Files
- **Web only** (no backend change — the data is already in the redacted `/api/accounts` payload):
  - `web/src/components/Exposure.tsx` — add the section + table (or a small `BlastRadiusTable.tsx`
    sub-component it renders). Reuse the existing account-row → `AccountDrawer` open pattern (read how
    `AccountsTable.tsx` opens the drawer) and the level-colour tokens.
  - `web/src/insights.ts` (or `util.ts`) — `isReachable(a: Account): boolean` shared helper.
  - `web/src/styles.css` — any new classes use `var(--space-*)`/colour tokens only (styleguard test bans
    literal inline spacing).
- Confirm the redacted `Account` type carries `controlled_object_count`, `controls_tier0`, `da_domains`,
  `cracked`, `enabled`, `hibp_breached`, `escalated_by_shared_da`, `escalated_by_mass_reuse`, `risk_level`,
  `username`, `domain` (it does — used elsewhere); add any missing field to the TS type.

## 5. Testing
- **vitest:** a pure helper test for the sort/filter/top-25/"+N more" logic if it's factored into a
  function (e.g. `topControllers(accts, 25)` in insights.ts) — assert descending order, the >0 filter, the
  remaining->">100" count, and `isReachable` truth table. `styleguard.test.ts` must stay green.
- **Gates:** `cd web` → `npx tsc --noEmit`, `npx vitest run`, `npm run build` (NEVER `npm install`).
- **Live (owner) + Playwright (mine, on the disposable :8444 only):** the table renders, sorts descending,
  the top rows show the big controllers with correct flags, clicking a row opens the drawer, console clean.

## 6. Definition of done
The Exposure tab shows a descending "blast radius" table of all object-controlling accounts (top 25 +
"+N more >100"), each with domain, object count, risk level, and T0/DA/Crk/RCH flags; rows open the
existing drawer; no new reveal surface; empty state handled. Pure frontend over existing data; `isReachable`
shared with the scoring logic. Ships in v2.29.0 with A (enrichment fix) and B (verdict graduation).
