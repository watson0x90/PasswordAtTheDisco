# Cross-Domain Bridge Cards — Design

**Date:** 2026-06-19
**Topic:** Replace the Exposure "cross-domain credential bridges" heatmap matrix with severity-tiered **bridge cards**.

## Problem

The Exposure view shows cross-domain credential reuse as a domain×domain **heatmap matrix** (cell = count of shared-password groups bridging that pair). A first-time CISO and Blue-Team Manager both couldn't read it:
- The cell number is ambiguous (groups? accounts? attack paths?).
- It collapses everything that matters per bridge (account count, cracked vs uncracked, reaches-Domain-Admin, password weakness) into one integer.
- It's **pairwise**, so a single password shared across 3 domains is split into 3 separate cells — inflating counts and losing the "one credential bridges all three" story.
- With the typical 2–3 domains, it's a near-empty grid.

## Decision

Replace the matrix (and its legend + the separate "Top credential bridges" text list) with a single **Bridge cards** list — one card per cross-domain bridge, severity-tiered, worst-first. Approved via brainstorming (option A) over a richer heatmap (B) and a chord diagram (C, which would overlap the existing network graph).

## Scope

Frontend only, one view. No backend, no API, no new dependencies. All data already exists in `crossDomainBridges(report).clusters`.

## Design

### Data (unchanged source)
`web/src/exposure.ts` already computes `crossDomainBridges(report)`, returning `clusters: BridgeCluster[]` where each bridge is:
```
BridgeCluster { domains: string[]; size: number; cracked: boolean; hasDA: boolean; hibpMax: number; members: ReportAccount[] }
```
already sorted **DA-first, then by blast-radius** (`size × domains.length`). This is exactly the per-bridge data the cards need.

**Simplification:** the `matrix` field and its build loop in `crossDomainBridges` become unused once the matrix UI is gone — remove the matrix-build loop and the `matrix` field from the `CrossDomain` interface (keep `clusters` + `domains`). Update any references.

### Card UI (`web/src/components/Exposure.tsx`)
Replace the `<table className="bridge-matrix">` block, its `.matrix-legend`, and the separate cluster list with a **Bridge cards** section:

- **Section header:** "Cross-domain credential bridges" + the existing `InfoTip` (GLOSSARY.bridge_matrix — reword to "A bridge is one shared password whose accounts span 2+ domains; an attacker who cracks it can pivot between them.") + a count ("N bridges").
- **Each card** (a `<div>`, severity class drives the left-accent + tint):
  - **Severity tier** (worst-first, already the cluster sort order):
    - `hasDA` → **red** ("⚠ Reaches Domain Admin")
    - else `cracked` → **amber** ("Cracked")
    - else → **grey** ("Uncracked — shared hash, no cleartext")
  - **Domain chain:** `domains.join(" ↔ ")` (handles 3+ domains as one card).
  - **Account count:** `size`, prominent.
  - **Fact badges:** `cracked`/`uncracked`; `HIBP {hibpMax.toLocaleString()}` when `hibpMax > 0`; `{domains.length} domains`.
  - **Members expander:** reuse the existing `openCluster` toggle (stable key `domains.join("/")+"#"+idx`) — expands to the redacted member list `username · domain · risk_level` (existing render).
- **Top-N + show-all:** carry over the existing `showAllBridges` toggle — default top 10, "show all {N}" / "show fewer".
- **Empty state:** when no cross-domain bridges (`bridges.domains.length < 2` / `clusters.length === 0`), show the existing "No credentials are shared across domains." panel.

### Styling (`web/src/styles.css`)
- Add `.bridge-card` + severity variants (`.bridge-card.crit` / `.cracked` / `.uncracked`) for the left-accent border + tint, the header row (label + domain chain on the left, count on the right), and the badge row. Reuse existing tokens/badge classes where possible.
- **Remove** the now-unused `.bridge-matrix` cell rules (`m0–m3`), `.matrix-legend`. Keep `.bridge-cluster-row`/member styles if still used by the expander, else fold into `.bridge-card`.

### Retired
- The heatmap `<table>` + `m0–m3` cells.
- The `.matrix-legend` caption.
- The click-a-cell **`pairFilter`** interaction and its state (cards already show the domain pairs; no separate filter needed).
- The separate "Top credential bridges" text list (the cards *are* that list).

### Kept
- The HIBP-repeat note ("Accounts sharing a password share its breach count…").
- The HIBP urgency triage + blast-radius worklist sections (unchanged).
- The Exposure view subtitle.

## Testing
- `web/src/exposure.test.ts`: existing `crossDomainBridges` tests stay green; if they assert on `matrix`, update them to the simplified shape (clusters-only). The cluster derivation + sort is unchanged.
- Component (cards) verified via `tsc` + `npm run build` + a live Playwright check on the loaded dataset (severity tiers render, 3-domain bridge shows as one card, expand works, top-N/show-all works, no console errors). No jsdom/testing-library added.

## Out of scope
- A domain filter (worst-first card scroll is enough for the typical few domains).
- Any change to the network graph, HIBP triage, or worklist.
- Backend / scoring / persistence.
