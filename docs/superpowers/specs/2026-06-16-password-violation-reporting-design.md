# Password-violation reporting — design

- **Date:** 2026-06-16
- **Status:** Approved (brainstorm), pending implementation plan
- **Owner:** watson0x90

## Problem

The analyzer checks every cracked password against the four wordlists in `lists/`
(common, dictionary, forbidden, keyboard) and these signals are surfaced as
per-account booleans/counts (the v2.2 "weak passwords" work: Accounts badges,
Actionable "Weak Passwords" report, CSV/HTML columns). What's still missing:

1. A **visualization** of violations *by count* (the original Python tool implied
   richer surfacing than badges).
2. The **specific matched terms** — which forbidden words / keyboard patterns
   actually recur — so an operator can act ("add these to the deny-list"). Today we
   deliberately expose only counts, never the matched word.

## Decisions (from brainstorm)

1. **Detail policy = "C"**: the actual matched word (a cleartext *fragment*) is shown
   **only in the web app**, behind the **same lead-gated, audited reveal** as a
   cleartext password (in memory). **Exports stay categories + counts** — never the
   word — preserving the product's "no cleartext on disk" rule.
2. **Two charts, both as counts:**
   - **By category** (common / dictionary / forbidden / keyboard) — shown in **both**
     the app and the weak-passwords HTML export.
   - **By specific term** (top recurring forbidden words + keyboard patterns) —
     **app only**, behind the audited reveal.
3. **Placement = "A"**: extend the existing **Actionable → Weak Passwords** section
   (app) and the existing **weak-passwords HTML export** (disk). No new nav tab, no
   new export file.
4. **Per-reveal auditing**: each reveal of recurring terms is audit-logged
   (who / when), exactly like a password reveal.

## Security model (the crux)

| Data | Sensitivity | Stored | Shown |
|---|---|---|---|
| Category booleans/counts (`is_common`, `banned_word_count`, …) | metadata (redacted-safe) | redacted account (already) | app + exports, freely |
| Matched forbidden words / keyboard patterns (`"2021"`, `"qwerty"`) | cleartext **fragment** | encrypted store only; stripped by `Redacted()` | app only, lead-gated + **audited per reveal** |
| Common / dictionary match | the term **is the whole password** | already covered by `Password` | **never** as a term — category count only |

**Critical nuance:** for `is_common` / `is_dictionary_word`, the "matched term" would
be the entire password. Therefore the **term drill-down covers forbidden words and
keyboard patterns only** (substring fragments). Common and dictionary remain
category-count-only everywhere.

## Backend

### Data model
- `model.Account` gains:
  - `BannedWords []string` `json:"banned_words,omitempty"`
  - `KeyboardPatterns []string` `json:"keyboard_patterns,omitempty"`
  These are the actual matches from `pwanalysis.Analyze` (which already returns them).
  They are cleartext fragments: persisted only in the encrypted store and **cleared by
  `Redacted()`** (alongside `Password` and `NTHash`). The existing redacted-safe count
  fields (`BannedWordCount`, `KeyboardPatternCount`, `IsCommon`, `IsDictionaryWord`)
  are kept and continue to drive badges + category counts.
- `engine.scoreCracked` stores both the slice and the count
  (`BannedWords: an.BannedWords, BannedWordCount: len(an.BannedWords)`, same for
  keyboard). `scoreUncracked` leaves them empty (no cleartext).

### Report category counts (redacted-safe)
- `model.Report` gains `ViolationCounts` (`json:"violation_counts"`):
  ```
  type ViolationCounts struct {
      Common, Dictionary, Forbidden, Keyboard int // # of accounts in each category
  }
  ```
  Computed in `BuildReport` over the accounts (an account in two categories counts in
  both bars). Rides along in `/api/report`. Redacted-safe (counts only).

### Term aggregation (sensitive)
- New `model.AggregateTerms(accts []Account, topN int) Terms`:
  ```
  type Term  struct { Term string; Count int }          // Count = # accounts containing it
  type Terms struct { Forbidden []Term; Keyboard []Term } // each sorted desc, capped at topN
  ```
  Counts each distinct term **once per account**, over `BannedWords` /
  `KeyboardPatterns`. Operates on **unredacted** accounts. `topN` = 25.

### Endpoint
- `GET /api/report/terms` — `requireAuth` + `requireUnlocked`, **lead-only** (checked
  in-handler like `handleReveal`). Loads `Accounts(id, true)`, calls `AggregateTerms`,
  returns `Terms`. Audit-logs a new action **`reveal_violation_terms`**
  (Result `ok` for leads, `denied` for non-leads — never the terms themselves in the
  log). This is the only place the matched words leave the process.

## Web app — Actionable → Weak Passwords

- A **category bar chart** at the top of the section: pure CSS bars (matching the
  existing risk-distribution bars — **no new chart dependency**), fed by
  `report.violation_counts`. Four bars: forbidden / common / dictionary / keyboard.
- A **lead-only** "🔓 reveal recurring terms" button → `api.reportTerms()` → expands a
  **term bar chart** (top forbidden words + keyboard patterns by account count). Each
  click hits the audited endpoint. Non-leads never see the button.
- The existing weak-passwords table stays below, unchanged.
- `Activity` view: add `reveal_violation_terms` to the action filter list.

## Exports

- **`weak.html`** (weak-passwords HTML export) gains a **category chart** header (same
  CSS bars) above the existing table. Implemented as a dedicated
  `report.WeakPasswordsHTML(w, name, generated, weakAccts)` that computes the four
  category counts from its input slice and renders chart + table. The handler
  (`handleExportWeakHTML`) switches from `AccountsHTML` to this. **No terms, no
  reveal** — categories + counts only.
- **`weak.csv`** and the accounts CSV are **unchanged** — the per-account category
  columns already exist and counts are derivable; the chart is an HTML-only artifact.
- The full report (`report.HTML`) is **unchanged** — the weak export is the violations
  home. (Adding the chart there later is a trivial follow-up if wanted.)

## Non-goals / out of scope

- No new nav tab, no new export file, no new dependency.
- Common/dictionary terms are never shown (they equal the whole password).
- `weak.csv` / accounts CSV format unchanged.
- Full `report.HTML` unchanged.

## Testing

- **Go**
  - `Redacted()` strips `BannedWords` + `KeyboardPatterns` (extend the redaction test;
    assert the words never appear in a redacted account or any export).
  - `BuildReport` `ViolationCounts` correctness (multi-category account counted twice).
  - `AggregateTerms`: per-account dedup, descending sort, `topN` cap, and that it draws
    only from forbidden/keyboard (never common/dictionary).
  - httpapi: `/api/report/terms` is lead-gated (403 + `denied` audit for non-lead) and
    audited (`reveal_violation_terms`) for a lead; `/api/report` and every export carry
    **no** matched word (grep the response bytes for a known planted term).
- **Frontend**
  - `tsc`; a small vitest for the category/term chart data transform.
  - Playwright: the reveal button is lead-only; category chart renders for any operator;
    term chart renders after reveal for a lead.
- **Live**: re-ingest the lab, confirm the category chart counts match, reveal terms as
  lead (e.g. `"2021"` recurring), confirm the audit event lands and the export HTML has
  the chart but not the word.

## Rough file touch-list

- `internal/model/model.go` (fields + `Redacted`), `internal/model/report.go`
  (`ViolationCounts`, `AggregateTerms`, `Terms`/`Term`), `internal/engine/engine.go`
  (store the slices), `internal/httpapi/server.go` (`handleReportTerms` + route +
  `handleExportWeakHTML` swap), `internal/report/report.go` (`WeakPasswordsHTML` +
  CSS bars), `web/src/api.ts` (types + `reportTerms`), `web/src/components/Actionable.tsx`
  (charts + reveal), `web/src/components/Activity.tsx` (action filter), a small chart
  component, `web/src/styles.css`.
