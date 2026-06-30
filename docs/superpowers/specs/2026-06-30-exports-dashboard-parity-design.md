# Unified metrics library + dashboard-parity exports (with optional unredacted reports)

- **Date:** 2026-06-30
- **Status:** Approved (brainstorming) — pending implementation plan
- **Owner:** watson0x90
- **Component area:** `internal/metrics` (new), `internal/model`, `internal/risk`, `internal/report`, `internal/httpapi`, `web/src`

## Problem

Exports do not match the dashboards, and the two surfaces do not use the same
calculations:

1. **Calculation drift (structural).** Several derived metrics are computed
   **twice** — once in Go and once in TypeScript:
   - Posture score, rating, verdict, reachability band — `internal/model/model.go`
     (`PostureScore`, gate verdict, reachability `L`) **and** `web/src/insights.ts`
     (`posture`, `gateVerdict`, `reachBand`).
   - Risk-tier cutoffs and the Exposure×Impact level matrix —
     `internal/risk/risk.go` (`tierOf`, `levelMatrix`, `LevelFromAxes`) **and**
     `web/src/matrix.ts` (`axisTier`, `LEVEL_MATRIX`, `cellLevel`).
   Some pairs are pinned by tests; the **frontend posture/verdict mirror is not**,
   and it is exactly what the per-domain dashboards rely on. A domain view can
   legitimately disagree with an export.

2. **No per-domain exports.** Every CSV/HTML export is audit-wide. Per-domain
   dashboards are filtered/recomputed **entirely in the frontend**
   (`web/src/domainScope.ts`, `web/src/domainData.ts`); there is no server
   per-domain summary and no per-domain report artifact.

3. **Exports are a subset of the dashboards.** The dashboards render many series
   (charts, the Exposure×Impact matrix, reuse/similarity network graphs, exposure
   headline, blast-radius worklist) that are computed only in TS and never appear
   in any export.

## Goals

- **Single source of truth for calculations** — Go. One reusable package computes
  every derived metric; the API serves it, the SPA renders it, the exporters
  render it. No metric is computed in two languages.
- **Exports match the dashboards** — both the **numbers** and the **visuals**
  (charts, matrix, graphs), for the org view and for each individual domain.
- **Per-domain reports** — delivered two ways: a per-domain **section** inside the
  org report, and **standalone** single-domain downloads.
- **Optional unredacted (cleartext) reports** — a deliberately gated tier that
  includes cracked cleartext passwords, without weakening the default.

## Non-goals

- No change to **per-account scoring math** (`internal/risk` v2 two-axis model
  stays as-is). This work consolidates *aggregate/derived* metrics and removes the
  TS duplicates; it must not move any number.
- The **sanitized JSON** export stays anonymized always; the unredacted tier does
  **not** apply to it.
- NT hashes are **never** written to disk in any tier (unredacted = cleartext
  passwords only).
- No new persistence engine; flat-JSON + in-memory store model is unchanged.

## Decisions (from brainstorming)

| Decision | Choice |
|---|---|
| Source of truth | **Go, server-authoritative.** SPA renders server values. |
| Export parity | **Full** — numeric *and* visual parity with the dashboards. |
| Per-domain delivery | **Both** — per-domain section in the org report **and** standalone per-domain downloads. |
| Formats in scope | **HTML, CSV, sanitized JSON.** |
| Unredacted scope | **Cleartext cracked passwords only** (no NT hashes). |
| Unredacted controls | **Lead-only + audit-logged + explicit typed confirmation (+CSRF) + visible "CONTAINS CLEARTEXT" watermark/timestamp.** |
| Unredacted formats | **HTML + CSV only.** Sanitized JSON always stays sanitized. |
| Spec/plan shape | **One spec, phased plan.** |

## Architecture: one Metrics bundle, three renderers

```
[]model.Account ─▶ internal/metrics.Compute(accounts, opts)
                        │   (redacted by default; no cleartext, no NT hash;
                        │    opaque reuse-group IDs)
                        ▼
                   metrics.Metrics  (org)            metrics.DomainMetrics[]  (per domain)
                        │                                   │
        ┌───────────────┼───────────────────────────────────┼───────────────┐
        ▼               ▼                                   ▼               ▼
   GET /api/metrics  internal/report (HTML)          CSV exporter    sanitized JSON
   (+?domain)        + per-domain sections           (+?domain)      (aggregates from lib)
        │            + standalone per-domain
        ▼
   web/src dashboards render the bundle
   (TS calc deleted; rendering kept)
```

**One computation, many renderers.** The bundle is computed once in Go and is the
only producer of derived numbers. The SPA, the HTML report, the CSV exporter, and
the sanitized JSON exporter are all *renderers* of that bundle (CSV/JSON also read
the per-account list for row-level fields).

### Component 1 — `internal/metrics` (new package)

Computes a comprehensive, **redacted-by-default** `Metrics` struct from
`[]model.Account` (reusing existing building blocks: `model.PostureScore`,
`model.BuildReport`, `risk.LevelFromAxes`). Contents (org-level and, identically,
per-domain):

- **Posture:** score, rating, likelihood, verdict, breakdown (risk/strength/
  compliance), reachability band + pct, overall. (Consolidates `model.PostureScore`
  as the single implementation.)
- **Summary counts:** total, cracked, hibp_breached, da_pathways, disabled,
  never_expires, stale, policy_violations, high_controlled, escalated_by_shared_da,
  escalated_by_mass_reuse, dormant_privileged, risk_counts, breach_impact.
- **Exposure×Impact matrix:** the 4×5 distribution grid + per-cell level (via the
  single `LevelFromAxes`/level matrix).
- **Chart series** (ported from `web/src/insights.ts` / `exposure.ts`):
  riskDistribution, hibpSplit, lengthBuckets, scoreBuckets, hibpVsRisk,
  sharingDistribution, daExposureByDomain, complexityCounts,
  controlledObjectsBuckets, passwordAgeBuckets, similarityBuckets, expirationSplit,
  axisFactorBars, exposureHeadline, blastRadius worklist, crossDomainBridges,
  hibpTriage, topRiskiest.
- **Graph data:** cross-domain reuse graph and similarity network as nodes/edges,
  **plus a deterministic server-computed static layout** (x/y per node) so the HTML
  export can draw them without a browser layout engine.
- **Per-domain:** `DomainMetrics` for each domain = the same struct computed over
  that domain's account subset. Replaces `domainScope.ts` / `domainData.ts`.

**Redaction:** the bundle never contains cleartext or NT hashes; reuse groups use
opaque IDs (as today). Redaction is a property of the *bundle*; the unredacted tier
(below) is handled by the **renderers** pulling cleartext from the store, not by the
bundle.

**Determinism:** all ordering, bucketing, and graph layout must be deterministic
(stable sorts, fixed seeds) so golden tests and exports are reproducible.

### Component 2 — API

- `GET /api/metrics` → org `Metrics` (JSON). `?domain=<d>` → that domain's bundle.
- `GET /api/summary` stays and is derived from / a subset of the bundle
  (back-compat for current callers).
- Per-account list endpoints unchanged (tables/drawers still need raw rows).
- Auth: `requireAuth` + `requireUnlocked` as today.

### Component 3 — Frontend refactor (largest, riskiest)

The SPA renders the bundle instead of recomputing:

- `web/src/insights.ts`, `exposure.ts`, `matrix.ts` — compute-functions become thin
  selectors over the server bundle (or are removed); **chart-rendering components
  are kept** and fed server series.
- `web/src/domainScope.ts`, `web/src/domainData.ts` — read the per-domain bundle
  (`/api/metrics?domain=`) instead of recomputing from the org report.
- Delete the duplicated posture/verdict/reachability/matrix math from TS.
- **Parity gate:** dashboards must render the same numbers before/after. Verified by
  comparing rendered values to the bundle and by Playwright snapshots on :8444.

### Component 4 — Exports (three renderers over the bundle)

- **HTML (full visual parity):** render charts, the matrix heatmap, and the two
  network graphs as **static inline SVG** (self-contained, no scripts — consistent
  with the current self-contained HTML report), driven by the bundle (graphs use the
  bundle's static layout). The org report gains a **per-domain section** per domain
  (its `DomainMetrics`). **Standalone per-domain** HTML via `?domain=<d>`.
- **CSV:** audit column set against the dashboard fields (close any gaps); add
  `?domain=<d>` variants for the account/cracked/hibp/weak/reuse CSVs.
- **Sanitized JSON:** its aggregates come from the shared library; optionally add
  per-domain rollups. Always anonymized.

### Component 5 — Redaction tiers (the unredacted option)

- **Default (redacted):** unchanged — no cleartext, no NT hash.
- **Unredacted (cleartext passwords only):** a `redaction=cleartext` option on the
  **HTML and CSV** export endpoints. Controls:
  - **Lead-only** (role gate, like the per-account reveal).
  - **Explicit confirmation:** request must carry a typed acknowledgement token +
    CSRF; not a default, not a bare GET toggle.
  - **Audit-logged:** actor, time, scope (org or domain), format, account count —
    **never the passwords themselves** (same discipline as the reveal log).
  - **Watermark:** the file carries a visible "CONTAINS CLEARTEXT — handle per
    policy" banner + generated-by + timestamp.
  - Cleartext is read from the in-memory store **only when authorized**, the same
    source as the one-account reveal; it is added as a column (CSV) / cell (HTML
    account table) and nowhere else.
- **Sanitized JSON:** no unredacted variant.

## Data flow (per request)

1. SPA dashboard load → `GET /api/metrics` (org) and `GET /api/metrics?domain=` on
   domain drill-down → render.
2. Export (redacted) → endpoint computes the bundle (org or domain) → renderer emits
   HTML/CSV/JSON.
3. Export (unredacted) → lead + confirmation + CSRF verified → audit event written →
   renderer emits with cleartext column + watermark.

## Error handling & edge cases

- **Impact Unknown** (no BloodHound coverage): preserved — bundle carries
  `impact_known=false`; matrix uses the Unknown column; provisional level = exposure
  tier. Single predicate in Go.
- **Disabled accounts:** posture hygiene over enabled only; reachability over all —
  exactly as the current Go `PostureScore`. The per-domain bundle uses the same
  predicates so a domain view and the org view agree on shared accounts.
- **Reuse groups:** opaque IDs; member lists truncated with a `truncated` flag (size
  = true total), as today.
- **Empty / single-domain audits:** per-domain bundle for the only domain equals the
  org bundle except where org-only concepts (cross-domain bridges) are naturally
  empty.
- **CSV injection (CWE-1236):** `csvSafe` neutralization preserved on every CSV,
  including the new cleartext column and per-domain variants.
- **Unauthorized unredacted request:** 403 for non-lead; 400 without the
  confirmation token; both audit-logged as denied.

## Testing strategy

- **Go golden parity tests:** snapshot the full bundle (org + per-domain) against
  values captured **before** the refactor, proving the port moves no numbers. Reuse
  / extend the existing matrix golden tests; pin posture/verdict/reachability.
- **Renderer tests:** HTML report snapshot (structure + key values + watermark
  presence/absence by tier); CSV header/row parity + injection neutralization;
  sanitized JSON schema.
- **Unredacted gating tests:** lead vs non-lead; missing confirmation token; audit
  event written and contains no password; cleartext present only in the unredacted
  output.
- **TS:** remove duplicated-calc unit tests; add "renders bundle" tests; keep a
  matrix parity test now asserting the SPA matches the server-served matrix.
- **Live (Playwright on :8444):** dashboards render identical numbers; org + per-
  domain reports download; standalone per-domain; unredacted flow (lead, confirm,
  watermark visible); console clean. Never touch live :8443.
- **Security review** of the new surface, with focus on the unredacted path (gating,
  audit, no secret in logs, no cleartext in the redacted tier or sanitized JSON).

## Phased delivery (for the implementation plan)

1. **`internal/metrics` library** (org + per-domain) + golden parity tests. No
   consumer changes yet.
2. **Serve `/api/metrics`** (+`?domain`); `/api/summary` becomes a subset.
3. **SPA renders the bundle**; delete TS duplicates; verify parity.
4. **Export parity + per-domain:** HTML visual parity + per-domain section +
   standalone; CSV column parity + per-domain; sanitized JSON aggregates from lib.
5. **Unredacted tier** (lead/audit/confirm/watermark) on HTML + CSV.
6. **Security review + finish** (build/test/live evidence; merge + tag).

Each phase is independently shippable and leaves the app working.

## Risks

- **Frontend refactor scope (Phase 3)** is the largest risk: many chart components
  switch from local compute to server data. Mitigated by golden parity tests + the
  bundle being a faithful port, and by doing it after the library is proven.
- **Static graph layout in Go (Phase 4)** for the network graphs is non-trivial
  (force-directed layout without a browser). Mitigated by a deterministic
  server-side layout in the bundle; acceptable fallback is a simplified node-link or
  adjacency view if a full force layout proves too costly — to be decided in the plan.
- **Unredacted tier (Phase 5)** reverses the core security guarantee for one gated
  path; the controls above are mandatory and get a dedicated security review.

## Open items for the plan

- Exact `/api/metrics` payload shape and whether `/api/summary` is kept verbatim or
  re-expressed as a view over the bundle.
- Graph-layout algorithm/quality bar for static export (full force layout vs.
  simplified) — pick in Phase 4.
- Whether per-domain standalone downloads are exposed per-format in the Reports UI
  or via a domain picker on the Domains view (UX detail for Phase 4).
