# Changelog

All notable changes to **Password!AtTheDisco** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

_Nothing yet._

## [2.28.0] — 2026-06-23 — Executive scoring rework (Hygiene × Reachability + Tier-0 gate)

> Resolves the "Strong posture next to Very-High breach" contradiction surfaced by auditing a sanitized
> export. Reworks the **audit-level executive rollup only**; the per-account two-axis engine is unchanged.
> Existing audits adopt it on their next **Recalculate**. Panel-vetted (offensive-security + measurement
> theory + risk-frameworks), built subagent-driven with two-stage review + an opus whole-branch review.

### Changed
- **Two orthogonal axes + a one-way gate.** *Credential Hygiene* (0–100, average over **enabled**
  accounts; the mathematically-dead privilege term removed; disabled excluded; weights 45/35/20) and
  *Breach Reachability* `L = 1 − ∏(1−pᵢ)^countᵢ` over reachable DA-path / Tier-0 / Critical enablers
  (smooth, integer-band, scale-aware). The headline **Verdict** (`Sound · Guarded · Elevated · High Risk
  · Critical · Critical — Tier-0 Reachable`) is gated so it can never read "Strong" while a reachable
  Tier-0/DA path exists; `Overall = Hygiene × (1−L)` is a labelled trend key, not the headline.
- **Reachability counts only *obtainable* credentials** — cracked **or HIBP-breached** or shared-DA /
  mass-reuse; and only *reachable* (enabled, credential-obtainable) DA/Tier-0 paths, never structural ones.
- **Breach impact ($ / recovery / probability) is reachability-driven**, single-sourced with the verdict.
- **Dormant privileged** (disabled but pre-compromised) accounts surfaced (Summary, sanitized export,
  HTML report, dashboard). `critN` requires Impact-known so unenriched weak accounts can't inflate
  reachability. Go⇄TS parity pinned by a 10-case golden fixture (+ a fixture-in-sync guard).

## [2.27.0] — 2026-06-23 — Reuse-floor mid tier (close the 100-cliff)

> A third scoring gap from the same **sanitized-export** review (2.25). Existing audits adopt the
> change on their next **Recalculate**.

### Changed
- **Mid-size reuse clusters now floor Exposure.** The Exposure reuse-floor previously applied only at
  ≥100 accounts (4.0) and ≥1000 (5.0), leaving a cliff: a 50–99 account *uncracked* reuse cluster got
  only the small reuse bump and read as bottom-of-*Low*, hiding on the Exposure worklists. A new
  **≥50 → 3.0** tier closes it; stacking with the reuse bump it lands such clusters at ~4.0
  (Medium-Exposure), monotonic with the existing 100/1000 tiers. Exposure-axis only — the composite
  Level still respects the Impact matrix (a latent low-blast-radius cluster stays *Low*; only *cracked*
  clusters escalate Level, via the 2.26 mass-reuse pass). Help copy updated.

## [2.26.0] — 2026-06-23 — Scoring-audit fixes (mass reuse + bulk Tier-0)

> Two scoring gaps surfaced by reviewing a **sanitized export** (2.25) of a real 6,000-account
> audit. Existing audits adopt the changes on their next **Recalculate**.

### Changed
- **Large cracked-password reuse clusters now escalate.** A password cracked across many accounts
  ("crack one, own N") used to read as N× *Low* — each account's blast radius is low, and the
  Exposure×Impact matrix caps a low-Impact account at Medium. Now the **Level** of members of a large
  *cracked* cluster escalates to **Medium / High** (scale-aware thresholds: ≥25 accounts or ≥5% of the
  audit → Medium; ≥100 or ≥25% → High; cap High). Impact is left honest (the blast radius really is
  low); a `MASS-REUSE` risk-vector tag, an `escalated_by_mass_reuse` flag, and an "Escalated
  (Mass-reuse)" drawer row explain the escalation. Critical accounts (DA / shared-DA) are never
  downgraded.

### Fixed
- **Tier-0 control is now flagged on large audits.** The bulk BloodHound enricher (used for big
  audits) never computed `controls_tier0`, so DCSync / Domain-Admin-group / KRBTGT / AdminSDHolder
  controllers were silently under-scored on any audit large enough to use bulk enrichment. A new bulk
  Cypher (using the same Tier-0 definition as the per-user path) closes the gap — verified live against
  a real BloodHound (it correctly surfaced an AD-sync DCSync account the bulk path had been missing).

## [2.25.0] — 2026-06-23 — Sanitized review export

### Added
- **Sanitized review export** (Reports → "Sanitized review export (JSON)", and
  `GET /api/export/sanitized.json`): a fully **anonymized** JSON report of an audit — every
  per-account scoring signal (exposure, impact, the risk vector, the score breakdown, coverage,
  the Kerberos/DA/controlled/reuse flags) plus the audit aggregates — with **all identifying and
  secret data removed**. No usernames, domain names, NT hashes, cleartext, matched wordlist
  substrings, DA pathway domain names, raw password-set timestamps, or audit name appear anywhere.
  Relational structure is preserved as **opaque, name-free tokens** (account ids, domain labels,
  reuse-group ids, similar-peer links) so the scoring can be reviewed for gaps — by a person or an
  AI — **without exposing customer data**. The export is audit-logged.
  - Built as an **allowlist** (a separate output type, never the account struct), so any future
    field is excluded by default; the guarantee is enforced by a canary byte-scan **and** a
    structural forbidden-key test, and verified live.

## [2.24.0] — 2026-06-22 — BloodHound user-properties upload fidelity

> Uploading a SharpHound/BHE **users** export (Setup → BloodHound → "Upload user data")
> now enriches accounts faithfully — without a live Neo4j query.

### Fixed
- **Uploaded properties no longer vanish on Recalculate.** A users-export upload sets
  per-account AD properties (enabled, password-last-set, controlled-object count) on
  accounts that BloodHound has not graph-enriched. A subsequent **Recalculate** used to
  silently wipe them back to defaults; now they survive — the account keeps its uploaded
  properties and Impact correctly stays **Unknown** (no Domain-Admin graph was collected).
- **An export that omits `enabled` no longer force-disables accounts** — a missing
  `enabled` key is treated as "unknown" (left as-is) instead of `false`.

### Added
- **Kerberoast / AS-REP from a users export.** The upload now reads and applies `hasspn`
  and `dontreqpreauth`, so the roastability scoring (incl. the AS-REP Exposure floor) works
  from an offline SharpHound/BHE export — not only a live BloodHound connection.
- **Recalculate nudge after an upload.** A lead is prompted to recalculate so the uploaded
  properties (credential age, roastability, the disabled-latent-risk flag) actually take
  effect — the same one-click affordance shown after policy / forbidden-words / HIBP edits.

## [2.23.0] — 2026-06-22 — Sharper Exposure weights (roastability, reuse, credential age)

> **Scoring was refined again** (Exposure axis only; Impact is unchanged). Existing audits keep
> their old numbers until you **Recalculate scoring** (Overview → Recalculate).

### Added
- **Credential age now scores.** A password that hasn't rotated in years is materially more
  crackable, so it adds a bounded Exposure bump (1–2 yr +0.25, 2–5 yr +0.5, 5 yr+ +0.75) when
  BloodHound supplies the last-set date. Surfaced as an **Age** row in the account drawer's
  Exposure breakdown and on the Insights Exposure radar.
- **"Latent risk" badge** in the account drawer for a **disabled** account that is still
  dangerous — it controls a Tier-0 asset, has a Domain-Admin pathway, controls objects, or its
  hash is reused (≥2 accounts). Disabled accounts are capped at Impact 2.0 (they can't
  authenticate), which can hide a re-enable / Pass-the-Hash persistence path; the badge surfaces
  it. (No score change — a surfacing-only safety net.)

### Changed
- **Roastability is weighted by attack economics.** AS-REP-roastable accounts (no pre-auth, no
  foothold needed) now outweigh Kerberoastable ones (which need a domain foothold): SPN +0.5,
  AS-REP +0.75. AS-REP additionally **raises an Exposure floor of 3.0** — the hash will be pulled
  and cracked offline regardless of how strong the password looks — so a roastable service account
  can no longer read as harmless.
- **Password reuse scales with the cluster.** The bump grows with the number of accounts sharing
  a hash, and a large cluster (≥100 → floor 4.0, ≥1000 → floor 5.0) now raises a credential's
  Exposure **floor** on its own: crack one, own the cluster — even if that password looks strong.
- The in-app **Help → How we score risk** chapter documents the new age, reuse-floor, and AS-REP
  weighting.

## [2.22.0] — 2026-06-23 — Recalculate scoring, a refined two-axis model & coverage tools

> **Scoring was refined.** Domain risk now *multiplies* Impact and the triage percentile is
> level-first (details below). Existing audits keep their old numbers until you **Recalculate
> scoring** (Overview → Recalculate) — the new action makes that one click.

### Added
- **Recalculate scoring** — a lead-only background job that re-scores the active audit against
  the *current* policy, forbidden-words, and HIBP index **without re-querying BloodHound**
  (each account's Impact is preserved), then nudges you to re-run enrichment. Editing a policy
  or wordlist now offers a one-click recalculate so changes actually reach existing accounts.
- **Enrichment Coverage** — a read-only section on the Integrations page listing the accounts
  BloodHound did **not** enrich (the same count as the Overview "Impact Unknown" KPI), with a
  why-diagnosis and a non-secret **CSV export** to take back to BloodHound. **Analysts can reach
  it** (Integrations is now role-aware: analysts see only the coverage view, not the lead-only
  HIBP/BloodHound config).
- **More of the score is now visible** in the account drawer: the **Tier-0 / DA-equivalent
  control** signal, the decomposed **weakness sub-penalties** (length / complexity / dictionary
  / similarity), the **failed policy rules**, and a **unicode** flag. The risk vector gained
  **`RO:`** (Kerberoast / AS-REP roastability) and **`T0:`** (Tier-0) tokens.
- The in-app **Help → How we score risk** chapter now documents the full live model: the domain
  multiplier, a vector-token legend, the level-first percentile, and the shared-DA escalation.

### Changed
- **Domain risk is now a multiplier on Impact** (`×1.1 / ×1.2 / ×1.3` for Medium / High / Critical),
  matching the labels in the Policies editor; the Exposure axis stays credential-intrinsic and
  unenriched accounts are unaffected. (Previously additive, contrary to the UI.)
- **Triage percentile is level-first** (Critical > High > Medium > Low, then an Impact-weighted
  tiebreak) — so it can never rank a Low-level account above a High one. It no longer rides the
  legacy `risk_score`.
- **Dashboard consistency:** the Insights "Cross-domain credential reuse" graph is built from the
  report's real reuse groups (no more fabricated edges; it agrees with the Exposure bridges
  panel); the Overview KPIs read the authoritative `Summary` counts.

### Fixed
- **A Recalculate no longer drops the HIBP Exposure floor** when the HIBP index is unavailable —
  the stored breach count is preserved (unknown ≠ zero).
- The shared-DA escalation now syncs the score **breakdown** to Impact 10 (the drawer no longer
  contradicts the headline); an open account drawer reflects a completed rescore **without a page
  reload**; the posture caption cites a real band; dead code and stale comments cleaned up.

### Security
- BloodHound **enrichment now refuses (409) while a rescore is running** and vice-versa (both
  rewrite the audit) — the guard is symmetric across the REST API and the UI.
- The coverage table/CSV expose only non-secret fields (username / domain / cracked / level);
  the new `contains_unicode` / `policy_violations` signals are descriptive (rule names, not
  passwords) and survive redaction. No cleartext or NT hash is added to any endpoint, vector, or
  the audit log.

## [2.21.0] — 2026-06-22 — MCP server for AI agents

### Added
- **MCP server** at `POST /api/mcp` — a stateless Streamable-HTTP JSON-RPC endpoint
  (stdlib only, no new dependencies) that lets AI agents (Gemini, Kiro, Claude, …) query
  an audit through **role-scoped API tokens**. Eight redacted read tools (`list_audits`,
  `get_posture`, `list_accounts` [filter/sort/paginate], `search_accounts`,
  `domain_breakdown`, `password_in_use`, `get_report`, `diff_audits`) plus a **lead-only**,
  one-account-at-a-time, **audit-logged and fail-closed** `reveal_password`. `audit_id`
  defaults to the most recent audit; every tool call is audited (never the token secret).
- **API token credential system** — `patdmcp_<id>_<secret>` tokens (SHA-256-hashed,
  shown once), a lead-gated Admin **MCP Tokens** panel, and a `patd token create|list|revoke`
  CLI. `requireMCPToken` bearer middleware attaches an `analyst|lead` role; issue/revoke
  are audited. Tokens live hashed in `mcp_tokens.json` (`PATD_MCP_TOKENS_FILE`, gitignored).

### Security
- Non-reveal MCP tools return only redacted data (no cleartext, no NT hash); cleartext
  flows solely through the lead-gated, audited, fail-closed `reveal_password`. The
  `password_in_use` candidate is matched by NT hash server-side and never stored or logged.

## [2.20.0] — 2026-06-21 — Colourised Exposure × Impact matrix + audit hardening

### Added
- **Colourised risk matrix** — the Overview's Exposure × Impact cells are now tinted by
  the risk **level** they resolve to (Critical → red, High → amber, Medium → green,
  Low → cyan), with a legend; account count still drives the tint intensity. A single
  shared `cellLevel()` feeds both the live grid and the in-app Help methodology diagram,
  so the two can't drift from the scoring engine.

### Fixed
Post-v2.19 subsystem audit:
- Kerberoastable / AS-REP-roastable signals are captured on **every** BloodHound response
  format (previously only the BHE CE "literals" path; tabular/node formats dropped them).
- Domain-Admin pathway tables now show each account's controlled-object count
  (`ReportAccount` carried none, so the column always rendered "—").
- Uncracked accounts now carry their score breakdown, so they appear in the
  risk-factor-by-tier dashboard rather than being silently excluded.
- A Domain-Admin account no longer self-flags as "escalated by shared-DA" (a false
  positive that inflated the lateral-movement report).
- The risk-factor breakdown uses the shared `impactIsKnown` predicate, so it can't
  diverge from the matrix and accounts table.
- A transient BloodHound outage now surfaces an error instead of being mistaken for
  "account not found", which had silently dropped Impact to Unknown.
- Matrix cell tint was an invalid non-final CSS background layer (so cells rendered
  un-coloured); it is now painted as a valid gradient layer over the glass.

## [2.19.1] — 2026-06-21 — Dead-session 401 console noise

### Fixed
- The console now returns to the login screen on any **401** (mirroring the existing
  423 → lock handling), so a dead server-side session — wiped by a restart or expired by
  the idle / absolute timeout — stops the lead-only job pollers from 401-ing every 5 s.
  While authenticated: zero console errors; on session death: a single bounce to login.

## [2.19.0] — 2026-06-21 — In-app Help / Methodology section

### Added
- **Help / Methodology** — a pre-auth, presentation-style section (reachable from the
  login and unlock screens, deep-linkable via `#help/<slug>`) with five chapters: the
  security thesis, the two-axis Exposure × Impact scoring model, the enrichment pipeline,
  the security / privacy model, and a glossary / FAQ. Inline-SVG diagrams, **pure static —
  no API calls.** Written to explain the model to CISOs and blue-team leads.

## [2.18.0] — 2026-06-21 — Two-axis (Exposure × Impact) risk scoring

### Changed
- **Risk scoring rebuilt around two axes.** **Exposure** (crackability / HIBP / reuse /
  roastable — always computed from the dump) × **Impact** (blast radius — BloodHound-derived,
  and explicitly **Unknown** when an account isn't enriched). The overall level comes from a
  2-D Exposure × Impact matrix, not a single blended number. **Scores change for every
  account — this is intentional.**

### Added
- True BloodHound **controlled-objects count** (uses the API's real total — removes the old
  10-object cap), **Tier-0 / DA-equivalent** control detection, roastable signals on the live
  enrichment path, and per-account **coverage**.
- **Within-audit percentile** triage, **shared-hash → DA** Impact inheritance, and HIBP
  de-duplication.
- Honest dashboard: per-axis sub-score bars (replacing the old radar), the Exposure × Impact
  matrix with an explicit **Unknown** column, a coverage banner, **provisional** badges, a
  needs-enrichment worklist, and two-axis KPIs.

### Removed
- The v1 single-axis CVSS-style scoring path.

## [2.17.0] — 2026-06-20 — Lead-gated reveal in the similarity breakdown

### Added
- Reveal the cleartext of a selected account and its similar peers from the **Password
  Similarity Clusters** breakdown, through the existing lead-only, audit-logged reveal — now
  domain-aware so the exact account is revealed.

### Fixed
- Similar-peer duplication (accounts sharing a password) and a doubled-domain audit target
  for `username@domain` accounts.

## [2.16.0] — 2026-06-20 — Similarity clusters: expand + explain

### Added
- The **Password Similarity Clusters** graph is now expandable into a large modal and
  explainable: clicking a node names its most-similar accounts and similarity scores, backed
  by new server-computed similar-peer references (redacted — username / domain / score, never
  the password).

### Changed
- Graph edges are now real pairwise links from those peers (replacing the prior heuristic
  domain-chain edges).
- **Search** page split into **Accounts** and **Password in use?** sub-tabs.

## [2.15.0] — 2026-06-19 — Global search + password-in-use probe

### Added
- **⌘/Ctrl-K command palette** — from any view, search accounts (opens the shared
  detail drawer) or jump to another view. Account search runs over the already-loaded
  redacted set; no extra round-trips.
- **Search** tab — account search backed by the sortable/paginated accounts table.
- **Password-in-use probe** (`POST /api/probe`) — check whether any account uses a
  specific password, **including uncracked ones**, by matching its NT hash server-side.
  Returns only redacted accounts; available to any operator, CSRF-gated, request body
  size-capped. Every check is audit-logged (`password_probe`) with the operator, time,
  and match count — the candidate is **never stored, logged, or echoed**.

### Fixed
- Revealing a cleartext password no longer forces a horizontal scrollbar on the
  accounts table (the secret cell wraps instead of widening the table).
- Main content width is now responsive (`clamp(1320px, 92vw, 1440px)`) so wide screens
  give tables — and a revealed password — room to stay on one line.

## [2.14.0] — 2026-06-19 — Sortable + paginated tables

### Added
- Column **sorting** (type-aware, severity-ranked risk, stable) and page-based
  **pagination** across Accounts, Activity, Domains detail, Operators, Actionable, and
  Compare cohorts, via a shared hook plus `SortHeader` / `Pager` controls.

### Changed
- The Accounts table's virtualized scroll was replaced by real pagination; the
  Actionable and Domains "top-N" display caps were replaced by paging (no more silently
  truncated lists).

## [2.13.0] — 2026-06-19 — App-wide clickable usernames

### Added
- Every audited-account username across the app (Accounts, Exposure, Actionable,
  Insights, Domains, Compare) is a clickable link that opens the shared account-detail
  drawer.
- `GET /api/audits/{id}/accounts` — redacted per-audit accounts, for opening the drawer
  from the Compare view's two compared audits.

## [2.12.1] — 2026-06-19

### Added
- Exposure cross-domain bridge members render as a clickable table that opens the shared
  account drawer (the drawer was extracted into a shared component for reuse).

## [2.12.0] — 2026-06-18 — Dashboard clarity

### Changed
- A dashboard-clarity pass: health-framed posture score ("higher is better, target ≥ 75"),
  inline ⓘ glossary tooltips, per-view purpose subtitles, a ranked **Priority Worklist** in
  Actionable, and severity-tiered cross-domain bridge cards.

## [2.11.0] — 2026-06-18 — BloodHound graph + exposure analytics

### Added
- BloodHound users import + bulk Cypher enrichment (DA reachability and controlled-object
  counts in one pass).
- Exposure analytics — cross-domain credential reuse, HIBP-vs-risk triage, blast-radius
  buckets, DA exposure by domain, password-age distribution, and a risk-factors radar —
  plus an interactive network graph; rebuilt **Insights** and **Domains** views.
- Editable forbidden-words list (lead-only, logged by count only).

### Fixed
- A fresh load no longer logs a console 401 (`/api/me` returns 200 with an `authenticated`
  flag); report and console polish; Playwright dev dependencies dropped.

## [2.10.0] — 2026-06-17

### Fixed
- UI review fixes: responsive ☰ header, quiet `/api/me`, readable complexity-chart labels;
  added `tools/dev_seed.sh` for a one-command, synthetic-data-loaded instance.

## [2.9.0] — 2026-06-17

### Added
- Editable forbidden-words list (lead-gated, audit-count-only); a CSS token system and a
  styleguard test.

### Fixed
- Graceful no-audit empty states (no console 409s) and overflow fixes.

## [2.8.0] — 2026-06-17 — Exposure dashboards

### Added
- Cross-domain bridges, HIBP triage, and a blast-radius worklist; an audit-data UX overhaul.

## [2.6.0] — 2026-06-16

### Added
- Upload UX improvements, decoupled BloodHound enrichment, domain drill-down, and
  background-job visibility.

## [2.4.1] — 2026-06-16

### Added
- Manage Audits view with secure delete.

## [2.4.0] — 2026-06-16

### Changed
- Console navigation consolidation and report parity.

## [2.3.0] — 2026-06-15

### Added
- Wordlist-violation reporting.

## [2.2.0] — 2026-06-15 — Reporting

### Added
- Redacted report exports as CSV and HTML.

## [2.1.0] — 2026-06-12 — Admin & oversight

### Added
- Runtime operator management with hot-reload, per-account login lockout + history, a
  searchable/CSV-exportable Activity view over the audit log, and an in-app HIBP downloader.

## [2.0.0] — 2026-06-10 — Secure Go + React rewrite

The ground-up Go API + React console that replaced the original Python tool.

### Added
- argon2id auth, revocable sessions, RBAC, append-only audit log, redacted-by-default
  endpoints, and ingest.
- The analysis engine: secretsdump parsing, HIBP NTLM lookup, password analysis, BloodHound
  Enterprise enrichment, and CVSS-style risk scoring.
- Encrypted-at-rest store with DEK re-keying, embedded single-page app, TLS fail-closed, and
  guided deploy scripts.

### Security
- Cleartext never written to disk; cleartext reveal is a lead-only, audit-logged action that
  never records the password value.

[Unreleased]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.21.0...HEAD
[2.21.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.20.0...v2.21.0
[2.20.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.19.1...v2.20.0
[2.19.1]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.19.0...v2.19.1
[2.19.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.18.0...v2.19.0
[2.18.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.17.0...v2.18.0
[2.17.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.16.0...v2.17.0
[2.16.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.15.0...v2.16.0
[2.15.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.14.0...v2.15.0
[2.14.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.13.0...v2.14.0
[2.13.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.12.1...v2.13.0
[2.12.1]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.12.0...v2.12.1
[2.12.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.11.0...v2.12.0
[2.11.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.10.0...v2.11.0
[2.10.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.9.0...v2.10.0
[2.9.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.8.0...v2.9.0
[2.8.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.6.0...v2.8.0
[2.6.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.4.1...v2.6.0
[2.4.1]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.4.0...v2.4.1
[2.4.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/watson0x90/PasswordAtTheDisco/releases/tag/v2.0.0
