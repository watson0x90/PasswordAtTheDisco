# Sanitized audit-review export — Design

> A new export that emits an audit's **scoring/structural data with all identifying and secret
> information removed**, so the scoring model can be audited for gaps/issues (by a human or an AI
> reviewer) **without exposing customer data** (usernames, domain names, NT hashes, cleartext).

## 1. Goal & threat model
Produce a JSON document containing every per-account *scoring* signal plus audit-level aggregates,
carrying **zero** identifying or secret data, so it can be shared with an external reviewer.

**Never present in the output** (directly or derivably): username, domain name, cleartext password,
NT hash, the matched wordlist substrings (`banned_words` / `keyboard_patterns`), DA pathway domain
names, the raw `pwd_last_set` epoch, and the operator-chosen audit name (may embed a customer name).

**Safety mechanism — allowlist, fail-closed.** The sanitizer does NOT marshal `model.Account`
(a denylist leaks any *future* sensitive field). It builds **separate output structs**
(`SanitizedReport`, `SanitizedAccount`, `SanitizedDomain`) by explicitly copying only named safe
fields. A field absent from the output struct cannot be emitted — so any field added to
`model.Account` later defaults to **excluded** until deliberately allowed.

## 2. Transforms (sensitive raw → safe derivation)
- `da_domains` (real domain names) → **`has_da_path bool`** (via `Account.HasDAPathway()`).
- `pwd_last_set` (raw epoch, correlatable) → **`password_age_days int`** = `floor((now - pwd_last_set)/86400)`, `0` when `pwd_last_set<=0`. (Also exactly what age-scoring audits need.)
- `domain` → opaque **`domain_label`** (`D1`, `D2`, … assigned in first-seen order over the account list).
- per-account identity → opaque **`id`** (`a1`, `a2`, … by account index in the sanitized order).
- hash-sharing → opaque **`reuse_group`** (`g1`, `g2`, … one per distinct non-empty NT-hash that is
  shared by ≥2 accounts; accounts not in any shared group have `reuse_group: ""`). The hash itself is
  never emitted — only the grouping. (Reuse key matches the engine: upper-cased NT hash, excluding the
  empty-password hash, same rule as `model.reuseKey`.)
- `similar_peers[].username` → that peer's opaque **`id`** within this report (peers in the same domain
  resolve to an emitted account; a peer not present in the set is dropped).

Opaque tokens are **ephemeral** — assigned per export, mapped to no persisted decoder. Findings are
expected to be about logic/patterns; a genuinely anomalous row is locatable in the UI by its
distinctive scoring attributes.

## 3. Output shape
```jsonc
{
  "schema_version": 1,
  "generated_at": "2026-06-23T05:50:00Z",   // RFC3339 UTC; no audit name
  "tool_version": "v2.24.0",                  // git-describe stamp
  "summary": { /* model.Summary verbatim — all aggregate, non-identifying */ },
  "domains": [ { "label": "D1", "account_count": 51, "risk_level": "High" } ],
  "accounts": [ {
     "id": "a7", "domain_label": "D2", "reuse_group": "g3",
     "cracked": true, "password_length": 11, "complexity": "loweralphanum",
     "risk_level": "High", "risk_score": 6.5, "risk_vector": "C:C1/...RO:A.../IMP:U",
     "exposure_score": 4.3, "impact_score": null, "impact_known": false, "percentile": 0.6,
     "hibp_breached": true, "hibp_breach_count": 355,
     "shared_with": 119, "escalated_by_shared_da": true,
     "has_da_path": false, "controlled_object_count": 0, "controls_tier0": false,
     "enabled": true, "coverage": "none",
     "meets_policy": false, "policy_violations": ["Length < 14"],
     "is_common": false, "is_dictionary_word": false, "banned_word_count": 1,
     "keyboard_pattern_count": 0, "contains_unicode": false,
     "password_age_days": 853, "pwd_never_expires": true, "days_out_of_compliance": 0,
     "has_spn": false, "dont_req_preauth": true,
     "similarity_score": 0.91, "similar_peers": [ { "id": "a9", "score": 0.91 } ],
     "score_breakdown": { /* model.ScoreBreakdown verbatim — all numeric, non-identifying */ }
  } ]
}
```
`impact_score` is `null` when `impact_known` is false (mirrors `model.Account.ImpactScore *float64`).
`pwd_never_expires` / `has_spn` / `dont_req_preauth` are `*bool` (omit/null when unknown), matching the
source. `score_breakdown` and `summary` are reused verbatim — both are already entirely numeric/aggregate.

### `domains[]` aggregate
One entry per `domain_label`: `account_count` (rows in that domain) and `risk_level` — the domain's
risk level. (`model.Account` doesn't store the per-account domain risk level today; it is carried in
the risk vector as the `DR:` token. The aggregate `risk_level` is the **most common** account
`risk_level` within the domain — a descriptive rollup, not a new scoring field. If that proves
unhelpful during implementation, fall back to omitting `risk_level` and keeping `account_count` only;
the spec's hard requirement is the per-domain account counts, the label, and zero domain names.)

## 4. Architecture / where it lives
- **`internal/report/sanitize.go`** (new): the output structs + a pure builder
  `Sanitize(accounts []model.Account, summary model.Summary, now time.Time, version string) SanitizedReport`
  and `SanitizedJSON(w io.Writer, accounts []model.Account, summary model.Summary, now time.Time, version string) error`
  (builds + `json.NewEncoder(w).SetIndent` + encode). Pure, no HTTP/store coupling — fully unit-testable.
  Mirrors the existing `report.CSV` / `report.HTML` entry-point style.
- **`internal/httpapi`**: `GET /api/export/sanitized.json` handler — same gating as the sibling exports
  (`requireAuth` + `requireUnlocked`), reads the active audit's accounts + computes the summary the same
  way the other export handlers do, sets `Content-Type: application/json` + a
  `Content-Disposition: attachment; filename="…-sanitized.json"`, and **audit-logs** the export
  (`Action: "export_sanitized"`, no account detail) like the other export endpoints.
- **`web/src/components/Reports.tsx`** (or wherever the export buttons live): a download entry
  "Sanitized JSON — for external review" alongside the CSV/HTML exports, hitting the new endpoint.
  `web/src/api.ts` gains the URL/typing if the others are typed there.

The version string is the same `main.version` ldflag stamp surfaced at `/api/version`; the handler
passes the server's known version (already available where `/api/version` is served).

## 5. Files
- **Go:** `internal/report/sanitize.go` (new) + `internal/report/sanitize_test.go` (new);
  `internal/httpapi/server.go` (route + handler) + `internal/httpapi/server_test.go` (handler test).
- **Web:** `web/src/components/Reports.tsx` (download button) + `web/src/api.ts` (export URL, if typed).

No change to `model.Account`, the scoring engine, or any existing export.

## 6. Testing
- **Canary leak test (decisive):** build accounts seeded with unmistakable sensitive values —
  `Username:"CANARY_USER"`, `Domain:"CANARY.CORP"`, `Password:"CANARY_PW"`, `NTHash:"CANARYHASH"`,
  `BannedWords:["CANARYWORD"]`, `KeyboardPatterns:["CANARYKBD"]`, `DADomains:"CANARY.CORP"`,
  `SimilarPeers:[{Username:"CANARY_PEER"}]` — serialize via `SanitizedJSON`, and assert the output bytes
  contain **none** of those literal canary strings (`bytes.Contains` for each). This is the fail-closed
  guarantee.
- **Transforms:** `has_da_path` true iff `HasDAPathway()`; `password_age_days` computed from
  `pwd_last_set` (and `0` when unset); `domain_label`/`id`/`reuse_group` are opaque (`D#`/`a#`/`g#`).
- **Structure:** two accounts sharing an NT hash get the **same** non-empty `reuse_group`; an account
  with no shared hash gets `""`; a `similar_peers` entry resolves to the opaque `id` of the peer row
  (and is dropped if the peer isn't in the set). Same domain → same `domain_label`.
- **Summary/breakdown:** carried through verbatim and present.
- **Handler:** `GET /api/export/sanitized.json` on a seeded unlocked audit returns 200,
  `application/json`, a parseable body with `accounts`/`summary`, and writes one audit-log event;
  unauth/locked is rejected like the sibling exports.
- **Gates:** `gofmt -l cmd internal`, `go build/vet/test ./...`, `govulncheck`; web `tsc`/`vitest`/`build`.

## 7. Definition of done
A lead can download a `…-sanitized.json` from the Reports tab (and `GET /api/export/sanitized.json`)
that contains every per-account scoring signal + the audit aggregates with opaque structure preserved,
and provably **no** usernames, domain names, hashes, cleartext, matched wordlist substrings, DA domain
names, raw password-set timestamps, or audit name. The export is audit-logged. The scoring engine and
existing exports are unchanged.
