# Release Hardening (pre-v2.22.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Fix the issues the tech-debt + security + math audits surfaced before tagging the "data-freshness / coverage tools" effort: one real correctness gap, two dead-code cleanups + stale comments, the Help scoring-doc drift, and make the Windows AD focus explicit.

**Source of truth:** the 2026-06-22 audit findings (tech-debt sweep + security/math panel over the merged A/C/D/E/B work). The math panel passed the engine ("ship it"); the security panel passed the engine but flagged Help-doc drift; the debt sweep gave exact fixes.

**Branch discipline (every task):** confirm `git branch --show-current` == `feature/release-hardening`; NEVER `git checkout`/`git switch`. Web: NEVER `npm install`/`npm ci`. No `--no-verify`. styleguard: className only.

---

## Task 1: Bidirectional enrich↔rescore mutual-exclusion (HIGH — real correctness/security gap)

Spec A §3.5 required BOTH `/api/rescore` and `/api/enrich` to refuse while the OTHER runs (both `Mutate` the same audit). Only the rescore side was implemented; an MCP token bypasses the UI and could start enrich on a running rescore.

**Files:**
- Modify: `internal/httpapi/server.go` (`handleEnrichStart` ~lines 711-731 — add the rescore-running 409, mirroring how `handleRescoreStart` checks `s.Enrich.Running()`)
- Modify: `web/src/components/BloodHound.tsx` (the "Run enrichment" button `disabled=` at ~line 205)
- Test: the httpapi handler test file (mirror the existing `TestRescoreStart409WhenEnrichRunning`)

- [ ] **Step 1: Write the failing test** — enrich start 409s when a rescore is running. READ the existing `TestRescoreStart409WhenEnrichRunning` in `internal/httpapi/server_test.go` and mirror it with the roles swapped: set `srv.Rescore` + `srv.Engine`, force the rescore into the running phase via its `ActivityHook` gate, then POST `/api/enrich` as lead → expect 409. (Reuse the same `newServer`/`loginCSRF`/`createAudit`/`sendJSON` helpers + the gate pattern.)

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/httpapi/ -run "TestEnrichStart409WhenRescore" -v`
Expected: FAIL — enrich currently starts (200) regardless of a running rescore.

- [ ] **Step 3: Add the guard.** In `handleEnrichStart` (server.go), after the lead check + the `s.Enrich/s.Engine` nil/HasEnricher checks and after `activeAudit` resolves, before `s.Enrich.Start(auditID)`, add:
```go
	if s.Rescore != nil && s.Rescore.Running() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "re-scoring in progress; run enrichment after it finishes"})
		return
	}
```
(`rescore.Manager.Running()` already exists. Place it parallel to how `handleRescoreStart` checks `s.Enrich.Running()`.)

- [ ] **Step 4: Disable the enrich button during a rescore.** In `web/src/components/BloodHound.tsx`, the `useJobs()` destructure (~line 11) currently pulls `{ enrich: enrichJob, refresh }` — add `rescore`. Change the "Run enrichment" button (~line 205) `disabled={enrichJob?.phase === "running" || !status?.active}` to also include `|| rescore?.phase === "running"`. (Optional: a short hint "re-scoring in progress" when so.)

- [ ] **Step 5: Run to verify pass**

Run: `go test ./internal/httpapi/ -v` → PASS (new test + existing rescore-409 test both green)
Run: `cd web && npx tsc --noEmit` → clean

- [ ] **Step 6: Commit**

```bash
test "$(git branch --show-current)" = "feature/release-hardening"
git add internal/httpapi/server.go internal/httpapi/server_test.go web/src/components/BloodHound.tsx
git commit -m "fix(api): enrich refuses (409) while a rescore runs + UI disables it (bidirectional A §3.5)"
```

---

## Task 2: Dead-code + stale-comment cleanups (MED/LOW)

**Files:**
- Modify: `internal/engine/engine.go` (delete `hibpCount` wrapper ~lines 498-503 — zero callers after the D `freshHIBP` migration)
- Modify: `web/src/components/RecalcControl.tsx` (delete the unreachable duplicate `if (me?.role !== "lead") return null` at ~line 36; the `if (!isLead) return null` above it already covers it)
- Modify: `internal/model/model.go` (`IngestEvent.Kind` comment ~line 447 — add `"rescore"` to the listed kinds)
- Modify: `web/src/coverage.ts` (`coverageWhy` doc ~line 17 — it says "an 'enrich' ingest event exists" but the only caller derives `enrichRan` from `accounts.some(coverage==="full")`; reword to "whether enrichment has run on this audit")

- [ ] **Step 1: Confirm no callers, then delete `hibpCount`.** Grep `\.hibpCount(` across the repo — expect only the definition. Delete the wrapper func (engine.go). (`freshHIBP` is the only HIBP accessor now.)

- [ ] **Step 2: Delete the duplicate RecalcControl guard.** In `RecalcControl.tsx`, remove the line `if (me?.role !== "lead") return null` that sits right after `if (!isLead) return null` (keep ONE; `isLead` is `me?.role === "lead"`).

- [ ] **Step 3: Fix the two stale comments** (model.go `IngestEvent.Kind` add `rescore`; coverage.ts `coverageWhy` doc).

- [ ] **Step 4: Verify + commit**

Run: `gofmt -l cmd internal && go build ./... && go vet ./... && go test ./internal/engine/ ./internal/model/` → clean/green
Run: `cd web && npx tsc --noEmit && npx vitest run` → clean + green
```bash
test "$(git branch --show-current)" = "feature/release-hardening"
git add internal/engine/engine.go web/src/components/RecalcControl.tsx internal/model/model.go web/src/coverage.ts
git commit -m "chore: remove dead hibpCount + duplicate lead-guard; fix stale IngestEvent.Kind/coverageWhy comments"
```

---

## Task 3: Update the Help scoring chapter to match the live model

`web/src/components/help/ChapterScoring.tsx` is what operators are told; it predates C/D and now under-describes the system. The security panel listed exactly what's stale.

**Files:**
- Modify: `web/src/components/help/ChapterScoring.tsx`
- (Possibly) `web/src/components/help/ChapterGlossary.tsx` if it's where a vector-token legend best fits — check both.

- [ ] **Step 1: READ `ChapterScoring.tsx` fully** (and skim `ChapterGlossary.tsx`/the pipeline diagram) to see its current structure + the worked examples.

- [ ] **Step 2: Apply these updates** (match the chapter's existing prose/JSX style; className-only):
  1. **Domain risk:** add to the Impact-axis explanation that a domain's criticality **multiplies Impact by ×1.1 / ×1.2 / ×1.3** (Medium/High/Critical), Exposure untouched, and it has no effect on un-enriched accounts (Impact Unknown).
  2. **Vector-token legend:** add (or extend) a legend covering at least the post-C/D tokens — `T0:` (Y/N — Tier-0 / DA-equivalent control), `RO:` (K=Kerberoast/SPN, A=AS-REP, KA=both, N=none), `DR:` (domain risk C/H/M/L, **or `U` when un-enriched**). If the chapter already lists other tokens (CO:/DA:/HIBP:…), slot these in consistently.
  3. **Triage percentile:** state it is **level-first** (Critical > High > Medium > Low) then an Impact-weighted tiebreak (`0.4·Exposure + 0.6·Impact`), and that it is **no longer derived from the legacy RiskScore** — so a Low-level account can never out-rank a High-level one.
  4. **Shared-DA escalation:** document the flagship signal — an account that **reuses a Domain-Admin's password (same NT hash)** inherits **Impact 10 / Critical**, even uncracked, even cross-domain (the highest-leverage finding the tool produces).
  5. **Fix the Case A worked example:** the HIBP floor for "appears 41,000×" is **8.0**, not 9.0 (the 9.0 floor needs ≥1,000,000). EITHER change the count to ≥1,000,000 OR change the Exposure number to ~8.0 so the example reproduces under the real scorer. (Confirm against `hibpExposureFloor` in `internal/risk/risk.go`.)

- [ ] **Step 3: Verify + commit**

Run: `cd web && npx tsc --noEmit && npx vitest run && npm run build` → clean + green (the help `wrap`/diagram tests must stay green)
```bash
test "$(git branch --show-current)" = "feature/release-hardening"
git add web/src/components/help/
git commit -m "docs(help): scoring chapter matches the live model (domain ×factor, T0:/RO:/DR: legend, level-first percentile, shared-DA escalation, fix Case A)"
```

---

## Task 4: Make the Windows Active Directory password-audit focus explicit

**Files:**
- Modify: `README.md` (the top/intro — state it plainly)
- Modify: the Help intro chapter (`web/src/components/help/` — the first/overview chapter) and/or the login/landing copy (`web/src/components/Login.tsx` tagline)

- [ ] **Step 1: README.** Ensure the README's opening sentence/tagline explicitly says this is a **Windows Active Directory password-security auditing tool** (it currently says "Active Directory password-security auditing tool" — make "Windows Active Directory" explicit and prominent in the first line / the What-is section).

- [ ] **Step 2: In-app.** Add the same framing where a new operator first sees it: the Help overview/intro chapter (read `web/src/components/help/` to find it — likely `ChapterIntro`/`ChapterPipeline` or an overview) and/or the Login screen tagline (the app subtitle is "credential exposure console" — consider adding/adjusting copy to name Windows AD password audits). Keep edits to copy only; className-only; no structural changes.

- [ ] **Step 3: Verify + commit**

Run: `cd web && npx tsc --noEmit && npm run build` → clean
```bash
test "$(git branch --show-current)" = "feature/release-hardening"
git add README.md web/src/components/
git commit -m "docs: state the Windows Active Directory password-audit focus (README + Help/landing)"
```

---

## Task 5: Whole-of-hardening verification

- [ ] **Step 1: Full gates.** `gofmt -l cmd internal && go build ./... && go vet ./... && go test ./...` → green; `govulncheck ./...` → clean; `cd web && npx tsc --noEmit && npx vitest run && npm run build` → clean.
- [ ] **Step 2: Live (build-and-run + Playwright).** Confirm: (a) the Help scoring chapter renders the new content (domain multiplier, token legend, percentile, escalation, corrected Case A); (b) the Windows-AD framing shows on the README/landing/Help intro; (c) with a rescore running, the "Run enrichment" button is disabled and `POST /api/enrich` returns 409; (d) console clean.
- [ ] **Step 3: Report evidence.** No commit; proceed to the final whole-branch review, then finishing-a-development-branch (merge to main), then the v2.22.0 tag + release prep.

---

## Self-Review notes (for the controller)
- **Coverage:** debt #1 (bidirectional guard) → Task 1; debt #2/#3/#4 (dead code + comments) → Task 2; security panel Help-drift items 1-5 → Task 3; the Windows-AD ask → Task 4; verify → Task 5.
- **Type consistency:** Task 1's enrich-guard mirrors the existing rescore-guard pattern (`s.X.Running()`); BloodHound.tsx adds `rescore` to its existing `useJobs()` destructure.
- **No scoring-formula change** in this pass — the math panel passed the engine; this is guards + dead-code + docs only.
