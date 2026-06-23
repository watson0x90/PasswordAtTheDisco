# Reuse-floor mid tier (Finding 3) — Design

> Finding 3 of the post-v2.25.0 scoring-audit fixes, deferred during the v2.26.0 batch and now
> picked up. The Exposure reuse-floor has a **cliff at 100**: a credential shared by 50–99 accounts
> gets only the small `reuseBump` (+1.0) and no floor, so a 66-account *uncracked* reuse cluster
> reads ~Exposure 1.5 / **Low**. This adds a lower floor tier so mid-size reuse clusters surface.

## 1. Problem (confirmed against the real 6,069-account sanitized export)
`reuseFloor(sharedWith)` floors Exposure only at `≥100→4.0` and `≥1000→5.0`. Below 100 the floor is
0, so a 50–99 reuse cluster's Exposure comes entirely from the `reuseBump` ceiling (+1.0 at ≥10
copies) plus whatever weakness/HIBP/cracked signal exists. For an **uncracked** mid-size cluster that
is the only signal, so a 66-account cluster lands at ~1.5 Exposure → **Low tier** and hides on the
worklist, despite "crack one hash, own 66 accounts" being a real systemic exposure.

This is the Exposure-axis sibling of Finding 1 (which fixed the *Level* of large **cracked** clusters):
Finding 1 escalates the Level of cracked clusters; Finding 3 raises the Exposure **floor** of *any*
mid-size cluster (crack-status-independent, like the existing 100/1000 tiers).

## 2. Approach
Add one tier to `reuseFloor` in `internal/risk/risk.go`:

```go
func reuseFloor(sharedWith int) float64 {
    switch {
    case sharedWith >= 1000:
        return 5.0
    case sharedWith >= 100:
        return 4.0
    case sharedWith >= 50:
        return 3.0
    default:
        return 0
    }
}
```

No other code changes. The floor is crack-status-independent (same as the existing tiers) and is
applied via `math.Max(floor, reuseFloor(...))` in `exposureScore`, exactly as today.

## 3. The stacking consequence (intended)
`reuseFloor` **stacks** with `reuseBump` by design (documented at `risk.go` reuseBump comment). So a
50–99 cluster of ≥10 copies lands at floor 3.0 + bump 1.0 = **Exposure 4.0 = Medium tier**:

| SharedWith | floor | + bump (≥10) | Exposure | tier   |
|-----------:|------:|-------------:|---------:|--------|
| 49         | 0     | 1.0          | ~1.5     | Low    |
| **50–99**  | **3.0** | 1.0        | **4.0**  | **Medium** |
| 100–999    | 4.0   | 1.0          | 5.0      | Medium/High boundary |
| 1000+      | 5.0   | 1.0          | 6.0      | High   |

Monotonic with the existing tiers. For an **unenriched** account (Coverage="none" → Impact Unknown),
Level = the Exposure tier, so a 50–99 uncracked cluster becomes **Medium level** — the desired fix
(it was Low). For an **enriched low-Impact** account the level matrix still caps it (Medium-Exposure ×
Low-Impact = Low), so honest low-blast-radius accounts are not over-escalated — only Exposure/visibility
and sort order rise. This asymmetry mirrors Finding 1 (cracked needs ≥25 for Medium; latent/uncracked
needs a bigger ≥50 cluster for the same Exposure tier).

**This is Exposure-axis only.** No Impact change, no Level-escalation pass, no new field, no new
endpoint. The 50-tier value (3.0, → Medium after the bump) was explicitly chosen over a gentler 2.5
(→ 3.5, top-of-Low) so mid-size clusters are genuinely triaged, not just nudged.

## 4. Files
- **Go:** `internal/risk/risk.go` — the one `case sharedWith >= 50: return 3.0` line.
  Test: `internal/risk/risk_test.go` — extend `TestReuseFloor` with boundary cases
  (`{49, 0}, {50, 3.0}, {99, 3.0}` inserted before `{100, 4.0}`); the existing monotonicity check
  must still hold. `TestReuseFloorAppliesUncracked` (SharedWith 200) is unaffected.
- **Web (doc only):** `web/src/components/help/ChapterScoring.tsx` — the "Password reuse" bullet
  currently says "a very large cluster (100+ accounts …)"; update to reflect the new mid tier, e.g.
  "a sizeable cluster (50+ accounts sharing one hash) raises a credential's Exposure floor on its own,
  and a very large one (100+/1000+) raises it further". No styleguard-affecting change (prose only).

No change to `reuseBump`, the Impact axis, the level matrix, `EscalateLargeCrackedReuse`, the sanitized
export, or any API/struct. (No sanitized-export field is needed — `reuse_group_size` / the resulting
Exposure already round-trip; the higher floor simply shows up in the existing numbers.)

## 5. Testing
- **Go:** `TestReuseFloor` covers 49→0, 50→3.0, 99→3.0, 100→4.0, 1000→5.0 with the monotonicity
  invariant. Gates: `gofmt -l cmd internal` (empty), `go build/vet/test ./...`, `govulncheck ./...`.
- **Web:** `cd web` → `npx tsc --noEmit`, `npx vitest run`, `npm run build` all green (prose-only edit,
  but verify nothing pins the help copy). NEVER `npm install` on this box.
- **Live:** rebuild (build-and-run skill), restart the long-lived `patd.exe`, re-export the sanitized
  report; confirm a 50–99 uncracked reuse cluster now reads Exposure ~4.0 / Medium (was ~1.5 / Low),
  and a 49-cluster is unchanged. This re-export is the user's verification of Findings 1–3 together.

## 6. Definition of done
A 50–99 reuse cluster floors Exposure at 3.0 (→ 4.0 / Medium with the standard bump), monotonic with
the 100/1000 tiers; the 100-cliff is gone; uncracked mid-size clusters are visible (Medium for
unenriched accounts) while enriched low-Impact accounts stay matrix-capped. Help copy updated. Impact,
Level matrix, and all other scoring untouched. Tag v2.27.0.
