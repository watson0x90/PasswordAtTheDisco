import type { Account } from "./api"
import { hasDA } from "./util"

// disabledLatentRisk reports whether a DISABLED account is still dangerous -- it controls a
// Tier-0 asset, has a DA pathway, controls objects, or its hash is reused (>=2 accounts). The
// Impact axis is capped at 2.0 for disabled accounts (they can't authenticate), which can lull
// an operator into ignoring a re-enable / Pass-the-Hash persistence path; this flag surfaces it.
// The >=2 reuse threshold (raised from >0 by the 2026-06-23 panel) cuts badge noise. `?? ""`
// keeps hasDA nil-safe for hand-built objects (the API always sends a da_domains string).
export function disabledLatentRisk(a: Account): boolean {
  return (
    !a.enabled &&
    (a.controls_tier0 === true ||
      hasDA(a.da_domains ?? "") ||
      a.controlled_object_count > 0 ||
      a.shared_with >= 2)
  )
}
