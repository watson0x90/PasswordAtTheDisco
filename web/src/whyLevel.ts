import type { Account } from "./api"
import { hasDA } from "./util"

// tierName mirrors the Go risk tierOf thresholds (display-only; not byte-pinned to Go).
function tierName(v: number): string {
  if (v >= 8) return "Critical"
  if (v >= 6) return "High"
  if (v >= 4) return "Medium"
  return "Low"
}

function impactTierLabel(a: Account): string {
  return a.impact_score == null ? "Unknown" : tierName(a.impact_score)
}

function exposureDriver(a: Account): string {
  if (a.hibp_breached) return `Exposure is floored — the password appears in ${a.hibp_breach_count.toLocaleString()} public breaches (HIBP).`
  if (a.cracked) return `Exposure is floored because the password was cracked.`
  if ((a.shared_with ?? 0) >= 50) return `Exposure is floored by a large reuse cluster — ${a.shared_with} other accounts share this password.`
  return `Exposure is ${tierName(a.exposure_score)} (${a.exposure_score.toFixed(1)}/10).`
}

// explainLevel returns ordered plain-English lines deriving the account's level. Line 0
// is the dominant reason (escalation override or the Exposure x Impact matrix cell);
// line 1 adds the dominant Exposure driver for context.
export function explainLevel(a: Account): string[] {
  const lvl = a.risk_level
  const lines: string[] = []
  if (a.escalated_by_shared_da) {
    lines.push(`${lvl} — this account shares a password with a Domain-Admin account; cracking this credential yields Domain Admin.`)
  } else if (hasDA(a.da_domains)) {
    lines.push(`${lvl} — this account has a confirmed Domain-Admin attack path (${a.da_domains}).`)
  } else if (a.controls_tier0) {
    lines.push(`${lvl} — this account controls a Tier-0 / DA-equivalent asset, so Impact is pinned to maximum.`)
  } else if (a.escalated_by_mass_reuse) {
    lines.push(`${lvl} — this account is part of a large cracked password-reuse cluster; cracking one member compromises all of them.`)
  } else {
    lines.push(`${lvl} — derived from Exposure ${tierName(a.exposure_score)} × Impact ${impactTierLabel(a)}.`)
  }
  lines.push(exposureDriver(a))
  return lines
}
