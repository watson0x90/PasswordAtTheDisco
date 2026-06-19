import type { Account } from "./api"
import { hasDA } from "./util"
export interface WorklistItem { account: Account; priority: number; reasons: string[]; action: string }
// Ranked remediation worklist: a composite priority (so ties break), human reasons,
// and a recommended action. Derived from the redacted account fields.
export function priorityWorklist(accounts: Account[]): WorklistItem[] {
  const items: WorklistItem[] = []
  for (const a of accounts) {
    const reasons: string[] = []
    let p = 0
    const da = hasDA(a.da_domains)
    if (da) { p += 100; reasons.push("DA path") }
    if (a.escalated_by_shared_da) { p += 50; reasons.push("Shares DA hash") }
    if (a.cracked && a.hibp_breached) { p += 40; reasons.push(`HIBP ${a.hibp_breach_count.toLocaleString()}`) }
    else if (a.cracked) { p += 25; reasons.push("Cracked") }
    if (a.shared_with > 0) { p += Math.min(20, a.shared_with); reasons.push(`Shared ${a.shared_with}`) }
    if (a.pwd_never_expires) { reasons.push("Never expires") }
    if (p === 0) continue
    // tie-break: raw risk (0-10) + a fraction of shared_with
    p += a.risk_score + Math.min(a.shared_with, 5) / 10
    let action = "Review"
    if (da || a.escalated_by_shared_da) action = "Rotate now + review DA path"
    else if (a.cracked && a.hibp_breached) action = "Rotate now — password is public"
    else if (a.cracked) action = "Rotate password"
    else if (a.pwd_never_expires) action = "Enforce expiry"
    items.push({ account: a, priority: p, reasons, action })
  }
  return items.sort((x, y) => y.priority - x.priority)
}
