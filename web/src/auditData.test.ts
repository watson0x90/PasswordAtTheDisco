import { describe, it, expect } from "vitest"
import { perDomainStatus } from "./auditData"
import type { Account, IngestEvent } from "./api"

const acct = (o: Partial<Account>): Account => ({
  username: "u", domain: "A", cracked: false, password_length: 0, risk_level: "Low",
  risk_score: 0, risk_vector: "", hibp_breached: false, hibp_breach_count: 0,
  da_domains: "None", controlled_object_count: 0, shared_with: 0, enabled: true,
  meets_policy: true, complexity: "", ...o,
})
const ev = (o: Partial<IngestEvent>): IngestEvent => ({ filename: "f", kind: "dump", at: "2026-06-17T00:00:00Z", by: "x", ...o })

describe("perDomainStatus", () => {
  it("counts accounts + cracked per domain", () => {
    const rows = perDomainStatus(
      [acct({ domain: "A", cracked: true }), acct({ domain: "A" }), acct({ domain: "B", cracked: true })],
      [ev({ kind: "dump", domain: "A", at: "2026-06-17T01:00:00Z" }), ev({ kind: "dump", domain: "B", at: "2026-06-17T02:00:00Z" })],
    )
    const a = rows.find((r) => r.domain === "A")!
    expect(a.accounts).toBe(2)
    expect(a.cracked).toBe(1)
  })
  it("enrichment freshness: none / fresh / stale", () => {
    const accts = [acct({ domain: "A" }), acct({ domain: "B" })]
    expect(perDomainStatus(accts, [ev({ kind: "dump", domain: "A", at: "2026-06-17T01:00:00Z" })]).find((r) => r.domain === "A")!.enriched).toBe("none")
    const evs: IngestEvent[] = [
      ev({ kind: "dump", domain: "A", at: "2026-06-17T01:00:00Z" }),
      ev({ kind: "enrich", at: "2026-06-17T03:00:00Z" }),
      ev({ kind: "dump", domain: "B", at: "2026-06-17T05:00:00Z" }),
    ]
    const rows = perDomainStatus(accts, evs)
    expect(rows.find((r) => r.domain === "A")!.enriched).toBe("fresh")
    expect(rows.find((r) => r.domain === "B")!.enriched).toBe("stale")
  })
  it("a domain with accounts but no dump event is 'none' (no load time to compare)", () => {
    const rows = perDomainStatus([acct({ domain: "Z" })], [ev({ kind: "enrich", at: "2026-06-17T03:00:00Z" })])
    expect(rows.find((r) => r.domain === "Z")!.enriched).toBe("none")
  })
})
