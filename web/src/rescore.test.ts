import { describe, it, expect, vi, beforeEach } from "vitest"
import { api } from "./api"

// Round-trip test mirroring enrich.test.ts: guards the RescoreJob wire shape so a
// backend field rename surfaces here instead of at runtime. Note RescoreJob has no
// `enriched` field (unlike EnrichJob) -- re-scoring has no per-account enriched count.
describe("rescore api", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn(async () =>
      new Response(JSON.stringify({ phase: "running", processed: 4, total: 12, elapsed_sec: 2, message: "Recomputing scores…" }), {
        status: 200, headers: { "Content-Type": "application/json" },
      }),
    ))
  })
  it("rescoreJob parses status", async () => {
    const st = await api.rescoreJob()
    expect(st.phase).toBe("running")
    expect(st.processed).toBe(4)
    expect(st.total).toBe(12)
    expect(st.elapsed_sec).toBe(2)
    expect(st.message).toBe("Recomputing scores…")
  })
})
