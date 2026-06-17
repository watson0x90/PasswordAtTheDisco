import { describe, it, expect, vi, beforeEach } from "vitest"
import { api } from "./api"

describe("enrich api", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn(async () =>
      new Response(JSON.stringify({ phase: "running", processed: 3, total: 10, enriched: 2, elapsed_sec: 1 }), {
        status: 200, headers: { "Content-Type": "application/json" },
      }),
    ))
  })
  it("enrichJob parses status", async () => {
    const st = await api.enrichJob()
    expect(st.phase).toBe("running")
    expect(st.processed).toBe(3)
    expect(st.total).toBe(10)
  })
})
