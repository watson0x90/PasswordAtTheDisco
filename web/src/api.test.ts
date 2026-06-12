import { describe, it, expect, vi, afterEach } from "vitest"
import { auditQuery, api, ApiError } from "./api"

describe("auditQuery", () => {
  it("is empty with no params", () => {
    expect(auditQuery({})).toBe("")
  })
  it("omits empty params", () => {
    expect(auditQuery({ q: "", action: "login" })).toBe("?action=login")
  })
  it("includes and URL-encodes set params", () => {
    const s = auditQuery({ q: "a b", action: "login", result: "ok", from: "2026-06-01", to: "2026-06-02", limit: 50 })
    expect(s.startsWith("?")).toBe(true)
    expect(s).toContain("q=a+b")
    expect(s).toContain("action=login")
    expect(s).toContain("result=ok")
    expect(s).toContain("from=2026-06-01")
    expect(s).toContain("to=2026-06-02")
    expect(s).toContain("limit=50")
  })
})

describe("auditLogCsvUrl", () => {
  it("targets /api with the same filters", () => {
    expect(api.auditLogCsvUrl({})).toBe("/api/audit-log.csv")
    expect(api.auditLogCsvUrl({ action: "reveal_secret" })).toBe("/api/audit-log.csv?action=reveal_secret")
  })
})

describe("request error handling", () => {
  afterEach(() => vi.unstubAllGlobals())

  it("throws an ApiError carrying message + parsed body on non-2xx", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: false,
        status: 409,
        text: async () => JSON.stringify({ error: "boom", output: "build log tail" }),
      })),
    )
    let caught: ApiError | null = null
    try {
      await api.pwnedBuild("csrf")
    } catch (e) {
      caught = e as ApiError
    }
    expect(caught).toBeInstanceOf(ApiError)
    expect(caught?.status).toBe(409)
    expect(caught?.message).toBe("boom")
    expect((caught?.body as { output?: string })?.output).toBe("build log tail")
  })

  it("wraps a network failure as ApiError status 0", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("offline") }))
    await expect(api.me()).rejects.toBeInstanceOf(ApiError)
  })
})
