import { describe, it, expect } from "vitest"
import { fmtBytes, fmtDuration, fmtWhen, resultClass } from "./format"

describe("fmtBytes", () => {
  it("handles zero and scales across units", () => {
    expect(fmtBytes(0)).toBe("0 B")
    expect(fmtBytes(512)).toBe("512.0 B")
    expect(fmtBytes(1500)).toBe("1.50 KB")
    expect(fmtBytes(53_000_000)).toBe("53.0 MB")
    expect(fmtBytes(74_465_354_267)).toBe("74.5 GB")
  })
})

describe("fmtDuration", () => {
  it("formats compactly, dropping leading zero units", () => {
    expect(fmtDuration(0)).toBe("0s")
    expect(fmtDuration(45)).toBe("45s")
    expect(fmtDuration(125)).toBe("2m 5s")
    expect(fmtDuration(3725)).toBe("1h 2m 5s")
  })
})

describe("fmtWhen", () => {
  it("returns 'never' for empty or invalid input", () => {
    expect(fmtWhen()).toBe("never")
    expect(fmtWhen("")).toBe("never")
    expect(fmtWhen("not-a-date")).toBe("never")
  })
  it("renders a valid ISO timestamp (locale-dependent, just not 'never')", () => {
    expect(fmtWhen("2026-01-01T12:00:00Z")).not.toBe("never")
  })
})

describe("resultClass", () => {
  it("maps results to badge classes", () => {
    expect(resultClass("ok")).toBe("ev-ok")
    expect(resultClass("denied")).toBe("ev-bad")
    expect(resultClass("failed")).toBe("ev-bad")
    expect(resultClass("locked")).toBe("ev-warn")
    expect(resultClass("rate_limited")).toBe("ev-warn")
    expect(resultClass("not_found")).toBe("ev-dim")
  })
})
