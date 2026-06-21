import { describe, it, expect } from "vitest"
import { parseHelpHash, formatHelpHash, isHelpHash } from "./useChapterHash"
import { CHAPTERS } from "./chapters"

describe("isHelpHash", () => {
  it("is true for the bare #help and any #help/<slug>", () => {
    expect(isHelpHash("#help")).toBe(true)
    expect(isHelpHash("#help/how-we-score")).toBe(true)
    // looser than parseHelpHash: an unknown slug still IS a help hash
    expect(isHelpHash("#help/bogus")).toBe(true)
  })

  it("is false for non-help hashes (and the #help prefix typosquat)", () => {
    expect(isHelpHash("#helpfoo")).toBe(false)
    expect(isHelpHash("#nope")).toBe(false)
    expect(isHelpHash("")).toBe(false)
  })
})

describe("parseHelpHash", () => {
  it("parses a known #help/<slug> hash to its chapter id", () => {
    expect(parseHelpHash("#help/how-we-score")).toBe("scoring")
    expect(parseHelpHash("#help/why-this-exists")).toBe("thesis")
  })

  it("returns null for a hash that is not #help/*", () => {
    expect(parseHelpHash("#nope")).toBeNull()
    expect(parseHelpHash("#help")).toBeNull()
    expect(parseHelpHash("#/help/how-we-score")).toBeNull()
  })

  it("returns null for an unknown slug under #help/", () => {
    expect(parseHelpHash("#help/not-a-real-slug")).toBeNull()
  })

  it("returns null for an empty hash", () => {
    expect(parseHelpHash("")).toBeNull()
  })
})

describe("formatHelpHash", () => {
  it("formats a chapter id to #help/<slug>", () => {
    expect(formatHelpHash("security")).toBe("#help/security-privacy")
    expect(formatHelpHash("thesis")).toBe("#help/why-this-exists")
  })
})

describe("round-trip", () => {
  it("parse(format(id)) === id for every chapter", () => {
    for (const c of CHAPTERS) {
      expect(parseHelpHash(formatHelpHash(c.id))).toBe(c.id)
    }
  })
})
