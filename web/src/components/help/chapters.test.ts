import { describe, it, expect } from "vitest"
import { CHAPTERS, chapterBySlug, type ChapterId } from "./chapters"

describe("CHAPTERS registry", () => {
  it("has exactly 5 entries in the intended order", () => {
    expect(CHAPTERS.map((c) => c.id)).toEqual([
      "thesis",
      "scoring",
      "pipeline",
      "security",
      "glossary",
    ])
  })

  it("maps each chapter to its intended slug", () => {
    expect(CHAPTERS.map((c) => c.slug)).toEqual([
      "why-this-exists",
      "how-we-score",
      "enrichment",
      "security-privacy",
      "glossary-faq",
    ])
  })

  it("gives every chapter a non-empty label", () => {
    for (const c of CHAPTERS) {
      expect(c.label.length).toBeGreaterThan(0)
    }
  })

  it("has unique ids", () => {
    const ids = CHAPTERS.map((c) => c.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it("has unique slugs", () => {
    const slugs = CHAPTERS.map((c) => c.slug)
    expect(new Set(slugs).size).toBe(slugs.length)
  })

  it("resolves a known slug to its id", () => {
    expect(chapterBySlug("how-we-score")).toBe<ChapterId>("scoring")
    expect(chapterBySlug("glossary-faq")).toBe<ChapterId>("glossary")
  })

  it("returns undefined for an unknown slug", () => {
    expect(chapterBySlug("nope")).toBeUndefined()
    expect(chapterBySlug("")).toBeUndefined()
  })
})
