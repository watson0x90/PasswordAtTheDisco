import { describe, it, expect } from "vitest"
import { wrap } from "./wrap"

describe("wrap", () => {
  it("wraps a long string into multiple lines, each within max", () => {
    const max = 22
    const text = "Cracked password — process RAM only, never written to disk"
    const lines = wrap(text, max)
    expect(lines.length).toBeGreaterThan(1)
    for (const line of lines) {
      expect(line.length).toBeLessThanOrEqual(max)
    }
  })

  it("never drops a word (regression guard for the truncated 'clusters'/'box' bug)", () => {
    // These captions previously wrapped to 4 lines and the diagrams' .slice(0,3)
    // silently dropped the final word. wrap() must now preserve every word.
    const captions = [
      "Strength, dictionary & keyboard patterns, reuse clusters",
      "Local NTLM index, matched offline — no hash leaves the box",
      "DA pathways, blast radius, Tier-0 control, roastability",
      "NTLM hashes + cracked passwords from the AD secrets dump",
      "Who · what account · when — the password is NEVER logged",
    ]
    for (const text of captions) {
      const inputWords = text.split(" ")
      const outputWords = wrap(text, 22).join(" ").split(" ")
      // Word-for-word equality: nothing dropped, nothing duplicated, order kept.
      expect(outputWords).toEqual(inputWords)
    }
  })

  it("keeps a caption that already fits on one line as a single line", () => {
    expect(wrap("short caption", 22)).toEqual(["short caption"])
    expect(wrap("one", 22)).toEqual(["one"])
  })

  it("does not split a single word that exceeds max (breaks only on spaces)", () => {
    const longWord = "supercalifragilisticexpialidocious"
    expect(wrap(longWord, 10)).toEqual([longWord])
  })

  it("the Analysis caption fits in <=3 lines at the pipeline width (24)", () => {
    const lines = wrap("Strength, dictionary & keyboard patterns, reuse clusters", 24)
    expect(lines.length).toBeLessThanOrEqual(3)
    expect(lines.join(" ")).toContain("clusters")
  })
})
