import { useEffect, useState } from "react"
import { CHAPTERS, chapterBySlug, type ChapterId } from "./chapters"

// Lightweight `#help/<slug>` deep-link sync — NOT a router. The active chapter
// is component state; this helper just (a) seeds it from location.hash on mount
// and (b) writes location.hash when it changes, so a chapter is linkable in an
// email. It only ever touches `#help/*` hashes.

const PREFIX = "#help/"

// parseHelpHash returns the chapter id for a `#help/<slug>` hash whose slug is a
// known chapter, else null. Anything that is not exactly `#help/<known-slug>`
// (including `#help`, `#help/`, other routes, or the empty string) yields null.
export function parseHelpHash(hash: string): ChapterId | null {
  if (!hash.startsWith(PREFIX)) return null
  const slug = hash.slice(PREFIX.length)
  return chapterBySlug(slug) ?? null
}

// formatHelpHash renders a chapter id back to its canonical `#help/<slug>` hash.
export function formatHelpHash(id: ChapterId): string {
  const chapter = CHAPTERS.find((c) => c.id === id)
  // id is a ChapterId so chapter is always defined; fall back defensively.
  return PREFIX + (chapter ? chapter.slug : "")
}

// useChapterHash holds the active chapter and keeps it in sync with the URL
// hash. It seeds from location.hash on mount (so a cold `#help/<slug>` URL opens
// on that chapter) and writes location.hash on change, only ever touching
// `#help/*` so it never clobbers an unrelated hash.
export function useChapterHash(initial: ChapterId): [ChapterId, (id: ChapterId) => void] {
  const [chapter, setChapter] = useState<ChapterId>(() => {
    if (typeof location === "undefined") return initial
    return parseHelpHash(location.hash) ?? initial
  })

  useEffect(() => {
    if (typeof location === "undefined") return
    const next = formatHelpHash(chapter)
    if (location.hash !== next) location.hash = next
  }, [chapter])

  return [chapter, setChapter]
}
