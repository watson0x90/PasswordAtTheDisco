import { useEffect, useState } from "react"
import { CHAPTERS, chapterBySlug, type ChapterId } from "./chapters"

// Lightweight `#help/<slug>` deep-link sync — NOT a router. The active chapter
// is component state; this helper just (a) seeds it from location.hash on mount
// and (b) writes location.hash when it changes, so a chapter is linkable in an
// email. It only ever touches `#help/*` hashes.

const PREFIX = "#help/"

// isHelpHash reports whether a hash addresses the Help surface at all — either
// the bare `#help` or a `#help/<anything>` sub-hash. It is intentionally looser
// than parseHelpHash (which also requires a KNOWN slug): a hash like
// `#help/bogus` still "is a help hash" and should open Help (on the default
// chapter). Crucially it rejects `#helpfoo`, which is NOT a help hash.
export function isHelpHash(hash: string): boolean {
  return hash === "#help" || hash.startsWith(PREFIX)
}

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

// useChapterHash holds the active chapter. When `sync` is true (STANDALONE,
// pre-auth/locked deep-link mode) it keeps the chapter in sync with the URL
// hash: it seeds from location.hash on mount (so a cold `#help/<slug>` URL opens
// on that chapter) and writes location.hash on change, only ever touching
// `#help/*` so it never clobbers an unrelated hash. When `sync` is false
// (EMBEDDED, post-auth — Help rendered inside the app shell) it is a plain
// useState: it never reads OR writes location.hash, so the post-auth Help tab
// does not pollute the URL and a later reload still lands on the app shell.
export function useChapterHash(initial: ChapterId, sync: boolean): [ChapterId, (id: ChapterId) => void] {
  const [chapter, setChapter] = useState<ChapterId>(() => {
    if (!sync || typeof location === "undefined") return initial
    return parseHelpHash(location.hash) ?? initial
  })

  useEffect(() => {
    if (!sync || typeof location === "undefined") return
    const next = formatHelpHash(chapter)
    if (location.hash !== next) location.hash = next
  }, [chapter, sync])

  return [chapter, setChapter]
}
