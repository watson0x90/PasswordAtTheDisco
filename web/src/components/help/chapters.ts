// Pure chapter registry for the Help / Methodology surface.
//
// Data-only (no React) so it is trivially unit-testable. Each chapter is a
// stable `id` (used in code + component state), a URL `slug` (used in the
// `#help/<slug>` deep-link), and a human `label` for the sub-nav.
//
// Component wiring lands in later tasks (T2–T5); this registry stays the single
// source of truth for chapter order, ids and slugs.

export type ChapterId = "thesis" | "scoring" | "pipeline" | "security" | "glossary"

export interface Chapter {
  id: ChapterId
  slug: string
  label: string
}

export const CHAPTERS: readonly Chapter[] = [
  { id: "thesis", slug: "why-this-exists", label: "Why this exists" },
  { id: "scoring", slug: "how-we-score", label: "How we score risk" },
  { id: "pipeline", slug: "enrichment", label: "The enrichment pipeline" },
  { id: "security", slug: "security-privacy", label: "Security & privacy" },
  { id: "glossary", slug: "glossary-faq", label: "Glossary & FAQ" },
] as const

// chapterBySlug resolves a URL slug to its chapter id, or undefined when the
// slug is not one of the registered chapters.
export function chapterBySlug(slug: string): ChapterId | undefined {
  return CHAPTERS.find((c) => c.slug === slug)?.id
}
