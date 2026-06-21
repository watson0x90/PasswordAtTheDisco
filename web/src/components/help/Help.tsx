import { CHAPTERS } from "./chapters"
import { useChapterHash } from "./useChapterHash"
import { ChapterThesis } from "./ChapterThesis"
import { ChapterScoring } from "./ChapterScoring"
import { ChapterPipeline } from "./ChapterPipeline"
import { ChapterSecurity } from "./ChapterSecurity"
import { ChapterGlossary } from "./ChapterGlossary"
import { Logo } from "../Logo"

// Help / Methodology surface — a PURE STATIC explainer of how the tool works.
// It makes NO authenticated API calls and imports NO data provider (useAuth,
// api, accountsData, …); a later review asserts this. The only thing it renders
// is static copy + diagrams (added in T2–T5).
//
// Mode is driven by `onClose`:
//   - present  → standalone full-screen shell with a brand lockup + "← Back"
//                (reachable pre-auth from Login and while locked from Unlock).
//   - absent   → embedded inside the app shell's <main> (post-auth).

export function Help({ onClose }: { onClose?: () => void }) {
  // Sync the `#help/<slug>` deep-link only in STANDALONE mode (onClose present:
  // the pre-auth/locked screens). Embedded (post-auth) Help must NOT touch the
  // URL hash, else a later reload would re-open the standalone Help shell.
  const [chapter, setChapter] = useChapterHash("thesis", !!onClose)
  const active = CHAPTERS.find((c) => c.id === chapter) ?? CHAPTERS[0]

  const body = (
    <div className="help-shell">
      <nav className="help-nav" aria-label="Help chapters">
        {CHAPTERS.map((c) => (
          <button
            key={c.id}
            type="button"
            className={c.id === chapter ? "help-nav-item active" : "help-nav-item"}
            aria-current={c.id === chapter ? "page" : undefined}
            onClick={() => setChapter(c.id)}
          >
            {c.label}
          </button>
        ))}
      </nav>
      <section className="help-content" aria-live="polite">
        {active.id === "thesis" ? (
          <ChapterThesis />
        ) : active.id === "scoring" ? (
          <ChapterScoring />
        ) : active.id === "pipeline" ? (
          <ChapterPipeline />
        ) : active.id === "security" ? (
          <ChapterSecurity />
        ) : (
          <ChapterGlossary />
        )}
      </section>
    </div>
  )

  if (!onClose) return body

  return (
    <div className="help-standalone">
      <header className="help-topbar">
        <div className="brand">
          <Logo size={28} />
          <span className="word">
            Password<b>!AtTheDisco</b>
          </span>
        </div>
        <button type="button" className="btn help-back" onClick={onClose}>
          ← Back
        </button>
      </header>
      {body}
    </div>
  )
}
