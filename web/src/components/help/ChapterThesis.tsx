import { RevealFlow } from "./diagrams/RevealFlow"

// ChapterThesis — Chapter 1 of the Help / Methodology surface: "Why this exists".
//
// A confident, executive-credible hero stating the security thesis: the legacy
// Python tool emitted a self-contained HTML report that wrote CLEARTEXT cracked
// passwords to disk; this tool NEVER does. Cleartext lives only in process
// memory and is revealed one account at a time to authorized lead operators,
// with every reveal audit-logged (the log never contains the password).
//
// PURE STATIC: no auth, no api, no data providers, no dynamic values. Just copy
// + the static RevealFlow diagram. A later review asserts this.

export function ChapterThesis() {
  return (
    <div className="help-chapter help-thesis">
      <section className="help-hero">
        <span className="help-hero-eyebrow">The thesis</span>
        <h1 className="help-hero-title">
          A password audit should never write the
          <span className="help-hero-mark"> cracked passwords to disk.</span>
        </h1>
        <p className="help-hero-lede">
          The original Python tool shipped its findings as a self-contained HTML report — and that report wrote{" "}
          <strong>cleartext cracked passwords straight to a file on disk</strong>. Anyone who later found that file
          held a plaintext list of working credentials. This tool was rebuilt, end to end, so that{" "}
          <strong>that file never exists.</strong>
        </p>
      </section>

      <section className="help-contrast" aria-label="Before and after: how cracked passwords are handled">
        <article className="help-contrast-card legacy">
          <header className="help-contrast-head">
            <span className="help-contrast-tag">Legacy · Python report</span>
            <h2 className="help-contrast-title">Cleartext written to disk</h2>
          </header>
          <ul className="help-contrast-list">
            <li>Self-contained HTML report bundled the cracked passwords inline.</li>
            <li>Plaintext credentials persisted to a file — copyable, emailable, leakable.</li>
            <li>No gate on who could open it; no record of who read what.</li>
            <li>Once written, the exposure outlived the engagement.</li>
          </ul>
        </article>

        <div className="help-contrast-arrow" aria-hidden="true">
          <span>→</span>
        </div>

        <article className="help-contrast-card current">
          <header className="help-contrast-head">
            <span className="help-contrast-tag">This tool · Go + React</span>
            <h2 className="help-contrast-title">Cleartext stays in memory</h2>
          </header>
          <ul className="help-contrast-list">
            <li>Cleartext lives only in process memory — it is never written to disk.</li>
            <li>Revealed one account at a time, to authorized lead operators only.</li>
            <li>Every reveal is audit-logged — who, which account, when.</li>
            <li>The audit log never contains the password itself.</li>
          </ul>
        </article>
      </section>

      <RevealFlow />

      <section className="help-pillars" aria-label="The three guarantees">
        <div className="help-pillar">
          <span className="help-pillar-k">In memory only</span>
          <p>No report on disk holds a working password. The cleartext exists only while the process runs.</p>
        </div>
        <div className="help-pillar">
          <span className="help-pillar-k">One reveal, one operator</span>
          <p>Reveal is a deliberate, role-gated action — a lead, a single account, redacted by default everywhere else.</p>
        </div>
        <div className="help-pillar">
          <span className="help-pillar-k">Logged, not leaked</span>
          <p>Every reveal leaves an audit trail of who and what — never the password — so access is accountable.</p>
        </div>
      </section>
    </div>
  )
}
