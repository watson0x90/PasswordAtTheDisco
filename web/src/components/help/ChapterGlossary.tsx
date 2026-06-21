import { type ReactNode } from "react"
import { GLOSSARY } from "../../glossary"

// ChapterGlossary — Chapter 5 of the Help / Methodology surface: a plain-language
// glossary plus a short FAQ.
//
// The glossary REUSES the exact strings from web/src/glossary.ts (the same copy
// the dashboard surfaces as InfoTip tooltips) so Help can never disagree with the
// rest of the app. Terms that have no dedicated GLOSSARY key (NT hash / NTLM,
// Kerberoastable, AS-REP-roastable, similarity clusters) are authored locally
// here as static copy.
//
// GLOSSARY is static data (a frozen `as const` record), not an API call — so this
// chapter stays a PURE STATIC surface: no auth, no api, no data providers. A later
// review asserts this.

type Term = { term: string; def: ReactNode; source: "glossary.ts" | "local" }

// Reused straight from glossary.ts (single source of truth with the dashboard).
const REUSED: Term[] = [
  { term: "NTLM / NT-hash exposure", def: GLOSSARY.hibp, source: "glossary.ts" },
  { term: "DA pathway", def: GLOSSARY.da_pathway, source: "glossary.ts" },
  { term: "Controlled objects (blast radius)", def: GLOSSARY.high_controlled, source: "glossary.ts" },
  { term: "Password reuse", def: GLOSSARY.shared_with, source: "glossary.ts" },
  { term: "Exposure (axis)", def: GLOSSARY.exposure_axis, source: "glossary.ts" },
  { term: "Impact (axis)", def: GLOSSARY.impact_axis, source: "glossary.ts" },
  { term: "Coverage", def: GLOSSARY.coverage, source: "glossary.ts" },
]

// Authored here — no dedicated glossary.ts key for these.
const LOCAL: Term[] = [
  {
    term: "NT hash / NTLM",
    def: "The unsalted MD4 hash Windows stores for a password (the NT hash) and the NTLM authentication scheme built on it. Because it is unsalted, two accounts with the same password have the same NT hash — which is how reuse and breach matching are detected without ever seeing the cleartext.",
    source: "local",
  },
  {
    term: "Kerberoastable",
    def: "An account with a Service Principal Name (SPN) whose Kerberos service ticket can be requested by any domain user and cracked offline. A weak password on a Kerberoastable account is unusually easy to recover, so it nudges Exposure up when known.",
    source: "local",
  },
  {
    term: "AS-REP-roastable",
    def: "An account with Kerberos pre-authentication disabled, letting an attacker request an AS-REP and crack it offline without any valid credentials. Like Kerberoasting, it makes a weak password easier to recover and adds a small Exposure bump.",
    source: "local",
  },
  {
    term: "Similarity clusters",
    def: "Groups of passwords that are not identical but closely related — variations on a base word, a season, or a pattern. Clustering surfaces a shared bad habit even when the exact NT hashes differ, so a whole family of guessable credentials can be addressed at once.",
    source: "local",
  },
]

// Render order interleaves reused + local into one alphabetically-sensible flow.
const TERMS: Term[] = [
  LOCAL[0], // NT hash / NTLM
  REUSED[0], // NTLM / NT-hash exposure (HIBP)
  REUSED[1], // DA pathway
  REUSED[2], // Controlled objects (blast radius)
  LOCAL[1], // Kerberoastable
  LOCAL[2], // AS-REP-roastable
  REUSED[4], // Exposure
  REUSED[5], // Impact
  REUSED[6], // Coverage
  LOCAL[3], // Similarity clusters
  REUSED[3], // Password reuse
]

type Faq = { q: string; a: ReactNode }

const FAQS: Faq[] = [
  {
    q: "Do you store cracked passwords?",
    a: (
      <>
        No. A recovered password lives <strong>only in process memory</strong> and is never written to disk — no report,
        no cache, no log. It is revealed one account at a time, to a lead, and the audit log records the reveal{" "}
        <strong>without the password</strong>.
      </>
    ),
  },
  {
    q: "What if we don't run BloodHound?",
    a: (
      <>
        Exposure stays <strong>fully valid</strong> — it is computed from the dump and the local HIBP corpus, never from
        BloodHound. Impact is honestly reported as <strong>Unknown</strong> (never &ldquo;low&rdquo;), the Level is marked{" "}
        <em>provisional</em>, and a coverage banner shows exactly how much of the audit has Impact data.
      </>
    ),
  },
  {
    q: "How is a reveal controlled and logged?",
    a: (
      <>
        Reveal is <strong>lead-role-only</strong> and acts on a <strong>single account at a time</strong>. Each reveal is{" "}
        <strong>audit-logged</strong> (who, which account, when) — but the audit log never contains the password. The
        cleartext is shown briefly and auto-hidden; everywhere else accounts stay redacted by default.
      </>
    ),
  },
  {
    q: "Where does the data live?",
    a: (
      <>
        Audit state persists in an <strong>encrypted-at-rest store</strong> (with re-keyable encryption), inside the single
        static binary&rsquo;s footprint. Cleartext credentials are the exception: they exist{" "}
        <strong>only in process memory</strong>, never on disk.
      </>
    ),
  },
]

export function ChapterGlossary() {
  return (
    <div className="help-chapter help-glossary">
      <section className="help-hero help-hero-compact">
        <span className="help-hero-eyebrow">Glossary &amp; FAQ</span>
        <h1 className="help-hero-title">
          The terms behind<span className="help-hero-mark"> the numbers.</span>
        </h1>
        <p className="help-hero-lede">
          Plain-language definitions for the vocabulary the dashboards use — the same wording you&rsquo;ll see in the
          in-app tooltips — followed by the questions reviewers ask most.
        </p>
      </section>

      <section className="gloss-list" aria-label="Glossary of terms">
        <dl className="gloss-dl">
          {TERMS.map((t) => (
            <div key={t.term} className="gloss-item">
              <dt className="gloss-term">
                {t.term}
                <span className={t.source === "glossary.ts" ? "gloss-src reused" : "gloss-src local"}>
                  {t.source === "glossary.ts" ? "in-app tooltip" : "reference"}
                </span>
              </dt>
              <dd className="gloss-def">{t.def}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section className="faq" aria-label="Frequently asked questions">
        <header className="faq-head">
          <span className="faq-eyebrow">FAQ</span>
          <h2 className="faq-title">The four questions reviewers ask first</h2>
        </header>
        <div className="faq-list">
          {FAQS.map((f) => (
            <article key={f.q} className="faq-item">
              <h3 className="faq-q">{f.q}</h3>
              <p className="faq-a">{f.a}</p>
            </article>
          ))}
        </div>
      </section>
    </div>
  )
}
