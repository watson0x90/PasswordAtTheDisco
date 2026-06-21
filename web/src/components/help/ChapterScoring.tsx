import { ExposureImpactGrid } from "./diagrams/ExposureImpactGrid"

// ChapterScoring — Chapter 2 of the Help / Methodology surface: "How we score
// risk". The centerpiece. Explains the SHIPPED two-axis Exposure × Impact model
// (scoring engine v2) in plain language that agrees with glossary.ts, renders the
// static Exposure × Impact matrix diagram, and walks one worked example end to
// end.
//
// Wording is deliberately consistent with web/src/glossary.ts (exposure_axis,
// impact_axis, impact_unknown, coverage, provisional, percentile) so the Help and
// the dashboard tooltips never disagree.
//
// PURE STATIC: no auth, no api, no data providers, no dynamic values. Copy + the
// static ExposureImpactGrid only. A later review asserts this.

export function ChapterScoring() {
  return (
    <div className="help-chapter help-scoring">
      <section className="help-hero help-hero-compact">
        <span className="help-hero-eyebrow">The model</span>
        <h1 className="help-hero-title">
          Two questions, scored<span className="help-hero-mark"> independently.</span>
        </h1>
        <p className="help-hero-lede">
          Every account is rated on two axes that answer two different questions, then combined into one Level.{" "}
          <strong>Exposure</strong> asks how easily the credential is compromised. <strong>Impact</strong> asks what an
          attacker reaches if it is. Keeping them separate is what lets us be honest when we simply don&rsquo;t know the
          blast radius — instead of pretending a number we don&rsquo;t have.
        </p>
      </section>

      {/* The two axes, side by side. */}
      <section className="score-axes" aria-label="The two scoring axes">
        <article className="score-axis exposure">
          <header className="score-axis-head">
            <span className="score-axis-tag">Axis 1</span>
            <h2 className="score-axis-title">Exposure</h2>
            <span className="score-axis-range">0–10 · always computed</span>
          </header>
          <p className="score-axis-lede">
            How easily this credential is compromised — derived from the dump and the local HIBP corpus, so it is{" "}
            <strong>always trustworthy</strong>, with or without BloodHound.
          </p>
          <ul className="score-axis-list">
            <li>
              <b>Crackability / weakness</b> — length, complexity, dictionary and keyboard patterns, each weighed
              independently so a long-but-simple password is no longer let off the hook by its length alone.
            </li>
            <li>
              <b>HIBP breach prevalence</b> — how many times the password&rsquo;s NT hash appears in public breach corpora;
              raised in exactly one place (no double counting).
            </li>
            <li>
              <b>Password reuse</b> — more copies of the same hash means more chances for an attacker.
            </li>
            <li>
              <b>Roastability</b> — Kerberoastable / AS-REP-roastable accounts are easier to attack offline; a small bump
              when known.
            </li>
          </ul>
        </article>

        <article className="score-axis impact">
          <header className="score-axis-head">
            <span className="score-axis-tag">Axis 2</span>
            <h2 className="score-axis-title">Impact</h2>
            <span className="score-axis-range">0–10 · or Unknown</span>
          </header>
          <p className="score-axis-lede">
            The blast radius if this credential is compromised — almost entirely BloodHound-derived. When an account has no
            enrichment, Impact is <strong>Unknown — never &ldquo;low&rdquo;</strong>.
          </p>
          <ul className="score-axis-list">
            <li>
              <b>Privilege / blast radius</b> — the true count of AD objects this account controls, sensitivity-weighted
              (a controlled Domain Controller counts far more than a controlled user).
            </li>
            <li>
              <b>DA reachability</b> — a confirmed traversable Domain-Admin path maxes Impact.
            </li>
            <li>
              <b>Tier-0 / DA-equivalent</b> — control of DCSync rights, the Domain Admins group, AdminSDHolder or KRBTGT
              is treated as DA-equivalent even without a literal shortest path.
            </li>
            <li>
              <b>Enabled state</b> — a disabled account cannot authenticate, so its Impact is capped low.
            </li>
          </ul>
        </article>
      </section>

      {/* The matrix diagram — the centerpiece. */}
      <ExposureImpactGrid />

      {/* Coverage, provisional, percentile. */}
      <section className="score-concepts" aria-label="Coverage, provisional levels, and percentile">
        <div className="score-concept">
          <span className="score-concept-k">Coverage &amp; confidence</span>
          <p>
            The model degrades gracefully. Each account carries a coverage state — enriched by BloodHound, or not. Accounts
            with no coverage get an <strong>Unknown</strong> Impact and a provisional Level, and the dashboard shows a
            coverage banner (&ldquo;BloodHound: N/M accounts enriched&rdquo;) so the gap is visible at a glance.
          </p>
        </div>
        <div className="score-concept">
          <span className="score-concept-k">Provisional levels</span>
          <p>
            When Impact is Unknown, the Level is computed from <strong>Exposure alone</strong> and shown with a
            <em> provisional</em> badge. The account is routed to a &ldquo;needs enrichment&rdquo; worklist — we never claim
            an un-enriched account is low-impact.
          </p>
        </div>
        <div className="score-concept">
          <span className="score-concept-k">Percentile rank</span>
          <p>
            A within-audit triage rank (0–100th) — a <strong>sort key, not a displayed score</strong>. It breaks ties so a
            large block of Critical accounts still has a strict order: which 20 of 500 do you reset first?
          </p>
        </div>
      </section>

      {/* Worked example — walk one account end to end. */}
      <section className="score-example" aria-label="Worked example">
        <header className="score-example-head">
          <span className="score-example-eyebrow">Worked example</span>
          <h2 className="score-example-title">From inputs to Level — two accounts</h2>
          <p className="score-example-sub">
            Illustrative numbers, not live data — to show how the two axes resolve to one Level.
          </p>
        </header>

        <div className="score-example-grid">
          {/* Case A — fully enriched, ends Critical. */}
          <article className="score-case crit">
            <header className="score-case-head">
              <code className="score-case-acct">svc-backup@corp.local</code>
              <span className="score-case-result crit">Critical</span>
            </header>
            <ol className="score-case-steps">
              <li>
                <span className="score-case-step-k">Inputs</span>
                <span className="score-case-step-v">
                  Cracked password, 8 chars, appears 41,000× in HIBP. Enabled. Controls 320 AD objects including a path to
                  Domain Admins.
                </span>
              </li>
              <li>
                <span className="score-case-step-k">Exposure</span>
                <span className="score-case-step-v">
                  Weak + a high HIBP floor → <b>9.0</b> → tier <span className="tier-pill crit">Critical</span>
                </span>
              </li>
              <li>
                <span className="score-case-step-k">Impact</span>
                <span className="score-case-step-v">
                  Confirmed Domain-Admin path → <b>10</b> → tier <span className="tier-pill crit">Critical</span>
                </span>
              </li>
              <li>
                <span className="score-case-step-k">Level</span>
                <span className="score-case-step-v">
                  Exposure Critical × Impact Critical → <b className="c-crit">Critical</b>. The cracked + confirmed-DA hard
                  override would land Critical here on its own.
                </span>
              </li>
            </ol>
          </article>

          {/* Case B — no BloodHound, ends provisional. */}
          <article className="score-case prov">
            <header className="score-case-head">
              <code className="score-case-acct">jsmith@corp.local</code>
              <span className="score-case-result prov">High · provisional</span>
            </header>
            <ol className="score-case-steps">
              <li>
                <span className="score-case-step-k">Inputs</span>
                <span className="score-case-step-v">
                  Cracked password, 7 chars, seen 900× in HIBP. <b>No BloodHound coverage</b> for this account.
                </span>
              </li>
              <li>
                <span className="score-case-step-k">Exposure</span>
                <span className="score-case-step-v">
                  Short + breached → <b>7.0</b> → tier <span className="tier-pill high">High</span>
                </span>
              </li>
              <li>
                <span className="score-case-step-k">Impact</span>
                <span className="score-case-step-v">
                  No enrichment → <span className="tier-pill unknown">Unknown</span> (not &ldquo;low&rdquo;)
                </span>
              </li>
              <li>
                <span className="score-case-step-k">Level</span>
                <span className="score-case-step-v">
                  From Exposure alone → <b className="c-high">High</b>, flagged <em>provisional</em>; routed to the
                  needs-enrichment worklist. Run BloodHound to finalize.
                </span>
              </li>
            </ol>
          </article>
        </div>
      </section>
    </div>
  )
}
