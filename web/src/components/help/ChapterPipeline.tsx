import { PipelineFlow } from "./diagrams/PipelineFlow"

// ChapterPipeline — Chapter 3 of the Help / Methodology surface: "The enrichment
// pipeline". Explains how the two enrichment sources feed the scoring model:
//
//   - BloodHound (optional): the Impact signals — DA attack pathways, the TRUE
//     sensitivity-weighted blast radius (controlled-object count, no longer the
//     v1 10-cap), Tier-0 / DA-equivalent control, and roastability exposure.
//   - HIBP (always): the local NTLM breach corpus matched OFFLINE — no hash ever
//     leaves the box (the privacy point).
//   - Graceful degradation: without BloodHound, Exposure is fully valid (dump +
//     HIBP) and Impact is honestly Unknown — ties back to Chapter 2's coverage
//     model. Honest by design.
//
// Wording is deliberately consistent with web/src/glossary.ts and ChapterScoring
// so Help never disagrees with the dashboard tooltips.
//
// PURE STATIC: no auth, no api, no data providers, no dynamic values. Copy + the
// static PipelineFlow diagram only. A later review asserts this.

export function ChapterPipeline() {
  return (
    <div className="help-chapter help-pipeline">
      <section className="help-hero help-hero-compact">
        <span className="help-hero-eyebrow">The pipeline</span>
        <h1 className="help-hero-title">
          Two sources of truth,<span className="help-hero-mark"> joined offline.</span>
        </h1>
        <p className="help-hero-lede">
          A dump tells us how weak a credential is. It can&rsquo;t tell us what that credential reaches. Two enrichment
          sources fill that gap — <strong>HIBP</strong> for public breach exposure and <strong>BloodHound</strong> for
          Active-Directory blast radius — and the model is built so that missing one of them degrades honestly instead of
          silently.
        </p>
      </section>

      {/* The flow diagram — dump → analysis → enrichment → scoring → dashboard. */}
      <PipelineFlow />

      {/* The two enrichment sources, side by side. */}
      <section className="pipe-sources" aria-label="The two enrichment sources">
        <article className="pipe-source bloodhound">
          <header className="pipe-source-head">
            <span className="pipe-source-tag">Optional · feeds Impact</span>
            <h2 className="pipe-source-title">BloodHound</h2>
            <span className="pipe-source-range">Active-Directory blast radius</span>
          </header>
          <p className="pipe-source-lede">
            Where an attacker can go once they hold the credential. BloodHound&rsquo;s graph supplies almost the entire{" "}
            <strong>Impact</strong> axis.
          </p>
          <ul className="pipe-source-list">
            <li>
              <b>Domain-Admin attack pathways</b> — a confirmed, traversable path to Domain Admins maxes Impact; the account
              isn&rsquo;t just weak, it&rsquo;s a route to the top.
            </li>
            <li>
              <b>Controlled-object blast radius</b> — the <strong>true</strong> sensitivity-weighted count of AD objects an
              account controls. We count the real blast radius (a controlled DC counts far more than a controlled user);
              the v1 engine capped this at the first 10 controllables, so a principal controlling thousands of objects read
              the same as one controlling none. That cap is gone.
            </li>
            <li>
              <b>Tier-0 / DA-equivalent control</b> — DCSync rights, the Domain Admins group, AdminSDHolder or KRBTGT are
              treated as DA-equivalent even without a literal shortest path.
            </li>
            <li>
              <b>Roastable exposure</b> — Kerberoastable (SPN) and AS-REP-roastable accounts are easier to attack offline,
              a small, additive Exposure bump when this is known.
            </li>
          </ul>
        </article>

        <article className="pipe-source hibp">
          <header className="pipe-source-head">
            <span className="pipe-source-tag">Always · feeds Exposure</span>
            <h2 className="pipe-source-title">HIBP</h2>
            <span className="pipe-source-range">Public breach prevalence</span>
          </header>
          <p className="pipe-source-lede">
            How exposed the credential already is in public breach corpora — matched against a{" "}
            <strong>local copy of the Have I Been Pwned NTLM index</strong>.
          </p>
          <ul className="pipe-source-list">
            <li>
              <b>Matched offline</b> — the lookup runs against an on-box NTLM breach index. There is no API call.
            </li>
            <li>
              <b>No hash leaves the box</b> — neither a password nor its NT hash is ever sent anywhere; the match is purely
              local, so the audit corpus stays inside your perimeter.
            </li>
            <li>
              <b>Prevalence floors Exposure</b> — a hash seen millions of times in breaches floors Exposure high; it is
              raised in exactly one place, with no double counting.
            </li>
            <li>
              <b>Works even uncracked</b> — an NT hash can match the index without ever recovering the password, so HIBP
              contributes whether or not a credential was cracked.
            </li>
          </ul>
        </article>
      </section>

      {/* Graceful degradation — the honest-by-design story, tied to Chapter 2. */}
      <section className="pipe-degrade" aria-label="Graceful degradation without BloodHound">
        <header className="pipe-degrade-head">
          <span className="pipe-degrade-eyebrow">Honest by design</span>
          <h2 className="pipe-degrade-title">No BloodHound? The model still tells the truth.</h2>
        </header>
        <div className="pipe-degrade-grid">
          <div className="pipe-degrade-card valid">
            <span className="pipe-degrade-k">Exposure stays fully valid</span>
            <p>
              Exposure is computed from the dump and the local HIBP corpus alone — never from BloodHound. With no graph data
              at all, every account still gets a trustworthy Exposure score. Nothing about &ldquo;how weak is this
              credential?&rdquo; depends on enrichment.
            </p>
          </div>
          <div className="pipe-degrade-card unknown">
            <span className="pipe-degrade-k">Impact is honestly Unknown</span>
            <p>
              Without the graph we genuinely don&rsquo;t know the blast radius — so Impact is the explicit{" "}
              <strong>Unknown</strong> state, never a fabricated &ldquo;low.&rdquo; The Level is computed from Exposure
              alone and flagged <em>provisional</em>, and the account is routed to the needs-enrichment worklist.
            </p>
          </div>
          <div className="pipe-degrade-card banner">
            <span className="pipe-degrade-k">The gap is visible</span>
            <p>
              When enrichment is partial, a coverage banner (&ldquo;BloodHound: N/M accounts enriched&rdquo;) shows exactly
              how much of the audit has Impact data — so a provisional result is never mistaken for a complete one. This is
              the same coverage model Chapter&nbsp;2 describes.
            </p>
          </div>
        </div>
      </section>
    </div>
  )
}
