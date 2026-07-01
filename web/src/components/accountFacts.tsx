import type { ReactNode } from "react"
import type { Account, ScoreBreakdown } from "../api"
import { RISK_CLASS, hasDA, weaknessTags } from "../util"
import { disabledLatentRisk } from "../disabledRisk"
import { impactIsKnown, isProvisional, coverageState } from "../accountFlags"
import { GLOSSARY } from "../glossary"
import { weaknessSubFactors, policyViolationText } from "../drawerFactors"
import { explainLevel } from "../whyLevel"

// WeakCell shows wordlist-weakness badges (common / dictionary / forbidden /
// keyboard). The matched word itself is never shown — only the category.
export function WeakCell({ a }: { a: Account }) {
  const tags = weaknessTags(a)
  if (!tags.length) return <span className="muted">—</span>
  return (
    <span className="wtags" title="password matched a wordlist">
      {tags.map((t) => (
        <span key={t} className="badge wtag">
          {t}
        </span>
      ))}
    </span>
  )
}

function fmtAge(epoch: number | undefined): string {
  if (!epoch || epoch <= 0) return "Unknown"
  const days = Math.floor((Date.now() / 1000 - epoch) / 86400)
  if (days < 1) return "Today"
  if (days < 30) return `${days}d ago`
  if (days < 365) return `${Math.floor(days / 30)}mo ago`
  return `${(days / 365).toFixed(1)}y ago`
}

export function accountFactRows(a: Account): [string, ReactNode][] {
  return [
    ["Domain", a.domain],
    ["Status", a.cracked ? "Cracked" : "Uncracked"],
    ["Risk level", <span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span>],
    ["Exposure", a.exposure_score.toFixed(1)],
    [
      "Impact",
      impactIsKnown(a) ? (
        (a.impact_score as number).toFixed(1)
      ) : (
        <span className="badge-provisional" title={GLOSSARY.impact_unknown}>Unknown</span>
      ),
    ],
    ["Coverage", coverageState(a) === "full" ? "BloodHound-enriched" : "Not enriched"],
    ...(a.percentile != null ? ([["Triage percentile", `${Math.round(a.percentile * 100)}th`]] as [string, ReactNode][]) : []),
    ["Risk score", a.risk_score.toFixed(1)],
    ["Risk vector", <code className="vector">{a.risk_vector || "—"}</code>],
    ["HIBP breaches", a.hibp_breached ? a.hibp_breach_count.toLocaleString() : "—"],
    ["Complexity", a.cracked ? a.complexity : "—"],
    ["Password length", a.cracked ? a.password_length : "—"],
    ["Meets policy", a.cracked ? policyViolationText(a) : "—"],
    [
      "Weaknesses",
      !a.cracked ? "—" : weaknessTags(a).length ? <WeakCell a={a} /> : <span className="muted">none</span>,
    ],
    ...(a.cracked && a.contains_unicode ? ([["Contains Unicode", "Yes ⚠ — non-ASCII characters"]] as [string, ReactNode][]) : []),
    ["Similarity", a.cracked && (a.similarity_score ?? 0) > 0 ? `${((a.similarity_score ?? 0) * 100).toFixed(0)}% match to another password` : "—"],
    ["Shared with", a.shared_with],
    ["DA pathway", hasDA(a.da_domains) ? a.da_domains : "—"],
    ["Controlled objects", a.controlled_object_count],
    ...(a.controls_tier0 ? ([["Controls Tier-0", "Yes ⚠ — DA-equivalent asset"]] as [string, ReactNode][]) : []),
    ["Password last set", fmtAge(a.pwd_last_set)],
    ["Password never expires", a.pwd_never_expires === true ? "Yes ⚠" : a.pwd_never_expires === false ? "No" : "Unknown"],
    ["Days out of compliance", a.days_out_of_compliance ? `${a.days_out_of_compliance}d overdue` : "—"],
    ["Escalated (Shared-DA)", a.escalated_by_shared_da ? "Yes — shares hash with a DA account" : "—"],
    ["Escalated (Mass-reuse)", a.escalated_by_mass_reuse ? "Yes — one crack compromises this whole reuse cluster" : "—"],
    ["Kerberoastable (SPN)", a.has_spn === true ? "Yes ⚠ — offline crackable via TGS" : "No"],
    ["AS-REP roastable", a.dont_req_preauth === true ? "Yes ⚠ — no pre-auth required" : "No"],
    ["Enabled", a.enabled ? "Yes" : "No"],
    ...(disabledLatentRisk(a)
      ? ([["Latent risk", "Disabled ⚠ — re-enable / Pass-the-Hash persistence path"]] as [string, ReactNode][])
      : []),
  ]
}

// BreakdownCard — v2 axis sub-score card (one per axis: Exposure / Impact). Shows the
// axis score and its per-factor contributions. This is the v2 rewrite of the card #C1
// removed; it does NOT resurrect the v1 base/temporal/environmental cards.
// --- risk-vector decode: ties each breakdown factor to the vector segment it sets ---

// parseVector turns "C:C5/L:M/…" into { C: "C5", L: "M", … }.
function parseVector(vec: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const part of (vec || "").split("/")) {
    const i = part.indexOf(":")
    if (i > 0) out[part.slice(0, i)] = part.slice(i + 1)
  }
  return out
}

// factorCodes maps a breakdown factor label (sub-factor "· " prefix stripped) to the
// vector segment key(s) it produces. Weakness / Cracked floor / Age have no segment.
const factorCodes: Record<string, string[]> = {
  Length: ["L"], Complexity: ["C"], Dictionary: ["D"], Similarity: ["SM"],
  Reuse: ["S"], Roastable: ["RO"], "HIBP floor": ["HIBP"],
  Privilege: ["CO", "T0"], "DA path": ["DA"], Domain: ["DR"],
}

const tierName: Record<string, string> = { C: "Critical", H: "High", M: "Medium", L: "Low" }
const tierColor: Record<string, string> = { C: "tc-crit", H: "tc-high", M: "tc-med", L: "tc-low" }
// vectorInputKeys are the per-factor segments (highlighted); EXP/IMP are result tiers.
const vectorInputKeys = new Set(["C", "L", "D", "SM", "S", "RO", "HIBP", "DA", "CO", "T0", "DR"])

// VectorLine renders the full risk vector with the per-factor segments highlighted and
// the EXP/IMP result tiers coloured by severity.
function VectorLine({ vec }: { vec: string }) {
  const parts = (vec || "").split("/").filter(Boolean)
  if (!parts.length) return null
  return (
    <code className="bd-vector">
      {parts.map((part, i) => {
        const ci = part.indexOf(":")
        const k = ci > 0 ? part.slice(0, ci) : part
        const val = ci > 0 ? part.slice(ci + 1) : ""
        const cls = k === "EXP" || k === "IMP"
          ? `bd-vseg-tier ${tierColor[val] || ""}`
          : vectorInputKeys.has(k) ? "bd-vseg-in" : "bd-vseg-dim"
        return (
          <span key={i}>{i > 0 ? "/" : ""}{k}:<span className={cls}>{val}</span></span>
        )
      })}
    </code>
  )
}

function BreakdownCard({
  title, score, tierKey, factors, seg,
}: {
  title: string
  score: string
  tierKey: "EXP" | "IMP"
  factors: [string, number][]
  seg: Record<string, string>
}) {
  const tier = seg[tierKey]
  return (
    <div className="bd-card">
      <div className="bd-card-head">
        <span className="bd-card-title">{title}</span>
        <span className="bd-card-score">
          {score}
          {tier && (
            <span className="bd-card-tier">
              {" → "}
              <span className={`bd-tier ${tierColor[tier] || ""}`}>{tierName[tier] || tier}</span>{" "}
              <span className="bd-code">{tierKey}:{tier}</span>
            </span>
          )}
        </span>
      </div>
      <div className="bd-card-factors">
        {factors.map(([name, value]) => {
          const codes = (factorCodes[name.replace(/^· /, "")] || []).filter((k) => seg[k] != null)
          return (
            <div className="bd-factor" key={name}>
              <span>{name}</span>
              <span className="bd-factor-right">
                {codes.map((k) => <span className="bd-code" key={k}>{k}:{seg[k]}</span>)}
                <span className="mono">{value.toFixed(2)}</span>
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// v2 breakdown reads a.score_breakdown (v2 axis sub-scores). Per D2 every breakdown
// field is omitempty, so a missing key is a legitimate 0 (never "unknown"): the v()
// safe-accessor coalesces undefined → 0. (impact_score null is the only true Unknown
// and is handled separately via impactIsKnown — never coalesced.)
export function BreakdownCards({ a }: { a: Account }) {
  const bd = a.score_breakdown
  if (!bd && !isProvisional(a)) return null
  const v = (k: keyof ScoreBreakdown): number => {
    const x = bd?.[k]
    return typeof x === "number" ? x : 0
  }
  const seg = parseVector(a.risk_vector)
  return (
    <div className="drawer-breakdown">
      <div className="drawer-section-title">Score breakdown · each factor sets a vector segment</div>
      <div className="breakdown-grid">
        {/* Uncracked accounts DO carry a score_breakdown (engine scoreUncracked emits
            one); its weakness sub-scores are 0 (password unknown). The Exposure card
            still gates on `bd`, which is present for them. */}
        {bd && (
          <BreakdownCard
            title="Exposure"
            score={a.exposure_score.toFixed(1)}
            tierKey="EXP"
            seg={seg}
            factors={[
              ["Weakness", v("weakness_score")],
              ...weaknessSubFactors(bd).map(([label, val]) => [`· ${label}`, val] as [string, number]),
              ["HIBP floor", v("hibp_floor")],
              ["Cracked floor", v("cracked_floor")],
              ["Reuse", v("reuse_bump")],
              ["Roastable", v("roastable_bump")],
              ["Age", v("age_penalty")],
            ]}
          />
        )}
        {/* Impact: a known impact with a breakdown gets the factor card; an Unknown
            impact gets the Impact-Unknown panel regardless of whether bd exists, so
            uncracked+unenriched accounts (no bd) still get the "run enrichment" call. */}
        {impactIsKnown(a) ? (
          bd && (
            <BreakdownCard
              title="Impact"
              score={(a.impact_score as number).toFixed(1)}
              tierKey="IMP"
              seg={seg}
              factors={[
                ["Privilege", v("privilege_sub_score")],
                ["DA path", v("da_component")],
                ["Domain", v("domain_modifier")],
              ]}
            />
          )
        ) : (
          <div className="bd-card impact-unknown-card">
            <div className="bd-card-head">
              <span className="bd-card-title">Impact</span>
              <span className="badge-provisional" title={GLOSSARY.impact_unknown}>Unknown</span>
            </div>
            <p className="impact-unknown-note">
              Impact Unknown — this account was not BloodHound-enriched, so its blast
              radius can't be computed. Run enrichment to finalize the level.
            </p>
          </div>
        )}
      </div>
      {bd?.enabled_gated && (
        <p className="bd-note">Impact was gated because the account is disabled in AD.</p>
      )}
      {a.escalated_by_shared_da && (
        <p className="bd-note">Impact forced to 10 — shares a password with a Domain-Admin account.</p>
      )}
      {a.controls_tier0 && (
        <p className="bd-note">Privilege pinned to 10 — controls a Tier-0 / DA-equivalent asset.</p>
      )}
      {a.risk_vector && (
        <div className="bd-vfoot">
          <span className="bd-vfoot-label">Assembled risk vector</span>
          <VectorLine vec={a.risk_vector} />
          <p className="bd-vfoot-note">
            Highlighted segments are the factors above; <span className="bd-tier">EXP / IMP</span> are
            the resulting tiers (= the Exposure / Impact scores). CM (compliance) and EX (expires)
            come from the Active Directory card.
          </p>
        </div>
      )}
    </div>
  )
}

// ── Shared risk-summary pieces (used by BOTH the drawer peek and the full page) ──

const tierWord = (v: number) => (v >= 8 ? "Critical" : v >= 6 ? "High" : v >= 4 ? "Medium" : "Low")
const lvlClass = (level: string) => `lvl-${RISK_CLASS[level] || "low"}`

function Tile({ label, value, sub, level }: { label: string; value: string; sub?: string; level?: string }) {
  return (
    <div className={`stat stat-mini ad-tile${level ? ` ${lvlClass(level)}` : ""}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  )
}

// RiskTiles renders the at-a-glance risk summary (score / exposure / impact / triage)
// so the drawer peek and the full detail page read identically.
export function RiskTiles({ a }: { a: Account }) {
  const impactText = a.impact_score == null ? "Unknown" : a.impact_score.toFixed(1)
  return (
    <div className="ad-tiles">
      <Tile label="Risk score" value={a.risk_score.toFixed(1)} sub={a.risk_level} level={a.risk_level} />
      <Tile label="Exposure" value={a.exposure_score.toFixed(1)} sub={tierWord(a.exposure_score)} />
      <Tile label="Impact" value={impactText} sub={a.coverage === "full" ? "blast radius" : "not enriched"} />
      {a.percentile != null && <Tile label="Triage" value={`${Math.round(a.percentile * 100)}`} sub="percentile" />}
    </div>
  )
}

// WhyCallout renders the plain-English level rationale, accented by risk level.
export function WhyCallout({ a }: { a: Account }) {
  return (
    <section className={`ad-why ${RISK_CLASS[a.risk_level] || ""}`}>
      <div className="ad-why-label">Why this level</div>
      {explainLevel(a).map((line, i) => (
        <p key={i} className={i === 0 ? "ad-why-headline" : "ad-why-detail"}>{line}</p>
      ))}
    </section>
  )
}

// pickFacts selects the rows for a card/section in the given order, dropping empty
// "—" values so curated views stay uncluttered (the full page can show everything).
export function pickFacts(rows: [string, ReactNode][], labels: string[]): [string, ReactNode][] {
  const out: [string, ReactNode][] = []
  for (const label of labels) {
    const row = rows.find(([k]) => k === label)
    if (row && !(typeof row[1] === "string" && row[1].trim() === "—")) out.push(row)
  }
  return out
}
