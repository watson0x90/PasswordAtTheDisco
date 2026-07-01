import { useEffect, useState, type ReactNode } from "react"
import { api, ApiError, type Account, type BreachImpact, type Posture, type Report, type Summary } from "../api"
import { useAuth } from "../auth"
import { useAudits } from "../auditsData"
import { useAccountsData } from "../accountsData"
import { useNav } from "../nav"
import { riskDistribution, hibpSplit, lengthBuckets, kpiCounts } from "../insights"
import { coverageStats, exposureImpactMatrix, isProvisional, TIERS, type ExposureImpactMatrix, type ImpactCol, type Tier } from "../matrix"
import { Bars, ChartCard, Donut, MatrixHeatmap } from "./Charts"
import { ExposureHeadline } from "./ExposureHeadline"
import { Insights } from "./Insights"
import { RecalcControl } from "./RecalcControl"
import { RecalcSuggestion } from "./RecalcSuggestion"
import { useJobs } from "../jobs"
import { InfoTip } from "./InfoTip"
import { GLOSSARY } from "../glossary"
import type { ChartSeries, Graph, Matrix as BundleMatrix } from "../metricsBundle"
import { useMetrics } from "../metricsData"

// Verdict → CSS class suffix (maps to --crit / --high / --med / --low color tokens)
const VERDICT_CLS: Record<string, string> = {
  Critical: "crit",
  "High Risk": "high",
  Elevated: "med",
  Guarded: "low",
  Sound: "low",
  "No Data": "dim",
}

// Hygiene rating → CSS class suffix (rating scale differs from verdict scale)
const RATING_CLS: Record<string, string> = {
  Strong: "low",
  Fair: "high",
  Weak: "crit",
  "No Data": "dim",
}

// Reachability band → CSS class suffix
const REACH_CLS: Record<string, string> = {
  "Very High": "crit",
  High: "crit",
  Medium: "high",
  Low: "low",
  "—": "dim",
}

// bundleMatrixToEI: adapts the MetricsBundle Matrix (Go server output, string-keyed counts)
// to the ExposureImpactMatrix shape expected by MatrixHeatmap. The Go side always emits all
// Tier + "Unknown" column keys, so the cast is safe. matrixMaxCount iterates m.counts and
// produces the same value as bundle.matrix.max (both derive from the same source).
function bundleMatrixToEI(m: BundleMatrix): ExposureImpactMatrix {
  // Go emits Record<Tier, Record<ImpactCol, number>> — same keys, broader TS typing on receipt.
  const counts = m.counts as unknown as Record<Tier, Record<ImpactCol, number>>
  return { counts, total: m.total, cell: (exp, imp) => counts[exp]?.[imp] ?? 0 }
}

export function Dashboard() {
  const nav = useNav()
  const { activeId, audits, loading: auditsLoading, dataVersion } = useAudits()
  const { accounts, error } = useAccountsData()
  // Posture / summary comes from the MetricsBundle (single server fetch) so it
  // never drifts from the score the heatmap and coverage banner display. The
  // separate api.summary() call is dropped in favour of bundle.summary.
  const { bundle, loading: bundleLoading } = useMetrics()

  const [report, setReport] = useState<Report | null>(null)
  useEffect(() => {
    let alive = true
    api.report().then((r) => alive && setReport(r)).catch(() => {})
    return () => { alive = false }
  }, [activeId, dataVersion])

  if (auditsLoading) return <div className="center-state"><div className="spinner">loading</div></div>
  if (!activeId) {
    if (audits.length > 0) return <div className="center-state"><div className="spinner">opening audit</div></div>
    return <NoAudit />
  }
  if (error && !accounts) return <div className="center-state">{error}</div>
  if (!accounts) return <div className="center-state"><div className="spinner">loading</div></div>
  if (accounts.length === 0) return <GetStarted />

  // Gate on both loading flag and bundle presence: the provider briefly holds a
  // stale bundle across audit switches, so we must not render the org Overview
  // with a cross-audit bundle. When not ready, summary/matrix/coverageEnriched
  // are all undefined and OverviewView falls back to account-computed values.
  const bundleReady = !bundleLoading && bundle !== null
  const summary = bundleReady ? bundle.summary : null

  return (
    <>
      <OverviewView
        accounts={accounts}
        summary={summary}
        report={report}
        matrix={bundleReady ? bundle.matrix : undefined}
        coverageEnriched={bundleReady ? bundle.summary.coverage_enriched : undefined}
        charts={bundleReady ? bundle.charts : undefined}
        reuseGraph={bundleReady ? bundle.reports.reuse_graph : undefined}
        subtitle="Where do we stand? Org-wide posture at a glance."
        actions={
          <>
            <RecalcControl hasScored={!!summary?.generated_at} />
            <button className="btn" onClick={() => nav("reports")}>Reports &amp; export →</button>
          </>
        }
        notice={<RecalcSuggestion />}
      />
      <BackgroundJobsCard />
    </>
  )
}

// OverviewView is the presentational Overview dashboard, shared by the org Dashboard
// (its default render) and the per-domain page (fed domain-scoped accounts/summary/
// report). Its own body derives only from props — no context, no fetching. Org-global
// chrome that DOES need context (the Recalc/Reports buttons, the rescore-suggestion
// banner, the background-jobs card) is injected by the Dashboard wrapper via the
// `actions` and `notice` slots / rendered as siblings, so the domain page never shows it.
export function OverviewView({
  accounts,
  summary,
  report,
  title = "Overview",
  subtitle = "Where do we stand? Posture at a glance.",
  actions,
  notice,
  matrix: bundleMatrix,
  coverageEnriched,
  charts,
  reuseGraph,
}: {
  accounts: Account[]
  summary: Summary | null
  report: Report | null
  title?: string
  subtitle?: string
  actions?: ReactNode
  notice?: ReactNode
  // Optional — when provided by the org Dashboard the heatmap, coverage banner,
  // and Impact Unknown count use the server-computed bundle values instead of
  // recomputing from the accounts array. When absent (Domains.tsx per-domain path)
  // the existing account-derived computation is used unchanged.
  matrix?: BundleMatrix
  coverageEnriched?: number
  // When provided (org path), Insights renders chart series from the bundle
  // instead of recomputing client-side. Absent on the per-domain path.
  charts?: ChartSeries
  reuseGraph?: Graph
}) {
  const { total, cracked, breached, da } = kpiCounts(summary, accounts)
  const crackPct = total ? Math.round((cracked / total) * 100) : 0

  // Coverage banner: prefer bundle value (server-computed) when present.
  const cov =
    coverageEnriched !== undefined && bundleMatrix !== undefined
      ? { enriched: coverageEnriched, total: bundleMatrix.total, partial: coverageEnriched < bundleMatrix.total }
      : coverageStats(accounts)

  // Exposure × Impact matrix: prefer bundle (Go server) when present; fall back to
  // client-side compute for the per-domain path (Domains.tsx passes no bundleMatrix).
  const eiMatrix: ExposureImpactMatrix = bundleMatrix
    ? bundleMatrixToEI(bundleMatrix)
    : exposureImpactMatrix(accounts)

  // Impact Unknown: sum the "Unknown" column from the bundle matrix, or count via
  // isProvisional on the per-domain accounts fallback.
  const impactUnknown = bundleMatrix
    ? TIERS.reduce((sum, tier) => sum + ((bundleMatrix.counts[tier] as Record<string, number>)["Unknown"] ?? 0), 0)
    : accounts.filter(isProvisional).length

  return (
    <>
      <div className="view-head">
        <div className="section-label">{title}</div>
        <div className="export-actions">
          {summary?.generated_at && <span className="muted data-ts">Data scored {new Date(summary.generated_at).toLocaleString()}</span>}
          {actions}
        </div>
      </div>
      <div className="view-sub">{subtitle}</div>
      {cov.partial && (
        <div className="coverage-banner" role="status">
          <span className="coverage-banner-dot" aria-hidden="true" />
          <span className="coverage-banner-text">
            <b>BloodHound: {cov.enriched}/{cov.total} accounts enriched</b> — Impact is Unknown for the rest.
          </span>
          <InfoTip text={GLOSSARY.coverage} />
        </div>
      )}
      {notice}
      <div className="stat-grid">
        <Stat label="Accounts" value={total} delay={0} />
        <Stat label="Cracked" value={cracked} sub={`${crackPct}% of accounts`} delay={0.06} />
        <Stat label="HIBP Breached" value={breached} tip={GLOSSARY.hibp} accent delay={0.12} />
        <Stat label="DA Pathways" value={da} tip={GLOSSARY.da_pathway} crit delay={0.18} />
        <Stat label="Impact Unknown" value={impactUnknown} sub="no BloodHound coverage" tip={GLOSSARY.impact_unknown} accent delay={0.24} />
      </div>

      <ExposureHeadline accounts={accounts} report={report} />
      {summary && (
        <div className="stat-grid stat-grid-secondary">
          <Stat label="Disabled" value={summary.disabled_accounts} delay={0} />
          <Stat label="Never Expires" value={summary.never_expires} sub="password set to never expire" delay={0.06} />
          <Stat label="Stale Passwords" value={summary.stale_passwords} sub="past max age policy" accent delay={0.12} />
          <Stat label="Policy Violations" value={summary.policy_violations} sub="cracked & failing policy" accent delay={0.18} />
          <Stat label="Escalated (Shared-DA)" value={summary.escalated_by_shared_da} sub="shares hash with a DA" tip={GLOSSARY.escalated_shared_da} crit delay={0.24} />
          <Stat label="High Privilege" value={summary.high_controlled} sub="controls > 100 objects" tip={GLOSSARY.high_controlled} crit delay={0.3} />
        </div>
      )}

      <div className="section-label">Security Posture</div>
      {summary ? (
        <PostureCard
          posture={summary.posture}
          breachImpact={summary.breach_impact}
          dormantPrivileged={summary.dormant_privileged}
          enabledCount={summary.total_accounts - summary.disabled_accounts}
        />
      ) : (
        <div className="panel"><div className="center-state"><div className="spinner">scoring</div></div></div>
      )}

      <div className="section-label">Exposure × Impact <InfoTip text={GLOSSARY.exposure_impact_matrix} /></div>
      <div className="panel matrix-panel">
        <MatrixHeatmap m={eiMatrix} />
      </div>

      <div className="section-label">Charts</div>
      <div className="chart-grid">
        <ChartCard title="Risk distribution">
          <Donut data={riskDistribution(accounts)} />
        </ChartCard>
        <ChartCard title="HIBP exposure">
          <Donut data={hibpSplit(accounts)} />
        </ChartCard>
        <ChartCard title="Password length (cracked)">
          <Bars data={lengthBuckets(accounts)} color="#818cf8" />
        </ChartCard>
      </div>

      <Insights report={report} accounts={accounts} charts={charts} reuseGraph={reuseGraph} />
    </>
  )
}

// ---- Two-axis executive posture card ----------------------------------------

interface PostureCardProps {
  posture: Posture
  breachImpact: BreachImpact | undefined
  dormantPrivileged: number
  enabledCount: number
}

function PostureCard({ posture: p, breachImpact, dormantPrivileged, enabledCount }: PostureCardProps) {
  const verdictCls = VERDICT_CLS[p.verdict] ?? "dim"
  const reachCls = REACH_CLS[p.reachability] ?? "dim"
  const isGated = p.verdict === "Critical" || p.verdict === "High Risk"

  return (
    <div className="posture-exec-card panel">

      {/* — Verdict headline — */}
      <div className="pex-verdict-row">
        <div className={`pex-verdict c-${verdictCls}`}>
          {p.verdict}
          {p.verdict_reason && (
            <span className="pex-verdict-reason"> — {p.verdict_reason}</span>
          )}
        </div>
        {isGated && (
          <div className="pex-overall-pill">
            Overall {Math.round(p.overall)}/100
            <span className="pex-overall-reason">
              {p.verdict_reason?.includes("Tier-0 controller")
                ? " — capped by reachable Tier-0 path"
                : " — capped by breach reachability"}
            </span>
          </div>
        )}
      </div>

      {/* — Two component readouts — */}
      <div className="pex-axes">
        <div className="pex-axis">
          <div className="pex-axis-label">Credential Hygiene</div>
          <div className="pex-axis-sub">avg password health across enabled accounts (strength, crackability, compliance)</div>
          <div className="pex-axis-value">
            <span className={`pex-axis-score c-${RATING_CLS[p.rating] ?? "dim"}`}>{p.score}</span>
            <span className="pex-axis-of">/100</span>
            <span className="pex-axis-rating">{p.rating}</span>
          </div>
          <div className="pex-axis-footnote">over {enabledCount.toLocaleString()} enabled accounts</div>
        </div>

        <div className="pex-axis-divider" aria-hidden="true" />

        <div className="pex-axis">
          <div className="pex-axis-label">Breach Reachability</div>
          <div className="pex-axis-sub">likelihood ≥1 path to domain-control is exploitable; attack-path driven, modeled upper bound</div>
          <div className="pex-axis-value">
            <span className={`pex-axis-score c-${reachCls}`}>{p.reachability}</span>
            <span className="pex-axis-pct">{p.reachability_pct}</span>
          </div>
          <div className="pex-axis-footnote pex-modeled-tag">modeled upper bound · band only, not a point estimate</div>
        </div>
      </div>

      {/* — Relationship sentence (always) — */}
      <div className="pex-relationship">
        Two independent questions. Credential Hygiene measures the average health of all{" "}
        <em>enabled</em> accounts. Breach Reachability measures whether{" "}
        <em>any single path</em> to domain-control credentials exists — and one is enough.
        A fleet healthy on average can still be fully breachable.
      </div>

      {/* — Gate-reason + priority-action (only when gated) — */}
      {isGated && (
        <div className="pex-gate-block">
          <div className="pex-gate-reason">
            <span className="pex-gate-label">Why the verdict is {p.verdict}:</span>{" "}
            {p.verdict_reason?.includes("Tier-0 controller")
              ? `${p.verdict_reason}. Remediate the Tier-0 foothold to lift the verdict.`
              : p.verdict_reason
                ? `${p.verdict_reason}. Remediate to lift the verdict.`
                : "A reachable path to domain-control exists. Remediate to lift the verdict."}
          </div>
          <div className="pex-action">
            {p.rating === "Strong" || p.rating === "Fair"
              ? <>Remediate the reachable path(s) before the password-reset backlog; hygiene is already {p.rating} — the exposure is structural, not credential-quality.</>
              : <>Both credential hygiene and the reachable domain-control path need remediation — reset weak credentials and close the attack path.</>}
          </div>
        </div>
      )}

      {/* — Dormant privileged line — */}
      {dormantPrivileged > 0 && (
        <div className="pex-dormant">
          <span className="pex-dormant-count c-high">{dormantPrivileged.toLocaleString()}</span>{" "}
          dormant privileged (disabled) account{dormantPrivileged !== 1 ? "s" : ""} —
          pre-compromised credentials that become live if re-enabled.
        </div>
      )}

      {/* — Breach impact block — */}
      {breachImpact && p.verdict !== "No Data" && (
        <div className="pex-impact">
          <div className="pex-impact-label">
            Illustrative breach impact <span className="pex-impact-tag">modeled / illustrative</span>
            <InfoTip text={GLOSSARY.breach_impact} />
          </div>
          <div className="pex-impact-grid">
            <div className="pex-impact-item">
              <div className="pex-impact-k">Breach probability</div>
              <div className={`pex-impact-v breach-${breachImpact.probability.toLowerCase().replace(" ", "-")}`}>
                {breachImpact.probability}
              </div>
              <div className="pex-impact-foot">{breachImpact.probability_pct}</div>
            </div>
            <div className="pex-impact-item">
              <div className="pex-impact-k">Estimated cost</div>
              <div className="pex-impact-v">{breachImpact.estimated_cost}</div>
              <div className="pex-impact-foot">industry avg (IBM CODB)</div>
            </div>
            <div className="pex-impact-item">
              <div className="pex-impact-k">Recovery time</div>
              <div className="pex-impact-v">{breachImpact.recovery_time}</div>
              <div className="pex-impact-foot">to full remediation</div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ---- Background jobs (unchanged) --------------------------------------------

function BackgroundJobsCard() {
  const { me } = useAuth()
  const { enrich, hibp, rescore } = useJobs()
  // Jobs are lead-operated and the provider only polls for leads (non-leads always
  // read idle), so the card has nothing to show for analysts.
  if (me?.role !== "lead") return null
  const enrichLabel =
    !enrich || enrich.phase === "idle" ? "idle"
    : enrich.phase === "running" ? `running ${enrich.processed}/${enrich.total}`
    : enrich.phase === "done" ? `done — enriched ${enrich.enriched}/${enrich.total}`
    : enrich.phase
  const hibpLabel = !hibp || hibp.phase === "idle" ? "idle" : hibp.phase
  const rescoreLabel =
    !rescore || rescore.phase === "idle" ? "idle"
    : rescore.phase === "running" ? `running ${rescore.processed}/${rescore.total}`
    : rescore.phase === "done" ? `done — ${rescore.processed} accounts` : rescore.phase
  return (
    <div className="panel">
      <div className="section-label">Background jobs</div>
      <div className="jobs-card-row"><span>BloodHound enrichment</span><span className="muted">{enrichLabel}</span></div>
      <div className="jobs-card-row"><span>HIBP corpus</span><span className="muted">{hibpLabel}</span></div>
      <div className="jobs-card-row"><span>Re-scoring</span><span className="muted">{rescoreLabel}</span></div>
    </div>
  )
}

// NoAudit is shown when the session has no audit (typically none exist yet).
function NoAudit() {
  const { me } = useAuth()
  const { create } = useAudits()
  const isLead = me?.role === "lead"
  const [name, setName] = useState("")
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState("")

  async function go() {
    if (!name.trim()) return
    setBusy(true)
    setErr("")
    try {
      await create(name.trim())
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "failed to create audit")
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <div className="section-label">Get started</div>
      <div className="panel getstarted">
        <h2 className="gs-title">Create your first audit</h2>
        <p className="gs-sub">
          {isLead
            ? "An audit is a self-contained engagement — its own dataset, scoped views, and findings. Create one to begin (you can run several over time and switch between them up top)."
            : "No audits yet. A lead needs to create one before findings appear."}
        </p>
        {isLead && (
          <div className="audit-create-form gs-create">
            <input
              autoFocus
              className="search"
              placeholder="e.g. Acme Corp — Q2 review"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && go()}
            />
            <button className="btn btn-primary" disabled={busy} onClick={go}>
              Create audit
            </button>
          </div>
        )}
        {err && <div className="error">{err}</div>}
      </div>
    </>
  )
}

function GetStarted() {
  const { me } = useAuth()
  const { active } = useAudits()
  const nav = useNav()
  const isLead = me?.role === "lead"
  return (
    <>
      <div className="section-label">Get started</div>
      <div className="panel getstarted">
        <h2 className="gs-title">Start a password audit</h2>
        <p className="gs-sub">
          {isLead
            ? `No data in ${active ? `“${active.name}”` : "this audit"} yet — follow these steps.`
            : "No data ingested yet. A lead needs to upload credential dumps before findings appear."}
        </p>

        <ol className="gs-steps">
          <li className="gs-step">
            <span className="gs-num">1</span>
            <div className="gs-body">
              <div className="gs-head">
                Configure policies <span className="gs-opt">optional</span>
              </div>
              <div className="gs-text">
                Set per-domain password rules (min length, required classes, max age). They drive the
                “Meets Policy” and max-age compliance signals in scoring.
              </div>
            </div>
            {isLead && (
              <button className="btn gs-action" onClick={() => nav("policies")}>
                Open Policies →
              </button>
            )}
          </li>

          <li className="gs-step gs-current">
            <span className="gs-num">2</span>
            <div className="gs-body">
              <div className="gs-head">Upload credential dumps</div>
              <div className="gs-text">
                Upload the cracked (and optional uncracked) files for a domain. The server parses them,
                correlates against HIBP, scores each account, and ingests — cleartext never touches disk.
              </div>
            </div>
            {isLead && (
              <button className="btn btn-primary gs-action" onClick={() => nav("ingest")}>
                Upload data →
              </button>
            )}
          </li>

          <li className="gs-step">
            <span className="gs-num">3</span>
            <div className="gs-body">
              <div className="gs-head">Review findings</div>
              <div className="gs-text">
                Overview, Accounts, Actionable, and Domains light up once data is ingested.
              </div>
            </div>
          </li>
        </ol>
      </div>
    </>
  )
}

interface StatProps {
  label: string
  value: number
  sub?: string
  tip?: string
  accent?: boolean
  crit?: boolean
  delay: number
}

function Stat({ label, value, sub, tip, accent, crit, delay }: StatProps) {
  const cls = crit ? "stat crit" : accent ? "stat accent" : "stat"
  return (
    <div className={cls} style={{ animationDelay: `${delay}s` }}>
      <div className="stat-label">{label}{tip && <InfoTip text={tip} />}</div>
      <div className="stat-value">{value.toLocaleString()}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  )
}
