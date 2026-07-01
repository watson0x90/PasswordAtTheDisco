import { useAccountsData } from "../accountsData"
import { useAudits } from "../auditsData"
import type { TierFactorBars } from "../insights"
import { AccountLink } from "./AccountLink"
import { AxisFactorBars, Bars, ChartCard, Donut, HBars, ScatterPlot } from "./Charts"
import { NetworkGraph } from "./NetworkGraph"
import { SimilarityClusters } from "./SimilarityClusters"
import { RISK_CLASS, hasDA } from "../util"
import type { Account } from "../api"
import type { ChartSeries, Graph, TierFactorBars as BundleTierFactorBars } from "../metricsBundle"

// The bundle's TierFactorBars uses impact_known (Go JSON tag) while the insights.ts
// type and Charts.tsx component use impactKnown (camelCase). Normalize at the boundary
// so AxisFactorBars receives exactly what it expects and rendering is identical.
function normalizeTierFactorBars(bars: BundleTierFactorBars[]): TierFactorBars[] {
  return bars.map((b) => ({ ...b, impactKnown: b.impact_known }))
}

// charts is required — both callers gate on bundleReady so the bundle is always
// present when Insights is rendered. accounts is still needed for the SimilarityClusters
// node-click breakdown; reuseGraph is org-only (absent on per-domain path by design).
export function Insights({
  accounts: accountsProp,
  charts,
  reuseGraph,
  similarityGraph,
}: {
  accounts?: Account[]
  charts: ChartSeries
  reuseGraph?: Graph
  similarityGraph?: Graph
}) {
  const { activeId } = useAudits()
  const { accounts: ctxAccounts, error } = useAccountsData()
  const accounts = accountsProp ?? ctxAccounts

  if (!activeId) return <div className="center-state">Select or create an audit to see insights.</div>
  if (error && !accounts) return <div className="center-state">{error}</div>
  if (!accounts) return <div className="center-state"><div className="spinner">loading</div></div>
  if (accounts.length === 0) return <div className="center-state">No data in this audit yet — upload a domain to populate insights.</div>

  // All series come from the Go bundle (server-computed). Parent gates on bundleReady
  // so charts is always present — no client-compute fallbacks remain.
  const scoreBucketsData = charts.score_buckets
  const sharingData = charts.sharing_distribution
  const hibpVsRiskData = charts.hibp_vs_risk
  const complexity = charts.complexity_counts
  const da = charts.da_exposure_by_domain
  const controlledBuckets = charts.controlled_objects_buckets
  const ageBuckets = charts.password_age_buckets
  const simBuckets = charts.similarity_buckets
  // Normalize impact_known → impactKnown for Charts.tsx compatibility
  const axisBars = normalizeTierFactorBars(charts.axis_factor_bars)
  const ageScatter = charts.password_age_scatter
  const expirSlices = charts.expiration_split
  // topRiskiest is server-computed (AccountRef carries enabled/da_domains/hibp_breached).
  const topN = charts.top_riskiest

  return (
    <>
      <div className="section-label">Insights</div>
      <div className="chart-grid">
        <ChartCard title="Risk score distribution">
          <Bars data={scoreBucketsData} color="#818cf8" />
        </ChartCard>
        <ChartCard title="Account sharing">
          <Bars data={sharingData} color="#38bdf8" />
        </ChartCard>
        <ChartCard title="HIBP exposure vs risk">
          <ScatterPlot series={hibpVsRiskData} xLabel="HIBP breach count →" />
        </ChartCard>
      </div>

      <div className="chart-grid">
        <ChartCard title="Password complexity (cracked)">
          {complexity.length ? (
            <HBars data={complexity} color="#22d3ee" />
          ) : (
            <div className="chart-empty">No cracked passwords to classify yet.</div>
          )}
        </ChartCard>
        <ChartCard title="DA pathways by domain">
          {da.length ? (
            <HBars data={da} color="#fb7185" />
          ) : (
            <div className="chart-empty">
              No Domain Admin pathways found — enable BloodHound enrichment at ingest to populate this.
            </div>
          )}
        </ChartCard>
        <ChartCard title="Controlled objects">
          {controlledBuckets.length ? (
            <Bars data={controlledBuckets} color="#fbbf24" />
          ) : (
            <div className="chart-empty">No controlled-object data — run BloodHound enrichment to populate.</div>
          )}
        </ChartCard>
      </div>

      <div className="chart-grid">
        <ChartCard title="Password age">
          {ageBuckets.length ? (
            <Bars data={ageBuckets} color="#a78bfa" />
          ) : (
            <div className="chart-empty">No password-age data — BloodHound enrichment provides PwdLastSet.</div>
          )}
        </ChartCard>
        <ChartCard title="Password similarity (cracked)">
          {simBuckets.length ? (
            <Bars data={simBuckets} color="#f472b6" />
          ) : (
            <div className="chart-empty">No similarity data — computed for domains with ≤ 5000 cracked accounts.</div>
          )}
        </ChartCard>
      </div>

      <div className="chart-grid">
        <ChartCard title="Risk factor contribution by tier">
          {axisBars.length ? (
            <AxisFactorBars data={axisBars} />
          ) : (
            <div className="chart-empty">No score breakdown data — re-ingest or re-enrich to populate.</div>
          )}
        </ChartCard>
        <ChartCard title="Password age vs risk score">
          {ageScatter.length ? (
            <ScatterPlot series={ageScatter} xLabel="Days since password set →" />
          ) : (
            <div className="chart-empty">No password-age data available.</div>
          )}
        </ChartCard>
      </div>

      <div className="chart-grid">
        <ChartCard title="Password expiration status">
          {expirSlices.length > 1 || (expirSlices.length === 1 && expirSlices[0].name !== "Unknown") ? (
            <Donut data={expirSlices} />
          ) : (
            <div className="chart-empty">No expiration data — run BloodHound enrichment to populate.</div>
          )}
        </ChartCard>
        {reuseGraph && (
          <ChartCard title="Cross-domain credential reuse">
            {reuseGraph.nodes.length >= 2 ? (
              <NetworkGraph nodes={reuseGraph.nodes} edges={reuseGraph.edges} />
            ) : (
              <div className="chart-empty">Cross-domain graph requires ≥ 2 domains with shared credentials.</div>
            )}
          </ChartCard>
        )}
      </div>

      {similarityGraph && <SimilarityClusters accounts={accounts} graph={similarityGraph} />}

      <div className="section-label">Top 10 Riskiest Accounts</div>
      <div className="panel">
        <div className="table-wrap">
          <table className="accounts compact">
            <thead>
              <tr>
                <th>#</th>
                <th>Username</th>
                <th>Domain</th>
                <th>Risk</th>
                <th className="num">Score</th>
                <th className="num">HIBP</th>
                <th>DA</th>
                <th className="num">Controlled</th>
              </tr>
            </thead>
            <tbody>
              {topN.map((a, i) => (
                <tr key={`${a.domain}/${a.username}`}>
                  <td className="muted">{i + 1}</td>
                  <td><AccountLink username={a.username} domain={a.domain} />{!a.enabled && <span className="badge-disabled">disabled</span>}</td>
                  <td className="muted">{a.domain}</td>
                  <td><span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span></td>
                  <td className="num">{a.risk_score.toFixed(1)}</td>
                  <td className="num">{a.hibp_breached ? a.hibp_breach_count.toLocaleString() : "—"}</td>
                  <td>{hasDA(a.da_domains) ? <span className="badge crit">{a.da_domains}</span> : "—"}</td>
                  <td className="num">{a.controlled_object_count || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}
