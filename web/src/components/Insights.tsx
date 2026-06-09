import { useAccountsData } from "../accountsData"
import { useAudits } from "../auditsData"
import { complexityCounts, daExposureByDomain, hibpVsRisk, scoreBuckets, sharingDistribution } from "../insights"
import { Bars, ChartCard, HBars, ScatterPlot } from "./Charts"

export function Insights() {
  const { activeId } = useAudits()
  const { accounts, error } = useAccountsData()

  if (!activeId) return <div className="center-state">Select or create an audit to see insights.</div>
  if (error && !accounts) return <div className="center-state">{error}</div>
  if (!accounts) return <div className="center-state"><div className="spinner">loading</div></div>
  if (accounts.length === 0) return <div className="center-state">No data in this audit yet — upload a domain to populate insights.</div>

  const complexity = complexityCounts(accounts)
  const da = daExposureByDomain(accounts)

  return (
    <>
      <div className="section-label">Insights</div>
      <div className="chart-grid">
        <ChartCard title="Risk score distribution">
          <Bars data={scoreBuckets(accounts)} color="#818cf8" />
        </ChartCard>
        <ChartCard title="Account sharing">
          <Bars data={sharingDistribution(accounts)} color="#38bdf8" />
        </ChartCard>
        <ChartCard title="HIBP exposure vs risk">
          <ScatterPlot series={hibpVsRisk(accounts)} xLabel="HIBP breach count →" />
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
      </div>
    </>
  )
}
