import { useState } from "react"
import type { Account } from "../api"
import { useAccountsData } from "../accountsData"
import { hasDA } from "../util"
import { complexityCounts, hibpSplit, lengthBuckets, posture, riskDistribution } from "../insights"
import { Bars, ChartCard, Donut, HBars, PostureGauge } from "./Charts"

const RATING_COLOR: Record<string, string> = { Strong: "#34d399", Fair: "#fbbf24", Weak: "#fb7185", "No Data": "#8a96b2" }

interface DomainStat {
  domain: string
  total: number
  cracked: number
  breached: number
  critical: number
  da: number
}

export function Domains() {
  const { accounts, error } = useAccountsData()
  const [selected, setSelected] = useState<string | null>(null)

  if (error && !accounts) return <div className="center-state">{error}</div>
  if (!accounts) {
    return (
      <div className="center-state">
        <div className="spinner">loading</div>
      </div>
    )
  }

  if (selected) {
    const domainAccts = accounts.filter((a) => a.domain === selected)
    if (domainAccts.length === 0) {
      setSelected(null)
      return null
    }
    return <DomainDetail domain={selected} accounts={domainAccts} onBack={() => setSelected(null)} />
  }

  const byDomain = new Map<string, DomainStat>()
  for (const a of accounts) {
    let s = byDomain.get(a.domain)
    if (!s) {
      s = { domain: a.domain, total: 0, cracked: 0, breached: 0, critical: 0, da: 0 }
      byDomain.set(a.domain, s)
    }
    s.total++
    if (a.cracked) s.cracked++
    if (a.hibp_breached) s.breached++
    if (a.risk_level === "Critical") s.critical++
    if (hasDA(a.da_domains)) s.da++
  }
  const domains = [...byDomain.values()].sort((a, b) => b.critical - a.critical || b.total - a.total)

  return (
    <>
      <div className="section-label">Domains</div>
      <div className="domain-grid">
        {domains.map((d) => {
          const crackPct = d.total ? Math.round((d.cracked / d.total) * 100) : 0
          return (
            <button className="domain-card domain-card-btn" key={d.domain} onClick={() => setSelected(d.domain)}>
              <div className="domain-card-head">
                <span className="domain-name">{d.domain}</span>
                <span className="domain-pct">{crackPct}% cracked</span>
              </div>
              <div className="domain-stats">
                <DStat label="Accounts" value={d.total} />
                <DStat label="Cracked" value={d.cracked} />
                <DStat label="Breached" value={d.breached} tone="high" />
                <DStat label="Critical" value={d.critical} tone="crit" />
                <DStat label="DA Paths" value={d.da} tone="crit" />
              </div>
              <div className="domain-open">View dashboard →</div>
            </button>
          )
        })}
      </div>
    </>
  )
}

function DomainDetail({ domain, accounts, onBack }: { domain: string; accounts: Account[]; onBack: () => void }) {
  const p = posture(accounts)
  const pColor = RATING_COLOR[p.rating]
  const complexity = complexityCounts(accounts)
  const total = accounts.length
  const cracked = accounts.filter((a) => a.cracked).length
  const breached = accounts.filter((a) => a.hibp_breached).length
  const critical = accounts.filter((a) => a.risk_level === "Critical").length
  const da = accounts.filter((a) => hasDA(a.da_domains)).length

  return (
    <>
      <button className="link-btn domain-back" onClick={onBack}>
        ← All domains
      </button>
      <div className="section-label">{domain}</div>

      <div className="panel posture-panel">
        <div className="posture-gauge-wrap">
          <PostureGauge score={p.score} color={pColor} rating={p.rating} />
        </div>
        <div className="domain-detail-stats">
          <DStat label="Accounts" value={total} />
          <DStat label="Cracked" value={cracked} />
          <DStat label="Breached" value={breached} tone="high" />
          <DStat label="Critical" value={critical} tone="crit" />
          <DStat label="DA Paths" value={da} tone="crit" />
        </div>
      </div>

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

      <div className="chart-grid">
        <ChartCard title="Password complexity (cracked)">
          {complexity.length ? (
            <HBars data={complexity} color="#22d3ee" />
          ) : (
            <div className="chart-empty">No cracked passwords to classify.</div>
          )}
        </ChartCard>
      </div>
    </>
  )
}

function DStat({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="dstat">
      <div className={tone ? `dstat-v c-${tone}` : "dstat-v"}>{value.toLocaleString()}</div>
      <div className="dstat-l">{label}</div>
    </div>
  )
}
