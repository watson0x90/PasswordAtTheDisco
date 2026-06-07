import { useAccountsData } from "../accountsData"
import { hasDA } from "../util"

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

  if (error && !accounts) return <div className="center-state">{error}</div>
  if (!accounts) {
    return (
      <div className="center-state">
        <div className="spinner">loading</div>
      </div>
    )
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
            <div className="domain-card" key={d.domain}>
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
            </div>
          )
        })}
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
