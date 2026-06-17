import type { Account, Report } from "../api"
import { exposureHeadline } from "../exposure"
import { useNav } from "../nav"

export function ExposureHeadline({ accounts, report }: { accounts: Account[]; report: Report | null }) {
  const nav = useNav()
  if (!report) return null
  const h = exposureHeadline(accounts, report)
  return (
    <div className="exposure-strip">
      <button className="exp-tile crit" onClick={() => nav("exposure")} title="View the blast-radius worklist">
        <div className="exp-n">{h.crackedDA.toLocaleString()}</div>
        <div className="exp-l">Cracked <b>&amp;</b> Domain-Admin path</div>
      </button>
      <button className="exp-tile high" onClick={() => nav("exposure")} title="View HIBP urgency triage">
        <div className="exp-n">{h.crackedHibp.toLocaleString()}</div>
        <div className="exp-l">Cracked <b>&amp;</b> in public breaches</div>
      </button>
      <button className="exp-tile mid" onClick={() => nav("exposure")} title="View cross-domain credential bridges">
        <div className="exp-n">{h.crossDomainGroups.toLocaleString()}</div>
        <div className="exp-l">Passwords shared across domains{h.domainsSpanned ? ` (${h.domainsSpanned} domains)` : ""}</div>
      </button>
    </div>
  )
}
