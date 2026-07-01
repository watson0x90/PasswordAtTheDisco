import type { Account, Report } from "../api"
import { exposureHeadline } from "../exposure"
import { useNav } from "../nav"
import type { ExposureHeadline as BundleHeadline } from "../metricsBundle"

export function ExposureHeadline({ accounts, report, headline }: { accounts: Account[]; report: Report | null; headline?: BundleHeadline }) {
  const nav = useNav()

  // When the bundle headline is provided (org path), use pre-computed server values.
  // Otherwise fall back to client-side compute (per-domain path needs a report present).
  let h: { crackedDA: number; crackedHibp: number; crossDomainGroups: number; domainsSpanned: number }
  if (headline) {
    h = {
      crackedDA: headline.cracked_da,
      crackedHibp: headline.cracked_hibp,
      crossDomainGroups: headline.cross_domain_groups,
      domainsSpanned: headline.domains_spanned,
    }
  } else {
    if (!report) return null
    h = exposureHeadline(accounts, report)
  }

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
