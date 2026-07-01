import { useNav } from "../nav"
import type { ExposureHeadline as BundleHeadline } from "../metricsBundle"

// headline is required — both callers (org Dashboard and per-domain DomainDetail) pass
// dm.reports.exposure_headline / bundle.reports.exposure_headline from the Go bundle.
export function ExposureHeadline({ headline }: { headline: BundleHeadline }) {
  const nav = useNav()

  const h = {
    crackedDA: headline.cracked_da,
    crackedHibp: headline.cracked_hibp,
    crossDomainGroups: headline.cross_domain_groups,
    domainsSpanned: headline.domains_spanned,
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
