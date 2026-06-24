import { useEffect } from "react"
import type { Account } from "../api"
import { accountFactRows, BreakdownCards, WeakCell } from "./accountFacts"

export { WeakCell }

export function AccountDrawer({ account: a, onClose }: { account: Account; onClose: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose()
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [onClose])

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={`Account ${a.username}`}>
        <div className="drawer-head">
          <span className="drawer-title">{a.username}</span>
          <button className="link-btn" onClick={onClose}>
            close
          </button>
        </div>
        <dl className="drawer-fields">
          {accountFactRows(a).map(([k, v]) => (
            <div className="drawer-row" key={k}>
              <dt>{k}</dt>
              <dd>{v}</dd>
            </div>
          ))}
        </dl>
        <BreakdownCards a={a} />
      </aside>
    </>
  )
}
