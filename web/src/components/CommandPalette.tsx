import { useEffect, useMemo, useRef, useState } from "react"
import type { Account } from "../api"
import { useAccountsData } from "../accountsData"
import { useAccountDrawer } from "../accountDrawer"
import { useNav } from "../nav"
import { useAuth } from "../auth"
import { filterAccounts } from "../search"
import { RISK_CLASS } from "../util"
import { ADMIN_ITEMS, SETUP_ITEMS, TABS, type View } from "./AppShell"

type Row =
  | { kind: "account"; account: Account }
  | { kind: "view"; id: View; label: string }

export function CommandPalette() {
  const { accounts } = useAccountsData()
  const { openAccount } = useAccountDrawer()
  const nav = useNav()
  const { me } = useAuth()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState("")
  const [active, setActive] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  // Global ⌘/Ctrl-K toggles the palette; Esc closes.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) {
        e.preventDefault()
        setOpen((v) => !v)
      } else if (e.key === "Escape") {
        setOpen(false)
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [])

  // Reset + focus when opened.
  useEffect(() => {
    if (open) {
      setQuery("")
      setActive(0)
      const id = window.setTimeout(() => inputRef.current?.focus(), 0)
      return () => window.clearTimeout(id)
    }
  }, [open])

  const navItems = useMemo(() => {
    const lead = me?.role === "lead"
    return [...TABS, ...(lead ? [...SETUP_ITEMS, ...ADMIN_ITEMS] : [])]
  }, [me])

  const rows: Row[] = useMemo(() => {
    const q = query.trim().toLowerCase()
    const acctRows: Row[] = filterAccounts(accounts ?? [], query, 8).map((account) => ({ kind: "account", account }))
    const viewRows: Row[] = q
      ? navItems.filter((t) => t.label.toLowerCase().includes(q)).map((t) => ({ kind: "view", id: t.id, label: t.label }))
      : []
    return [...acctRows, ...viewRows]
  }, [accounts, query, navItems])

  useEffect(() => { setActive(0) }, [query])

  function activate(row: Row) {
    setOpen(false)
    if (row.kind === "account") openAccount(row.account)
    else nav(row.id)
  }

  if (!open) return null

  return (
    <div className="cmdk-overlay" onClick={() => setOpen(false)}>
      <div className="cmdk-panel" onClick={(e) => e.stopPropagation()}>
        <input
          ref={inputRef}
          className="cmdk-input"
          placeholder="Search accounts, or jump to a view…"
          value={query}
          spellCheck={false}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") { e.preventDefault(); setActive((i) => Math.min(i + 1, rows.length - 1)) }
            else if (e.key === "ArrowUp") { e.preventDefault(); setActive((i) => Math.max(i - 1, 0)) }
            else if (e.key === "Enter" && rows[active]) { e.preventDefault(); activate(rows[active]) }
          }}
        />
        <div className="cmdk-list">
          {rows.length === 0 ? (
            <div className="cmdk-empty">{query ? "No matches" : "Type to search accounts, or a view name"}</div>
          ) : (
            rows.map((row, i) => (
              <button
                key={row.kind === "account" ? `a/${row.account.domain}/${row.account.username}` : `v/${row.id}`}
                className={i === active ? "cmdk-row active" : "cmdk-row"}
                onMouseEnter={() => setActive(i)}
                onClick={() => activate(row)}
              >
                {row.kind === "account" ? (
                  <>
                    <span className="cmdk-row-main">{row.account.username}</span>
                    <span className="cmdk-row-meta">{row.account.domain}</span>
                    <span className={`badge ${RISK_CLASS[row.account.risk_level] || ""}`}>{row.account.risk_level}</span>
                  </>
                ) : (
                  <>
                    <span className="cmdk-row-main">{row.label}</span>
                    <span className="cmdk-row-meta">view</span>
                  </>
                )}
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
