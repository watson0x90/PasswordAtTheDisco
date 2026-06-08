import { useState, type FormEvent } from "react"
import { api, ApiError } from "../api"
import { useAuth } from "../auth"
import { Logo } from "./Logo"

export function Unlock() {
  const { me, refresh, logout } = useAuth()
  const firstRun = me ? !me.store_initialized : false
  const isLead = me?.role === "lead"

  const [pass, setPass] = useState("")
  const [confirm, setConfirm] = useState("")
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (!me) return
    if (firstRun && pass !== confirm) {
      setError("passphrases do not match")
      return
    }
    setBusy(true)
    setError("")
    try {
      await api.unlock(pass, me.csrf_token)
      await refresh() // picks up store_unlocked = true
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "unlock failed")
      setBusy(false)
    }
  }

  if (!isLead) {
    return (
      <div className="login-wrap">
        <div className="login-card">
          <div className="login-brand">
            <Logo size={34} />
            <span className="word">
              Password<b>!AtTheDisco</b>
            </span>
          </div>
          <div className="login-tag">data store locked</div>
          <p className="ingest-note">
            The encrypted data store is locked. A <b>lead</b> must unlock it before audits are available.
          </p>
          <div className="unlock-actions">
            <button className="btn" onClick={() => void refresh()}>
              Check again
            </button>
            <button className="btn" onClick={() => void logout()}>
              Sign out
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={onSubmit}>
        <div className="login-brand">
          <Logo size={34} />
          <span className="word">
            Password<b>!AtTheDisco</b>
          </span>
        </div>
        <div className="login-tag">{firstRun ? "set store passphrase" : "unlock data store"}</div>
        <p className="ingest-note">
          {firstRun
            ? "First run: choose a passphrase that encrypts every audit on this server. It is never stored — if you lose it, the data cannot be recovered."
            : "Enter the store passphrase to decrypt this server's audits. It is held only in memory until the server restarts."}
        </p>

        {error && <div className="error">{error}</div>}

        <div className="field">
          <label htmlFor="pp">Passphrase</label>
          <input
            id="pp"
            type="password"
            autoFocus
            value={pass}
            onChange={(e) => setPass(e.target.value)}
            autoComplete={firstRun ? "new-password" : "current-password"}
          />
        </div>
        {firstRun && (
          <div className="field">
            <label htmlFor="pp2">Confirm passphrase</label>
            <input id="pp2" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />
          </div>
        )}

        <button className="btn btn-primary" type="submit" disabled={busy || !pass}>
          {busy ? "Unlocking…" : firstRun ? "Set passphrase & unlock" : "Unlock"}
        </button>
        <button type="button" className="link-btn unlock-signout" onClick={() => void logout()}>
          sign out
        </button>
      </form>
    </div>
  )
}
