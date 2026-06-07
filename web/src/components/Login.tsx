import { useState, type FormEvent } from "react"
import { useAuth } from "../auth"
import { ApiError } from "../api"
import { Logo } from "./Logo"

export function Login() {
  const { login } = useAuth()
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setError("")
    setBusy(true)
    try {
      await login(username, password)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "login failed")
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={onSubmit}>
        <div className="login-brand">
          <Logo size={34} />
          <span className="word">Password<b>!AtTheDisco</b></span>
        </div>
        <div className="login-tag">credential exposure console</div>

        {error && <div className="error">{error}</div>}

        <div className="field">
          <label htmlFor="u">Operator</label>
          <input
            id="u"
            autoFocus
            autoComplete="username"
            spellCheck={false}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="p">Passphrase</label>
          <input
            id="p"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <button className="btn btn-primary" type="submit" disabled={busy || !username || !password}>
          {busy ? "Authenticating…" : "Sign In"}
        </button>
      </form>
    </div>
  )
}
