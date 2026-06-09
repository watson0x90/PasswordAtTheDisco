import { useEffect, useRef, useState } from "react"
import { api, ApiError, type PolicyRule } from "../api"
import { useAuth } from "../auth"

const CLASS_FIELDS: [keyof PolicyRule, string][] = [
  ["require_lowercase", "a–z"],
  ["require_uppercase", "A–Z"],
  ["require_digits", "0–9"],
  ["require_special", "!@#"],
]

type Row = { id: number; name: string; rule: PolicyRule }

function PolicyFields({ rule, onChange }: { rule: PolicyRule; onChange: (r: PolicyRule) => void }) {
  const set = (patch: Partial<PolicyRule>) => onChange({ ...rule, ...patch })
  return (
    <div className="policy-fields">
      <label className="pf-num">
        Min length
        <input
          type="number"
          min={1}
          max={256}
          value={rule.min_length}
          onChange={(e) => set({ min_length: Number(e.target.value) })}
        />
      </label>
      <label className="pf-num">
        Max age (days)
        <input
          type="number"
          min={0}
          value={rule.max_password_age_days}
          onChange={(e) => set({ max_password_age_days: Number(e.target.value) })}
        />
      </label>
      <div className="pf-checks">
        {CLASS_FIELDS.map(([k, label]) => (
          <label key={k} className="pf-check">
            <input
              type="checkbox"
              checked={rule[k] as boolean}
              onChange={(e) => set({ [k]: e.target.checked } as Partial<PolicyRule>)}
            />
            {label}
          </label>
        ))}
      </div>
    </div>
  )
}

export function Policies() {
  const { me } = useAuth()
  const [def, setDef] = useState<PolicyRule | null>(null)
  const [rows, setRows] = useState<Row[]>([])
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [okMsg, setOkMsg] = useState("")
  const nextId = useRef(1)

  useEffect(() => {
    api
      .getPolicies()
      .then((p) => {
        setDef(p.default)
        setRows(
          Object.entries(p.domains).map(([name, rule]) => ({ id: nextId.current++, name, rule })),
        )
      })
      .catch((e) => setError(e instanceof ApiError ? e.message : "failed to load policies"))
      .finally(() => setLoading(false))
  }, [])

  if (me?.role !== "lead") return <div className="center-state">Editing policies requires the lead role.</div>
  if (loading) return <div className="center-state"><div className="spinner">loading policies</div></div>
  if (!def) return <div className="center-state">{error || "no policies"}</div>

  const addRow = () => setRows((r) => [...r, { id: nextId.current++, name: "", rule: { ...def } }])
  const removeRow = (id: number) => setRows((r) => r.filter((x) => x.id !== id))
  const patchRow = (id: number, patch: Partial<Row>) =>
    setRows((r) => r.map((x) => (x.id === id ? { ...x, ...patch } : x)))

  async function save() {
    if (!me || !def) return
    const domains: Record<string, PolicyRule> = {}
    for (const row of rows) {
      const name = row.name.trim()
      if (!name) {
        setError("every domain row needs a name")
        return
      }
      domains[name] = row.rule
    }
    setBusy(true)
    setError("")
    setOkMsg("")
    try {
      const r = await api.savePolicies({ default: def, domains }, me.csrf_token)
      setOkMsg(`saved — ${r.domains} domain override(s), persisted to ${r.persisted}`)
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "save failed")
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <div className="section-label">Password Policies</div>
      <div className="panel policy-panel">
        <p className="ingest-note">
          Per-domain policies drive “Meets Policy” and the max-age compliance signal in scoring. The
          default applies to any domain without an override. Saving persists to{" "}
          <code>password_policy.json</code> and applies to the next ingest.
        </p>

        <div className="policy-block">
          <div className="policy-head">
            <span className="policy-name-tag">default</span>
            <span className="action-sub">applies to domains without an override</span>
          </div>
          <PolicyFields rule={def} onChange={setDef} />
        </div>

        {rows.map((row) => (
          <div className="policy-block" key={row.id}>
            <div className="policy-head">
              <input
                className="search policy-domain"
                placeholder="DOMAIN.LOCAL"
                value={row.name}
                spellCheck={false}
                onChange={(e) => patchRow(row.id, { name: e.target.value })}
              />
              <button type="button" className="link-btn" onClick={() => removeRow(row.id)}>
                remove
              </button>
            </div>
            <PolicyFields rule={row.rule} onChange={(r) => patchRow(row.id, { rule: r })} />
          </div>
        ))}

        {error && <div className="error">{error}</div>}
        {okMsg && <div className="ingest-ok">✓ {okMsg}</div>}

        <div className="policy-actions">
          <button type="button" className="btn" onClick={addRow}>
            + Add domain
          </button>
          <button type="button" className="btn btn-primary" onClick={save} disabled={busy}>
            {busy ? "Saving…" : "Save policies"}
          </button>
        </div>
      </div>

      <div className="section-label">Store passphrase</div>
      <ChangePassphrase csrf={me.csrf_token} />
    </>
  )
}

function ChangePassphrase({ csrf }: { csrf: string }) {
  const [oldPass, setOld] = useState("")
  const [newPass, setNew] = useState("")
  const [confirm, setConfirm] = useState("")
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState("")
  const [ok, setOk] = useState(false)

  const MIN = 12

  async function submit() {
    setErr("")
    setOk(false)
    if (newPass.length < MIN) {
      setErr(`new passphrase must be at least ${MIN} characters`)
      return
    }
    if (newPass !== confirm) {
      setErr("new passphrases do not match")
      return
    }
    setBusy(true)
    try {
      await api.changePassphrase(oldPass, newPass, csrf)
      setOk(true)
      setOld("")
      setNew("")
      setConfirm("")
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "change failed")
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="panel ingest-form">
      <p className="ingest-note">
        Rotate the store passphrase (re-wraps the data key; audits are not re-encrypted). The passphrase is
        unrecoverable — there is no reset.
      </p>
      <div className="field">
        <label htmlFor="op">Current passphrase</label>
        <input id="op" type="password" value={oldPass} onChange={(e) => setOld(e.target.value)} />
      </div>
      <div className="field">
        <label htmlFor="np">New passphrase</label>
        <input id="np" type="password" value={newPass} onChange={(e) => setNew(e.target.value)} autoComplete="new-password" />
        <span className="field-hint">at least {MIN} characters</span>
      </div>
      <div className="field">
        <label htmlFor="cp">Confirm new passphrase</label>
        <input id="cp" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />
      </div>
      {err && <div className="error">{err}</div>}
      {ok && <div className="ingest-ok">✓ store passphrase changed</div>}
      <button type="button" className="btn btn-primary" onClick={submit} disabled={busy || !oldPass || !newPass}>
        {busy ? "Changing…" : "Change passphrase"}
      </button>
    </div>
  )
}
