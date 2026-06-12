// Typed client for the Password!AtTheDisco API. Auth is a same-origin session
// cookie (HttpOnly), so every request sends credentials; state-changing requests
// carry the per-session CSRF token in the X-CSRF-Token header.

export type Role = "analyst" | "lead"

export interface Me {
  username: string
  role: Role
  csrf_token: string
  active_audit: string
  store_initialized: boolean
  store_unlocked: boolean
}

export interface AuditMeta {
  id: string
  name: string
  notes?: string
  created_at: string
  updated_at: string
}

export interface AuditListItem extends AuditMeta {
  total_accounts: number
  cracked: number
}

export interface DiffAccount {
  username: string
  domain: string
  risk_a?: string
  risk_b?: string
}

export interface AuditDiff {
  posture_a: number
  posture_b: number
  still_cracked: number
  newly_cracked: DiffAccount[]
  remediated: DiffAccount[]
  newly_breached: DiffAccount[]
  regressed: DiffAccount[]
}

export interface DiffResult {
  a: AuditMeta
  b: AuditMeta
  diff: AuditDiff
}

export interface Posture {
  score: number
  rating: string
  likelihood: string
  breakdown: { risk: number; strength: number; privilege: number; compliance: number }
}

export interface Summary {
  total_accounts: number
  cracked: number
  hibp_breached: number
  da_pathways: number
  risk_counts: Record<string, number>
  posture: Posture
  generated_at: string
}

export interface Account {
  username: string
  domain: string
  cracked: boolean
  password_length: number
  risk_level: string
  risk_score: number
  risk_vector: string
  hibp_breached: boolean
  hibp_breach_count: number
  da_domains: string
  controlled_object_count: number
  shared_with: number
  enabled: boolean
  meets_policy: boolean
  complexity: string
}

export interface PolicyRule {
  min_length: number
  require_lowercase: boolean
  require_uppercase: boolean
  require_digits: boolean
  require_special: boolean
  max_password_age_days: number
}

export interface PoliciesPayload {
  default: PolicyRule
  domains: Record<string, PolicyRule>
}

export class ApiError extends Error {
  status: number
  body: unknown // parsed response body, when present (e.g. build output on a failed build)
  constructor(status: number, message: string, body?: unknown) {
    super(message)
    this.status = status
    this.body = body
    this.name = "ApiError"
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(`/api${path}`, { credentials: "include", ...init })
  } catch {
    throw new ApiError(0, "network error — is the server reachable?")
  }
  const text = await res.text()
  const body = text ? safeParse(text) : null
  if (!res.ok) {
    // 423 = the store auto-locked for inactivity. Broadcast so the app can return
    // to the unlock screen instead of stranding the operator on a raw error.
    if (res.status === 423) {
      window.dispatchEvent(new CustomEvent("patd:locked"))
    }
    let msg = `request failed (${res.status})`
    if (body && typeof body === "object" && "error" in body) {
      const e = (body as { error?: unknown }).error
      if (typeof e === "string" && e) msg = e
    }
    throw new ApiError(res.status, msg, body)
  }
  return body as T
}

function safeParse(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return text
  }
}

export const api = {
  login: (username: string, password: string) =>
    request<Me>("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    }),

  me: () => request<Me>("/me"),

  logout: (csrf: string) =>
    request<{ status: string }>("/logout", {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
    }),

  summary: () => request<Summary>("/summary"),

  accounts: () => request<Account[]>("/accounts"),

  revealSecret: (username: string) =>
    request<{ username: string; password: string }>(`/accounts/${encodeURIComponent(username)}/secret`),

  audit: (domain: string, cracked: File, uncracked: File | null, csrf: string) => {
    const fd = new FormData()
    fd.append("domain", domain)
    fd.append("cracked", cracked)
    if (uncracked) fd.append("uncracked", uncracked)
    // No Content-Type header: the browser sets the multipart boundary.
    return request<AuditResult>("/upload", { method: "POST", headers: { "X-CSRF-Token": csrf }, body: fd })
  },

  unlock: (passphrase: string, csrf: string) =>
    request<{ unlocked: boolean; initialized: boolean }>("/unlock", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ passphrase }),
    }),

  lock: (csrf: string) =>
    request<{ unlocked: boolean }>("/lock", { method: "POST", headers: { "X-CSRF-Token": csrf } }),

  changePassphrase: (oldPass: string, newPass: string, csrf: string) =>
    request<{ changed: boolean }>("/passphrase", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ old: oldPass, new: newPass }),
    }),

  rekey: (passphrase: string, csrf: string) =>
    request<{ rekeyed: boolean }>("/rekey", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ passphrase }),
    }),

  listAudits: () => request<AuditListItem[]>("/audits"),

  diff: (a: string, b: string) =>
    request<DiffResult>(`/audits/${encodeURIComponent(a)}/diff/${encodeURIComponent(b)}`),

  createAudit: (name: string, notes: string, csrf: string) =>
    request<AuditMeta>("/audits", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ name, notes }),
    }),

  deleteAudit: (id: string, csrf: string) =>
    request<{ status: string }>(`/audits/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: { "X-CSRF-Token": csrf },
    }),

  openAudit: (id: string, csrf: string) =>
    request<{ active_audit: string }>(`/audits/${encodeURIComponent(id)}/open`, {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
    }),

  getPolicies: () => request<PoliciesPayload>("/policies"),

  savePolicies: (payload: PoliciesPayload, csrf: string) =>
    request<{ domains: number; persisted: string }>("/policies", {
      method: "PUT",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify(payload),
    }),

  pwnedStatus: () => request<PwnedStatus>("/pwned/status"),

  pwnedBuild: (csrf: string) =>
    request<PwnedBuild>("/pwned/build", { method: "POST", headers: { "X-CSRF-Token": csrf } }),

  pwnedProbe: (csrf: string) =>
    request<PwnedProbe>("/pwned/probe", { method: "POST", headers: { "X-CSRF-Token": csrf } }),

  pwnedJob: () => request<PwnedJob>("/pwned/job"),

  pwnedDownload: (resume: boolean, csrf: string) =>
    request<PwnedJob>("/pwned/download", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ resume }),
    }),

  pwnedIndex: (csrf: string) =>
    request<PwnedJob>("/pwned/index", { method: "POST", headers: { "X-CSRF-Token": csrf } }),

  pwnedCancel: (csrf: string) =>
    request<PwnedJob>("/pwned/cancel", { method: "POST", headers: { "X-CSRF-Token": csrf } }),

  listUsers: () => request<Operator[]>("/users"),

  createUser: (username: string, password: string, role: Role, csrf: string) =>
    request<{ username: string; role: string }>("/users", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ username, password, role }),
    }),

  updateUser: (username: string, patch: { role?: Role; password?: string; disabled?: boolean }, csrf: string) =>
    request<{ username: string }>(`/users/${encodeURIComponent(username)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify(patch),
    }),

  deleteUser: (username: string, csrf: string) =>
    request<{ deleted: string }>(`/users/${encodeURIComponent(username)}`, {
      method: "DELETE",
      headers: { "X-CSRF-Token": csrf },
    }),

  unlockUser: (username: string, csrf: string) =>
    request<{ unlocked: string }>(`/users/${encodeURIComponent(username)}/unlock`, {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
    }),

  loginActivity: () => request<LoginAttempt[]>("/login-activity"),

  auditLog: (params: { q?: string; action?: string; result?: string; limit?: number }) => {
    const qs = new URLSearchParams()
    if (params.q) qs.set("q", params.q)
    if (params.action) qs.set("action", params.action)
    if (params.result) qs.set("result", params.result)
    if (params.limit) qs.set("limit", String(params.limit))
    const s = qs.toString()
    return request<AuditEvent[]>(`/audit-log${s ? "?" + s : ""}`)
  },
}

export interface AuditEvent {
  time: string
  actor?: string
  role?: string
  action: string
  target?: string
  source?: string
  result: string
}

export interface Operator {
  username: string
  role: Role
  disabled: boolean
  is_self: boolean
  last_login?: string
  last_login_ip?: string
  failed_attempts: number
  locked: boolean
  locked_until?: string
}

export interface LoginAttempt {
  time: string
  username: string
  source: string
  result: "ok" | "denied" | "locked"
}

export type PwnedPhase = "idle" | "downloading" | "indexing" | "done" | "failed" | "cancelled"

export interface PwnedJob {
  phase: PwnedPhase
  resume: boolean
  started_at?: string
  ended_at?: string
  elapsed_sec: number
  bytes_now: number
  est_total: number
  rate_bps: number
  index_scanned: number
  index_entries: number
  data_file: string
  error?: string
}

export interface PwnedStatus {
  source_dir: string
  source_present: boolean
  dotnet_version?: string
  built: boolean
  exe_path?: string
  data_file?: string
  data_bytes: number
}

export interface PwnedBuild {
  ok: boolean
  exe_path?: string
  output: string
  elapsed: string
}

export interface PwnedProbe {
  ok: boolean
  url: string
  status: number
  suffixes: number
  sample?: string
  elapsed: string
}

export interface AuditResult {
  accounts: number
  cracked: number
  uncracked: number
}
