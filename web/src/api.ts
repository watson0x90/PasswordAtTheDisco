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

export interface Summary {
  total_accounts: number
  cracked: number
  hibp_breached: number
  da_pathways: number
  risk_counts: Record<string, number>
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
  constructor(status: number, message: string) {
    super(message)
    this.status = status
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
    let msg = `request failed (${res.status})`
    if (body && typeof body === "object" && "error" in body) {
      const e = (body as { error?: unknown }).error
      if (typeof e === "string" && e) msg = e
    }
    throw new ApiError(res.status, msg)
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

  listAudits: () => request<AuditListItem[]>("/audits"),

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
}

export interface AuditResult {
  accounts: number
  cracked: number
  uncracked: number
}
