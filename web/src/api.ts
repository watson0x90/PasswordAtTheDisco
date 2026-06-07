// Typed client for the Password!AtTheDisco API. Auth is a same-origin session
// cookie (HttpOnly), so every request sends credentials; state-changing requests
// carry the per-session CSRF token in the X-CSRF-Token header.

export type Role = "analyst" | "lead"

export interface Me {
  username: string
  role: Role
  csrf_token: string
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
}
