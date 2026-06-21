// Typed client for the Password!AtTheDisco API. Auth is a same-origin session
// cookie (HttpOnly), so every request sends credentials; state-changing requests
// carry the per-session CSRF token in the X-CSRF-Token header.

export type Role = "analyst" | "lead"

export interface Me {
  // false for an anonymous probe (GET /api/me is reachable without a session and
  // returns 200 so a fresh page load logs no console 401); absent/true otherwise.
  authenticated?: boolean
  username: string
  role: Role
  csrf_token: string
  active_audit: string
  store_initialized: boolean
  store_unlocked: boolean
}

// Compile-time build identity from GET /api/version (footer build confirmation).
export interface VersionInfo {
  name: string
  version: string
  commit: string
  build_date: string
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
  // Extended stats
  disabled_accounts: number
  never_expires: number
  stale_passwords: number
  escalated_by_shared_da: number
  policy_violations: number
  high_controlled: number
  // Executive breach impact
  breach_impact: BreachImpact
}

export interface BreachImpact {
  probability: string
  probability_pct: string
  estimated_cost: string
  recovery_time: string
}

export interface Account {
  username: string
  domain: string
  cracked: boolean
  password_length: number
  risk_level: string
  risk_score: number
  // --- scoring engine v2 (two-axis Exposure × Impact) ---
  // exposure_score: 0–10, ALWAYS present (dump+HIBP+reuse derived).
  exposure_score: number
  // impact_score: 0–10, or null when Impact is Unknown (no BloodHound coverage).
  // null is load-bearing — never coalesce it to 0/low.
  impact_score: number | null
  // impact_known: false => Impact is Unknown; render "Unknown" + a provisional level badge.
  impact_known: boolean
  // coverage: "full" = this account was BloodHound-enriched; "none" = not enriched.
  // Absent (omitempty) means no enrichment record at all → treat as "none".
  coverage?: "full" | "none"
  // percentile: within-audit triage rank [0,1] (sort key, not a displayed score).
  // Always serialized by the Go side (no omitempty: 0.0 is a valid lowest rank).
  percentile: number
  risk_vector: string
  hibp_breached: boolean
  hibp_breach_count: number
  da_domains: string
  controlled_object_count: number
  shared_with: number
  enabled: boolean
  meets_policy: boolean
  complexity: string
  // wordlist weakness signals (cracked accounts only; counts/booleans, never the matched word)
  is_common?: boolean
  is_dictionary_word?: boolean
  banned_word_count?: number
  keyboard_pattern_count?: number
  // Enrichment-derived temporal/privilege signals
  pwd_last_set?: number
  pwd_never_expires?: boolean
  days_out_of_compliance?: number
  similarity_score?: number
  similar_peers?: SimilarPeer[]
  escalated_by_shared_da?: boolean
  // Kerberos attack surface
  has_spn?: boolean
  dont_req_preauth?: boolean
  // Full score breakdown (cracked accounts only)
  score_breakdown?: ScoreBreakdown
}

// v2 score_breakdown: per-axis sub-scores. Go serializes these with omitempty, so a
// legitimately-zero factor is ABSENT — readers MUST treat a missing key as 0, never
// "unknown" (a safe-accessor helper that coalesces undefined→0 is added in a later
// task). All optional for that reason.
export interface ScoreBreakdown {
  // Exposure axis
  exposure_score?: number
  weakness_score?: number
  length_penalty?: number
  complexity_penalty?: number
  dict_penalty?: number
  sim_penalty?: number
  hibp_floor?: number
  cracked_floor?: number
  reuse_bump?: number
  roastable_bump?: number
  // Impact axis
  impact_score?: number
  privilege_sub_score?: number
  da_component?: number
  domain_modifier?: number
  enabled_gated?: boolean
}

export interface SimilarPeer {
  username: string
  domain: string
  score: number
}

export interface ProbeResult {
  count: number
  matches: Account[]
}

// A redacted account row in the Actionable reports — no cleartext, no NT hash.
export interface ReportAccount {
  username: string
  domain: string
  cracked: boolean
  password_length?: number
  risk_level: string
  risk_score: number
  hibp_breach_count: number
  shared_with: number
  da_domains?: string
  controlled_object_count: number
  enabled: boolean
  is_common?: boolean
  is_dictionary_word?: boolean
  banned_word_count?: number
  keyboard_pattern_count?: number
}

// A set of accounts sharing one NT hash (= one password). The hash is never exposed.
export interface ReuseGroup {
  group_id: number
  size: number
  cracked: boolean
  password_length?: number
  hibp_breach_count: number
  has_da_pathway: boolean
  domains: number
  truncated?: boolean
  members: ReportAccount[]
}

export interface ViolationCounts {
  common: number
  dictionary: number
  forbidden: number
  keyboard: number
}

export interface Term {
  term: string
  count: number
}

export interface Terms {
  forbidden: Term[]
  keyboard: Term[]
}

export interface Report {
  total_accounts: number
  cracked_count: number
  uncracked_count: number
  da_pathways: ReportAccount[]
  cracked: ReportAccount[]
  cracked_reuse: ReuseGroup[]
  uncracked_reuse: ReuseGroup[]
  hibp_exposed: ReportAccount[]
  weak_passwords: ReportAccount[]
  violation_counts: ViolationCounts
  escalated_by_shared_da: ReportAccount[]
  high_controlled: ReportAccount[]
  never_expires: ReportAccount[]
  stale_passwords: ReportAccount[]
  kerberoastable: ReportAccount[]
  asrep_roastable: ReportAccount[]
}

export interface PolicyRule {
  min_length: number
  require_lowercase: boolean
  require_uppercase: boolean
  require_digits: boolean
  require_special: boolean
  max_password_age_days: number
  domain_risk_level?: string
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
    // 401 = the session is gone (server restart wiped the in-memory session store,
    // or the session hit idle/absolute expiry). Broadcast so AuthProvider returns to
    // the login screen instead of leaving the SPA in a stale "authenticated" state
    // where mounted pollers (JobsProvider) keep hitting lead-only endpoints and the
    // browser logs a recurring console 401 every few seconds.
    if (res.status === 401) {
      window.dispatchEvent(new CustomEvent("patd:unauthorized"))
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

// uploadForm POSTs multipart FormData via XMLHttpRequest so upload progress is observable
// (fetch can't report it). Mirrors request()'s error handling.
export function uploadForm<T>(
  path: string,
  form: FormData,
  csrf: string,
  onProgress?: (loaded: number, total: number) => void,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open("POST", `/api${path}`)
    xhr.withCredentials = true
    xhr.setRequestHeader("X-CSRF-Token", csrf)
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress?.(e.loaded, e.total)
    }
    xhr.onload = () => {
      const body = xhr.responseText ? safeParse(xhr.responseText) : null
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(body as T)
        return
      }
      if (xhr.status === 423) window.dispatchEvent(new CustomEvent("patd:locked"))
      if (xhr.status === 401) window.dispatchEvent(new CustomEvent("patd:unauthorized"))
      let msg = `request failed (${xhr.status})`
      if (body && typeof body === "object" && "error" in body) {
        const e = (body as { error?: unknown }).error
        if (typeof e === "string" && e) msg = e
      }
      reject(new ApiError(xhr.status, msg, body))
    }
    xhr.onerror = () => reject(new ApiError(0, "network error — is the server reachable?"))
    xhr.send(form)
  })
}

export const api = {
  login: (username: string, password: string) =>
    request<Me>("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    }),

  me: () => request<Me>("/me"),

  version: () => request<VersionInfo>("/version"),

  logout: (csrf: string) =>
    request<{ status: string }>("/logout", {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
    }),

  summary: () => request<Summary>("/summary"),

  accounts: () => request<Account[]>("/accounts"),

  report: () => request<Report>("/report"),
  reportTerms: () => request<Terms>("/report/terms"),

  revealSecret: (username: string, domain?: string) =>
    request<{ username: string; password: string }>(
      `/accounts/${encodeURIComponent(username)}/secret${domain ? `?domain=${encodeURIComponent(domain)}` : ""}`,
    ),

  probe: (password: string, csrf: string) =>
    request<ProbeResult>("/probe", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ password }),
    }),

  audit: (domain: string, cracked: File | null, uncracked: File | null, csrf: string, onProgress?: (l: number, t: number) => void) => {
    const fd = new FormData()
    fd.append("domain", domain) // must precede files (server streams parts in order)
    if (cracked) fd.append("cracked", cracked)
    if (uncracked) fd.append("uncracked", uncracked)
    return uploadForm<AuditResult>("/upload", fd, csrf, onProgress)
  },

  applyCracks: (crackfile: File, csrf: string, onProgress?: (l: number, t: number) => void) => {
    const fd = new FormData()
    fd.append("crackfile", crackfile)
    return uploadForm<ApplyCracksResult>("/upload/cracks", fd, csrf, onProgress)
  },

  uploadBHEUsers: (file: File, csrf: string, onProgress?: (l: number, t: number) => void) => {
    const fd = new FormData()
    fd.append("bheusers", file)
    return uploadForm<BHEUsersResult>("/upload/bheusers", fd, csrf, onProgress)
  },

  ingests: () => request<IngestEvent[]>("/ingests"),

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

  auditAccounts: (id: string) => request<Account[]>(`/audits/${encodeURIComponent(id)}/accounts`),

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

  getForbiddenWords: () => request<{ words: string[] }>("/forbidden-words"),
  setForbiddenWords: (words: string[], csrf: string) =>
    request<{ count: number; persisted: string }>("/forbidden-words", {
      method: "PUT",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ words }),
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

  bheStatus: () => request<BHEStatus>("/bhe/status"),

  bheTest: (cfg: BHEConfigInput, csrf: string) =>
    request<BHETestResult>("/bhe/test", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify(cfg),
    }),

  bheConfig: (cfg: BHEConfigInput, csrf: string) =>
    request<{ saved: boolean; active: boolean }>("/bhe/config", {
      method: "PUT",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify(cfg),
    }),

  deleteDomain: (domain: string, csrf: string) =>
    request<{ removed: number }>(`/domains/${encodeURIComponent(domain)}`, {
      method: "DELETE",
      headers: { "X-CSRF-Token": csrf },
    }),

  enrich: (csrf: string) =>
    request<EnrichJob>("/enrich", { method: "POST", headers: { "X-CSRF-Token": csrf } }),

  enrichJob: () => request<EnrichJob>("/enrich/job"),

  enrichCancel: (csrf: string) =>
    request<EnrichJob>("/enrich/cancel", { method: "POST", headers: { "X-CSRF-Token": csrf } }),

  auditLog: (params: AuditQuery) => request<AuditEvent[]>(`/audit-log${auditQuery(params)}`),

  // full /api URL for an <a download> (the browser sends the session cookie)
  auditLogCsvUrl: (params: AuditQuery) => `/api/audit-log.csv${auditQuery(params)}`,
}

export interface AuditQuery {
  q?: string
  action?: string
  result?: string
  from?: string
  to?: string
  limit?: number
}

export function auditQuery(p: AuditQuery): string {
  const qs = new URLSearchParams()
  if (p.q) qs.set("q", p.q)
  if (p.action) qs.set("action", p.action)
  if (p.result) qs.set("result", p.result)
  if (p.from) qs.set("from", p.from)
  if (p.to) qs.set("to", p.to)
  if (p.limit) qs.set("limit", String(p.limit))
  const s = qs.toString()
  return s ? "?" + s : ""
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

export interface BHEStatus {
  scheme: string
  host: string
  port: number
  search_limit: number
  controllables_limit: number
  token_configured: boolean
  active: boolean
  config_path: string
}

export interface BHEConfigInput {
  scheme: string
  host: string
  port: number
  token_id?: string
  token_key?: string
}

export interface BHETestResult {
  ok: boolean
  server_version?: string
  domains?: { name: string; collected: boolean }[]
  error?: string
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

export interface ApplyCracksResult {
  crack_entries: number
  hashes_matched: number
  newly_cracked: number
}

export interface BHEUsersResult {
  uploaded_users: number
  matched_accounts: number
}

export interface IngestEvent {
  filename: string
  kind: "dump" | "cracks" | "domain_delete" | "enrich"
  domain?: string
  accounts_loaded?: number
  hashes_matched?: number
  newly_cracked?: number
  at: string
  by: string
}

export interface EnrichJob {
  phase: "idle" | "running" | "done" | "failed" | "cancelled"
  audit_id?: string
  processed: number
  total: number
  enriched: number
  started_at?: string
  elapsed_sec: number
  error?: string
  message?: string
}
