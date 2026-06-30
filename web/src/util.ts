export const RISK_CLASS: Record<string, string> = {
  Critical: "crit",
  High: "high",
  Medium: "med",
  Low: "low",
}

// Severity rank for sorting (Critical highest). Mirrors RISK_CLASS keys.
export const RISK_RANK: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1 }

// hasDA reports whether an account has a Domain Admin pathway.
export function hasDA(daDomains: string): boolean {
  return daDomains !== "" && daDomains !== "None" && daDomains !== "Unknown"
}

// credentialObtainable mirrors Go model.CredentialObtainable exactly (no enabled gate —
// callers that need enabled-only reachability use insights.isReachable instead).
export function credentialObtainable(a: {
  cracked: boolean
  hibp_breached: boolean
  escalated_by_shared_da?: boolean
  escalated_by_mass_reuse?: boolean
}): boolean {
  return !!a.cracked || !!a.hibp_breached || !!a.escalated_by_shared_da || !!a.escalated_by_mass_reuse
}

// hasObtainableDA mirrors Go Account.HasObtainableDAPathway = HasDAPathway && CredentialObtainable.
// Use this instead of hasDA() whenever counting "how many DA accounts are a real threat."
export function hasObtainableDA(a: {
  cracked: boolean
  hibp_breached: boolean
  escalated_by_shared_da?: boolean
  escalated_by_mass_reuse?: boolean
  da_domains: string
}): boolean {
  return hasDA(a.da_domains) && credentialObtainable(a)
}

// weaknessTags returns the wordlist-weakness labels for an account (common,
// dictionary, forbidden word, keyboard pattern). Empty if none / not cracked.
export function weaknessTags(a: {
  is_common?: boolean
  is_dictionary_word?: boolean
  banned_word_count?: number
  keyboard_pattern_count?: number
}): string[] {
  const t: string[] = []
  if (a.is_common) t.push("Common")
  if (a.is_dictionary_word) t.push("Dictionary")
  if ((a.banned_word_count ?? 0) > 0) t.push("Forbidden")
  if ((a.keyboard_pattern_count ?? 0) > 0) t.push("Keyboard")
  return t
}
