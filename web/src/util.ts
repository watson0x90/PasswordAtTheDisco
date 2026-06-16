export const RISK_CLASS: Record<string, string> = {
  Critical: "crit",
  High: "high",
  Medium: "med",
  Low: "low",
}

// hasDA reports whether an account has a Domain Admin pathway.
export function hasDA(daDomains: string): boolean {
  return daDomains !== "" && daDomains !== "None" && daDomains !== "Unknown"
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
