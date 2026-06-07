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
