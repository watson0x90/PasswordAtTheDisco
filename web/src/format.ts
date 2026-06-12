// Shared, pure display formatters. Unit-tested in format.test.ts (no DOM needed).

// fmtBytes renders a byte count with a binary-ish unit (decimal 1000 steps to match
// disk-vendor sizing the HIBP dump is reported in). 0 -> "0 B".
export function fmtBytes(n: number): string {
  if (!n) return "0 B"
  const u = ["B", "KB", "MB", "GB", "TB"]
  let i = 0
  let v = n
  while (v >= 1000 && i < u.length - 1) {
    v /= 1000
    i++
  }
  return `${v.toFixed(v < 10 && i > 0 ? 2 : 1)} ${u[i]}`
}

// fmtDuration renders seconds as a compact "1h 2m 3s" (drops leading zero units).
export function fmtDuration(sec: number): string {
  if (sec <= 0) return "0s"
  const h = Math.floor(sec / 3600)
  const m = Math.floor((sec % 3600) / 60)
  const s = sec % 60
  return [h ? `${h}h` : "", h || m ? `${m}m` : "", `${s}s`].filter(Boolean).join(" ")
}

// fmtWhen renders an ISO timestamp as a locale string; empty/invalid -> "never".
export function fmtWhen(iso?: string): string {
  if (!iso) return "never"
  const d = new Date(iso)
  return isNaN(d.getTime()) ? "never" : d.toLocaleString()
}

// resultClass maps an audit/login result to its badge CSS class.
export function resultClass(r: string): string {
  if (r === "ok") return "ev-ok"
  if (r === "denied" || r === "failed") return "ev-bad"
  if (r === "locked" || r === "rate_limited") return "ev-warn"
  return "ev-dim"
}
