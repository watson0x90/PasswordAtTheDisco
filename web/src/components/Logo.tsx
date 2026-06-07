// The Password!AtTheDisco mark: a faceted disco ball inside a blue app-tile.
export function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id="patd-tile" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#0ea5e9" />
          <stop offset="1" stopColor="#4f46e5" />
        </linearGradient>
        <radialGradient id="patd-ball" cx="38%" cy="32%" r="70%">
          <stop offset="0%" stopColor="#e0f2fe" />
          <stop offset="50%" stopColor="#7dd3fc" />
          <stop offset="100%" stopColor="#1e3a8a" />
        </radialGradient>
        <clipPath id="patd-cb">
          <circle cx="20" cy="20" r="9" />
        </clipPath>
      </defs>
      <rect x="3" y="3" width="34" height="34" rx="10" fill="url(#patd-tile)" />
      <circle cx="20" cy="20" r="9" fill="url(#patd-ball)" />
      <g clipPath="url(#patd-cb)" stroke="rgba(7,11,40,0.45)" strokeWidth="0.9">
        <line x1="16" y1="11" x2="16" y2="29" />
        <line x1="20" y1="11" x2="20" y2="29" />
        <line x1="24" y1="11" x2="24" y2="29" />
        <line x1="11" y1="16" x2="29" y2="16" />
        <line x1="11" y1="20" x2="29" y2="20" />
        <line x1="11" y1="24" x2="29" y2="24" />
      </g>
      <g clipPath="url(#patd-cb)" fill="rgba(255,255,255,0.7)">
        <rect x="16" y="12" width="4" height="4" />
        <rect x="20" y="20" width="4" height="4" />
      </g>
    </svg>
  )
}
