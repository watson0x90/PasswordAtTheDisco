// The Password!AtTheDisco mark: a faceted disco ball (no background tile).
export function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" aria-hidden="true" focusable="false">
      <defs>
        <radialGradient id="patd-ball" cx="36%" cy="30%" r="78%">
          <stop offset="0%" stopColor="#cdeafe" />
          <stop offset="45%" stopColor="#38bdf8" />
          <stop offset="100%" stopColor="#4338ca" />
        </radialGradient>
        <clipPath id="patd-cb">
          <circle cx="20" cy="22" r="15" />
        </clipPath>
      </defs>
      {/* hanger */}
      <line x1="20" y1="2" x2="20" y2="7.5" stroke="#64748b" strokeWidth="1.5" />
      <circle cx="20" cy="22" r="15" fill="url(#patd-ball)" />
      {/* facet grid */}
      <g clipPath="url(#patd-cb)" stroke="rgba(7,11,30,0.4)" strokeWidth="1">
        <line x1="9" y1="7" x2="9" y2="37" />
        <line x1="14.5" y1="7" x2="14.5" y2="37" />
        <line x1="20" y1="7" x2="20" y2="37" />
        <line x1="25.5" y1="7" x2="25.5" y2="37" />
        <line x1="31" y1="7" x2="31" y2="37" />
        <line x1="5" y1="12" x2="35" y2="12" />
        <line x1="5" y1="17" x2="35" y2="17" />
        <line x1="5" y1="22" x2="35" y2="22" />
        <line x1="5" y1="27" x2="35" y2="27" />
        <line x1="5" y1="32" x2="35" y2="32" />
      </g>
      {/* bright facets */}
      <g clipPath="url(#patd-cb)" fill="rgba(255,255,255,0.6)">
        <rect x="14.5" y="12" width="5.5" height="5" />
        <rect x="20" y="22" width="5.5" height="5" />
        <rect x="9" y="17" width="5.5" height="5" fill="rgba(255,255,255,0.3)" />
      </g>
      {/* sparkle */}
      <path d="M33 8 l1 3 3 1 -3 1 -1 3 -1 -3 -3 -1 3 -1z" fill="#e0f2fe" />
    </svg>
  )
}
