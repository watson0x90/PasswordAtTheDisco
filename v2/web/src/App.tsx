import { useEffect, useState } from 'react'

// Skeleton shell. Talks to the Go API (same origin). Real views (auth, redacted
// dashboard, authz-gated cleartext) are built on top of this.
export function App() {
  const [version, setVersion] = useState('...')

  useEffect(() => {
    fetch('/api/version')
      .then((r) => r.json())
      .then((d) => setVersion(d.version as string))
      .catch(() => setVersion('unavailable'))
  }, [])

  return (
    <main style={{ fontFamily: 'system-ui, sans-serif', padding: '2rem', color: '#d1d5db', background: '#1a1d23', minHeight: '100vh' }}>
      <h1>Password!AtTheDisco</h1>
      <p>Secure delivery stack — API version: {version}</p>
    </main>
  )
}
