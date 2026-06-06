import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The dev server is bound to localhost only and never `--host`-exposed: the
// 2025-2026 Vite dev-server CVEs (arbitrary file read, fs.deny bypass) only
// affect network-exposed dev servers. Production is the Go binary serving the
// built dist/ -- the Vite dev server never runs there.
export default defineConfig({
  plugins: [react()],
  server: { host: '127.0.0.1', strictPort: true },
  build: { outDir: 'dist', sourcemap: false },
})
