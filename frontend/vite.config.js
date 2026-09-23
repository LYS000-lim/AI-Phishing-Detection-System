import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    // 127.0.0.1, not "localhost": on Windows "localhost" resolves to IPv6
    // (::1) first, and uvicorn only listens on IPv4, so every proxied API
    // call waited ~200 ms for the IPv4 fallback.
    proxy: { '/api': 'http://127.0.0.1:8000' },
    // Pre-transform every page module when the dev server starts, so the
    // first visit to each (lazy-loaded) page after a restart is instant
    // instead of compiling on demand.
    warmup: {
      clientFiles: ['./src/main.jsx', './src/App.jsx', './src/components/**/*.jsx'],
    },
  },
})
