import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// 127.0.0.1, not "localhost": on Windows "localhost" resolves to IPv6
// (::1) first, and uvicorn only listens on IPv4, so every proxied API
// call waited ~200 ms for the IPv4 fallback.
const apiTarget = process.env.VITE_PROXY_TARGET || 'http://127.0.0.1:8000'

// Security headers found missing by the OWASP ZAP scan.
const securityHeaders = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
}

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: { '/api': apiTarget },
    // No CSP on the dev server: React Fast Refresh injects an inline script.
    headers: securityHeaders,
    // Pre-transform every page module when the dev server starts, so the
    // first visit to each (lazy-loaded) page after a restart is instant
    // instead of compiling on demand.
    warmup: {
      clientFiles: ['./src/main.jsx', './src/App.jsx', './src/components/**/*.jsx'],
    },
  },
  // The production build has no inline scripts, so it gets a strict CSP.
  preview: {
    proxy: { '/api': apiTarget },
    headers: {
      ...securityHeaders,
      'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "font-src 'self'",
        "img-src 'self' data: blob:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
      ].join('; '),
    },
  },
})
