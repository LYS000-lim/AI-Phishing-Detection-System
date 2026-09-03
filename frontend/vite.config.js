import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Proxy /api to the FastAPI backend during development
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: { '/api': 'http://localhost:8000' }
  }
})
