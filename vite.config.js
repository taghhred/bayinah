import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Use IPv4 explicitly — on some Windows setups "localhost" fails or proxies oddly.
    host: '127.0.0.1',
    port: 5173,
    strictPort: false,
    open: true,
    proxy: {
      // Match IPv4; "localhost" can resolve to ::1 while uvicorn listens on 127.0.0.1 only.
      // Long timeouts: /analyze waits on Gemini (parallel calls); default proxy timeouts cause HTTP 502.
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        timeout: 300_000,
        proxyTimeout: 300_000,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
  preview: {
    host: '127.0.0.1',
    strictPort: false,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        timeout: 300_000,
        proxyTimeout: 300_000,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})
