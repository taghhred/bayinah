/**
 * Base URL for FastAPI. Default `/api` uses the Vite dev/preview proxy.
 *
 * If `VITE_IDS_API_URL` is absolute and ends with `/api`, that suffix is removed:
 * routes like `/auth/login` and `/analyze` live on the server root, not under `/api`.
 */
export function getApiBaseUrl() {
  const raw = import.meta.env.VITE_IDS_API_URL
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return '/api'
  }
  let s = String(raw).trim().replace(/\/$/, '')
  if (s === '/api') {
    return '/api'
  }
  if (/^https?:\/\//i.test(s) && /\/api$/i.test(s)) {
    const stripped = s.replace(/\/api$/i, '')
    return stripped || s
  }
  return s
}
