import { createContext, useCallback, useContext, useMemo, useState } from 'react'
import { getApiBaseUrl } from '../apiBase.js'

/** Demo credentials — must match backend `app.py` until real user store + JWT. */
export const DEMO_USERNAME = '1111'
export const DEMO_PASSWORD = '1111'

const AUTH_STORAGE_KEY = 'baunah_auth_session'

const AuthContext = createContext(null)

function readStoredSession() {
  try {
    const raw = localStorage.getItem(AUTH_STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw)
    if (parsed && typeof parsed.token === 'string' && typeof parsed.username === 'string') {
      return { token: parsed.token, username: parsed.username }
    }
  } catch {
    /* ignore */
  }
  return null
}

function writeStoredSession(session) {
  try {
    if (session) {
      localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(session))
    } else {
      localStorage.removeItem(AUTH_STORAGE_KEY)
    }
  } catch {
    /* ignore */
  }
}

function formatLoginError(data, status) {
  const detail = data?.detail
  if (typeof detail === 'string' && detail.trim()) {
    return detail.trim()
  }
  if (Array.isArray(detail) && detail.length > 0) {
    return detail.map((item) => item?.msg || JSON.stringify(item)).join(' — ')
  }
  return `فشل تسجيل الدخول (HTTP ${status})`
}

export function AuthProvider({ children }) {
  const [session, setSession] = useState(() => readStoredSession())

  const logout = useCallback(() => {
    writeStoredSession(null)
    setSession(null)
  }, [])

  /**
   * Validates with POST /auth/login when the API is reachable.
   * On network failure only, falls back to static demo credentials (offline dev).
   * Replace session storage with httpOnly cookies + JWT when hardening.
   */
  const login = useCallback(async (username, password) => {
    const u = String(username || '').trim()
    const p = String(password || '')
    if (!u || !p) {
      throw new Error('يرجى إدخال اسم المستخدم وكلمة المرور.')
    }

    try {
      const response = await fetch(`${getApiBaseUrl()}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u, password: p }),
      })
      let data = {}
      try {
        data = await response.json()
      } catch {
        /* ignore */
      }
      if (response.ok && data.access_token) {
        const next = {
          token: String(data.access_token),
          username: String(data.username || u),
        }
        writeStoredSession(next)
        setSession(next)
        return
      }
      const detailNorm =
        typeof data?.detail === 'string' ? data.detail.trim().toLowerCase() : ''
      const looksLikeMissingRoute =
        response.status === 404 || detailNorm === 'not found'
      if (
        looksLikeMissingRoute &&
        u === DEMO_USERNAME &&
        p === DEMO_PASSWORD
      ) {
        const next = { token: 'local-demo-session', username: u }
        writeStoredSession(next)
        setSession(next)
        return
      }
      throw new Error(formatLoginError(data, response.status))
    } catch (err) {
      if (err instanceof TypeError) {
        if (u === DEMO_USERNAME && p === DEMO_PASSWORD) {
          const next = { token: 'local-offline-session', username: u }
          writeStoredSession(next)
          setSession(next)
          return
        }
        throw new Error(
          'تعذر الاتصال بالخادم. شغّل FastAPI على المنفذ 8000، أو جرّب بيانات الدخول التجريبية عند انقطاع الشبكة.',
          { cause: err },
        )
      }
      throw err
    }
  }, [])

  const value = useMemo(
    () => ({
      session,
      user: session?.username ?? null,
      token: session?.token ?? null,
      isAuthenticated: Boolean(session?.token),
      login,
      logout,
    }),
    [session, login, logout],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

// Hook is intentionally co-located with the provider; HMR still refreshes the module cleanly.
// eslint-disable-next-line react-refresh/only-export-components -- useAuth must live next to AuthContext
export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) {
    throw new Error('useAuth must be used within AuthProvider')
  }
  return ctx
}
