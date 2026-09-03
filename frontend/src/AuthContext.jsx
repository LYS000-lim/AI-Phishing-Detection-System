import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import * as api from './api.js'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [ready, setReady] = useState(false)

  useEffect(() => {
    const token = api.getToken()
    if (!token) {
      setReady(true)
      return
    }
    api
      .me()
      .then(setUser)
      .catch(() => api.clearToken())
      .finally(() => setReady(true))
  }, [])

  const login = useCallback(async (email, password) => {
    const res = await api.login({ email, password })
    api.setToken(res.access_token)
    setUser(res.user)
    return res.user
  }, [])

  const register = useCallback(async (full_name, email, password) => {
    const res = await api.register({ full_name, email, password })
    return res
  }, [])

  const logout = useCallback(async () => {
    try {
      await api.logout()
    } catch {
      /* token may already be invalid, ignore */
    }
    api.clearToken()
    setUser(null)
  }, [])

  const refresh = useCallback(async () => {
    const fresh = await api.me()
    setUser(fresh)
    return fresh
  }, [])

  return (
    <AuthContext.Provider value={{ user, ready, login, register, logout, refresh }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
