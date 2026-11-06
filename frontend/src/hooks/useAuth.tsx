import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { api, ApiError, setUnauthorizedHandler } from '@/services/api'
import type { Me } from '@/types/api'

interface AuthState {
  me: Me | null
  loading: boolean
  refresh: () => Promise<Me | null>
  logout: () => Promise<void>
  /** UI convenience only — the backend re-checks every permission. */
  can: (permission: string) => boolean
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null)
  const [loading, setLoading] = useState(true)
  const qc = useQueryClient()

  const refresh = useCallback(async () => {
    try {
      const data = await api.get<Me>('/auth/me')
      setMe(data)
      return data
    } catch (e) {
      if (!(e instanceof ApiError && e.status === 401)) console.error(e)
      setMe(null)
      return null
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setMe(null)
      qc.clear()
    })
    void refresh()
  }, [refresh, qc])

  const logout = useCallback(async () => {
    try {
      await api.post('/auth/logout')
    } finally {
      setMe(null)
      qc.clear()
    }
  }, [qc])

  const value = useMemo<AuthState>(
    () => ({ me, loading, refresh, logout, can: (p) => !!me?.permissions.includes(p) }),
    [me, loading, refresh, logout],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
