import { useCallback, useEffect, useMemo, useState } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { AuthCtx } from './auth'
import { api, setCsrfToken, type Meta, type SessionInfo, type User } from './api'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Devices from './pages/Devices'
import NewDevice from './pages/NewDevice'
import ProfileDelivery from './pages/ProfileDelivery'
import Usage from './pages/Usage'
import Users from './pages/Users'
import Policies from './pages/Policies'
import Servers from './pages/Servers'
import Peers from './pages/Peers'
import WireGuard from './pages/WireGuard'
import Audit from './pages/Audit'
import Settings from './pages/Settings'
import Kyros from './pages/Kyros'

export default function App() {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)
  const [meta, setMeta] = useState<Meta | null>(null)
  const location = useLocation()

  const refresh = useCallback(async () => {
    try {
      const { data } = await api<SessionInfo>('/api/v1/auth/session')
      setCsrfToken(data.csrf_token)
      setUser(data.user)
    } catch {
      setCsrfToken('')
      setUser(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void refresh()
    void api<Meta>('/api/v1/meta')
      .then((r) => setMeta(r.data))
      .catch(() => setMeta(null))
  }, [refresh])

  const login = useCallback(
    async (email: string, password: string) => {
      const { data } = await api<{ user: User; csrf_token: string }>('/api/v1/auth/login', {
        method: 'POST',
        json: { email, password },
      })
      setCsrfToken(data.csrf_token)
      setUser(data.user)
    },
    [],
  )

  const logout = useCallback(async () => {
    await api<void>('/api/v1/auth/logout', { method: 'POST' }).catch(() => undefined)
    setCsrfToken('')
    setUser(null)
  }, [])

  const value = useMemo(
    () => ({ user, loading, meta, refresh, login, logout }),
    [user, loading, meta, refresh, login, logout],
  )

  if (loading) {
    return (
      <div className="auth-wrap">
        <div className="muted">Chargement…</div>
      </div>
    )
  }

  return (
    <AuthCtx.Provider value={value}>
      <Routes>
        <Route path="/login" element={user ? <Navigate to="/" replace /> : <Login />} />
        <Route
          path="/*"
          element={
            user ? (
              <Layout>
                <Routes>
                  <Route index element={<Dashboard />} />
                  <Route path="devices" element={<Devices />} />
                  <Route path="devices/new" element={<NewDevice />} />
                  <Route path="devices/:id/profile" element={<ProfileDelivery />} />
                  <Route path="usage" element={<Usage />} />
                  <Route path="admin" element={<Dashboard />} />
                  <Route path="admin/users" element={<Users />} />
                  <Route path="admin/policies" element={<Policies />} />
                  <Route path="admin/servers" element={<Servers />} />
                  <Route path="admin/devices" element={<Devices adminMode />} />
                  <Route path="admin/peers" element={<Peers />} />
                  <Route path="admin/wireguard" element={<WireGuard />} />
                  <Route path="admin/usage" element={<Usage adminMode />} />
                  <Route path="admin/audit" element={<Audit />} />
                  <Route path="admin/kyros" element={<Kyros />} />
                  <Route path="settings" element={<Settings />} />
                  <Route path="*" element={<Navigate to="/" replace />} />
                </Routes>
              </Layout>
            ) : (
              <Navigate to="/login" replace state={{ from: location.pathname }} />
            )
          }
        />
      </Routes>
    </AuthCtx.Provider>
  )
}
