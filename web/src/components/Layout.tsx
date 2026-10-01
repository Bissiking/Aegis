import { useState, type ReactNode } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth'

interface Props {
  children: ReactNode
}

const userNav = [
  { to: '/', label: 'Vue d’ensemble', ico: '◈', end: true },
  { to: '/devices', label: 'Mes appareils', ico: '▤' },
  { to: '/devices/new', label: 'Ajouter un appareil', ico: '＋' },
  { to: '/usage', label: 'Consommation', ico: '◑' },
  { to: '/settings', label: 'Paramètres', ico: '⚙' },
]

const adminNav = [
  { to: '/admin', label: 'Tableau de bord', ico: '◈', end: true },
  { to: '/admin/wireguard', label: 'État WireGuard', ico: '⇄' },
  { to: '/admin/users', label: 'Utilisateurs', ico: '☺' },
  { to: '/admin/devices', label: 'Appareils', ico: '▤' },
  { to: '/admin/peers', label: 'Peers', ico: '⬡' },
  { to: '/admin/policies', label: 'Politiques & quotas', ico: '⚖' },
  { to: '/admin/servers', label: 'Serveurs VPN', ico: '⛁' },
  { to: '/admin/usage', label: 'Consommation', ico: '◑' },
  { to: '/admin/audit', label: 'Journal d’audit', ico: '☰' },
  { to: '/admin/kyros', label: 'Intégration Kyros', ico: '✦' },
]

export default function Layout({ children }: Props) {
  const { user, meta, logout } = useAuth()
  const nav = useNavigate()
  const [open, setOpen] = useState(false)
  const isAdmin = user?.role === 'admin'

  const close = () => setOpen(false)

  return (
    <div className="app">
      <aside className={`sidebar${open ? ' open' : ''}`}>
        <div className="brand">
          <span className="mark">A</span>
          <span>
            Aegis VPN
            <small>WireGuard control panel</small>
          </span>
        </div>

        {isAdmin && (
          <>
            <div className="nav-label">Administration</div>
            {adminNav.map((i) => (
              <NavLink key={i.to} to={i.to} end={i.end} className="nav-item" onClick={close}>
                <span className="ico">{i.ico}</span>
                {i.label}
              </NavLink>
            ))}
            <div className="nav-label">Mon compte</div>
          </>
        )}
        {userNav.map((i) => (
          <NavLink key={i.to} to={i.to} end={i.end} className="nav-item" onClick={close}>
            <span className="ico">{i.ico}</span>
            {i.label}
          </NavLink>
        ))}

        <footer>
          <div>v{meta?.version ?? '—'}</div>
          <div className="muted">{meta?.environment ?? ''}</div>
        </footer>
      </aside>

      <div className="main">
        <header className="topbar">
          <div className="flex">
            <button className="btn ghost sm menu-toggle" onClick={() => setOpen((v) => !v)} aria-label="Menu">
              ☰
            </button>
            <strong>{user?.display_name || user?.email}</strong>
            <span className="badge accent">{user?.role === 'admin' ? 'Administrateur' : 'Utilisateur'}</span>
          </div>
          <div className="who">
            <span className="truncate">{user?.email}</span>
            <span className="avatar">{(user?.display_name || user?.email || '?').slice(0, 1).toUpperCase()}</span>
            <button
              className="btn sm"
              onClick={() => {
                void logout().then(() => nav('/login'))
              }}
            >
              Déconnexion
            </button>
          </div>
        </header>
        <div className="content">{children}</div>
      </div>
    </div>
  )
}
