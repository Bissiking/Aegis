import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, formatBytes, formatRelative, type Device, type Stats, type UsageOverview } from '../api'
import { useAuth } from '../auth'
import StateBadge from '../components/StateBadge'

export default function Dashboard() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [stats, setStats] = useState<Stats | null>(null)
  const [usage, setUsage] = useState<UsageOverview | null>(null)
  const [devices, setDevices] = useState<Device[]>([])
  const [health, setHealth] = useState<any>(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    api<UsageOverview>('/api/v1/me/usage').then((r) => setUsage(r.data)).catch((e) => setErr(e.message))
    api<Device[]>('/api/v1/me/devices?limit=5').then((r) => setDevices(r.data)).catch(() => undefined)
    if (isAdmin) {
      api<Stats>('/api/v1/admin/stats').then((r) => setStats(r.data)).catch(() => undefined)
      api<any>('/api/v1/health').then((r) => setHealth(r.data)).catch(() => setHealth(null))
    }
  }, [isAdmin])

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Tableau de bord</h1>
          <p>Vue d’ensemble de votre accès VPN{isAdmin ? ' et de l’instance' : ''}.</p>
        </div>
        <div className="actions">
          <Link className="btn primary" to="/devices/new">
            ＋ Ajouter un appareil
          </Link>
        </div>
      </div>

      {err && <div className="alert error">{err}</div>}

      <div className="grid cols-4 mb">
        <div className="card stat">
          <div className="label">Consommation du mois</div>
          <div className="value">{formatBytes(usage?.total_bytes ?? 0)}</div>
          <div className="sub">{usage?.month ?? ''}</div>
        </div>
        <div className="card stat">
          <div className="label">Appareils</div>
          <div className="value">
            {usage?.device_count ?? 0}
            <span className="muted" style={{ fontSize: 16 }}>
              {' '}
              / {usage && usage.max_devices > 0 ? usage.max_devices : '∞'}
            </span>
          </div>
          <div className="sub">Politique « {usage?.policy_name ?? '—'} »</div>
        </div>
        <div className="card stat">
          <div className="label">Expiration</div>
          <div className="value" style={{ fontSize: 20 }}>
            {usage?.expires_at ? new Date(usage.expires_at * 1000).toLocaleDateString('fr-FR') : 'Aucune'}
          </div>
          <div className="sub">
            état : <StateBadge state={usage?.status ?? 'active'} />
          </div>
        </div>
        <div className="card stat">
          <div className="label">Quota mensuel</div>
          <div className="value" style={{ fontSize: 20 }}>
            {usage?.quota_bytes ? formatBytes(usage.quota_bytes) : 'Illimité'}
          </div>
          <div className="sub">
            {usage?.quota_bytes ? `${usage.quota_used_percent.toFixed(1)} % utilisé` : 'Aucune limite'}
          </div>
        </div>
      </div>

      {usage?.quota_bytes ? (
        <div className="card mb">
          <div className="between">
            <strong>Quota mensuel</strong>
            <span className="muted">
              {formatBytes(usage.total_bytes)} / {formatBytes(usage.quota_bytes)}
            </span>
          </div>
          <div className="progress mt" style={{ marginTop: 10 }}>
            <i
              style={{ width: `${Math.min(100, usage.quota_used_percent)}%` }}
              className={usage.quota_used_percent > 90 ? '' : ''}
            />
          </div>
        </div>
      ) : null}

      {isAdmin && stats && (
        <div className="grid cols-4 mb">
          <div className="card stat">
            <div className="label">Utilisateurs</div>
            <div className="value">{stats.users}</div>
            <div className="sub">{stats.admins} administrateur(s)</div>
          </div>
          <div className="card stat">
            <div className="label">Peers actifs</div>
            <div className="value">{stats.active_peers}</div>
            <div className="sub">{stats.suspended_peers} suspendu(s)</div>
          </div>
          <div className="card stat">
            <div className="label">Appareils</div>
            <div className="value">{stats.devices}</div>
            <div className="sub">{stats.revoked_peers} révoqué(s)</div>
          </div>
          <div className="card stat">
            <div className="label">Trafic du mois</div>
            <div className="value" style={{ fontSize: 22 }}>
              {formatBytes(stats.traffic_month_bytes)}
            </div>
            <div className="sub">{stats.audit_events} événements d’audit</div>
          </div>
        </div>
      )}

      {isAdmin && health && (
        <div className={`alert ${health.status === 'ok' ? 'ok' : 'warn'}`}>
          Santé : <strong>{health.status}</strong> — base {health.database_ok ? 'OK' : 'KO'}, WireGuard{' '}
          {health.wireguard_ok ? 'OK' : health.wireguard_detail || 'KO'}, migrations en attente :{' '}
          {health.pending_migrations}
          {health.kyros_enabled ? ' — Kyros activé' : ' — Kyros désactivé'}
        </div>
      )}

      <div className="card tight">
        <div className="card-head">
          <strong>Mes appareils récents</strong>
          <Link to="/devices">Tout afficher</Link>
        </div>
        {devices.length === 0 ? (
          <div className="empty">
            <div className="ico">▤</div>
            Aucun appareil. Créez votre premier profil WireGuard.
            <div className="mt">
              <Link className="btn primary" to="/devices/new">
                Ajouter un appareil
              </Link>
            </div>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Nom</th>
                  <th>Adresse VPN</th>
                  <th>Dernier handshake</th>
                  <th>État</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((d) => (
                  <tr key={d.id}>
                    <td>{d.name}</td>
                    <td className="mono">{d.allowed_ip ?? '—'}</td>
                    <td>{formatRelative(d.last_handshake_at)}</td>
                    <td>
                      <StateBadge state={d.effective_state} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}
