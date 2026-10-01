import { useEffect, useState } from 'react'
import { api, errorMessage, formatRelative } from '../api'
import StateBadge from '../components/StateBadge'

interface WGServer {
  server_id: string
  name: string
  interface: string
  port: number
  network: string
  status: string
  error?: string
  listen_port?: number
  peer_count?: number
  collected_at?: number
}

export default function WireGuard() {
  const [rows, setRows] = useState<WGServer[]>([])
  const [health, setHealth] = useState<any>(null)
  const [err, setErr] = useState('')

  const load = () => {
    api<{ servers: WGServer[] }>('/api/v1/admin/wireguard')
      .then((r) => setRows(r.data.servers))
      .catch((e) => setErr(errorMessage(e)))
    api<any>('/api/v1/health')
      .then((r) => setHealth(r.data))
      .catch(() => setHealth(null))
  }

  useEffect(() => {
    load()
    const t = setInterval(load, 15000)
    return () => clearInterval(t)
  }, [])

  return (
    <>
      <div className="page-head">
        <div>
          <h1>État WireGuard</h1>
          <p>Lecture de l’interface via l’agent privilégié — le panneau web n’a aucun droit root.</p>
        </div>
        <button className="btn sm" onClick={load}>
          Actualiser
        </button>
      </div>

      {err && <div className="alert error">{err}</div>}

      {health && (
        <div className={`alert ${health.status === 'ok' ? 'ok' : 'warn'}`}>
          Application <strong>{health.status}</strong> — version {health.version} — base{' '}
          {health.database_ok ? 'OK' : 'KO'} — WireGuard {health.wireguard_ok ? 'OK' : (health.wireguard_detail ?? 'KO')}{' '}
          — migrations en attente : {health.pending_migrations}
        </div>
      )}

      <div className="grid cols-2">
        {rows.map((s) => (
          <div className="card" key={s.server_id}>
            <div className="between">
              <strong>{s.name}</strong>
              <StateBadge state={s.status} />
            </div>
            <dl className="kv mt">
              <dt>Interface</dt>
              <dd className="mono">{s.interface}</dd>
              <dt>Écoute</dt>
              <dd className="mono">{s.listen_port ?? s.port}/udp</dd>
              <dt>Réseau</dt>
              <dd className="mono">{s.network}</dd>
              <dt>Peers</dt>
              <dd>{s.peer_count ?? '—'}</dd>
              <dt>Relevé</dt>
              <dd>{formatRelative(s.collected_at)}</dd>
            </dl>
            {s.error && <div className="alert error mt">{s.error}</div>}
          </div>
        ))}
      </div>

      <div className="card mt">
        <h3>Opérations autorisées de l’agent</h3>
        <div className="pill-group">
          <span className="badge muted">add_peer</span>
          <span className="badge muted">modify_peer</span>
          <span className="badge muted">remove_peer</span>
          <span className="badge muted">read_state</span>
          <span className="badge muted">apply_rate_limit</span>
          <span className="badge muted">sync_config</span>
        </div>
        <p className="muted mt" style={{ marginBottom: 0, fontSize: 12 }}>
          Liste fermée. Aucune commande shell n’est construite à partir d’une valeur reçue de
          l’utilisateur.
        </p>
      </div>
    </>
  )
}
