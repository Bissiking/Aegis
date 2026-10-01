import { useCallback, useEffect, useState } from 'react'
import { api, errorMessage, formatBytes, formatDate, type AuditEvent } from '../api'

export default function Audit() {
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [total, setTotal] = useState(0)
  const [q, setQ] = useState('')
  const [action, setAction] = useState('')
  const [offset, setOffset] = useState(0)
  const [err, setErr] = useState('')
  const [detail, setDetail] = useState<AuditEvent | null>(null)
  const limit = 30

  const load = useCallback(async () => {
    try {
      const sp = new URLSearchParams({ limit: String(limit), offset: String(offset) })
      if (q) sp.set('q', q)
      if (action) sp.set('action', action)
      const r = await api<AuditEvent[]>(`/api/v1/admin/audit?${sp}`)
      setEvents(r.data)
      setTotal(Number(r.meta?.total ?? r.data.length))
    } catch (e) {
      setErr(errorMessage(e))
    }
  }, [q, action, offset])

  useEffect(() => {
    void load()
  }, [load])

  const actions = [
    'auth.login_success',
    'auth.login_failed',
    'device.create',
    'device.revoke',
    'device.rotate',
    'profile.deliver',
    'user.create',
    'user.update',
    'user.delete',
    'policy.create',
    'policy.update',
    'server.create',
    'server.update',
    'peer.suspend_quota',
    'peer.resume',
    'peer.expire',
    'access.suspend',
    'access.resume',
  ]

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Journal d’audit</h1>
          <p>Journal append-only, non modifiable depuis l’interface. Aucun secret n’y est inscrit.</p>
        </div>
        <div className="flex">
          <select value={action} onChange={(e) => setAction(e.target.value)} style={{ maxWidth: 230 }}>
            <option value="">Toutes les actions</option>
            {actions.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
          <input
            placeholder="Rechercher…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            style={{ maxWidth: 220 }}
          />
        </div>
      </div>

      {err && <div className="alert error">{err}</div>}

      <div className="card tight">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Horodatage</th>
                <th>Action</th>
                <th>Acteur</th>
                <th>Cible</th>
                <th>IP</th>
                <th>Corrélation</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted">
                    Aucun événement.
                  </td>
                </tr>
              )}
              {events.map((e) => (
                <tr key={e.id} onClick={() => setDetail(e)} style={{ cursor: 'pointer' }}>
                  <td>{formatDate(e.ts)}</td>
                  <td>
                    <span
                      className={`badge ${
                        e.action.includes('failed') || e.action.includes('revoke') || e.action.includes('suspend')
                          ? 'warn'
                          : e.action.includes('login_success')
                            ? 'ok'
                            : 'accent'
                      }`}
                    >
                      {e.action}
                    </span>
                  </td>
                  <td className="mono muted">
                    {e.actor_kind}
                    {e.actor_user_id ? `:${e.actor_user_id.slice(0, 12)}` : ''}
                  </td>
                  <td className="mono truncate">
                    {e.target_kind ? `${e.target_kind}:${e.target_id.slice(0, 16)}` : '—'}
                  </td>
                  <td className="mono">{e.ip}</td>
                  <td className="mono muted truncate">{e.correlation_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {total > limit && (
          <div className="pager">
            <button className="btn sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}>
              ←
            </button>
            <span>
              {offset + 1}–{Math.min(offset + limit, total)} / {total}
            </span>
            <button className="btn sm" disabled={offset + limit >= total} onClick={() => setOffset(offset + limit)}>
              →
            </button>
          </div>
        )}
      </div>

      {detail && (
        <div className="card mt">
          <div className="between">
            <h2 style={{ margin: 0 }}>Événement #{detail.id}</h2>
            <button className="btn sm ghost" onClick={() => setDetail(null)}>
              Fermer
            </button>
          </div>
          <dl className="kv mt">
            <dt>Action</dt>
            <dd className="mono">{detail.action}</dd>
            <dt>Horodatage</dt>
            <dd>{formatDate(detail.ts)}</dd>
            <dt>Acteur</dt>
            <dd className="mono">
              {detail.actor_kind} {detail.actor_user_id}
            </dd>
            <dt>Cible</dt>
            <dd className="mono">
              {detail.target_kind} {detail.target_id}
            </dd>
            <dt>IP / UA</dt>
            <dd className="mono">{detail.ip}</dd>
            <dt>Corrélation</dt>
            <dd className="mono">{detail.correlation_id}</dd>
            <dt>Détail</dt>
            <dd>
              <pre className="conf">{JSON.stringify(JSON.parse(detail.detail || '{}'), null, 2)}</pre>
            </dd>
          </dl>
        </div>
      )}

      <p className="muted mt" style={{ fontSize: 12 }}>
        {formatBytes(total)} entrées indexées.
      </p>
    </>
  )
}
