import { useCallback, useEffect, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { api, errorMessage, formatBytes, formatRelative, type Device } from '../api'
import StateBadge from '../components/StateBadge'
import { putProfile } from '../profileStore'
import type { CreatedDevice } from '../api'

export default function Devices({ adminMode = false }: { adminMode?: boolean }) {
  const nav = useNavigate()
  const [params, setParams] = useSearchParams()
  const [devices, setDevices] = useState<Device[]>([])
  const [total, setTotal] = useState(0)
  const [q, setQ] = useState(params.get('q') ?? '')
  const [status, setStatus] = useState(params.get('status') ?? '')
  const [offset, setOffset] = useState(0)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState('')
  const limit = 25

  const base = adminMode ? '/api/v1/admin/devices' : '/api/v1/me/devices'

  const load = useCallback(async () => {
    try {
      const sp = new URLSearchParams({ limit: String(limit), offset: String(offset) })
      if (q) sp.set('q', q)
      if (status) sp.set('status', status)
      const r = await api<Device[]>(`${base}?${sp}`)
      setDevices(r.data)
      setTotal(Number(r.meta?.total ?? r.data.length))
    } catch (e) {
      setErr(errorMessage(e))
    }
  }, [base, q, status, offset])

  useEffect(() => {
    void load()
  }, [load])

  async function revoke(d: Device) {
    if (!confirm(`Révoquer « ${d.name} » ? Le peer sera retiré immédiatement de l’interface.`)) return
    setBusy(d.id)
    try {
      await api<void>(`${base}/${d.id}/revoke`, { method: 'POST' })
      await load()
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy('')
    }
  }

  async function rotate(d: Device) {
    if (!confirm(`Rotater les clés de « ${d.name} » ? La configuration actuelle deviendra invalide.`)) return
    setBusy(d.id)
    try {
      const r = await api<CreatedDevice>(`${base}/${d.id}/rotate`, { method: 'POST' })
      putProfile(d.id, r.data)
      nav(`/devices/${d.id}/profile`)
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy('')
    }
  }

  async function remove(d: Device) {
    if (!confirm(`Supprimer définitivement « ${d.name} » ?`)) return
    setBusy(d.id)
    try {
      await api<void>(`${base}/${d.id}`, { method: 'DELETE' })
      await load()
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy('')
    }
  }

  function applyFilters() {
    const next = new URLSearchParams()
    if (q) next.set('q', q)
    if (status) next.set('status', status)
    setParams(next)
    setOffset(0)
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>{adminMode ? 'Tous les appareils' : 'Mes appareils'}</h1>
          <p>
            Chaque appareil possède sa propre clé et sa propre adresse VPN. La révocation d’un appareil
            n’affecte jamais les autres.
          </p>
        </div>
        {!adminMode && (
          <Link className="btn primary" to="/devices/new">
            ＋ Ajouter un appareil
          </Link>
        )}
      </div>

      {err && <div className="alert error">{err}</div>}

      <div className="card tight">
        <div className="card-head">
          <div className="flex" style={{ flex: 1 }}>
            <input
              placeholder="Rechercher (nom, id, utilisateur)…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && applyFilters()}
              style={{ maxWidth: 320 }}
            />
            <select value={status} onChange={(e) => setStatus(e.target.value)} style={{ maxWidth: 190 }}>
              <option value="">Tous les états</option>
              <option value="active">Actifs</option>
              <option value="revoked">Révoqués</option>
            </select>
            <button className="btn sm" onClick={applyFilters}>
              Filtrer
            </button>
          </div>
          <span className="muted">{total} résultat(s)</span>
        </div>

        {devices.length === 0 ? (
          <div className="empty">
            <div className="ico">▤</div>
            Aucun appareil.
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Nom</th>
                  {adminMode && <th>Utilisateur</th>}
                  <th>Plateforme</th>
                  <th>Adresse VPN</th>
                  <th>Clé publique</th>
                  <th>Handshake</th>
                  <th className="num">Reçu</th>
                  <th className="num">Envoyé</th>
                  <th>État</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {devices.map((d) => {
                  const revoked = d.effective_state === 'revoked'
                  return (
                    <tr key={d.id}>
                      <td>
                        <strong>{d.name}</strong>
                        <div className="muted mono" style={{ fontSize: 11 }}>
                          {d.id}
                        </div>
                      </td>
                      {adminMode && <td className="muted mono">{d.user_id}</td>}
                      <td className="dim">{d.platform}</td>
                      <td className="mono">{d.allowed_ip ?? '—'}</td>
                      <td className="mono truncate" title={d.public_key}>
                        {d.public_key ? d.public_key.slice(0, 16) + '…' : '—'}
                      </td>
                      <td>{formatRelative(d.last_handshake_at)}</td>
                      <td className="num">{formatBytes(d.rx_bytes ?? 0)}</td>
                      <td className="num">{formatBytes(d.tx_bytes ?? 0)}</td>
                      <td>
                        <StateBadge state={d.effective_state} />
                      </td>
                      <td>
                        <div className="actions">
                          {!revoked && (
                            <button className="btn sm" disabled={busy === d.id} onClick={() => rotate(d)}>
                              Rotation
                            </button>
                          )}
                          {!revoked && (
                            <button className="btn sm danger" disabled={busy === d.id} onClick={() => revoke(d)}>
                              Révoquer
                            </button>
                          )}
                          <button className="btn sm ghost" disabled={busy === d.id} onClick={() => remove(d)}>
                            Suppr.
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}

        {total > limit && (
          <div className="pager">
            <button className="btn sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}>
              ← Précédent
            </button>
            <span>
              {offset + 1}–{Math.min(offset + limit, total)} / {total}
            </span>
            <button
              className="btn sm"
              disabled={offset + limit >= total}
              onClick={() => setOffset(offset + limit)}
            >
              Suivant →
            </button>
          </div>
        )}
      </div>

      <div className="card mt">
        <h3>Révocation immédiate</h3>
        <p>
          La révocation retire le peer de l’interface active <em>et</em> de la configuration persistante
          (<span className="mono">/etc/wireguard/*.conf</span>) dans la foulée.
        </p>
      </div>

    </>
  )
}
