import { useEffect, useState } from 'react'
import { api, errorMessage, formatBytes, formatRelative, type PeerRow } from '../api'
import StateBadge from '../components/StateBadge'

export default function Peers() {
  const [peers, setPeers] = useState<PeerRow[]>([])
  const [err, setErr] = useState('')

  useEffect(() => {
    const load = () =>
      api<PeerRow[]>('/api/v1/admin/peers')
        .then((r) => setPeers(r.data))
        .catch((e) => setErr(errorMessage(e)))
    void load()
    const t = setInterval(load, 30000)
    return () => clearInterval(t)
  }, [])

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Peers WireGuard</h1>
          <p>État en base miroir de l’interface : handshake, trafic cumulé et suspension.</p>
        </div>
        <button className="btn sm" onClick={() => api<PeerRow[]>('/api/v1/admin/peers').then((r) => setPeers(r.data))}>
          Actualiser
        </button>
      </div>

      {err && <div className="alert error">{err}</div>}

      <div className="card tight">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Appareil</th>
                <th>Utilisateur</th>
                <th>Clé publique</th>
                <th>Adresse</th>
                <th>Dernier handshake</th>
                <th className="num">Reçu</th>
                <th className="num">Envoyé</th>
                <th>État</th>
              </tr>
            </thead>
            <tbody>
              {peers.length === 0 && (
                <tr>
                  <td colSpan={8} className="muted">
                    Aucun peer enregistré.
                  </td>
                </tr>
              )}
              {peers.map((p) => (
                <tr key={p.id}>
                  <td>
                    {p.device_name}
                    <div className="muted mono" style={{ fontSize: 11 }}>
                      {p.device_id}
                    </div>
                  </td>
                  <td className="mono muted">{p.user_id}</td>
                  <td className="mono truncate" title={p.public_key}>
                    {p.public_key.slice(0, 16)}…
                  </td>
                  <td className="mono">{p.allowed_ip}</td>
                  <td>{formatRelative(p.last_handshake_at)}</td>
                  <td className="num">{formatBytes(p.rx_bytes)}</td>
                  <td className="num">{formatBytes(p.tx_bytes)}</td>
                  <td>
                    <StateBadge state={p.suspended_reason || p.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}
