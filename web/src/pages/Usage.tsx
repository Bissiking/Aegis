import { useEffect, useState } from 'react'
import { api, formatBytes, type UsageOverview } from '../api'

export default function Usage({ adminMode = false }: { adminMode?: boolean }) {
  const [mine, setMine] = useState<UsageOverview | null>(null)
  const [rows, setRows] = useState<any[]>([])
  const [month, setMonth] = useState('')
  const [err, setErr] = useState('')

  useEffect(() => {
    api<UsageOverview>('/api/v1/me/usage').then((r) => setMine(r.data)).catch((e) => setErr(e.message))
    if (adminMode) {
      const sp = month ? `?month=${month}` : ''
      api<any[]>(`/api/v1/admin/usage${sp}`)
        .then((r) => setRows(r.data))
        .catch((e) => setErr(e.message))
    }
  }, [adminMode, month])

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Consommation</h1>
          <p>
            Les compteurs WireGuard sont relevés périodiquement ; les deltas négatifs (remise à zéro de
            l’interface) sont neutralisés.
          </p>
        </div>
      </div>

      {err && <div className="alert error">{err}</div>}

      {mine && (
        <>
          <div className="grid cols-4 mb">
            <div className="card stat">
              <div className="label">Période</div>
              <div className="value" style={{ fontSize: 22 }}>
                {mine.month}
              </div>
              <div className="sub">Politique « {mine.policy_name} »</div>
            </div>
            <div className="card stat">
              <div className="label">Reçu</div>
              <div className="value" style={{ fontSize: 22 }}>
                {formatBytes(mine.rx_bytes)}
              </div>
              <div className="sub">téléchargement</div>
            </div>
            <div className="card stat">
              <div className="label">Envoyé</div>
              <div className="value" style={{ fontSize: 22 }}>
                {formatBytes(mine.tx_bytes)}
              </div>
              <div className="sub">envoi</div>
            </div>
            <div className="card stat">
              <div className="label">Total / quota</div>
              <div className="value" style={{ fontSize: 22 }}>
                {formatBytes(mine.total_bytes)}
              </div>
              <div className="sub">{mine.quota_bytes ? `sur ${formatBytes(mine.quota_bytes)}` : 'quota illimité'}</div>
            </div>
          </div>

          {mine.quota_bytes > 0 && (
            <div className="card mb">
              <div className="between">
                <strong>Quota mensuel</strong>
                <span className={mine.quota_used_percent > 90 ? 'badge danger' : 'badge accent'}>
                  {mine.quota_used_percent.toFixed(1)} %
                </span>
              </div>
              <div className="progress" style={{ marginTop: 10 }}>
                <i style={{ width: `${Math.min(100, mine.quota_used_percent)}%` }} />
              </div>
              <div className="muted" style={{ marginTop: 8, fontSize: 12 }}>
                Restant : {formatBytes(mine.remaining_bytes)} — réactivation automatique :{' '}
                {mine.auto_reactivate ? 'oui' : 'non'}
                {mine.up_kbps || mine.down_kbps
                  ? ` — débit limité à ${mine.up_kbps || '∞'} / ${mine.down_kbps || '∞'} kbit/s`
                  : ''}
              </div>
            </div>
          )}

          <div className="card tight mb">
            <div className="card-head">
              <strong>Historique mensuel</strong>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Mois</th>
                    <th className="num">Reçu</th>
                    <th className="num">Envoyé</th>
                    <th className="num">Total</th>
                    <th className="num">%</th>
                  </tr>
                </thead>
                <tbody>
                  {mine.history.length === 0 && (
                    <tr>
                      <td colSpan={5} className="muted">
                        Aucune consommation enregistrée.
                      </td>
                    </tr>
                  )}
                  {mine.history.map((h) => (
                    <tr key={h.month}>
                      <td>{h.month}</td>
                      <td className="num">{formatBytes(h.rx_bytes)}</td>
                      <td className="num">{formatBytes(h.tx_bytes)}</td>
                      <td className="num">{formatBytes(h.total_bytes)}</td>
                      <td className="num">
                        {mine.quota_bytes
                          ? `${((h.total_bytes / mine.quota_bytes) * 100).toFixed(1)} %`
                          : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {adminMode && (
        <div className="card tight">
          <div className="card-head">
            <strong>Consommation par utilisateur</strong>
            <input
              type="month"
              value={month}
              onChange={(e) => setMonth(e.target.value)}
              style={{ maxWidth: 180 }}
            />
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Utilisateur</th>
                  <th className="num">Reçu</th>
                  <th className="num">Envoyé</th>
                  <th className="num">Total</th>
                </tr>
              </thead>
              <tbody>
                {rows.length === 0 && (
                  <tr>
                    <td colSpan={4} className="muted">
                      Aucune donnée pour cette période.
                    </td>
                  </tr>
                )}
                {rows.map((r) => (
                  <tr key={r.user_id + r.month}>
                    <td className="mono">{r.user_id}</td>
                    <td className="num">{formatBytes(r.rx_bytes)}</td>
                    <td className="num">{formatBytes(r.tx_bytes)}</td>
                    <td className="num">{formatBytes(r.total_bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  )
}
