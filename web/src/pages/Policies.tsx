import { useCallback, useEffect, useState } from 'react'
import { api, errorMessage, formatBytes, type Policy } from '../api'

const blank = {
  name: '',
  description: '',
  max_devices: 5,
  monthly_quota_bytes: 0,
  up_kbps: 0,
  down_kbps: 0,
  expires_at: null as number | null,
  full_tunnel: true,
  allowed_networks: '0.0.0.0/0',
  auto_reactivate: true,
}

export default function Policies() {
  const [policies, setPolicies] = useState<Policy[]>([])
  const [form, setForm] = useState({ ...blank })
  const [editing, setEditing] = useState<string | null>(null)
  const [err, setErr] = useState('')

  const load = useCallback(async () => {
    try {
      const r = await api<Policy[]>('/api/v1/admin/policies')
      setPolicies(r.data)
    } catch (e) {
      setErr(errorMessage(e))
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  async function save() {
    setErr('')
    try {
      if (editing) {
        await api(`/api/v1/admin/policies/${editing}`, { method: 'PATCH', json: form })
      } else {
        await api('/api/v1/admin/policies', { method: 'POST', json: form })
      }
      setForm({ ...blank })
      setEditing(null)
      await load()
    } catch (e) {
      setErr(errorMessage(e))
    }
  }

  async function remove(p: Policy) {
    if (!confirm(`Supprimer la politique « ${p.name} » ?`)) return
    try {
      await api(`/api/v1/admin/policies/${p.id}`, { method: 'DELETE' })
      await load()
    } catch (e) {
      setErr(errorMessage(e))
    }
  }

  function edit(p: Policy) {
    setEditing(p.id)
    setForm({
      name: p.name,
      description: p.description,
      max_devices: p.max_devices,
      monthly_quota_bytes: p.monthly_quota_bytes,
      up_kbps: p.up_kbps,
      down_kbps: p.down_kbps,
      expires_at: p.expires_at,
      full_tunnel: p.full_tunnel,
      allowed_networks: p.allowed_networks,
      auto_reactivate: p.auto_reactivate,
    })
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Politiques & quotas</h1>
          <p>Nombre d’appareils, quota mensuel, débit, expiration et portée réseau.</p>
        </div>
      </div>

      {err && <div className="alert error">{err}</div>}

      <div className="grid cols-2 mb">
        <form
          className="card"
          onSubmit={(e) => {
            e.preventDefault()
            void save()
          }}
        >
          <h3>{editing ? 'Modifier la politique' : 'Nouvelle politique'}</h3>
          <div className="row two">
            <div className="field">
              <label>Nom</label>
              <input required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </div>
            <div className="field">
              <label>Appareils max (0 = illimité)</label>
              <input
                type="number"
                min={0}
                value={form.max_devices}
                onChange={(e) => setForm({ ...form, max_devices: Number(e.target.value) })}
              />
            </div>
          </div>
          <div className="field">
            <label>Description</label>
            <input
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
          </div>
          <div className="row two">
            <div className="field">
              <label>Quota mensuel (octets, 0 = illimité)</label>
              <input
                type="number"
                min={0}
                value={form.monthly_quota_bytes}
                onChange={(e) => setForm({ ...form, monthly_quota_bytes: Number(e.target.value) })}
              />
              <span className="hint">
                {form.monthly_quota_bytes ? `≈ ${formatBytes(form.monthly_quota_bytes)}` : 'aucune limite'}
              </span>
            </div>
            <div className="field">
              <label>Expiration (date, optionnelle)</label>
              <input
                type="date"
                value={form.expires_at ? new Date(form.expires_at * 1000).toISOString().slice(0, 10) : ''}
                onChange={(e) =>
                  setForm({
                    ...form,
                    expires_at: e.target.value ? Math.floor(new Date(e.target.value).getTime() / 1000) : null,
                  })
                }
              />
            </div>
          </div>
          <div className="row two">
            <div className="field">
              <label>Débit montant (kbit/s, 0 = illimité)</label>
              <input
                type="number"
                min={0}
                value={form.up_kbps}
                onChange={(e) => setForm({ ...form, up_kbps: Number(e.target.value) })}
              />
            </div>
            <div className="field">
              <label>Débit descendant (kbit/s, 0 = illimité)</label>
              <input
                type="number"
                min={0}
                value={form.down_kbps}
                onChange={(e) => setForm({ ...form, down_kbps: Number(e.target.value) })}
              />
            </div>
          </div>
          <div className="field">
            <label>Réseaux autorisés</label>
            <input
              value={form.allowed_networks}
              onChange={(e) => setForm({ ...form, allowed_networks: e.target.value })}
            />
            <span className="hint">
              0.0.0.0/0 = accès Internet complet. Aucun ::/0 n’est annoncé tant que l’IPv6 n’est pas
              configuré.
            </span>
          </div>
          <div className="flex" style={{ gap: 22 }}>
            <label className="flex" style={{ gap: 8 }}>
              <input
                type="checkbox"
                checked={form.full_tunnel}
                onChange={(e) => setForm({ ...form, full_tunnel: e.target.checked })}
                style={{ width: 16 }}
              />
              Tunnel complet
            </label>
            <label className="flex" style={{ gap: 8 }}>
              <input
                type="checkbox"
                checked={form.auto_reactivate}
                onChange={(e) => setForm({ ...form, auto_reactivate: e.target.checked })}
                style={{ width: 16 }}
              />
              Réactivation à chaque nouvelle période
            </label>
          </div>
          <div className="actions mt">
            <button className="btn primary" type="submit">
              {editing ? 'Enregistrer' : 'Créer'}
            </button>
            {editing && (
              <button
                type="button"
                className="btn"
                onClick={() => {
                  setEditing(null)
                  setForm({ ...blank })
                }}
              >
                Annuler
              </button>
            )}
          </div>
        </form>

        <div className="card tight">
          <div className="card-head">
            <strong>Politiques existantes</strong>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Nom</th>
                  <th className="num">Appareils</th>
                  <th className="num">Quota</th>
                  <th className="num">Débit</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {policies.map((p) => (
                  <tr key={p.id}>
                    <td>
                      <strong>{p.name}</strong>
                      <div className="muted" style={{ fontSize: 11 }}>
                        {p.description}
                      </div>
                    </td>
                    <td className="num">{p.max_devices || '∞'}</td>
                    <td className="num">{p.monthly_quota_bytes ? formatBytes(p.monthly_quota_bytes) : '∞'}</td>
                    <td className="num">
                      {p.up_kbps || p.down_kbps ? `${p.up_kbps || '∞'} / ${p.down_kbps || '∞'}` : '∞'}
                    </td>
                    <td>
                      <div className="actions">
                        <button className="btn sm" onClick={() => edit(p)}>
                          Modifier
                        </button>
                        <button className="btn sm danger" onClick={() => void remove(p)}>
                          Suppr.
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="card">
        <h3>Limites du MVP</h3>
        <p style={{ marginBottom: 0 }}>
          La limitation de débit repose sur <span className="mono">tc</span> (HTB, sortie serveur
          uniquement) et reste désactivable via <span className="mono">AEGIS_RATE_LIMIT_ENABLED</span>. Le
          quota mensuel est appliqué par suspension automatique du peer, avec réactivation à la période
          suivante si la politique l’autorise.
        </p>
      </div>
    </>
  )
}
