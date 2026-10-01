import { useCallback, useEffect, useState } from 'react'
import { api, errorMessage, type VPNServer } from '../api'
import StateBadge from '../components/StateBadge'

const blank = {
  name: '',
  host: '',
  country: '',
  wg_interface: 'wg0',
  wg_port: 51820,
  vpn_cidr: '10.77.0.0/24',
  dns: '1.1.1.1,1.0.0.1',
  endpoint_public: '',
  max_peers: 128,
  profile_ttl_hours: 0,
  full_tunnel: true,
  ipv6_enabled: false,
  is_default: true,
  enabled: true,
}

export default function Servers() {
  const [servers, setServers] = useState<VPNServer[]>([])
  const [form, setForm] = useState({ ...blank })
  const [editing, setEditing] = useState<string | null>(null)
  const [err, setErr] = useState('')

  const load = useCallback(async () => {
    try {
      const r = await api<VPNServer[]>('/api/v1/admin/servers')
      setServers(r.data)
    } catch (e) {
      setErr(errorMessage(e))
    }
  }, [])

  useEffect(() => {
    void load()
    const t = setInterval(() => void load(), 30000)
    return () => clearInterval(t)
  }, [load])

  async function save() {
    setErr('')
    try {
      if (editing) {
        await api(`/api/v1/admin/servers/${editing}`, { method: 'PATCH', json: form })
      } else {
        await api('/api/v1/admin/servers', { method: 'POST', json: form })
      }
      setForm({ ...blank })
      setEditing(null)
      await load()
    } catch (e) {
      setErr(errorMessage(e))
    }
  }

  function edit(s: VPNServer) {
    setEditing(s.id)
    setForm({
      name: s.name,
      host: s.host,
      country: s.country,
      wg_interface: s.wg_interface,
      wg_port: s.wg_port,
      vpn_cidr: s.vpn_cidr,
      dns: s.dns,
      endpoint_public: s.endpoint_public,
      max_peers: s.max_peers,
      profile_ttl_hours: s.profile_ttl_hours,
      full_tunnel: s.full_tunnel,
      ipv6_enabled: s.ipv6_enabled,
      is_default: s.is_default,
      enabled: s.enabled,
    })
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Serveurs VPN</h1>
          <p>
            Chaque VPS est un enregistrement <span className="mono">VPNServer</span> : le modèle est prêt
            pour plusieurs serveurs et plusieurs pays.
          </p>
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
          <h3>{editing ? 'Modifier le serveur' : 'Ajouter un serveur'}</h3>
          <div className="row two">
            <div className="field">
              <label>Nom</label>
              <input required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </div>
            <div className="field">
              <label>Pays</label>
              <input value={form.country} onChange={(e) => setForm({ ...form, country: e.target.value })} />
            </div>
          </div>
          <div className="row two">
            <div className="field">
              <label>Interface</label>
              <input
                value={form.wg_interface}
                onChange={(e) => setForm({ ...form, wg_interface: e.target.value })}
              />
            </div>
            <div className="field">
              <label>Port UDP</label>
              <input
                type="number"
                min={1}
                max={65535}
                value={form.wg_port}
                onChange={(e) => setForm({ ...form, wg_port: Number(e.target.value) })}
              />
            </div>
          </div>
          <div className="row two">
            <div className="field">
              <label>Réseau VPN (CIDR)</label>
              <input value={form.vpn_cidr} onChange={(e) => setForm({ ...form, vpn_cidr: e.target.value })} />
            </div>
            <div className="field">
              <label>DNS client</label>
              <input value={form.dns} onChange={(e) => setForm({ ...form, dns: e.target.value })} />
            </div>
          </div>
          <div className="row two">
            <div className="field">
              <label>Endpoint public (hôte)</label>
              <input
                value={form.endpoint_public}
                onChange={(e) => setForm({ ...form, endpoint_public: e.target.value })}
                placeholder="vpn.exemple.fr"
              />
            </div>
            <div className="field">
              <label>Peers max</label>
              <input
                type="number"
                min={1}
                value={form.max_peers}
                onChange={(e) => setForm({ ...form, max_peers: Number(e.target.value) })}
              />
            </div>
          </div>
          <div className="row two">
            <div className="field">
              <label>Durée de validité du profil (h, 0 = illimitée)</label>
              <input
                type="number"
                min={0}
                value={form.profile_ttl_hours}
                onChange={(e) => setForm({ ...form, profile_ttl_hours: Number(e.target.value) })}
              />
            </div>
            <div className="field">
              <label>État</label>
              <select
                value={form.enabled ? '1' : '0'}
                onChange={(e) => setForm({ ...form, enabled: e.target.value === '1' })}
              >
                <option value="1">Activé</option>
                <option value="0">Désactivé</option>
              </select>
            </div>
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
                checked={form.is_default}
                onChange={(e) => setForm({ ...form, is_default: e.target.checked })}
                style={{ width: 16 }}
              />
              Serveur par défaut
            </label>
            <label className="flex" style={{ gap: 8 }}>
              <input
                type="checkbox"
                checked={form.ipv6_enabled}
                onChange={(e) => setForm({ ...form, ipv6_enabled: e.target.checked })}
                style={{ width: 16 }}
              />
              IPv6 (expérimental)
            </label>
          </div>
          <div className="actions mt">
            <button className="btn primary" type="submit">
              {editing ? 'Enregistrer' : 'Ajouter'}
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
            <strong>Serveurs</strong>
            <button className="btn sm" onClick={() => void load()}>
              Actualiser
            </button>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Nom</th>
                  <th>Réseau</th>
                  <th className="num">Peers</th>
                  <th className="num">Connectés</th>
                  <th>État</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {servers.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <strong>{s.name}</strong> {s.is_default && <span className="badge accent">défaut</span>}
                      <div className="muted" style={{ fontSize: 11 }}>
                        {s.wg_interface} :{s.wg_port} {s.country ? `· ${s.country}` : ''}
                      </div>
                    </td>
                    <td className="mono">{s.vpn_cidr}</td>
                    <td className="num">{s.peer_count}</td>
                    <td className="num">{s.connected}</td>
                    <td>
                      <StateBadge state={s.enabled ? s.status || 'active' : 'suspended'} />
                    </td>
                    <td>
                      <button className="btn sm" onClick={() => edit(s)}>
                        Modifier
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  )
}
