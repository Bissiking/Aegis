import { useEffect, useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, errorMessage, type VPNServer } from '../api'
import { useAuth } from '../auth'
import { putProfile } from '../profileStore'
import type { CreatedDevice } from '../api'

export default function NewDevice() {
  const { user, refresh } = useAuth()
  const nav = useNavigate()
  const [name, setName] = useState('')
  const [platform, setPlatform] = useState('generic')
  const [serverId, setServerId] = useState('')
  const [servers, setServers] = useState<VPNServer[]>([])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    // Servers are only listed for administrators; regular users get the default.
    api<VPNServer[]>('/api/v1/admin/servers')
      .then((r) => setServers(r.data.filter((s) => s.enabled)))
      .catch(() => setServers([]))
  }, [])

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setErr('')
    setBusy(true)
    try {
      const r = await api<CreatedDevice>('/api/v1/me/devices', {
        method: 'POST',
        json: { name, platform, server_id: serverId },
      })
      putProfile(r.data.device.id, r.data)
      await refresh()
      nav(`/devices/${r.data.device.id}/profile`)
    } catch (e2) {
      setErr(errorMessage(e2))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Ajouter un appareil</h1>
          <p>
            Un peer WireGuard unique sera créé pour cet appareil. La clé privée est générée une seule fois
            et affichée immédiatement.
          </p>
        </div>
      </div>

      <div className="grid cols-2">
        <form className="card" onSubmit={onSubmit}>
          {err && <div className="alert error">{err}</div>}
          <div className="field">
            <label htmlFor="name">Nom de l’appareil</label>
            <input
              id="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Téléphone de Marie"
              required
              maxLength={64}
              autoFocus
            />
            <span className="hint">Visible uniquement par vous et les administrateurs.</span>
          </div>
          <div className="field">
            <label htmlFor="platform">Plateforme</label>
            <select id="platform" value={platform} onChange={(e) => setPlatform(e.target.value)}>
              <option value="generic">Générique</option>
              <option value="android">Android</option>
              <option value="ios">iOS</option>
              <option value="windows">Windows</option>
              <option value="macos">macOS</option>
              <option value="linux">Linux</option>
            </select>
          </div>
          {user?.role === 'admin' && servers.length > 1 && (
            <div className="field">
              <label htmlFor="server">Serveur VPN</label>
              <select id="server" value={serverId} onChange={(e) => setServerId(e.target.value)}>
                <option value="">Serveur par défaut</option>
                {servers.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name} — {s.vpn_cidr}
                  </option>
                ))}
              </select>
            </div>
          )}
          <button className="btn primary block" type="submit" disabled={busy}>
            {busy ? 'Création du peer…' : 'Créer et générer la configuration'}
          </button>
        </form>

        <div className="card">
          <h3>Avant de continuer</h3>
          <div className="alert warn">
            La configuration (clé privée incluse) sera affichée <strong>une seule fois</strong>. Elle ne
            sera jamais stockée sur le serveur et ne pourra pas être récupérée ultérieurement.
          </div>
          <ul className="dim" style={{ paddingLeft: 18, lineHeight: 1.9 }}>
            <li>Enregistrez le fichier <span className="mono">.conf</span> ou scannez le QR code immédiatement.</li>
            <li>Le QR code est compatible avec l’application officielle WireGuard.</li>
            <li>Ensuite, seule la rotation ou la révocation du profil sera possible.</li>
            <li>Chaque appareil possède sa clé et son adresse VPN propres.</li>
            <li>Aucun <span className="mono">::/0</span> n’est annoncé (routage IPv6 non configuré).</li>
          </ul>
        </div>
      </div>
    </>
  )
}
