import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, errorMessage, formatDate } from '../api'
import { peekProfile, putProfile, takeProfile } from '../profileStore'
import type { CreatedDevice } from '../api'

export default function ProfileDelivery() {
  const { id = '' } = useParams()
  const [payload, setPayload] = useState<CreatedDevice | undefined>(() => peekProfile(id))
  const [err, setErr] = useState('')
  const [dismissed, setDismissed] = useState(false)
  const [busy, setBusy] = useState(false)

  async function rotate() {
    if (!confirm('Rotater les clés ? La configuration actuelle deviendra immédiatement invalide.')) return
    setBusy(true)
    setErr('')
    try {
      const r = await api<CreatedDevice>(`/api/v1/me/devices/${id}/rotate`, { method: 'POST' })
      putProfile(id, r.data)
      setPayload(r.data)
      setDismissed(false)
    } catch (e) {
      setErr(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  function download() {
    if (!payload) return
    const blob = new Blob([payload.profile.conf], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = payload.profile.filename
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  function confirmSaved() {
    takeProfile(id)
    setDismissed(true)
    setPayload(undefined)
  }

  if (!payload || dismissed) {
    return (
      <>
        <div className="page-head">
          <div>
            <h1>Configuration déjà délivrée</h1>
            <p>Cette configuration a été affichée une seule fois et n’est plus disponible.</p>
          </div>
        </div>
        <div className="card">
          <div className="alert warn">
            Pour des raisons de sécurité, Aegis ne conserve jamais la clé privée d’un client. Si vous avez
            perdu la configuration, effectuez une <strong>rotation du profil</strong> pour en générer une
            nouvelle (l’ancienne deviendra invalide).
          </div>
          {err && <div className="alert error">{err}</div>}
          <div className="actions">
            <button className="btn primary" disabled={busy} onClick={rotate}>
              {busy ? 'Rotation…' : 'Rotater le profil'}
            </button>
            <Link className="btn" to="/devices">
              Retour aux appareils
            </Link>
          </div>
        </div>
      </>
    )
  }

  const p = payload.profile

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Configuration de « {payload.device.name} »</h1>
          <p>Adresse VPN {p.allowed_ip} — serveur {p.server_name}</p>
        </div>
      </div>

      <div className="alert error">
        <strong>Sauvegardez-la maintenant.</strong> Cette clé privée ne sera <strong>jamais</strong> réaffichée.
        Fermez cette page uniquement après avoir téléchargé le fichier ou scanné le QR code.
      </div>

      <div className="card">
        <div className="profile-grid">
          <div>
            <div className="qr-box">
              <img
                alt="QR code de configuration WireGuard"
                src={`data:image/png;base64,${p.qr_png_base64}`}
                width={232}
                height={232}
              />
            </div>
            <p className="muted" style={{ marginTop: 10, fontSize: 12 }}>
              Ouvrez l’application WireGuard puis « Importer » → « Scan from QR code ».
            </p>
          </div>
          <div>
            <h3>Fichier de configuration</h3>
            <pre className="conf">{p.conf}</pre>
            <div className="actions mt">
              <button className="btn primary" onClick={download}>
                ⬇ Télécharger {p.filename}
              </button>
              <button className="btn" onClick={() => void navigator.clipboard?.writeText(p.conf)}>
                Copier
              </button>
              <Link className="btn ghost" to="/devices">
                Retour
              </Link>
            </div>
            <dl className="kv mt">
              <dt>Clé publique</dt>
              <dd className="mono">{p.public_key}</dd>
              <dt>Endpoint</dt>
              <dd className="mono">{p.endpoint || '—'}</dd>
              <dt>DNS</dt>
              <dd className="mono">{p.dns}</dd>
              <dt>Expiration du profil</dt>
              <dd>{formatDate(p.expires_at)}</dd>
            </dl>
            <div className="actions mt">
              <button className="btn" onClick={confirmSaved}>
                J’ai sauvegardé ma configuration
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  )
}
