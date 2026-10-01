import { useState, type FormEvent } from 'react'
import { api, errorMessage, formatDate } from '../api'
import { useAuth } from '../auth'

export default function Settings() {
  const { user, meta, refresh } = useAuth()
  const [displayName, setDisplayName] = useState(user?.display_name ?? '')
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')

  async function saveName(e: FormEvent) {
    e.preventDefault()
    setErr('')
    setMsg('')
    try {
      await api('/api/v1/me', { method: 'PATCH', json: { display_name: displayName } })
      await refresh()
      setMsg('Profil mis à jour.')
    } catch (e2) {
      setErr(errorMessage(e2))
    }
  }

  async function changePassword(e: FormEvent) {
    e.preventDefault()
    setErr('')
    setMsg('')
    try {
      await api('/api/v1/me/password', { method: 'POST', json: { current, new: next } })
      setCurrent('')
      setNext('')
      setMsg('Mot de passe modifié.')
    } catch (e2) {
      setErr(errorMessage(e2))
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Paramètres</h1>
          <p>Profil et sécurité de votre compte.</p>
        </div>
      </div>

      {msg && <div className="alert ok">{msg}</div>}
      {err && <div className="alert error">{err}</div>}

      <div className="grid cols-2">
        <form className="card" onSubmit={saveName}>
          <h3>Profil</h3>
          <dl className="kv mb">
            <dt>Identifiant</dt>
            <dd className="mono">{user?.id}</dd>
            <dt>E-mail</dt>
            <dd>{user?.email}</dd>
            <dt>Rôle</dt>
            <dd>{user?.role === 'admin' ? 'Administrateur' : 'Utilisateur'}</dd>
            <dt>Compte</dt>
            <dd>
              {user?.has_kyros_identity ? 'Kyros' : ''}
              {user?.has_kyros_identity && user?.has_local_password ? ' + ' : ''}
              {user?.has_local_password ? 'Local' : ''}
              {!user?.has_kyros_identity && !user?.has_local_password ? 'Aucune' : ''}
            </dd>
            <dt>Créé le</dt>
            <dd>{formatDate(user?.created_at)}</dd>
          </dl>
          <div className="field">
            <label>Nom affiché</label>
            <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
          </div>
          <button className="btn primary" type="submit">
            Enregistrer
          </button>
        </form>

        <form className="card" onSubmit={changePassword}>
          <h3>Mot de passe</h3>
          {user?.has_local_password ? (
            <>
              <div className="field">
                <label>Mot de passe actuel</label>
                <input
                  type="password"
                  autoComplete="current-password"
                  value={current}
                  onChange={(e) => setCurrent(e.target.value)}
                  required
                />
              </div>
              <div className="field">
                <label>Nouveau mot de passe</label>
                <input
                  type="password"
                  autoComplete="new-password"
                  value={next}
                  onChange={(e) => setNext(e.target.value)}
                  required
                />
                <span className="hint">
                  12 caractères minimum, 3 classes parmi minuscules / majuscules / chiffres / symboles.
                </span>
              </div>
              <button className="btn primary" type="submit">
                Changer le mot de passe
              </button>
            </>
          ) : (
            <div className="alert info">
              Ce compte ne possède pas de mot de passe local (connexion via Kyros).
            </div>
          )}

          <div className="mt">
            <h3>Instance</h3>
            <dl className="kv">
              <dt>Version</dt>
              <dd>{meta?.version}</dd>
              <dt>Environnement</dt>
              <dd>{meta?.environment}</dd>
              <dt>Auth locale</dt>
              <dd>{meta?.local_auth_enabled ? 'Activée' : 'Désactivée'}</dd>
              <dt>Kyros</dt>
              <dd>{meta?.kyros.enabled ? 'Activé' : 'Désactivé'}</dd>
            </dl>
          </div>
        </form>
      </div>
    </>
  )
}
