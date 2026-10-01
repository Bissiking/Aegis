import { useState, type FormEvent } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { errorMessage } from '../api'
import { useAuth } from '../auth'

export default function Login() {
  const { login, meta } = useAuth()
  const nav = useNavigate()
  const [params] = useSearchParams()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const oauthError = params.get('error')

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      await login(email, password)
      nav('/', { replace: true })
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const localEnabled = meta?.local_auth_enabled ?? true
  const kyrosEnabled = meta?.kyros.enabled ?? false

  return (
    <div className="auth-wrap">
      <form className="auth-card" onSubmit={onSubmit}>
        <div className="logo">
          <span className="brand">
            <span className="mark">A</span>
            Aegis VPN
          </span>
        </div>

        {oauthError && (
          <div className="alert error">
            {oauthError === 'state'
              ? 'La session d’authentification a expiré. Réessayez.'
              : oauthError === 'denied'
                ? 'Accès refusé par Kyros ou compte non autorisé.'
                : oauthError === 'issuer'
                  ? 'La réponse Kyros provient d’un émetteur inattendu. Contactez un administrateur.'
                  : oauthError === 'unavailable'
                    ? 'Kyros est temporairement indisponible. Vous pouvez utiliser la connexion locale.'
                    : oauthError === 'token'
                      ? 'Le jeton Kyros est invalide ou ne possède pas les autorisations requises.'
                : 'La connexion Kyros a échoué.'}
          </div>
        )}
        {error && <div className="alert error">{error}</div>}

        {localEnabled ? (
          <>
            <div className="field">
              <label htmlFor="email">Adresse e-mail</label>
              <input
                id="email"
                type="email"
                autoComplete="username"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoFocus
              />
            </div>
            <div className="field">
              <label htmlFor="password">Mot de passe</label>
              <input
                id="password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            <button className="btn primary block" type="submit" disabled={busy}>
              {busy ? 'Connexion…' : 'Se connecter'}
            </button>
          </>
        ) : (
          <div className="alert info">La connexion locale est désactivée sur cette instance.</div>
        )}

        {kyrosEnabled && (
          <>
            {localEnabled && (
              <div className="muted" style={{ textAlign: 'center', margin: '16px 0 12px' }}>
                ─ ou ─
              </div>
            )}
            <a className="btn block" href="/api/v1/auth/kyros/start">
              {meta?.kyros.button_label || 'Se connecter avec Kyros'}
            </a>
          </>
        )}

        <p className="muted" style={{ marginTop: 18, fontSize: 12, textAlign: 'center' }}>
          Tunnels WireGuard existants : aucune interruption en cas d’indisponibilité de Kyros.
        </p>
      </form>
    </div>
  )
}
