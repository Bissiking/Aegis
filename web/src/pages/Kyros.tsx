import { useEffect, useState } from 'react'
import { api, errorMessage } from '../api'

export default function Kyros() {
  const [status, setStatus] = useState<any>(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    api<any>('/api/v1/admin/kyros')
      .then((r) => setStatus(r.data))
      .catch((e) => setErr(errorMessage(e)))
  }, [])

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Intégration Kyros</h1>
          <p>
            Adaptateur OIDC générique (Authorization Code + PKCE). Aucun endpoint, scope ou claim n’est
            inventé : tout provient de la découverte <span className="mono">/.well-known/openid-configuration</span>.
          </p>
        </div>
      </div>

      {err && <div className="alert error">{err}</div>}

      {!status && !err && <div className="card muted">Chargement…</div>}

      {status && (
        <>
          <div className={`alert ${status.enabled && status.ready ? 'ok' : status.enabled ? 'warn' : 'info'}`}>
            {status.enabled
              ? status.ready
                ? 'Adaptateur configuré et découverte OIDC réussie.'
                : `Configuré mais non prêt : ${status.detail ?? 'découverte échouée'}`
              : 'Connexion Kyros désactivée par configuration (AUTH_PROVIDER n’est pas défini sur kyros).'}
          </div>

          <div className="card">
            <h3>Paramètres effectifs (aucun secret affiché)</h3>
            <dl className="kv">
              <dt>Activé</dt>
              <dd>{status.enabled ? 'oui' : 'non'}</dd>
              <dt>Issuer</dt>
              <dd className="mono">{status.issuer || '—'}</dd>
              <dt>Client ID</dt>
              <dd className="mono">{status.client_id || '—'}</dd>
              <dt>Redirect URI</dt>
              <dd className="mono">{status.redirect_url || '—'}</dd>
              <dt>Scopes</dt>
              <dd className="mono">{(status.scopes ?? []).join(' ') || '—'}</dd>
              <dt>Découverte</dt>
              <dd className="mono">{status.discovery ?? '—'}</dd>
              <dt>Authorization endpoint</dt>
              <dd className="mono">{status.authorization_endpoint || '—'}</dd>
              <dt>Token endpoint</dt>
              <dd className="mono">{status.token_endpoint || '—'}</dd>
              <dt>Prêt</dt>
              <dd>{status.ready ? 'oui' : 'non'}</dd>
              <dt>Détail</dt>
              <dd>{status.detail ?? '—'}</dd>
            </dl>
          </div>

          <div className="card mt">
            <h3>Paramètres restant à fournir côté Kyros</h3>
            <ol className="dim" style={{ paddingLeft: 20, lineHeight: 1.9, marginBottom: 0 }}>
              <li>Enregistrement d’une application client (client_id / client_secret).</li>
              <li>Liste exacte des scopes autorisés (ne rien inventer côté Aegis).</li>
              <li>Redirect URI exact : <span className="mono">/api/v1/auth/kyros/callback</span>.</li>
              <li>Claim portant l’identifiant stable (généralement <span className="mono">sub</span>).</li>
              <li>Activation de PKCE S256 et du claim <span className="mono">nonce</span>.</li>
              <li>Éventuel endpoint de déconnexion (RSO) s’il est publié dans la découverte.</li>
            </ol>
            <p className="muted mt" style={{ fontSize: 12, marginBottom: 0 }}>
              Le détail complet figure dans <span className="mono">docs/kyros-integration.md</span>.
            </p>
          </div>
        </>
      )}
    </>
  )
}
