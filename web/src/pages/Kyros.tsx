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
            Client natif Kyros SSO v4 : PAR, Authorization Code avec PKCE S256 et validation RS256/JWKS.
            La découverte utilise <span className="mono">/.well-known/kyros-configuration</span>.
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
                ? 'Intégration Kyros v4 configurée et découverte réussie.'
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
              <dt>Scopes demandés</dt>
              <dd className="mono">{(status.requested_scopes ?? []).join(' ') || '—'}</dd>
              <dt>Scopes requis</dt>
              <dd className="mono">{(status.required_scopes ?? []).join(' ') || '—'}</dd>
              <dt>Audience ressource</dt>
              <dd className="mono">{status.resource_audience || '—'}</dd>
              <dt>Découverte</dt>
              <dd className="mono">{status.discovery ?? '—'}</dd>
              <dt>Authorization endpoint</dt>
              <dd className="mono">{status.authorization_endpoint || '—'}</dd>
              <dt>Token endpoint</dt>
              <dd className="mono">{status.token_endpoint || '—'}</dd>
              <dt>PAR endpoint</dt>
              <dd className="mono">{status.par_endpoint || '—'}</dd>
              <dt>JWKS endpoint</dt>
              <dd className="mono">{status.jwks_endpoint || '—'}</dd>
              <dt>Prêt</dt>
              <dd>{status.ready ? 'oui' : 'non'}</dd>
              <dt>Détail</dt>
              <dd>{status.detail ?? '—'}</dd>
            </dl>
          </div>

          <div className="card mt">
            <h3>Contrat attendu côté Kyros</h3>
            <ol className="dim" style={{ paddingLeft: 20, lineHeight: 1.9, marginBottom: 0 }}>
              <li>Enregistrement d’une application client (client_id / client_secret).</li>
              <li>Application enregistrée explicitement en SSO v4.</li>
              <li>Liste exacte des scopes autorisés et audience ressource Aegis.</li>
              <li>Redirect URI exact : <span className="mono">/api/v1/auth/kyros/callback</span>.</li>
              <li>PAR et PKCE S256 activés.</li>
              <li>Access tokens RS256 publiés par le JWKS v4 avec tous les claims obligatoires.</li>
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
