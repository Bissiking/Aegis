import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { api, errorMessage, formatDate, type Policy, type Role, type User, type UsageOverview } from '../api'
import { useAuth } from '../auth'

const emptyForm = {
  email: '',
  display_name: '',
  role: 'user' as Role,
  password: '',
  policy_id: '',
}

export default function Users() {
  const { user: me } = useAuth()
  const [users, setUsers] = useState<User[]>([])
  const [policies, setPolicies] = useState<Policy[]>([])
  const [total, setTotal] = useState(0)
  const [q, setQ] = useState('')
  const [role, setRole] = useState('')
  const [offset, setOffset] = useState(0)
  const [form, setForm] = useState(emptyForm)
  const [err, setErr] = useState('')
  const [detail, setDetail] = useState<{ user: User; usage: UsageOverview | null } | null>(null)
  const limit = 25

  const load = useCallback(async () => {
    try {
      const sp = new URLSearchParams({ limit: String(limit), offset: String(offset) })
      if (q) sp.set('q', q)
      if (role) sp.set('role', role)
      const r = await api<User[]>(`/api/v1/admin/users?${sp}`)
      setUsers(r.data)
      setTotal(Number(r.meta?.total ?? r.data.length))
    } catch (e) {
      setErr(errorMessage(e))
    }
  }, [q, role, offset])

  useEffect(() => {
    void load()
    api<Policy[]>('/api/v1/admin/policies').then((r) => setPolicies(r.data)).catch(() => undefined)
  }, [load])

  async function create(e: FormEvent) {
    e.preventDefault()
    setErr('')
    try {
      await api('/api/v1/admin/users', { method: 'POST', json: form })
      setForm(emptyForm)
      await load()
    } catch (e2) {
      setErr(errorMessage(e2))
    }
  }

  async function patch(id: string, body: Record<string, unknown>) {
    setErr('')
    try {
      await api(`/api/v1/admin/users/${id}`, { method: 'PATCH', json: body })
      await load()
      if (detail?.user.id === id) await open(id)
    } catch (e) {
      setErr(errorMessage(e))
    }
  }

  async function open(id: string) {
    try {
      const r = await api<{ user: User; usage: UsageOverview | null }>(`/api/v1/admin/users/${id}`)
      setDetail(r.data)
    } catch (e) {
      setErr(errorMessage(e))
    }
  }

  async function suspend(u: User) {
    const path = u.status === 'active' ? 'suspend' : 'resume'
    const label = path === 'suspend' ? 'suspendre' : 'réactiver'
    if (!confirm(`${label.charAt(0).toUpperCase() + label.slice(1)} ${u.email} ?`)) return
    try {
      await api(`/api/v1/admin/users/${u.id}/${path}`, { method: 'POST' })
      await load()
    } catch (e) {
      setErr(errorMessage(e))
    }
  }

  async function remove(u: User) {
    if (!confirm(`Supprimer définitivement ${u.email} et tous ses peers ?`)) return
    try {
      await api(`/api/v1/admin/users/${u.id}`, { method: 'DELETE' })
      setDetail(null)
      await load()
    } catch (e) {
      setErr(errorMessage(e))
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Utilisateurs</h1>
          <p>Comptes Kyros et comptes locaux, rôles, politiques et quotas.</p>
        </div>
      </div>

      {err && <div className="alert error">{err}</div>}

      <div className="grid cols-2 mb">
        <form className="card" onSubmit={create}>
          <h3>Créer un utilisateur</h3>
          <div className="row two">
            <div className="field">
              <label>E-mail</label>
              <input
                type="email"
                required
                value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })}
              />
            </div>
            <div className="field">
              <label>Nom affiché</label>
              <input
                value={form.display_name}
                onChange={(e) => setForm({ ...form, display_name: e.target.value })}
              />
            </div>
          </div>
          <div className="row two">
            <div className="field">
              <label>Rôle</label>
              <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
                <option value="user">Utilisateur</option>
                <option value="admin">Administrateur</option>
              </select>
            </div>
            <div className="field">
              <label>Politique</label>
              <select
                value={form.policy_id}
                onChange={(e) => setForm({ ...form, policy_id: e.target.value })}
              >
                <option value="">Par défaut</option>
                {policies.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="field">
            <label>Mot de passe local (optionnel)</label>
            <input
              type="password"
              autoComplete="new-password"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              placeholder="12 caractères min., 3 classes de caractères"
            />
            <span className="hint">Laisser vide pour un compte Kyros sans mot de passe local.</span>
          </div>
          <button className="btn primary" type="submit">
            Créer
          </button>
        </form>

        <div className="card tight">
          <div className="card-head">
            <div className="flex" style={{ flex: 1 }}>
              <input
                placeholder="Rechercher…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                style={{ maxWidth: 240 }}
              />
              <select value={role} onChange={(e) => setRole(e.target.value)} style={{ maxWidth: 170 }}>
                <option value="">Tous les rôles</option>
                <option value="admin">Administrateurs</option>
                <option value="user">Utilisateurs</option>
              </select>
            </div>
            <span className="muted">{total}</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Utilisateur</th>
                  <th>Rôle</th>
                  <th>Appareils</th>
                  <th>État</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>
                      <a href="#" onClick={(e) => { e.preventDefault(); void open(u.id) }}>
                        {u.display_name || u.email}
                      </a>
                      <div className="muted" style={{ fontSize: 11 }}>
                        {u.email}
                        {u.has_kyros_identity ? ' · Kyros' : ''}
                        {u.has_local_password ? ' · local' : ''}
                      </div>
                    </td>
                    <td>
                      <span className={`badge ${u.role === 'admin' ? 'info' : 'muted'}`}>
                        {u.role === 'admin' ? 'Admin' : 'Utilisateur'}
                      </span>
                    </td>
                    <td className="num">{u.device_count}</td>
                    <td>
                      <span className={`badge ${u.status === 'active' ? 'ok' : 'warn'}`}>
                        {u.status === 'active' ? 'Actif' : 'Suspendu'}
                      </span>
                    </td>
                    <td>
                      <div className="actions">
                        <button className="btn sm" onClick={() => void suspend(u)}>
                          {u.status === 'active' ? 'Suspendre' : 'Réactiver'}
                        </button>
                        {u.id !== me?.id && (
                          <button className="btn sm danger" onClick={() => void remove(u)}>
                            Suppr.
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {total > limit && (
            <div className="pager">
              <button className="btn sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}>
                ←
              </button>
              <span>
                {offset + 1}–{Math.min(offset + limit, total)} / {total}
              </span>
              <button className="btn sm" disabled={offset + limit >= total} onClick={() => setOffset(offset + limit)}>
                →
              </button>
            </div>
          )}
        </div>
      </div>

      {detail && (
        <div className="card">
          <div className="between">
            <h2 style={{ margin: 0 }}>
              {detail.user.display_name || detail.user.email}
            </h2>
            <button className="btn sm ghost" onClick={() => setDetail(null)}>
              Fermer
            </button>
          </div>
          <div className="grid cols-2 mt">
            <dl className="kv">
              <dt>ID</dt>
              <dd className="mono">{detail.user.id}</dd>
              <dt>E-mail</dt>
              <dd>{detail.user.email}</dd>
              <dt>Rôle</dt>
              <dd>
                <select
                  value={detail.user.role}
                  onChange={(e) => void patch(detail.user.id, { role: e.target.value })}
                  style={{ maxWidth: 200 }}
                >
                  <option value="user">Utilisateur</option>
                  <option value="admin">Administrateur</option>
                </select>
              </dd>
              <dt>Créé le</dt>
              <dd>{formatDate(detail.user.created_at)}</dd>
              <dt>Dernière connexion</dt>
              <dd>{formatDate(detail.user.last_login_at)}</dd>
              <dt>Expiration</dt>
              <dd>
                <input
                  type="date"
                  defaultValue={
                    detail.user.expires_at
                      ? new Date(detail.user.expires_at * 1000).toISOString().slice(0, 10)
                      : ''
                  }
                  onChange={(e) => {
                    const v = e.target.value
                    void patch(detail.user.id, { expires_at: v ? Math.floor(new Date(v).getTime() / 1000) : 0 })
                  }}
                  style={{ maxWidth: 200 }}
                />
              </dd>
            </dl>
            <dl className="kv">
              <dt>Politique</dt>
              <dd>
                <select
                  value={detail.user.policy_id ?? ''}
                  onChange={(e) => void patch(detail.user.id, { policy_id: e.target.value })}
                  style={{ maxWidth: 260 }}
                >
                  <option value="">Par défaut</option>
                  {policies.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </select>
              </dd>
              <dt>Quota personnalisé</dt>
              <dd>
                <input
                  type="number"
                  min={0}
                  defaultValue={detail.user.quota_bytes_override ?? 0}
                  onBlur={(e) => void patch(detail.user.id, { quota_bytes: Number(e.target.value) })}
                  style={{ maxWidth: 220 }}
                />
                <div className="hint">octets, 0 = utiliser la politique</div>
              </dd>
              <dt>Consommation du mois</dt>
              <dd>{detail.usage ? `${detail.usage.total_bytes} octets (${detail.usage.month})` : '—'}</dd>
              <dt>Appareils</dt>
              <dd>
                {detail.usage ? `${detail.usage.device_count} / ${detail.usage.max_devices || '∞'}` : '—'}
              </dd>
              <dt>Identités</dt>
              <dd>
                {detail.user.has_kyros_identity ? 'Kyros ' : ''}
                {detail.user.has_local_password ? 'Local' : ''}
                {!detail.user.has_kyros_identity && !detail.user.has_local_password ? 'Aucune' : ''}
              </dd>
            </dl>
          </div>
        </div>
      )}
    </>
  )
}
