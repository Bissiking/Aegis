interface Props {
  state: string
}

const MAP: Record<string, { label: string; cls: string }> = {
  active: { label: 'Actif', cls: 'ok' },
  connected_recently: { label: 'Connecté récemment', cls: 'accent' },
  never_connected: { label: 'Jamais connecté', cls: 'muted' },
  expired: { label: 'Expiré', cls: 'warn' },
  suspended: { label: 'Suspendu', cls: 'warn' },
  quota_exceeded: { label: 'Quota dépassé', cls: 'danger' },
  revoked: { label: 'Révoqué', cls: 'danger' },
  online: { label: 'En ligne', cls: 'ok' },
  unreachable: { label: 'Injoignable', cls: 'danger' },
  admin: { label: 'Suspendu (admin)', cls: 'warn' },
  quota: { label: 'Quota dépassé', cls: 'danger' },
}

export default function StateBadge({ state }: Props) {
  const m = MAP[state] ?? { label: state || '—', cls: 'muted' }
  return <span className={`badge ${m.cls}`}>{m.label}</span>
}
