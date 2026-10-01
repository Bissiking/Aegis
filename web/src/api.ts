export type Role = 'admin' | 'user'
export type UserStatus = 'active' | 'suspended'

export interface User {
  id: string
  email: string
  display_name: string
  role: Role
  status: UserStatus
  policy_id: string | null
  quota_bytes_override: number | null
  expires_at: number | null
  created_at: number
  updated_at: number
  last_login_at: number | null
  has_local_password: boolean
  has_kyros_identity: boolean
  device_count: number
}

export interface Policy {
  id: string
  name: string
  description: string
  max_devices: number
  monthly_quota_bytes: number
  up_kbps: number
  down_kbps: number
  expires_at: number | null
  full_tunnel: boolean
  allowed_networks: string
  auto_reactivate: boolean
  created_at: number
  updated_at: number
}

export interface VPNServer {
  id: string
  name: string
  host: string
  country: string
  wg_interface: string
  wg_port: number
  vpn_cidr: string
  dns: string
  endpoint_public: string
  max_peers: number
  profile_ttl_hours: number
  full_tunnel: boolean
  ipv6_enabled: boolean
  is_default: boolean
  enabled: boolean
  created_at: number
  updated_at: number
  connected: number
  peer_count: number
  status: string
}

export interface Device {
  id: string
  user_id: string
  server_id: string
  name: string
  platform: string
  status: string
  created_at: number
  updated_at: number
  revoked_at: number | null
  last_seen_at: number | null
  allowed_ip?: string
  public_key?: string
  peer_status?: string
  suspended_reason?: string
  last_handshake_at?: number | null
  rx_bytes?: number
  tx_bytes?: number
  profile_delivered_at?: number | null
  peer_expires_at?: number | null
  effective_state: string
}

export interface DeviceProfile {
  filename: string
  conf: string
  qr_png_base64: string
  one_time_only: boolean
  server_name: string
  allowed_ip: string
  public_key: string
  expires_at: number | null
  dns: string
  endpoint: string
}

export interface CreatedDevice {
  device: Device
  peer: unknown
  profile: DeviceProfile
}

export interface UsageOverview {
  month: string
  rx_bytes: number
  tx_bytes: number
  total_bytes: number
  quota_bytes: number
  quota_used_percent: number
  remaining_bytes: number
  max_devices: number
  device_count: number
  expires_at: number | null
  status: string
  history: { month: string; total_bytes: number; rx_bytes: number; tx_bytes: number }[]
  policy_name: string
  up_kbps: number
  down_kbps: number
  auto_reactivate: boolean
}

export interface AuditEvent {
  id: number
  ts: number
  actor_user_id: string
  actor_kind: string
  action: string
  target_kind: string
  target_id: string
  ip: string
  correlation_id: string
  detail: string
}

export interface Stats {
  users: number
  admins: number
  devices: number
  active_peers: number
  suspended_peers: number
  revoked_peers: number
  traffic_month_bytes: number
  audit_events: number
}

export interface PeerRow {
  id: string
  device_id: string
  device_name: string
  user_id: string
  public_key: string
  allowed_ip: string
  status: string
  suspended_reason: string
  last_handshake_at: number | null
  rx_bytes: number
  tx_bytes: number
  created_at: number
}

export interface SessionInfo {
  user: User
  csrf_token: string
  session_expires: number
}

export interface Meta {
  local_auth_enabled: boolean
  kyros: { enabled: boolean; button_label: string }
  csrf_cookie: string
  version: string
  environment: string
}

export interface ApiError {
  code: string
  message: string
  details?: Record<string, unknown>
  status: number
  request_id?: string
}

let csrfToken = ''

export function setCsrfToken(token: string) {
  csrfToken = token
}

export function getCsrfToken() {
  return csrfToken
}

function readCookie(name: string): string {
  if (typeof document === 'undefined') return ''
  const m = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'))
  return m ? decodeURIComponent(m[1]) : ''
}

export async function api<T>(
  path: string,
  init: RequestInit & { json?: unknown } = {},
): Promise<{ data: T; meta?: Record<string, unknown> }> {
  const method = init.method ?? 'GET'
  const headers = new Headers(init.headers)
  let body = init.body
  if (init.json !== undefined) {
    headers.set('Content-Type', 'application/json')
    body = JSON.stringify(init.json)
  }
  if (method !== 'GET' && method !== 'HEAD') {
    const token = csrfToken || readCookie('aegis_csrf')
    if (token) headers.set('X-CSRF-Token', token)
  }
  const res = await fetch(path, { method, headers, body, credentials: 'same-origin' })
  if (res.status === 204) return { data: undefined as T }
  const text = await res.text()
  let parsed: any = null
  try {
    parsed = text ? JSON.parse(text) : null
  } catch {
    parsed = null
  }
  if (!res.ok) {
    const err = parsed?.error
    const e: ApiError = {
      code: err?.code ?? 'http_error',
      message: err?.message ?? `Erreur ${res.status}`,
      details: err?.details,
      status: res.status,
      request_id: parsed?.request_id,
    }
    throw e
  }
  return { data: parsed?.data as T, meta: parsed?.meta }
}

export function errorMessage(e: unknown): string {
  if (e && typeof e === 'object' && 'message' in e) return String((e as any).message)
  return 'Une erreur est survenue.'
}

export function formatBytes(n: number): string {
  if (!n || n <= 0) return '0 o'
  const units = ['o', 'Ko', 'Mo', 'Go', 'To']
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1)
  const v = n / Math.pow(1024, i)
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`
}

export function formatDate(ts?: number | null): string {
  if (!ts) return '—'
  return new Date(ts * 1000).toLocaleString('fr-FR', {
    dateStyle: 'short',
    timeStyle: 'short',
  })
}

export function formatRelative(ts?: number | null): string {
  if (!ts) return 'jamais'
  const diff = Math.floor(Date.now() / 1000) - ts
  if (diff < 60) return 'à l’instant'
  if (diff < 3600) return `il y a ${Math.floor(diff / 60)} min`
  if (diff < 86400) return `il y a ${Math.floor(diff / 3600)} h`
  if (diff < 86400 * 30) return `il y a ${Math.floor(diff / 86400)} j`
  return formatDate(ts)
}
