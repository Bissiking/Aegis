# Architecture

## Components

```
                      browser
                          │ HTTPS (reverse proxy)
                          ▼
        ┌─────────────────────────────────────────┐
        │  aegis  (Go, user aegis, no capabilities)│
        │  ├─ internal/api      HTTP + JSON        │
        │  ├─ internal/auth     session, CSRF, Kyros v4│
        │  ├─ internal/service  domain rules       │
        │  ├─ internal/store    SQLite (WAL)       │
        │  └─ static SPA        web/dist           │
        └────────────────┬────────────────────────┘
                         │ Unix socket /run/aegis/agent.sock
                         │ JSON request/response, optional shared token
        ┌────────────────▼────────────────────────┐
        │  aegis-agent (root, CAP_NET_ADMIN/RAW)   │
        │  closed op set → wg / tc / sysctl / iptables │
        └────────────────┬────────────────────────┘
                         ▼
                 kernel WireGuard + /etc/wireguard/*.conf
```

Two processes, one boundary. The panel holds no capability that would let it
touch the network; the agent holds no HTTP server and never parses a session.

## Request flow: creating a device

1. `POST /api/v1/me/devices` — session resolved, CSRF checked, rate limited.
2. `service.CreateDevice` checks ownership, active status, policy
   `max_devices`, account expiry and quota.
3. An IP is allocated from the server CIDR (`allocateIP`, first usable host is
   reserved for the interface address).
4. `crypto/wgkeys.Generate()` creates the Curve25519 key pair **in memory**.
   The private key exists only in the returned struct.
5. `wg.Client.AddPeer` sends `add_peer` to the agent; the agent validates
   interface/public key/allowed IP and runs `wg set`.
6. `syncPersistent` rewrites `/etc/wireguard/<iface>.conf` through the agent
   (`sync_config`, atomic temp file + `rename`, mode 0600).
7. `service.Audit` records `device.create` with the public key only.
8. The API responds **once** with the `.conf` text, the QR code and a warning;
   afterwards `GET .../profile` always answers `410 Gone`.

The private key is never persisted: not in SQLite, not in the audit detail,
not in logs, not in `localStorage`/`sessionStorage` (enforced by
`internal/api/repo_security_test.go`).

## Data model

Schema lives in `internal/store/migrations/0001_init.sql`, applied at startup
by an embedded migration runner (forward-only, recorded in `schema_migrations`).

| Table               | Purpose                                                        |
| ------------------- | -------------------------------------------------------------- |
| `access_policies`   | max devices, monthly quota, rate limits, expiry, allowed nets   |
| `users`             | local/Kyros accounts, role, status, quota override              |
| `identities`        | Kyros subject ↔ user link (`provider=kyros`)                    |
| `local_credentials` | Argon2id hash, failed attempts, lockout                         |
| `vpn_servers`       | endpoint, CIDR, DNS, interface, profile TTL                     |
| `devices`           | user-visible device, delivery timestamp, effective state        |
| `wireguard_peers`   | public key, allowed IP, status, counters, suspension reason     |
| `traffic_snapshots` | periodic counter readings with deltas and reset detection       |
| `monthly_usage`     | per-user, per-month accumulator feeding quotas                  |
| `audit_events`      | append-only trail (actor, action, target, correlation id)       |
| `sessions`          | SHA-256 of the cookie token + CSRF token + idle expiry          |
| `oauth_states`      | hashed Kyros state, PKCE verifier, expiry                       |
| `settings`          | key/value (reserved)                                            |

Counters are cumulative; `AddSnapshot` computes deltas and flags a
`counter_reset` when a value decreases (interface restart), so usage can never
go negative. The first snapshot of a peer is a **baseline** (delta 0), which
prevents a peer that already had traffic from being charged retroactively.

## Status model

`devices.status` ∈ `active | revoked`; the peer adds `suspended`
(`suspended_reason` = `quota | expiry | admin`).

`service.ComputeState` merges device status, peer status, policy expiry and
account status into a single `effective_state` used by the UI:
`active`, `suspended`, `expired`, `revoked`, `limit_reached`.

Quota enforcement runs in the collector (`internal/service/collector.go`):

* every `AEGIS_USAGE_INTERVAL` counters are read, deltas accumulated;
* over quota → peer suspended (`reason=quota`), agent `remove_peer`;
* on the next calendar month, if the policy has `auto_reactivate`, suspended
  quota peers are resumed.

## Agent protocol

Transport: Unix socket in production, `tcp://127.0.0.1:<port>` in development
(requires `AEGIS_AGENT_TOKEN`). One JSON request per connection, one response.

```jsonc
// request
{ "op": "add_peer", "token": "...", "interface": "wg0",
  "public_key": "<b64>", "allowed_ip": "10.77.0.2/32",
  "up_kbps": 0, "down_kbps": 0 }

// response
{ "ok": true, "result": { ... }, "error": "" }
```

Closed operation set (`internal/wg/protocol.go`):

| op              | effect                                                        |
| --------------- | ------------------------------------------------------------- |
| `health`        | liveness + `wg` availability                                  |
| `read_state`    | `wg show <iface> dump` for collection                          |
| `add_peer`      | `wg set <iface> peer <k> allowed-ips <ip>` (+ optional `tc`)   |
| `modify_peer`   | change allowed IP / shaping for an existing peer               |
| `remove_peer`    | `wg set <iface> peer <k> remove` (+ `tc` class deletion)       |
| `apply_rate_limit` | egress HTB class for a peer                                 |
| `sync_config`   | rewrite `/etc/wireguard/<iface>.conf` atomically, mode 0600    |

Validation happens **on both sides**: the panel validates before sending, the
agent validates again before executing. Interface names must match
`^[a-zA-Z0-9][a-zA-Z0-9_=+.-]{0,14}$` (no leading dash → cannot be read as a
flag), allowed IPs must be single-host CIDRs, public keys must be 32-byte
base64, and `PostUp`/`PostDown` lines must match a fixed builtin allowlist
(`iptables`, `ip6tables`, `nft`, `sysctl`) with no shell metacharacters.

## Concurrency and integrity

* SQLite opens with `journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`
  and a single writer connection; every mutation runs in a transaction.
* Session cookie carries a random 256-bit token; only its SHA-256 is stored,
  so a database leak cannot be replayed as a session.
* Sessions rotate on every login; the CSRF token is bound to the session and
  sent back in `X-CSRF-Token` (double submit, constant-time compare).
* Login attempts and API calls are throttled per client IP with an in-memory
  sliding window (process-local by design for the MVP).

## Frontend

React 19 + TypeScript, Vite build served by the Go binary.
`AEGIS_FRONTEND_DIR` points at `web/dist`. A CSP is applied per surface:

* `/api/*` → `default-src 'none'` (plus `no-store`)
* SPA → `default-src 'self'`, `script-src 'self'`, `connect-src 'self'`,
  `frame-ancestors 'none'`, no `unsafe-inline` for scripts

The delivered profile lives in a module-level `Map` for the length of the
confirmation view only (`web/src/profileStore.ts`); taking it deletes it.
