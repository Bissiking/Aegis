# Aegis

Aegis is a self-hosted control panel for a WireGuard VPN server: it manages
users, devices (peers), quotas and audit trails, and delivers each client its
configuration exactly once.

The stack is deliberately small:

| Layer        | Process                         | Privileges                          |
| ------------ | ------------------------------- | ----------------------------------- |
| Web panel    | `aegis` (Go + SQLite)           | unprivileged user `aegis`, no caps  |
| Agent        | `aegis-agent` (Go)              | root, only `CAP_NET_ADMIN/RAW`       |
| Frontend     | React SPA, served by `aegis`    | static files only                   |
| Identity     | local admin + native Kyros SSO v4 | —                                |

The panel never executes a command. Every privileged operation (adding a peer
to `wg`, rewriting `/etc/wireguard`, shaping with `tc`) travels over a Unix
socket to `aegis-agent`, which validates the request against a **closed set of
six operations** and execs `wg`/`tc`/`sysctl`/`iptables` with fixed arguments —
never a shell.

---

## Quick start (development)

Requirements: Go 1.27+, Node 22+.

```bash
git clone <repo> && cd aegis

# backend
go build ./...
go vet ./cmd/... ./internal/...
go test  ./cmd/... ./internal/...

# frontend
cd web && npm ci && npm run lint && npm run typecheck && npm test && npm run build
cd ..

# run the panel with an in-memory WireGuard backend (no root needed)
$env:AEGIS_WG_BACKEND='fake'          # PowerShell; export AEGIS_WG_BACKEND=fake on bash
$env:AEGIS_ENV='development'
$env:AEGIS_LISTEN='127.0.0.1:18080'
$env:AEGIS_DATABASE_PATH="$PWD/aegis-dev.db"
$env:AEGIS_FRONTEND_DIR="$PWD/web/dist"
$env:AEGIS_BOOTSTRAP_USER='admin@example.org'
$env:AEGIS_BOOTSTRAP_PASSWORD='Change-Me-Now!23'
$env:AEGIS_COOKIE_SECURE='false'
$env:AEGIS_SESSION_SECRET='dev-secret-dev-secret-dev-secret-123456'
go run ./cmd/aegis
```

Open <http://127.0.0.1:18080> and sign in with the bootstrap account.

`AEGIS_WG_BACKEND=fake` replaces the agent client with an in-memory
implementation: the whole HTTP surface (including device creation and profile
delivery) works without root and without WireGuard.

To run the real thing (root + WireGuard), use the installer:

```bash
chmod +x deploy/install.sh scripts/*.sh
sudo ./deploy/install.sh
```

See [docs/deployment.md](docs/deployment.md).

---

## Repository layout

```
cmd/aegis/            web panel entry point (never root)
cmd/aegis-agent/      privileged agent: only place allowed to exec processes
internal/api/         HTTP router, middleware, handlers, OpenAPI, security tests
internal/auth/        Argon2id passwords, sessions/CSRF/rate limit, Kyros v4
internal/config/      environment + optional key=value file
internal/crypto/      WireGuard X25519 key generation
internal/service/     business logic (devices, policies, quotas, collector)
internal/store/       SQLite persistence, embedded migrations, audit log
internal/wg/          agent protocol, validation, client, test double
web/                  React + TypeScript SPA
deploy/               installer and systemd units
scripts/              backup / restore / update
docs/                 architecture, security, deployment, API, Kyros
```

### Main entry points

| Concern                            | File                                          |
| ---------------------------------- | --------------------------------------------- |
| HTTP routes                        | `internal/api/router.go`                      |
| Auth, CSRF, rate limit middleware  | `internal/api/middleware.go`                  |
| Login / session / Kyros flow       | `internal/api/handlers_auth.go`               |
| Device lifecycle + one-time profile| `internal/api/handlers_devices.go`            |
| Administration (users, peers, WG)  | `internal/api/handlers_admin.go`              |
| Business rules and policy engine   | `internal/service/*.go`                       |
| Peer/provisioning state            | `internal/service/devices.go`                 |
| Usage collection + quota suspend   | `internal/service/collector.go`               |
| Database schema                    | `internal/store/migrations/0001_init.sql`     |
| Agent wire protocol                | `internal/wg/protocol.go`                     |
| Agent command execution            | `cmd/aegis-agent/main.go`                     |

---

## Commands

### Backend

```bash
go build ./...                    # compile everything
go vet ./cmd/... ./internal/...   # static analysis (note: ./... also picks up web/node_modules)
gofmt -l ./cmd ./internal          # formatting check
go test ./cmd/... ./internal/...  # unit + integration + repo-wide security tests
go test -count=1 -race ./cmd/... ./internal/...
```

### Frontend (`web/`)

```bash
npm ci
npm run lint          # eslint, zero warnings allowed
npm run typecheck     # tsc -b
npm test              # vitest
npm run build         # typecheck + vite build -> web/dist
npm run dev           # dev server on :5173, proxies /api to :8080
```

### Production build

```bash
cd web && npm ci && npm run build && cd ..
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o build/aegis ./cmd/aegis
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o build/aegis-agent ./cmd/aegis-agent
```

Both binaries are pure Go (`modernc.org/sqlite`, no CGO) and cross-compile.

---

## Tests

| Suite                                                | Command                                             |
| ---------------------------------------------------- | --------------------------------------------------- |
| Store, auth (Argon2id/CSRF), service, WireGuard protocol | `go test ./internal/...`                        |
| HTTP integration: login, CSRF, IDOR, privilege escalation, rate limit, 410 profile, audit, headers | `go test ./internal/api/...` |
| Repo-wide static security rules (no `os/exec` outside the agent, no browser storage in the SPA, no committed keys) | included in `go test ./internal/api/...` |
| Frontend units (CSRF header, error envelope, one-time profile store) | `cd web && npm test`                     |

Not covered by tests (documented, not claimed): TLS termination, the real
`wg`/`tc` binaries against a live kernel, and the actual Kyros IdP (no
credentials available).

---

## Documentation

| Document                                          | Contents                                          |
| ------------------------------------------------- | -------------------------------------------------- |
| [docs/architecture.md](docs/architecture.md)      | components, data flow, schema, agent protocol      |
| [docs/security.md](docs/security.md)              | threat model, mitigations, residual risks          |
| [docs/deployment.md](docs/deployment.md)          | install, reverse proxy, systemd, upgrades          |
| [docs/api.md](docs/api.md)                        | HTTP surface, envelopes, error codes              |
| [docs/kyros-integration.md](docs/kyros-integration.md) | native Kyros SSO v4 contract and deployment checks |
| [docs/backup-restore.md](docs/backup-restore.md)  | backup, restore, disaster recovery                 |
