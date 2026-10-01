# HTTP API

Base path: `/api/v1`. The machine-readable contract lives in
`internal/api/openapi.yaml`, served at `GET /api/v1/openapi.yaml`.

## Envelopes

Success:

```json
{ "data": { }, "meta": { }, "request_id": "…" }
```

`meta` is present on list endpoints (`total`, `limit`, `offset`).

Failure:

```json
{ "error": { "code": "forbidden", "message": "…", "details": { } },
  "request_id": "…" }
```

### Error codes

| HTTP | `code`             | Meaning                                          |
| ---- | ------------------ | ------------------------------------------------ |
| 400  | `invalid`          | malformed JSON / unknown field / bad value        |
| 400  | `validation_failed`| field-level validation (`details.field`)          |
| 400  | `password_policy`  | password does not meet the policy                 |
| 401  | `unauthorized`     | no session or bad credentials                     |
| 403  | `forbidden`        | authenticated but not allowed (or not owner)      |
| 403  | `csrf_failed`      | missing/incorrect `X-CSRF-Token`                  |
| 404  | `not_found`        | unknown endpoint or resource                      |
| 409  | `conflict`         | already exists                                    |
| 409  | `quota_exceeded`   | device count or monthly quota reached             |
| 410  | `gone`             | the profile was already delivered / rotated away  |
| 429  | `rate_limited`     | login or API throttle                             |
| 500  | `internal_error`   | unexpected failure (details are never leaked)     |
| 503  | `unavailable`      | agent unreachable                                 |

## Authentication

Two mechanisms:

* **Local** — `POST /api/v1/auth/login` with `{email, password}`. On success
  the server sets two cookies (`aegis_session` HttpOnly, `aegis_csrf` readable
  by the SPA) and returns `csrf_token` in the body.
* **Kyros SSO v4** — `GET /api/v1/auth/kyros/start` creates a PAR and redirects
  to Kyros; `GET /api/v1/auth/kyros/callback` validates code+PKCE and the RS256
  access token before starting a local Aegis session.

Every **non-GET** request on an authenticated route must send
`X-CSRF-Token: <csrf_token>`. `GET`, `HEAD` and `OPTIONS` are exempt.

## Routes

### Public

| Method | Path                        | Notes                                  |
| ------ | --------------------------- | -------------------------------------- |
| GET    | `/api/v1/health`            | 503 when a dependency is down          |
| GET    | `/api/v1/meta`              | login page capabilities (Kyros, CSRF…) |
| POST   | `/api/v1/auth/login`        | local login, throttled per IP          |
| POST   | `/api/v1/auth/logout`       | destroys the session                   |
| GET    | `/api/v1/auth/kyros/start`  | redirect to the IdP                    |
| GET    | `/api/v1/auth/kyros/callback`| Kyros SSO v4 callback                  |
| GET    | `/api/v1/openapi.yaml`      | OpenAPI 3 document                     |

### Authenticated (session required)

| Method | Path                              | Notes                                    |
| ------ | --------------------------------- | ---------------------------------------- |
| GET    | `/api/v1/auth/session`            | user + `csrf_token` + expiry             |
| GET    | `/api/v1/me`                      | current user                             |
| PATCH  | `/api/v1/me`                      | **only** `display_name`, `password`, `current_password` |
| POST   | `/api/v1/me/password`             | `{current, new}`                         |
| GET    | `/api/v1/me/usage`                | monthly usage overview                   |
| GET    | `/api/v1/me/devices`              | caller's devices                         |
| POST   | `/api/v1/me/devices`              | provision; returns the profile **once**  |
| GET    | `/api/v1/me/devices/{id}`         | one device (owner or admin)              |
| GET    | `/api/v1/me/devices/{id}/profile` | always `410 Gone`                        |
| POST   | `/api/v1/me/devices/{id}/revoke`  | 204, removes the peer                    |
| POST   | `/api/v1/me/devices/{id}/rotate`  | new keys, returns a new profile          |
| DELETE | `/api/v1/me/devices/{id}`         | 204, deletes device + peer               |

### Administrator

| Method | Path                                        |
| ------ | ------------------------------------------- |
| GET    | `/api/v1/admin/stats`                       |
| GET/POST | `/api/v1/admin/users`                     |
| GET/PATCH/DELETE | `/api/v1/admin/users/{id}`            |
| POST   | `/api/v1/admin/users/{id}/suspend`          |
| POST   | `/api/v1/admin/users/{id}/resume`           |
| GET/POST | `/api/v1/admin/policies`                 |
| PATCH/DELETE | `/api/v1/admin/policies/{id}`          |
| GET/POST | `/api/v1/admin/servers`                  |
| PATCH  | `/api/v1/admin/servers/{id}`                |
| GET    | `/api/v1/admin/devices`                     |
| POST   | `/api/v1/admin/devices/{id}/revoke`         |
| POST   | `/api/v1/admin/devices/{id}/rotate`         |
| GET    | `/api/v1/admin/peers`                       |
| GET    | `/api/v1/admin/wireguard`                   |
| GET    | `/api/v1/admin/usage`                       |
| GET    | `/api/v1/admin/audit`                       |
| GET    | `/api/v1/admin/kyros`                       |
| GET    | `/api/v1/admin/sessions/prune`              |

## Profile delivery

`POST /api/v1/me/devices` and `POST /api/v1/me/devices/{id}/rotate` are the
**only** responses that contain a configuration:

```json
{
  "device": { "id": "dev_…", "name": "laptop", "status": "active" },
  "peer":   { "public_key": "…", "allowed_ip": "10.77.0.2/32", "status": "active" },
  "profile": {
    "filename": "laptop.conf",
    "conf": "[Interface]\nPrivateKey = …",
    "qr_png_base64": "…",
    "one_time_only": true,
    "server_name": "primary",
    "allowed_ip": "10.77.0.2/32",
    "public_key": "…",
    "expires_at": null,
    "dns": "1.1.1.1",
    "endpoint": "vpn.example.com:51820"
  }
}
```

`GET …/profile` never returns the key again — it answers `410` so clients can
distinguish "lost configuration" from "not found" and trigger a rotation.

## Rate limits

* `AEGIS_LOGIN_RATE_LIMIT` (default 10/min) applies to login, logout, meta,
  health and the Kyros endpoints, keyed by client IP.
* `AEGIS_API_RATE_LIMIT` (default 300/min) applies to every authenticated and
  admin route, keyed by client IP.

Both are answered with `429` and `code: rate_limited`.

## Objects

Timestamps are Unix seconds (UTC). IDs are opaque prefixed strings
(`dev_…`, `usr_…`, `srv_…`, `pol_…`, `per_…`) and must not be parsed by
clients. Sizes are bytes. `GET` list endpoints accept `q`, `status`, `limit`
(capped at 500) and `offset`.
