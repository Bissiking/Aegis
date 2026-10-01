# Kyros integration (generic OIDC)

Aegis talks to Kyros through a **standard OpenID Connect client**. No Kyros
endpoint, scope, claim name or proprietary API is invented or hard-coded: the
adapter discovers everything from
`{AEGIS_KYROS_ISSUER}/.well-known/openid-configuration`.

Implementation: `internal/auth/kyros.go` (provider) and
`internal/api/handlers_auth.go` (start/callback handlers).

## What is implemented

* Authorization Code flow with **PKCE (S256)** and a `nonce`.
* Issuer/audience/signature/expiry/nonce validation of the `id_token` via
  `github.com/coreos/go-oidc/v3` (JWKS fetched from discovery).
* State stored **hashed** with a 10-minute expiry (`oauth_states` table),
  single use.
* Stable account linkage on the `sub` claim — never on the email address.
* Auto-provisioning: the first successful login creates an Aegis user
  (`role=user`, status active) and links `identities(provider=kyros)`.
* Scopes are configurable; defaults are `openid profile email`.
* Failures never touch WireGuard: if Kyros is unreachable, local login still
  works and tunnels stay up (covered by `TestKyrosOutageDoesNotTouchTunnels`).
* Status endpoint `GET /api/v1/admin/kyros` reports whether discovery
  succeeded.

## What Kyros must provide (currently unknown)

Nothing below was available while building this repository, so none of it is
assumed anywhere in the code. Collect it from the Kyros client registration:

| Value              | Where it goes                                   | Notes |
| ------------------ | ----------------------------------------------- | ----- |
| Issuer URL         | `AEGIS_KYROS_ISSUER`                            | must serve `/.well-known/openid-configuration` |
| Client ID          | `AEGIS_KYROS_CLIENT_ID`                         | public identifier of the Aegis client |
| Client secret      | `AEGIS_KYROS_CLIENT_SECRET`                     | only if Kyros marks the client as confidential |
| Redirect URI       | `AEGIS_KYROS_REDIRECT_URL`                      | must match the registration **exactly**: `https://<your-domain>/api/v1/auth/kyros/callback` |
| Scopes             | `AEGIS_KYROS_SCOPES`                            | space separated; `openid` is mandatory |
| Button label       | `AEGIS_KYROS_BUTTON_LABEL`                      | shown on the login page |
| Is PKCE required?  | —                                               | Aegis always sends `code_challenge_method=S256`; confirm Kyros accepts it |
| Claim: `sub`       | read as the stable identity                     | **must** be present and stable |
| Claim: `email`     | read for display/initial value                  | optional; used only if present |
| Claim: `name`      | read for display name                           | optional |
| Groups/roles claim | **not read**                                     | Aegis has no RBAC mapping yet — see "Not implemented" |
| Logout endpoint    | `auth.KyrosProvider.LogoutURL` is available but not wired to a route | see "Not implemented" |
| Issuer behind a self-signed certificate? | `AEGIS_KYROS_SKIP_ISSUER_CHECK` | development only |

## Configuration

```ini
AEGIS_KYROS_ENABLED=true
AEGIS_KYROS_ISSUER=https://kyros.example.com/realms/aegis
AEGIS_KYROS_CLIENT_ID=aegis-panel
AEGIS_KYROS_CLIENT_SECRET=<from the Kyros registration>
AEGIS_KYROS_REDIRECT_URL=https://vpn.example.com/api/v1/auth/kyros/callback
AEGIS_KYROS_SCOPES=openid profile email
AEGIS_KYROS_BUTTON_LABEL=Se connecter avec Kyros
AEGIS_KYROS_SKIP_ISSUER_CHECK=false
```

Restart the panel after editing. `AEGIS_KYROS_ENABLED=false` (the default)
removes the button entirely and never contacts the IdP.

Local login stays available as long as `AEGIS_LOCAL_AUTH_ENABLED=true`, which
is the recommended safety net while the IdP is being configured.

## Flow

1. `GET /api/v1/auth/kyros/start?next=/devices`
   → state+nonce+verifier created (state hashed, 10 min TTL),
   → 302 to the authorization endpoint from discovery.
2. Kyros authenticates the user and redirects to
   `GET /api/v1/auth/kyros/callback?code=…&state=…`.
3. State is checked (hash lookup, not expired, single use), the code is
   exchanged with the PKCE verifier, the `id_token` is verified.
4. `sub` is looked up in `identities`; on first login the user is created.
5. A normal Aegis session is issued (same cookies, same CSRF rules as local
   login) and the user is redirected to `next` (validated by `safeRedirect`).

## Not implemented (needs a decision or Kyros details)

* **Role/group mapping** from a claims source (e.g. `roles`, `groups`,
  `realm_access`). Aegis currently grants `user` to every Kyros login; only
  the local bootstrap administrator has `admin`.
* **Single logout (RP-initiated)** — `LogoutURL()` exists but no route calls it.
* **Token refresh** — sessions are Aegis sessions; the ID token is not kept
  after the exchange, so long-lived IdP sessions are irrelevant here.
* **Account de-provisioning on IdP side** — suspend/delete must be done in
  Aegis today.
* **Tested against a real Kyros deployment** — no credentials were available.
  Everything above is verified by unit tests against the standard OIDC
  contract, not against your IdP.

## Checklist for the first integration test

1. `curl -s https://kyros.example.com/realms/aegis/.well-known/openid-configuration`
   must return JSON containing `authorization_endpoint`, `token_endpoint`,
   `jwks_uri`, `issuer`.
2. `GET /api/v1/admin/kyros` in Aegis must report `discovery: ok`.
3. `GET /api/v1/auth/kyros/start` must redirect without an error page.
4. After callback, `GET /api/v1/me` must return the new user and
   `has_kyros_identity: true`.
5. `identities` must contain exactly one row for `provider=kyros`.
