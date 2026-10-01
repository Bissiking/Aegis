# Security

## Threat model

| Asset                              | Adversary                                   |
| ---------------------------------- | -------------------------------------------- |
| WireGuard client private keys      | anyone reading the DB, logs, browser storage |
| VPN traffic / peer configuration   | another tenant of the panel                   |
| Server (root)                      | a remote attacker reaching the panel          |
| Session/CSRF tokens                | cross-site request forgery, cookie theft      |
| Admin credentials                  | password spraying, brute force                |

Out of scope for the MVP: a compromised kernel, a compromised build chain,
and physical access to the host.

## Design decisions

**Least privilege, split in two.** `aegis` runs as an unprivileged system user
with an empty capability bounding set. Only `aegis-agent` is privileged, and it
is limited to `CAP_NET_ADMIN` + `CAP_NET_RAW`. There is no shell anywhere in
the request path: commands are assembled as typed argument lists and passed to
`exec.Command`, never to a string that a shell would parse.

**Closed protocol.** The agent accepts six operations plus `health`. Unknown
operations are rejected; inputs are re-validated inside the agent even though
the panel already validated them.

**Private keys are ephemeral.** A key pair is generated in memory, returned
once, and discarded. Nothing in the repository writes it anywhere: this is
enforced by tests (`TestSecretsNeverAppearInListingsOrAudit`,
`TestFrontendNeverPersistsSecrets`, `TestNoKeyMaterialIsCommitted`).

**Secrets at rest.** The session cookie stores a random token; the database
stores only its SHA-256. Passwords use Argon2id (default t=3, m=64 MiB, p=2,
32-byte tag). OAuth state is stored hashed. `/etc/aegis/aegis.env` is
`0600 root:aegis`.

**Headers.** Every response sets `X-Content-Type-Options`, `X-Frame-Options:
DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`,
`Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, and `no-store`
for API responses. HSTS is emitted when `AEGIS_COOKIE_SECURE=true`.

## Controls and where they are tested

| Control                                   | Implementation                                | Test |
| ----------------------------------------- | --------------------------------------------- | ---- |
| Session required for authenticated routes | `api/middleware.go` `requireAuth`             | `TestLoginSessionAndLogout` |
| CSRF double submit on every mutation      | `api/middleware.go` `csrf`                    | `TestCSRFRequiredForMutations` |
| Admin routes rejected for normal users    | `api/middleware.go` `requireAdmin`            | `TestNonAdminCannotEscalateOrReachAdminAPI` |
| Object-level authorization (IDOR)         | `service.requireOwnership`                    | `TestCrossUserDeviceAccessIsBlocked` |
| Self-service schema cannot change role/quota | `handlers_auth.go` `updateMeRequest`       | `TestNonAdminCannotEscalateOrReachAdminAPI` |
| Login brute-force throttling              | `auth.LoginLimiter`                           | `TestLoginIsRateLimited` |
| One-time profile delivery                 | `service.GetProfile` → `ErrGone`              | `TestProfileIsDeliveredOnceThenGone` |
| Audit without secrets                     | `service.Audit`                               | `TestSecretsNeverAppearInListingsOrAudit` |
| Strict JSON decoding (unknown fields)     | `api.decode`                                  | escalation test |
| CSP split per surface                     | `api/middleware.go`                           | `TestSecurityHeadersAndAPICSP` |
| No path traversal outside the SPA root    | `api/router.go` `frontend()`                  | `TestFrontendIsSandboxedAndServesOpenAPI` |
| No `os/exec` outside the agent            | `cmd/aegis-agent` only                        | `TestOnlyTheAgentMaySpawnProcesses` |
| No privilege escalation hooks             | no `Setuid`/`Setgid` in panel code            | `TestWebServerNeverTouchesPrivileges` |
| No browser storage for keys               | `web/src/profileStore.ts`                     | `TestFrontendNeverPersistsSecrets` |
| Interface/allowed-IP/command validation   | `wg/protocol.go`                              | `internal/wg/protocol_test.go` |
| Session is opaque, HttpOnly, forged cookie rejected | `auth/session.go`                   | `TestSessionCookieIsOpaqueHttpOnlyAndRejectedWhenForged` |

## Operational hardening

* Reverse proxy terminates TLS; panel listens on `127.0.0.1:8443`.
  Set `AEGIS_COOKIE_SECURE=true` and `AEGIS_TRUST_PROXY=true` (only when the
  proxy really sets `X-Forwarded-For`, otherwise the rate limiter is spoofable).
* systemd units: `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`,
  `PrivateTmp`, `RestrictAddressFamilies`, `LockPersonality`,
  `RestrictSUIDSGID`, empty capability set for the panel.
* The agent is the only root process; its attack surface is a Unix socket
  with mode `0770 root:aegis` plus an optional shared token.
* `AEGIS_RATE_LIMIT_ENABLED` (egress shaping with `tc`) is **off by default**;
  enabling it requires `CAP_NET_ADMIN` on the agent (already granted) and an
  egress interface.

## Known limitations / residual risks

1. **Rate limiter is in-memory and per-process.** Restarting the panel resets
   the counters, and a multi-replica deployment would not share them. For the
   MVP Aegis runs as a single process behind one proxy.
2. **`X-Forwarded-For` is trusted only when `AEGIS_TRUST_PROXY=true`.**
   Misconfiguring it in production lets an attacker bypass login throttling.
3. **TLS is not terminated by the panel.** There is no built-in HTTPS; a
   reverse proxy is mandatory for production.
4. **No key escrow, by design.** If a user loses the delivered configuration it
   cannot be recovered: it must be rotated (`POST .../rotate`), which
   invalidates the previous key. Users are told this in the UI.
5. **Egress interface detection** reads `/proc/net/route`. On unusual network
   topologies (multiple default routes, policy routing) the MASQUERADE rule is
   skipped with a warning; set `AEGIS_WG_EGRESS_IFACE` explicitly.
6. **`iptables` legacy vs `nft`** is not auto-detected: the PostUp rule assumes
   `iptables`. On `nft`-only distributions adapt `syncPersistent` or install
   `iptables-nft`.
7. **SQLite single-writer.** Concurrency is bounded by one writer connection;
   this is intentional and sufficient for a control plane, not for data-plane
   traffic.
8. **Kyros integration is untested against a real IdP** in this repository: the
   adapter implements standard OIDC code flow + PKCE with discovery, but no
   Kyros credentials were available. See `docs/kyros-integration.md`.
9. **No 2FA, no audit log shipping, no RBAC beyond `admin`/`user`.**
10. **The agent trusts the socket group.** Any process able to write to
    `/run/aegis/agent.sock` as group `aegis` can add or remove peers. Keep the
    panel account unshared, and enable `AEGIS_AGENT_TOKEN`.
