-- Aegis initial schema.
-- All timestamps are stored as Unix epoch seconds (UTC).

CREATE TABLE access_policies (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE,
    description         TEXT NOT NULL DEFAULT '',
    max_devices         INTEGER NOT NULL DEFAULT 5,
    monthly_quota_bytes INTEGER NOT NULL DEFAULT 0,
    up_kbps             INTEGER NOT NULL DEFAULT 0,
    down_kbps           INTEGER NOT NULL DEFAULT 0,
    expires_at          INTEGER,
    full_tunnel         INTEGER NOT NULL DEFAULT 1,
    allowed_networks    TEXT NOT NULL DEFAULT '0.0.0.0/0',
    auto_reactivate     INTEGER NOT NULL DEFAULT 1,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
);

CREATE TABLE users (
    id                   TEXT PRIMARY KEY,
    email                TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name         TEXT NOT NULL DEFAULT '',
    role                 TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin','user')),
    status               TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
    policy_id            TEXT REFERENCES access_policies(id) ON DELETE SET NULL,
    quota_bytes_override INTEGER,
    expires_at           INTEGER,
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL,
    last_login_at        INTEGER
);

CREATE TABLE identities (
    id               TEXT PRIMARY KEY,
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider         TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    email            TEXT NOT NULL DEFAULT '',
    created_at       INTEGER NOT NULL,
    last_login_at    INTEGER,
    UNIQUE (provider, provider_subject)
);
CREATE INDEX idx_identities_user ON identities(user_id);

CREATE TABLE local_credentials (
    user_id              TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password_hash        TEXT NOT NULL,
    algo                 TEXT NOT NULL DEFAULT 'argon2id',
    failed_attempts      INTEGER NOT NULL DEFAULT 0,
    locked_until         INTEGER,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    updated_at           INTEGER NOT NULL
);

CREATE TABLE vpn_servers (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL UNIQUE,
    host              TEXT NOT NULL DEFAULT '',
    country           TEXT NOT NULL DEFAULT '',
    wg_interface      TEXT NOT NULL DEFAULT 'wg0',
    wg_port           INTEGER NOT NULL DEFAULT 51820,
    vpn_cidr          TEXT NOT NULL DEFAULT '10.77.0.0/24',
    dns               TEXT NOT NULL DEFAULT '1.1.1.1,1.0.0.1',
    endpoint_public   TEXT NOT NULL DEFAULT '',
    max_peers         INTEGER NOT NULL DEFAULT 128,
    profile_ttl_hours INTEGER NOT NULL DEFAULT 0,
    full_tunnel       INTEGER NOT NULL DEFAULT 1,
    ipv6_enabled      INTEGER NOT NULL DEFAULT 0,
    is_default        INTEGER NOT NULL DEFAULT 0,
    enabled           INTEGER NOT NULL DEFAULT 1,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);

CREATE TABLE devices (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id    TEXT NOT NULL REFERENCES vpn_servers(id) ON DELETE RESTRICT,
    name         TEXT NOT NULL,
    platform     TEXT NOT NULL DEFAULT 'generic',
    status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    revoked_at   INTEGER,
    last_seen_at INTEGER
);
CREATE INDEX idx_devices_user ON devices(user_id);

CREATE TABLE wireguard_peers (
    id                 TEXT PRIMARY KEY,
    device_id          TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    server_id          TEXT NOT NULL REFERENCES vpn_servers(id) ON DELETE RESTRICT,
    public_key         TEXT NOT NULL UNIQUE,
    allowed_ip         TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','revoked')),
    suspended_reason   TEXT NOT NULL DEFAULT '',
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    rotated_at         INTEGER,
    revoked_at         INTEGER,
    last_handshake_at  INTEGER,
    rx_bytes           INTEGER NOT NULL DEFAULT 0,
    tx_bytes           INTEGER NOT NULL DEFAULT 0,
    profile_delivered_at INTEGER,
    expires_at         INTEGER
);
CREATE INDEX idx_peers_device ON wireguard_peers(device_id);
CREATE INDEX idx_peers_server ON wireguard_peers(server_id);

CREATE TABLE traffic_snapshots (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id       TEXT NOT NULL REFERENCES wireguard_peers(id) ON DELETE CASCADE,
    taken_at      INTEGER NOT NULL,
    rx_bytes      INTEGER NOT NULL,
    tx_bytes      INTEGER NOT NULL,
    delta_rx      INTEGER NOT NULL DEFAULT 0,
    delta_tx      INTEGER NOT NULL DEFAULT 0,
    counter_reset INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_snapshots_peer_time ON traffic_snapshots(peer_id, taken_at);

CREATE TABLE monthly_usage (
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    month       TEXT NOT NULL,
    rx_bytes    INTEGER NOT NULL DEFAULT 0,
    tx_bytes    INTEGER NOT NULL DEFAULT 0,
    total_bytes INTEGER NOT NULL DEFAULT 0,
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (user_id, month)
);

CREATE TABLE audit_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             INTEGER NOT NULL,
    actor_user_id  TEXT NOT NULL DEFAULT '',
    actor_kind     TEXT NOT NULL DEFAULT 'system',
    action         TEXT NOT NULL,
    target_kind    TEXT NOT NULL DEFAULT '',
    target_id      TEXT NOT NULL DEFAULT '',
    ip             TEXT NOT NULL DEFAULT '',
    user_agent     TEXT NOT NULL DEFAULT '',
    correlation_id TEXT NOT NULL DEFAULT '',
    detail         TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_audit_ts ON audit_events(ts);
CREATE INDEX idx_audit_actor ON audit_events(actor_user_id, ts);

CREATE TABLE sessions (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token   TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    rotated_from TEXT,
    ip           TEXT NOT NULL DEFAULT '',
    user_agent   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE oauth_states (
    state_hash    TEXT PRIMARY KEY,
    code_verifier TEXT NOT NULL,
    nonce         TEXT NOT NULL,
    redirect_to   TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL
);

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
