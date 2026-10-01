package store

// Role of an Aegis user.
type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

// UserStatus of an Aegis account.
type UserStatus string

const (
	UserActive    UserStatus = "active"
	UserSuspended UserStatus = "suspended"
)

// User is an Aegis account, possibly linked to a Kyros identity.
type User struct {
	ID                 string     `json:"id"`
	Email              string     `json:"email"`
	DisplayName        string     `json:"display_name"`
	Role               Role       `json:"role"`
	Status             UserStatus `json:"status"`
	PolicyID           *string    `json:"policy_id"`
	QuotaBytesOverride *int64     `json:"quota_bytes_override"`
	ExpiresAt          *int64     `json:"expires_at"`
	CreatedAt          int64      `json:"created_at"`
	UpdatedAt          int64      `json:"updated_at"`
	LastLoginAt        *int64     `json:"last_login_at"`
	HasLocalPassword   bool       `json:"has_local_password"`
	HasKyrosIdentity   bool       `json:"has_kyros_identity"`
	DeviceCount        int        `json:"device_count"`
}

// Identity links an external provider subject to a user.
type Identity struct {
	ID              string `json:"id"`
	UserID          string `json:"user_id"`
	Provider        string `json:"provider"`
	ProviderSubject string `json:"provider_subject"`
	Email           string `json:"email"`
	CreatedAt       int64  `json:"created_at"`
	LastLoginAt     *int64 `json:"last_login_at"`
}

// LocalCredential holds the Argon2id hash for a local account.
type LocalCredential struct {
	UserID             string `json:"user_id"`
	PasswordHash       string `json:"-"`
	Algo               string `json:"algo"`
	FailedAttempts     int    `json:"failed_attempts"`
	LockedUntil        *int64 `json:"locked_until"`
	MustChangePassword bool   `json:"must_change_password"`
	UpdatedAt          int64  `json:"updated_at"`
}

// AccessPolicy defines quotas and limits applied to a user.
type AccessPolicy struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Description       string `json:"description"`
	MaxDevices        int    `json:"max_devices"`
	MonthlyQuotaBytes int64  `json:"monthly_quota_bytes"`
	UpKbps            int    `json:"up_kbps"`
	DownKbps          int    `json:"down_kbps"`
	ExpiresAt         *int64 `json:"expires_at"`
	FullTunnel        bool   `json:"full_tunnel"`
	AllowedNetworks   string `json:"allowed_networks"`
	AutoReactivate    bool   `json:"auto_reactivate"`
	CreatedAt         int64  `json:"created_at"`
	UpdatedAt         int64  `json:"updated_at"`
}

// VPNServer describes one WireGuard endpoint (a future multi-VPS topology).
type VPNServer struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Host            string `json:"host"`
	Country         string `json:"country"`
	WGInterface     string `json:"wg_interface"`
	WGPort          int    `json:"wg_port"`
	VPNCIDR         string `json:"vpn_cidr"`
	DNS             string `json:"dns"`
	EndpointPublic  string `json:"endpoint_public"`
	MaxPeers        int    `json:"max_peers"`
	ProfileTTLHours int    `json:"profile_ttl_hours"`
	FullTunnel      bool   `json:"full_tunnel"`
	IPv6Enabled     bool   `json:"ipv6_enabled"`
	IsDefault       bool   `json:"is_default"`
	Enabled         bool   `json:"enabled"`
	CreatedAt       int64  `json:"created_at"`
	UpdatedAt       int64  `json:"updated_at"`
	// Runtime (not persisted)
	Connected int    `json:"connected"`
	PeerCount int    `json:"peer_count"`
	Status    string `json:"status"`
}

// Device is one physical or virtual client belonging to a user.
type Device struct {
	ID         string `json:"id"`
	UserID     string `json:"user_id"`
	ServerID   string `json:"server_id"`
	Name       string `json:"name"`
	Platform   string `json:"platform"`
	Status     string `json:"status"`
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
	RevokedAt  *int64 `json:"revoked_at"`
	LastSeenAt *int64 `json:"last_seen_at"`
	// Joined fields
	AllowedIP        string `json:"allowed_ip,omitempty"`
	PublicKey        string `json:"public_key,omitempty"`
	PeerStatus       string `json:"peer_status,omitempty"`
	SuspendedReason  string `json:"suspended_reason,omitempty"`
	LastHandshakeAt  *int64 `json:"last_handshake_at,omitempty"`
	RxBytes          int64  `json:"rx_bytes,omitempty"`
	TxBytes          int64  `json:"tx_bytes,omitempty"`
	ProfileDelivered *int64 `json:"profile_delivered_at,omitempty"`
	PeerExpiresAt    *int64 `json:"peer_expires_at,omitempty"`
	EffectiveState   string `json:"effective_state"`
}

// WireGuardPeer is the WireGuard representation of one device.
type WireGuardPeer struct {
	ID                 string `json:"id"`
	DeviceID           string `json:"device_id"`
	ServerID           string `json:"server_id"`
	PublicKey          string `json:"public_key"`
	AllowedIP          string `json:"allowed_ip"`
	Status             string `json:"status"`
	SuspendedReason    string `json:"suspended_reason"`
	CreatedAt          int64  `json:"created_at"`
	UpdatedAt          int64  `json:"updated_at"`
	RotatedAt          *int64 `json:"rotated_at"`
	RevokedAt          *int64 `json:"revoked_at"`
	LastHandshakeAt    *int64 `json:"last_handshake_at"`
	RxBytes            int64  `json:"rx_bytes"`
	TxBytes            int64  `json:"tx_bytes"`
	ProfileDeliveredAt *int64 `json:"profile_delivered_at"`
	ExpiresAt          *int64 `json:"expires_at"`
	// Owner of the parent device; populated by list queries that join devices.
	UserID     string `json:"-"`
	DeviceName string `json:"-"`
}

// TrafficSnapshot is one periodic reading of a peer's cumulative counters.
type TrafficSnapshot struct {
	ID           int64  `json:"id"`
	PeerID       string `json:"peer_id"`
	TakenAt      int64  `json:"taken_at"`
	RxBytes      int64  `json:"rx_bytes"`
	TxBytes      int64  `json:"tx_bytes"`
	DeltaRx      int64  `json:"delta_rx"`
	DeltaTx      int64  `json:"delta_tx"`
	CounterReset bool   `json:"counter_reset"`
}

// MonthlyUsage aggregates traffic for one user in one UTC month.
type MonthlyUsage struct {
	UserID     string `json:"user_id"`
	Month      string `json:"month"`
	RxBytes    int64  `json:"rx_bytes"`
	TxBytes    int64  `json:"tx_bytes"`
	TotalBytes int64  `json:"total_bytes"`
	UpdatedAt  int64  `json:"updated_at"`
}

// AuditEvent is an append-only journal entry. It must never contain secrets.
type AuditEvent struct {
	ID            int64  `json:"id"`
	Ts            int64  `json:"ts"`
	ActorUserID   string `json:"actor_user_id"`
	ActorKind     string `json:"actor_kind"`
	Action        string `json:"action"`
	TargetKind    string `json:"target_kind"`
	TargetID      string `json:"target_id"`
	IP            string `json:"ip"`
	UserAgent     string `json:"user_agent"`
	CorrelationID string `json:"correlation_id"`
	Detail        string `json:"detail"`
}

// Session is a server-side session record. The cookie carries an opaque token;
// only its hash is stored.
type Session struct {
	ID          string  `json:"id"`
	UserID      string  `json:"user_id"`
	CSRFToken   string  `json:"csrf_token"`
	CreatedAt   int64   `json:"created_at"`
	ExpiresAt   int64   `json:"expires_at"`
	LastSeenAt  int64   `json:"last_seen_at"`
	RotatedFrom *string `json:"rotated_from"`
	IP          string  `json:"ip"`
	UserAgent   string  `json:"user_agent"`
}
