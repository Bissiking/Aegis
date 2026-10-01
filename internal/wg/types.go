// Package wg defines the narrow, explicit contract between the unprivileged
// Aegis web service and the privileged WireGuard agent.
//
// Only these operations exist. Nothing in this package accepts a free-form
// shell command, a file path supplied by a user, or an arbitrary WireGuard
// configuration payload.
package wg

import (
	"context"
	"time"
)

// Operation names accepted by the agent. The list is closed on purpose.
const (
	OpAddPeer    = "add_peer"
	OpModifyPeer = "modify_peer"
	OpRemovePeer = "remove_peer"
	OpReadState  = "read_state"
	OpRateLimit  = "apply_rate_limit"
	OpSyncConfig = "sync_config"
	OpHealth     = "health"
)

// PeerState is the runtime state of a peer as reported by the kernel.
type PeerState struct {
	PublicKey       string    `json:"public_key"`
	AllowedIPs      []string  `json:"allowed_ips"`
	LastHandshakeAt time.Time `json:"last_handshake_at"`
	RxBytes         int64     `json:"rx_bytes"`
	TxBytes         int64     `json:"tx_bytes"`
	PersistentKA    int       `json:"persistent_keepalive"`
	Endpoint        string    `json:"endpoint,omitempty"`
}

// State is the runtime state of an interface.
type State struct {
	Interface   string      `json:"interface"`
	ListenPort  int         `json:"listen_port"`
	Peers       []PeerState `json:"peers"`
	CollectedAt time.Time   `json:"collected_at"`
}

// ConfigPeer is one peer entry of the persistent configuration.
type ConfigPeer struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
}

// PersistentConfig is the subset of WireGuard configuration Aegis is allowed to
// write. It is assembled by the web service from validated values only.
type PersistentConfig struct {
	Interface  string       `json:"interface"`
	ListenPort int          `json:"listen_port"`
	Address    string       `json:"address"`
	DNS        []string     `json:"dns,omitempty"`
	Table      string       `json:"table,omitempty"`
	PostUp     []string     `json:"post_up,omitempty"`
	PostDown   []string     `json:"post_down,omitempty"`
	SaveConfig bool         `json:"save_config"`
	Peers      []ConfigPeer `json:"peers"`
}

// Client is the contract used by the business layer. Production wires
// AgentClient; tests wire Fake.
type Client interface {
	AddPeer(ctx context.Context, iface, publicKey, allowedIP string) error
	ModifyPeer(ctx context.Context, iface, publicKey, allowedIP string) error
	RemovePeer(ctx context.Context, iface, publicKey string) error
	ReadState(ctx context.Context, iface string) (*State, error)
	ApplyRateLimit(ctx context.Context, iface, publicKey, allowedIP string, upKbps, downKbps int) error
	SyncConfig(ctx context.Context, cfg PersistentConfig) error
}
