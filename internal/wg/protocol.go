package wg

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// Validation helpers shared by the client side so invalid values are rejected
// before they ever reach the privileged agent.

var (
	// Interface names must start with an alphanumeric character: a leading
	// dash could otherwise be interpreted as a command line flag.
	ifaceRe     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_=+.-]{0,14}$`)
	base64KeyRe = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
)

// ValidateInterface rejects anything that is not a plain interface name.
func ValidateInterface(name string) error {
	if !ifaceRe.MatchString(name) {
		return fmt.Errorf("invalid interface name")
	}
	return nil
}

// ValidatePublicKey rejects malformed WireGuard public keys.
func ValidatePublicKey(key string) error {
	if !base64KeyRe.MatchString(key) {
		return fmt.Errorf("invalid wireguard public key")
	}
	return nil
}

// ValidateAllowedIP rejects anything that is not a single host CIDR.
func ValidateAllowedIP(cidr string) error {
	if strings.ContainsAny(cidr, " ,;\t\n") {
		return fmt.Errorf("allowed-ip must be a single host CIDR")
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid allowed-ip")
	}
	ones, bits := ipNet.Mask.Size()
	if ones != bits {
		// Rejects 0.0.0.0/0, 10.0.0.0/8, ... only /32 (or /128) is a host.
		return fmt.Errorf("allowed-ip must be a single host CIDR")
	}
	return nil
}

// ValidateRateLimits validates optional shaping parameters.
func ValidateRateLimits(up, down int) error {
	if up < 0 || down < 0 {
		return fmt.Errorf("rate limits must not be negative")
	}
	if up > 10_000_000 || down > 10_000_000 {
		return fmt.Errorf("rate limit out of range")
	}
	return nil
}

// Request is the wire format spoken over the agent socket.
type Request struct {
	Op        string            `json:"op"`
	Token     string            `json:"token,omitempty"`
	Interface string            `json:"interface,omitempty"`
	PublicKey string            `json:"public_key,omitempty"`
	AllowedIP string            `json:"allowed_ip,omitempty"`
	UpKbps    int               `json:"up_kbps,omitempty"`
	DownKbps  int               `json:"down_kbps,omitempty"`
	Config    *PersistentConfig `json:"config,omitempty"`
}

// Response is the wire format returned by the agent.
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	State *State `json:"state,omitempty"`
}

// Validate performs agent-side validation of an incoming request. The agent
// re-validates everything even though the web service already did.
func (r *Request) Validate() error {
	if r.Token == "" && RequireToken {
		return fmt.Errorf("missing agent token")
	}
	switch r.Op {
	case OpAddPeer, OpModifyPeer:
		if err := ValidateInterface(r.Interface); err != nil {
			return err
		}
		if err := ValidatePublicKey(r.PublicKey); err != nil {
			return err
		}
		if err := ValidateAllowedIP(r.AllowedIP); err != nil {
			return err
		}
	case OpRemovePeer:
		if err := ValidateInterface(r.Interface); err != nil {
			return err
		}
		if err := ValidatePublicKey(r.PublicKey); err != nil {
			return err
		}
	case OpReadState, OpHealth:
		if r.Interface != "" {
			if err := ValidateInterface(r.Interface); err != nil {
				return err
			}
		}
	case OpRateLimit:
		if err := ValidateInterface(r.Interface); err != nil {
			return err
		}
		if err := ValidatePublicKey(r.PublicKey); err != nil {
			return err
		}
		if err := ValidateAllowedIP(r.AllowedIP); err != nil {
			return err
		}
		if err := ValidateRateLimits(r.UpKbps, r.DownKbps); err != nil {
			return err
		}
	case OpSyncConfig:
		if r.Config == nil {
			return fmt.Errorf("missing config")
		}
		return validatePersistentConfig(r.Config)
	default:
		return fmt.Errorf("unknown operation")
	}
	return nil
}

func validatePersistentConfig(c *PersistentConfig) error {
	if err := ValidateInterface(c.Interface); err != nil {
		return err
	}
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		return fmt.Errorf("invalid listen port")
	}
	if _, _, err := net.ParseCIDR(c.Address); err != nil {
		return fmt.Errorf("invalid interface address")
	}
	if len(c.Peers) > 4096 {
		return fmt.Errorf("too many peers")
	}
	for _, p := range c.Peers {
		if err := ValidatePublicKey(p.PublicKey); err != nil {
			return err
		}
		for _, a := range p.AllowedIPs {
			if err := ValidateAllowedIP(a); err != nil {
				return err
			}
		}
	}
	for _, d := range c.DNS {
		if net.ParseIP(d) == nil {
			return fmt.Errorf("invalid dns entry")
		}
	}
	// PostUp/PostDown are only ever produced by Aegis itself; reject anything
	// containing shell metacharacters as defence in depth.
	for _, cmd := range append(append([]string{}, c.PostUp...), c.PostDown...) {
		if err := validateBuiltinNetCommand(cmd); err != nil {
			return err
		}
	}
	return nil
}

var builtinRe = regexp.MustCompile(`^(iptables|ip6tables|sysctl|nft) [a-zA-Z0-9_\-./=:,%@+ ]+$`)

func validateBuiltinNetCommand(cmd string) error {
	if !builtinRe.MatchString(cmd) {
		return fmt.Errorf("unsupported builtin command")
	}
	for _, bad := range []string{"`", "$", ";", "|", "&", ">", "<", "(", ")", "'", "\"", "\n"} {
		if strings.Contains(cmd, bad) {
			return fmt.Errorf("unsupported character in builtin command")
		}
	}
	return nil
}

// EncodeRequest serialises a request.
func EncodeRequest(r *Request) ([]byte, error) { return json.Marshal(r) }

// DecodeResponse parses an agent response.
func DecodeResponse(b []byte) (*Response, error) {
	var resp Response
	if err := json.Unmarshal(b, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RequireToken controls whether the agent demands the shared secret. It is set
// by the agent binary from configuration.
var RequireToken = false

// DefaultTimeout is the default client-side deadline.
const DefaultTimeout = 10 * time.Second
