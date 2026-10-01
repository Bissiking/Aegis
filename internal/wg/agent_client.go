package wg

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// AgentClient talks to the privileged agent over a local socket.
//
// Address forms:
//   - unix:///run/aegis/agent.sock  (production, POSIX)
//   - tcp://127.0.0.1:9441          (loopback only, local development/tests)
type AgentClient struct {
	dial    func() (net.Conn, error)
	token   string
	timeout time.Duration
}

// NewAgentClient builds a client for the given agent address.
func NewAgentClient(address, token string, timeout time.Duration) (*AgentClient, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	var dial func() (net.Conn, error)
	switch {
	case strings.HasPrefix(address, "unix://"):
		path := strings.TrimPrefix(address, "unix://")
		if path == "" {
			return nil, fmt.Errorf("empty unix socket path")
		}
		dial = func() (net.Conn, error) { return net.DialTimeout("unix", path, timeout) }
	case strings.HasPrefix(address, "tcp://"):
		addr := strings.TrimPrefix(address, "tcp://")
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid agent tcp address: %w", err)
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("agent tcp transport is restricted to loopback")
		}
		dial = func() (net.Conn, error) { return net.DialTimeout("tcp", addr, timeout) }
	case strings.HasPrefix(address, "/") || strings.HasPrefix(address, `\\.\pipe\`):
		// Bare path: unix socket on POSIX, named pipe path not supported.
		if strings.HasPrefix(address, `\\.\pipe\`) {
			return nil, fmt.Errorf("named pipes are not supported, use unix:// or tcp://")
		}
		path := address
		dial = func() (net.Conn, error) { return net.DialTimeout("unix", path, timeout) }
	default:
		return nil, fmt.Errorf("unsupported agent address %q", address)
	}
	return &AgentClient{dial: dial, token: token, timeout: timeout}, nil
}

func (c *AgentClient) do(ctx context.Context, req *Request) (*Response, error) {
	req.Token = c.token
	body, err := EncodeRequest(req)
	if err != nil {
		return nil, err
	}
	conn, err := c.dial()
	if err != nil {
		return nil, fmt.Errorf("agent unreachable: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(append(body, '\n')); err != nil {
		return nil, fmt.Errorf("agent write: %w", err)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("agent read: %w", err)
	}
	resp, err := DecodeResponse(line)
	if err != nil {
		return nil, fmt.Errorf("agent decode: %w", err)
	}
	if !resp.OK {
		return nil, fmt.Errorf("agent: %s", resp.Error)
	}
	return resp, nil
}

// AddPeer adds a peer to the live interface.
func (c *AgentClient) AddPeer(ctx context.Context, iface, publicKey, allowedIP string) error {
	_, err := c.do(ctx, &Request{Op: OpAddPeer, Interface: iface, PublicKey: publicKey, AllowedIP: allowedIP})
	return err
}

// ModifyPeer updates the allowed IPs of an existing peer.
func (c *AgentClient) ModifyPeer(ctx context.Context, iface, publicKey, allowedIP string) error {
	_, err := c.do(ctx, &Request{Op: OpModifyPeer, Interface: iface, PublicKey: publicKey, AllowedIP: allowedIP})
	return err
}

// RemovePeer removes a peer from the live interface.
func (c *AgentClient) RemovePeer(ctx context.Context, iface, publicKey string) error {
	_, err := c.do(ctx, &Request{Op: OpRemovePeer, Interface: iface, PublicKey: publicKey})
	return err
}

// ReadState reads the current interface state.
func (c *AgentClient) ReadState(ctx context.Context, iface string) (*State, error) {
	resp, err := c.do(ctx, &Request{Op: OpReadState, Interface: iface})
	if err != nil {
		return nil, err
	}
	if resp.State == nil {
		return nil, fmt.Errorf("agent returned no state")
	}
	return resp.State, nil
}

// ApplyRateLimit applies best-effort tc shaping to one peer.
func (c *AgentClient) ApplyRateLimit(ctx context.Context, iface, publicKey, allowedIP string, upKbps, downKbps int) error {
	_, err := c.do(ctx, &Request{Op: OpRateLimit, Interface: iface, PublicKey: publicKey, AllowedIP: allowedIP, UpKbps: upKbps, DownKbps: downKbps})
	return err
}

// SyncConfig rewrites the persistent WireGuard configuration.
func (c *AgentClient) SyncConfig(ctx context.Context, cfg PersistentConfig) error {
	local := cfg
	_, err := c.do(ctx, &Request{Op: OpSyncConfig, Config: &local})
	return err
}

// Health pings the agent.
func (c *AgentClient) Health(ctx context.Context) error {
	_, err := c.do(ctx, &Request{Op: OpHealth})
	return err
}

// MarshalState is a helper used by the agent to encode state.
func MarshalState(s *State) []byte {
	b, _ := json.Marshal(s)
	return b
}
