package service

import (
	"context"
	"errors"
	"strings"

	"github.com/aegis-vpn/aegis/internal/store"
)

// PolicyInput is the admin-facing policy payload.
type PolicyInput struct {
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
}

func (in PolicyInput) validate() error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		return &FieldError{Field: "name"}
	}
	if in.MaxDevices < 0 || in.MaxDevices > 1000 {
		return &FieldError{Field: "max_devices"}
	}
	if in.MonthlyQuotaBytes < 0 {
		return &FieldError{Field: "monthly_quota_bytes"}
	}
	if in.UpKbps < 0 || in.DownKbps < 0 || in.UpKbps > 10_000_000 || in.DownKbps > 10_000_000 {
		return &FieldError{Field: "rate_limit"}
	}
	if len(in.AllowedNetworks) > 4096 {
		return &FieldError{Field: "allowed_networks"}
	}
	return nil
}

// CreatePolicy creates an access policy.
func (s *Service) CreatePolicy(ctx context.Context, actor Actor, in PolicyInput) (*store.AccessPolicy, error) {
	if !actor.IsAdmin() {
		return nil, ErrForbidden
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	p := &store.AccessPolicy{
		ID:                store.NewID("pol"),
		Name:              strings.TrimSpace(in.Name),
		Description:       truncate(in.Description, 500),
		MaxDevices:        in.MaxDevices,
		MonthlyQuotaBytes: in.MonthlyQuotaBytes,
		UpKbps:            in.UpKbps,
		DownKbps:          in.DownKbps,
		ExpiresAt:         in.ExpiresAt,
		FullTunnel:        in.FullTunnel,
		AllowedNetworks:   in.AllowedNetworks,
		AutoReactivate:    in.AutoReactivate,
	}
	if p.AllowedNetworks == "" {
		p.AllowedNetworks = defaultNetworks(s.Cfg)
	}
	if err := s.Store.CreatePolicy(ctx, p); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}
	s.Audit(ctx, actor, "policy.create", "policy", p.ID, map[string]any{
		"name": p.Name, "max_devices": p.MaxDevices, "monthly_quota_bytes": p.MonthlyQuotaBytes,
		"up_kbps": p.UpKbps, "down_kbps": p.DownKbps,
	})
	return p, nil
}

// UpdatePolicy modifies an access policy.
func (s *Service) UpdatePolicy(ctx context.Context, actor Actor, id string, in PolicyInput) (*store.AccessPolicy, error) {
	if !actor.IsAdmin() {
		return nil, ErrForbidden
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	p, err := s.Store.GetPolicy(ctx, id)
	if err != nil {
		return nil, err
	}
	p.Name = strings.TrimSpace(in.Name)
	p.Description = truncate(in.Description, 500)
	p.MaxDevices = in.MaxDevices
	p.MonthlyQuotaBytes = in.MonthlyQuotaBytes
	p.UpKbps = in.UpKbps
	p.DownKbps = in.DownKbps
	p.ExpiresAt = in.ExpiresAt
	p.FullTunnel = in.FullTunnel
	p.AllowedNetworks = in.AllowedNetworks
	p.AutoReactivate = in.AutoReactivate
	if err := s.Store.UpdatePolicy(ctx, p); err != nil {
		return nil, err
	}
	s.Audit(ctx, actor, "policy.update", "policy", p.ID, map[string]any{
		"name": p.Name, "max_devices": p.MaxDevices, "monthly_quota_bytes": p.MonthlyQuotaBytes,
		"up_kbps": p.UpKbps, "down_kbps": p.DownKbps,
	})
	return p, nil
}

// DeletePolicy removes a policy (users keep working with defaults).
func (s *Service) DeletePolicy(ctx context.Context, actor Actor, id string) error {
	if !actor.IsAdmin() {
		return ErrForbidden
	}
	if err := s.Store.DeletePolicy(ctx, id); err != nil {
		return err
	}
	s.Audit(ctx, actor, "policy.delete", "policy", id, nil)
	return nil
}

// ListPolicies returns every policy.
func (s *Service) ListPolicies(ctx context.Context, actor Actor) ([]*store.AccessPolicy, error) {
	if !actor.IsAdmin() {
		return nil, ErrForbidden
	}
	return s.Store.ListPolicies(ctx)
}

// ------------------------------------------------------------- servers

// ServerInput is the admin-facing server payload.
type ServerInput struct {
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
}

// CreateServer registers a new VPN endpoint (multi-VPS readiness).
func (s *Service) CreateServer(ctx context.Context, actor Actor, in ServerInput) (*store.VPNServer, error) {
	if !actor.IsAdmin() {
		return nil, ErrForbidden
	}
	if strings.TrimSpace(in.Name) == "" {
		return nil, &FieldError{Field: "name"}
	}
	if err := wgValidateServer(in); err != nil {
		return nil, err
	}
	srv := &store.VPNServer{
		ID:              store.NewID("srv"),
		Name:            strings.TrimSpace(in.Name),
		Host:            strings.TrimSpace(in.Host),
		Country:         strings.TrimSpace(in.Country),
		WGInterface:     in.WGInterface,
		WGPort:          in.WGPort,
		VPNCIDR:         in.VPNCIDR,
		DNS:             in.DNS,
		EndpointPublic:  strings.TrimSpace(in.EndpointPublic),
		MaxPeers:        in.MaxPeers,
		ProfileTTLHours: in.ProfileTTLHours,
		FullTunnel:      in.FullTunnel,
		IPv6Enabled:     in.IPv6Enabled,
		IsDefault:       in.IsDefault,
		Enabled:         in.Enabled,
	}
	if err := s.Store.CreateServer(ctx, srv); err != nil {
		return nil, err
	}
	s.Audit(ctx, actor, "server.create", "server", srv.ID, map[string]any{"name": srv.Name, "wg_port": srv.WGPort})
	return srv, nil
}

// UpdateServer modifies a VPN endpoint.
func (s *Service) UpdateServer(ctx context.Context, actor Actor, id string, in ServerInput) (*store.VPNServer, error) {
	if !actor.IsAdmin() {
		return nil, ErrForbidden
	}
	if err := wgValidateServer(in); err != nil {
		return nil, err
	}
	srv, err := s.Store.GetServer(ctx, id)
	if err != nil {
		return nil, err
	}
	srv.Name = strings.TrimSpace(in.Name)
	srv.Host = in.Host
	srv.Country = in.Country
	srv.WGInterface = in.WGInterface
	srv.WGPort = in.WGPort
	srv.VPNCIDR = in.VPNCIDR
	srv.DNS = in.DNS
	srv.EndpointPublic = in.EndpointPublic
	srv.MaxPeers = in.MaxPeers
	srv.ProfileTTLHours = in.ProfileTTLHours
	srv.FullTunnel = in.FullTunnel
	srv.IPv6Enabled = in.IPv6Enabled
	srv.IsDefault = in.IsDefault
	srv.Enabled = in.Enabled
	if err := s.Store.UpdateServer(ctx, srv); err != nil {
		return nil, err
	}
	_ = s.syncPersistent(ctx, srv)
	s.Audit(ctx, actor, "server.update", "server", srv.ID, map[string]any{"name": srv.Name})
	return srv, nil
}

// ListServers returns every VPN endpoint with its runtime status.
func (s *Service) ListServers(ctx context.Context, actor Actor) ([]*store.VPNServer, error) {
	if !actor.IsAdmin() {
		return nil, ErrForbidden
	}
	servers, err := s.Store.ListServers(ctx)
	if err != nil {
		return nil, err
	}
	for _, srv := range servers {
		n, _ := s.Store.CountPeersOnServer(ctx, srv.ID)
		srv.PeerCount = n
		st, err := s.WG.ReadState(ctx, srv.WGInterface)
		if err != nil {
			srv.Status = "unreachable"
			srv.Connected = 0
			continue
		}
		srv.Status = "online"
		connected := 0
		for _, p := range st.Peers {
			if !p.LastHandshakeAt.IsZero() {
				connected++
			}
		}
		srv.Connected = connected
	}
	return servers, nil
}

// WireGuardStatus returns the live interface view for the admin dashboard.
func (s *Service) WireGuardStatus(ctx context.Context, actor Actor) (map[string]any, error) {
	if !actor.IsAdmin() {
		return nil, ErrForbidden
	}
	servers, err := s.Store.ListServers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(servers))
	for _, srv := range servers {
		entry := map[string]any{
			"server_id": srv.ID,
			"name":      srv.Name,
			"interface": srv.WGInterface,
			"port":      srv.WGPort,
			"network":   srv.VPNCIDR,
		}
		st, err := s.WG.ReadState(ctx, srv.WGInterface)
		if err != nil {
			entry["status"] = "unreachable"
			entry["error"] = err.Error()
		} else {
			entry["status"] = "online"
			entry["listen_port"] = st.ListenPort
			entry["peer_count"] = len(st.Peers)
			entry["collected_at"] = st.CollectedAt.Unix()
		}
		out = append(out, entry)
	}
	return map[string]any{"servers": out}, nil
}
