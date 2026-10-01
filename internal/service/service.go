// Package service holds the Aegis business logic. It is the only layer allowed
// to combine persistence, WireGuard control and policy decisions; the HTTP layer
// only validates input, checks permissions and renders output.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aegis-vpn/aegis/internal/config"
	"github.com/aegis-vpn/aegis/internal/store"
	"github.com/aegis-vpn/aegis/internal/wg"
)

// Sentinel errors mapped to HTTP by the API layer.
var (
	ErrForbidden     = errors.New("forbidden")
	ErrUnauthorized  = errors.New("unauthorized")
	ErrInvalid       = errors.New("invalid input")
	ErrQuota         = errors.New("quota exceeded")
	ErrRateLimited   = errors.New("too many attempts")
	ErrAlreadyExists = errors.New("already exists")
	ErrGone          = errors.New("resource is no longer available")
	ErrUnavailable   = errors.New("dependency unavailable")
)

// Service wires the business logic.
type Service struct {
	Store *store.Store
	WG    wg.Client
	Cfg   *config.Config
	Log   *slog.Logger
	// AgentHealthy is updated by the health loop.
	agentChecked time.Time
	agentErr     error
}

// New creates a Service.
func New(st *store.Store, client wg.Client, cfg *config.Config, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{Store: st, WG: client, Cfg: cfg, Log: log}
}

// Bootstrap seeds the default policy, default server and the local
// administrator account when the database is empty. It is idempotent.
func (s *Service) Bootstrap(ctx context.Context) error {
	n, err := s.Store.GetStats(ctx, store.CurrentMonth(time.Now()))
	if err != nil {
		return err
	}

	if n.Users == 0 {
		pol, err := s.Store.ListPolicies(ctx)
		if err != nil {
			return err
		}
		if len(pol) == 0 {
			p := &store.AccessPolicy{
				ID:              store.NewID("pol"),
				Name:            "standard",
				Description:     "Politique par défaut",
				MaxDevices:      s.Cfg.MaxDevicesDefault,
				FullTunnel:      s.Cfg.WGFullTunnel,
				AllowedNetworks: defaultNetworks(s.Cfg),
				AutoReactivate:  true,
			}
			if err := s.Store.CreatePolicy(ctx, p); err != nil {
				return fmt.Errorf("seed default policy: %w", err)
			}
		}
	}

	if err := s.Store.EnsureDefaultServer(ctx, "primary", s.Cfg.WGInterface, s.Cfg.WGNetwork, s.Cfg.WGDNS,
		s.Cfg.WGEndpoint, s.Cfg.WGPort, s.Cfg.WGMaxPeers, s.Cfg.WGProfileTTLHrs, s.Cfg.WGFullTunnel); err != nil {
		return fmt.Errorf("seed default server: %w", err)
	}

	if n.Users == 0 && s.Cfg.LocalBootstrapUser != "" && s.Cfg.LocalBootstrapPassword != "" {
		if _, err := s.CreateAdminWithPassword(ctx, s.Cfg.LocalBootstrapUser, s.Cfg.LocalBootstrapPassword, "system"); err != nil {
			return fmt.Errorf("bootstrap administrator: %w", err)
		}
	}
	return nil
}

func defaultNetworks(cfg *config.Config) string {
	if cfg.WGFullTunnel {
		return "0.0.0.0/0"
	}
	return cfg.WGNetwork
}

// Audit writes an audit event. Detail must never contain secrets.
func (s *Service) Audit(ctx context.Context, actor Actor, action, targetKind, targetID string, detail map[string]any) {
	if detail == nil {
		detail = map[string]any{}
	}
	b, _ := json.Marshal(detail)
	e := &store.AuditEvent{
		ActorUserID:   actor.UserID,
		ActorKind:     actor.Kind,
		Action:        action,
		TargetKind:    targetKind,
		TargetID:      targetID,
		IP:            actor.IP,
		UserAgent:     actor.UserAgent,
		CorrelationID: actor.CorrelationID,
		Detail:        string(b),
	}
	if err := s.Store.AppendAudit(ctx, e); err != nil {
		s.Log.Error("audit write failed", "action", action, "err", err)
	}
}

// Actor identifies who performed an action.
type Actor struct {
	UserID        string `json:"user_id"`
	Kind          string `json:"kind"` // local | kyros | system | anonymous
	Role          store.Role
	IP            string
	UserAgent     string
	CorrelationID string
}

// IsAdmin reports whether the actor has administrative rights.
func (a Actor) IsAdmin() bool { return a.Role == store.RoleAdmin }

// IsSelf reports whether the actor targets their own account.
func (a Actor) IsSelf(userID string) bool { return a.UserID != "" && a.UserID == userID }

// requireOwnership returns ErrForbidden unless the actor is an admin or the
// owner of the resource.
func (a Actor) requireOwnership(userID string) error {
	if a.IsAdmin() || a.IsSelf(userID) {
		return nil
	}
	return ErrForbidden
}

// HealthReport describes application health.
type HealthReport struct {
	Status           string `json:"status"`
	Version          string `json:"version"`
	DatabaseOK       bool   `json:"database_ok"`
	WireGuardOK      bool   `json:"wireguard_ok"`
	WireGuardDetail  string `json:"wireguard_detail,omitempty"`
	PendingMigration int    `json:"pending_migrations"`
	KyrosEnabled     bool   `json:"kyros_enabled"`
	Now              int64  `json:"now"`
}

// Version is set at build time via -ldflags.
var Version = "0.1.0-dev"

// Health collects health information.
func (s *Service) Health(ctx context.Context) (*HealthReport, error) {
	rep := &HealthReport{Version: Version, Now: time.Now().Unix()}
	if err := s.Store.Health(ctx); err != nil {
		rep.Status = "degraded"
		rep.DatabaseOK = false
		return rep, nil
	}
	rep.DatabaseOK = true
	pending, err := s.Store.PendingMigrations(ctx)
	if err == nil {
		rep.PendingMigration = pending
	}
	iface := s.defaultInterface(ctx)
	if st, err := s.WG.ReadState(ctx, iface); err != nil {
		rep.WireGuardOK = false
		rep.WireGuardDetail = err.Error()
	} else {
		rep.WireGuardOK = true
		_ = st
	}
	rep.KyrosEnabled = s.Cfg.KyrosEnabled
	if rep.Status == "" {
		if rep.DatabaseOK && rep.WireGuardOK {
			rep.Status = "ok"
		} else {
			rep.Status = "degraded"
		}
	}
	return rep, nil
}

func (s *Service) defaultInterface(ctx context.Context) string {
	srv, err := s.Store.GetDefaultServer(ctx)
	if err != nil || srv == nil {
		return s.Cfg.WGInterface
	}
	return srv.WGInterface
}

// syncPersistent rewrites the persistent configuration of a server from the
// current database state.
func (s *Service) syncPersistent(ctx context.Context, server *store.VPNServer) error {
	peers, err := s.Store.ListPeersOnServer(ctx, server.ID)
	if err != nil {
		return err
	}
	addr, err := interfaceAddress(server.VPNCIDR)
	if err != nil {
		return err
	}
	cfg := wg.PersistentConfig{
		Interface:  server.WGInterface,
		ListenPort: server.WGPort,
		Address:    addr,
		DNS:        splitCSV(server.DNS),
		SaveConfig: false,
	}
	if server.FullTunnel {
		// Enabling forwarding is part of the tunnel configuration itself.
		up := []string{"sysctl -w net.ipv4.ip_forward=1"}
		var down []string
		egress, err := egressInterface(s.Cfg.WGEgressIface)
		if err != nil {
			// Do not hard-fail the whole sync: the operator is told once, and
			// can fix the configuration without losing existing peers.
			s.Log.Warn("MASQUERADE rule skipped", "err", err)
		} else {
			nat := "iptables -t nat -A POSTROUTING -s " + server.VPNCIDR + " -o " + egress + " -j MASQUERADE"
			up = append(up, nat)
			down = append(down, strings.Replace(nat, " -A ", " -D ", 1))
		}
		cfg.PostUp = up
		cfg.PostDown = down
	}
	for _, p := range peers {
		if p.Status == "revoked" {
			continue
		}
		cfg.Peers = append(cfg.Peers, wg.ConfigPeer{PublicKey: p.PublicKey, AllowedIPs: []string{p.AllowedIP}})
	}
	return s.WG.SyncConfig(ctx, cfg)
}

func splitCSV(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' || r == ' ' || r == '\t' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
