package service

import (
	"context"
	"sync"
	"time"

	"github.com/aegis-vpn/aegis/internal/store"
)

// Collector periodically reads WireGuard counters, records snapshots, computes
// deltas, aggregates monthly usage, enforces quotas and applies expirations.
type Collector struct {
	svc      *Service
	interval time.Duration
	stop     chan struct{}
	once     sync.Once
}

// NewCollector creates a collector.
func NewCollector(svc *Service, interval time.Duration) *Collector {
	if interval <= 0 {
		interval = time.Minute
	}
	return &Collector{svc: svc, interval: interval, stop: make(chan struct{})}
}

// Start launches the background loop.
func (c *Collector) Start() {
	go func() {
		t := time.NewTicker(c.interval)
		defer t.Stop()
		for {
			select {
			case <-c.stop:
				return
			case <-t.C:
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				if err := c.svc.CollectOnce(ctx); err != nil {
					c.svc.Log.Warn("usage collection failed", "err", err)
				}
				cancel()
			}
		}
	}()
}

// Stop terminates the background loop.
func (c *Collector) Stop() {
	c.once.Do(func() { close(c.stop) })
}

// CollectOnce runs one full collection and enforcement pass.
func (s *Service) CollectOnce(ctx context.Context) error {
	peers, err := s.Store.ListPeersWithOwners(ctx)
	if err != nil {
		return err
	}
	servers, err := s.Store.ListServers(ctx)
	if err != nil {
		return err
	}
	serverByID := map[string]*store.VPNServer{}
	for _, srv := range servers {
		serverByID[srv.ID] = srv
	}

	now := s.Store.Now()
	month := store.CurrentMonth(now)

	type observed struct {
		rx, tx int64
		hand   int64
		seen   bool
	}
	observedByKey := map[string]observed{}

	for _, srv := range servers {
		st, err := s.WG.ReadState(ctx, srv.WGInterface)
		if err != nil {
			s.Log.Warn("wireguard state unavailable", "server", srv.Name, "err", err)
			continue
		}
		byKey := map[string]int{}
		for _, p := range st.Peers {
			byKey[p.PublicKey] = 1
		}
		for _, p := range st.Peers {
			observedByKey[srv.ID+"|"+p.PublicKey] = observed{
				rx: p.RxBytes, tx: p.TxBytes, hand: p.LastHandshakeAt.Unix(), seen: true,
			}
		}
		_ = byKey
	}

	// Reconcile DB peers with the live interface.
	for _, p := range peers {
		srv, ok := serverByID[p.ServerID]
		if !ok {
			continue
		}
		obs, seen := observedByKey[srv.ID+"|"+p.PublicKey]
		if !seen {
			// Interface lost the peer (restart, manual removal): restore it so
			// a reboot never silently drops an active configuration.
			if p.Status == "active" && p.AllowedIP != "" {
				if err := s.WG.AddPeer(ctx, srv.WGInterface, p.PublicKey, p.AllowedIP); err != nil {
					s.Log.Warn("peer restore failed", "peer", p.ID, "err", err)
				} else {
					s.Log.Info("peer restored after interface restart", "peer", p.ID)
				}
			}
			continue
		}

		snap, err := s.Store.AddSnapshot(ctx, p.ID, obs.rx, obs.tx, now.Unix())
		if err != nil {
			return err
		}
		if obs.hand > 0 {
			p.LastHandshakeAt = &obs.hand
		}
		p.RxBytes = obs.rx
		p.TxBytes = obs.tx
		if err := s.Store.UpdatePeer(ctx, p); err != nil {
			return err
		}
		if snap.DeltaRx > 0 || snap.DeltaTx > 0 {
			if err := s.Store.AddMonthlyUsage(ctx, p.UserID, month, snap.DeltaRx, snap.DeltaTx); err != nil {
				return err
			}
		}
		if obs.hand > 0 && p.DeviceID != "" {
			if d, err := s.Store.GetDevice(ctx, p.DeviceID); err == nil {
				h := obs.hand
				if d.LastSeenAt == nil || *d.LastSeenAt < h {
					d.LastSeenAt = &h
					_ = s.Store.UpdateDevice(ctx, d)
				}
			}
		}
	}

	if err := s.enforceExpiry(ctx, now.Unix()); err != nil {
		return err
	}
	if s.Cfg.QuotaAutoSuspend {
		if err := s.enforceQuota(ctx, month, now.Unix()); err != nil {
			return err
		}
	}
	return s.reactivateNewPeriod(ctx, month)
}

// enforceExpiry revokes peers whose profile lifetime or access expired.
func (s *Service) enforceExpiry(ctx context.Context, now int64) error {
	peers, err := s.Store.ListPeersWithOwners(ctx)
	if err != nil {
		return err
	}
	servers, err := s.Store.ListServers(ctx)
	if err != nil {
		return err
	}
	serverByID := map[string]*store.VPNServer{}
	for _, srv := range servers {
		serverByID[srv.ID] = srv
	}
	for _, p := range peers {
		if p.ExpiresAt == nil || now <= *p.ExpiresAt {
			continue
		}
		srv, ok := serverByID[p.ServerID]
		if !ok {
			continue
		}
		if err := s.WG.RemovePeer(ctx, srv.WGInterface, p.PublicKey); err != nil {
			continue
		}
		p.Status = "revoked"
		p.RevokedAt = &now
		_ = s.Store.UpdatePeer(ctx, p)
		_ = s.syncPersistent(ctx, srv)
		if d, err := s.Store.GetDevice(ctx, p.DeviceID); err == nil {
			d.Status = "revoked"
			d.RevokedAt = &now
			_ = s.Store.UpdateDevice(ctx, d)
		}
		s.Audit(ctx, Actor{Kind: "system"}, "peer.expire", "peer", p.ID, map[string]any{
			"user_id": p.UserID, "public_key": p.PublicKey,
		})
	}
	return nil
}

// enforceQuota suspends peers whose owner exceeded the monthly quota.
func (s *Service) enforceQuota(ctx context.Context, month string, now int64) error {
	peers, err := s.Store.ListPeersWithOwners(ctx)
	if err != nil {
		return err
	}
	servers, err := s.Store.ListServers(ctx)
	if err != nil {
		return err
	}
	serverByID := map[string]*store.VPNServer{}
	for _, srv := range servers {
		serverByID[srv.ID] = srv
	}
	userCache := map[string]*store.User{}

	for _, p := range peers {
		if p.Status != "active" {
			continue
		}
		u, ok := userCache[p.UserID]
		if !ok {
			u, err = s.Store.GetUser(ctx, p.UserID)
			if err != nil {
				continue
			}
			userCache[p.UserID] = u
		}
		pol, err := s.EffectivePolicy(ctx, u)
		if err != nil {
			continue
		}
		quota := s.QuotaFor(u, pol)
		if quota <= 0 {
			continue
		}
		usage, err := s.Store.GetMonthlyUsage(ctx, u.ID, month)
		if err != nil {
			continue
		}
		if usage.TotalBytes < quota {
			continue
		}
		srv, ok := serverByID[p.ServerID]
		if !ok {
			continue
		}
		if err := s.WG.RemovePeer(ctx, srv.WGInterface, p.PublicKey); err != nil {
			continue
		}
		p.Status = "suspended"
		p.SuspendedReason = "quota"
		_ = s.Store.UpdatePeer(ctx, p)
		_ = s.syncPersistent(ctx, srv)
		s.Audit(ctx, Actor{Kind: "system"}, "peer.suspend_quota", "peer", p.ID, map[string]any{
			"user_id": p.UserID, "month": month, "used_bytes": usage.TotalBytes, "quota_bytes": quota,
		})
		_ = now
	}
	return nil
}

// reactivateNewPeriod re-enables quota-suspended peers when a new month starts
// and the policy allows it.
func (s *Service) reactivateNewPeriod(ctx context.Context, month string) error {
	peers, err := s.Store.ListPeersWithOwners(ctx)
	if err != nil {
		return err
	}
	servers, err := s.Store.ListServers(ctx)
	if err != nil {
		return err
	}
	serverByID := map[string]*store.VPNServer{}
	for _, srv := range servers {
		serverByID[srv.ID] = srv
	}
	for _, p := range peers {
		if p.Status != "suspended" || p.SuspendedReason != "quota" {
			continue
		}
		u, err := s.Store.GetUser(ctx, p.UserID)
		if err != nil {
			continue
		}
		pol, err := s.EffectivePolicy(ctx, u)
		if err != nil || !pol.AutoReactivate {
			continue
		}
		usage, err := s.Store.GetMonthlyUsage(ctx, u.ID, month)
		if err != nil {
			continue
		}
		quota := s.QuotaFor(u, pol)
		if quota > 0 && usage.TotalBytes >= quota {
			continue
		}
		srv, ok := serverByID[p.ServerID]
		if !ok {
			continue
		}
		if err := s.WG.AddPeer(ctx, srv.WGInterface, p.PublicKey, p.AllowedIP); err != nil {
			continue
		}
		if pol.UpKbps > 0 || pol.DownKbps > 0 {
			if s.Cfg.RateLimitEnabled {
				_ = s.WG.ApplyRateLimit(ctx, srv.WGInterface, p.PublicKey, p.AllowedIP, pol.UpKbps, pol.DownKbps)
			}
		}
		p.Status = "active"
		p.SuspendedReason = ""
		_ = s.Store.UpdatePeer(ctx, p)
		_ = s.syncPersistent(ctx, srv)
		s.Audit(ctx, Actor{Kind: "system"}, "peer.resume", "peer", p.ID, map[string]any{
			"user_id": p.UserID, "month": month,
		})
	}
	return nil
}

// SuspendAccess suspends or restores every peer of a user (administrative).
func (s *Service) SuspendAccess(ctx context.Context, actor Actor, userID string, suspend bool) error {
	if !actor.IsAdmin() {
		return ErrForbidden
	}
	u, err := s.Store.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	servers, err := s.Store.ListServers(ctx)
	if err != nil {
		return err
	}
	serverByID := map[string]*store.VPNServer{}
	for _, srv := range servers {
		serverByID[srv.ID] = srv
	}
	peers, err := s.Store.ListPeersWithOwners(ctx)
	if err != nil {
		return err
	}
	for _, p := range peers {
		if p.UserID != userID || p.Status == "revoked" {
			continue
		}
		srv, ok := serverByID[p.ServerID]
		if !ok {
			continue
		}
		if suspend {
			if p.Status != "active" {
				continue
			}
			if err := s.WG.RemovePeer(ctx, srv.WGInterface, p.PublicKey); err != nil {
				return err
			}
			p.Status = "suspended"
			p.SuspendedReason = "admin"
		} else {
			if p.Status != "suspended" || p.SuspendedReason != "admin" {
				continue
			}
			if err := s.WG.AddPeer(ctx, srv.WGInterface, p.PublicKey, p.AllowedIP); err != nil {
				return err
			}
			p.Status = "active"
			p.SuspendedReason = ""
		}
		_ = s.Store.UpdatePeer(ctx, p)
		_ = s.syncPersistent(ctx, srv)
	}
	action := "access.suspend"
	if !suspend {
		action = "access.resume"
	}
	s.Audit(ctx, actor, action, "user", u.ID, nil)
	return nil
}
