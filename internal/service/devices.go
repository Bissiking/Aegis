package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aegis-vpn/aegis/internal/crypto/wgkeys"
	"github.com/aegis-vpn/aegis/internal/store"
)

// EffectivePolicy resolves the policy applied to a user: the user's own policy
// when set, otherwise the default "standard" policy, otherwise built-in
// defaults derived from configuration.
func (s *Service) EffectivePolicy(ctx context.Context, u *store.User) (*store.AccessPolicy, error) {
	if u.PolicyID != nil && *u.PolicyID != "" {
		p, err := s.Store.GetPolicy(ctx, *u.PolicyID)
		if err == nil {
			return p, nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	policies, err := s.Store.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range policies {
		if p.Name == "standard" {
			return p, nil
		}
	}
	if len(policies) > 0 {
		return policies[0], nil
	}
	return &store.AccessPolicy{
		MaxDevices:        s.Cfg.MaxDevicesDefault,
		MonthlyQuotaBytes: 0,
		FullTunnel:        s.Cfg.WGFullTunnel,
		AllowedNetworks:   defaultNetworks(s.Cfg),
		AutoReactivate:    true,
	}, nil
}

// QuotaFor returns the effective monthly quota in bytes (0 = unlimited).
func (s *Service) QuotaFor(u *store.User, p *store.AccessPolicy) int64 {
	if u.QuotaBytesOverride != nil && *u.QuotaBytesOverride > 0 {
		return *u.QuotaBytesOverride
	}
	if p != nil {
		return p.MonthlyQuotaBytes
	}
	return 0
}

// MaxDevicesFor returns the effective device limit (0 = unlimited).
func (s *Service) MaxDevicesFor(p *store.AccessPolicy) int {
	if p == nil {
		return s.Cfg.MaxDevicesDefault
	}
	if p.MaxDevices < 0 {
		return 0
	}
	return p.MaxDevices
}

// AccessExpiry returns the earliest applicable expiry timestamp, if any.
func (s *Service) AccessExpiry(u *store.User, p *store.AccessPolicy) *int64 {
	candidates := []*int64{}
	if u.ExpiresAt != nil {
		candidates = append(candidates, u.ExpiresAt)
	}
	if p != nil && p.ExpiresAt != nil {
		candidates = append(candidates, p.ExpiresAt)
	}
	if len(candidates) == 0 {
		return nil
	}
	min := *candidates[0]
	for _, c := range candidates[1:] {
		if *c < min {
			min = *c
		}
	}
	return &min
}

// CreateDeviceInput is the user-facing device payload.
type CreateDeviceInput struct {
	UserID   string
	Name     string
	Platform string
	ServerID string
}

// DeviceProfile is the one-time configuration delivered exactly once.
type DeviceProfile struct {
	Filename    string `json:"filename"`
	Conf        string `json:"conf"`
	QRPNGBase64 string `json:"qr_png_base64"`
	Warned      bool   `json:"one_time_only"`
	ServerName  string `json:"server_name"`
	AllowedIP   string `json:"allowed_ip"`
	PublicKey   string `json:"public_key"`
	ExpiresAt   *int64 `json:"expires_at"`
	DNS         string `json:"dns"`
	Endpoint    string `json:"endpoint"`
}

// CreatedDevice is returned by CreateDevice and RotateDevice.
type CreatedDevice struct {
	Device  *store.Device        `json:"device"`
	Peer    *store.WireGuardPeer `json:"peer"`
	Profile *DeviceProfile       `json:"profile"`
}

// CreateDevice provisions a device, its WireGuard peer and returns the
// configuration exactly once.
//
// The private key is generated here, returned in this response and never
// written to disk, database or logs.
func (s *Service) CreateDevice(ctx context.Context, actor Actor, in CreateDeviceInput) (*CreatedDevice, error) {
	targetID := in.UserID
	if targetID == "" {
		targetID = actor.UserID
	}
	if err := actor.requireOwnership(targetID); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, fmtInvalid("name")
	}
	if len(name) > 64 {
		return nil, fmtInvalid("name")
	}
	platform := sanitizePlatform(in.Platform)

	user, err := s.Store.GetUser(ctx, targetID)
	if err != nil {
		return nil, err
	}
	if user.Status != store.UserActive {
		return nil, ErrForbidden
	}
	policy, err := s.EffectivePolicy(ctx, user)
	if err != nil {
		return nil, err
	}
	now := s.Store.Now().Unix()
	if exp := s.AccessExpiry(user, policy); exp != nil && *exp < now {
		return nil, ErrForbidden
	}

	count, err := s.Store.CountActiveDevices(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	if max := s.MaxDevicesFor(policy); max > 0 && count >= max {
		return nil, &FieldError{Field: "max_devices"}
	}

	srv, err := s.resolveServer(ctx, in.ServerID)
	if err != nil {
		return nil, err
	}
	peerCount, err := s.Store.CountPeersOnServer(ctx, srv.ID)
	if err != nil {
		return nil, err
	}
	if srv.MaxPeers > 0 && peerCount >= srv.MaxPeers {
		return nil, ErrQuota
	}

	used, err := s.Store.UsedIPs(ctx, srv.ID)
	if err != nil {
		return nil, err
	}
	ip, err := allocateIP(srv.VPNCIDR, used)
	if err != nil {
		return nil, err
	}

	keys, err := wgkeys.Generate()
	if err != nil {
		return nil, err
	}
	pub := keys.EncodePublic()

	device := &store.Device{
		ID:       store.NewID("dev"),
		UserID:   user.ID,
		ServerID: srv.ID,
		Name:     name,
		Platform: platform,
		Status:   "active",
	}
	if err := s.Store.CreateDevice(ctx, device); err != nil {
		return nil, err
	}

	peer := &store.WireGuardPeer{
		ID:        store.NewID("per"),
		DeviceID:  device.ID,
		ServerID:  srv.ID,
		PublicKey: pub,
		AllowedIP: ip,
		Status:    "active",
	}
	if ttl := profileTTL(srv); ttl > 0 {
		exp := now + int64(ttl)*3600
		peer.ExpiresAt = &exp
	}
	if err := s.Store.CreatePeer(ctx, peer); err != nil {
		_ = s.Store.DeleteDevice(ctx, device.ID)
		return nil, err
	}

	if err := s.WG.AddPeer(ctx, srv.WGInterface, pub, ip); err != nil {
		_ = s.Store.DeleteDevice(ctx, device.ID)
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if policy.UpKbps > 0 || policy.DownKbps > 0 {
		if s.Cfg.RateLimitEnabled {
			_ = s.WG.ApplyRateLimit(ctx, srv.WGInterface, pub, ip, policy.UpKbps, policy.DownKbps)
		}
	}
	_ = s.syncPersistent(ctx, srv)

	profile, err := s.renderProfile(ctx, srv, device, peer, keys)
	if err != nil {
		return nil, err
	}
	s.Audit(ctx, actor, "device.create", "device", device.ID, map[string]any{
		"user_id": user.ID, "server_id": srv.ID, "public_key": pub, "allowed_ip": ip,
	})
	s.Audit(ctx, actor, "profile.deliver", "device", device.ID, map[string]any{"public_key": pub})

	full, err := s.Store.GetDevice(ctx, device.ID)
	if err != nil {
		full = device
	}
	return &CreatedDevice{Device: full, Peer: peer, Profile: profile}, nil
}

func profileTTL(srv *store.VPNServer) int {
	if srv.ProfileTTLHours > 0 {
		return srv.ProfileTTLHours
	}
	return 0
}

func sanitizePlatform(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	switch p {
	case "android", "ios", "windows", "macos", "linux", "generic":
		return p
	case "":
		return "generic"
	default:
		return "generic"
	}
}

func (s *Service) resolveServer(ctx context.Context, id string) (*store.VPNServer, error) {
	if id == "" {
		srv, err := s.Store.GetDefaultServer(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: no vpn server configured", ErrUnavailable)
		}
		return srv, nil
	}
	srv, err := s.Store.GetServer(ctx, id)
	if err != nil {
		return nil, fmtInvalid("server_id")
	}
	if !srv.Enabled {
		return nil, ErrForbidden
	}
	return srv, nil
}

// renderProfile builds the client configuration and its QR code. The private
// key exists only inside this function's inputs and its return value.
func (s *Service) renderProfile(ctx context.Context, srv *store.VPNServer, dev *store.Device, peer *store.WireGuardPeer, keys wgkeys.KeyPair) (*DeviceProfile, error) {
	allowedIPs := "0.0.0.0/0"
	if !srv.FullTunnel {
		allowedIPs = srv.VPNCIDR
	}
	// IPv6 is only announced when the deployment really routes it.
	if srv.IPv6Enabled {
		allowedIPs += ", ::/0"
	}
	endpoint := srv.EndpointPublic
	if endpoint == "" {
		endpoint = s.Cfg.WGEndpoint
	}
	if endpoint != "" && !strings.Contains(endpoint, ":") {
		endpoint = fmt.Sprintf("%s:%d", endpoint, srv.WGPort)
	}

	state, err := s.WG.ReadState(ctx, srv.WGInterface)
	if err != nil {
		return nil, fmt.Errorf("%w: read WireGuard server state: %v", ErrUnavailable, err)
	}
	serverPublicKey := strings.TrimSpace(state.PublicKey)
	if serverPublicKey == "" {
		return nil, fmt.Errorf("%w: WireGuard server public key unavailable", ErrUnavailable)
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = " + keys.EncodePrivate() + "\n")
	b.WriteString("Address = " + peer.AllowedIP + ", fd77::" + hostSuffix(peer.AllowedIP) + "/128\n")
	b.WriteString("DNS = " + srv.DNS + "\n")
	b.WriteString("\n[Peer]\n")
	b.WriteString("PublicKey = " + serverPublicKey + "\n")
	b.WriteString("AllowedIPs = " + allowedIPs + "\n")
	if endpoint != "" {
		b.WriteString("Endpoint = " + endpoint + "\n")
	}
	if s.Cfg.WGPersistentKeepalive > 0 {
		b.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", s.Cfg.WGPersistentKeepalive))
	}
	conf := b.String()

	png, err := encodeQR(conf)
	if err != nil {
		return nil, err
	}
	return &DeviceProfile{
		Filename:    wireGuardProfileFilename(dev.Name),
		Conf:        conf,
		QRPNGBase64: png,
		Warned:      true,
		ServerName:  srv.Name,
		AllowedIP:   peer.AllowedIP,
		PublicKey:   peer.PublicKey,
		ExpiresAt:   peer.ExpiresAt,
		DNS:         srv.DNS,
		Endpoint:    endpoint,
	}, nil
}

// hostSuffix derives the trailing IPv6 hextet from an IPv4 host address so the
// profile always carries a stable, valid IPv6 host address. ::/0 is never
// announced.
func wireGuardProfileFilename(name string) string {
	base := "aegis-" + strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	lastDash := false
	for _, r := range base {
		allowed := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
			r == '_' || r == '=' || r == '+' || r == '.' || r == '-'
		if allowed {
			if r == '-' {
				if lastDash {
					continue
				}
				lastDash = true
			} else {
				lastDash = false
			}
			b.WriteRune(r)
		} else if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	base = strings.Trim(b.String(), "-.")
	if base == "" || base == "aegis" {
		base = "aegis-device"
	}
	// WireGuard tunnel names are interface names on several clients. Keep the
	// basename within the Linux IFNAMSIZ-compatible 15 character limit.
	if len(base) > 15 {
		base = strings.TrimRight(base[:15], "-.")
	}
	if base == "" {
		base = "aegis"
	}
	return base + ".conf"
}

func hostSuffix(ipv4CIDR string) string {
	addr := ipv4CIDR
	if i := strings.IndexByte(addr, '/'); i > 0 {
		addr = addr[:i]
	}
	parts := strings.Split(addr, ".")
	if len(parts) != 4 {
		return "1"
	}
	a := toInt(parts[0])
	b := toInt(parts[1])
	c := toInt(parts[2])
	d := toInt(parts[3])
	v := a<<24 | b<<16 | c<<8 | d
	return fmt.Sprintf("%x:%x", (v>>16)&0xffff, v&0xffff)
}

func toInt(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// GetProfile always refuses: a configuration is deliverable exactly once.
func (s *Service) GetProfile(ctx context.Context, actor Actor, deviceID string) error {
	d, err := s.Store.GetDevice(ctx, deviceID)
	if err != nil {
		return err
	}
	if err := actor.requireOwnership(d.UserID); err != nil {
		return err
	}
	return ErrGone
}

// RevokeDevice removes the peer immediately from the live interface and from
// the persistent configuration. Other devices are untouched.
func (s *Service) RevokeDevice(ctx context.Context, actor Actor, deviceID string) error {
	d, err := s.Store.GetDevice(ctx, deviceID)
	if err != nil {
		return err
	}
	if err := actor.requireOwnership(d.UserID); err != nil {
		return err
	}
	if d.Status == "revoked" {
		return nil
	}
	peer, err := s.Store.GetPeerByDevice(ctx, deviceID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if peer != nil {
		srv, err := s.Store.GetServer(ctx, peer.ServerID)
		if err == nil {
			if err := s.WG.RemovePeer(ctx, srv.WGInterface, peer.PublicKey); err != nil {
				return fmt.Errorf("%w: %v", ErrUnavailable, err)
			}
			peer.Status = "revoked"
			now := s.Store.Now().Unix()
			peer.RevokedAt = &now
			_ = s.Store.UpdatePeer(ctx, peer)
			_ = s.syncPersistent(ctx, srv)
		}
	}
	now := s.Store.Now().Unix()
	d.Status = "revoked"
	d.RevokedAt = &now
	if err := s.Store.UpdateDevice(ctx, d); err != nil {
		return err
	}
	s.Audit(ctx, actor, "device.revoke", "device", d.ID, map[string]any{"user_id": d.UserID})
	return nil
}

// RotateDevice generates a new key pair for an existing device, replaces the
// peer on the interface and returns the new configuration exactly once.
func (s *Service) RotateDevice(ctx context.Context, actor Actor, deviceID string) (*CreatedDevice, error) {
	d, err := s.Store.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	if err := actor.requireOwnership(d.UserID); err != nil {
		return nil, err
	}
	if d.Status == "revoked" {
		return nil, ErrGone
	}
	peer, err := s.Store.GetPeerByDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	srv, err := s.Store.GetServer(ctx, peer.ServerID)
	if err != nil {
		return nil, err
	}
	keys, err := wgkeys.Generate()
	if err != nil {
		return nil, err
	}
	oldKey := peer.PublicKey
	newKey := keys.EncodePublic()

	if err := s.WG.RemovePeer(ctx, srv.WGInterface, oldKey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if err := s.WG.AddPeer(ctx, srv.WGInterface, newKey, peer.AllowedIP); err != nil {
		// Best effort: restore the previous peer so the device keeps working.
		_ = s.WG.AddPeer(ctx, srv.WGInterface, oldKey, peer.AllowedIP)
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	now := s.Store.Now().Unix()
	if err := s.Store.ReplacePeerPublicKey(ctx, peer.ID, newKey, now); err != nil {
		return nil, err
	}
	peer, err = s.Store.GetPeer(ctx, peer.ID)
	if err != nil {
		return nil, err
	}
	_ = s.syncPersistent(ctx, srv)

	profile, err := s.renderProfile(ctx, srv, d, peer, keys)
	if err != nil {
		return nil, err
	}
	s.Audit(ctx, actor, "device.rotate", "device", d.ID, map[string]any{
		"old_public_key": oldKey, "new_public_key": newKey,
	})
	s.Audit(ctx, actor, "profile.deliver", "device", d.ID, map[string]any{"public_key": newKey})

	full, err := s.Store.GetDevice(ctx, d.ID)
	if err != nil {
		full = d
	}
	return &CreatedDevice{Device: full, Peer: peer, Profile: profile}, nil
}

// DeleteDevice removes the device record entirely (after revoking the peer).
func (s *Service) DeleteDevice(ctx context.Context, actor Actor, deviceID string) error {
	d, err := s.Store.GetDevice(ctx, deviceID)
	if err != nil {
		return err
	}
	if !actor.IsAdmin() && !actor.IsSelf(d.UserID) {
		return ErrForbidden
	}
	peer, err := s.Store.GetPeerByDevice(ctx, deviceID)
	if err == nil {
		if srv, err := s.Store.GetServer(ctx, peer.ServerID); err == nil {
			_ = s.WG.RemovePeer(ctx, srv.WGInterface, peer.PublicKey)
			_ = s.syncPersistent(ctx, srv)
		}
	}
	if err := s.Store.DeleteDevice(ctx, deviceID); err != nil {
		return err
	}
	s.Audit(ctx, actor, "device.delete", "device", deviceID, map[string]any{"user_id": d.UserID})
	return nil
}

// DeviceState is the human-facing status of a device.
type DeviceState string

const (
	StateActive         DeviceState = "active"
	StateNeverConnected DeviceState = "never_connected"
	StateRecent         DeviceState = "connected_recently"
	StateExpired        DeviceState = "expired"
	StateSuspended      DeviceState = "suspended"
	StateQuotaExceeded  DeviceState = "quota_exceeded"
	StateRevoked        DeviceState = "revoked"
)

// ComputeState derives the displayed state from device, peer, user and clock.
func (s *Service) ComputeState(d *store.Device, peer *store.WireGuardPeer, u *store.User, p *store.AccessPolicy, now int64) DeviceState {
	if d.Status == "revoked" {
		return StateRevoked
	}
	if peer != nil && peer.Status == "revoked" {
		return StateRevoked
	}
	if u != nil && u.Status == store.UserSuspended {
		return StateSuspended
	}
	if peer != nil && peer.Status == "suspended" {
		if peer.SuspendedReason == "quota" {
			return StateQuotaExceeded
		}
		return StateSuspended
	}
	if exp := s.AccessExpiry(u, p); exp != nil && now > *exp {
		return StateExpired
	}
	if peer != nil && peer.ExpiresAt != nil && now > *peer.ExpiresAt {
		return StateExpired
	}
	if peer == nil || peer.LastHandshakeAt == nil || *peer.LastHandshakeAt == 0 {
		return StateNeverConnected
	}
	if now-*peer.LastHandshakeAt <= 180 {
		return StateRecent
	}
	return StateActive
}

// ListDevices returns devices visible to the actor.
func (s *Service) ListDevices(ctx context.Context, actor Actor, f store.DeviceFilter) ([]*store.Device, int, error) {
	if !actor.IsAdmin() {
		if f.UserID != "" && f.UserID != actor.UserID {
			return nil, 0, ErrForbidden
		}
		f.UserID = actor.UserID
	}
	devs, total, err := s.Store.ListDevices(ctx, f)
	if err != nil {
		return nil, 0, err
	}
	now := s.Store.Now().Unix()
	for _, d := range devs {
		var u *store.User
		var pol *store.AccessPolicy
		if actor.IsAdmin() && d.UserID != actor.UserID {
			u, _ = s.Store.GetUser(ctx, d.UserID)
			if u != nil {
				pol, _ = s.EffectivePolicy(ctx, u)
			}
		} else {
			u, _ = s.Store.GetUser(ctx, d.UserID)
			if u != nil {
				pol, _ = s.EffectivePolicy(ctx, u)
			}
		}
		var peer *store.WireGuardPeer
		if d.PublicKey != "" {
			peer = &store.WireGuardPeer{
				Status:             d.PeerStatus,
				SuspendedReason:    d.SuspendedReason,
				LastHandshakeAt:    d.LastHandshakeAt,
				ExpiresAt:          d.PeerExpiresAt,
				PublicKey:          d.PublicKey,
				AllowedIP:          d.AllowedIP,
				RxBytes:            d.RxBytes,
				TxBytes:            d.TxBytes,
				ProfileDeliveredAt: d.ProfileDelivered,
			}
		}
		d.EffectiveState = string(s.ComputeState(d, peer, u, pol, now))
	}
	return devs, total, nil
}

// GetDevice returns one device with its computed state.
func (s *Service) GetDevice(ctx context.Context, actor Actor, deviceID string) (*store.Device, error) {
	d, err := s.Store.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	if err := actor.requireOwnership(d.UserID); err != nil {
		return nil, err
	}
	u, _ := s.Store.GetUser(ctx, d.UserID)
	var pol *store.AccessPolicy
	if u != nil {
		pol, _ = s.EffectivePolicy(ctx, u)
	}
	var peer *store.WireGuardPeer
	if d.PublicKey != "" {
		peer = &store.WireGuardPeer{
			Status:          d.PeerStatus,
			SuspendedReason: d.SuspendedReason,
			LastHandshakeAt: d.LastHandshakeAt,
			ExpiresAt:       d.PeerExpiresAt,
			PublicKey:       d.PublicKey,
			AllowedIP:       d.AllowedIP,
			RxBytes:         d.RxBytes,
			TxBytes:         d.TxBytes,
		}
	}
	d.EffectiveState = string(s.ComputeState(d, peer, u, pol, s.Store.Now().Unix()))
	return d, nil
}

// TouchDevice marks a device as seen (used when a profile is delivered).
func (s *Service) TouchDevice(ctx context.Context, deviceID string) {
	d, err := s.Store.GetDevice(ctx, deviceID)
	if err != nil {
		return
	}
	now := s.Store.Now().Unix()
	d.LastSeenAt = &now
	_ = s.Store.UpdateDevice(ctx, d)
}
