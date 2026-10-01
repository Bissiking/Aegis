package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"log/slog"
	"os"

	"github.com/aegis-vpn/aegis/internal/config"
	"github.com/aegis-vpn/aegis/internal/store"
	"github.com/aegis-vpn/aegis/internal/wg"
)

func testConfig() *config.Config {
	return &config.Config{
		DatabasePath:            ":memory:",
		ListenAddr:              "127.0.0.1:0",
		SessionSecret:           "test-secret-test-secret-test-secret-1234",
		LocalAuthEnabled:        true,
		LocalBootstrapUser:      "admin@example.org",
		LocalBootstrapPassword:  "Bootstrap-Passw0rd!",
		ArgonTime:               1,
		ArgonMemoryKiB:          8 * 1024,
		ArgonThreads:            1,
		ArgonKeyLen:             32,
		LoginRateLimitPerMinute: 10,
		APIRateLimitPerMinute:   600,
		WGInterface:             "wg0",
		WGPort:                  51820,
		WGNetwork:               "10.77.0.0/24",
		WGDNS:                   []string{"1.1.1.1"},
		WGMaxPeers:              32,
		WGFullTunnel:            true,
		WGPersistentKeepalive:   25,
		MaxDevicesDefault:       3,
		CookieSecure:            false,
		Environment:             "development",
		Development:             true,
	}
}

func newSvc(t *testing.T) (*Service, *wg.Fake, *store.Store) {
	t.Helper()
	cfg := testConfig()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	fake := wg.NewFake()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := New(st, fake, cfg, log)
	if err := svc.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	return svc, fake, st
}

func adminActor() Actor {
	return Actor{UserID: "usr_admin", Kind: "local", Role: store.RoleAdmin}
}

func TestBootstrapIsIdempotent(t *testing.T) {
	svc, _, st := newSvc(t)
	if err := svc.Bootstrap(context.Background()); err != nil {
		t.Fatalf("second bootstrap: %v", err)
	}
	users, total, err := st.ListUsers(context.Background(), store.UserFilter{})
	if err != nil || total != 1 {
		t.Fatalf("users=%d err=%v", total, err)
	}
	if users[0].Role != store.RoleAdmin {
		t.Fatalf("role = %s", users[0].Role)
	}
	servers, err := st.ListServers(context.Background())
	if err != nil || len(servers) != 1 {
		t.Fatalf("servers=%d err=%v", len(servers), err)
	}
	pols, _ := st.ListPolicies(context.Background())
	if len(pols) != 1 {
		t.Fatalf("policies=%d", len(pols))
	}
}

func createUser(t *testing.T, svc *Service, email string) *store.User {
	t.Helper()
	u, err := svc.CreateUser(context.Background(), adminActor(), CreateUserInput{
		Email: email, DisplayName: email, Role: store.RoleUser, Password: "Valid-Password1!",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func actorForUser(u *store.User) Actor {
	return Actor{UserID: u.ID, Kind: "local", Role: u.Role}
}

func TestDeviceLimitEnforced(t *testing.T) {
	svc, _, _ := newSvc(t)
	u := createUser(t, svc, "limit@example.org")

	for i := 0; i < 3; i++ {
		_, err := svc.CreateDevice(context.Background(), actorForUser(u), CreateDeviceInput{
			UserID: u.ID, Name: "dev", Platform: "linux",
		})
		if err != nil {
			t.Fatalf("device %d: %v", i, err)
		}
	}
	_, err := svc.CreateDevice(context.Background(), actorForUser(u), CreateDeviceInput{
		UserID: u.ID, Name: "over", Platform: "linux",
	})
	var fe *FieldError
	if !errors.As(err, &fe) || fe.Field != "max_devices" {
		t.Fatalf("expected max_devices error, got %v", err)
	}
}

func TestRevokeOnlyAffectsTargetDevice(t *testing.T) {
	svc, fake, _ := newSvc(t)
	u := createUser(t, svc, "multi@example.org")
	ctx := context.Background()

	a, err := svc.CreateDevice(ctx, actorForUser(u), CreateDeviceInput{UserID: u.ID, Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.CreateDevice(ctx, actorForUser(u), CreateDeviceInput{UserID: u.ID, Name: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	if !fake.HasPeer("wg0", a.Peer.PublicKey) || !fake.HasPeer("wg0", b.Peer.PublicKey) {
		t.Fatal("both peers should exist")
	}

	if err := svc.RevokeDevice(ctx, actorForUser(u), a.Device.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if fake.HasPeer("wg0", a.Peer.PublicKey) {
		t.Fatal("revoked peer still present on the interface")
	}
	if !fake.HasPeer("wg0", b.Peer.PublicKey) {
		t.Fatal("other device must be untouched")
	}
	// Persistent config must no longer contain the revoked peer.
	cfg, err := fake.LastConfig()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range cfg.Peers {
		if p.PublicKey == a.Peer.PublicKey {
			t.Fatal("revoked peer persisted in configuration")
		}
	}
}

func TestProfileIsDeliveredExactlyOnce(t *testing.T) {
	svc, _, _ := newSvc(t)
	u := createUser(t, svc, "once@example.org")
	ctx := context.Background()

	d, err := svc.CreateDevice(ctx, actorForUser(u), CreateDeviceInput{UserID: u.ID, Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Profile == nil || d.Profile.Conf == "" || d.Profile.QRPNGBase64 == "" {
		t.Fatal("profile must be returned on creation")
	}
	// A second fetch must fail with 410 Gone.
	if err := svc.GetProfile(ctx, actorForUser(u), d.Device.ID); !errors.Is(err, ErrGone) {
		t.Fatalf("expected ErrGone, got %v", err)
	}
}

func TestGeneratedProfileUsesServerPublicKeyAndSafeFilename(t *testing.T) {
	svc, _, _ := newSvc(t)
	u := createUser(t, svc, "profile@example.org")
	ctx := context.Background()

	d, err := svc.CreateDevice(ctx, actorForUser(u), CreateDeviceInput{
		UserID: u.ID,
		Name:   "Bertha de poche",
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Profile == nil {
		t.Fatal("profile is nil")
	}
	const serverKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if !contains(d.Profile.Conf, "PublicKey = "+serverKey+"\n") {
		t.Fatalf("profile does not contain server public key: %s", d.Profile.Conf)
	}
	if contains(d.Profile.Conf, "PublicKey = "+d.Peer.PublicKey+"\n") {
		t.Fatal("client profile must not use the client public key as [Peer] PublicKey")
	}
	if d.Profile.Filename != "aegis-bertha-de.conf" {
		t.Fatalf("filename = %q", d.Profile.Filename)
	}
}

func TestPrivateNeverStoredNorLogged(t *testing.T) {
	svc, fake, st := newSvc(t)
	u := createUser(t, svc, "secret@example.org")
	ctx := context.Background()

	d, err := svc.CreateDevice(ctx, actorForUser(u), CreateDeviceInput{UserID: u.ID, Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	priv := extractPrivate(t, d.Profile.Conf)
	if priv == "" {
		t.Fatal("no private key in profile")
	}

	// 1. Not in the database.
	events, _, err := st.ListAudit(ctx, store.AuditFilter{Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if contains(e.Detail, priv) {
			t.Fatal("private key leaked into the audit journal")
		}
	}
	// 2. Not in the peer record (public key only).
	peer, err := st.GetPeerByDevice(ctx, d.Device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if peer.PublicKey == priv {
		t.Fatal("private key stored as public key")
	}
	// 3. Not in the persistent WireGuard configuration written by the agent.
	cfg, _ := fake.LastConfig()
	for _, p := range cfg.Peers {
		if p.PublicKey == priv {
			t.Fatal("private key present in agent configuration")
		}
	}
}

func extractPrivate(t *testing.T, conf string) string {
	t.Helper()
	const marker = "PrivateKey = "
	i := indexOf(conf, marker)
	if i < 0 {
		t.Fatal("no PrivateKey line")
	}
	rest := conf[i+len(marker):]
	j := indexOf(rest, "\n")
	if j < 0 {
		j = len(rest)
	}
	return rest[:j]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func contains(s, sub string) bool { return indexOf(s, sub) >= 0 }

func TestRotateInvalidatesPreviousKey(t *testing.T) {
	svc, fake, _ := newSvc(t)
	u := createUser(t, svc, "rotate@example.org")
	ctx := context.Background()

	d, err := svc.CreateDevice(ctx, actorForUser(u), CreateDeviceInput{UserID: u.ID, Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	old := d.Peer.PublicKey
	out, err := svc.RotateDevice(ctx, actorForUser(u), d.Device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if out.Peer.PublicKey == old {
		t.Fatal("public key did not change")
	}
	if fake.HasPeer("wg0", old) {
		t.Fatal("old peer still on the interface")
	}
	if !fake.HasPeer("wg0", out.Peer.PublicKey) {
		t.Fatal("new peer missing on the interface")
	}
	if out.Profile == nil {
		t.Fatal("new profile must be delivered")
	}
}

func TestUserCannotAccessOtherUsersDevices(t *testing.T) {
	svc, _, _ := newSvc(t)
	alice := createUser(t, svc, "alice@example.org")
	bob := createUser(t, svc, "bob@example.org")
	ctx := context.Background()

	d, err := svc.CreateDevice(ctx, actorForUser(alice), CreateDeviceInput{UserID: alice.ID, Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	bobActor := actorForUser(bob)

	if _, err := svc.GetDevice(ctx, bobActor, d.Device.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("bob must not read alice's device, got %v", err)
	}
	if err := svc.RevokeDevice(ctx, bobActor, d.Device.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("bob must not revoke alice's device, got %v", err)
	}
	if _, err := svc.RotateDevice(ctx, bobActor, d.Device.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("bob must not rotate alice's device, got %v", err)
	}
	if err := svc.DeleteDevice(ctx, bobActor, d.Device.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("bob must not delete alice's device, got %v", err)
	}
	// Bob only sees his own devices.
	devs, total, err := svc.ListDevices(ctx, bobActor, store.DeviceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 || len(devs) != 0 {
		t.Fatalf("bob sees %d devices", total)
	}
}

func TestUserCannotRaiseOwnQuota(t *testing.T) {
	svc, _, _ := newSvc(t)
	u := createUser(t, svc, "quota@example.org")
	actor := actorForUser(u)

	over := int64(999_999_999_999)
	_, err := svc.UpdateUser(context.Background(), actor, u.ID, UpdateUserInput{Quota: &over})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected forbidden, got %v", err)
	}
	role := store.RoleAdmin
	if _, err := svc.UpdateUser(context.Background(), actor, u.ID, UpdateUserInput{Role: &role}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected forbidden on self promotion, got %v", err)
	}
	// An admin can set it.
	if _, err := svc.UpdateUser(context.Background(), adminActor(), u.ID, UpdateUserInput{Quota: &over}); err != nil {
		t.Fatalf("admin quota update: %v", err)
	}
	got, _ := svc.Store.GetUser(context.Background(), u.ID)
	if got.QuotaBytesOverride == nil || *got.QuotaBytesOverride != over {
		t.Fatalf("quota not applied: %+v", got.QuotaBytesOverride)
	}
}

func TestQuotaSuspendsPeerAndReactivatesOnNewPeriod(t *testing.T) {
	svc, fake, st := newSvc(t)
	ctx := context.Background()
	u := createUser(t, svc, "cap@example.org")

	// Tight quota: 1000 bytes.
	small := int64(1000)
	if _, err := svc.UpdateUser(ctx, adminActor(), u.ID, UpdateUserInput{Quota: &small}); err != nil {
		t.Fatal(err)
	}
	d, err := svc.CreateDevice(ctx, actorForUser(u), CreateDeviceInput{UserID: u.ID, Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}

	// Simulate traffic above the quota.
	month := store.CurrentMonth(time.Now())
	if err := st.AddMonthlyUsage(ctx, u.ID, month, 900, 500); err != nil {
		t.Fatal(err)
	}
	if err := svc.enforceQuota(ctx, month, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if fake.HasPeer("wg0", d.Peer.PublicKey) {
		t.Fatal("peer should have been removed on quota exceeded")
	}
	peer, err := st.GetPeerByDevice(ctx, d.Device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if peer.Status != "suspended" || peer.SuspendedReason != "quota" {
		t.Fatalf("peer state = %s/%s", peer.Status, peer.SuspendedReason)
	}

	state := svc.ComputeState(d.Device, peer, u, nil, time.Now().Unix())
	if state != StateQuotaExceeded {
		t.Fatalf("state = %s", state)
	}

	// New period: reset usage, auto reactivation kicks in.
	_ = st.ResetMonthlyUsage(ctx, u.ID, month)
	if err := svc.reactivateNewPeriod(ctx, month+"-next"); err != nil {
		t.Fatal(err)
	}
	// usage for the new month is zero -> resume
	peer, _ = st.GetPeerByDevice(ctx, d.Device.ID)
	if peer.Status != "active" {
		t.Fatalf("peer status = %s after reactivation", peer.Status)
	}
	if !fake.HasPeer("wg0", d.Peer.PublicKey) {
		t.Fatal("peer should be back on the interface")
	}
}

func TestCounterResetDoesNotProduceNegativeUsage(t *testing.T) {
	svc, _, st := newSvc(t)
	ctx := context.Background()
	u := createUser(t, svc, "counters@example.org")
	_, err := svc.CreateDevice(ctx, actorForUser(u), CreateDeviceInput{UserID: u.ID, Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	month := store.CurrentMonth(time.Now())

	// First pass with high counters.
	if err := st.AddMonthlyUsage(ctx, u.ID, month, 5000, 4000); err != nil {
		t.Fatal(err)
	}
	// Interface restarts: AddSnapshot flags a reset and returns positive deltas.
	peers, _ := st.ListAllPeers(ctx)
	if len(peers) != 1 {
		t.Fatalf("peers = %d", len(peers))
	}
	// Baseline observation with high counters.
	if _, err := st.AddSnapshot(ctx, peers[0].ID, 5000, 4000, time.Now().Unix()-60); err != nil {
		t.Fatal(err)
	}
	snap, err := st.AddSnapshot(ctx, peers[0].ID, 10, 5, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if !snap.CounterReset || snap.DeltaRx < 0 || snap.DeltaTx < 0 {
		t.Fatalf("snapshot = %+v", snap)
	}
	if err := st.AddMonthlyUsage(ctx, u.ID, month, snap.DeltaRx, snap.DeltaTx); err != nil {
		t.Fatal(err)
	}
	usage, _ := st.GetMonthlyUsage(ctx, u.ID, month)
	if usage.TotalBytes < 9000 {
		t.Fatalf("usage must not decrease, got %d", usage.TotalBytes)
	}
}

func TestCollectOnceSurvivesAgentRestart(t *testing.T) {
	svc, fake, st := newSvc(t)
	ctx := context.Background()
	u := createUser(t, svc, "restart@example.org")
	d, err := svc.CreateDevice(ctx, actorForUser(u), CreateDeviceInput{UserID: u.ID, Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}

	// Simulate an interface restart: the peer vanished from the kernel.
	for k := range fake.PeersOn("wg0") {
		_ = fake.RemovePeer(ctx, "wg0", k)
	}
	if err := svc.CollectOnce(ctx); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !fake.HasPeer("wg0", d.Peer.PublicKey) {
		t.Fatal("peer should be restored after interface restart")
	}
	peer, _ := st.GetPeerByDevice(ctx, d.Device.ID)
	if peer.Status != "active" {
		t.Fatalf("peer status = %s", peer.Status)
	}
}

func TestKyrosLinksExistingLocalUserByEmail(t *testing.T) {
	svc, _, st := newSvc(t)
	ctx := context.Background()
	local := createUser(t, svc, "same@example.org")
	svc.Cfg.KyrosEnabled = true

	got, err := svc.LoginKyros(ctx, "same@example.org", "kyros-subject-1", "Kyros User", true)
	if err != nil {
		t.Fatalf("LoginKyros: %v", err)
	}
	if got.ID != local.ID {
		t.Fatalf("expected existing user %s, got %s", local.ID, got.ID)
	}

	ident, err := st.GetIdentity(ctx, "kyros", "kyros-subject-1")
	if err != nil {
		t.Fatalf("linked identity: %v", err)
	}
	if ident.UserID != local.ID {
		t.Fatalf("identity linked to %s, expected %s", ident.UserID, local.ID)
	}

	users, total, err := st.ListUsers(ctx, store.UserFilter{})
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	_ = users
	// Bootstrap admin + the existing local user; no duplicate Kyros user.
	if total != 2 {
		t.Fatalf("expected 2 users after linking, got %d", total)
	}
}

func TestKyrosDoesNotRelinkExistingUserToDifferentSubject(t *testing.T) {
	svc, _, st := newSvc(t)
	ctx := context.Background()
	local := createUser(t, svc, "same@example.org")
	svc.Cfg.KyrosEnabled = true

	if err := st.CreateIdentity(ctx, &store.Identity{
		ID:              store.NewID("idn"),
		UserID:          local.ID,
		Provider:        "kyros",
		ProviderSubject: "kyros-subject-1",
		Email:           local.Email,
	}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	if _, err := svc.LoginKyros(ctx, local.Email, "kyros-subject-2", "Other", true); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden for different Kyros subject, got %v", err)
	}
}

func TestKyrosOutageDoesNotTouchTunnels(t *testing.T) {
	svc, fake, _ := newSvc(t)
	ctx := context.Background()
	u := createUser(t, svc, "kyrosdown@example.org")
	d, err := svc.CreateDevice(ctx, actorForUser(u), CreateDeviceInput{UserID: u.ID, Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}

	// Kyros disabled: login path refuses, but nothing removes the peer.
	svc.Cfg.KyrosEnabled = false
	if _, err := svc.LoginKyros(ctx, "x@example.org", "subject-1", "X", true); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected unauthorized, got %v", err)
	}
	if !fake.HasPeer("wg0", d.Peer.PublicKey) {
		t.Fatal("tunnel must survive a Kyros outage")
	}
}

func TestAccessExpiry(t *testing.T) {
	svc, _, _ := newSvc(t)
	u := createUser(t, svc, "expire@example.org")
	past := time.Now().Add(-time.Hour).Unix()
	if _, err := svc.UpdateUser(context.Background(), adminActor(), u.ID, UpdateUserInput{ExpiresAt: &past}); err != nil {
		t.Fatal(err)
	}
	u, _ = svc.Store.GetUser(context.Background(), u.ID)
	_, err := svc.CreateDevice(context.Background(), actorForUser(u), CreateDeviceInput{UserID: u.ID, Name: "late"})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected forbidden for expired access, got %v", err)
	}
}

func TestComputeStateVariants(t *testing.T) {
	svc, _, _ := newSvc(t)
	now := time.Now().Unix()
	u := &store.User{Status: store.UserActive}
	dev := &store.Device{Status: "active"}

	peer := &store.WireGuardPeer{Status: "active"}
	if got := svc.ComputeState(dev, peer, u, nil, now); got != StateNeverConnected {
		t.Fatalf("never connected => %s", got)
	}
	h := now - 30
	peer.LastHandshakeAt = &h
	if got := svc.ComputeState(dev, peer, u, nil, now); got != StateRecent {
		t.Fatalf("recent => %s", got)
	}
	h = now - 600
	peer.LastHandshakeAt = &h
	if got := svc.ComputeState(dev, peer, u, nil, now); got != StateActive {
		t.Fatalf("active => %s", got)
	}
	peer.Status = "revoked"
	if got := svc.ComputeState(dev, peer, u, nil, now); got != StateRevoked {
		t.Fatalf("revoked => %s", got)
	}
	peer.Status = "active"
	dev.Status = "revoked"
	if got := svc.ComputeState(dev, peer, u, nil, now); got != StateRevoked {
		t.Fatalf("device revoked => %s", got)
	}
	dev.Status = "active"
	u.Status = store.UserSuspended
	if got := svc.ComputeState(dev, peer, u, nil, now); got != StateSuspended {
		t.Fatalf("user suspended => %s", got)
	}
	u.Status = store.UserActive
	past := now - 10
	u.ExpiresAt = &past
	if got := svc.ComputeState(dev, peer, u, nil, now); got != StateExpired {
		t.Fatalf("expired => %s", got)
	}
}

func TestAllocateIPSkipsUsed(t *testing.T) {
	used := map[string]bool{}
	ip1, err := allocateIP("10.77.0.0/24", used)
	if err != nil {
		t.Fatal(err)
	}
	if ip1 != "10.77.0.2/32" {
		t.Fatalf("first ip = %s", ip1)
	}
	used[ip1] = true
	ip2, err := allocateIP("10.77.0.0/24", used)
	if err != nil {
		t.Fatal(err)
	}
	if ip2 == ip1 {
		t.Fatal("must not reuse an address")
	}
	if _, err := allocateIP("not-a-cidr", nil); err == nil {
		t.Fatal("invalid cidr must fail")
	}
}

func TestDefaultRouteIface(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "route")
	table := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"wlan0\t0000FEA9\t00000000\t0001\t0\t0\t600\t0000FFFF\t0\t0\t0\n" +
		"ens3\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	if err := os.WriteFile(path, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	iface, ok := defaultRouteIface(path)
	if !ok || iface != "ens3" {
		t.Fatalf("iface = %q ok=%v", iface, ok)
	}

	if _, ok := defaultRouteIface(filepath.Join(dir, "missing")); ok {
		t.Fatal("missing routing table must not resolve")
	}
}

func TestEgressInterfaceValidation(t *testing.T) {
	if got, err := egressInterface("ens3"); err != nil || got != "ens3" {
		t.Fatalf("got %q err %v", got, err)
	}
	for _, bad := range []string{"eth0; reboot", "a b", "-o"} {
		if _, err := egressInterface(bad); err == nil {
			t.Errorf("egress %q must be rejected", bad)
		}
	}
	if iface, err := egressInterface(""); err == nil {
		// Falls back to the kernel routing table: must yield a valid name.
		if vErr := wg.ValidateInterface(iface); vErr != nil {
			t.Fatalf("detected egress %q is not a valid interface: %v", iface, vErr)
		}
	}
}
