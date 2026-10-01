package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "aegis.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// seedPeer creates the minimal graph needed by traffic_snapshots.
func seedPeer(t *testing.T, s *Store) (userID, peerID string) {
	t.Helper()
	ctx := context.Background()
	userID = NewID("usr")
	if err := s.CreateUser(ctx, &User{ID: userID, Email: userID + "@example.org", Role: RoleUser, Status: UserActive}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	srvID := NewID("srv")
	if err := s.CreateServer(ctx, &VPNServer{ID: srvID, Name: "primary-" + srvID, WGPort: 51820,
		VPNCIDR: "10.77.0.0/24", Enabled: true}); err != nil {
		t.Fatalf("seed server: %v", err)
	}
	devID := NewID("dev")
	if err := s.CreateDevice(ctx, &Device{ID: devID, UserID: userID, ServerID: srvID, Name: "phone", Status: "active"}); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	peerID = NewID("per")
	if err := s.CreatePeer(ctx, &WireGuardPeer{ID: peerID, DeviceID: devID, ServerID: srvID,
		PublicKey: NewID("pub"), AllowedIP: "10.77.0.2/32", Status: "active"}); err != nil {
		t.Fatalf("seed peer: %v", err)
	}
	return userID, peerID
}

func TestMigrationsAreIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aegis.db")

	s1, err := Open(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if pending, err := s1.PendingMigrations(context.Background()); err != nil || pending != 0 {
		t.Fatalf("pending after open = %d, err = %v", pending, err)
	}
	if err := s1.Migrate(context.Background()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	var n int
	if err := s2.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no migration recorded")
	}
	if err := s2.CreatePolicy(context.Background(), &AccessPolicy{
		ID: NewID("pol"), Name: "std", MaxDevices: 3, AllowedNetworks: "0.0.0.0/0",
	}); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	pols, err := s2.ListPolicies(context.Background())
	if err != nil || len(pols) != 1 {
		t.Fatalf("policies = %d, err = %v", len(pols), err)
	}
}

func TestSnapshotDeltas(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	_, peerID := seedPeer(t, s)

	first, err := s.AddSnapshot(ctx, peerID, 1000, 500, 1)
	if err != nil {
		t.Fatal(err)
	}
	// First observation is a baseline: nothing is counted yet, so a peer that
	// already had traffic before Aegis started never gets over-charged.
	if first.DeltaRx != 0 || first.DeltaTx != 0 || first.CounterReset {
		t.Fatalf("baseline snapshot deltas = %+v", first)
	}

	second, err := s.AddSnapshot(ctx, peerID, 1500, 900, 2)
	if err != nil {
		t.Fatal(err)
	}
	if second.DeltaRx != 500 || second.DeltaTx != 400 || second.CounterReset {
		t.Fatalf("second snapshot deltas = %+v", second)
	}
}

func TestSnapshotCounterResetNeverGoesNegative(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	_, peerID := seedPeer(t, s)

	if _, err := s.AddSnapshot(ctx, peerID, 5000, 4000, 1); err != nil {
		t.Fatal(err)
	}
	// Interface restarted: counters restarted from a lower value.
	reset, err := s.AddSnapshot(ctx, peerID, 120, 80, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !reset.CounterReset {
		t.Fatal("expected counter_reset flag")
	}
	if reset.DeltaRx < 0 || reset.DeltaTx < 0 {
		t.Fatalf("negative delta: %+v", reset)
	}
	if reset.DeltaRx != 120 || reset.DeltaTx != 80 {
		t.Fatalf("unexpected deltas after reset: %+v", reset)
	}

	// Monthly usage must never decrease.
	userID, _ := seedPeer(t, s)
	month := CurrentMonth(time.Now())
	if err := s.AddMonthlyUsage(ctx, userID, month, reset.DeltaRx, reset.DeltaTx); err != nil {
		t.Fatal(err)
	}
	usage, err := s.GetMonthlyUsage(ctx, userID, month)
	if err != nil {
		t.Fatal(err)
	}
	if usage.TotalBytes != 200 {
		t.Fatalf("total = %d", usage.TotalBytes)
	}
}

func TestMonthlyUsageAccumulates(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	userID, _ := seedPeer(t, s)
	month := CurrentMonth(time.Now())
	for i := 0; i < 3; i++ {
		if err := s.AddMonthlyUsage(ctx, userID, month, 100, 50); err != nil {
			t.Fatal(err)
		}
	}
	u, err := s.GetMonthlyUsage(ctx, userID, month)
	if err != nil {
		t.Fatal(err)
	}
	if u.TotalBytes != 450 || u.RxBytes != 300 || u.TxBytes != 150 {
		t.Fatalf("usage = %+v", u)
	}
	// Negative inputs are clamped.
	if err := s.AddMonthlyUsage(ctx, userID, month, -10, -10); err != nil {
		t.Fatal(err)
	}
	u, _ = s.GetMonthlyUsage(ctx, userID, month)
	if u.TotalBytes != 450 {
		t.Fatalf("usage after clamp = %+v", u)
	}
}

func TestOpaqueIDsAreNotSequential(t *testing.T) {
	a, b := NewID("dev"), NewID("dev")
	if a == b {
		t.Fatal("ids must differ")
	}
	if len(a) < 20 {
		t.Fatalf("id too short: %s", a)
	}
}

func TestAuditIsAppendOnlyAndPaginated(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := s.AppendAudit(ctx, &AuditEvent{
			ActorKind: "local", Action: "device.create", TargetKind: "device", TargetID: NewID("dev"),
			Detail: `{"i":1}`,
		}); err != nil {
			t.Fatal(err)
		}
	}
	events, total, err := s.ListAudit(ctx, AuditFilter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 || len(events) != 2 {
		t.Fatalf("total=%d len=%d", total, len(events))
	}
	if events[0].ID < events[1].ID {
		t.Fatal("expected newest first")
	}
}
