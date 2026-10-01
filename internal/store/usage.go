package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// AddSnapshot stores one counter reading and returns it enriched with deltas.
//
// The delta is computed against the previous snapshot of the same peer. If the
// current counters are lower than the previous ones (interface restart, counter
// reset), the delta is taken from zero and `counter_reset` is flagged, which
// guarantees usage never turns negative.
func (s *Store) AddSnapshot(ctx context.Context, peerID string, rx, tx int64, takenAt int64) (*TrafficSnapshot, error) {
	if takenAt == 0 {
		takenAt = s.Now().Unix()
	}
	var prevRx, prevTx sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT rx_bytes, tx_bytes FROM traffic_snapshots
		WHERE peer_id=? ORDER BY id DESC LIMIT 1`, peerID).Scan(&prevRx, &prevTx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	snap := &TrafficSnapshot{PeerID: peerID, TakenAt: takenAt, RxBytes: rx, TxBytes: tx}
	if prevRx.Valid {
		pr, pt := prevRx.Int64, prevTx.Int64
		if rx < pr || tx < pt {
			snap.CounterReset = true
			snap.DeltaRx = max64(rx, 0)
			snap.DeltaTx = max64(tx, 0)
		} else {
			snap.DeltaRx = rx - pr
			snap.DeltaTx = tx - pt
		}
	}
	if snap.DeltaRx < 0 {
		snap.DeltaRx = 0
	}
	if snap.DeltaTx < 0 {
		snap.DeltaTx = 0
	}

	res, err := s.db.ExecContext(ctx, `INSERT INTO traffic_snapshots
		(peer_id, taken_at, rx_bytes, tx_bytes, delta_rx, delta_tx, counter_reset)
		VALUES (?,?,?,?,?,?,?)`,
		peerID, takenAt, rx, tx, snap.DeltaRx, snap.DeltaTx, boolToInt(snap.CounterReset))
	if err != nil {
		return nil, err
	}
	if id, err := res.LastInsertId(); err == nil {
		snap.ID = id
	}
	return snap, nil
}

// AddMonthlyUsage accumulates deltas into the user's monthly bucket.
// It is idempotent per snapshot because the caller only adds freshly computed
// deltas once.
func (s *Store) AddMonthlyUsage(ctx context.Context, userID, month string, dRx, dTx int64) error {
	if dRx < 0 {
		dRx = 0
	}
	if dTx < 0 {
		dTx = 0
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO monthly_usage (user_id, month, rx_bytes, tx_bytes, total_bytes, updated_at)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT(user_id, month) DO UPDATE SET
			rx_bytes = rx_bytes + excluded.rx_bytes,
			tx_bytes = tx_bytes + excluded.tx_bytes,
			total_bytes = total_bytes + excluded.total_bytes,
			updated_at = excluded.updated_at`,
		userID, month, dRx, dTx, dRx+dTx, s.Now().Unix())
	return err
}

// GetMonthlyUsage returns the bucket for a month (zero value if absent).
func (s *Store) GetMonthlyUsage(ctx context.Context, userID, month string) (*MonthlyUsage, error) {
	u := &MonthlyUsage{UserID: userID, Month: month}
	err := s.db.QueryRowContext(ctx, `SELECT rx_bytes, tx_bytes, total_bytes, updated_at
		FROM monthly_usage WHERE user_id=? AND month=?`, userID, month).
		Scan(&u.RxBytes, &u.TxBytes, &u.TotalBytes, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return &MonthlyUsage{UserID: userID, Month: month}, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// ListMonthlyUsage returns the last n months of usage for one user.
func (s *Store) ListMonthlyUsage(ctx context.Context, userID string, limit int) ([]*MonthlyUsage, error) {
	if limit <= 0 {
		limit = 12
	}
	rows, err := s.db.QueryContext(ctx, `SELECT user_id, month, rx_bytes, tx_bytes, total_bytes, updated_at
		FROM monthly_usage WHERE user_id=? ORDER BY month DESC LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*MonthlyUsage, 0)
	for rows.Next() {
		u := &MonthlyUsage{}
		if err := rows.Scan(&u.UserID, &u.Month, &u.RxBytes, &u.TxBytes, &u.TotalBytes, &u.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ListMonthlyUsageAll aggregates usage for the current month across users.
func (s *Store) ListMonthlyUsageAll(ctx context.Context, month string, limit int) ([]*MonthlyUsage, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT user_id, month, rx_bytes, tx_bytes, total_bytes, updated_at
		FROM monthly_usage WHERE month=? ORDER BY total_bytes DESC LIMIT ?`, month, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*MonthlyUsage, 0)
	for rows.Next() {
		u := &MonthlyUsage{}
		if err := rows.Scan(&u.UserID, &u.Month, &u.RxBytes, &u.TxBytes, &u.TotalBytes, &u.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SumMonthlyUsageAll returns the total traffic of a month.
func (s *Store) SumMonthlyUsageAll(ctx context.Context, month string) (int64, error) {
	var n sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT SUM(total_bytes) FROM monthly_usage WHERE month=?`, month).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n.Int64, nil
}

// ResetMonthlyUsage clears buckets (administrative action, audited by caller).
func (s *Store) ResetMonthlyUsage(ctx context.Context, userID string, month string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM monthly_usage WHERE user_id=? AND month=?`, userID, month)
	return err
}

// CurrentMonth returns the UTC month key YYYY-MM.
func CurrentMonth(t time.Time) string {
	return t.UTC().Format("2006-01")
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// ------------------------------------------------------------------ stats

// Stats aggregates dashboard numbers.
type Stats struct {
	Users          int   `json:"users"`
	Admins         int   `json:"admins"`
	Devices        int   `json:"devices"`
	ActivePeers    int   `json:"active_peers"`
	SuspendedPeers int   `json:"suspended_peers"`
	RevokedPeers   int   `json:"revoked_peers"`
	TrafficMonth   int64 `json:"traffic_month_bytes"`
	AuditEvents    int   `json:"audit_events"`
}

// GetStats collects dashboard counters.
func (s *Store) GetStats(ctx context.Context, month string) (*Stats, error) {
	st := &Stats{}
	q := func(query string, dest ...any) error { return s.db.QueryRowContext(ctx, query).Scan(dest...) }
	if err := q(`SELECT COUNT(*) FROM users`, &st.Users); err != nil {
		return nil, err
	}
	if err := q(`SELECT COUNT(*) FROM users WHERE role='admin'`, &st.Admins); err != nil {
		return nil, err
	}
	if err := q(`SELECT COUNT(*) FROM devices WHERE status='active'`, &st.Devices); err != nil {
		return nil, err
	}
	if err := q(`SELECT COUNT(*) FROM wireguard_peers WHERE status='active'`, &st.ActivePeers); err != nil {
		return nil, err
	}
	if err := q(`SELECT COUNT(*) FROM wireguard_peers WHERE status='suspended'`, &st.SuspendedPeers); err != nil {
		return nil, err
	}
	if err := q(`SELECT COUNT(*) FROM wireguard_peers WHERE status='revoked'`, &st.RevokedPeers); err != nil {
		return nil, err
	}
	if err := q(`SELECT COUNT(*) FROM audit_events`, &st.AuditEvents); err != nil {
		return nil, err
	}
	var t int64
	_ = s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(total_bytes),0) FROM monthly_usage WHERE month=?`, month).Scan(&t)
	st.TrafficMonth = t
	return st, nil
}

// Health checks database connectivity.
func (s *Store) Health(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// String implements fmt.Stringer without leaking the DSN secrets.
func (s *Store) String() string { return fmt.Sprintf("sqlite(%s)", s.path) }
