package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

const deviceJoin = `d.id, d.user_id, d.server_id, d.name, d.platform, d.status, d.created_at, d.updated_at,
	d.revoked_at, d.last_seen_at, p.allowed_ip, p.public_key, p.status, p.suspended_reason,
	p.last_handshake_at, p.rx_bytes, p.tx_bytes, p.profile_delivered_at, p.expires_at`

func scanDevice(sc interface{ Scan(...any) error }) (*Device, error) {
	d := &Device{}
	var peerStatus, allowedIP, pubkey, reason sql.NullString
	var handshake, delivered, peerExp sql.NullInt64
	err := sc.Scan(&d.ID, &d.UserID, &d.ServerID, &d.Name, &d.Platform, &d.Status, &d.CreatedAt,
		&d.UpdatedAt, &d.RevokedAt, &d.LastSeenAt, &allowedIP, &pubkey, &peerStatus, &reason,
		&handshake, &d.RxBytes, &d.TxBytes, &delivered, &peerExp)
	if err != nil {
		return nil, err
	}
	d.AllowedIP = allowedIP.String
	d.PublicKey = pubkey.String
	d.PeerStatus = peerStatus.String
	d.SuspendedReason = reason.String
	if handshake.Valid {
		v := handshake.Int64
		d.LastHandshakeAt = &v
	}
	if delivered.Valid {
		v := delivered.Int64
		d.ProfileDelivered = &v
	}
	if peerExp.Valid {
		v := peerExp.Int64
		d.PeerExpiresAt = &v
	}
	return d, nil
}

// CreateDevice inserts a device without any peer.
func (s *Store) CreateDevice(ctx context.Context, d *Device) error {
	now := s.Now().Unix()
	d.CreatedAt, d.UpdatedAt = now, now
	_, err := s.db.ExecContext(ctx, `INSERT INTO devices (id, user_id, server_id, name, platform, status, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?)`, d.ID, d.UserID, d.ServerID, d.Name, d.Platform, d.Status, d.CreatedAt, d.UpdatedAt)
	if err != nil {
		return fmtErr("create device", err)
	}
	return nil
}

// CountActiveDevices returns how many active devices a user owns.
func (s *Store) CountActiveDevices(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE user_id=? AND status='active'`, userID).Scan(&n)
	return n, err
}

// DeviceFilter narrows device listings.
type DeviceFilter struct {
	UserID string
	Status string
	Query  string
	Limit  int
	Offset int
}

// ListDevices returns devices (with joined peer data) plus a total count.
func (s *Store) ListDevices(ctx context.Context, f DeviceFilter) ([]*Device, int, error) {
	where := []string{"1=1"}
	args := []any{}
	if f.UserID != "" {
		where = append(where, "d.user_id = ?")
		args = append(args, f.UserID)
	}
	if f.Status != "" {
		where = append(where, "d.status = ?")
		args = append(args, f.Status)
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		where = append(where, "(d.name LIKE ? OR d.id LIKE ? OR d.user_id LIKE ?)")
		like := "%" + q + "%"
		args = append(args, like, like, like)
	}
	cond := strings.Join(where, " AND ")

	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices d WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	q := fmt.Sprintf(`SELECT %s FROM devices d LEFT JOIN wireguard_peers p ON p.device_id = d.id
		WHERE %s ORDER BY d.created_at DESC LIMIT ? OFFSET ?`, deviceJoin, cond)
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]*Device, 0)
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, d)
	}
	return out, total, rows.Err()
}

// GetDevice loads one device with joined peer data.
func (s *Store) GetDevice(ctx context.Context, id string) (*Device, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+deviceJoin+` FROM devices d
		LEFT JOIN wireguard_peers p ON p.device_id = d.id WHERE d.id=?`, id)
	d, err := scanDevice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

// UpdateDevice applies a partial device update.
func (s *Store) UpdateDevice(ctx context.Context, d *Device) error {
	d.UpdatedAt = s.Now().Unix()
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET name=?, platform=?, status=?, updated_at=?, revoked_at=?, last_seen_at=? WHERE id=?`,
		d.Name, d.Platform, d.Status, d.UpdatedAt, d.RevokedAt, d.LastSeenAt, d.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteDevice removes a device (and its peer through cascade).
func (s *Store) DeleteDevice(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM devices WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ------------------------------------------------------------------ peers

// CreatePeer inserts a WireGuard peer.
func (s *Store) CreatePeer(ctx context.Context, p *WireGuardPeer) error {
	now := s.Now().Unix()
	p.CreatedAt, p.UpdatedAt = now, now
	_, err := s.db.ExecContext(ctx, `INSERT INTO wireguard_peers
		(id, device_id, server_id, public_key, allowed_ip, status, suspended_reason, created_at, updated_at, expires_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		p.ID, p.DeviceID, p.ServerID, p.PublicKey, p.AllowedIP, p.Status, p.SuspendedReason,
		p.CreatedAt, p.UpdatedAt, p.ExpiresAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return fmtErr("create peer", err)
	}
	return nil
}

const peerCols = `id, device_id, server_id, public_key, allowed_ip, status, suspended_reason,
	created_at, updated_at, rotated_at, revoked_at, last_handshake_at, rx_bytes, tx_bytes,
	profile_delivered_at, expires_at`

func scanPeer(sc interface{ Scan(...any) error }) (*WireGuardPeer, error) {
	p := &WireGuardPeer{}
	err := sc.Scan(&p.ID, &p.DeviceID, &p.ServerID, &p.PublicKey, &p.AllowedIP, &p.Status,
		&p.SuspendedReason, &p.CreatedAt, &p.UpdatedAt, &p.RotatedAt, &p.RevokedAt,
		&p.LastHandshakeAt, &p.RxBytes, &p.TxBytes, &p.ProfileDeliveredAt, &p.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// GetPeer loads one peer.
func (s *Store) GetPeer(ctx context.Context, id string) (*WireGuardPeer, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+peerCols+` FROM wireguard_peers WHERE id=?`, id)
	p, err := scanPeer(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return p, err
}

// GetPeerByDevice returns the current peer of a device (most recent first).
func (s *Store) GetPeerByDevice(ctx context.Context, deviceID string) (*WireGuardPeer, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+peerCols+` FROM wireguard_peers WHERE device_id=?
		ORDER BY created_at DESC LIMIT 1`, deviceID)
	p, err := scanPeer(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return p, err
}

// GetPeerByPublicKey looks a peer up by its public key.
func (s *Store) GetPeerByPublicKey(ctx context.Context, pubkey string) (*WireGuardPeer, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+peerCols+` FROM wireguard_peers WHERE public_key=?`, pubkey)
	p, err := scanPeer(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return p, err
}

// ListPeersByStatus returns peers matching a status.
func (s *Store) ListPeersByStatus(ctx context.Context, status string) ([]*WireGuardPeer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+peerCols+` FROM wireguard_peers WHERE status=? ORDER BY created_at`, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectPeers(rows)
}

// ListPeersOnServer returns every non-revoked peer of a server.
func (s *Store) ListPeersOnServer(ctx context.Context, serverID string) ([]*WireGuardPeer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+peerCols+` FROM wireguard_peers WHERE server_id=? AND status <> 'revoked' ORDER BY created_at`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectPeers(rows)
}

// ListAllPeers returns every peer (used by the collector).
func (s *Store) ListAllPeers(ctx context.Context) ([]*WireGuardPeer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+peerCols+` FROM wireguard_peers WHERE status <> 'revoked' ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectPeers(rows)
}

func collectPeers(rows *sql.Rows) ([]*WireGuardPeer, error) {
	out := make([]*WireGuardPeer, 0)
	for rows.Next() {
		p, err := scanPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdatePeer persists peer runtime state.
func (s *Store) UpdatePeer(ctx context.Context, p *WireGuardPeer) error {
	p.UpdatedAt = s.Now().Unix()
	res, err := s.db.ExecContext(ctx, `UPDATE wireguard_peers SET public_key=?, allowed_ip=?, status=?,
		suspended_reason=?, updated_at=?, rotated_at=?, revoked_at=?, last_handshake_at=?, rx_bytes=?,
		tx_bytes=?, profile_delivered_at=?, expires_at=? WHERE id=?`,
		p.PublicKey, p.AllowedIP, p.Status, p.SuspendedReason, p.UpdatedAt, p.RotatedAt, p.RevokedAt,
		p.LastHandshakeAt, p.RxBytes, p.TxBytes, p.ProfileDeliveredAt, p.ExpiresAt, p.ID)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ReplacePeerPublicKey handles key rotation.
func (s *Store) ReplacePeerPublicKey(ctx context.Context, id, newPub string, now int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE wireguard_peers SET public_key=?, rotated_at=?, updated_at=?,
		profile_delivered_at=NULL WHERE id=?`, newPub, now, now, id)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountPeersOnServer returns how many peers a server currently hosts.
func (s *Store) CountPeersOnServer(ctx context.Context, serverID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM wireguard_peers WHERE server_id=? AND status <> 'revoked'`, serverID).Scan(&n)
	return n, err
}

// UsedIPs returns the host addresses already allocated inside a server CIDR.
func (s *Store) UsedIPs(ctx context.Context, serverID string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT allowed_ip FROM wireguard_peers WHERE server_id=?`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	used := map[string]bool{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		used[ip] = true
	}
	return used, rows.Err()
}

// ListPeersWithOwners returns every non-revoked peer joined with its device
// and owning user. Used by the traffic collector.
func (s *Store) ListPeersWithOwners(ctx context.Context) ([]*WireGuardPeer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT p.id, p.device_id, p.server_id, p.public_key, p.allowed_ip,
		p.status, p.suspended_reason, p.created_at, p.updated_at, p.rotated_at, p.revoked_at,
		p.last_handshake_at, p.rx_bytes, p.tx_bytes, p.profile_delivered_at, p.expires_at,
		d.user_id, d.name, d.status
		FROM wireguard_peers p JOIN devices d ON d.id = p.device_id
		WHERE p.status <> 'revoked' ORDER BY p.created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WireGuardPeer
	for rows.Next() {
		p := &WireGuardPeer{}
		var deviceStatus string
		if err := rows.Scan(&p.ID, &p.DeviceID, &p.ServerID, &p.PublicKey, &p.AllowedIP, &p.Status,
			&p.SuspendedReason, &p.CreatedAt, &p.UpdatedAt, &p.RotatedAt, &p.RevokedAt,
			&p.LastHandshakeAt, &p.RxBytes, &p.TxBytes, &p.ProfileDeliveredAt, &p.ExpiresAt,
			&p.UserID, &p.DeviceName, &deviceStatus); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
