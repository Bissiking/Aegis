package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// GetIdentity finds a link by provider subject.
func (s *Store) GetIdentity(ctx context.Context, provider, subject string) (*Identity, error) {
	i := &Identity{}
	var last sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, provider, provider_subject, email, created_at, last_login_at
		FROM identities WHERE provider=? AND provider_subject=?`, provider, subject).
		Scan(&i.ID, &i.UserID, &i.Provider, &i.ProviderSubject, &i.Email, &i.CreatedAt, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if last.Valid {
		v := last.Int64
		i.LastLoginAt = &v
	}
	return i, nil
}

// CreateIdentity links a provider subject to a user.
func (s *Store) CreateIdentity(ctx context.Context, i *Identity) error {
	i.CreatedAt = s.Now().Unix()
	_, err := s.db.ExecContext(ctx, `INSERT INTO identities (id, user_id, provider, provider_subject, email, created_at, last_login_at)
		VALUES (?,?,?,?,?,?,?)`, i.ID, i.UserID, i.Provider, i.ProviderSubject, i.Email, i.CreatedAt, i.LastLoginAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	return nil
}

// TouchIdentity updates email and last login of an existing identity.
func (s *Store) TouchIdentity(ctx context.Context, id string, email string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE identities SET last_login_at=?, email=CASE WHEN ? <> '' THEN ? ELSE email END WHERE id=?`,
		s.Now().Unix(), email, email, id)
	return err
}

// ListIdentities returns all identities of a user.
func (s *Store) ListIdentities(ctx context.Context, userID string) ([]*Identity, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, provider, provider_subject, email, created_at, last_login_at
		FROM identities WHERE user_id=? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Identity
	for rows.Next() {
		i := &Identity{}
		var last sql.NullInt64
		if err := rows.Scan(&i.ID, &i.UserID, &i.Provider, &i.ProviderSubject, &i.Email, &i.CreatedAt, &last); err != nil {
			return nil, err
		}
		if last.Valid {
			v := last.Int64
			i.LastLoginAt = &v
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- policies

// CreatePolicy inserts an access policy.
func (s *Store) CreatePolicy(ctx context.Context, p *AccessPolicy) error {
	now := s.Now().Unix()
	p.CreatedAt, p.UpdatedAt = now, now
	_, err := s.db.ExecContext(ctx, `INSERT INTO access_policies
		(id, name, description, max_devices, monthly_quota_bytes, up_kbps, down_kbps, expires_at,
		 full_tunnel, allowed_networks, auto_reactivate, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.ID, p.Name, p.Description, p.MaxDevices, p.MonthlyQuotaBytes, p.UpKbps, p.DownKbps, p.ExpiresAt,
		boolToInt(p.FullTunnel), p.AllowedNetworks, boolToInt(p.AutoReactivate), p.CreatedAt, p.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	return nil
}

// UpdatePolicy updates an access policy.
func (s *Store) UpdatePolicy(ctx context.Context, p *AccessPolicy) error {
	p.UpdatedAt = s.Now().Unix()
	res, err := s.db.ExecContext(ctx, `UPDATE access_policies SET name=?, description=?, max_devices=?,
		monthly_quota_bytes=?, up_kbps=?, down_kbps=?, expires_at=?, full_tunnel=?, allowed_networks=?,
		auto_reactivate=?, updated_at=? WHERE id=?`,
		p.Name, p.Description, p.MaxDevices, p.MonthlyQuotaBytes, p.UpKbps, p.DownKbps, p.ExpiresAt,
		boolToInt(p.FullTunnel), p.AllowedNetworks, boolToInt(p.AutoReactivate), p.UpdatedAt, p.ID)
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

// DeletePolicy removes an access policy.
func (s *Store) DeletePolicy(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM access_policies WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetPolicy loads one policy.
func (s *Store) GetPolicy(ctx context.Context, id string) (*AccessPolicy, error) {
	p := &AccessPolicy{}
	var full, react int
	err := s.db.QueryRowContext(ctx, `SELECT id, name, description, max_devices, monthly_quota_bytes,
		up_kbps, down_kbps, expires_at, full_tunnel, allowed_networks, auto_reactivate, created_at, updated_at
		FROM access_policies WHERE id=?`, id).
		Scan(&p.ID, &p.Name, &p.Description, &p.MaxDevices, &p.MonthlyQuotaBytes, &p.UpKbps, &p.DownKbps,
			&p.ExpiresAt, &full, &p.AllowedNetworks, &react, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.FullTunnel = full != 0
	p.AutoReactivate = react != 0
	return p, nil
}

// ListPolicies returns all access policies ordered by name.
func (s *Store) ListPolicies(ctx context.Context) ([]*AccessPolicy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, description, max_devices, monthly_quota_bytes,
		up_kbps, down_kbps, expires_at, full_tunnel, allowed_networks, auto_reactivate, created_at, updated_at
		FROM access_policies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AccessPolicy
	for rows.Next() {
		p := &AccessPolicy{}
		var full, react int
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.MaxDevices, &p.MonthlyQuotaBytes, &p.UpKbps,
			&p.DownKbps, &p.ExpiresAt, &full, &p.AllowedNetworks, &react, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		p.FullTunnel = full != 0
		p.AutoReactivate = react != 0
		out = append(out, p)
	}
	return out, rows.Err()
}

// ------------------------------------------------------------ vpn servers

// CreateServer inserts a VPN server definition.
func (s *Store) CreateServer(ctx context.Context, srv *VPNServer) error {
	now := s.Now().Unix()
	srv.CreatedAt, srv.UpdatedAt = now, now
	if srv.IsDefault {
		if _, err := s.db.ExecContext(ctx, `UPDATE vpn_servers SET is_default=0, updated_at=?`, now); err != nil {
			return err
		}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO vpn_servers
		(id, name, host, country, wg_interface, wg_port, vpn_cidr, dns, endpoint_public, max_peers,
		 profile_ttl_hours, full_tunnel, ipv6_enabled, is_default, enabled, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		srv.ID, srv.Name, srv.Host, srv.Country, srv.WGInterface, srv.WGPort, srv.VPNCIDR, srv.DNS,
		srv.EndpointPublic, srv.MaxPeers, srv.ProfileTTLHours, boolToInt(srv.FullTunnel),
		boolToInt(srv.IPv6Enabled), boolToInt(srv.IsDefault), boolToInt(srv.Enabled), srv.CreatedAt, srv.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	return nil
}

// UpdateServer updates a VPN server definition.
func (s *Store) UpdateServer(ctx context.Context, srv *VPNServer) error {
	srv.UpdatedAt = s.Now().Unix()
	if srv.IsDefault {
		if _, err := s.db.ExecContext(ctx, `UPDATE vpn_servers SET is_default=0, updated_at=?`, srv.UpdatedAt); err != nil {
			return err
		}
	}
	res, err := s.db.ExecContext(ctx, `UPDATE vpn_servers SET name=?, host=?, country=?, wg_interface=?,
		wg_port=?, vpn_cidr=?, dns=?, endpoint_public=?, max_peers=?, profile_ttl_hours=?, full_tunnel=?,
		ipv6_enabled=?, is_default=?, enabled=?, updated_at=? WHERE id=?`,
		srv.Name, srv.Host, srv.Country, srv.WGInterface, srv.WGPort, srv.VPNCIDR, srv.DNS,
		srv.EndpointPublic, srv.MaxPeers, srv.ProfileTTLHours, boolToInt(srv.FullTunnel),
		boolToInt(srv.IPv6Enabled), boolToInt(srv.IsDefault), boolToInt(srv.Enabled), srv.UpdatedAt, srv.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanServer(sc interface{ Scan(...any) error }) (*VPNServer, error) {
	srv := &VPNServer{}
	var full, ipv6, def, enabled int
	err := sc.Scan(&srv.ID, &srv.Name, &srv.Host, &srv.Country, &srv.WGInterface, &srv.WGPort,
		&srv.VPNCIDR, &srv.DNS, &srv.EndpointPublic, &srv.MaxPeers, &srv.ProfileTTLHours,
		&full, &ipv6, &def, &enabled, &srv.CreatedAt, &srv.UpdatedAt)
	if err != nil {
		return nil, err
	}
	srv.FullTunnel = full != 0
	srv.IPv6Enabled = ipv6 != 0
	srv.IsDefault = def != 0
	srv.Enabled = enabled != 0
	return srv, nil
}

const serverCols = `id, name, host, country, wg_interface, wg_port, vpn_cidr, dns, endpoint_public,
	max_peers, profile_ttl_hours, full_tunnel, ipv6_enabled, is_default, enabled, created_at, updated_at`

// GetServer loads one server.
func (s *Store) GetServer(ctx context.Context, id string) (*VPNServer, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+serverCols+` FROM vpn_servers WHERE id=?`, id)
	srv, err := scanServer(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return srv, err
}

// GetDefaultServer loads the default (or first enabled) server.
func (s *Store) GetDefaultServer(ctx context.Context) (*VPNServer, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+serverCols+` FROM vpn_servers WHERE enabled=1
		ORDER BY is_default DESC, created_at ASC LIMIT 1`)
	srv, err := scanServer(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return srv, err
}

// ListServers returns every server.
func (s *Store) ListServers(ctx context.Context) ([]*VPNServer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+serverCols+` FROM vpn_servers ORDER BY is_default DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*VPNServer
	for rows.Next() {
		srv, err := scanServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, srv)
	}
	return out, rows.Err()
}

// EnsureDefaultServer seeds the first server from configuration.
func (s *Store) EnsureDefaultServer(ctx context.Context, name, iface, cidr string, dns []string, endpoint string, port, maxPeers, ttl int, fullTunnel bool) error {
	n := 0
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vpn_servers`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	return s.CreateServer(ctx, &VPNServer{
		ID:              NewID("srv"),
		Name:            name,
		WGInterface:     iface,
		WGPort:          port,
		VPNCIDR:         cidr,
		DNS:             strings.Join(dns, ","),
		EndpointPublic:  endpoint,
		MaxPeers:        maxPeers,
		ProfileTTLHours: ttl,
		FullTunnel:      fullTunnel,
		IsDefault:       true,
		Enabled:         true,
	})
}

func fmtErr(op string, err error) error { return fmt.Errorf("%s: %w", op, err) }
