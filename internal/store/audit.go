package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// AppendAudit writes an immutable audit event. The caller is responsible for
// making sure `detail` contains no secret material.
func (s *Store) AppendAudit(ctx context.Context, e *AuditEvent) error {
	if e.Ts == 0 {
		e.Ts = s.Now().Unix()
	}
	if e.Detail == "" {
		e.Detail = "{}"
	}
	if !json.Valid([]byte(e.Detail)) {
		b, _ := json.Marshal(e.Detail)
		e.Detail = string(b)
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO audit_events
		(ts, actor_user_id, actor_kind, action, target_kind, target_id, ip, user_agent, correlation_id, detail)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		e.Ts, e.ActorUserID, e.ActorKind, e.Action, e.TargetKind, e.TargetID, e.IP,
		truncate(e.UserAgent, 256), e.CorrelationID, e.Detail)
	if err != nil {
		return fmtErr("append audit", err)
	}
	if e.ID == 0 {
		if id, err := res.LastInsertId(); err == nil {
			e.ID = id
		}
	}
	return nil
}

// AuditFilter narrows the audit journal.
type AuditFilter struct {
	Actor  string
	Action string
	Query  string
	From   int64
	To     int64
	Limit  int
	Offset int
}

// ListAudit returns a page of audit events plus the total count.
func (s *Store) ListAudit(ctx context.Context, f AuditFilter) ([]*AuditEvent, int, error) {
	where := []string{"1=1"}
	args := []any{}
	if f.Actor != "" {
		where = append(where, "actor_user_id = ?")
		args = append(args, f.Actor)
	}
	if f.Action != "" {
		where = append(where, "action = ?")
		args = append(args, f.Action)
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		where = append(where, "(action LIKE ? OR target_id LIKE ? OR correlation_id LIKE ? OR detail LIKE ?)")
		like := "%" + q + "%"
		args = append(args, like, like, like, like)
	}
	if f.From > 0 {
		where = append(where, "ts >= ?")
		args = append(args, f.From)
	}
	if f.To > 0 {
		where = append(where, "ts <= ?")
		args = append(args, f.To)
	}
	cond := strings.Join(where, " AND ")

	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events WHERE `+cond, args...).Scan(&total); err != nil {
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
	q := fmt.Sprintf(`SELECT id, ts, actor_user_id, actor_kind, action, target_kind, target_id, ip,
		user_agent, correlation_id, detail FROM audit_events WHERE %s ORDER BY id DESC LIMIT ? OFFSET ?`, cond)
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]*AuditEvent, 0)
	for rows.Next() {
		e := &AuditEvent{}
		if err := rows.Scan(&e.ID, &e.Ts, &e.ActorUserID, &e.ActorKind, &e.Action, &e.TargetKind,
			&e.TargetID, &e.IP, &e.UserAgent, &e.CorrelationID, &e.Detail); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ---------------------------------------------------------------- sessions

// CreateSession stores a new session. `id` is the hash of the cookie token.
func (s *Store) CreateSession(ctx context.Context, sess *Session) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions
		(id, user_id, csrf_token, created_at, expires_at, last_seen_at, rotated_from, ip, user_agent)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		sess.ID, sess.UserID, sess.CSRFToken, sess.CreatedAt, sess.ExpiresAt, sess.LastSeenAt,
		sess.RotatedFrom, sess.IP, truncate(sess.UserAgent, 256))
	return err
}

// GetSession loads a session by token hash.
func (s *Store) GetSession(ctx context.Context, id string) (*Session, error) {
	sess := &Session{}
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, csrf_token, created_at, expires_at,
		last_seen_at, rotated_from, ip, user_agent FROM sessions WHERE id=?`, id).
		Scan(&sess.ID, &sess.UserID, &sess.CSRFToken, &sess.CreatedAt, &sess.ExpiresAt,
			&sess.LastSeenAt, &sess.RotatedFrom, &sess.IP, &sess.UserAgent)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return sess, nil
}

// TouchSession refreshes the idle deadline.
func (s *Store) TouchSession(ctx context.Context, id string, lastSeen, expiresAt int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at=?, expires_at=? WHERE id=?`,
		lastSeen, expiresAt, id)
	return err
}

// DeleteSession removes one session.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id=?`, id)
	return err
}

// DeleteUserSessions removes every session of a user (used on password change,
// role change or administrative lockout).
func (s *Store) DeleteUserSessions(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, userID)
	return err
}

// PruneExpiredSessions deletes expired sessions.
func (s *Store) PruneExpiredSessions(ctx context.Context, now int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, now)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ------------------------------------------------------------- oauth state

// SaveOAuthState stores a pending Authorization Code + PKCE exchange.
func (s *Store) SaveOAuthState(ctx context.Context, hash, verifier, nonce, redirectTo string, createdAt, expiresAt int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO oauth_states
		(state_hash, code_verifier, nonce, redirect_to, created_at, expires_at) VALUES (?,?,?,?,?,?)`,
		hash, verifier, nonce, redirectTo, createdAt, expiresAt)
	return err
}

// ConsumeOAuthState loads and deletes a pending state (single use).
func (s *Store) ConsumeOAuthState(ctx context.Context, hash string) (verifier, nonce, redirectTo string, err error) {
	row := s.db.QueryRowContext(ctx, `SELECT code_verifier, nonce, redirect_to FROM oauth_states WHERE state_hash=?`, hash)
	if err = row.Scan(&verifier, &nonce, &redirectTo); err != nil {
		if err == sql.ErrNoRows {
			return "", "", "", ErrNotFound
		}
		return "", "", "", err
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM oauth_states WHERE state_hash=?`, hash)
	return verifier, nonce, redirectTo, nil
}

// PruneOAuthStates removes stale states.
func (s *Store) PruneOAuthStates(ctx context.Context, now int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM oauth_states WHERE expires_at < ?`, now)
	return err
}

// ---------------------------------------------------------------- settings

// SetSetting stores a key/value setting.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key, value, updated_at) VALUES (?,?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		key, value, s.Now().Unix())
	return err
}

// GetSetting loads a setting.
func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", ErrNotFound
	}
	return v, err
}
