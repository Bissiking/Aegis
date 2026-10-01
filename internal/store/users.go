package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned on uniqueness violations.
var ErrConflict = errors.New("conflict")

const userCols = `id, email, display_name, role, status, policy_id, quota_bytes_override,
	expires_at, created_at, updated_at, last_login_at`

type userScanner interface {
	Scan(dest ...any) error
}

func scanUser(sc userScanner) (*User, error) {
	u := &User{}
	err := sc.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Role, &u.Status, &u.PolicyID,
		&u.QuotaBytesOverride, &u.ExpiresAt, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// UserFilter narrows user listings.
type UserFilter struct {
	Query  string
	Role   Role
	Status UserStatus
	Limit  int
	Offset int
}

// CreateUser inserts a user.
func (s *Store) CreateUser(ctx context.Context, u *User) error {
	now := s.Now().Unix()
	u.CreatedAt = now
	u.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, `INSERT INTO users
		(id, email, display_name, role, status, policy_id, quota_bytes_override, expires_at, created_at, updated_at, last_login_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		u.ID, u.Email, u.DisplayName, string(u.Role), string(u.Status), u.PolicyID,
		u.QuotaBytesOverride, u.ExpiresAt, u.CreatedAt, u.UpdatedAt, u.LastLoginAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

// GetUser loads a user by id.
func (s *Store) GetUser(ctx context.Context, id string) (*User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.decorateUsers(ctx, []*User{u})[0], nil
}

// GetUserByEmail loads a user by email (case-insensitive).
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE email = ? COLLATE NOCASE`, strings.TrimSpace(email))
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// ListUsers returns a filtered, paginated user list plus the total count.
func (s *Store) ListUsers(ctx context.Context, f UserFilter) ([]*User, int, error) {
	where := []string{"1=1"}
	args := []any{}
	if q := strings.TrimSpace(f.Query); q != "" {
		where = append(where, "(email LIKE ? OR display_name LIKE ? OR id LIKE ?)")
		like := "%" + q + "%"
		args = append(args, like, like, like)
	}
	if f.Role != "" {
		where = append(where, "role = ?")
		args = append(args, string(f.Role))
	}
	if f.Status != "" {
		where = append(where, "status = ?")
		args = append(args, string(f.Status))
	}
	cond := strings.Join(where, " AND ")

	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE `+cond, args...).Scan(&total); err != nil {
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
	q := fmt.Sprintf(`SELECT %s FROM users WHERE %s ORDER BY created_at DESC LIMIT ? OFFSET ?`, userCols, cond)
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return s.decorateUsers(ctx, out), total, nil
}

func (s *Store) decorateUsers(ctx context.Context, users []*User) []*User {
	for _, u := range users {
		_ = s.db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM local_credentials WHERE user_id = ?)`+` AND EXISTS(SELECT 1 FROM identities WHERE user_id = ? AND provider='local')`,
			u.ID, u.ID).Scan(&u.HasLocalPassword)
		_ = s.db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM identities WHERE user_id = ? AND provider='kyros')`, u.ID).Scan(&u.HasKyrosIdentity)
		_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE user_id = ? AND status='active'`, u.ID).Scan(&u.DeviceCount)
	}
	return users
}

// UpdateUser applies a partial update.
func (s *Store) UpdateUser(ctx context.Context, u *User) error {
	u.UpdatedAt = s.Now().Unix()
	res, err := s.db.ExecContext(ctx, `UPDATE users SET email=?, display_name=?, role=?, status=?,
		policy_id=?, quota_bytes_override=?, expires_at=?, updated_at=?, last_login_at=? WHERE id=?`,
		u.Email, u.DisplayName, string(u.Role), string(u.Status), u.PolicyID,
		u.QuotaBytesOverride, u.ExpiresAt, u.UpdatedAt, u.LastLoginAt, u.ID)
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

// DeleteUser removes a user and cascades to identities, devices and peers.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateLocalCredential stores an Argon2id hash.
func (s *Store) CreateLocalCredential(ctx context.Context, c *LocalCredential) error {
	c.UpdatedAt = s.Now().Unix()
	_, err := s.db.ExecContext(ctx, `INSERT INTO local_credentials
		(user_id, password_hash, algo, failed_attempts, locked_until, must_change_password, updated_at)
		VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(user_id) DO UPDATE SET password_hash=excluded.password_hash, algo=excluded.algo,
		failed_attempts=0, locked_until=NULL, must_change_password=excluded.must_change_password,
		updated_at=excluded.updated_at`,
		c.UserID, c.PasswordHash, c.Algo, c.FailedAttempts, c.LockedUntil, boolToInt(c.MustChangePassword), c.UpdatedAt)
	return err
}

// GetLocalCredential loads the local credential of a user.
func (s *Store) GetLocalCredential(ctx context.Context, userID string) (*LocalCredential, error) {
	c := &LocalCredential{}
	var locked sql.NullInt64
	var must int
	err := s.db.QueryRowContext(ctx, `SELECT user_id, password_hash, algo, failed_attempts,
		locked_until, must_change_password, updated_at FROM local_credentials WHERE user_id=?`, userID).
		Scan(&c.UserID, &c.PasswordHash, &c.Algo, &c.FailedAttempts, &locked, &must, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if locked.Valid {
		v := locked.Int64
		c.LockedUntil = &v
	}
	c.MustChangePassword = must != 0
	return c, nil
}

// SetLoginFailure records a failed local login and locks the account when the
// threshold is reached.
func (s *Store) SetLoginFailure(ctx context.Context, userID string, maxAttempts int, lockSeconds int) error {
	_, err := s.db.ExecContext(ctx, `UPDATE local_credentials SET failed_attempts = failed_attempts + 1,
		locked_until = CASE WHEN failed_attempts + 1 >= ? THEN ? ELSE locked_until END,
		updated_at = ? WHERE user_id=?`,
		maxAttempts, s.Now().Unix()+int64(lockSeconds), s.Now().Unix(), userID)
	return err
}

// ClearLoginFailures resets the failure counter after a successful login.
func (s *Store) ClearLoginFailures(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE local_credentials SET failed_attempts=0, locked_until=NULL, updated_at=? WHERE user_id=?`,
		s.Now().Unix(), userID)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") || strings.Contains(msg, "constraint failed")
}
