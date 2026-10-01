package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aegis-vpn/aegis/internal/auth"
	"github.com/aegis-vpn/aegis/internal/store"
)

// LoginResult is returned by both login paths.
type LoginResult struct {
	User *store.User
}

// LoginLocal authenticates a local account and returns its user.
//
// Errors are deliberately generic: they never disclose whether an account
// exists.
func (s *Service) LoginLocal(ctx context.Context, email, password, ip string) (*store.User, error) {
	if !s.Cfg.LocalAuthEnabled {
		return nil, ErrUnauthorized
	}
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" || password == "" {
		return nil, ErrUnauthorized
	}

	user, err := s.Store.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Constant-time-ish: perform a dummy verification.
			_, _ = auth.VerifyPassword(dummyHash, password)
			return nil, ErrUnauthorized
		}
		return nil, err
	}
	cred, err := s.Store.GetLocalCredential(ctx, user.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			_, _ = auth.VerifyPassword(dummyHash, password)
			return nil, ErrUnauthorized
		}
		return nil, err
	}
	now := s.Store.Now().Unix()
	if cred.LockedUntil != nil && *cred.LockedUntil > now {
		return nil, ErrRateLimited
	}
	if user.Status != store.UserActive {
		return nil, ErrUnauthorized
	}
	ok, verr := auth.VerifyPassword(cred.PasswordHash, password)
	if verr != nil || !ok {
		_ = s.Store.SetLoginFailure(ctx, user.ID, 8, 300)
		return nil, ErrUnauthorized
	}
	_ = s.Store.ClearLoginFailures(ctx, user.ID)
	user.LastLoginAt = &now
	_ = s.Store.UpdateUser(ctx, user)
	return user, nil
}

// dummyHash is a syntactically valid Argon2id hash used to equalise timing
// when the account does not exist. It never matches any password.
const dummyHash = "argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// LoginKyros maps a validated Kyros identity onto an Aegis user.
func (s *Service) LoginKyros(ctx context.Context, email, subject, name string, autoProvision bool) (*store.User, error) {
	if !s.Cfg.KyrosEnabled {
		return nil, ErrUnauthorized
	}
	if subject == "" {
		return nil, ErrUnauthorized
	}
	ident, err := s.Store.GetIdentity(ctx, "kyros", subject)
	if err == nil {
		user, err := s.Store.GetUser(ctx, ident.UserID)
		if err != nil {
			return nil, ErrUnauthorized
		}
		if user.Status != store.UserActive {
			return nil, ErrUnauthorized
		}
		_ = s.Store.TouchIdentity(ctx, ident.ID, email)
		now := s.Store.Now().Unix()
		user.LastLoginAt = &now
		if email != "" && user.Email != email {
			// Keep the Aegis e-mail in sync with the identity provider.
			user.Email = email
		}
		_ = s.Store.UpdateUser(ctx, user)
		return user, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if !autoProvision {
		return nil, ErrUnauthorized
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return nil, ErrUnauthorized
	}

	// If a local Aegis account already exists with the verified Kyros e-mail,
	// link the Kyros subject to that account instead of creating a duplicate.
	// The provider subject remains the primary external identity key.
	existing, existingErr := s.Store.GetUserByEmail(ctx, email)
	if existingErr == nil {
		if existing.Status != store.UserActive {
			return nil, ErrUnauthorized
		}

		identities, err := s.Store.ListIdentities(ctx, existing.ID)
		if err != nil {
			return nil, err
		}
		for _, linked := range identities {
			if linked.Provider == "kyros" && linked.ProviderSubject != subject {
				return nil, ErrForbidden
			}
		}

		identity := &store.Identity{
			ID:              store.NewID("idn"),
			UserID:          existing.ID,
			Provider:        "kyros",
			ProviderSubject: subject,
			Email:           email,
		}
		if err := s.Store.CreateIdentity(ctx, identity); err != nil {
			if !errors.Is(err, store.ErrConflict) {
				return nil, err
			}
			// Handle concurrent callbacks safely: only accept the conflict when
			// the subject ended up linked to the same Aegis account.
			linked, lookupErr := s.Store.GetIdentity(ctx, "kyros", subject)
			if lookupErr != nil || linked.UserID != existing.ID {
				return nil, ErrForbidden
			}
			identity = linked
		}

		_ = s.Store.TouchIdentity(ctx, identity.ID, email)
		now := s.Store.Now().Unix()
		existing.LastLoginAt = &now
		if existing.DisplayName == "" && name != "" {
			existing.DisplayName = name
		}
		if err := s.Store.UpdateUser(ctx, existing); err != nil {
			return nil, err
		}
		return existing, nil
	}
	if !errors.Is(existingErr, store.ErrNotFound) {
		return nil, existingErr
	}
	return s.provisionKyrosUser(ctx, email, subject, name)
}

func (s *Service) provisionKyrosUser(ctx context.Context, email, subject, name string) (*store.User, error) {
	pol, err := s.Store.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}
	u := &store.User{
		ID:          store.NewID("usr"),
		Email:       strings.ToLower(strings.TrimSpace(email)),
		DisplayName: name,
		Role:        store.RoleUser,
		Status:      store.UserActive,
	}
	if len(pol) > 0 {
		u.PolicyID = &pol[0].ID
	}
	if err := s.Store.CreateUser(ctx, u); err != nil {
		return nil, err
	}
	if err := s.Store.CreateIdentity(ctx, &store.Identity{
		ID:              store.NewID("idn"),
		UserID:          u.ID,
		Provider:        "kyros",
		ProviderSubject: subject,
		Email:           u.Email,
	}); err != nil {
		return nil, err
	}
	return u, nil
}

// ------------------------------------------------------------ user mgmt

// CreateUserInput is the admin-facing creation payload.
type CreateUserInput struct {
	Email       string
	DisplayName string
	Role        store.Role
	Password    string
	PolicyID    string
	ExpiresAt   *int64
}

// CreateUser creates an Aegis user (optionally with a local password).
func (s *Service) CreateUser(ctx context.Context, actor Actor, in CreateUserInput) (*store.User, error) {
	if !actor.IsAdmin() {
		return nil, ErrForbidden
	}
	in.Email = strings.TrimSpace(strings.ToLower(in.Email))
	if in.Email == "" || !strings.Contains(in.Email, "@") {
		return nil, fmtInvalid("email")
	}
	if in.Role != store.RoleAdmin && in.Role != store.RoleUser {
		return nil, fmtInvalid("role")
	}
	if in.DisplayName == "" {
		in.DisplayName = strings.SplitN(in.Email, "@", 2)[0]
	}
	u := &store.User{
		ID:          store.NewID("usr"),
		Email:       in.Email,
		DisplayName: truncate(in.DisplayName, 120),
		Role:        in.Role,
		Status:      store.UserActive,
		ExpiresAt:   in.ExpiresAt,
	}
	if in.PolicyID != "" {
		if _, err := s.Store.GetPolicy(ctx, in.PolicyID); err != nil {
			return nil, fmtInvalid("policy_id")
		}
		u.PolicyID = &in.PolicyID
	}
	if err := s.Store.CreateUser(ctx, u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}
	if in.Password != "" {
		if err := s.setPassword(ctx, u.ID, in.Password); err != nil {
			return nil, err
		}
	}
	s.Audit(ctx, actor, "user.create", "user", u.ID, map[string]any{"email": u.Email, "role": u.Role})
	return u, nil
}

// UpdateUserInput allows partial modification of a user.
type UpdateUserInput struct {
	DisplayName *string
	Role        *store.Role
	Status      *store.UserStatus
	PolicyID    *string
	Quota       *int64
	ExpiresAt   *int64
	Password    *string
}

// UpdateUser modifies a user. Role or password changes revoke sessions.
func (s *Service) UpdateUser(ctx context.Context, actor Actor, id string, in UpdateUserInput) (*store.User, error) {
	if !actor.IsAdmin() && !actor.IsSelf(id) {
		return nil, ErrForbidden
	}
	u, err := s.Store.GetUser(ctx, id)
	if err != nil {
		return nil, err
	}
	roleChanged := false
	if in.DisplayName != nil {
		u.DisplayName = truncate(*in.DisplayName, 120)
	}
	if in.Role != nil {
		if !actor.IsAdmin() {
			return nil, ErrForbidden
		}
		if *in.Role != store.RoleAdmin && *in.Role != store.RoleUser {
			return nil, fmtInvalid("role")
		}
		if *in.Role != u.Role {
			roleChanged = true
			if *in.Role == store.RoleUser && s.countAdmins(ctx, u.ID) == 0 {
				return nil, errors.New("cannot demote the last administrator")
			}
		}
		u.Role = *in.Role
	}
	if in.Status != nil {
		if !actor.IsAdmin() {
			return nil, ErrForbidden
		}
		if *in.Status != store.UserActive && *in.Status != store.UserSuspended {
			return nil, fmtInvalid("status")
		}
		u.Status = *in.Status
	}
	if in.PolicyID != nil {
		if !actor.IsAdmin() {
			return nil, ErrForbidden
		}
		if *in.PolicyID == "" {
			u.PolicyID = nil
		} else {
			if _, err := s.Store.GetPolicy(ctx, *in.PolicyID); err != nil {
				return nil, fmtInvalid("policy_id")
			}
			u.PolicyID = in.PolicyID
		}
	}
	if in.Quota != nil {
		if !actor.IsAdmin() {
			return nil, ErrForbidden
		}
		if *in.Quota < 0 {
			return nil, fmtInvalid("quota_bytes")
		}
		if *in.Quota == 0 {
			u.QuotaBytesOverride = nil
		} else {
			u.QuotaBytesOverride = in.Quota
		}
	}
	if in.ExpiresAt != nil {
		if !actor.IsAdmin() && !actor.IsSelf(id) {
			return nil, ErrForbidden
		}
		if *in.ExpiresAt == 0 {
			u.ExpiresAt = nil
		} else {
			u.ExpiresAt = in.ExpiresAt
		}
	}
	if in.Password != nil && *in.Password != "" {
		if !actor.IsAdmin() && !actor.IsSelf(id) {
			return nil, ErrForbidden
		}
		if err := s.setPassword(ctx, u.ID, *in.Password); err != nil {
			return nil, err
		}
	}
	if err := s.Store.UpdateUser(ctx, u); err != nil {
		return nil, err
	}
	if roleChanged {
		_ = s.Store.DeleteUserSessions(ctx, u.ID)
	}
	s.Audit(ctx, actor, "user.update", "user", u.ID, map[string]any{
		"role": u.Role, "status": u.Status, "role_changed": roleChanged,
	})
	return u, nil
}

func (s *Service) countAdmins(ctx context.Context, excludeID string) int {
	users, total, err := s.Store.ListUsers(ctx, store.UserFilter{Role: store.RoleAdmin, Limit: 500})
	if err != nil {
		return 0
	}
	n := 0
	for _, u := range users {
		if u.ID != excludeID {
			n++
		}
	}
	_ = total
	return n
}

// DeleteUser removes a user. Every WireGuard peer is removed first.
func (s *Service) DeleteUser(ctx context.Context, actor Actor, id string) error {
	if !actor.IsAdmin() {
		return ErrForbidden
	}
	u, err := s.Store.GetUser(ctx, id)
	if err != nil {
		return err
	}
	if u.Role == store.RoleAdmin && s.countAdmins(ctx, id) == 0 {
		return errors.New("cannot delete the last administrator")
	}
	if err := s.revokeAllUserPeers(ctx, u.ID); err != nil {
		return err
	}
	if err := s.Store.DeleteUser(ctx, id); err != nil {
		return err
	}
	s.Audit(ctx, actor, "user.delete", "user", id, map[string]any{"email": u.Email})
	return nil
}

func (s *Service) revokeAllUserPeers(ctx context.Context, userID string) error {
	devs, _, err := s.Store.ListDevices(ctx, store.DeviceFilter{UserID: userID, Limit: 500})
	if err != nil {
		return err
	}
	for _, d := range devs {
		peer, err := s.Store.GetPeerByDevice(ctx, d.ID)
		if err != nil {
			continue
		}
		if peer.Status == "revoked" {
			continue
		}
		srv, err := s.Store.GetServer(ctx, peer.ServerID)
		if err != nil {
			continue
		}
		_ = s.WG.RemovePeer(ctx, srv.WGInterface, peer.PublicKey)
	}
	return nil
}

// CreateAdminWithPassword creates the initial local administrator.
func (s *Service) CreateAdminWithPassword(ctx context.Context, email, password, kind string) (*store.User, error) {
	actor := Actor{Kind: kind, UserID: "system", Role: store.RoleAdmin}
	return s.CreateUser(ctx, actor, CreateUserInput{
		Email:       email,
		DisplayName: "Administrateur",
		Role:        store.RoleAdmin,
		Password:    password,
	})
}

// setPassword stores an Argon2id hash.
func (s *Service) setPassword(ctx context.Context, userID, password string) error {
	hash, err := auth.HashPassword(password, auth.Params{
		Time:    s.Cfg.ArgonTime,
		Memory:  s.Cfg.ArgonMemoryKiB,
		Threads: s.Cfg.ArgonThreads,
		KeyLen:  s.Cfg.ArgonKeyLen,
		SaltLen: 16,
	})
	if err != nil {
		return err
	}
	return s.Store.CreateLocalCredential(ctx, &store.LocalCredential{
		UserID:       userID,
		PasswordHash: hash,
		Algo:         "argon2id",
	})
}

// ChangePassword performs a self-service password change.
func (s *Service) ChangePassword(ctx context.Context, actor Actor, current, next string) error {
	if actor.UserID == "" {
		return ErrUnauthorized
	}
	cred, err := s.Store.GetLocalCredential(ctx, actor.UserID)
	if err != nil {
		return ErrForbidden
	}
	ok, _ := auth.VerifyPassword(cred.PasswordHash, current)
	if !ok {
		return ErrUnauthorized
	}
	if err := s.setPassword(ctx, actor.UserID, next); err != nil {
		return err
	}
	s.Audit(ctx, actor, "user.password_change", "user", actor.UserID, nil)
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func fmtInvalid(field string) error {
	return &FieldError{Field: field}
}

// FieldError identifies an invalid field without leaking internals.
type FieldError struct {
	Field string
}

func (e *FieldError) Error() string { return "invalid field: " + e.Field }

// Now is a small helper used across services.
func (s *Service) now() time.Time { return s.Store.Now() }
