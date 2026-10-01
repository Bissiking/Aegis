package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aegis-vpn/aegis/internal/store"
)

// SessionManager owns server-side sessions and CSRF tokens.
//
// The session cookie carries an opaque random token; the database only stores
// SHA-256 of that token so a database leak cannot be replayed as a session.
type SessionManager struct {
	store      *store.Store
	cookieName string
	csrfCookie string
	secure     bool
	ttl        time.Duration
	idleTTL    time.Duration
	trustProxy bool
}

// NewSessionManager builds a session manager.
func NewSessionManager(st *store.Store, cookieName, csrfCookie string, secure bool, ttl, idleTTL time.Duration, trustProxy bool) *SessionManager {
	return &SessionManager{
		store:      st,
		cookieName: cookieName,
		csrfCookie: csrfCookie,
		secure:     secure,
		ttl:        ttl,
		idleTTL:    idleTTL,
		trustProxy: trustProxy,
	}
}

// hashToken returns the storage identifier for a cookie token.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Create issues a new session and writes both cookies.
func (m *SessionManager) Create(ctx context.Context, w http.ResponseWriter, userID, ip, userAgent, rotatedFrom string) (*store.Session, error) {
	token, err := store.RandomToken(32)
	if err != nil {
		return nil, err
	}
	csrf, err := store.RandomToken(32)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	sess := &store.Session{
		ID:          hashToken(token),
		UserID:      userID,
		CSRFToken:   csrf,
		CreatedAt:   now.Unix(),
		ExpiresAt:   now.Add(m.ttl).Unix(),
		LastSeenAt:  now.Unix(),
		RotatedFrom: nil,
		IP:          ip,
		UserAgent:   userAgent,
	}
	if rotatedFrom != "" {
		prev := rotatedFrom
		sess.RotatedFrom = &prev
	}
	if err := m.store.CreateSession(ctx, sess); err != nil {
		return nil, err
	}
	m.setSessionCookie(w, token, now.Add(m.ttl))
	m.setCSRFCookie(w, csrf, now.Add(m.ttl))
	return sess, nil
}

func (m *SessionManager) setSessionCookie(w http.ResponseWriter, token string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    token,
		Path:     "/",
		Expires:  exp,
		MaxAge:   int(time.Until(exp).Seconds()),
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (m *SessionManager) setCSRFCookie(w http.ResponseWriter, token string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.csrfCookie,
		Value:    token,
		Path:     "/",
		Expires:  exp,
		MaxAge:   int(time.Until(exp).Seconds()),
		HttpOnly: false, // readable by the SPA to echo back in X-CSRF-Token
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// Clear removes both cookies.
func (m *SessionManager) Clear(w http.ResponseWriter) {
	for _, name := range []string{m.cookieName, m.csrfCookie} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   m.secure,
			SameSite: http.SameSiteLaxMode,
		})
	}
}

// Resolve validates the session cookie and returns the session plus its user.
func (m *SessionManager) Resolve(ctx context.Context, r *http.Request) (*store.Session, *store.User, error) {
	c, err := r.Cookie(m.cookieName)
	if err != nil || c.Value == "" {
		return nil, nil, store.ErrNotFound
	}
	token := c.Value
	sess, err := m.store.GetSession(ctx, hashToken(token))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC().Unix()
	if sess.ExpiresAt < now {
		_ = m.store.DeleteSession(ctx, sess.ID)
		return nil, nil, store.ErrNotFound
	}
	if now-sess.LastSeenAt > int64(m.idleTTL.Seconds()) {
		_ = m.store.DeleteSession(ctx, sess.ID)
		return nil, nil, store.ErrNotFound
	}
	user, err := m.store.GetUser(ctx, sess.UserID)
	if err != nil {
		return nil, nil, err
	}
	if user.Status != store.UserActive {
		_ = m.store.DeleteSession(ctx, sess.ID)
		return nil, nil, store.ErrNotFound
	}
	if now-sess.LastSeenAt > 60 {
		_ = m.store.TouchSession(ctx, sess.ID, now, sess.ExpiresAt)
	}
	return sess, user, nil
}

// Destroy invalidates one session.
func (m *SessionManager) Destroy(ctx context.Context, w http.ResponseWriter, sess *store.Session) error {
	m.Clear(w)
	if sess == nil {
		return nil
	}
	return m.store.DeleteSession(ctx, sess.ID)
}

// DestroyAll invalidates every session of a user.
func (m *SessionManager) DestroyAll(ctx context.Context, w http.ResponseWriter, userID string) error {
	m.Clear(w)
	return m.store.DeleteUserSessions(ctx, userID)
}

// ValidateCSRF enforces the double-submit token for state-changing requests.
func (m *SessionManager) ValidateCSRF(r *http.Request, sess *store.Session) bool {
	header := r.Header.Get("X-CSRF-Token")
	if header == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(header), []byte(sess.CSRFToken)) == 1
}

// CookieName returns the session cookie name.
func (m *SessionManager) CookieName() string { return m.cookieName }

// CSRFHeader is the header the SPA must send.
const CSRFHeader = "X-CSRF-Token"

// ------------------------------------------------------------- throttling

// LoginLimiter is a small in-memory sliding-window throttle keyed by string
// (IP, IP+email, ...). It is intentionally process-local for the MVP.
type LoginLimiter struct {
	mu     sync.Mutex
	events map[string][]time.Time
	limit  int
	window time.Duration
}

// NewLoginLimiter creates a limiter allowing `limit` events per window.
func NewLoginLimiter(limit int, window time.Duration) *LoginLimiter {
	if limit <= 0 {
		limit = 10
	}
	if window <= 0 {
		window = time.Minute
	}
	return &LoginLimiter{events: map[string][]time.Time{}, limit: limit, window: window}
}

// Allow reports whether the key may proceed, recording the attempt.
func (l *LoginLimiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	ev := l.events[key]
	cutoff := now.Add(-l.window)
	kept := ev[:0]
	for _, t := range ev {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.limit {
		l.events[key] = kept
		return false
	}
	l.events[key] = append(kept, now)
	if len(l.events) > 10000 {
		for k, v := range l.events {
			if len(v) == 0 || v[len(v)-1].Before(cutoff) {
				delete(l.events, k)
			}
		}
	}
	return true
}

// Reset clears a key after a successful authentication.
func (l *LoginLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.events, key)
}

// ClientIP extracts the caller address honouring X-Forwarded-For only when the
// deployment explicitly trusts the proxy.
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if v := strings.TrimSpace(parts[0]); v != "" {
				return v
			}
		}
		if h := strings.TrimSpace(r.Header.Get("X-Real-IP")); h != "" {
			return h
		}
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}
