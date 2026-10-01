package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/aegis-vpn/aegis/internal/auth"
	"github.com/aegis-vpn/aegis/internal/service"
	"github.com/aegis-vpn/aegis/internal/store"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// handleHealth exposes application health without authentication.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	rep, err := s.svc.Health(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	status := http.StatusOK
	if rep.Status != "ok" {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, Envelope{Data: rep, ReqID: reqID(r)})
}

// handleMeta gives the SPA everything it needs to render the login page.
func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	kyros := map[string]any{"enabled": false, "button_label": ""}
	if s.kyros != nil && s.kyros.Enabled() {
		kyros["enabled"] = true
		kyros["button_label"] = s.kyros.Config().ButtonLabel
	}
	writeJSON(w, http.StatusOK, Envelope{
		Data: map[string]any{
			"local_auth_enabled": s.svc.Cfg.LocalAuthEnabled,
			"kyros":              kyros,
			"csrf_cookie":        s.svc.Cfg.CSRFCookieName,
			"version":            service.Version,
			"environment":        s.svc.Cfg.Environment,
		},
		ReqID: reqID(r),
	})
}

// handleLogin authenticates a local account.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decode(r, &req, true); err != nil {
		s.fail(w, r, err)
		return
	}
	ip := auth.ClientIP(r, s.trustPrx)
	actor := service.Actor{Kind: "local", IP: ip, UserAgent: r.Header.Get("User-Agent"), CorrelationID: reqID(r)}

	user, err := s.svc.LoginLocal(r.Context(), req.Email, req.Password, ip)
	if err != nil {
		s.svc.Audit(r.Context(), actor, "auth.login_failed", "user", "", map[string]any{
			"email": maskEmail(req.Email),
		})
		if errors.Is(err, service.ErrRateLimited) {
			writeJSON(w, http.StatusTooManyRequests, ErrorBody{
				Error: ErrorDetail{Code: "rate_limited", Message: "Too many attempts. Try again later."},
				ReqID: reqID(r),
			})
			return
		}
		s.fail(w, r, service.ErrUnauthorized)
		return
	}
	_ = s.svc.Store.ClearLoginFailures(r.Context(), user.ID)
	csrf, err := s.startSession(w, r, user)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.svc.Audit(r.Context(), actorFor(user, ip, r, reqID(r)), "auth.login_success", "user", user.ID, nil)
	s.ok(w, r, map[string]any{"user": user, "csrf_token": csrf})
}

// startSession issues a brand new session (rotation by construction) and
// returns the CSRF token to echo back on subsequent mutations.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, user *store.User) (string, error) {
	sess, err := s.sessions.Create(r.Context(), w, user.ID,
		auth.ClientIP(r, s.trustPrx), r.Header.Get("User-Agent"), "")
	if err != nil {
		return "", err
	}
	return sess.CSRFToken, nil
}

func actorFor(user *store.User, ip string, r *http.Request, corr string) service.Actor {
	kind := "local"
	if user != nil && user.HasKyrosIdentity && !user.HasLocalPassword {
		kind = "kyros"
	}
	return service.Actor{
		UserID:        user.ID,
		Kind:          kind,
		Role:          user.Role,
		IP:            ip,
		UserAgent:     r.Header.Get("User-Agent"),
		CorrelationID: corr,
	}
}

// handleLogout terminates the current session.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	u := userFrom(r)
	if sess != nil && u != nil {
		s.svc.Audit(r.Context(), actorFor(u, auth.ClientIP(r, s.trustPrx), r, reqID(r)),
			"auth.logout", "user", u.ID, nil)
	}
	_ = s.sessions.Destroy(r.Context(), w, sess)
	s.noContent(w)
}

// handleSession returns the current session state for the SPA.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	sess := sessionFrom(r)
	if u == nil || sess == nil {
		writeJSON(w, http.StatusUnauthorized, ErrorBody{
			Error: ErrorDetail{Code: "unauthorized", Message: "Not authenticated."},
			ReqID: reqID(r),
		})
		return
	}
	s.ok(w, r, map[string]any{
		"user":            u,
		"csrf_token":      sess.CSRFToken,
		"session_expires": sess.ExpiresAt,
	})
}

// handleMe returns the current user.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	full, err := s.svc.Store.GetUser(r.Context(), u.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, full)
}

type updateMeRequest struct {
	DisplayName     *string `json:"display_name"`
	Password        *string `json:"password"`
	CurrentPassword *string `json:"current_password"`
}

// handleUpdateMe allows self-service profile changes.
func (s *Server) handleUpdateMe(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var req updateMeRequest
	if err := decode(r, &req, true); err != nil {
		s.fail(w, r, err)
		return
	}
	in := service.UpdateUserInput{DisplayName: req.DisplayName}
	if req.Password != nil && *req.Password != "" {
		if req.CurrentPassword == nil {
			s.fail(w, r, service.ErrInvalid)
			return
		}
		if err := s.svc.ChangePassword(r.Context(), ActorFrom(r), *req.CurrentPassword, *req.Password); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	updated, err := s.svc.UpdateUser(r.Context(), ActorFrom(r), u.ID, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, updated)
}

type changePasswordRequest struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

// handleChangePassword performs a self-service password change.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	if err := decode(r, &req, true); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.svc.ChangePassword(r.Context(), ActorFrom(r), req.Current, req.New); err != nil {
		s.fail(w, r, err)
		return
	}
	s.noContent(w)
}

// ------------------------------------------------------------------ kyros

// handleKyrosStart begins the OIDC authorization code + PKCE flow.
func (s *Server) handleKyrosStart(w http.ResponseWriter, r *http.Request) {
	if s.kyros == nil || !s.kyros.Enabled() {
		s.fail(w, r, service.ErrForbidden)
		return
	}
	ctx := r.Context()
	pkce, authURL, err := s.kyros.Begin(ctx)
	if err != nil {
		s.log.Error("kyros begin failed", "err", err)
		s.fail(w, r, service.ErrUnavailable)
		return
	}
	if err := s.svc.Store.SaveOAuthState(ctx, auth.HashState(pkce.State), pkce.Verifier, pkce.Nonce,
		safeRedirect(r.URL.Query().Get("next")), time.Now().Unix(), time.Now().Add(10*time.Minute).Unix()); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleKyrosCallback finishes the flow and creates a local session.
func (s *Server) handleKyrosCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("error") != "" {
		http.Redirect(w, r, "/?error=kyros", http.StatusFound)
		return
	}
	code, state := q.Get("code"), q.Get("state")
	if code == "" || state == "" {
		http.Redirect(w, r, "/?error=kyros", http.StatusFound)
		return
	}
	ctx := r.Context()
	verifier, nonce, redirectTo, err := s.svc.Store.ConsumeOAuthState(ctx, auth.HashState(state))
	if err != nil {
		http.Redirect(w, r, "/?error=state", http.StatusFound)
		return
	}
	ident, err := s.kyros.Complete(ctx, code, verifier, nonce)
	if err != nil {
		s.log.Error("kyros callback failed", "err", err)
		http.Redirect(w, r, "/?error=kyros", http.StatusFound)
		return
	}
	user, err := s.svc.LoginKyros(ctx, ident.Email, ident.Subject, ident.Name, true)
	if err != nil {
		s.svc.Audit(ctx, service.Actor{Kind: "kyros", IP: auth.ClientIP(r, s.trustPrx), CorrelationID: reqID(r)},
			"auth.login_failed", "user", "", map[string]any{"provider": "kyros"})
		http.Redirect(w, r, "/?error=denied", http.StatusFound)
		return
	}
	if _, err := s.startSession(w, r, user); err != nil {
		s.fail(w, r, err)
		return
	}
	s.svc.Audit(ctx, service.Actor{
		UserID: user.ID, Kind: "kyros", Role: user.Role,
		IP: auth.ClientIP(r, s.trustPrx), UserAgent: r.Header.Get("User-Agent"), CorrelationID: reqID(r),
	}, "auth.login_success", "user", user.ID, map[string]any{"provider": "kyros"})
	if redirectTo == "" {
		redirectTo = "/"
	}
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

// handleKyrosStatus reports the integration state to administrators.
func (s *Server) handleKyrosStatus(w http.ResponseWriter, r *http.Request) {
	if s.kyros == nil {
		s.ok(w, r, map[string]any{"enabled": false, "detail": "adapter not configured"})
		return
	}
	s.ok(w, r, s.kyros.Status(r.Context()))
}

// safeRedirect only accepts same-site relative paths.
func safeRedirect(v string) string {
	if v == "" || v[0] != '/' || stringsHasPrefix(v, "//") {
		return "/"
	}
	return v
}

func stringsHasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}

func maskEmail(e string) string {
	at := -1
	for i := 0; i < len(e); i++ {
		if e[i] == '@' {
			at = i
			break
		}
	}
	if at <= 0 {
		return "***"
	}
	local := e[:at]
	if len(local) > 2 {
		local = local[:1] + "***" + local[len(local)-1:]
	} else {
		local = "***"
	}
	return local + e[at:]
}
