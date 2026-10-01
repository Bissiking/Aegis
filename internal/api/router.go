package api

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/aegis-vpn/aegis/internal/auth"
)

// Handler assembles every route and its middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// ---- public -------------------------------------------------------
	public := func(pattern string, h http.Handler) {
		mux.Handle(pattern, s.base(h))
	}
	// Auth endpoints: rate limited by client address.
	loginL := s.rateLimit(s.limiter, ipKey)
	public("GET /api/v1/health", loginL(http.HandlerFunc(s.handleHealth)))
	public("GET /api/v1/meta", loginL(http.HandlerFunc(s.handleMeta)))
	public("POST /api/v1/auth/login", loginL(http.HandlerFunc(s.handleLogin)))
	public("POST /api/v1/auth/logout", loginL(http.HandlerFunc(s.handleLogout)))
	public("GET /api/v1/auth/kyros/start", loginL(http.HandlerFunc(s.handleKyrosStart)))
	public("GET /api/v1/auth/kyros/callback", loginL(http.HandlerFunc(s.handleKyrosCallback)))

	// ---- authenticated ------------------------------------------------
	apiLimit := s.rateLimit(s.apiLimit, ipKey)
	// Order matters: the session must be resolved before authentication and
	// CSRF checks, otherwise every state-changing request would be rejected.
	authed := func(pattern string, h http.Handler) {
		mux.Handle(pattern, s.chain(h, apiLimit, s.withOptionalAuth, s.requireAuth, s.csrf))
	}
	authed("GET /api/v1/auth/session", http.HandlerFunc(s.handleSession))
	authed("GET /api/v1/me", http.HandlerFunc(s.handleMe))
	authed("PATCH /api/v1/me", http.HandlerFunc(s.handleUpdateMe))
	authed("POST /api/v1/me/password", http.HandlerFunc(s.handleChangePassword))
	authed("GET /api/v1/me/usage", http.HandlerFunc(s.handleMyUsage))
	authed("GET /api/v1/me/devices", http.HandlerFunc(s.handleMyDevices))
	authed("POST /api/v1/me/devices", http.HandlerFunc(s.handleCreateDevice))
	authed("GET /api/v1/me/devices/{id}", http.HandlerFunc(s.handleGetMyDevice))
	authed("GET /api/v1/me/devices/{id}/profile", http.HandlerFunc(s.handleGetProfile))
	authed("POST /api/v1/me/devices/{id}/revoke", http.HandlerFunc(s.handleRevokeDevice))
	authed("POST /api/v1/me/devices/{id}/rotate", http.HandlerFunc(s.handleRotateDevice))
	authed("DELETE /api/v1/me/devices/{id}", http.HandlerFunc(s.handleDeleteMyDevice))

	// ---- administrator ------------------------------------------------
	admin := func(pattern string, h http.Handler) {
		mux.Handle(pattern, s.chain(h, apiLimit, s.withOptionalAuth, s.requireAdmin, s.requireAuth, s.csrf))
	}
	admin("GET /api/v1/admin/stats", http.HandlerFunc(s.handleStats))
	admin("GET /api/v1/admin/users", http.HandlerFunc(s.handleListUsers))
	admin("POST /api/v1/admin/users", http.HandlerFunc(s.handleCreateUser))
	admin("GET /api/v1/admin/users/{id}", http.HandlerFunc(s.handleGetUser))
	admin("PATCH /api/v1/admin/users/{id}", http.HandlerFunc(s.handleUpdateUser))
	admin("DELETE /api/v1/admin/users/{id}", http.HandlerFunc(s.handleDeleteUser))
	admin("POST /api/v1/admin/users/{id}/suspend", http.HandlerFunc(s.handleSuspendUser))
	admin("POST /api/v1/admin/users/{id}/resume", http.HandlerFunc(s.handleResumeUser))
	admin("GET /api/v1/admin/policies", http.HandlerFunc(s.handleListPolicies))
	admin("POST /api/v1/admin/policies", http.HandlerFunc(s.handleCreatePolicy))
	admin("PATCH /api/v1/admin/policies/{id}", http.HandlerFunc(s.handleUpdatePolicy))
	admin("DELETE /api/v1/admin/policies/{id}", http.HandlerFunc(s.handleDeletePolicy))
	admin("GET /api/v1/admin/servers", http.HandlerFunc(s.handleListServers))
	admin("POST /api/v1/admin/servers", http.HandlerFunc(s.handleCreateServer))
	admin("PATCH /api/v1/admin/servers/{id}", http.HandlerFunc(s.handleUpdateServer))
	admin("GET /api/v1/admin/devices", http.HandlerFunc(s.handleAdminDevices))
	admin("POST /api/v1/admin/devices/{id}/revoke", http.HandlerFunc(s.handleAdminRevokeDevice))
	admin("POST /api/v1/admin/devices/{id}/rotate", http.HandlerFunc(s.handleAdminRotateDevice))
	admin("GET /api/v1/admin/peers", http.HandlerFunc(s.handleListPeers))
	admin("GET /api/v1/admin/wireguard", http.HandlerFunc(s.handleWireGuardStatus))
	admin("GET /api/v1/admin/usage", http.HandlerFunc(s.handleAdminUsage))
	admin("GET /api/v1/admin/audit", http.HandlerFunc(s.handleListAudit))
	admin("GET /api/v1/admin/kyros", http.HandlerFunc(s.handleKyrosStatus))
	admin("GET /api/v1/admin/sessions/prune", http.HandlerFunc(s.handlePrune))

	// ---- openapi ------------------------------------------------------
	mux.Handle("GET /api/v1/openapi.yaml", s.base(http.HandlerFunc(s.handleOpenAPI)))

	// ---- frontend -----------------------------------------------------
	mux.Handle("/", s.base(s.frontend()))

	return mux
}

// frontend serves the built SPA with a history fallback.
func (s *Server) frontend() http.Handler {
	fs := http.FileServer(http.Dir(s.frontDir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSON(w, http.StatusNotFound, ErrorBody{
				Error: ErrorDetail{Code: "not_found", Message: "Unknown endpoint."},
				ReqID: reqID(r),
			})
			return
		}
		clean := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		if clean == "." {
			clean = "index.html"
		}
		full := filepath.Join(s.frontDir, clean)
		if !strings.HasPrefix(full, filepath.Clean(s.frontDir)) {
			http.NotFound(w, r)
			return
		}
		if st, err := os.Stat(full); err == nil && !st.IsDir() {
			if strings.HasSuffix(clean, "index.html") {
				w.Header().Set("Cache-Control", "no-store")
			} else {
				w.Header().Set("Cache-Control", "public, max-age=3600")
			}
			fs.ServeHTTP(w, r)
			return
		}
		// SPA fallback.
		idx := filepath.Join(s.frontDir, "index.html")
		f, err := os.Open(idx)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, ErrorBody{
				Error: ErrorDetail{Code: "frontend_missing", Message: "Frontend build not found."},
				ReqID: reqID(r),
			})
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, f)
	})
}

var _ = auth.CSRFHeader
