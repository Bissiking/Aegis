package api

import (
	"context"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/aegis-vpn/aegis/internal/auth"
	"github.com/aegis-vpn/aegis/internal/service"
	"github.com/aegis-vpn/aegis/internal/store"
)

type ctxKey int

const (
	ctxReqID ctxKey = iota
	ctxSession
	ctxUser
	ctxActor
)

// ActorFrom builds the audit actor of the current request.
func ActorFrom(r *http.Request) service.Actor {
	if a, ok := r.Context().Value(ctxActor).(service.Actor); ok {
		return a
	}
	return service.Actor{Kind: "anonymous", CorrelationID: reqID(r), IP: auth.ClientIP(r, false), UserAgent: r.Header.Get("User-Agent")}
}

func sessionFrom(r *http.Request) *store.Session {
	s, _ := r.Context().Value(ctxSession).(*store.Session)
	return s
}

func userFrom(r *http.Request) *store.User {
	u, _ := r.Context().Value(ctxUser).(*store.User)
	return u
}

// chain applies middlewares so that the outermost runs first.
func (s *Server) chain(h http.Handler, extra ...func(http.Handler) http.Handler) http.Handler {
	var fn http.Handler = h
	for i := len(extra) - 1; i >= 0; i-- {
		fn = extra[i](fn)
	}
	return fn
}

// withRecovery, withRequestID, withSecurityHeaders and withLogging are applied
// to every request.
func (s *Server) base(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newRequestID()
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		if s.secure {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Security-Policy",
				"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
			w.Header().Set("Cache-Control", "no-store")
		} else {
			w.Header().Set("Content-Security-Policy", cspForFrontend())
		}

		ctx := context.WithValue(r.Context(), ctxReqID, id)
		r = r.WithContext(ctx)

		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic recovered", "path", r.URL.Path, "panic", rec, "stack", string(debug.Stack()))
				writeJSON(w, http.StatusInternalServerError, ErrorBody{
					Error: ErrorDetail{Code: "internal_error", Message: "An internal error occurred."},
					ReqID: id,
				})
			}
		}()
		h.ServeHTTP(w, r)
	})
}

func cspForFrontend() string {
	return "default-src 'self'; " +
		"img-src 'self' data:; " +
		"style-src 'self' 'unsafe-inline'; " +
		"script-src 'self'; " +
		"connect-src 'self'; " +
		"font-src 'self' data:; " +
		"object-src 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'; " +
		"frame-ancestors 'none'"
}

// withAuth resolves the session cookie for routes that may be public.
func (s *Server) withOptionalAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, user, err := s.sessions.Resolve(r.Context(), r)
		if err == nil && sess != nil && user != nil {
			actor := service.Actor{
				UserID:        user.ID,
				Kind:          "local",
				Role:          user.Role,
				IP:            auth.ClientIP(r, s.trustPrx),
				UserAgent:     r.Header.Get("User-Agent"),
				CorrelationID: reqID(r),
			}
			if ident, err := s.svc.Store.GetIdentity(r.Context(), "kyros", user.ID); err == nil && ident != nil {
				_ = ident
			}
			ctx := context.WithValue(r.Context(), ctxSession, sess)
			ctx = context.WithValue(ctx, ctxUser, user)
			ctx = context.WithValue(ctx, ctxActor, actor)
			r = r.WithContext(ctx)
		}
		h.ServeHTTP(w, r)
	})
}

// requireAuth rejects unauthenticated requests.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sessionFrom(r) == nil || userFrom(r) == nil {
			writeJSON(w, http.StatusUnauthorized, ErrorBody{
				Error: ErrorDetail{Code: "unauthorized", Message: "Authentication required."},
				ReqID: reqID(r),
			})
			return
		}
		h.ServeHTTP(w, r)
	})
}

// requireAdmin rejects non-administrators.
func (s *Server) requireAdmin(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := userFrom(r)
		if u == nil || u.Role != store.RoleAdmin {
			writeJSON(w, http.StatusForbidden, ErrorBody{
				Error: ErrorDetail{Code: "forbidden", Message: "Administrator access required."},
				ReqID: reqID(r),
			})
			return
		}
		h.ServeHTTP(w, r)
	})
}

// csrf protects state-changing authenticated requests with a double-submit
// token bound to the session.
func (s *Server) csrf(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			h.ServeHTTP(w, r)
			return
		}
		sess := sessionFrom(r)
		if sess == nil {
			writeJSON(w, http.StatusUnauthorized, ErrorBody{
				Error: ErrorDetail{Code: "unauthorized", Message: "Authentication required."},
				ReqID: reqID(r),
			})
			return
		}
		if !s.sessions.ValidateCSRF(r, sess) {
			writeJSON(w, http.StatusForbidden, ErrorBody{
				Error: ErrorDetail{Code: "csrf_failed", Message: "Invalid or missing CSRF token."},
				ReqID: reqID(r),
			})
			return
		}
		h.ServeHTTP(w, r)
	})
}

// rateLimit throttles sensitive routes per client address.
func (s *Server) rateLimit(l *auth.LoginLimiter, perKey func(*http.Request) string) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := perKey(r)
			if !l.Allow(key) {
				writeJSON(w, http.StatusTooManyRequests, ErrorBody{
					Error: ErrorDetail{Code: "rate_limited", Message: "Too many requests. Try again later."},
					ReqID: reqID(r),
				})
				return
			}
			h.ServeHTTP(w, r)
		})
	}
}

func ipKey(r *http.Request) string { return auth.ClientIP(r, false) }

// ensure no time import is dropped.
var _ = time.Second
