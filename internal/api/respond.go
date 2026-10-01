// Package api exposes the versioned JSON HTTP API of Aegis.
package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/aegis-vpn/aegis/internal/auth"
	"github.com/aegis-vpn/aegis/internal/service"
	"github.com/aegis-vpn/aegis/internal/store"
)

// Envelope is the uniform success payload.
type Envelope struct {
	Data  any            `json:"data"`
	Meta  map[string]any `json:"meta,omitempty"`
	ReqID string         `json:"request_id"`
}

// ErrorBody is the uniform error payload.
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
	ReqID string      `json:"request_id"`
}

// ErrorDetail describes a failure without leaking internals.
type ErrorDetail struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// Server hosts every handler and its dependencies.
type Server struct {
	svc      *service.Service
	sessions *auth.SessionManager
	kyros    *auth.KyrosProvider
	log      *slog.Logger
	limiter  *auth.LoginLimiter
	apiLimit *auth.LoginLimiter
	trustPrx bool
	frontDir string
	secure   bool
}

// Options configures the API server.
type Options struct {
	Service      *service.Service
	Sessions     *auth.SessionManager
	Kyros        *auth.KyrosProvider
	Logger       *slog.Logger
	TrustProxy   bool
	FrontendDir  string
	CookieSecure bool
	LoginLimit   int
	APIRateLimit int
}

// New builds the API server.
func New(o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Server{
		svc:      o.Service,
		sessions: o.Sessions,
		kyros:    o.Kyros,
		log:      o.Logger,
		limiter:  auth.NewLoginLimiter(o.LoginLimit, time.Minute),
		apiLimit: auth.NewLoginLimiter(o.APIRateLimit, time.Minute),
		trustPrx: o.TrustProxy,
		frontDir: o.FrontendDir,
		secure:   o.CookieSecure,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) ok(w http.ResponseWriter, r *http.Request, data any) {
	writeJSON(w, http.StatusOK, Envelope{Data: data, ReqID: reqID(r)})
}

func (s *Server) okMeta(w http.ResponseWriter, r *http.Request, data any, meta map[string]any) {
	writeJSON(w, http.StatusOK, Envelope{Data: data, Meta: meta, ReqID: reqID(r)})
}

func (s *Server) created(w http.ResponseWriter, r *http.Request, data any) {
	writeJSON(w, http.StatusCreated, Envelope{Data: data, ReqID: reqID(r)})
}

func (s *Server) noContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// fail maps domain errors onto a uniform JSON error.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	code := "internal_error"
	status := http.StatusInternalServerError
	msg := "An internal error occurred."
	details := map[string]any{}

	switch {
	case errors.Is(err, service.ErrUnauthorized):
		status, code, msg = http.StatusUnauthorized, "unauthorized", "Invalid credentials."
	case errors.Is(err, service.ErrForbidden):
		status, code, msg = http.StatusForbidden, "forbidden", "You are not allowed to perform this action."
	case errors.Is(err, service.ErrGone):
		status, code, msg = http.StatusGone, "gone", "This resource is no longer available."
	case errors.Is(err, service.ErrAlreadyExists):
		status, code, msg = http.StatusConflict, "conflict", "The resource already exists."
	case errors.Is(err, service.ErrRateLimited):
		status, code, msg = http.StatusTooManyRequests, "rate_limited", "Too many attempts. Try again later."
	case errors.Is(err, service.ErrQuota):
		status, code, msg = http.StatusConflict, "quota_exceeded", "A configured limit has been reached."
	case errors.Is(err, service.ErrUnavailable):
		status, code, msg = http.StatusServiceUnavailable, "unavailable", "A dependency is temporarily unavailable."
	case errors.Is(err, service.ErrInvalid):
		status, code, msg = http.StatusBadRequest, "invalid", "The request is invalid."
	case errors.Is(err, store.ErrNotFound):
		status, code, msg = http.StatusNotFound, "not_found", "The requested resource does not exist."
	case errors.Is(err, auth.ErrPasswordPolicy):
		status, code, msg = http.StatusBadRequest, "password_policy", err.Error()
	default:
		var fe *service.FieldError
		if errors.As(err, &fe) {
			status, code, msg = http.StatusBadRequest, "validation_failed", "One or more fields are invalid."
			details["field"] = fe.Field
		} else {
			s.log.Error("request failed", "path", r.URL.Path, "err", err, "stack", string(debug.Stack()))
		}
	}
	writeJSON(w, status, ErrorBody{
		Error: ErrorDetail{Code: code, Message: msg, Details: details},
		ReqID: reqID(r),
	})
}

func reqID(r *http.Request) string {
	if v := r.Header.Get("X-Request-ID"); v != "" && len(v) < 64 {
		return v
	}
	if v, ok := r.Context().Value(ctxReqID).(string); ok && v != "" {
		return v
	}
	return ""
}

func newRequestID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "req-unknown"
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// decode reads a JSON body with a hard size limit and rejects unknown fields
// when strict is true.
func decode(r *http.Request, dst any, strict bool) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return service.ErrInvalid
	}
	if strict {
		// ensure no trailing content
		if dec.More() {
			return service.ErrInvalid
		}
	}
	return nil
}
