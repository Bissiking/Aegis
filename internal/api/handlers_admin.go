package api

import (
	"net/http"
	"strconv"

	"github.com/aegis-vpn/aegis/internal/service"
	"github.com/aegis-vpn/aegis/internal/store"
)

// ------------------------------------------------------------ dashboard

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	st, err := s.svc.Store.GetStats(r.Context(), store.CurrentMonth(s.svc.Store.Now()))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, st)
}

func (s *Server) handlePrune(w http.ResponseWriter, r *http.Request) {
	n, err := s.svc.Store.PruneExpiredSessions(r.Context(), s.svc.Store.Now().Unix())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, map[string]any{"pruned": n})
}

// ---------------------------------------------------------------- users

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	f := store.UserFilter{
		Query:  r.URL.Query().Get("q"),
		Role:   store.Role(r.URL.Query().Get("role")),
		Status: store.UserStatus(r.URL.Query().Get("status")),
		Limit:  queryInt(r, "limit", 50),
		Offset: queryInt(r, "offset", 0),
	}
	users, total, err := s.svc.Store.ListUsers(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.okMeta(w, r, users, map[string]any{"total": total, "limit": f.Limit, "offset": f.Offset})
}

type createUserRequest struct {
	Email       string     `json:"email"`
	DisplayName string     `json:"display_name"`
	Role        store.Role `json:"role"`
	Password    string     `json:"password"`
	PolicyID    string     `json:"policy_id"`
	ExpiresAt   *int64     `json:"expires_at"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := decode(r, &req, true); err != nil {
		s.fail(w, r, err)
		return
	}
	u, err := s.svc.CreateUser(r.Context(), ActorFrom(r), service.CreateUserInput{
		Email:       req.Email,
		DisplayName: req.DisplayName,
		Role:        req.Role,
		Password:    req.Password,
		PolicyID:    req.PolicyID,
		ExpiresAt:   req.ExpiresAt,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.created(w, r, u)
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.svc.Store.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	usage, _ := s.svc.GetUsageOverview(r.Context(), ActorFrom(r), u.ID)
	s.ok(w, r, map[string]any{"user": u, "usage": usage})
}

type updateUserRequest struct {
	DisplayName *string           `json:"display_name"`
	Role        *store.Role       `json:"role"`
	Status      *store.UserStatus `json:"status"`
	PolicyID    *string           `json:"policy_id"`
	Quota       *int64            `json:"quota_bytes"`
	ExpiresAt   *int64            `json:"expires_at"`
	Password    *string           `json:"password"`
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	var req updateUserRequest
	if err := decode(r, &req, true); err != nil {
		s.fail(w, r, err)
		return
	}
	u, err := s.svc.UpdateUser(r.Context(), ActorFrom(r), r.PathValue("id"), service.UpdateUserInput{
		DisplayName: req.DisplayName,
		Role:        req.Role,
		Status:      req.Status,
		PolicyID:    req.PolicyID,
		Quota:       req.Quota,
		ExpiresAt:   req.ExpiresAt,
		Password:    req.Password,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, u)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.DeleteUser(r.Context(), ActorFrom(r), r.PathValue("id")); err != nil {
		s.fail(w, r, err)
		return
	}
	s.noContent(w)
}

func (s *Server) handleSuspendUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st := store.UserSuspended
	u, err := s.svc.UpdateUser(r.Context(), ActorFrom(r), id, service.UpdateUserInput{Status: &st})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.svc.SuspendAccess(r.Context(), ActorFrom(r), id, true); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.svc.Store.DeleteUserSessions(r.Context(), id)
	s.ok(w, r, u)
}

func (s *Server) handleResumeUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st := store.UserActive
	u, err := s.svc.UpdateUser(r.Context(), ActorFrom(r), id, service.UpdateUserInput{Status: &st})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.svc.SuspendAccess(r.Context(), ActorFrom(r), id, false); err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, u)
}

// ------------------------------------------------------------- policies

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	pol, err := s.svc.ListPolicies(r.Context(), ActorFrom(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, pol)
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var req service.PolicyInput
	if err := decode(r, &req, true); err != nil {
		s.fail(w, r, err)
		return
	}
	p, err := s.svc.CreatePolicy(r.Context(), ActorFrom(r), req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.created(w, r, p)
}

func (s *Server) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	var req service.PolicyInput
	if err := decode(r, &req, true); err != nil {
		s.fail(w, r, err)
		return
	}
	p, err := s.svc.UpdatePolicy(r.Context(), ActorFrom(r), r.PathValue("id"), req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, p)
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.DeletePolicy(r.Context(), ActorFrom(r), r.PathValue("id")); err != nil {
		s.fail(w, r, err)
		return
	}
	s.noContent(w)
}

// -------------------------------------------------------------- servers

func (s *Server) handleListServers(w http.ResponseWriter, r *http.Request) {
	servers, err := s.svc.ListServers(r.Context(), ActorFrom(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, servers)
}

func (s *Server) handleCreateServer(w http.ResponseWriter, r *http.Request) {
	var req service.ServerInput
	if err := decode(r, &req, true); err != nil {
		s.fail(w, r, err)
		return
	}
	srv, err := s.svc.CreateServer(r.Context(), ActorFrom(r), req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.created(w, r, srv)
}

func (s *Server) handleUpdateServer(w http.ResponseWriter, r *http.Request) {
	var req service.ServerInput
	if err := decode(r, &req, true); err != nil {
		s.fail(w, r, err)
		return
	}
	srv, err := s.svc.UpdateServer(r.Context(), ActorFrom(r), r.PathValue("id"), req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, srv)
}

// -------------------------------------------------------------- devices

func (s *Server) handleAdminDevices(w http.ResponseWriter, r *http.Request) {
	f := store.DeviceFilter{
		UserID: r.URL.Query().Get("user_id"),
		Status: r.URL.Query().Get("status"),
		Query:  r.URL.Query().Get("q"),
		Limit:  queryInt(r, "limit", 50),
		Offset: queryInt(r, "offset", 0),
	}
	devs, total, err := s.svc.ListDevices(r.Context(), ActorFrom(r), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.okMeta(w, r, devs, map[string]any{"total": total, "limit": f.Limit, "offset": f.Offset})
}

func (s *Server) handleAdminRevokeDevice(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.RevokeDevice(r.Context(), ActorFrom(r), r.PathValue("id")); err != nil {
		s.fail(w, r, err)
		return
	}
	s.noContent(w)
}

func (s *Server) handleAdminRotateDevice(w http.ResponseWriter, r *http.Request) {
	out, err := s.svc.RotateDevice(r.Context(), ActorFrom(r), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}

// ---------------------------------------------------------------- peers

func (s *Server) handleListPeers(w http.ResponseWriter, r *http.Request) {
	peers, err := s.svc.Store.ListPeersWithOwners(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type row struct {
		ID              string `json:"id"`
		DeviceID        string `json:"device_id"`
		DeviceName      string `json:"device_name"`
		UserID          string `json:"user_id"`
		PublicKey       string `json:"public_key"`
		AllowedIP       string `json:"allowed_ip"`
		Status          string `json:"status"`
		SuspendedReason string `json:"suspended_reason"`
		LastHandshakeAt *int64 `json:"last_handshake_at"`
		RxBytes         int64  `json:"rx_bytes"`
		TxBytes         int64  `json:"tx_bytes"`
		CreatedAt       int64  `json:"created_at"`
	}
	out := make([]row, 0, len(peers))
	for _, p := range peers {
		out = append(out, row{
			ID: p.ID, DeviceID: p.DeviceID, DeviceName: p.DeviceName, UserID: p.UserID,
			PublicKey: p.PublicKey, AllowedIP: p.AllowedIP, Status: p.Status,
			SuspendedReason: p.SuspendedReason, LastHandshakeAt: p.LastHandshakeAt,
			RxBytes: p.RxBytes, TxBytes: p.TxBytes, CreatedAt: p.CreatedAt,
		})
	}
	s.ok(w, r, out)
}

func (s *Server) handleWireGuardStatus(w http.ResponseWriter, r *http.Request) {
	out, err := s.svc.WireGuardStatus(r.Context(), ActorFrom(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}

// ---------------------------------------------------------------- usage

func (s *Server) handleAdminUsage(w http.ResponseWriter, r *http.Request) {
	month := r.URL.Query().Get("month")
	if month == "" {
		month = store.CurrentMonth(s.svc.Store.Now())
	}
	rows, err := s.svc.Store.ListMonthlyUsageAll(r.Context(), month, queryInt(r, "limit", 100))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	total, _ := s.svc.Store.SumMonthlyUsageAll(r.Context(), month)
	s.okMeta(w, r, rows, map[string]any{"month": month, "total_bytes": total})
}

// ---------------------------------------------------------------- audit

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	f := store.AuditFilter{
		Actor:  r.URL.Query().Get("actor"),
		Action: r.URL.Query().Get("action"),
		Query:  r.URL.Query().Get("q"),
		Limit:  queryInt(r, "limit", 50),
		Offset: queryInt(r, "offset", 0),
	}
	if v := r.URL.Query().Get("from"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			f.From = n
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			f.To = n
		}
	}
	events, total, err := s.svc.Store.ListAudit(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.okMeta(w, r, events, map[string]any{"total": total, "limit": f.Limit, "offset": f.Offset})
}
