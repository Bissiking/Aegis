package api

import (
	"net/http"

	"github.com/aegis-vpn/aegis/internal/service"
	"github.com/aegis-vpn/aegis/internal/store"
)

type createDeviceRequest struct {
	Name     string `json:"name"`
	Platform string `json:"platform"`
	ServerID string `json:"server_id"`
	UserID   string `json:"user_id"`
}

// handleMyDevices lists the caller's devices.
func (s *Server) handleMyDevices(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	f := store.DeviceFilter{
		UserID: u.ID,
		Query:  r.URL.Query().Get("q"),
		Status: r.URL.Query().Get("status"),
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

// handleCreateDevice provisions a device and delivers its profile once.
func (s *Server) handleCreateDevice(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var req createDeviceRequest
	if err := decode(r, &req, true); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := service.ValidateDeviceName(req.Name); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.UserID == "" {
		req.UserID = u.ID
	}
	out, err := s.svc.CreateDevice(r.Context(), ActorFrom(r), service.CreateDeviceInput{
		UserID:   req.UserID,
		Name:     req.Name,
		Platform: req.Platform,
		ServerID: req.ServerID,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.svc.TouchDevice(r.Context(), out.Device.ID)
	s.created(w, r, out)
}

// handleGetMyDevice returns one of the caller's devices.
func (s *Server) handleGetMyDevice(w http.ResponseWriter, r *http.Request) {
	d, err := s.svc.GetDevice(r.Context(), ActorFrom(r), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, d)
}

// handleGetProfile always answers 410: a configuration is delivered exactly
// once, at creation or rotation time.
func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	err := s.svc.GetProfile(r.Context(), ActorFrom(r), r.PathValue("id"))
	s.fail(w, r, err)
}

// handleRevokeDevice revokes a device immediately.
func (s *Server) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.RevokeDevice(r.Context(), ActorFrom(r), r.PathValue("id")); err != nil {
		s.fail(w, r, err)
		return
	}
	s.noContent(w)
}

// handleRotateDevice rotates the keys of a device and returns a new profile.
func (s *Server) handleRotateDevice(w http.ResponseWriter, r *http.Request) {
	out, err := s.svc.RotateDevice(r.Context(), ActorFrom(r), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}

// handleDeleteMyDevice deletes a device owned by the caller.
func (s *Server) handleDeleteMyDevice(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.DeleteDevice(r.Context(), ActorFrom(r), r.PathValue("id")); err != nil {
		s.fail(w, r, err)
		return
	}
	s.noContent(w)
}

// handleMyUsage returns the caller's consumption overview.
func (s *Server) handleMyUsage(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	ov, err := s.svc.GetUsageOverview(r.Context(), ActorFrom(r), u.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, ov)
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if n > 500 {
		return 500
	}
	return n
}
