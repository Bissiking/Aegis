package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegis-vpn/aegis/internal/auth"
	"github.com/aegis-vpn/aegis/internal/config"
	"github.com/aegis-vpn/aegis/internal/service"
	"github.com/aegis-vpn/aegis/internal/store"
	"github.com/aegis-vpn/aegis/internal/wg"
)

const (
	testAdminEmail    = "admin@example.org"
	testAdminPassword = "Bootstrap-Passw0rd!"
)

type harness struct {
	t     *testing.T
	srv   *httptest.Server
	store *store.Store
	svc   *service.Service
	fake  *wg.Fake
	cfg   *config.Config
}

func newHarness(t *testing.T, tune func(*config.Config)) *harness {
	t.Helper()

	cfg := &config.Config{
		DatabasePath:            ":memory:",
		ListenAddr:              "127.0.0.1:0",
		SessionSecret:           "test-secret-test-secret-test-secret-1234",
		SessionTTL:              time.Hour,
		SessionIdleTTL:          time.Hour,
		CookieName:              "aegis_session",
		CSRFCookieName:          "aegis_csrf",
		LocalAuthEnabled:        true,
		LocalBootstrapUser:      testAdminEmail,
		LocalBootstrapPassword:  testAdminPassword,
		ArgonTime:               1,
		ArgonMemoryKiB:          8 * 1024,
		ArgonThreads:            1,
		ArgonKeyLen:             32,
		LoginRateLimitPerMinute: 100,
		APIRateLimitPerMinute:   1000,
		WGInterface:             "wg0",
		WGPort:                  51820,
		WGNetwork:               "10.77.0.0/24",
		WGDNS:                   []string{"1.1.1.1"},
		WGMaxPeers:              32,
		WGFullTunnel:            true,
		WGPersistentKeepalive:   25,
		MaxDevicesDefault:       3,
		Environment:             "development",
		Development:             true,
		FrontendDir:             t.TempDir(),
	}
	if tune != nil {
		tune(cfg)
	}

	st, err := store.Open(cfg.DatabasePath)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	fake := wg.NewFake()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(st, fake, cfg, log)
	if err := svc.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	sessions := auth.NewSessionManager(st, cfg.CookieName, cfg.CSRFCookieName,
		cfg.CookieSecure, cfg.SessionTTL, cfg.SessionIdleTTL, cfg.TrustProxy)

	apiSrv := New(Options{
		Service:      svc,
		Sessions:     sessions,
		Logger:       log,
		TrustProxy:   cfg.TrustProxy,
		FrontendDir:  cfg.FrontendDir,
		CookieSecure: cfg.CookieSecure,
		LoginLimit:   cfg.LoginRateLimitPerMinute,
		APIRateLimit: cfg.APIRateLimitPerMinute,
	})

	ts := httptest.NewServer(apiSrv.Handler())
	t.Cleanup(ts.Close)

	return &harness{t: t, srv: ts, store: st, svc: svc, fake: fake, cfg: cfg}
}

// client is a tiny cookie/CSRF aware HTTP client.
type client struct {
	t        *testing.T
	base     string
	cookies  map[string]string
	csrf     string
	sendCSRF bool
	// loginResp is kept so a test can inspect the login Set-Cookie flags.
	loginResp *http.Response
}

func (h *harness) client() *client {
	return &client{t: h.t, base: h.srv.URL, cookies: map[string]string{}, sendCSRF: true}
}

func (c *client) do(method, path string, body any) (*http.Response, []byte) {
	c.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		c.t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if len(c.cookies) > 0 {
		parts := make([]string, 0, len(c.cookies))
		for k, v := range c.cookies {
			parts = append(parts, k+"="+v)
		}
		req.Header.Set("Cookie", strings.Join(parts, "; "))
	}
	if c.sendCSRF && c.csrf != "" {
		req.Header.Set(auth.CSRFHeader, c.csrf)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	for _, ck := range resp.Cookies() {
		if ck.Value == "" || ck.MaxAge < 0 {
			delete(c.cookies, ck.Name)
			continue
		}
		c.cookies[ck.Name] = ck.Value
	}
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatalf("read body: %v", err)
	}
	return resp, out
}

func (c *client) mustStatus(method, path string, body any, want int) []byte {
	c.t.Helper()
	resp, out := c.do(method, path, body)
	if resp.StatusCode != want {
		c.t.Fatalf("%s %s = %d, want %d; body=%s", method, path, resp.StatusCode, want, out)
	}
	return out
}

func (c *client) login(email, password string) {
	c.t.Helper()
	resp, out := c.do(http.MethodPost, "/api/v1/auth/login",
		map[string]string{"email": email, "password": password})
	c.loginResp = resp
	if resp.StatusCode != http.StatusOK {
		c.t.Fatalf("login = %d, want 200; body=%s", resp.StatusCode, out)
	}
	var env struct {
		Data struct {
			CSRFToken string `json:"csrf_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		c.t.Fatalf("login envelope: %v", err)
	}
	c.csrf = env.Data.CSRFToken
	if c.csrf == "" {
		c.t.Fatal("login returned no csrf token")
	}
}

func (c *client) mustFail(method, path string, body any, want int, wantCode string) {
	c.t.Helper()
	resp, out := c.do(method, path, body)
	if resp.StatusCode != want {
		c.t.Fatalf("%s %s = %d, want %d; body=%s", method, path, resp.StatusCode, want, out)
	}
	var eb ErrorBody
	if err := json.Unmarshal(out, &eb); err != nil {
		c.t.Fatalf("error envelope: %v (%s)", err, out)
	}
	if eb.Error.Code != wantCode {
		c.t.Fatalf("%s %s code = %q, want %q; body=%s", method, path, eb.Error.Code, wantCode, out)
	}
}

func decodeData[T any](t *testing.T, out []byte) T {
	t.Helper()
	var env struct {
		Data T `json:"data"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("decode data: %v (%s)", err, out)
	}
	return env.Data
}

// ---------------------------------------------------------------- tests

func TestLoginSessionAndLogout(t *testing.T) {
	h := newHarness(t, nil)
	c := h.client()

	c.mustStatus(http.MethodGet, "/api/v1/me", nil, http.StatusUnauthorized)
	c.mustFail(http.MethodPost, "/api/v1/auth/login",
		map[string]string{"email": testAdminEmail, "password": "wrong-password"},
		http.StatusUnauthorized, "unauthorized")

	c.login(testAdminEmail, testAdminPassword)
	out := c.mustStatus(http.MethodGet, "/api/v1/me", nil, http.StatusOK)
	me := decodeData[map[string]any](t, out)
	if me["email"] != testAdminEmail {
		t.Fatalf("email = %v", me["email"])
	}
	if me["role"] != string(store.RoleAdmin) {
		t.Fatalf("role = %v", me["role"])
	}

	c.mustStatus(http.MethodPost, "/api/v1/auth/logout", nil, http.StatusNoContent)
	c.mustStatus(http.MethodGet, "/api/v1/me", nil, http.StatusUnauthorized)
}

func TestCSRFRequiredForMutations(t *testing.T) {
	h := newHarness(t, nil)
	c := h.client()
	c.login(testAdminEmail, testAdminPassword)

	// Token present but not sent.
	saved := c.csrf
	c.csrf = ""
	c.mustFail(http.MethodPost, "/api/v1/me/devices",
		map[string]string{"name": "phone"}, http.StatusForbidden, "csrf_failed")

	// Token sent but wrong.
	c.csrf = "not-the-real-token"
	c.mustFail(http.MethodPost, "/api/v1/me/devices",
		map[string]string{"name": "phone"}, http.StatusForbidden, "csrf_failed")

	c.csrf = saved
	c.mustStatus(http.MethodPost, "/api/v1/me/devices",
		map[string]string{"name": "phone"}, http.StatusCreated)
}

func TestCrossUserDeviceAccessIsBlocked(t *testing.T) {
	h := newHarness(t, nil)
	admin := h.client()
	admin.login(testAdminEmail, testAdminPassword)

	createUser := func(email string) {
		admin.mustStatus(http.MethodPost, "/api/v1/admin/users", map[string]any{
			"email": email, "display_name": email, "role": store.RoleUser,
			"password": "User-Passw0rd!23",
		}, http.StatusCreated)
	}
	createUser("alice@example.org")
	createUser("bob@example.org")

	alice := h.client()
	alice.login("alice@example.org", "User-Passw0rd!23")
	bob := h.client()
	bob.login("bob@example.org", "User-Passw0rd!23")

	out := bob.mustStatus(http.MethodPost, "/api/v1/me/devices", map[string]string{"name": "bob-phone"}, http.StatusCreated)
	created := decodeData[struct {
		Device struct {
			ID     string `json:"id"`
			UserID string `json:"user_id"`
		} `json:"device"`
		Profile *service.DeviceProfile `json:"profile"`
	}](t, out)
	if created.Device.UserID == "" || created.Profile == nil {
		t.Fatalf("unexpected create response: %+v", created)
	}

	// IDOR: alice must not read, revoke, rotate or delete bob's device.
	alice.mustFail(http.MethodGet, "/api/v1/me/devices/"+created.Device.ID, nil, http.StatusForbidden, "forbidden")
	alice.mustFail(http.MethodPost, "/api/v1/me/devices/"+created.Device.ID+"/revoke", nil, http.StatusForbidden, "forbidden")
	alice.mustFail(http.MethodPost, "/api/v1/me/devices/"+created.Device.ID+"/rotate", nil, http.StatusForbidden, "forbidden")
	alice.mustFail(http.MethodDelete, "/api/v1/me/devices/"+created.Device.ID, nil, http.StatusForbidden, "forbidden")

	// Creating a device on behalf of someone else is rejected.
	alice.mustFail(http.MethodPost, "/api/v1/me/devices",
		map[string]string{"name": "stolen", "user_id": created.Device.UserID},
		http.StatusForbidden, "forbidden")
}

func TestNonAdminCannotEscalateOrReachAdminAPI(t *testing.T) {
	h := newHarness(t, nil)
	admin := h.client()
	admin.login(testAdminEmail, testAdminPassword)
	admin.mustStatus(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"email": "dave@example.org", "display_name": "dave", "role": store.RoleUser,
		"password": "User-Passw0rd!23",
	}, http.StatusCreated)

	dave := h.client()
	dave.login("dave@example.org", "User-Passw0rd!23")

	// The self-service endpoint does not even accept privileged fields.
	dave.mustFail(http.MethodPatch, "/api/v1/me",
		map[string]any{"role": store.RoleAdmin}, http.StatusBadRequest, "invalid")
	dave.mustFail(http.MethodPatch, "/api/v1/me",
		map[string]any{"quota_bytes": int64(1) << 40}, http.StatusBadRequest, "invalid")
	dave.mustFail(http.MethodPatch, "/api/v1/me",
		map[string]any{"display_name": "dave", "status": store.UserSuspended}, http.StatusBadRequest, "invalid")

	// Privileged endpoints are refused outright.
	dave.mustFail(http.MethodGet, "/api/v1/admin/stats", nil, http.StatusForbidden, "forbidden")
	dave.mustFail(http.MethodGet, "/api/v1/admin/audit", nil, http.StatusForbidden, "forbidden")
	dave.mustFail(http.MethodPost, "/api/v1/admin/users", map[string]any{
		"email": "evil@example.org", "role": store.RoleAdmin, "password": "User-Passw0rd!23",
	}, http.StatusForbidden, "forbidden")

	// The account is still a plain user.
	out := dave.mustStatus(http.MethodGet, "/api/v1/me", nil, http.StatusOK)
	me := decodeData[map[string]any](t, out)
	if me["role"] != string(store.RoleUser) {
		t.Fatalf("role = %v", me["role"])
	}
}

func TestProfileIsDeliveredOnceThenGone(t *testing.T) {
	h := newHarness(t, nil)
	c := h.client()
	c.login(testAdminEmail, testAdminPassword)

	out := c.mustStatus(http.MethodPost, "/api/v1/me/devices", map[string]string{"name": "laptop"}, http.StatusCreated)
	created := decodeData[struct {
		Device struct {
			ID string `json:"id"`
		} `json:"device"`
		Peer    *store.WireGuardPeer   `json:"peer"`
		Profile *service.DeviceProfile `json:"profile"`
	}](t, out)

	if created.Profile == nil || !strings.Contains(created.Profile.Conf, "PrivateKey") {
		t.Fatalf("profile must contain the private key once: %+v", created.Profile)
	}
	if created.Peer == nil || created.Peer.PublicKey == "" {
		t.Fatal("peer public key missing")
	}
	if created.Peer.PublicKey == created.Peer.ID {
		t.Fatal("peer id must not be the key")
	}

	// Second delivery attempt is refused.
	c.mustFail(http.MethodGet, "/api/v1/me/devices/"+created.Device.ID+"/profile", nil,
		http.StatusGone, "gone")

	// Rotation delivers exactly one fresh configuration.
	out = c.mustStatus(http.MethodPost, "/api/v1/me/devices/"+created.Device.ID+"/rotate", nil, http.StatusOK)
	rotated := decodeData[struct {
		Device struct {
			ID string `json:"id"`
		} `json:"device"`
		Peer    *store.WireGuardPeer   `json:"peer"`
		Profile *service.DeviceProfile `json:"profile"`
	}](t, out)
	if rotated.Profile == nil || !strings.Contains(rotated.Profile.Conf, "PrivateKey") {
		t.Fatal("rotation must return a new configuration")
	}
	if rotated.Peer.PublicKey == created.Peer.PublicKey {
		t.Fatal("rotation must change the public key")
	}
	c.mustFail(http.MethodGet, "/api/v1/me/devices/"+created.Device.ID+"/profile", nil,
		http.StatusGone, "gone")
}

func TestSecretsNeverAppearInListingsOrAudit(t *testing.T) {
	h := newHarness(t, nil)
	c := h.client()
	c.login(testAdminEmail, testAdminPassword)

	out := c.mustStatus(http.MethodPost, "/api/v1/me/devices", map[string]string{"name": "phone"}, http.StatusCreated)
	created := decodeData[struct {
		Device struct {
			ID string `json:"id"`
		} `json:"device"`
		Profile *service.DeviceProfile `json:"profile"`
	}](t, out)
	conf := created.Profile.Conf
	priv := ""
	for _, line := range strings.Split(conf, "\n") {
		if strings.HasPrefix(line, "PrivateKey") {
			priv = strings.TrimSpace(strings.TrimPrefix(line, "PrivateKey"))
			priv = strings.TrimPrefix(priv, "=")
			priv = strings.TrimSpace(priv)
		}
	}
	if priv == "" {
		t.Fatal("could not extract private key from delivered configuration")
	}

	list := c.mustStatus(http.MethodGet, "/api/v1/me/devices", nil, http.StatusOK)
	one := c.mustStatus(http.MethodGet, "/api/v1/me/devices/"+created.Device.ID, nil, http.StatusOK)
	for name, blob := range map[string]string{"list": string(list), "get": string(one)} {
		if strings.Contains(blob, priv) {
			t.Fatalf("private key leaked in device %s response", name)
		}
	}

	// The password must never be readable anywhere.
	if strings.Contains(string(list), testAdminPassword) {
		t.Fatal("password leaked in device list")
	}

	audit := c.mustStatus(http.MethodGet, "/api/v1/admin/audit?limit=200", nil, http.StatusOK)
	if strings.Contains(string(audit), priv) {
		t.Fatal("private key leaked in audit log")
	}
	if strings.Contains(string(audit), testAdminPassword) {
		t.Fatal("password leaked in audit log")
	}
	if !strings.Contains(string(audit), "device.create") {
		t.Fatalf("expected device.create audit event: %s", audit)
	}
}

func TestLoginIsRateLimited(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.LoginRateLimitPerMinute = 3 })
	c := h.client()

	for i := 0; i < 3; i++ {
		c.mustFail(http.MethodPost, "/api/v1/auth/login",
			map[string]string{"email": testAdminEmail, "password": "nope"},
			http.StatusUnauthorized, "unauthorized")
	}
	c.mustFail(http.MethodPost, "/api/v1/auth/login",
		map[string]string{"email": testAdminEmail, "password": testAdminPassword},
		http.StatusTooManyRequests, "rate_limited")
}

func TestSecurityHeadersAndAPICSP(t *testing.T) {
	h := newHarness(t, nil)

	resp, _ := h.client().do(http.MethodGet, "/api/v1/health", nil)
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff")
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("missing frame denial")
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("api responses must not be cached")
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("api csp too permissive: %q", csp)
	}
}

func TestUnknownAPIPathIsJSONNotFound(t *testing.T) {
	h := newHarness(t, nil)
	h.client().mustFail(http.MethodGet, "/api/v1/does-not-exist", nil,
		http.StatusNotFound, "not_found")
}

func TestFrontendIsSandboxedAndServesOpenAPI(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>aegis</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A secret living next to (not inside) the served directory.
	if err := os.WriteFile(filepath.Join(filepath.Dir(dir), "secret.txt"), []byte("TOP-SECRET-MARKER"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, func(c *config.Config) { c.FrontendDir = dir })
	c := h.client()

	resp, out := c.do(http.MethodGet, "/", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(out), "aegis") {
		t.Fatalf("index: %d %s", resp.StatusCode, out)
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("frontend csp unexpected: %q", csp)
	}

	resp, out = c.do(http.MethodGet, "/../secret.txt", nil)
	if strings.Contains(string(out), "TOP-SECRET-MARKER") {
		t.Fatalf("path traversal served a file outside the frontend directory (%d)", resp.StatusCode)
	}

	spec := c.mustStatus(http.MethodGet, "/api/v1/openapi.yaml", nil, http.StatusOK)
	if !strings.Contains(string(spec), "openapi:") {
		t.Fatal("openapi.yaml not served")
	}
}

func TestSessionCookieIsOpaqueHttpOnlyAndRejectedWhenForged(t *testing.T) {
	h := newHarness(t, nil)
	c := h.client()
	c.login(testAdminEmail, testAdminPassword)

	first := c.cookies[h.cfg.CookieName]
	if len(first) < 32 || strings.Contains(first, testAdminEmail) {
		t.Fatalf("session cookie must be an opaque random token, got %q", first)
	}

	// A forged or expired cookie is rejected without touching the account.
	forged := h.client()
	forged.cookies[h.cfg.CookieName] = "attacker-controlled-token"
	forged.mustStatus(http.MethodGet, "/api/v1/me", nil, http.StatusUnauthorized)

	// The session cookie must not be readable from JavaScript.
	found := false
	for _, ck := range c.loginResp.Cookies() {
		if ck.Name == h.cfg.CookieName {
			found = true
			if !ck.HttpOnly {
				t.Error("session cookie must be HttpOnly")
			}
		}
		if ck.Name == h.cfg.CSRFCookieName && ck.HttpOnly {
			t.Error("csrf cookie must stay readable by the SPA")
		}
	}
	if !found {
		t.Error("session cookie not returned")
	}

	// A second login issues a distinct token.
	c.login(testAdminEmail, testAdminPassword)
	if c.cookies[h.cfg.CookieName] == first {
		t.Error("a fresh login must rotate the session token")
	}
}
