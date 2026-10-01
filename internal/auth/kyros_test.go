package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func TestKyrosV4PARPKCEAndTokenValidation(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicJWK := jose.JSONWebKey{Key: &privateKey.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       jose.JSONWebKey{Key: privateKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	var baseURL string
	var par map[string]string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/kyros-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(t, w, map[string]any{
			"issuer": "kyros", "audience": "kyros-modules",
			"authorization_endpoint": baseURL + "/authorize", "token_endpoint": baseURL + "/token",
			"pushed_authorization_request_endpoint": baseURL + "/par", "jwks_uri": baseURL + "/jwks",
			"sso_version": "v3", "sso_versions_supported": []string{"v3", "v4"}, "sso_v4_enabled": true,
			"code_challenge_methods_supported":          []string{"S256"},
			"access_token_signing_alg_values_supported": map[string][]string{"v4": {"RS256"}},
		})
	})
	mux.HandleFunc("POST /par", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("PAR content type = %q", r.Header.Get("Content-Type"))
		}
		if err := json.NewDecoder(r.Body).Decode(&par); err != nil {
			t.Fatal(err)
		}
		writeTestJSON(t, w, map[string]string{"request_uri": "urn:kyros:test-request"})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(body["code_verifier"]))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != par["code_challenge"] {
			t.Error("token exchange did not reuse the PKCE verifier")
		}
		for key, want := range map[string]string{
			"grant_type": "authorization_code", "client_id": "aegis-test", "client_secret": "test-secret",
			"kyros_sso_version": "v4", "kyros_edition": "standard", "kyros_application_scope": "standard",
		} {
			if body[key] != want {
				t.Errorf("token %s = %q, want %q", key, body[key], want)
			}
		}
		now := time.Now().Unix()
		claims := map[string]any{
			"iss": "kyros", "aud": "kyros-modules", "resource_aud": "kyros:sso:aegis",
			"client_id": "aegis-test", "sub": "user-42", "exp": now + 300, "nbf": now - 1,
			"sso_version": "v4", "scope": "profile email", "email": "user@example.org", "display_name": "Test User",
		}
		payload, _ := json.Marshal(claims)
		signed, signErr := signer.Sign(payload)
		if signErr != nil {
			t.Fatal(signErr)
		}
		token, compactErr := signed.CompactSerialize()
		if compactErr != nil {
			t.Fatal(compactErr)
		}
		writeTestJSON(t, w, map[string]string{"access_token": token, "token_type": "Bearer"})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(t, w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicJWK}})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	baseURL = server.URL

	provider := NewKyrosProvider(testKyrosConfig(baseURL))
	pkce, authorizationURL, err := provider.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pkce.State == "" || pkce.Verifier == "" {
		t.Fatal("state and verifier must be generated")
	}
	for key, want := range map[string]string{
		"code_challenge_method": "S256", "kyros_sso_version": "v4",
		"kyros_edition": "standard", "kyros_application_scope": "standard", "client_secret": "test-secret",
	} {
		if par[key] != want {
			t.Errorf("PAR %s = %q, want %q", key, par[key], want)
		}
	}
	parsedURL, _ := url.Parse(authorizationURL)
	if parsedURL.Path != "/authorize" || parsedURL.Query().Get("request_uri") != "urn:kyros:test-request" {
		t.Fatalf("authorization URL = %s", authorizationURL)
	}
	if parsedURL.Query().Get("state") != "" || parsedURL.Query().Get("code_challenge") != "" {
		t.Fatal("pushed parameters must not be repeated in the browser URL")
	}
	if err := provider.ValidateCallbackIssuer("kyros"); err != nil {
		t.Fatal(err)
	}
	identity, err := provider.Complete(context.Background(), "test-code", pkce.Verifier)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != "user-42" || identity.Email != "user@example.org" || identity.Name != "Test User" {
		t.Fatalf("unexpected identity: %+v", identity)
	}
}

func TestKyrosV4RejectsEveryRequiredClaim(t *testing.T) {
	provider := NewKyrosProvider(testKyrosConfig("https://kyros.example"))
	now := time.Now()
	valid := kyrosClaims{
		Issuer: "kyros", Audience: stringList{"kyros-modules"}, ResourceAudience: stringList{"kyros:sso:aegis"},
		Subject: "user-42", ClientID: "aegis-test", Scope: stringList{"profile", "email"},
		ExpiresAt: now.Add(time.Minute).Unix(), NotBefore: now.Add(-time.Second).Unix(), SSOVersion: "v4",
	}
	tests := map[string]func(*kyrosClaims){
		"iss":          func(c *kyrosClaims) { c.Issuer = "other" },
		"aud":          func(c *kyrosClaims) { c.Audience = stringList{"other"} },
		"resource_aud": func(c *kyrosClaims) { c.ResourceAudience = stringList{"other"} },
		"client_id":    func(c *kyrosClaims) { c.ClientID = "other" },
		"sub":          func(c *kyrosClaims) { c.Subject = "" },
		"exp":          func(c *kyrosClaims) { c.ExpiresAt = now.Add(-time.Second).Unix() },
		"nbf":          func(c *kyrosClaims) { c.NotBefore = now.Add(time.Minute).Unix() },
		"sso_version":  func(c *kyrosClaims) { c.SSOVersion = "v3" },
		"scope":        func(c *kyrosClaims) { c.Scope = stringList{"profile"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			claims := valid
			mutate(&claims)
			if err := provider.validateClaims(claims, now); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("error = %v, want rejection mentioning %s", err, name)
			}
		})
	}
}

func TestKyrosRejectsNonRS256AndNeverExposesSecrets(t *testing.T) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("test-signing-secret-test-signing-secret")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign([]byte(`{"sub":"user-42"}`))
	if err != nil {
		t.Fatal(err)
	}
	token, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	provider := NewKyrosProvider(testKyrosConfig("https://kyros.example"))
	if _, err := provider.verifyAccessToken(context.Background(), "https://kyros.example/jwks", token); err == nil || !strings.Contains(err.Error(), "RS256") {
		t.Fatalf("error = %v, want RS256 rejection", err)
	}

	provider.cfg.Enabled = false
	encoded, err := json.Marshal(provider.Status(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), provider.cfg.ClientSecret) {
		t.Fatal("Kyros status exposed the client secret")
	}

	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeTestJSON(t, w, map[string]string{
			"error": "invalid_client", "error_description": "leaked test-signing-secret",
		})
	}))
	defer errorServer.Close()
	var out map[string]any
	err = provider.postJSON(context.Background(), errorServer.URL, map[string]string{"client_secret": provider.cfg.ClientSecret}, &out, "token")
	if err == nil || strings.Contains(err.Error(), "leaked") || strings.Contains(err.Error(), provider.cfg.ClientSecret) {
		t.Fatalf("unsafe or missing sanitized error: %v", err)
	}
}

func testKyrosConfig(baseURL string) KyrosConfig {
	return KyrosConfig{
		Enabled: true, SSOVersion: "v4", BaseURL: baseURL, ClientID: "aegis-test", ClientSecret: "test-secret",
		Issuer: "kyros", Audience: "kyros-modules", ResourceAudience: "kyros:sso:aegis",
		RedirectURL:     "https://aegis.example/api/v1/auth/kyros/callback",
		RequestedScopes: []string{"profile", "email"}, RequiredScopes: []string{"profile", "email"},
		Edition: "standard", ApplicationScope: "standard", Timeout: 2 * time.Second,
	}
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatal(err)
	}
}
