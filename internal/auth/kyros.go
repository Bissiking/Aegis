package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ErrKyrosDisabled is returned when the Kyros adapter is switched off.
var ErrKyrosDisabled = errors.New("kyros authentication is disabled")

// KyrosConfig holds the *unknown-but-required* Kyros integration parameters.
// Every value comes from deployment configuration; nothing is hard-coded, and
// no endpoint, scope or claim is invented by Aegis. See docs/kyros-integration.md.
type KyrosConfig struct {
	Enabled         bool
	Issuer          string
	ClientID        string
	ClientSecret    string
	RedirectURL     string
	Scopes          []string
	SkipIssuerCheck bool
	AutoProvision   bool // create an Aegis user on first successful login
	ButtonLabel     string
	Timeout         time.Duration
}

// KyrosIdentity is the outcome of a successful OIDC exchange.
type KyrosIdentity struct {
	Subject string // stable Kyros identifier, never the email address
	Email   string
	Name    string
	Raw     map[string]any
}

// KyrosProvider is a generic OAuth2 Authorization Code + PKCE / OIDC adapter.
// It is deliberately lazy: initialising it performs network discovery, so it
// happens on first use and a Kyros outage never blocks the rest of Aegis.
type KyrosProvider struct {
	cfg  KyrosConfig
	mu   sync.Mutex
	prov *oidc.Provider
	vf   *oidc.IDTokenVerifier
	oac  *oauth2.Config
	init bool
	err  error
}

// NewKyrosProvider creates an adapter. It does not perform any network call.
func NewKyrosProvider(cfg KyrosConfig) *KyrosProvider {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid"}
	}
	if cfg.ButtonLabel == "" {
		cfg.ButtonLabel = "Se connecter avec Kyros"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &KyrosProvider{cfg: cfg}
}

// Enabled reports whether the adapter is configured.
func (k *KyrosProvider) Enabled() bool { return k.cfg.Enabled }

// Config exposes the (non-secret) configuration for the status endpoint.
func (k *KyrosProvider) Config() KyrosConfig { return k.cfg }

func (k *KyrosProvider) ensure(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.init {
		return k.err
	}
	k.init = true
	if !k.cfg.Enabled {
		k.err = ErrKyrosDisabled
		return k.err
	}
	if k.cfg.Issuer == "" || k.cfg.ClientID == "" || k.cfg.RedirectURL == "" {
		k.err = errors.New("kyros adapter is missing issuer, client id or redirect url")
		return k.err
	}
	ctx, cancel := context.WithTimeout(ctx, k.cfg.Timeout)
	defer cancel()

	if k.cfg.SkipIssuerCheck {
		// Only usable in development; documented in docs/kyros-integration.md.
		ctx = oidc.InsecureIssuerURLContext(ctx, k.cfg.Issuer)
	}
	prov, err := oidc.NewProvider(ctx, k.cfg.Issuer)
	if err != nil {
		k.err = fmt.Errorf("oidc discovery failed: %w", err)
		return k.err
	}
	k.prov = prov
	k.vf = prov.Verifier(&oidc.Config{
		ClientID:          k.cfg.ClientID,
		SkipIssuerCheck:   k.cfg.SkipIssuerCheck,
		SkipClientIDCheck: false,
		SkipExpiryCheck:   false,
	})
	k.oac = &oauth2.Config{
		ClientID:     k.cfg.ClientID,
		ClientSecret: k.cfg.ClientSecret,
		Endpoint:     prov.Endpoint(),
		RedirectURL:  k.cfg.RedirectURL,
		Scopes:       k.cfg.Scopes,
	}
	return nil
}

// Status describes the adapter for the admin UI. It never returns secrets.
func (k *KyrosProvider) Status(ctx context.Context) map[string]any {
	st := map[string]any{
		"enabled":      k.cfg.Enabled,
		"issuer":       k.cfg.Issuer,
		"client_id":    k.cfg.ClientID,
		"redirect_url": k.cfg.RedirectURL,
		"scopes":       k.cfg.Scopes,
		"ready":        false,
	}
	if !k.cfg.Enabled {
		st["detail"] = "Kyros login disabled by configuration"
		return st
	}
	if err := k.ensure(ctx); err != nil {
		st["detail"] = err.Error()
		return st
	}
	st["ready"] = true
	st["authorization_endpoint"] = k.oac.Endpoint.AuthURL
	st["token_endpoint"] = k.oac.Endpoint.TokenURL
	st["discovery"] = k.cfg.Issuer + "/.well-known/openid-configuration"
	return st
}

// PKCE stores the code verifier between the two legs of the flow.
type PKCE struct {
	State    string
	Verifier string
	Nonce    string
}

// randomURLToken returns a base64url random token.
func randomURLToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Begin starts the authorization flow and returns the state/verifier/nonce
// triple that the caller must persist server-side (single use).
func (k *KyrosProvider) Begin(ctx context.Context) (*PKCE, string, error) {
	if err := k.ensure(ctx); err != nil {
		return nil, "", err
	}
	state, err := randomURLToken(32)
	if err != nil {
		return nil, "", err
	}
	nonce, err := randomURLToken(32)
	if err != nil {
		return nil, "", err
	}
	verifier, err := randomURLToken(48)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	authURL := k.oac.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("nonce", nonce),
	)
	return &PKCE{State: state, Verifier: verifier, Nonce: nonce}, authURL, nil
}

// HashState returns the storage key for a state value.
func HashState(state string) string {
	sum := sha256.Sum256([]byte(state))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Complete exchanges the callback code for tokens and validates the ID token
// (signature, issuer, audience, expiry, nonce).
func (k *KyrosProvider) Complete(ctx context.Context, code, verifier, nonce string) (*KyrosIdentity, error) {
	if err := k.ensure(ctx); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, k.cfg.Timeout)
	defer cancel()

	tok, err := k.oac.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return nil, errors.New("token response contains no id_token")
	}
	idTok, err := k.vf.Verify(ctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("id_token verification failed: %w", err)
	}
	var claims map[string]any
	if err := idTok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("id_token claims: %w", err)
	}
	if idTok.Nonce != nonce {
		return nil, errors.New("nonce mismatch")
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, errors.New("id_token has no stable subject claim")
	}
	id := &KyrosIdentity{Subject: sub, Raw: claims}
	if e, ok := claims["email"].(string); ok {
		id.Email = e
	}
	if n, ok := claims["name"].(string); ok {
		id.Name = n
	}
	return id, nil
}

// LogoutURL builds an end-session redirect when the provider publishes one.
// It returns "" when the provider does not support it (nothing is invented).
func (k *KyrosProvider) LogoutURL(ctx context.Context, idToken string) string {
	if err := k.ensure(ctx); err != nil {
		return ""
	}
	meta, err := k.discoveryDoc(ctx)
	if err != nil {
		return ""
	}
	end, _ := meta["end_session_endpoint"].(string)
	if end == "" {
		return ""
	}
	v := url.Values{}
	v.Set("post_logout_redirect_uri", k.cfg.RedirectURL)
	if idToken != "" {
		v.Set("id_token_hint", idToken)
	}
	return end + "?" + v.Encode()
}

func (k *KyrosProvider) discoveryDoc(ctx context.Context) (map[string]any, error) {
	// go-oidc does not expose the raw document; re-fetch the well-known URL.
	u := k.cfg.Issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	return doc, nil
}
