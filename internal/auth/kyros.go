package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

var (
	ErrKyrosDisabled    = errors.New("kyros authentication is disabled")
	ErrKyrosUnavailable = errors.New("kyros is temporarily unavailable")
)

// KyrosConfig is the native Kyros SSO v4 client configuration. Endpoint
// overrides use the shared KYROS_* contract; otherwise discovery supplies them.
type KyrosConfig struct {
	Enabled                                     bool
	SSOVersion, BaseURL, ClientID, ClientSecret string
	Issuer, Audience, ResourceAudience          string
	RedirectURL, Edition, ApplicationScope      string
	AuthorizeURL, TokenURL, PARURL, JWKSURL     string
	RequestedScopes, RequiredScopes             []string
	Timeout                                     time.Duration
}

// KyrosIdentity contains only identity data from a verified access token.
type KyrosIdentity struct{ Subject, Email, Name string }

type kyrosDiscovery struct {
	Issuer                 string              `json:"issuer"`
	Audience               string              `json:"audience"`
	AuthorizationEndpoint  string              `json:"authorization_endpoint"`
	TokenEndpoint          string              `json:"token_endpoint"`
	PAREndpoint            string              `json:"pushed_authorization_request_endpoint"`
	JWKSURI                string              `json:"jwks_uri"`
	SSOVersion             string              `json:"sso_version"`
	SSOVersionsSupported   []string            `json:"sso_versions_supported"`
	SSOV4Enabled           bool                `json:"sso_v4_enabled"`
	CodeChallengeMethods   []string            `json:"code_challenge_methods_supported"`
	AccessTokenSigningAlgs map[string][]string `json:"access_token_signing_alg_values_supported"`
}

type kyrosEndpoints struct{ Authorize, Token, PAR, JWKS string }

// KyrosProvider implements discovery, PAR, Authorization Code + PKCE S256,
// and RS256 access-token validation through JWKS.
type KyrosProvider struct {
	cfg    KyrosConfig
	client *http.Client
	mu     sync.Mutex

	endpoints *kyrosEndpoints
	jwks      *jose.JSONWebKeySet
	jwksAt    time.Time
}

// NewKyrosProvider is lazy so a Kyros outage never disables local login.
func NewKyrosProvider(cfg KyrosConfig) *KyrosProvider {
	if cfg.SSOVersion == "" {
		cfg.SSOVersion = "v4"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &KyrosProvider{cfg: cfg, client: &http.Client{
		Timeout: cfg.Timeout,
		// Never forward PAR/token POST bodies (which can contain the client
		// secret) through an HTTP redirect.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

func (k *KyrosProvider) Enabled() bool { return k.cfg.Enabled }
func (k *KyrosProvider) discoveryURL() string {
	return strings.TrimRight(k.cfg.BaseURL, "/") + "/.well-known/kyros-configuration"
}

func (k *KyrosProvider) ensure(ctx context.Context) (*kyrosEndpoints, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.endpoints != nil {
		return k.endpoints, nil
	}
	if !k.cfg.Enabled {
		return nil, ErrKyrosDisabled
	}
	if err := k.validateConfig(); err != nil {
		return nil, err
	}
	var doc kyrosDiscovery
	if err := k.getJSON(ctx, k.discoveryURL(), &doc); err != nil {
		return nil, fmt.Errorf("kyros discovery unavailable: %w", err)
	}
	if err := k.validateDiscovery(doc); err != nil {
		return nil, err
	}
	ep := &kyrosEndpoints{
		Authorize: firstNonEmpty(k.cfg.AuthorizeURL, doc.AuthorizationEndpoint),
		Token:     firstNonEmpty(k.cfg.TokenURL, doc.TokenEndpoint),
		PAR:       firstNonEmpty(k.cfg.PARURL, doc.PAREndpoint),
		JWKS:      firstNonEmpty(k.cfg.JWKSURL, doc.JWKSURI),
	}
	for name, endpoint := range map[string]string{"authorization": ep.Authorize, "token": ep.Token, "PAR": ep.PAR, "JWKS": ep.JWKS} {
		if err := validHTTPURL(endpoint); err != nil {
			return nil, fmt.Errorf("kyros discovery has invalid %s endpoint: %w", name, err)
		}
	}
	k.endpoints = ep
	return ep, nil
}

func (k *KyrosProvider) validateConfig() error {
	missing := make([]string, 0)
	for name, value := range map[string]string{
		"KYROS_BASE_URL": k.cfg.BaseURL, "KYROS_CLIENT_ID": k.cfg.ClientID,
		"KYROS_ISSUER": k.cfg.Issuer, "KYROS_AUDIENCE": k.cfg.Audience,
		"KYROS_RESOURCE_AUDIENCE": k.cfg.ResourceAudience, "KYROS_EDITION": k.cfg.Edition,
		"KYROS_APPLICATION_SCOPE": k.cfg.ApplicationScope, "redirect URL": k.cfg.RedirectURL,
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("kyros configuration is incomplete: missing %s", strings.Join(missing, ", "))
	}
	if k.cfg.SSOVersion != "v4" {
		return fmt.Errorf("unsupported KYROS_SSO_VERSION %q: Aegis requires v4", k.cfg.SSOVersion)
	}
	if len(k.cfg.RequestedScopes) == 0 || len(k.cfg.RequiredScopes) == 0 {
		return errors.New("kyros requested and required scopes must not be empty")
	}
	if err := validHTTPURL(k.cfg.BaseURL); err != nil {
		return fmt.Errorf("invalid KYROS_BASE_URL: %w", err)
	}
	return nil
}

func (k *KyrosProvider) validateDiscovery(doc kyrosDiscovery) error {
	if doc.Issuer != k.cfg.Issuer {
		return fmt.Errorf("kyros discovery issuer mismatch: expected %q", k.cfg.Issuer)
	}
	if doc.Audience != "" && doc.Audience != k.cfg.Audience {
		return fmt.Errorf("kyros discovery audience mismatch: expected %q", k.cfg.Audience)
	}
	if !contains(doc.SSOVersionsSupported, "v4") && doc.SSOVersion != "v4" {
		return errors.New("kyros discovery does not advertise SSO v4")
	}
	if !doc.SSOV4Enabled {
		return errors.New("kyros discovery reports SSO v4 as disabled")
	}
	if !contains(doc.CodeChallengeMethods, "S256") {
		return errors.New("kyros discovery does not support PKCE S256")
	}
	if !contains(doc.AccessTokenSigningAlgs["v4"], "RS256") {
		return errors.New("kyros discovery does not support RS256 access tokens for v4")
	}
	if doc.PAREndpoint == "" && k.cfg.PARURL == "" {
		return errors.New("kyros discovery has no PAR endpoint for v4")
	}
	if doc.JWKSURI == "" && k.cfg.JWKSURL == "" {
		return errors.New("kyros discovery has no JWKS endpoint for v4")
	}
	return nil
}

// Status exposes no client secret and no token. Failed discovery is not cached.
func (k *KyrosProvider) Status(ctx context.Context) map[string]any {
	st := map[string]any{
		"enabled": k.cfg.Enabled, "ready": false, "sso_version": k.cfg.SSOVersion,
		"issuer": k.cfg.Issuer, "client_id": k.cfg.ClientID, "audience": k.cfg.Audience,
		"resource_audience": k.cfg.ResourceAudience, "redirect_url": k.cfg.RedirectURL,
		"requested_scopes": k.cfg.RequestedScopes, "required_scopes": k.cfg.RequiredScopes,
		"edition": k.cfg.Edition, "application_scope": k.cfg.ApplicationScope,
	}
	if !k.cfg.Enabled {
		st["detail"] = "Kyros login disabled by configuration"
		return st
	}
	ep, err := k.ensure(ctx)
	if err != nil {
		st["detail"] = err.Error()
		return st
	}
	st["ready"] = true
	st["authorization_endpoint"], st["token_endpoint"] = ep.Authorize, ep.Token
	st["par_endpoint"], st["jwks_endpoint"] = ep.PAR, ep.JWKS
	st["discovery"] = k.discoveryURL()
	return st
}

type PKCE struct{ State, Verifier string }

func randomURLToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Begin creates a PAR and returns a browser redirect containing only the
// client identifier and opaque request_uri.
func (k *KyrosProvider) Begin(ctx context.Context) (*PKCE, string, error) {
	ep, err := k.ensure(ctx)
	if err != nil {
		return nil, "", err
	}
	state, err := randomURLToken(32)
	if err != nil {
		return nil, "", errors.New("could not generate kyros state")
	}
	verifier, err := randomURLToken(48)
	if err != nil {
		return nil, "", errors.New("could not generate PKCE verifier")
	}
	sum := sha256.Sum256([]byte(verifier))
	req := map[string]string{
		"client_id": k.cfg.ClientID, "redirect_uri": k.cfg.RedirectURL,
		"scope": strings.Join(k.cfg.RequestedScopes, " "), "state": state,
		"code_challenge":        base64.RawURLEncoding.EncodeToString(sum[:]),
		"code_challenge_method": "S256", "kyros_sso_version": k.cfg.SSOVersion,
		"kyros_edition": k.cfg.Edition, "kyros_application_scope": k.cfg.ApplicationScope,
	}
	if k.cfg.ClientSecret != "" {
		req["client_secret"] = k.cfg.ClientSecret
	}
	var response struct {
		RequestURI string `json:"request_uri"`
	}
	if err := k.postJSON(ctx, ep.PAR, req, &response, "PAR"); err != nil {
		return nil, "", err
	}
	if response.RequestURI == "" {
		return nil, "", errors.New("kyros PAR response contains no request_uri")
	}
	u, _ := url.Parse(ep.Authorize)
	q := u.Query()
	q.Set("client_id", k.cfg.ClientID)
	q.Set("request_uri", response.RequestURI)
	u.RawQuery = q.Encode()
	return &PKCE{State: state, Verifier: verifier}, u.String(), nil
}

func HashState(state string) string {
	sum := sha256.Sum256([]byte(state))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ValidateCallbackIssuer prevents authorization-response mix-up attacks.
func (k *KyrosProvider) ValidateCallbackIssuer(issuer string) error {
	if issuer == "" {
		return errors.New("kyros callback is missing issuer")
	}
	if issuer != k.cfg.Issuer {
		return errors.New("kyros callback issuer mismatch")
	}
	return nil
}

// Complete exchanges the code and validates the returned access token.
func (k *KyrosProvider) Complete(ctx context.Context, code, verifier string) (*KyrosIdentity, error) {
	ep, err := k.ensure(ctx)
	if err != nil {
		return nil, err
	}
	req := map[string]string{
		"grant_type": "authorization_code", "client_id": k.cfg.ClientID,
		"code": code, "code_verifier": verifier, "redirect_uri": k.cfg.RedirectURL,
		"kyros_sso_version": k.cfg.SSOVersion, "kyros_edition": k.cfg.Edition,
		"kyros_application_scope": k.cfg.ApplicationScope,
	}
	if k.cfg.ClientSecret != "" {
		req["client_secret"] = k.cfg.ClientSecret
	}
	var response struct {
		AccessToken string `json:"access_token"`
	}
	if err := k.postJSON(ctx, ep.Token, req, &response, "token"); err != nil {
		return nil, err
	}
	if response.AccessToken == "" {
		return nil, errors.New("kyros token response contains no access_token")
	}
	return k.verifyAccessToken(ctx, ep.JWKS, response.AccessToken)
}

type stringList []string

func (s *stringList) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*s = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return errors.New("claim must be a string or string array")
	}
	*s = many
	return nil
}

type kyrosClaims struct {
	Issuer           string     `json:"iss"`
	Audience         stringList `json:"aud"`
	ResourceAudience stringList `json:"resource_aud"`
	Subject          string     `json:"sub"`
	ClientID         string     `json:"client_id"`
	Scope            stringList `json:"-"`
	ExpiresAt        int64      `json:"exp"`
	NotBefore        int64      `json:"nbf"`
	SSOVersion       string     `json:"sso_version"`
	Email            string     `json:"email"`
	Name             string     `json:"name"`
	DisplayName      string     `json:"display_name"`
	Username         string     `json:"username"`
}

func (c *kyrosClaims) UnmarshalJSON(data []byte) error {
	type alias kyrosClaims
	var raw struct {
		*alias
		Scope json.RawMessage `json:"scope"`
	}
	raw.alias = (*alias)(c)
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if len(raw.Scope) > 0 {
		var text string
		if err := json.Unmarshal(raw.Scope, &text); err == nil {
			c.Scope = strings.Fields(text)
		} else if err := json.Unmarshal(raw.Scope, &c.Scope); err != nil {
			return errors.New("scope claim must be a string or string array")
		}
	}
	return nil
}

func (k *KyrosProvider) verifyAccessToken(ctx context.Context, jwksURL, token string) (*KyrosIdentity, error) {
	parsed, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(parsed.Signatures) != 1 {
		return nil, errors.New("kyros access token is not a valid RS256 JWT")
	}
	header := parsed.Signatures[0].Header
	if header.Algorithm != string(jose.RS256) || header.KeyID == "" {
		return nil, errors.New("kyros access token must use RS256 and contain a kid")
	}
	keys, err := k.keysFor(ctx, jwksURL, header.KeyID, false)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		keys, err = k.keysFor(ctx, jwksURL, header.KeyID, true)
		if err != nil {
			return nil, err
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("kyros JWKS has no key matching the access token kid")
	}
	var payload []byte
	for _, key := range keys {
		if key.Algorithm != "" && key.Algorithm != string(jose.RS256) {
			continue
		}
		payload, err = parsed.Verify(key.Key)
		if err == nil {
			break
		}
	}
	if err != nil || payload == nil {
		return nil, errors.New("kyros access token signature is invalid")
	}
	var claims kyrosClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.New("kyros access token claims are malformed")
	}
	if err := k.validateClaims(claims, time.Now()); err != nil {
		return nil, err
	}
	return &KyrosIdentity{Subject: claims.Subject, Email: claims.Email, Name: firstNonEmpty(claims.Name, claims.DisplayName, claims.Username)}, nil
}

func (k *KyrosProvider) validateClaims(c kyrosClaims, now time.Time) error {
	checks := []struct {
		ok      bool
		message string
	}{
		{c.Issuer == k.cfg.Issuer, "issuer does not match KYROS_ISSUER"},
		{contains(c.Audience, k.cfg.Audience), "audience does not contain KYROS_AUDIENCE"},
		{contains(c.ResourceAudience, k.cfg.ResourceAudience), "resource_aud does not contain KYROS_RESOURCE_AUDIENCE"},
		{c.ClientID == k.cfg.ClientID, "client_id does not match KYROS_CLIENT_ID"},
		{c.Subject != "", "sub is missing"},
		{c.ExpiresAt > 0 && now.Unix() < c.ExpiresAt, "exp is missing or expired"},
		{c.NotBefore > 0 && now.Unix() >= c.NotBefore, "nbf is missing or in the future"},
		{c.SSOVersion == "v4", "sso_version is not v4"},
	}
	for _, check := range checks {
		if !check.ok {
			return errors.New("kyros access token rejected: " + check.message)
		}
	}
	for _, required := range k.cfg.RequiredScopes {
		if !contains(c.Scope, required) {
			return fmt.Errorf("kyros access token rejected: required scope %q is missing", required)
		}
	}
	return nil
}

func (k *KyrosProvider) keysFor(ctx context.Context, jwksURL, kid string, force bool) ([]jose.JSONWebKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if force || k.jwks == nil || time.Since(k.jwksAt) >= 5*time.Minute {
		var set jose.JSONWebKeySet
		if err := k.getJSON(ctx, jwksURL, &set); err != nil {
			return nil, fmt.Errorf("kyros JWKS unavailable: %w", err)
		}
		k.jwks, k.jwksAt = &set, time.Now()
	}
	return k.jwks.Key(kid), nil
}

func (k *KyrosProvider) getJSON(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return errors.New("invalid endpoint URL")
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: network request failed", ErrKyrosUnavailable)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return fmt.Errorf("%w: endpoint returned HTTP %d", ErrKyrosUnavailable, resp.StatusCode)
		}
		return fmt.Errorf("endpoint returned HTTP %d", resp.StatusCode)
	}
	return decodeLimitedJSON(resp.Body, out)
}

func (k *KyrosProvider) postJSON(ctx context.Context, endpoint string, in, out any, operation string) error {
	body, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("kyros %s request could not be encoded", operation)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("kyros %s endpoint is invalid", operation)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: kyros %s endpoint request failed", ErrKyrosUnavailable, operation)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var remote struct {
			Code string `json:"error"`
		}
		_ = decodeLimitedJSON(resp.Body, &remote)
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return fmt.Errorf("%w: kyros %s endpoint returned HTTP %d", ErrKyrosUnavailable, operation, resp.StatusCode)
		}
		if code := safeErrorCode(remote.Code); code != "" {
			return fmt.Errorf("kyros %s request rejected (%s, HTTP %d)", operation, code, resp.StatusCode)
		}
		return fmt.Errorf("kyros %s request rejected (HTTP %d)", operation, resp.StatusCode)
	}
	if err := decodeLimitedJSON(resp.Body, out); err != nil {
		return fmt.Errorf("kyros %s response is invalid", operation)
	}
	return nil
}

func decodeLimitedJSON(r io.Reader, out any) error {
	return json.NewDecoder(io.LimitReader(r, 1<<20)).Decode(out)
}

var errorCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func safeErrorCode(v string) string {
	if errorCodePattern.MatchString(v) {
		return v
	}
	return ""
}

func validHTTPURL(v string) error {
	u, err := url.Parse(v)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("must be an absolute HTTP(S) URL")
	}
	if u.User != nil {
		return errors.New("must not contain URL credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must not contain a query string or fragment")
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func contains[S ~[]string](values S, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
