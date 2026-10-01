package config

import (
	"reflect"
	"testing"
	"time"
)

func TestLoadKyrosV4StandardContract(t *testing.T) {
	t.Setenv("AEGIS_ENV", "development")
	t.Setenv("AEGIS_PUBLIC_URL", "https://aegis.example/")
	t.Setenv("AUTH_PROVIDER", "kyros")
	t.Setenv("KYROS_SSO_VERSION", "v4")
	t.Setenv("KYROS_BASE_URL", "https://kyros.example/")
	t.Setenv("KYROS_CLIENT_ID", "aegis-test")
	t.Setenv("KYROS_CLIENT_SECRET", "test-secret")
	t.Setenv("KYROS_ISSUER", "kyros")
	t.Setenv("KYROS_AUDIENCE", "kyros-modules")
	t.Setenv("KYROS_RESOURCE_AUDIENCE", "kyros:sso:aegis")
	t.Setenv("KYROS_REQUESTED_SCOPE", "profile email")
	t.Setenv("KYROS_REQUIRED_SCOPES", "profile")
	t.Setenv("KYROS_EDITION", "standard")
	t.Setenv("KYROS_APPLICATION_SCOPE", "standard")
	t.Setenv("KYROS_TIMEOUT_SECONDS", "7")
	t.Setenv("KYROS_AUTHORIZE_URL", "https://kyros.example/authorize")
	t.Setenv("KYROS_TOKEN_URL", "https://kyros.example/token")
	t.Setenv("KYROS_PAR_URL", "https://kyros.example/par")
	t.Setenv("KYROS_JWKS_URL", "https://kyros.example/sso/v4/jwks")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.KyrosEnabled || cfg.KyrosBaseURL != "https://kyros.example" || cfg.KyrosTimeout != 7*time.Second {
		t.Fatalf("unexpected Kyros enable/base URL/timeout values")
	}
	if cfg.KyrosRedirectURL != "https://aegis.example/api/v1/auth/kyros/callback" {
		t.Fatalf("redirect URL = %q", cfg.KyrosRedirectURL)
	}
	if !reflect.DeepEqual(cfg.KyrosRequestedScopes, []string{"profile", "email"}) ||
		!reflect.DeepEqual(cfg.KyrosRequiredScopes, []string{"profile"}) {
		t.Fatalf("unexpected scopes: requested=%v required=%v", cfg.KyrosRequestedScopes, cfg.KyrosRequiredScopes)
	}
}

func TestLoadRejectsNonV4Kyros(t *testing.T) {
	t.Setenv("AEGIS_ENV", "development")
	t.Setenv("AUTH_PROVIDER", "kyros")
	t.Setenv("KYROS_SSO_VERSION", "v3")
	t.Setenv("KYROS_BASE_URL", "https://kyros.example")
	t.Setenv("KYROS_CLIENT_ID", "aegis-test")
	t.Setenv("KYROS_ISSUER", "kyros")
	t.Setenv("KYROS_AUDIENCE", "kyros-modules")
	t.Setenv("KYROS_RESOURCE_AUDIENCE", "kyros:sso:aegis")
	t.Setenv("KYROS_EDITION", "standard")
	t.Setenv("KYROS_APPLICATION_SCOPE", "standard")
	if _, err := Load(""); err == nil || err.Error() != "KYROS_SSO_VERSION must be v4" {
		t.Fatalf("error = %v", err)
	}
}
