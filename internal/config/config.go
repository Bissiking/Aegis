// Package config loads Aegis configuration from environment variables and an
// optional key=value file. Secrets are never logged by this package.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the full runtime configuration for the Aegis web service and the
// privileged agent.
type Config struct {
	// Core
	DatabasePath   string
	DataDir        string
	ListenAddr     string
	PublicBaseURL  string
	SessionSecret  string
	SessionTTL     time.Duration
	SessionIdleTTL time.Duration
	TrustProxy     bool
	Environment    string // "production" | "development"
	FrontendDir    string
	CookieSecure   bool
	CookieName     string
	CSRFCookieName string

	// Local authentication
	LocalAuthEnabled        bool
	LocalBootstrapUser      string
	LocalBootstrapPassword  string
	ArgonTime               uint32
	ArgonMemoryKiB          uint32
	ArgonThreads            uint8
	ArgonKeyLen             uint32
	LoginRateLimitPerMinute int
	APIRateLimitPerMinute   int

	// Kyros (generic OIDC/OAuth2 adapter)
	KyrosEnabled                 bool
	KyrosIssuer                  string
	KyrosClientID                string
	KyrosClientSecret            string
	KyrosRedirectURL             string
	KyrosScopes                  []string
	KyrosButtonLabel             string
	KyrosInsecureSkipIssuerCheck bool

	// WireGuard
	WGInterface           string
	WGEgressIface         string
	WGPort                int
	WGNetwork             string
	WGDNS                 []string
	WGEndpoint            string
	WGMaxPeers            int
	WGProfileTTLHrs       int
	WGFullTunnel          bool
	WGPersistentKeepalive int
	WGIPv6Enabled         bool
	AgentSocket           string
	AgentToken            string
	AgentTimeout          time.Duration
	RateLimitEnabled      bool

	// Usage collector
	UsageInterval    time.Duration
	QuotaAutoSuspend bool

	// Misc
	MaxDevicesDefault int
	Development       bool
}

// Load reads configuration. Values already present in the process environment
// win over values coming from the optional config file.
func Load(path string) (*Config, error) {
	fileVars := map[string]string{}
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("open config: %w", err)
			}
		} else {
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				k, v, ok := strings.Cut(line, "=")
				if !ok {
					continue
				}
				k = strings.TrimSpace(k)
				v = strings.TrimSpace(v)
				v = strings.Trim(v, `"'`)
				fileVars[k] = v
			}
			if err := sc.Err(); err != nil {
				return nil, fmt.Errorf("read config: %w", err)
			}
		}
	}

	get := func(key, def string) string {
		if v, ok := os.LookupEnv(key); ok && v != "" {
			return v
		}
		if v, ok := fileVars[key]; ok && v != "" {
			return v
		}
		return def
	}
	getInt := func(key string, def int) int {
		v := get(key, "")
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return def
		}
		return n
	}
	getBool := func(key string, def bool) bool {
		v := get(key, "")
		if v == "" {
			return def
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			return def
		}
		return b
	}
	getDur := func(key string, def time.Duration) time.Duration {
		v := get(key, "")
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			return def
		}
		return d
	}
	getList := func(key string, def []string) []string {
		v := get(key, "")
		if v == "" {
			return def
		}
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	getSpaceList := func(key string, def []string) []string {
		v := get(key, "")
		if v == "" {
			return def
		}
		return strings.Fields(v)
	}

	env := get("AEGIS_ENV", "production")
	c := &Config{
		DatabasePath:   get("AEGIS_DATABASE_PATH", "/var/lib/aegis/aegis.db"),
		DataDir:        get("AEGIS_DATA_DIR", "/var/lib/aegis"),
		ListenAddr:     get("AEGIS_LISTEN", "127.0.0.1:8443"),
		PublicBaseURL:  strings.TrimRight(get("AEGIS_PUBLIC_URL", "https://vpn.example.com"), "/"),
		SessionSecret:  get("AEGIS_SESSION_SECRET", ""),
		SessionTTL:     getDur("AEGIS_SESSION_TTL", 12*time.Hour),
		SessionIdleTTL: getDur("AEGIS_SESSION_IDLE_TTL", 2*time.Hour),
		TrustProxy:     getBool("AEGIS_TRUST_PROXY", false),
		Environment:    env,
		FrontendDir:    get("AEGIS_FRONTEND_DIR", "./web/dist"),
		CookieName:     get("AEGIS_COOKIE_NAME", "aegis_session"),
		CSRFCookieName: get("AEGIS_CSRF_COOKIE", "aegis_csrf"),
		CookieSecure:   getBool("AEGIS_COOKIE_SECURE", true),

		LocalAuthEnabled:        getBool("AEGIS_LOCAL_AUTH_ENABLED", true),
		LocalBootstrapUser:      get("AEGIS_BOOTSTRAP_USER", ""),
		LocalBootstrapPassword:  get("AEGIS_BOOTSTRAP_PASSWORD", ""),
		ArgonTime:               uint32(getInt("AEGIS_ARGON_TIME", 3)),
		ArgonMemoryKiB:          uint32(getInt("AEGIS_ARGON_MEMORY", 65536)),
		ArgonThreads:            uint8(getInt("AEGIS_ARGON_THREADS", 2)),
		ArgonKeyLen:             uint32(getInt("AEGIS_ARGON_KEYLEN", 32)),
		LoginRateLimitPerMinute: getInt("AEGIS_LOGIN_RATE_LIMIT", 10),
		APIRateLimitPerMinute:   getInt("AEGIS_API_RATE_LIMIT", 300),

		KyrosEnabled:                 strings.EqualFold(get("AUTH_PROVIDER", ""), "kyros"),
		KyrosIssuer:                  get("KYROS_ISSUER", ""),
		KyrosClientID:                get("KYROS_CLIENT_ID", ""),
		KyrosClientSecret:            get("KYROS_CLIENT_SECRET", ""),
		KyrosRedirectURL:             get("KYROS_REDIRECT_URI", strings.TrimRight(get("AEGIS_PUBLIC_URL", "https://vpn.example.com"), "/")+"/api/v1/auth/kyros/callback"),
		KyrosScopes:                  getSpaceList("KYROS_REQUESTED_SCOPE", []string{"profile", "email"}),
		KyrosButtonLabel:             get("AEGIS_KYROS_BUTTON_LABEL", "Se connecter avec Kyros"),
		KyrosInsecureSkipIssuerCheck: getBool("AEGIS_KYROS_SKIP_ISSUER_CHECK", false),

		WGInterface:           get("AEGIS_WG_INTERFACE", "wg0"),
		WGEgressIface:         get("AEGIS_WG_EGRESS_IFACE", ""),
		WGPort:                getInt("AEGIS_WG_PORT", 51820),
		WGNetwork:             get("AEGIS_WG_NETWORK", "10.77.0.0/24"),
		WGDNS:                 getList("AEGIS_WG_DNS", []string{"1.1.1.1", "1.0.0.1"}),
		WGEndpoint:            get("AEGIS_WG_ENDPOINT", ""),
		WGMaxPeers:            getInt("AEGIS_WG_MAX_PEERS", 128),
		WGProfileTTLHrs:       getInt("AEGIS_WG_PROFILE_TTL_HOURS", 0),
		WGFullTunnel:          getBool("AEGIS_WG_FULL_TUNNEL", true),
		WGPersistentKeepalive: getInt("AEGIS_WG_KEEPALIVE", 25),
		WGIPv6Enabled:         getBool("AEGIS_WG_IPV6", false),
		AgentSocket:           get("AEGIS_AGENT_SOCKET", "/run/aegis/agent.sock"),
		AgentToken:            get("AEGIS_AGENT_TOKEN", ""),
		AgentTimeout:          getDur("AEGIS_AGENT_TIMEOUT", 10*time.Second),
		RateLimitEnabled:      getBool("AEGIS_RATE_LIMIT_ENABLED", false),

		UsageInterval:    getDur("AEGIS_USAGE_INTERVAL", time.Minute),
		QuotaAutoSuspend: getBool("AEGIS_QUOTA_AUTO_SUSPEND", true),

		MaxDevicesDefault: getInt("AEGIS_MAX_DEVICES_DEFAULT", 5),
		Development:       env == "development",
	}

	if c.SessionSecret == "" {
		if c.Development {
			c.SessionSecret = "dev-only-insecure-session-secret-change-me"
		} else {
			return nil, fmt.Errorf("AEGIS_SESSION_SECRET is required in production")
		}
	}
	if len(c.SessionSecret) < 32 && !c.Development {
		return nil, fmt.Errorf("AEGIS_SESSION_SECRET must be at least 32 characters")
	}
	if c.KyrosEnabled {
		if c.KyrosIssuer == "" {
			return nil, fmt.Errorf("KYROS_ISSUER is required when AUTH_PROVIDER=kyros")
		}
		if c.KyrosClientID == "" {
			return nil, fmt.Errorf("KYROS_CLIENT_ID is required when AUTH_PROVIDER=kyros")
		}
		if c.KyrosRedirectURL == "" {
			return nil, fmt.Errorf("KYROS_REDIRECT_URI or AEGIS_PUBLIC_URL is required when AUTH_PROVIDER=kyros")
		}
	}
	if err := validateNetwork(c.WGNetwork); err != nil {
		return nil, err
	}
	return c, nil
}

func validateNetwork(cidr string) error {
	if !strings.Contains(cidr, "/") {
		return fmt.Errorf("AEGIS_WG_NETWORK must be a CIDR, got %q", cidr)
	}
	return nil
}

// CookieSameSite returns the SameSite mode used for session cookies.
func (c *Config) IsProduction() bool { return !c.Development }
