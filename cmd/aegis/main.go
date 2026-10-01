// aegis is the unprivileged Aegis web panel. It never runs as root and never
// touches WireGuard directly: all privileged operations go through the agent
// socket.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aegis-vpn/aegis/internal/api"
	"github.com/aegis-vpn/aegis/internal/auth"
	"github.com/aegis-vpn/aegis/internal/config"
	"github.com/aegis-vpn/aegis/internal/service"
	"github.com/aegis-vpn/aegis/internal/store"
	"github.com/aegis-vpn/aegis/internal/wg"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "aegis: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := os.Getenv("AEGIS_CONFIG")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	level := slog.LevelInfo
	if cfg.Development {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	st, err := store.Open(cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer st.Close()

	wgClient, err := buildWGClient(cfg)
	if err != nil {
		return err
	}

	svc := service.New(st, wgClient, cfg, log)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := svc.Bootstrap(ctx); err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}

	kyros := auth.NewKyrosProvider(auth.KyrosConfig{
		Enabled:         cfg.KyrosEnabled,
		Issuer:          cfg.KyrosIssuer,
		ClientID:        cfg.KyrosClientID,
		ClientSecret:    cfg.KyrosClientSecret,
		RedirectURL:     cfg.KyrosRedirectURL,
		Scopes:          cfg.KyrosScopes,
		SkipIssuerCheck: cfg.KyrosInsecureSkipIssuerCheck,
		AutoProvision:   true,
		ButtonLabel:     cfg.KyrosButtonLabel,
		Timeout:         10 * time.Second,
	})

	sessions := auth.NewSessionManager(st, cfg.CookieName, cfg.CSRFCookieName, cfg.CookieSecure,
		cfg.SessionTTL, cfg.SessionIdleTTL, cfg.TrustProxy)

	apiSrv := api.New(api.Options{
		Service:      svc,
		Sessions:     sessions,
		Kyros:        kyros,
		Logger:       log,
		TrustProxy:   cfg.TrustProxy,
		FrontendDir:  cfg.FrontendDir,
		CookieSecure: cfg.CookieSecure,
		LoginLimit:   cfg.LoginRateLimitPerMinute,
		APIRateLimit: cfg.APIRateLimitPerMinute,
	})

	collector := service.NewCollector(svc, cfg.UsageInterval)
	collector.Start()
	defer collector.Stop()

	// Housekeeping: prune expired sessions and stale OAuth states.
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				now := time.Now().Unix()
				_, _ = st.PruneExpiredSessions(ctx, now)
				_ = st.PruneOAuthStates(ctx, now)
			}
		}
	}()

	// First collection pass shortly after boot so counters survive restarts.
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
			if err := svc.CollectOnce(ctx); err != nil {
				log.Warn("initial usage collection failed", "err", err)
			}
		}
	}()

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           apiSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
		ErrorLog:          nil,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("aegis listening",
			"addr", cfg.ListenAddr,
			"env", cfg.Environment,
			"database", cfg.DatabasePath,
			"version", service.Version)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelShutdown()
	return httpSrv.Shutdown(shutdownCtx)
}

// buildWGClient wires the privileged transport, or an in-memory fake when
// AEGIS_WG_BACKEND=fake (used by development and the test suite).
func buildWGClient(cfg *config.Config) (wg.Client, error) {
	backend := strings.TrimSpace(os.Getenv("AEGIS_WG_BACKEND"))
	if backend == "fake" {
		return wg.NewFake(), nil
	}
	return wg.NewAgentClient(cfg.AgentSocket, cfg.AgentToken, cfg.AgentTimeout)
}
