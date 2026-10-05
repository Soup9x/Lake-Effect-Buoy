// Package server wires the console server together.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/agentapi"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/auth"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/config"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/httpx"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/secret"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/store"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/web"
)

// Handler builds the full HTTP handler. Public routes: /agent/v1/*,
// /downloads/*, /healthz. Everything else (UI, /readyz) is restricted to
// AdminAllowedCIDRs here as well as in Caddy (design 0a.4).
func Handler(cfg *config.Config, pool *pgxpool.Pool, log *slog.Logger) http.Handler {
	hasher := secret.NewHasher(cfg.TokenHashKey, cfg.TokenHashKeyPrevious)
	am := auth.NewManager(pool, hasher, log, cfg.SessionIdleTimeout, cfg.SessionAbsoluteTimeout, cfg.CookieSecure)
	ui := web.New(pool, am, hasher, log, cfg.PublicURL, cfg.AgentOfflineAfter, cfg.DownloadsDir)

	public := http.NewServeMux()
	agentapi.New(pool, hasher, log).Register(public)
	public.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	public.Handle("GET /downloads/{file}", downloads(cfg.DownloadsDir))

	admin := http.NewServeMux()
	admin.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	admin.Handle("/", ui.Handler())

	root := http.NewServeMux()
	root.Handle("/agent/", public)
	root.Handle("/healthz", public)
	root.Handle("/downloads/", public)
	root.Handle("/", httpx.AllowCIDRs(cfg.AdminAllowedCIDRs, admin))
	return httpx.RealIP(cfg.TrustedProxies)(httpx.SecurityHeaders(root))
}

var downloadName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// downloads serves agent release files (binaries, .minisig, install
// scripts) from a flat directory. Integrity comes from the offline release
// signature, not from this server (design 0a.1).
func downloads(dir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("file")
		if !downloadName.MatchString(name) {
			http.NotFound(w, r)
			return
		}
		// name matched downloadName: no separators or "..", so p stays in dir.
		p := filepath.Join(dir, name)
		st, err := os.Stat(p) //nolint:gosec // validated above
		if err != nil || !st.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, p) //nolint:gosec // validated above
	})
}

// ActionRetention is how long agent action results are kept.
const ActionRetention = 90 * 24 * time.Hour

// RunBackground runs periodic maintenance until ctx is cancelled.
func RunBackground(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config, log *slog.Logger) {
	sweep := time.NewTicker(30 * time.Second)
	cleanup := time.NewTicker(time.Hour)
	defer sweep.Stop()
	defer cleanup.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sweep.C:
			if n, err := store.SweepOnlineState(ctx, pool, cfg.AgentOfflineAfter); err != nil && !errors.Is(err, context.Canceled) {
				log.Error("online sweep failed", "err", err)
			} else if n > 0 {
				log.Info("agent online state changed", "count", n)
			}
			if n, err := store.ExpireActions(ctx, pool); err != nil && !errors.Is(err, context.Canceled) {
				log.Error("action expiry failed", "err", err)
			} else if n > 0 {
				log.Info("agent actions expired", "count", n)
			}
		case <-cleanup.C:
			if err := store.DeleteStaleSessions(ctx, pool, 7*24*time.Hour); err != nil && !errors.Is(err, context.Canceled) {
				log.Error("session cleanup failed", "err", err)
			}
			if _, err := store.DeleteOldJobs(ctx, pool, ActionRetention); err != nil && !errors.Is(err, context.Canceled) {
				log.Error("action history cleanup failed", "err", err)
			}
		}
	}
}
