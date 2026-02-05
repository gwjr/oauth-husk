package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gwjr/oauth-husk/internal/database"
	"github.com/gwjr/oauth-husk/internal/oauth"
)

const (
	oauthRateLimitBurst  = 20
	oauthRateLimitPerMin = 60
)

func New(listenAddr string, db *database.DB, logger *slog.Logger, allowedCIDRs []string) (*http.Server, *RateLimiter, error) {
	signingKey, err := db.SigningKey()
	if err != nil {
		return nil, nil, err
	}

	tokenSvc, err := oauth.NewTokenService(signingKey)
	if err != nil {
		return nil, nil, err
	}

	h := &oauth.Handlers{
		DB:     db,
		Tokens: tokenSvc,
		Logger: logger,
	}

	mux := http.NewServeMux()

	// Discovery endpoints (GET + HEAD)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", h.ProtectedResourceMetadata)
	mux.HandleFunc("HEAD /.well-known/oauth-protected-resource", h.ProtectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", h.AuthorizationServerMetadata)
	mux.HandleFunc("HEAD /.well-known/oauth-authorization-server", h.AuthorizationServerMetadata)

	// OAuth endpoints
	mux.HandleFunc("GET /authorize", h.Authorize)
	mux.HandleFunc("POST /token", h.Token)

	// Forward auth endpoint for Caddy
	mux.HandleFunc("GET /auth/verify", h.VerifyToken)

	allowed, err := parseAllowedCIDRs(allowedCIDRs)
	if err != nil {
		return nil, nil, err
	}
	limiter := newRateLimiter(oauthRateLimitPerMin, oauthRateLimitBurst)

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isAllowedRemote(r.RemoteAddr, allowed) {
			logger.Warn("request blocked: remote not allowed", "remote", r.RemoteAddr, "path", r.URL.Path)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if isRateLimitedPath(r.URL.Path) && !limiter.Allow(remoteIP(r.RemoteAddr)) {
			logger.Warn("request rate-limited", "remote", r.RemoteAddr, "path", r.URL.Path)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		mux.ServeHTTP(w, r)
	})

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      protected,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return srv, limiter, nil
}

func isAllowedRemote(remoteAddr string, allowed []*net.IPNet) bool {
	ip := net.ParseIP(remoteIP(remoteAddr))
	if ip == nil {
		return false
	}
	for _, netw := range allowed {
		if netw.Contains(ip) {
			return true
		}
	}
	return false
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func parseAllowedCIDRs(cidrs []string) ([]*net.IPNet, error) {
	if len(cidrs) == 0 {
		cidrs = []string{"127.0.0.0/8", "::1/128"}
	}
	var allowed []*net.IPNet
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			if ip := net.ParseIP(raw); ip != nil {
				if ip.To4() != nil {
					raw = raw + "/32"
				} else {
					raw = raw + "/128"
				}
			}
		}
		_, netw, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, err
		}
		allowed = append(allowed, netw)
	}
	return allowed, nil
}

func isRateLimitedPath(path string) bool {
	return path == "/authorize" || path == "/token"
}

type RateLimiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	bucket map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(perMin, burst int) *RateLimiter {
	return &RateLimiter{
		rate:   float64(perMin) / 60.0,
		burst:  float64(burst),
		bucket: make(map[string]*bucket),
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	if key == "" {
		return false
	}
	now := time.Now()

	rl.mu.Lock()
	b, ok := rl.bucket[key]
	if !ok {
		rl.bucket[key] = &bucket{tokens: rl.burst - 1, last: now}
		rl.mu.Unlock()
		return true
	}

	elapsed := now.Sub(b.last).Seconds()
	b.tokens = min(rl.burst, b.tokens+elapsed*rl.rate)
	b.last = now

	if b.tokens < 1 {
		rl.mu.Unlock()
		return false
	}
	b.tokens -= 1
	rl.mu.Unlock()
	return true
}

// cleanup removes stale rate limiter entries that haven't been seen recently.
func (rl *RateLimiter) cleanup(maxAge time.Duration) {
	now := time.Now()
	rl.mu.Lock()
	for key, b := range rl.bucket {
		if now.Sub(b.last) > maxAge {
			delete(rl.bucket, key)
		}
	}
	rl.mu.Unlock()
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// StartCleanup runs periodic expired token/code cleanup and rate limiter pruning.
// Cancel the context to stop.
func StartCleanup(ctx context.Context, db *database.DB, limiter *RateLimiter, logger *slog.Logger) {
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				if err := db.CleanupExpired(); err != nil {
					logger.Error("cleanup: failed", "error", err)
				} else {
					logger.Debug("cleanup: completed")
				}
				if limiter != nil {
					limiter.cleanup(10 * time.Minute)
				}
			}
		}
	}()
}
