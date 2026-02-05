package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gwjr/oauth-husk/internal/database"
)

func newHandler(t *testing.T, allowed []string) http.Handler {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	svc, err := New("127.0.0.1:0", db, logger, allowed)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc.HTTP.Handler
}

func TestParseAllowedCIDRs(t *testing.T) {
	nets, err := parseAllowedCIDRs([]string{"127.0.0.1", "10.0.0.0/8", "  ::1/128  "})
	if err != nil {
		t.Fatalf("parseAllowedCIDRs: %v", err)
	}
	if len(nets) != 3 {
		t.Fatalf("expected 3 networks, got %d", len(nets))
	}

	if _, err := parseAllowedCIDRs([]string{"not-a-cidr"}); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestIsAllowedRemote(t *testing.T) {
	allowed, err := parseAllowedCIDRs([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatalf("parseAllowedCIDRs: %v", err)
	}

	if !isAllowedRemote("127.0.0.1:1234", allowed) {
		t.Fatal("expected loopback to be allowed")
	}
	if isAllowedRemote("10.0.0.1:1234", allowed) {
		t.Fatal("expected non-allowed IP to be rejected")
	}
}

func TestAllowlistBlocks(t *testing.T) {
	handler := newHandler(t, []string{"127.0.0.0/8"})

	req := httptest.NewRequest(http.MethodPost, "http://example.com/token", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestRateLimit(t *testing.T) {
	handler := newHandler(t, []string{"127.0.0.0/8"})

	allowedCodes := 0
	for i := 0; i < oauthRateLimitBurst; i++ {
		req := httptest.NewRequest(http.MethodPost, "http://example.com/token", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusTooManyRequests {
			allowedCodes++
		}
	}

	req := httptest.NewRequest(http.MethodPost, "http://example.com/token", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected rate limit to trigger, got %d (allowed %d)", rr.Code, allowedCodes)
	}
}

func TestStartCleanupStops(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	StartCleanup(ctx, db, nil, logger)
	cancel()

	time.Sleep(10 * time.Millisecond)
}
