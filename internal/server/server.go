package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gwjr/oauth-husk/internal/database"
	"github.com/gwjr/oauth-husk/internal/oauth"
)

func New(listenAddr string, db *database.DB, logger *slog.Logger) (*http.Server, error) {
	signingKey, err := db.SigningKey()
	if err != nil {
		return nil, err
	}

	tokenSvc, err := oauth.NewTokenService(signingKey)
	if err != nil {
		return nil, err
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

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return srv, nil
}

// StartCleanup runs periodic expired token/code cleanup. Cancel the context to stop.
func StartCleanup(ctx context.Context, db *database.DB, logger *slog.Logger) {
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
			}
		}
	}()
}
