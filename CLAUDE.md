# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Minimal OAuth 2.0 authorization server in Go that satisfies MCP (Model Context Protocol) authentication requirements. Sits behind Caddy and provides token-based auth for an upstream MCP server via `forward_auth`. Single-operator design — no multi-user auth, no consent screen. You register clients with shared secrets and any MCP client with valid credentials gets a token.

## Architecture

OAuth server handles authentication only. Caddy handles all routing and proxying:

```
Cloudflare → Caddy (:8443, TLS) → OAuth Server (:8200)  [OAuth endpoints]
                                 → MCP Server             [MCP endpoints, after forward_auth]
```

The OAuth server:
- Serves discovery endpoints (`/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`)
- Handles OAuth authorization code flow with PKCE (`/authorize`, `/token`)
- Provides `/auth/verify` endpoint for Caddy `forward_auth` (token validation)
- Derives its base URL from `X-Forwarded-Host`/`X-Forwarded-Proto` headers (set by Caddy)
- Uses SQLite (WAL mode) for clients, auth codes, tokens, and signing key
- Signs access tokens with HMAC-SHA256

## Build & Run

```bash
go build
./oauth-husk serve                          # defaults: 127.0.0.1:8200
./oauth-husk serve --port 9000 --db /path/to/db
./oauth-husk install                        # install as launchd service
./oauth-husk client add my-client           # generates and prints secret once
```

## Test

```bash
go test ./...                  # all tests
go test ./internal/oauth/      # single package
go test -run TestPKCE ./...    # single test by name
```

## Project Structure

```
main.go                         # CLI entry point (serve, install/uninstall, client add/list/revoke)
internal/
  database/{database,clients,codes,tokens}.go  # SQLite connection, migrations, CRUD
  oauth/{handlers,pkce,tokens}.go              # HTTP handlers, PKCE validation, token gen/verify
  server/server.go              # HTTP server setup, routing, CORS, cleanup
Caddyfile                       # Example Caddy config with forward_auth pattern
```

## Configuration

No config file. CLI flags only:
- `serve`: `--host` (default 127.0.0.1), `--port` (default 8200), `--db` (default `~/.config/oauth-husk/oauth.db`)
- `install`: `--port`, `--db`
- `serve` and `install`: `--allow-from` (comma-separated CIDRs/IPs; default loopback only)

The signing key is auto-generated and stored in the SQLite database on first run. Client commands prompt to install the launchd service if not already installed.

## Key Implementation Details

- **PKCE**: Enforce S256 only. Verify `base64url(sha256(code_verifier)) == stored code_challenge`.
- **Auth codes**: 32 bytes random, base64url-encoded, 120s TTL, single-use.
- **Client secrets**: Generated via `client add`, shown once. Stored as bcrypt hash (cost 12).
- **Redirect URI**: Optional on `client add`. Captured and locked on first successful auth. Exact match enforced after lock.
- **401 responses** must include: `WWW-Authenticate: Bearer resource_metadata="{base_url}/.well-known/oauth-protected-resource"`
- **Token format**: `base64url(payload).base64url(HMAC-SHA256(payload, key))` with jti, sub, iat, exp, scope claims.
- **SQLite**: WAL mode, file permissions 600.
- **Dependencies**: `modernc.org/sqlite` (no CGO), `golang.org/x/crypto/bcrypt`, stdlib only.
