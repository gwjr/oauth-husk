# oauth-husk

A minimal OAuth 2.0 authorization server for protecting self-hosted [MCP](https://modelcontextprotocol.io/) servers. It implements just enough of the spec for Claude.ai (and other MCP clients) to authenticate, without the complexity of multi-user auth. One server, one operator, one set of credentials.

## Why

Claude.ai requires OAuth to connect to remote MCP servers. If you're self-hosting an MCP server behind Caddy, you need something to handle the OAuth dance. oauth-husk is that something: a single binary with no config file, no external dependencies, and a SQLite database that creates itself.

What it deliberately leaves out is any concept of multiple users — there's no login page, no user database, no consent screen. You register a client with a shared secret, and any MCP client with those credentials can get a token. This is appropriate if (but probably only if!) you're the only user and the MCP server is yours.

Security goal (practical): treat oauth-husk as roughly equivalent in risk to pre-shared bearer tokens/API keys, while providing the OAuth flow required by MCP clients.

## How it works

```
Claude.ai → Cloudflare → Caddy → oauth-husk (:8200)  — OAuth endpoints
                                → your MCP server      — after forward_auth
```

1. Claude.ai discovers the OAuth endpoints via `/.well-known/` metadata
2. It gets an authorization code from `/authorize` (with PKCE)
3. It exchanges the code for tokens at `/token`
4. On each MCP request, Caddy calls oauth-husk's `/auth/verify` endpoint
5. If the token is valid, Caddy proxies the request to your MCP server

oauth-husk never sees your MCP traffic. It just says yes or no.

## Quick start

```bash
go build

# Install as a launchd service (macOS)
./oauth-husk install

# Register a client
./oauth-husk client add claude-mcp
# → prints the client secret once — save it

# Point Caddy at it (see Caddyfile in this repo)
```

## Commands

```
oauth-husk serve               Start the server (foreground)
oauth-husk install              Install and start as a launchd service
oauth-husk uninstall            Stop and remove the launchd service
oauth-husk client add <id>      Register a client, print its secret
oauth-husk client list          List registered clients
oauth-husk client revoke <id>   Revoke all tokens for a client
```

`serve` and `install` accept `--port` (default 8200), `--db` (default `~/.config/oauth-husk/oauth.db`), `--allow-from` (comma-separated CIDRs/IPs; default loopback only, e.g. `--allow-from 127.0.0.0/8,::1/128,172.18.0.0/16` for Docker), and `--allow-insecure-http` for local testing without TLS. The database and signing key are created automatically on first run.

## Caddy setup

oauth-husk is designed to sit behind Caddy using `forward_auth`. An example Caddyfile is included — the key parts:

```
@oauth path /.well-known/oauth-protected-resource /.well-known/oauth-authorization-server /authorize /token
handle @oauth {
    reverse_proxy localhost:8200
}

@mcp path /mcp /sse /messages
handle @mcp {
    forward_auth localhost:8200 {
        uri /auth/verify
    }
    reverse_proxy localhost:8105
}
```

## Client setup

When you register a client, you can optionally lock its redirect URI:

```bash
./oauth-husk client add claude-mcp --redirect-uri https://claude.ai/api/mcp/auth_callback
```

If you omit `--redirect-uri`, the URI from the first successful authorization is captured and locked automatically. After that, only that exact URI is accepted.

## Design choices

- **No config file.** Flags for the two things that vary (port and DB path). The base URL is derived from Caddy's forwarded headers.
- **No CGO.** Uses `modernc.org/sqlite` for a pure-Go build. Single static binary.
- **Signing key in the database.** Auto-generated on first run, stored in a `settings` table. No secrets on the command line or in files.
- **Access tokens are signed and stateless.** `/auth/verify` validates signature + expiry only. Refresh tokens are stored hashed for rotation and revocation.
- **bcrypt for client secrets.** Cost 12. Timing-safe comparison even for unknown client IDs.

## Running tests

```bash
go test ./...
```
