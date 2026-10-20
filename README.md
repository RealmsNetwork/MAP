# Model Access Panel (MAP)

RealmsNetwork/MAP is a self-hosted Model Context Protocol (MCP) gateway for authorized Pterodactyl panel access. It is intended for the RealmsNetwork EU Debian VPS; panel credentials remain on that host.

## Initial read-only tools

- panel_url: return the configured panel URL for the user to open.
- list_servers: list servers visible to the configured Pterodactyl Client API key.
- server_resources: read current resource usage for a server identifier.

## Security defaults

- Streamable HTTP binds to 127.0.0.1 by default and refuses non-loopback bind addresses. Do not expose it directly to the public internet.
- Client API read-only calls only. No console commands, power actions, file mutation, arbitrary URL, or arbitrary HTTP method tools.
- API keys and Authorization headers are never returned by tools.
- Redirects are rejected so credentials cannot be silently forwarded to another host.
- PANEL_BASE_URL must be HTTPS, without embedded credentials, query strings, or fragments.
- curl_cffi TLS impersonation is for compatibility with authorized endpoints. It does not bypass authentication or guarantee access through Cloudflare Access/WAF challenges.
- Keep the production .env outside this checkout and never commit secrets.

## Local development

Requires Python 3.11 or newer.

    python3 -m venv .venv
    . .venv/bin/activate
    python -m pip install --upgrade pip
    python -m pip install -e '.[test]'
    cp .env.example .env
    # Edit .env with the authorized panel URL and a least-privilege Client API key.
    python -m map_server.server

The example panel URL is intentionally invalid. Configure the actual authorized panel endpoint before starting MAP.

## Production deployment plan

Use a dedicated unprivileged systemd service account and an environment file such as /etc/realmsnetwork-map/.env with restrictive permissions. Keep MAP bound to localhost until an authenticated remote MCP transport or private authenticated tunnel is configured. Never put credentials in GitHub Actions logs, commits, tool output, or issue reports.
