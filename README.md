# Model Access Panel (MAP)

**RealmsNetwork/MAP** is a self-hosted Model Context Protocol (MCP) gateway for authorized Pterodactyl administration. Deploy it on the RealmsNetwork EU Debian VPS. API credentials stay in the server-side environment.

## Scope

MAP exposes a generic `panel_api_request` tool for the Client, Application, and Admin API namespaces. It supports GET, POST, PUT, PATCH, and DELETE against a configured panel, with JSON or raw-text bodies. This exposes the available API surface without requiring a new MCP tool for every endpoint.

Dedicated tools cover panel discovery/status, server listing and resource usage, power actions, console commands, text file read/write, binary file upload/download (base64), directory creation, file deletion/renaming, and backups. For other operations, use `panel_api_request` and the API documentation for the installed Pterodactyl version.

This lets authorized callers access API features such as schedules, databases, allocations, startup variables, subusers, backup operations, server configuration, and panel-wide administration when those endpoints and credentials support them.

## API credentials

- Configure multiple panels through `MAP_PANELS_JSON`, or configure one panel using the `PANEL_*` variables.
- Each record may have a Client API key, Application API key, and/or root-admin Client API key for the Admin namespace.
- Pterodactyl versions differ in which token types each namespace accepts. MAP reports available token types without returning their values.
- Use a root-administrator Client API token only when broad administrative access is genuinely required. The tool can perform destructive API calls when the configured token permits them.

## File transfers

MAP uses the panel API to request signed Wings URLs for binary uploads and downloads. Signed URLs are not returned to the caller. For this to work, list the exact HTTPS node hostnames returned by the panel in `MAP_TRUSTED_WINGS_HOSTS`, separated by commas. The panel hostname is trusted automatically. Inline binary transfers are capped by `MAP_MAX_INLINE_FILE_BYTES` (6,000,000 bytes by default).

## Transport and security

- MAP binds to `127.0.0.1` by default. It refuses non-loopback binding unless `MAP_MCP_BEARER_TOKEN` is configured.
- The static bearer guard requires a token of at least 32 characters. For Internet access, put TLS and appropriate ingress controls in front of MAP; don't expose plaintext HTTP publicly.
- Requests can only target a configured panel's HTTPS URL. Absolute URLs, redirects, and path traversal are rejected.
- Common credential fields are redacted from JSON API responses. API response sizes are capped.
- TLS fingerprint impersonation supports compatible network paths; it does not bypass authentication, Cloudflare Access, or WAF policies.
- Pterodactyl panel access is not the same thing as SSH/root access to the EU VPS or Wings nodes. Host-level shell administration would require separate credentials and a separate tool integration.

## Install and run

Requires Python 3.11+.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[test]'
cp .env.example .env
# Configure the real panel URL and appropriate API keys.
python -m map_server.server
```

For systemd deployment, use the supplied `deploy/realmsnetwork-map.service` and store secrets outside the repository in `/etc/realmsnetwork-map/map.env` with restrictive ownership and permissions. Do not add real environment files to Git.
