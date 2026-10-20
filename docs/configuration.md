# Configuration reference

MAP reads environment variables at startup. A local `.env` is loaded for development; in production, use your service manager or secret store. Environment variables override `.env` values.

## Multiple panels

Set `MAP_PANELS_JSON` to a JSON array. Each item has these fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | Yes | Unique routing ID; 1–48 letters, numbers, underscores, or hyphens. |
| `name` | No | Display name; defaults to the ID. |
| `base_url` | Yes for requests | HTTPS panel origin with no username/password, query, or fragment. |
| `client_api_key` | Depends on use | Client API key for server operations. |
| `application_api_key` | Depends on use | Application API key for panel-wide endpoints. |
| `admin_api_key` | Depends on use | Root-administrator Client API key for Admin API where supported. |

Every panel is independent. A missing key disables that namespace; MAP never falls back to credentials from another panel.

### Key selection

- **Client API:** uses `client_api_key`.
- **Application API:** uses `application_api_key`, or `admin_api_key` as a fallback where supported.
- **Admin API:** uses `admin_api_key` and requires a root-admin Client API key on Pterodactyl 2.x.

Pterodactyl 1.x documents Client and Application APIs. Pterodactyl 2.x documents Client, Application, and Admin APIs. Forks may differ. See official [1.x](https://docs.pterodactyl.io/v1/api) and [2.x](https://docs.pterodactyl.io/v2/api) docs.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `MAP_PANELS_JSON` | empty | Multi-panel JSON; takes precedence over base64 config. |
| `MAP_PANELS_JSON_B64` | empty | Base64-encoded UTF-8 JSON, useful for systemd EnvironmentFile values. |
| `PANEL_BASE_URL` | empty | Legacy single-panel URL when multi-panel variables are empty. |
| `PANEL_NAME` | `Default Pterodactyl Panel` | Legacy display name. |
| `PANEL_CLIENT_API_KEY` | empty | Legacy Client key; `PANEL_API_KEY` remains a fallback. |
| `PANEL_APPLICATION_API_KEY` | empty | Legacy Application key. |
| `PANEL_ADMIN_API_KEY` | empty | Legacy root-admin Client key. |
| `MAP_TRANSPORT` | `http` | CLI transport: `http` or `stdio`. |
| `MAP_HOST` | `127.0.0.1` | HTTP bind host. Non-loopback needs a strong bearer token. |
| `MAP_PORT` | `8765` | HTTP port. |
| `MAP_MCP_BEARER_TOKEN` | empty | Static HTTP bearer guard, minimum 32 characters. |
| `MAP_TRUSTED_WINGS_HOSTS` | empty | Exact comma-separated HTTPS hostnames allowed for signed Wings URLs. |
| `MAP_MAX_RESPONSE_CHARS` | `200000` | Maximum returned string length. |
| `MAP_MAX_INLINE_FILE_BYTES` | `6000000` | Inline base64 file transfer cap in bytes. |
| `CURL_CFFI_IMPERSONATE` | `chrome` | curl-cffi fingerprint profile; not an authentication bypass. |
| `MAP_LOG_LEVEL` | `info` | Uvicorn log level. |

## Production configuration

Prefer `deploy/configure_panels.py` for systemd. It reads keys with hidden input and writes the panel array in base64 form to `/etc/realmsnetwork-map/map.env`. The file should remain root-owned, group-readable by the MAP account, and mode `0640`.

Base64 is encoding, not encryption. Filesystem permissions still matter. Never put secrets in command-line arguments, committed JSON, screenshots, bug reports, or prompts.
