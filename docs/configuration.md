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

Every panel is independent; configuration supports at most 20 panel entries. A missing key disables that namespace, and MAP never falls back to credentials from another panel. Panel IDs and display names are limited to 48 and 128 characters respectively.

### Key selection

- **Client API:** uses `client_api_key`.
- **Application API:** uses `application_api_key`, or `admin_api_key` as a fallback where supported.
- **Admin API:** uses `admin_api_key` and requires a root-admin Client API key on Pterodactyl 2.x.

Pterodactyl 1.x documents Client and Application APIs. Pterodactyl 2.x documents Client, Application, and Admin APIs. Forks may differ. See official [1.x](https://docs.pterodactyl.io/v1/api) and [2.x](https://docs.pterodactyl.io/v2/api) docs.


## Provider selection

Each panel may set a `provider` (also accepted as `panel_type` or `type`). Unknown providers are rejected rather than silently routed to the wrong API.

| Provider | Default API prefix | Auth defaults | Dedicated tools |
| --- | --- | --- | --- |
| `pterodactyl` | Namespace routes under `/api/client`, `/api/application`, or `/api/admin` | Separate Client/Application/Admin credentials | Server power, console, files, backups, resource state |
| `pelican` | Pterodactyl-compatible Client/Application routes | Client/Application credentials | Compatible server tools; no Admin namespace |
| `mcsmanager` | `/api` | API key in query parameter `apikey` | Instance list, power actions, command, output log |
| `crafty` | `/api/v2` | Bearer key by default; configurable | Generic/native REST |
| `pufferpanel` | `/api` | OAuth2 client credentials, automatically refreshed when configured | Generic/native REST |
| `calagopus` | `/api` | Bearer key by default; configurable | Generic/native REST; its API differs from Pterodactyl |
| `amp` | `/API` | Username/password login with optional TOTP; MAP caches the session ID | Generic/native AMP POST JSON API; no API key is used |
| `generic_rest` | Empty unless `api_base_path` is configured | Bearer by default; configurable | Generic/native REST |

For Pterodactyl, set `panel_version: "1.x"` to reject the 2.x-only Admin namespace, or `panel_version: "2.x"` for a 2.x panel. The default is `auto` for existing configurations. Pterodactyl 1.x and 2.x both list the user's servers via `GET /api/client`. The Application API's full server list is `GET /api/application/servers`.

Calagopus is a separate implementation, not an API-compatible Pterodactyl fork. Its API docs are available at the panel's `/api` path, and API keys must be regenerated after migrating from Pterodactyl. See the [official migration guide](https://calagopus.com/docs/additional/migrations/pterodactyl/standalone). MAP treats it as native REST instead of routing Pterodactyl tools to it.

For non-Pterodactyl providers, call `panel_api_request` with `api="native"` and a relative `path` from the vendor's API documentation. The adapter prepends `api_base_path` and then applies the configured authentication. MAP does not assume endpoint equivalence across unrelated panels.

### Native provider fields

| Field | Meaning |
| --- | --- |
| `provider` | `pterodactyl` (default), `pelican`, `mcsmanager`, `crafty`, `pufferpanel`, `calagopus`, `amp`, or `generic_rest`. |
| `panel_version` | Pterodactyl compatibility gate; may also document the installed MCSManager version. |
| `api_base_path` | Prefix for native APIs. Defaults: MCSManager `/api`, Crafty `/api/v2`, PufferPanel `/api`, Calagopus `/api`, AMP `/API`, generic REST empty. |
| `status_path` | Optional native endpoint for `panel_status`; MCSManager defaults to `overview`. |
| `api_key` | Native provider key or bearer token. |
| `auth_type` | `bearer`, `header`, `query`, `basic`, `none`, `oauth2_client_credentials`, or `amp_session`. |
| `auth_header` | Header name for header/bearer/Basic auth; defaults to `Authorization`. |
| `auth_scheme` | Prefix such as `Bearer`. Use an empty value for raw API-key header auth. |
| `auth_query_param` | Query key used for query auth; MCSManager defaults to `apikey`. |
| `custom_headers` | Optional object of extra HTTP headers. Sensitive values are server-side only. Reserved routing and hop-by-hop headers are ignored. |
| `oauth_client_id` / `oauth_client_secret` | PufferPanel OAuth2 client-credentials pair. Preferred to manually supplied short-lived access tokens. |
| `oauth_token_path` | OAuth token endpoint path; defaults to `/oauth2/token` for PufferPanel. |
| `auth_username` / `auth_password` | HTTP Basic credentials or AMP session login credentials. Store server-side only. |
| `amp_totp_token` | Optional current AMP two-factor token for API login where required. |

Example: CubeCoders AMP. MAP logs in through `/API/Core/Login`, caches the returned session ID, and injects it into native JSON POST calls. These are login credentials, not an API key.

```json
{
  "id": "amp-main",
  "name": "AMP Main",
  "provider": "amp",
  "base_url": "https://amp.example.net",
  "api_base_path": "/API",
  "auth_type": "amp_session",
  "auth_username": "REPLACE_WITH_AMP_SERVICE_USER",
  "auth_password": "REPLACE_WITH_AMP_PASSWORD",
  "amp_totp_token": ""
}
```

Example: Calagopus. Its API differs from Pterodactyl, and API keys must be regenerated after migration.

```json
{
  "id": "calagopus",
  "name": "Calagopus",
  "provider": "calagopus",
  "base_url": "https://calagopus.example.net",
  "api_base_path": "/api",
  "api_key": "REPLACE_WITH_CALAGOPUS_API_KEY",
  "auth_type": "bearer"
}
```

Example: MCSManager 10.x (use a real panel URL and keep the key secret).

```json
{
  "id": "mcsm-eu",
  "name": "MCSManager Europe",
  "provider": "mcsmanager",
  "panel_version": "10.x",
  "base_url": "https://mcsm.example.net",
  "api_base_path": "/api",
  "api_key": "REPLACE_WITH_MCSMANAGER_API_KEY",
  "auth_type": "query",
  "auth_query_param": "apikey"
}
```

Example: PufferPanel with OAuth2 client credentials.

```json
{
  "id": "puffer",
  "name": "PufferPanel",
  "provider": "pufferpanel",
  "base_url": "https://puffer.example.net",
  "api_base_path": "/api",
  "oauth_client_id": "REPLACE_WITH_OAUTH_CLIENT_ID",
  "oauth_client_secret": "REPLACE_WITH_OAUTH_CLIENT_SECRET",
  "auth_type": "oauth2_client_credentials",
  "oauth_token_path": "/oauth2/token"
}
```

Set MCSManager `panel_version` to `9.x` or `10.x` so MAP can choose the correct daemon selector (`remote_uuid` for 9.x, `daemonId` for 10.x). MCSManager's documented API accepts its key as a query parameter. HTTPS encrypts the request in transit, but reverse-proxy access logs may record query strings. Restrict and redact such logs; never paste raw request URLs into issues. See the [MCSManager authentication guide](https://docs.mcsmanager.com/apis/get_apikey.html).

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `MAP_PANELS_JSON` | empty | Multi-panel JSON; takes precedence over base64 config. |
| `MAP_PANELS_JSON_B64` | empty | Base64-encoded UTF-8 JSON, useful for systemd EnvironmentFile values. |
| `PANEL_BASE_URL` | empty | Legacy single-panel URL when multi-panel variables are empty. |
| `PANEL_NAME` | `Default Pterodactyl Panel` | Legacy display name. |
| `PANEL_PROVIDER` | `pterodactyl` | Legacy single-panel provider; supports Pterodactyl or Pelican. |
| `PANEL_VERSION` | `auto` | Legacy Pterodactyl API compatibility setting. |
| `PANEL_CLIENT_API_KEY` | empty | Legacy Client key; `PANEL_API_KEY` remains a fallback. |
| `PANEL_APPLICATION_API_KEY` | empty | Legacy Application key. |
| `PANEL_ADMIN_API_KEY` | empty | Legacy root-admin Client key. |
| `MAP_TRANSPORT` | `http` | CLI transport: `http` or `stdio`. |
| `MAP_SERVER_NAME` | `Model Access Panel (MAP)` | MCP server display name for client lists. |
| `MAP_HOST` | `127.0.0.1` | HTTP bind host. Non-loopback needs a strong bearer token. |
| `MAP_PORT` | `8765` | HTTP port. |
| `MAP_MCP_BEARER_TOKEN` | empty | Static HTTP bearer guard, minimum 32 characters. |
| `MAP_TRUSTED_WINGS_HOSTS` | empty | Exact comma-separated HTTPS hostnames allowed for signed Wings URLs. |
| `MAP_MAX_RESPONSE_CHARS` | `200000` | Maximum returned string length. |
| `MAP_MAX_REQUEST_BODY_BYTES` | `2000000` | Maximum generic API request body size. |
| `MAP_MAX_RESPONSE_BYTES` | `5000000` | Maximum total API response body size before parsing. |
| `MAP_MAX_INLINE_FILE_BYTES` | `6000000` | Inline base64 file transfer cap in bytes. |
| `CURL_CFFI_IMPERSONATE` | `chrome` | curl-cffi fingerprint profile; not an authentication bypass. |
| `MAP_LOG_LEVEL` | `info` | Uvicorn log level. |

## Production configuration

Prefer `deploy/configure_panels.py` for systemd. It reads keys with hidden input and writes the panel array in base64 form to `/etc/realmsnetwork-map/map.env`. The file should remain root-owned, group-readable by the MAP account, and mode `0640`.

Base64 is encoding, not encryption. Filesystem permissions still matter. The helper preserves the server name and request/response/file-size limits and prompts for each provider's authentication type. Never put secrets in command-line arguments, committed JSON, screenshots, bug reports, or prompts.

MAP's OAuth and AMP session caches are process-local and keyed only by non-secret panel identity fields. **Restart the MAP service after rotating an OAuth client secret, AMP password, or TOTP configuration** so cached tokens and sessions are discarded.
