# Model Access Panel (MAP)

<p align="center">
  <strong>One MCP gateway. Multiple game-server panels. Broad API control.</strong><br>
  A self-hosted, open-source administration gateway from RealmsNetwork.
</p>

<p align="center">
  <a href="https://github.com/RealmsNetwork/MAP/actions/workflows/ci.yml"><img src="https://github.com/RealmsNetwork/MAP/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/Python-3.11%2B-blue.svg" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/MCP-Streamable%20HTTP%20%7C%20stdio-8b5cf6.svg" alt="MCP transports">
</p>

MAP is a self-hosted [Model Context Protocol](https://modelcontextprotocol.io/) gateway for administering multiple game-server and hosting panels. It preserves the familiar Pterodactyl API workflow for older 1.x and newer 2.x installations, and adds provider adapters for panels with different API conventions. Configure each host once, select it by ID, and use dedicated tools where a provider is supported or the native API gateway elsewhere. No universal adapter can infer vendor-specific endpoints or permissions automatically.

**Heads up:** MAP is an administrative integration, not a read-only dashboard. Depending on configured API keys and panel permissions, it can stop servers, execute console commands, alter files, delete backups, and call destructive panel-wide endpoints. Only install it for systems you administer.

## Features

- **Multiple providers:** each panel has its own ID, origin, provider type, endpoint prefix, and credentials.
- **Broad API access:** namespaced Client/Application/Admin requests for compatible panels and a generic native REST request tool supporting GET, POST, PUT, PATCH, and DELETE.
- **Server operations:** Pterodactyl/Pelican server power/resources/console/file/backup tools; native MCSManager instance list, power, console-command, and output-log tools; AMP session-based native calls.
- **Files and backups:** browse/read/write, create directories, rename/delete files, manage backups, and transfer bounded binary files through trusted Wings hosts.
- **Two MCP transports:** Streamable HTTP for hosted deployments and stdio for local MCP clients.
- **Customization:** configure the MCP display name, request/response limits, native API prefix, auth scheme/header/query parameter, optional custom headers, panel routing, timeout, and trusted Wings hosts.
- **Deployment options:** Docker, systemd, and interactive panel configuration.
- **Maintainer automation:** Python test matrix, static checks, package build, secret scanning, CodeQL, dependency updates, and issue templates.

## Quick start

Requires Python 3.11+.

```bash
git clone https://github.com/RealmsNetwork/MAP.git
cd MAP
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
cp .env.example .env
```

Edit `.env` with your authorized panels and keys. Never commit the file or paste production credentials into issues/prompts.

Run the local HTTP MCP endpoint:

```bash
map-server --transport http
```

Default endpoint: `http://127.0.0.1:8765/mcp`. For local MCP clients that launch subprocesses, use `map-server --transport stdio`.

## Multiple hosts

Set `MAP_PANELS_JSON` to a JSON array. Each panel uses a unique `id`; pass that value as `panel_id` to MAP tools.

```json
[
  {
    "id": "realms-us",
    "name": "RealmsNetwork US",
    "base_url": "https://panel-us.example.net",
    "client_api_key": "REPLACE_WITH_CLIENT_API_KEY",
    "application_api_key": "REPLACE_WITH_APPLICATION_API_KEY",
    "admin_api_key": "REPLACE_WITH_ROOT_ADMIN_CLIENT_API_KEY"
  },
  {
    "id": "realms-eu",
    "name": "RealmsNetwork Europe",
    "base_url": "https://panel-eu.example.net",
    "client_api_key": "REPLACE_WITH_CLIENT_API_KEY",
    "application_api_key": "",
    "admin_api_key": ""
  }
]
```

These are placeholders, not working credentials. Each host has its own base URL and keys. MAP will not reuse keys from another configured panel. For production, use the interactive configurator or a secret store. See [Configuration](docs/configuration.md).

## Supported panel providers

| Provider | API mode | Support level |
| --- | --- | --- |
| [Pterodactyl](https://docs.pterodactyl.io/v1/api) 1.x | `client` / `application` | Dedicated server tools and generic API; Client server listing uses the older `GET /api/client` route. Admin API is unavailable in 1.x. |
| [Pterodactyl](https://docs.pterodactyl.io/v2/api) 2.x | `client` / `application` / `admin` | Dedicated server tools plus the 2.x Admin namespace when configured. |
| [Pelican Panel](https://pelican.dev/docs/panel/advanced/api-docs/) | `client` / `application` | Pterodactyl-compatible Client/Application APIs. |
| [Calagopus](https://calagopus.com/docs/) | `native` | Generic/native REST adapter with default prefix `/api`; its API and keys are not compatible with Pterodactyl. The native API reference is available on each Calagopus panel at `/api`. |
| [MCSManager](https://docs.mcsmanager.com/apis/api_instance.html) 10.x | `native` | Dedicated instance list, start/stop/restart/kill, command, and output-log tools; native REST access for other endpoints. MCSManager 9.x has API differences, so verify endpoints against your installed version. |
| [Crafty Controller](https://docs.craftycontrol.com/pages/developer-guide/api-reference/v2/) API v2 | `native` | Generic REST adapter, default prefix `/api/v2`, configurable auth header/scheme or other supported auth mode. |
| [PufferPanel](https://docs.pufferpanel.com/en/2.x/guides/common-problems.html) 2.x | `native` | Generic REST adapter with OAuth2 client-credentials token refresh, or a directly supplied bearer token. |
| [CubeCoders AMP](https://github-wiki-see.page/m/CubeCoders/AMP/wiki/Developers%3A-How-do-I-start-working-with-AMP%27s-API%3F) | `native` | Session-based native API: MAP logs in and caches SESSIONID for POST JSON calls. Requires a least-privilege AMP account; no API key is assumed. |
| Other HTTPS REST panels | `native` | Generic adapter with configurable API prefix and `bearer`, `header`, `query`, `basic`, `oauth2_client_credentials`, or `none` auth plus optional custom headers. Provider-specific actions need an adapter and tests before MAP claims native tool support. |

Use `api="native"` for MCSManager, Crafty, PufferPanel, Calagopus, AMP, and generic REST requests. For Pterodactyl/Pelican, use the corresponding API namespace. Calagopus uses its own native API and its keys must be regenerated after migration. AMP uses session authentication, and generic REST profiles also support HTTP Basic authentication. See [provider configuration](docs/configuration.md) and [tool reference](docs/tools.md).

## Deployment and security

MAP binds to loopback by default. Never expose plaintext HTTP directly to the Internet. For remote access, use HTTPS termination, a strong random bearer token, firewall restrictions, and any additional access control required by your environment. Docker Compose binds to host loopback and requires a bearer token.

MAP is **not** an SSH server and does not grant root access to its host or Wings nodes. Its authority is limited to the configured provider's API credentials and permissions.

- [Security model](docs/security.md)
- [Docker and systemd deployment](docs/deployment.md)
- [Tool reference](docs/tools.md)
- [Architecture](docs/architecture.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Contributing](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [Project wiki](https://github.com/RealmsNetwork/MAP/wiki)

## API compatibility

MAP intentionally keeps Pterodactyl 1.x support. Both 1.x and 2.x expose Client and Application APIs; Admin is a 2.x API. Configure `panel_version: "1.x"` to reject Admin calls locally, or `auto` when the version is unknown. The generic API tool does not invent endpoints: check the documentation for the exact panel and version.

Official references: [AMP API guide](https://github-wiki-see.page/m/CubeCoders/AMP/wiki/Developers%3A-How-do-I-start-working-with-AMP%27s-API%3F), [Calagopus migration notes](https://calagopus.com/docs/additional/migrations/pterodactyl/standalone), [Pterodactyl 1.x](https://docs.pterodactyl.io/v1/api), [Pterodactyl 2.x](https://docs.pterodactyl.io/v2/api), [MCSManager API](https://docs.mcsmanager.com/apis/api_instance.html), [Crafty API v2](https://docs.craftycontrol.com/pages/developer-guide/api-reference/v2/), and [PufferPanel OAuth2 guidance](https://docs.pufferpanel.com/en/2.x/guides/common-problems.html).

## Development

```bash
python -m pip install -e '.[dev]'
ruff check src tests deploy
pytest -q
python -m build
```

Please report bugs with sanitized reproduction steps. Never include API keys, signed transfer URLs, private panel addresses, or production logs.

## Design references

MAP's implementation is original. Maintainers reviewed public MCP-server conventions and Pterodactyl API guidance for ideas such as concise setup instructions, clear developer workflows, and private security reporting. We did not transplant another project's source files. See [PixlFlip-Enterprises/PterodactylMCP](https://github.com/PixlFlip-Enterprises/PterodactylMCP) and [GitHub's official MCP Server](https://github.com/github/github-mcp-server) as independent reference projects.
