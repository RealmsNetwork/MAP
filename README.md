# Model Access Panel (MAP)

<p align="center">
  <strong>One MCP gateway. Multiple Pterodactyl panels. Broad API control.</strong><br>
  A self-hosted, open-source administration gateway from RealmsNetwork.
</p>

<p align="center">
  <a href="https://github.com/RealmsNetwork/MAP/actions/workflows/ci.yml"><img src="https://github.com/RealmsNetwork/MAP/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/Python-3.11%2B-blue.svg" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/MCP-Streamable%20HTTP%20%7C%20stdio-8b5cf6.svg" alt="MCP transports">
</p>

MAP is a self-hosted [Model Context Protocol](https://modelcontextprotocol.io/) server for administering one or many [Pterodactyl](https://pterodactyl.io/) panels from MCP-compatible clients. Configure each host once, choose it by ID in a tool call, and use dedicated server tools or the generic API gateway.

**Heads up:** MAP is an administrative integration, not a read-only dashboard. Depending on configured API keys and panel permissions, it can stop servers, execute console commands, alter files, delete backups, and call destructive panel-wide endpoints. Only install it for systems you administer.

## Features

- **Multiple panels/hosts:** distinct IDs, labels, HTTPS origins, and credentials.
- **Broad API access:** generic Client, Application, and Admin request tool supporting GET, POST, PUT, PATCH, and DELETE.
- **Server operations:** list servers, inspect resources, start/stop/restart/kill, and send console commands.
- **Files and backups:** browse/read/write, create directories, rename/delete files, manage backups, and transfer bounded binary files through trusted Wings hosts.
- **Two MCP transports:** Streamable HTTP for hosted deployments and stdio for local MCP clients.
- **Customization:** configure the MCP display name, request/response limits, panel routing, timeout, and trusted Wings hosts.
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

## Deployment and security

MAP binds to loopback by default. Never expose plaintext HTTP directly to the Internet. For remote access, use HTTPS termination, a strong random bearer token, firewall restrictions, and any additional access control required by your environment. Docker Compose binds to host loopback and requires a bearer token.

MAP is **not** an SSH server and does not grant root access to its host or Wings nodes. Its authority is limited to configured Pterodactyl API credentials and permissions.

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

Pterodactyl 1.x documents Client and Application APIs. Pterodactyl 2.x documents Client, Application, and Admin APIs, with different key requirements. MAP does not invent missing endpoints: consult docs for your installed panel version and use supported namespaces. See official [1.x API docs](https://docs.pterodactyl.io/v1/api) and [2.x API docs](https://docs.pterodactyl.io/v2/api).

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
