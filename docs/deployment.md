# Deployment guide

MAP supports HTTP for hosted services and stdio for local MCP clients, plus Docker and systemd examples.

## Local development

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
map-server --transport http
```

Default URL is `http://127.0.0.1:8765/mcp`. For local stdio clients, configure `map-server --transport stdio` in an environment where MAP config can be loaded.

## Docker

Build with `docker build -t realmsnetwork-map:local .`. Set `MAP_PANELS_JSON_B64` and a random `MAP_MCP_BEARER_TOKEN` of at least 32 characters in your deployment environment, then run:

```bash
docker compose up -d --build
docker compose logs -f map
```

Compose publishes port 8765 only on host loopback and requires bearer auth. For HTTPS ingress, preserve the `/mcp` path and bearer header. Do not expose plaintext HTTP to the Internet.

## Linux systemd

`deploy/realmsnetwork-map.service` and `deploy/configure_panels.py` assume the checkout is `/opt/realmsnetwork-map`. Full steps are in [deploy/README.md](../deploy/README.md). The service runs as an unprivileged `mapmcp` user and reads `/etc/realmsnetwork-map/map.env`.

The helper hides credential input and stores panel JSON in base64. Base64 is not encryption; keep the file root-owned and mode 0640.

## Reverse proxy

Use HTTPS, a trusted proxy/tunnel, a strong bearer token, and network restrictions. DNS/TLS are not configured automatically because each deployment has its own domain and ingress policy.

Verify panel IDs with `list_panels` and allowlist exact Wings hostnames before using binary transfers.
