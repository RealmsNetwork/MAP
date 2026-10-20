# Architecture

- `config.py` loads environment settings, validates panel identifiers/origins, and selects credentials by API namespace.
- `client.py` sends requests, redacts response content, and validates signed Wings transfer URLs.
- `security.py` provides the ASGI bearer guard for HTTP transport.
- `server.py` registers MCP tools and offers HTTP/stdio entry points.
- `deploy/` contains systemd and interactive configuration files; `docs/` contains operator and contributor guides.

## Request flow

1. The client chooses a `panel_id`.
2. MAP loads that panel's server-side record and selects the requested API key.
3. MAP combines the configured HTTPS origin with a validated relative path.
4. The panel validates the key and permission for the endpoint.
5. MAP bounds and redacts returned content.

Binary transfers request a signed URL from the panel, check HTTPS and the hostname allowlist, and then transfer a bounded payload. The signed URL is not returned.

Extensions should keep common workflows as validated named tools, preserve the generic endpoint tool, avoid arbitrary origins, never log secrets by default, clearly identify destructive behavior, and test with mocked requests.
