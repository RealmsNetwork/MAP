# Troubleshooting

## Startup exits

- Non-loopback HTTP binds need `MAP_MCP_BEARER_TOKEN` with at least 32 characters.
- Verify `MAP_PORT` and JSON in `MAP_PANELS_JSON` or `MAP_PANELS_JSON_B64`.
- For systemd inspect `journalctl -u realmsnetwork-map.service`; do not paste unredacted logs into an issue.

## No panels appear

Configure multi-panel environment settings or run the interactive configurator, then restart MAP.

## 401 or 403

Check key type, API namespace, and permissions. Pterodactyl 1.x documents Client/Application; 2.x also documents Admin. Application keys are not Admin API keys.

## 404

Check panel version, endpoint, and namespace. Supply a relative path; MAP adds the namespace prefix. Consult official docs for the installed panel and any fork-specific endpoints.

## File transfer refused

Add the exact Wings/node hostname to `MAP_TRUSTED_WINGS_HOSTS`, verify DNS/TLS/firewall connectivity, and keep files under `MAP_MAX_INLINE_FILE_BYTES`. Do not disable host checks.

## MCP client cannot connect

HTTP uses `/mcp`. Loopback binds are accessible only on the same host or through a secure tunnel. Remote clients must use HTTPS ingress and send `Authorization: Bearer <token>`. For stdio choose `map-server --transport stdio`.
