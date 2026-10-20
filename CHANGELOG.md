# Changelog

MAP is currently in beta.

## Unreleased

- Preserve Pterodactyl 1.x Client/Application compatibility and gate the 2.x-only Admin API when the host version is configured.
- Add provider-aware native REST adapters for Calagopus, MCSManager, Crafty Controller, PufferPanel, and configurable custom REST APIs, with explicit MCSManager 9.x/10.x daemon parameter compatibility.
- Add MCSManager-native instance listing, actions, command, and output-log tools plus PufferPanel OAuth2 client-credentials refresh.
- Add CubeCoders AMP session login with cached SESSIONID injection, and HTTP Basic authentication for custom REST panels.
- Add provider-specific auth configuration and tests for legacy routing, custom paths, query/header auth, and token caching.

- Split runtime into configuration, panel-client, transport-security, and MCP tool modules.
- Add stdio alongside Streamable HTTP.
- Expand configuration, architecture, deployment, security, and troubleshooting docs.
- Add Docker, contribution policies/templates, CodeQL, secret scanning, dependency updates, and a Python test matrix.

## 0.2.x

- Initial multi-panel configuration and generic Client/Application/Admin API gateway.
- Server power, console, file, backup, bounded base64 transfer tools, and systemd deployment.
