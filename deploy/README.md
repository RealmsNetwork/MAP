# Systemd deployment for the EU Debian VPS

The service runs under the dedicated unprivileged account mapmcp. It does not run as VPS root.

The service definition is deploy/realmsnetwork-map.service and the sysuser definition is deploy/realmsnetwork-map.sysusers.

## Configure panel keys without sharing them in chat

After updating the checkout, run the sysuser helper (as root):

    systemd-sysusers /opt/realmsnetwork-map/deploy/realmsnetwork-map.sysusers

Install/reload the unit, then run the local interactive configuration helper:

    systemctl daemon-reload
    /opt/realmsnetwork-map/.venv/bin/python /opt/realmsnetwork-map/deploy/configure_panels.py

The helper uses hidden input for API keys, writes a root-owned environment file at /etc/realmsnetwork-map/map.env, and restarts MAP. It never prints API keys. Configure a Client API key for server-level power/files, an Application API key where needed, and a root-admin Client API key for the modern Admin API namespace.

The helper can configure up to 20 panels. It writes a base64-encoded JSON environment variable so special characters in panel credentials do not break systemd EnvironmentFile parsing.

For binary file upload/download, enter exact trusted Wings/node hostnames. Only panel URL hostnames and the configured trusted hostnames are contacted by the file-transfer tools.

Keep the env file group-readable only by mapmcp (root:mapmcp, mode 0640) and its directory root:mapmcp mode 0750.

## External MCP access

MAP binds to 127.0.0.1 by default. For remote clients, put TLS and authentication-aware ingress in front of the local port. If binding MAP directly to a non-loopback address, set a long random MAP_MCP_BEARER_TOKEN (at least 32 characters) first; don't expose plaintext HTTP publicly.
