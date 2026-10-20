# Systemd deployment for the EU Debian VPS

1. Copy this service to /etc/systemd/system/realmsnetwork-map.service.
2. Create /etc/realmsnetwork-map/map.env as root. Use .env.example as a reference, but replace every placeholder.
3. Keep the env file readable by the service's group: root:nogroup mode 0640. The directory should be root:nogroup mode 0750.
4. Keep MAP_HOST=127.0.0.1 unless you have configured HTTPS and a protected remote ingress. If binding MAP directly to a non-loopback interface, configure a long MAP_MCP_BEARER_TOKEN (at least 32 characters) first.
5. Run systemctl daemon-reload, systemctl enable --now realmsnetwork-map, and inspect systemctl status realmsnetwork-map.
6. Use systemctl restart realmsnetwork-map after rotating tokens or editing the environment file.

The default service runs as nobody and is sandboxed. It is not granted VPS root access.
