# Linux systemd deployment

The example targets Debian/Ubuntu and does not expose MAP publicly or grant OS-root access.

## Install

Create an unprivileged account (such as `mapmcp`), clone the repo into `/opt/realmsnetwork-map`, and install Python 3.11+.

```bash
cd /opt/realmsnetwork-map
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install .
```

## Unit setup

```bash
install -o root -g root -m 0644 deploy/realmsnetwork-map.service /etc/systemd/system/realmsnetwork-map.service
install -d -o root -g mapmcp -m 0750 /etc/realmsnetwork-map
systemctl daemon-reload
systemctl enable --now realmsnetwork-map.service
```

The unit expects `/etc/realmsnetwork-map/map.env`, owned by root with group `mapmcp` and mode `0640`. Do not store secrets in the unit file.

## Configure panels

Run the interactive helper as root; keys are entered with hidden input:

```bash
/opt/realmsnetwork-map/.venv/bin/python /opt/realmsnetwork-map/deploy/configure_panels.py
```

The helper stores panel JSON as base64. Base64 is not encryption, so filesystem permissions remain essential. Add exact Wings/node hostnames for binary transfers.

## Verify and upgrade

```bash
systemctl status realmsnetwork-map.service
journalctl -u realmsnetwork-map.service -n 100 --no-pager
```

The listener defaults to `127.0.0.1:8765` with MCP path `/mcp`. For remote bind, set a random bearer token and use HTTPS ingress. During upgrades, back up the env file and never replace it with `.env.example`.
