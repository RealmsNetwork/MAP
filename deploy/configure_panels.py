#!/usr/bin/env python3
"""Configure MAP panel API credentials interactively without echoing secrets."""
from __future__ import annotations

import base64
import getpass
import grp
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

CONFIG = Path("/etc/realmsnetwork-map/map.env")
PANEL_ID = re.compile(r"^[A-Za-z0-9_-]{1,48}$")
PANEL_KEYS = {
    "MAP_HOST", "MAP_PORT", "MAP_MCP_BEARER_TOKEN", "MAP_MAX_RESPONSE_CHARS",
    "MAP_MAX_INLINE_FILE_BYTES", "MAP_LOG_LEVEL", "MAP_TRUSTED_WINGS_HOSTS",
}


def read_settings() -> dict[str, str]:
    result: dict[str, str] = {}
    if CONFIG.exists():
        for line in CONFIG.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            result[key.strip()] = value.strip().strip('"').strip("'")
    return result


def main() -> int:
    if os.geteuid() != 0:
        print("Run this helper as root on the EU Debian VPS. API secrets are entered locally and never printed.")
        return 2
    try:
        map_gid = grp.getgrnam("mapmcp").gr_gid
    except KeyError:
        print("MAP service account is not installed yet. Run systemd-sysusers first.")
        return 2

    existing = read_settings()
    print("Model Access Panel (MAP) panel setup")
    print("API keys are hidden as you type and are stored only in the root-owned server environment file.")
    while True:
        raw_count = input("How many Pterodactyl panels should MAP configure? [1]: ").strip()
        if not raw_count:
            count = 1
            break
        if raw_count.isdigit() and 1 <= int(raw_count) <= 20:
            count = int(raw_count)
            break
        print("Enter a number from 1 to 20.")

    panels = []
    seen = set()
    for index in range(count):
        print(f"\nPanel {index + 1} of {count}")
        while True:
            panel_id = input("Panel ID (letters/numbers/_/-; e.g. byteproject): ").strip()
            if PANEL_ID.fullmatch(panel_id) and panel_id not in seen:
                seen.add(panel_id)
                break
            print("That panel ID is invalid or already used.")
        name = input(f"Display name [{panel_id}]: ").strip() or panel_id
        base_url = input("Panel base URL (https://...): ").strip().rstrip("/")
        parsed = urlparse(base_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            print("Invalid URL: use an HTTPS panel URL without embedded credentials, query, or fragment.")
            return 2
        client_key = getpass.getpass("Client API key (required for server power/files; leave blank only if not needed): ").strip()
        application_key = getpass.getpass("Application API key (for panel-wide application endpoints; optional): ").strip()
        admin_key = getpass.getpass("Root-admin Client API key (for Admin endpoints; optional): ").strip()
        if not (client_key or application_key or admin_key):
            print("At least one API key is required for each panel.")
            return 2
        panels.append({
            "id": panel_id,
            "name": name,
            "base_url": base_url,
            "client_api_key": client_key,
            "application_api_key": application_key,
            "admin_api_key": admin_key,
        })

    previous_hosts = existing.get("MAP_TRUSTED_WINGS_HOSTS", "")
    prompt = "Exact Wings/node HTTPS hostnames for binary transfers, comma-separated"
    if previous_hosts:
        prompt += f" [{previous_hosts}]"
    else:
        prompt += " [none]"
    trusted_hosts = input(prompt + ": ").strip() or previous_hosts

    host = existing.get("MAP_HOST", "127.0.0.1")
    bearer = existing.get("MAP_MCP_BEARER_TOKEN", "")
    if host not in {"127.0.0.1", "::1", "localhost"} and len(bearer) < 32:
        print("MAP is configured for a non-loopback bind without a valid bearer token; refusing to save.")
        return 2

    print("\nPanels to save:")
    for panel in panels:
        print(f"  - {panel['id']}: {panel['name']} ({panel['base_url']})")
    confirm = input("Save this configuration and restart MAP? [y/N]: ").strip().lower()
    if confirm != "y":
        print("Cancelled; no configuration was changed.")
        return 1

    encoded = base64.b64encode(json.dumps(panels, separators=(",", ":")).encode("utf-8")).decode("ascii")
    settings = {
        "MAP_HOST": host,
        "MAP_PORT": existing.get("MAP_PORT", "8765"),
        "MAP_MAX_RESPONSE_CHARS": existing.get("MAP_MAX_RESPONSE_CHARS", "200000"),
        "MAP_MAX_INLINE_FILE_BYTES": existing.get("MAP_MAX_INLINE_FILE_BYTES", "6000000"),
        "MAP_LOG_LEVEL": existing.get("MAP_LOG_LEVEL", "info"),
        "MAP_TRUSTED_WINGS_HOSTS": trusted_hosts,
        "MAP_PANELS_JSON_B64": encoded,
    }
    if bearer:
        settings["MAP_MCP_BEARER_TOKEN"] = bearer
    output = "# Managed by deploy/configure_panels.py. Keep root-owned; do not commit.\n"
    output += "".join(f"{key}={value}\n" for key, value in settings.items())
    CONFIG.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(CONFIG.parent, 0, map_gid)
    os.chmod(CONFIG.parent, 0o750)
    fd = os.open(CONFIG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    try:
        os.fchown(fd, 0, map_gid)
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(output)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    print("Configuration saved securely. Restarting the MAP service...")
    os.system("systemctl restart realmsnetwork-map.service")
    status = os.system("systemctl --quiet is-active realmsnetwork-map.service")
    if status != 0:
        print("MAP did not become active. Inspect: journalctl -u realmsnetwork-map.service")
        return 1
    print("MAP service is active. API key values were not printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
