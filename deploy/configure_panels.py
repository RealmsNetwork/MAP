#!/usr/bin/env python3
"""Configure MAP panel API credentials interactively without echoing secrets."""
from __future__ import annotations

import base64
import getpass
import ipaddress
import grp
import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

CONFIG = Path("/etc/realmsnetwork-map/map.env")
PANEL_ID = re.compile(r"^[A-Za-z0-9_-]{1,48}$")

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
        raw_count = input("How many panels should MAP configure? [1]: ").strip()
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
        try:
            parsed.port
        except ValueError:
            print("Invalid panel URL port.")
            return 2
        try:
            address = ipaddress.ip_address(parsed.hostname or "")
        except ValueError:
            address = None
        if (
            not base_url
            or len(base_url) > 2048
            or any(char.isspace() for char in base_url)
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or (address and not address.is_global)
        ):
            print("Invalid URL: use a public HTTPS panel URL without embedded credentials, query, or fragment.")
            return 2
        provider_choices = {
            "1": "pterodactyl",
            "2": "pelican",
            "3": "mcsmanager",
            "4": "crafty",
            "5": "pufferpanel",
            "6": "generic_rest",
            "7": "calagopus",
            "8": "amp",
        }
        print("Panel provider: 1) Pterodactyl 2) Pelican 3) MCSManager 4) Crafty Controller 5) PufferPanel 6) Generic REST 7) Calagopus 8) CubeCoders AMP")
        raw_provider = input("Choose provider [1]: ").strip() or "1"
        provider = provider_choices.get(raw_provider, raw_provider.lower())
        if provider not in set(provider_choices.values()):
            print("Unsupported provider. Choose one of the listed providers.")
            return 2

        record = {
            "id": panel_id,
            "name": name,
            "base_url": base_url,
            "provider": provider,
        }
        if provider == "pterodactyl":
            panel_version = input("Pterodactyl API version (1.x / 2.x / auto) [auto]: ").strip().lower() or "auto"
            if panel_version not in {"1", "1.x", "2", "2.x", "auto"}:
                print("Enter 1.x, 2.x, or auto.")
                return 2
            record["panel_version"] = "1.x" if panel_version in {"1", "1.x"} else "2.x" if panel_version in {"2", "2.x"} else "auto"
            record["client_api_key"] = getpass.getpass("Client API key (required for server actions): ").strip()
            record["application_api_key"] = getpass.getpass("Application API key (optional for panel-wide endpoints): ").strip()
            if record["panel_version"] != "1.x":
                record["admin_api_key"] = getpass.getpass("Root-admin Client API key (optional, Pterodactyl 2.x): ").strip()
            else:
                record["admin_api_key"] = ""
            if not (record["client_api_key"] or record["application_api_key"]):
                print("Configure at least a Client or Application API key.")
                return 2
        elif provider == "pelican":
            record["client_api_key"] = getpass.getpass("Client API key (required for server actions): ").strip()
            record["application_api_key"] = getpass.getpass("Application API key (optional for panel-wide endpoints): ").strip()
            if not (record["client_api_key"] or record["application_api_key"]):
                print("Configure at least a Client or Application API key.")
                return 2
        elif provider == "mcsmanager":
            record["api_key"] = getpass.getpass("MCSManager API key (hidden input): ").strip()
            version = input("MCSManager version [10.x]: ").strip() or "10.x"
            if version not in {"9", "9.x", "10", "10.x"}:
                print("Enter 9.x or 10.x.")
                return 2
            record["panel_version"] = "9.x" if version in {"9", "9.x"} else "10.x"
            record["api_base_path"] = "/api"
            record["auth_type"] = "query"
            record["auth_query_param"] = "apikey"
            if not record["api_key"]:
                print("MCSManager requires an API key for the native API.")
                return 2
        elif provider == "amp":
            record["api_base_path"] = input("AMP API base path [/API]: ").strip() or "/API"
            record["auth_type"] = "amp_session"
            record["auth_username"] = input("AMP username (create a least-privilege service account): ").strip()
            record["auth_password"] = getpass.getpass("AMP password (hidden input): ")
            record["amp_totp_token"] = getpass.getpass("AMP 2FA token (blank if not required; hidden input): ").strip()
            if not record["auth_username"] or not record["auth_password"]:
                print("AMP needs a username and password for its session API.")
                return 2
        elif provider == "pufferpanel":
            record["api_base_path"] = input("PufferPanel API base path [/api]: ").strip() or "/api"
            oauth_id = input("OAuth client ID (blank to use a direct access token): ").strip()
            oauth_secret = getpass.getpass("OAuth client secret (hidden; blank for direct token): ").strip() if oauth_id else ""
            if oauth_id and oauth_secret:
                record["oauth_client_id"] = oauth_id
                record["oauth_client_secret"] = oauth_secret
                record["auth_type"] = "oauth2_client_credentials"
                record["oauth_token_path"] = "/oauth2/token"
            else:
                record["api_key"] = getpass.getpass("Bearer access token (hidden; expires and must be rotated): ").strip()
                record["auth_type"] = "bearer"
                if not record["api_key"]:
                    print("Configure OAuth client credentials or a bearer access token.")
                    return 2
        else:
            default_path = "/api/v2" if provider == "crafty" else "/api" if provider == "calagopus" else "/API" if provider == "amp" else ""
            record["api_base_path"] = input(f"Native API base path [{default_path or '/'}]: ").strip() or default_path
            print("Authentication style: bearer / header / query / basic / none / oauth2_client_credentials")
            auth_type = input("Auth style [bearer]: ").strip().lower() or "bearer"
            if auth_type not in {"bearer", "header", "query", "basic", "none"}:
                print("Unsupported auth style.")
                return 2
            record["auth_type"] = auth_type
            if auth_type == "basic":
                record["auth_username"] = input("HTTP Basic auth username: ").strip()
                record["auth_password"] = getpass.getpass("HTTP Basic auth password (hidden input): ")
                if not record["auth_username"] or not record["auth_password"]:
                    print("Basic auth requires a username and password.")
                    return 2
            elif auth_type != "none":
                record["api_key"] = getpass.getpass("API key/token (hidden input): ").strip()
                if not record["api_key"]:
                    print("An API key/token is required for that auth style.")
                    return 2
            if auth_type == "header":
                record["auth_header"] = input("HTTP auth header [X-API-Key]: ").strip() or "X-API-Key"
                record["auth_scheme"] = input("Auth scheme/prefix (blank for raw key) []: ").strip()
            elif auth_type == "query":
                record["auth_query_param"] = input("Query parameter name [api_key]: ").strip() or "api_key"
            elif auth_type == "bearer":
                record["auth_header"] = "Authorization"
                record["auth_scheme"] = "Bearer"

        panels.append(record)
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
        "MAP_SERVER_NAME": existing.get("MAP_SERVER_NAME", "Model Access Panel (MAP)"),
        "MAP_MAX_RESPONSE_CHARS": existing.get("MAP_MAX_RESPONSE_CHARS", "200000"),
        "MAP_MAX_REQUEST_BODY_BYTES": existing.get("MAP_MAX_REQUEST_BODY_BYTES", "2000000"),
        "MAP_MAX_RESPONSE_BYTES": existing.get("MAP_MAX_RESPONSE_BYTES", "5000000"),
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
