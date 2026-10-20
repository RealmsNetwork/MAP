"""Read-only MCP gateway for an explicitly configured Pterodactyl panel."""
from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import urlparse

from curl_cffi import requests
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

load_dotenv()

PANEL_BASE_URL = os.getenv("PANEL_BASE_URL", "").strip().rstrip("/")
PANEL_API_KEY = os.getenv("PANEL_API_KEY", "").strip()
IMPERSONATE = os.getenv("CURL_CFFI_IMPERSONATE", "chrome").strip() or "chrome"
HOST = os.getenv("MAP_HOST", "127.0.0.1").strip()
PORT = int(os.getenv("MAP_PORT", "8765"))
if HOST not in {"127.0.0.1", "::1", "localhost"}:
    raise RuntimeError("MAP must bind to localhost until an authenticated remote transport is configured.")

mcp = FastMCP("Model Access Panel (MAP)", host=HOST, port=PORT)


def _validate_config() -> None:
    if not PANEL_BASE_URL or not PANEL_API_KEY:
        raise RuntimeError("PANEL_BASE_URL and PANEL_API_KEY must be configured in the environment.")
    parsed = urlparse(PANEL_BASE_URL)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise RuntimeError("PANEL_BASE_URL must be an HTTPS URL without embedded credentials.")
    if parsed.query or parsed.fragment:
        raise RuntimeError("PANEL_BASE_URL must not contain a query string or fragment.")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        address = None
    if address and (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved):
        raise RuntimeError("PANEL_BASE_URL must use the panel hostname, not a raw private IP.")
    if HOST not in {"127.0.0.1", "::1", "localhost"}:
        raise RuntimeError("MAP must bind to localhost until an authenticated remote transport is configured.")


def _api_get(path: str, params: dict | None = None) -> dict:
    _validate_config()
    if (path != "/api/client" and not path.startswith("/api/client/")) or ".." in path.split("/"):
        raise ValueError("Only fixed Pterodactyl Client API paths are allowed.")
    response = requests.get(
        f"{PANEL_BASE_URL}{path}",
        headers={
            "Authorization": f"Bearer {PANEL_API_KEY}",
            "Accept": "Application/vnd.pterodactyl.v1+json",
            "Content-Type": "application/json",
        },
        params=params,
        impersonate=IMPERSONATE,
        timeout=15,
        allow_redirects=False,
    )
    if 300 <= response.status_code < 400:
        raise RuntimeError("Panel redirected the API request; check PANEL_BASE_URL and panel access configuration.")
    if response.status_code in (401, 403):
        raise RuntimeError(f"Panel authorization failed (HTTP {response.status_code}); verify key permissions.")
    if response.status_code >= 400:
        raise RuntimeError(f"Pterodactyl API returned HTTP {response.status_code}.")
    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError("Panel returned a non-JSON response; verify the API endpoint and access route.") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("Unexpected Pterodactyl API response shape.")
    return payload


@mcp.tool()
def panel_url() -> str:
    """Return the configured Pterodactyl panel URL for the user to open."""
    _validate_config()
    return PANEL_BASE_URL


@mcp.tool()
def list_servers(page: int = 1) -> dict:
    """List servers visible to the configured Client API key. Page must be 1 or greater."""
    if page < 1 or page > 1000:
        raise ValueError("page must be between 1 and 1000.")
    payload = _api_get("/api/client", {"page": page})
    safe_data = []
    for item in payload.get("data", []):
        attrs = item.get("attributes", {}) if isinstance(item, dict) else {}
        safe_data.append({
            "identifier": attrs.get("identifier"),
            "name": attrs.get("name"),
            "description": attrs.get("description"),
            "status": attrs.get("status"),
            "node": attrs.get("node"),
            "limits": attrs.get("limits"),
        })
    meta = payload.get("meta", {})
    pagination = meta.get("pagination", {}) if isinstance(meta, dict) else {}
    return {"servers": safe_data, "pagination": pagination}


@mcp.tool()
def server_resources(identifier: str) -> dict:
    """Read current resource usage for a server by its Pterodactyl identifier."""
    if not identifier or len(identifier) > 64 or not re.fullmatch(r"[A-Za-z0-9-]+", identifier):
        raise ValueError("identifier must be a valid Pterodactyl server identifier.")
    payload = _api_get(f"/api/client/servers/{identifier}/resources")
    attrs = payload.get("attributes", {})
    return {
        "current_state": attrs.get("current_state"),
        "is_suspended": attrs.get("is_suspended"),
        "resources": attrs.get("resources", {}),
    }


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
