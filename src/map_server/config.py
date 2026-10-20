"""Environment-backed settings and validated multi-panel configuration."""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv()

HOST = os.getenv("MAP_HOST", "127.0.0.1").strip()
PORT = int(os.getenv("MAP_PORT", "8765"))
MCP_BEARER_TOKEN = os.getenv("MAP_MCP_BEARER_TOKEN", "").strip()
IMPERSONATE = os.getenv("CURL_CFFI_IMPERSONATE", "chrome").strip() or "chrome"
MAX_RESPONSE_CHARS = int(os.getenv("MAP_MAX_RESPONSE_CHARS", "200000"))
MAX_INLINE_FILE_BYTES = int(os.getenv("MAP_MAX_INLINE_FILE_BYTES", "6000000"))
PANEL_IDS_RE = re.compile(r"^[A-Za-z0-9_-]{1,48}$")
SERVER_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
SUPPORTED_APIS = {"client", "application", "admin"}
SUPPORTED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}

def _read_panels() -> dict[str, dict[str, str]]:
    """Load panel URLs and API keys from server-side environment only."""
    panels: dict[str, dict[str, str]] = {}
    raw = os.getenv("MAP_PANELS_JSON", "").strip()
    if not raw:
        encoded = os.getenv("MAP_PANELS_JSON_B64", "").strip()
        if encoded:
            try:
                raw = base64.b64decode(encoded, validate=True).decode("utf-8")
            except Exception as exc:
                raise RuntimeError("MAP_PANELS_JSON_B64 must be base64-encoded UTF-8 JSON.") from exc
    if raw:
        try:
            entries = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("MAP_PANELS_JSON must be valid JSON.") from exc
        if not isinstance(entries, list):
            raise RuntimeError("MAP_PANELS_JSON must be a JSON array.")
        for entry in entries:
            if not isinstance(entry, dict):
                raise RuntimeError("Each MAP_PANELS_JSON entry must be an object.")
            panel_id = str(entry.get("id", "")).strip()
            if not PANEL_IDS_RE.fullmatch(panel_id) or panel_id in panels:
                raise RuntimeError("Panel IDs must be unique and use letters, numbers, underscores, or hyphens.")
            panels[panel_id] = {
                "id": panel_id,
                "name": str(entry.get("name") or panel_id),
                "base_url": str(entry.get("base_url") or "").strip().rstrip("/"),
                "client_api_key": str(entry.get("client_api_key") or "").strip(),
                "application_api_key": str(entry.get("application_api_key") or "").strip(),
                "admin_api_key": str(entry.get("admin_api_key") or "").strip(),
            }
    else:
        base_url = os.getenv("PANEL_BASE_URL", "").strip().rstrip("/")
        if base_url:
            panels["default"] = {
                "id": "default",
                "name": os.getenv("PANEL_NAME", "Default Pterodactyl Panel").strip(),
                "base_url": base_url,
                "client_api_key": os.getenv("PANEL_CLIENT_API_KEY", os.getenv("PANEL_API_KEY", "")).strip(),
                "application_api_key": os.getenv("PANEL_APPLICATION_API_KEY", "").strip(),
                "admin_api_key": os.getenv("PANEL_ADMIN_API_KEY", "").strip(),
            }
    return panels


def _panels() -> dict[str, dict[str, str]]:
    return _read_panels()


def _panel(panel_id: str) -> dict[str, str]:
    if not PANEL_IDS_RE.fullmatch(panel_id or ""):
        raise ValueError("panel_id must be a configured panel ID.")
    panel = _panels().get(panel_id)
    if not panel:
        raise ValueError(f"Panel ID '{panel_id}' is not configured. Use list_panels to inspect configured IDs.")
    parsed = urlparse(panel["base_url"])
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise RuntimeError(f"Panel '{panel_id}' must have an HTTPS base_url without embedded credentials.")
    if parsed.query or parsed.fragment:
        raise RuntimeError(f"Panel '{panel_id}' base_url must not contain a query string or fragment.")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        address = None
    if address and (address.is_loopback or address.is_link_local or address.is_reserved):
        raise RuntimeError(f"Panel '{panel_id}' uses a disallowed loopback, link-local, or reserved IP address.")
    return panel


def _token_for(panel: dict[str, str], api: str) -> str:
    if api == "client":
        token = panel.get("client_api_key", "")
    elif api == "application":
        token = panel.get("application_api_key", "") or panel.get("admin_api_key", "")
    elif api == "admin":
        token = panel.get("admin_api_key", "")
    else:
        raise ValueError("api must be client, application, or admin.")
    if not token:
        raise RuntimeError(
            f"Panel '{panel['id']}' has no key configured for the {api} API. "
            "Add the appropriate key to the server-side environment."
        )
    return token


