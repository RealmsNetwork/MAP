"""Environment-backed settings and validated multi-panel configuration."""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
from urllib.parse import urlparse
from typing import Any

from .providers import normalize_api_base_path, normalize_provider

from dotenv import load_dotenv

load_dotenv()

HOST = os.getenv("MAP_HOST", "127.0.0.1").strip()
PORT = int(os.getenv("MAP_PORT", "8765"))
MCP_BEARER_TOKEN = os.getenv("MAP_MCP_BEARER_TOKEN", "").strip()
MAP_SERVER_NAME = os.getenv("MAP_SERVER_NAME", "Model Access Panel (MAP)").strip() or "Model Access Panel (MAP)"
IMPERSONATE = os.getenv("CURL_CFFI_IMPERSONATE", "chrome").strip() or "chrome"
MAX_RESPONSE_CHARS = int(os.getenv("MAP_MAX_RESPONSE_CHARS", "200000"))
MAX_REQUEST_BODY_BYTES = int(os.getenv("MAP_MAX_REQUEST_BODY_BYTES", "2000000"))
MAX_RESPONSE_BYTES = int(os.getenv("MAP_MAX_RESPONSE_BYTES", "5000000"))
MAX_INLINE_FILE_BYTES = int(os.getenv("MAP_MAX_INLINE_FILE_BYTES", "6000000"))
MAX_REQUEST_BODY_BYTES = int(os.getenv("MAP_MAX_REQUEST_BODY_BYTES", "2000000"))
MAX_RESPONSE_BYTES = int(os.getenv("MAP_MAX_RESPONSE_BYTES", "5000000"))
MAX_CONFIGURED_PANELS = 20
PANEL_IDS_RE = re.compile(r"^[A-Za-z0-9_-]{1,48}$")
SERVER_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
SUPPORTED_APIS = {"client", "application", "admin", "native"}
SUPPORTED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}

if not 1 <= PORT <= 65535:
    raise RuntimeError("MAP_PORT must be between 1 and 65535.")
if min(MAX_RESPONSE_CHARS, MAX_REQUEST_BODY_BYTES, MAX_RESPONSE_BYTES, MAX_INLINE_FILE_BYTES) < 1:
    raise RuntimeError("MAP response and file size limits must all be positive integers.")


def _validate_base_url(panel_id: str, base_url: str) -> None:
    """Validate a panel origin before it can be used for authenticated requests."""
    if not base_url or len(base_url) > 2048 or any(char.isspace() for char in base_url):
        raise RuntimeError(f"Panel '{panel_id}' must have a base_url between 1 and 2048 characters.")
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RuntimeError(f"Panel '{panel_id}' must have a valid HTTPS base_url without embedded credentials, query, or fragment.")
    try:
        parsed.port
    except ValueError:
        raise RuntimeError(f"Panel '{panel_id}' base_url has an invalid port.") from None
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        address = None
    if address and not address.is_global:
        raise RuntimeError(f"Panel '{panel_id}' cannot use a non-public IP address as its base_url.")


def _read_panels() -> dict[str, dict[str, Any]]:
    """Load panel URLs and API keys from server-side environment only."""
    panels: dict[str, dict[str, Any]] = {}
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
        if len(entries) > MAX_CONFIGURED_PANELS:
            raise RuntimeError(f"MAP_PANELS_JSON supports at most {MAX_CONFIGURED_PANELS} panels.")
        for entry in entries:
            if not isinstance(entry, dict):
                raise RuntimeError("Each MAP_PANELS_JSON entry must be an object.")
            panel_id = str(entry.get("id", "")).strip()
            if not PANEL_IDS_RE.fullmatch(panel_id) or panel_id in panels:
                raise RuntimeError("Panel IDs must be unique and use letters, numbers, underscores, or hyphens.")
            base_url = str(entry.get("base_url") or "").strip().rstrip("/")
            _validate_base_url(panel_id, base_url)
            name = str(entry.get("name") or panel_id).strip()
            if not name or len(name) > 128:
                raise RuntimeError("Panel display name must be between 1 and 128 characters.")
            provider = normalize_provider(
                entry.get("provider", entry.get("panel_type", entry.get("type", "pterodactyl")))
            )
            panel_version = str(entry.get("panel_version", entry.get("version", "auto")) or "auto").strip().lower()
            if provider == "pterodactyl" and panel_version not in {"auto", "1", "1.x", "v1", "2", "2.x", "v2"}:
                raise RuntimeError(f"Panel '{panel_id}' panel_version must be auto, 1.x, or 2.x.")
            default_auth = {
                "pterodactyl": "bearer",
                "pelican": "bearer",
                "mcsmanager": "query",
                "crafty": "bearer",
                "pufferpanel": "oauth2_client_credentials",
                "calagopus": "bearer",
                "amp": "amp_session",
                "generic_rest": "bearer",
            }[provider]
            auth_type = str(entry.get("auth_type") or default_auth).strip().lower()
            if auth_type not in {"bearer", "header", "query", "basic", "none", "oauth2_client_credentials", "amp_session"}:
                raise RuntimeError(
                    f"Panel '{panel_id}' auth_type must be bearer, header, query, basic, none, oauth2_client_credentials, or amp_session."
                )
            api_key = str(entry.get("api_key") or entry.get("auth_token") or "").strip()
            oauth_client_id = str(entry.get("oauth_client_id") or "").strip()
            oauth_client_secret = str(entry.get("oauth_client_secret") or "").strip()
            auth_username = str(entry.get("auth_username") or "").strip()
            auth_password = str(entry.get("auth_password") or "")
            amp_totp_token = str(entry.get("amp_totp_token") or "").strip()
            if provider == "amp":
                if not (auth_username and auth_password):
                    raise RuntimeError("AMP panels require auth_username and auth_password.")
                auth_type = "amp_session"
            if provider == "pufferpanel":
                if bool(oauth_client_id) != bool(oauth_client_secret):
                    raise RuntimeError("PufferPanel OAuth requires both oauth_client_id and oauth_client_secret.")
                if oauth_client_id and oauth_client_secret:
                    auth_type = "oauth2_client_credentials"
                elif api_key:
                    auth_type = "bearer"
                else:
                    raise RuntimeError("PufferPanel requires OAuth client credentials or a bearer api_key.")
            auth_header = str(entry.get("auth_header") or "Authorization").strip()
            if not re.fullmatch(r"[!#$%&'*+.^_|~0-9A-Za-z-]{1,128}", auth_header):
                raise RuntimeError(f"Panel '{panel_id}' auth_header is not a valid HTTP header name.")
            auth_scheme = str(entry.get("auth_scheme", "Bearer" if auth_type == "bearer" else "")).strip()
            auth_query_param = str(entry.get("auth_query_param") or ("apikey" if provider == "mcsmanager" else "api_key")).strip()
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", auth_query_param):
                raise RuntimeError(f"Panel '{panel_id}' auth_query_param contains unsupported characters.")
            custom_headers = entry.get("custom_headers") or {}
            if not isinstance(custom_headers, dict) or len(custom_headers) > 32:
                raise RuntimeError(f"Panel '{panel_id}' custom_headers must be an object with at most 32 entries.")
            for header_name, header_value in custom_headers.items():
                if (
                    not isinstance(header_name, str)
                    or not re.fullmatch(r"[!#$%&'*+._|~0-9A-Za-z-]{1,128}", header_name)
                    or header_name.lower() in {"host", "content-length", "connection", "transfer-encoding", "proxy-authorization", "authorization"}
                    or not isinstance(header_value, str)
                    or len(header_value) > 8192
                    or "\r" in header_value
                    or "\n" in header_value
                ):
                    raise RuntimeError(f"Panel '{panel_id}' has an invalid custom HTTP header.")
            api_base_path = normalize_api_base_path(entry, provider)
            oauth_token_path = str(entry.get("oauth_token_path") or "/oauth2/token").strip()
            if (
                not oauth_token_path.startswith("/")
                or oauth_token_path.startswith("//")
                or any(char.isspace() for char in oauth_token_path)
                or "?" in oauth_token_path
                or "#" in oauth_token_path
                or "://" in oauth_token_path
                or "\\" in oauth_token_path
                or any(part in {".", ".."} for part in oauth_token_path.strip("/").split("/"))
            ):
                raise RuntimeError(f"Panel '{panel_id}' oauth_token_path must be an absolute path on its configured host.")
            panels[panel_id] = {
                "id": panel_id,
                "name": name,
                "base_url": base_url,
                "provider": provider,
                "panel_version": panel_version,
                "api_base_path": api_base_path,
                "status_path": str(entry.get("status_path") or ("overview" if provider == "mcsmanager" else "")).strip(),
                "auth_type": auth_type,
                "api_key": api_key,
                "auth_header": auth_header,
                "auth_scheme": auth_scheme,
                "auth_query_param": auth_query_param,
                "oauth_client_id": oauth_client_id,
                "oauth_client_secret": oauth_client_secret,
                "auth_username": auth_username,
                "auth_password": auth_password,
                "amp_totp_token": amp_totp_token,
                "oauth_token_path": oauth_token_path,
                "custom_headers": dict(custom_headers),
                "client_api_key": str(entry.get("client_api_key") or "").strip(),
                "application_api_key": str(entry.get("application_api_key") or "").strip(),
                "admin_api_key": str(entry.get("admin_api_key") or "").strip(),
            }
    else:
        base_url = os.getenv("PANEL_BASE_URL", "").strip().rstrip("/")
        if base_url:
            _validate_base_url("default", base_url)
            legacy_name = os.getenv("PANEL_NAME", "Default Pterodactyl Panel").strip()
            if not legacy_name or len(legacy_name) > 128:
                raise RuntimeError("PANEL_NAME must be between 1 and 128 characters.")
            provider = normalize_provider(os.getenv("PANEL_PROVIDER", "pterodactyl"))
            if provider not in {"pterodactyl", "pelican"}:
                raise RuntimeError("Legacy single-panel variables support Pterodactyl/Pelican; use MAP_PANELS_JSON for other providers.")
            panel_version = os.getenv("PANEL_VERSION", "auto").strip().lower()
            if provider == "pterodactyl" and panel_version not in {"auto", "1", "1.x", "v1", "2", "2.x", "v2"}:
                raise RuntimeError("PANEL_VERSION must be auto, 1.x, or 2.x.")
            panels["default"] = {
                "id": "default",
                "name": legacy_name,
                "base_url": base_url,
                "provider": provider,
                "panel_version": panel_version,
                "api_base_path": "",
                "status_path": "",
                "auth_type": "bearer",
                "api_key": "",
                "auth_header": "Authorization",
                "auth_scheme": "Bearer",
                "auth_query_param": "api_key",
                "oauth_client_id": "",
                "oauth_client_secret": "",
                "auth_username": "",
                "auth_password": "",
                "amp_totp_token": "",
                "oauth_token_path": "/oauth2/token",
                "custom_headers": {},
                "client_api_key": os.getenv("PANEL_CLIENT_API_KEY", os.getenv("PANEL_API_KEY", "")).strip(),
                "application_api_key": os.getenv("PANEL_APPLICATION_API_KEY", "").strip(),
                "admin_api_key": os.getenv("PANEL_ADMIN_API_KEY", "").strip(),
            }
    return panels


def _panels() -> dict[str, dict[str, Any]]:
    return _read_panels()


def _panel(panel_id: str) -> dict[str, Any]:
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


