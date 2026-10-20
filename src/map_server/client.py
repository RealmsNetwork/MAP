"""HTTP client for authorized panel APIs and trusted Wings file transfers."""
from __future__ import annotations

import base64
import ipaddress
import os
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urlparse, urlunsplit

from curl_cffi import requests

from .config import (
    IMPERSONATE,
    MAX_INLINE_FILE_BYTES,
    MAX_RESPONSE_CHARS,
    MCP_BEARER_TOKEN,
    SERVER_ID_RE,
    SUPPORTED_APIS,
    SUPPORTED_METHODS,
    _panel,
    _panels,
    _token_for,
)

SENSITIVE_KEYS = (
    "authorization", "password", "secret", "api_key", "apikey", "access_token",
    "refresh_token", "private_key", "client_secret", "bearer", "cookie", "token", "signature",
)

def _safe_json(value: Any) -> Any:
    """Redact common credential fields while preserving useful API output."""
    if isinstance(value, dict):
        safe: dict[str, Any] = {}
        for key, item in value.items():
            lower = str(key).lower().replace("-", "_")
            if any(secret_part in lower for secret_part in SENSITIVE_KEYS):
                safe[key] = "[REDACTED]"
            else:
                safe[key] = _safe_json(item)
        return safe
    if isinstance(value, list):
        return [_safe_json(item) for item in value]
    if isinstance(value, str):
        parsed_value = urlparse(value)
        if parsed_value.scheme in {"http", "https"} and parsed_value.netloc and parsed_value.query:
            query = parse_qsl(parsed_value.query, keep_blank_values=True)
            if any(any(part in key.lower() for part in SENSITIVE_KEYS) for key, _ in query):
                query = [(key, "[REDACTED]" if any(part in key.lower() for part in SENSITIVE_KEYS) else item) for key, item in query]
                value = urlunsplit((parsed_value.scheme, parsed_value.netloc, parsed_value.path, urlencode(query), parsed_value.fragment))
        for panel in _panels().values():
            for key in ("client_api_key", "application_api_key", "admin_api_key"):
                secret = panel.get(key, "")
                if secret:
                    value = value.replace(secret, "[REDACTED]")
        return value[:MAX_RESPONSE_CHARS] + "…[truncated]" if len(value) > MAX_RESPONSE_CHARS else value
    return value


def _api_request(
    panel_id: str,
    api: str,
    method: str,
    path: str,
    query_params: dict[str, Any] | None = None,
    json_body: Any = None,
    raw_body: str | None = None,
    content_type: str | None = None,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    panel = _panel(panel_id)
    api = api.lower().strip()
    if api not in SUPPORTED_APIS:
        raise ValueError("api must be client, application, or admin.")
    method = method.upper().strip()
    if method not in SUPPORTED_METHODS:
        raise ValueError("method must be GET, POST, PUT, PATCH, or DELETE.")
    if json_body is not None and raw_body is not None:
        raise ValueError("Pass json_body or raw_body, not both.")
    if raw_body is not None and method in {"GET", "DELETE"}:
        raise ValueError("raw_body is only supported for POST, PUT, and PATCH.")
    if not isinstance(path, str):
        raise ValueError("path must be a relative API path.")
    input_path = path.strip()
    if input_path.startswith("//"):
        raise ValueError("Absolute network-path URLs are not allowed.")
    relative = input_path.lstrip("/")
    prefix = f"api/{api}"
    if relative == prefix:
        relative = ""
    elif relative.startswith(prefix + "/"):
        relative = relative[len(prefix) + 1:]
    if "://" in relative or relative.startswith("//") or "?" in relative or "#" in relative or "%" in relative or "\\" in relative:
        raise ValueError("path must be relative to the selected API namespace; pass query parameters separately.")
    decoded = unquote(relative)
    if any(segment in {".", ".."} for segment in decoded.split("/")) or "\\" in decoded:
        raise ValueError("path cannot contain traversal segments.")
    if len(relative) > 2048:
        raise ValueError("path is too long.")
    token = _token_for(panel, api)
    url = f"{panel['base_url']}/api/{api}" + (f"/{relative}" if relative else "")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "Application/vnd.pterodactyl.v1+json",
    }
    kwargs: dict[str, Any] = {
        "headers": headers,
        "params": query_params or {},
        "impersonate": IMPERSONATE,
        "timeout": max(1, min(int(timeout_seconds), 120)),
        "allow_redirects": False,
    }
    if json_body is not None:
        kwargs["json"] = json_body
        headers["Content-Type"] = "application/json"
    elif raw_body is not None:
        kwargs["data"] = raw_body.encode("utf-8")
        headers["Content-Type"] = content_type or "text/plain; charset=utf-8"
    elif content_type:
        headers["Content-Type"] = content_type
    try:
        response = requests.request(method, url, **kwargs)
    except Exception as exc:
        raise RuntimeError(
            f"Panel API transport failed ({type(exc).__name__}). Check DNS, TLS, and panel connectivity."
        ) from None
    if 300 <= response.status_code < 400:
        return {
            "ok": False,
            "status_code": response.status_code,
            "error": "Panel redirected the request; redirect following is disabled to protect API credentials.",
        }
    response_type = response.headers.get("content-type", "")
    if not response.content:
        data: Any = None
    elif "json" in response_type.lower():
        try:
            data = _safe_json(response.json())
        except ValueError:
            data = "[Panel returned invalid JSON]"
    elif "text/" in response_type.lower() or "xml" in response_type.lower():
        text_value = response.text
        for secret in (token, MCP_BEARER_TOKEN):
            if secret:
                text_value = text_value.replace(secret, "[REDACTED]")
        data = text_value[:MAX_RESPONSE_CHARS] + "…[truncated]" if len(text_value) > MAX_RESPONSE_CHARS else text_value
    else:
        data = {
            "content_type": response_type or "unknown",
            "byte_length": len(response.content),
            "note": "Binary response omitted. Use a purpose-built file transfer tool for downloads.",
        }
    return {
        "ok": 200 <= response.status_code < 300,
        "status_code": response.status_code,
        "method": method,
        "api": api,
        "path": "/" + relative,
        "data": data,
    }


def _signed_wings_url(panel_id: str, server_id: str, operation: str, query: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    if not SERVER_ID_RE.fullmatch(server_id or ""):
        raise ValueError("server_id contains unsupported characters.")
    panel = _panel(panel_id)
    token = _token_for(panel, "client")
    try:
        response = requests.get(
            f"{panel['base_url']}/api/client/servers/{server_id}/files/{operation}",
            headers={"Authorization": f"Bearer {token}", "Accept": "Application/vnd.pterodactyl.v1+json"},
            params=query,
            impersonate=IMPERSONATE,
            timeout=30,
            allow_redirects=False,
        )
    except Exception as exc:
        raise RuntimeError(f"Panel file-transfer request failed ({type(exc).__name__}).") from None
    if 300 <= response.status_code < 400:
        return None, {"ok": False, "status_code": response.status_code, "error": "Panel redirected the request; redirects are disabled."}
    if response.status_code < 200 or response.status_code >= 300:
        return None, {"ok": False, "status_code": response.status_code, "error": "Panel refused the file-transfer request."}
    try:
        payload = response.json()
        url = payload.get("attributes", {}).get("url")
    except (ValueError, AttributeError):
        url = None
    if not isinstance(url, str) or not url:
        return None, {"ok": False, "status_code": response.status_code, "error": "Panel did not return a signed file-transfer URL."}
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return None, {"ok": False, "status_code": response.status_code, "error": "The signed Wings URL is not an acceptable HTTPS URL."}
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        address = None
    if address and (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved):
        return None, {"ok": False, "status_code": response.status_code, "error": "The signed Wings URL points at a private or reserved IP."}
    panel_host = urlparse(panel["base_url"]).hostname or ""
    trusted_hosts = {panel_host.lower()}
    trusted_hosts.update(
        host.strip().lower()
        for host in os.getenv("MAP_TRUSTED_WINGS_HOSTS", "").split(",")
        if host.strip()
    )
    if parsed.hostname.lower() not in trusted_hosts:
        return None, {
            "ok": False,
            "status_code": response.status_code,
            "error": f"Wings host '{parsed.hostname}' is not trusted. Add its exact hostname to MAP_TRUSTED_WINGS_HOSTS on the EU VPS.",
        }
    return url, None
