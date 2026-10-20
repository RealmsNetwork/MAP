"""HTTP client for authorized panel APIs and trusted Wings file transfers."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import threading
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunsplit

from curl_cffi import requests

from .providers import PTERODACTYL_COMPATIBLE, normalize_provider, route_request

from .config import (
    IMPERSONATE,
    MAX_REQUEST_BODY_BYTES,
    MAX_RESPONSE_BYTES,
    MAX_RESPONSE_CHARS,
    MCP_BEARER_TOKEN,
    SERVER_ID_RE,
    SUPPORTED_METHODS,
    _panel,
    _panels,
    _token_for,
)

SENSITIVE_KEYS = (
    "authorization", "password", "secret", "api_key", "apikey", "access_token",
    "refresh_token", "private_key", "client_secret", "bearer", "cookie", "token", "signature",
    "credential", "session_id", "sessionid", "x_amz_security_token",
)



def _redact_url(value: str) -> str:
    """Redact credentials in URLs, including URLs embedded in text responses."""
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return value
    query = parse_qsl(parsed.query, keep_blank_values=True)
    def sensitive(key: str) -> bool:
        normalized = key.lower().replace("-", "_")
        return any(part.replace("-", "_") in normalized for part in SENSITIVE_KEYS)
    if any(sensitive(key) for key, _ in query):
        query = [(key, "[REDACTED]" if sensitive(key) else item) for key, item in query]
    # Never pass through user-info returned inside a URL.
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parsed.scheme, netloc, parsed.path, urlencode(query), parsed.fragment))


def _redact_text(value: str, token: str = "") -> str:
    """Redact configured secrets and credentials in any signed URLs contained in text."""
    for panel in _panels().values():
        for secret in _panel_secrets(panel):
            value = value.replace(secret, "[REDACTED]")
    for secret in (token, MCP_BEARER_TOKEN, *(item[0] for item in _OAUTH_CACHE.values()), *(item[0] for item in _AMP_SESSION_CACHE.values())):
        if secret:
            value = value.replace(secret, "[REDACTED]")

    url_pattern = re.compile(r'https?://[^\s<>"]+')
    def clean_match(match: re.Match[str]) -> str:
        url = match.group(0)
        suffix = ""
        while url and url[-1] in ".,);":
            suffix = url[-1] + suffix
            url = url[:-1]
        return _redact_url(url) + suffix

    return url_pattern.sub(clean_match, value)



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
        value = _redact_text(value)
        value = _redact_url(value)
        return value[:MAX_RESPONSE_CHARS] + "…[truncated]" if len(value) > MAX_RESPONSE_CHARS else value
    return value



_OAUTH_CACHE: dict[str, tuple[str, float]] = {}
_OAUTH_LOCK = threading.Lock()
_AMP_SESSION_CACHE: dict[str, tuple[str, float]] = {}
_AMP_SESSION_LOCK = threading.Lock()


def _oauth_access_token(panel: dict[str, Any]) -> str:
    """Fetch and cache a OAuth22 client-credentials token."""
    client_id = panel.get("oauth_client_id", "")
    client_secret = panel.get("oauth_client_secret", "")
    if not client_id or not client_secret:
        token = panel.get("api_key", "")
        if token:
            return token
        raise RuntimeError(
            f"Panel '{panel['id']}' needs oauth_client_id/oauth_client_secret or a bearer api_key."
        )
    panel_id = str(panel["id"])
    cache_key = "|".join((
        panel_id,
        str(panel.get("base_url", "")),
        str(panel.get("oauth_client_id", "")),
        hashlib.sha256(str(panel.get("oauth_client_secret", "")).encode("utf-8")).hexdigest(),
        str(panel.get("oauth_token_path", "/oauth2/token")),
    ))
    now = time.monotonic()
    cached = _OAUTH_CACHE.get(cache_key)
    if cached and cached[1] > now + 30:
        return cached[0]
    with _OAUTH_LOCK:
        now = time.monotonic()
        cached = _OAUTH_CACHE.get(cache_key)
        if cached and cached[1] > now + 30:
            return cached[0]
        url = str(panel["base_url"]).rstrip("/") + str(panel.get("oauth_token_path", "/oauth2/token"))
        try:
            response = requests.post(
                url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                },
                headers={"Accept": "application/json"},
                impersonate=IMPERSONATE,
                timeout=20,
                allow_redirects=False,
                stream=True,
            )
            try:
                if 300 <= response.status_code < 400:
                    raise RuntimeError("OAuth2 endpoint redirected; redirect following is disabled.")
                if not 200 <= response.status_code < 300:
                    raise RuntimeError(
                        f"OAuth2 token request failed with HTTP {response.status_code}."
                    )
                length = response.headers.get("content-length", "")
                if length.isdigit() and int(length) > 65536:
                    raise RuntimeError("OAuth2 response was larger than 64 KB.")
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > 65536:
                        raise RuntimeError("OAuth2 response was larger than 64 KB.")
                    chunks.append(chunk)
                payload = json.loads(b"".join(chunks).decode("utf-8"))
            finally:
                response.close()
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(f"OAuth2 request failed ({type(exc).__name__}).") from None
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise RuntimeError("OAuth2 response did not contain an access_token.")
        try:
            lifetime = max(10, int(payload.get("expires_in", 300)) - 30)
        except (TypeError, ValueError):
            lifetime = 270
        _OAUTH_CACHE[cache_key] = (token, time.monotonic() + lifetime)
        return token



def _amp_session(panel: dict[str, Any]) -> str:
    """Authenticate against CubeCoders AMP and cache its session ID."""
    panel_id = str(panel["id"])
    base_url = str(panel["base_url"]).rstrip("/")
    username = str(panel.get("auth_username", ""))
    password = str(panel.get("auth_password", ""))
    if not username or not password:
        raise RuntimeError(f"AMP panel '{panel_id}' requires auth_username and auth_password.")
    password_fingerprint = hashlib.sha256(password.encode("utf-8")).hexdigest()
    cache_key = "|".join((panel_id, base_url, username, password_fingerprint))
    now = time.monotonic()
    cached = _AMP_SESSION_CACHE.get(cache_key)
    if cached and cached[1] > now + 30:
        return cached[0]
    with _AMP_SESSION_LOCK:
        now = time.monotonic()
        cached = _AMP_SESSION_CACHE.get(cache_key)
        if cached and cached[1] > now + 30:
            return cached[0]
        payload = {
            "username": username,
            "password": password,
            "token": str(panel.get("amp_totp_token", "")),
            "rememberMe": False,
        }
        try:
            response = requests.post(
                base_url + "/API/Core/Login",
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                impersonate=IMPERSONATE,
                timeout=20,
                allow_redirects=False,
                stream=True,
            )
            try:
                if 300 <= response.status_code < 400:
                    raise RuntimeError("AMP login redirected; redirect following is disabled.")
                if not 200 <= response.status_code < 300:
                    raise RuntimeError(f"AMP login failed with HTTP {response.status_code}.")
                length = response.headers.get("content-length", "")
                if length.isdigit() and int(length) > 65536:
                    raise RuntimeError("AMP login response was larger than 64 KB.")
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > 65536:
                        raise RuntimeError("AMP login response was larger than 64 KB.")
                    chunks.append(chunk)
                payload_result = json.loads(b"".join(chunks).decode("utf-8"))
            finally:
                response.close()
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(
                f"AMP login request failed ({type(exc).__name__}). Check credentials and panel reachability."
            ) from None

        session_id = ""
        if isinstance(payload_result, dict):
            for key, value in payload_result.items():
                if key.lower() in {"sessionid", "session_id"} and isinstance(value, str):
                    session_id = value
                    break
        if not session_id:
            raise RuntimeError(
                "AMP login did not return a sessionID. Verify credentials, permissions, and any required 2FA token."
            )
        _AMP_SESSION_CACHE[cache_key] = (session_id, time.monotonic() + 1200)
        return session_id


def _panel_secrets(panel: dict[str, Any]) -> list[str]:
    """Collect configured secret values for response redaction without exposing them."""
    keys = {
        "client_api_key", "application_api_key", "admin_api_key", "api_key", "auth_token",
        "oauth_client_secret", "auth_password", "amp_totp_token",
    }
    secrets = [str(panel[key]) for key in keys if panel.get(key)]
    if panel.get("auth_type") == "basic" and panel.get("auth_username") and panel.get("auth_password"):
        pair = f"{panel['auth_username']}:{panel['auth_password']}".encode("utf-8")
        secrets.append("Basic " + base64.b64encode(pair).decode("ascii"))
    custom = panel.get("custom_headers", {})
    if isinstance(custom, dict):
        for name, value in custom.items():
            if any(word in str(name).lower().replace("-", "_") for word in SENSITIVE_KEYS):
                if isinstance(value, str) and value:
                    secrets.append(value)
    secrets.extend(value[0] for value in _OAUTH_CACHE.values())
    secrets.extend(value[0] for value in _AMP_SESSION_CACHE.values())
    return list(dict.fromkeys(secret for secret in secrets if secret))


def _apply_panel_auth(
    panel: dict[str, Any],
    api_kind: str,
    headers: dict[str, str],
    params: dict[str, Any],
) -> str:
    """Apply provider-specific auth and return the active token for response redaction."""
    provider = normalize_provider(panel.get("provider"))
    if provider in PTERODACTYL_COMPATIBLE:
        token = _token_for(panel, api_kind)
        headers["Authorization"] = f"Bearer {token}"
        return token

    auth_type = str(panel.get("auth_type", "bearer")).lower()
    token = ""
    if auth_type == "amp_session":
        token = _amp_session(panel)
    elif auth_type == "basic":
        username = str(panel.get("auth_username", ""))
        password = str(panel.get("auth_password", ""))
        if not username or not password:
            raise RuntimeError(f"Panel '{panel['id']}' requires auth_username and auth_password for Basic auth.")
        token = password
        encoded = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        headers[str(panel.get("auth_header") or "Authorization")] = f"Basic {encoded}"
    elif auth_type == "oauth2_client_credentials":
        token = _oauth_access_token(panel)
        headers[str(panel.get("auth_header") or "Authorization")] = f"Bearer {token}"
    elif auth_type == "bearer":
        token = str(panel.get("api_key", "") or panel.get("auth_token", ""))
        if not token:
            raise RuntimeError(f"Panel '{panel['id']}' has no bearer API key configured.")
        header = str(panel.get("auth_header") or "Authorization")
        scheme = str(panel.get("auth_scheme") or "Bearer").strip()
        headers[header] = f"{scheme} {token}".strip()
    elif auth_type == "header":
        token = str(panel.get("api_key", "") or panel.get("auth_token", ""))
        if not token:
            raise RuntimeError(f"Panel '{panel['id']}' has no API key configured for header authentication.")
        header = str(panel.get("auth_header") or "X-API-Key")
        scheme = str(panel.get("auth_scheme") or "").strip()
        headers[header] = f"{scheme} {token}".strip() if scheme else token
    elif auth_type == "query":
        token = str(panel.get("api_key", "") or panel.get("auth_token", ""))
        if not token:
            raise RuntimeError(f"Panel '{panel['id']}' has no API key configured for query authentication.")
        params[str(panel.get("auth_query_param") or "api_key")] = token
    elif auth_type != "none":
        raise RuntimeError(f"Panel '{panel['id']}' has unsupported auth_type '{auth_type}'.")

    if provider == "mcsmanager":
        headers.setdefault("X-Requested-With", "XMLHttpRequest")
        headers.setdefault("Content-Type", "application/json; charset=utf-8")
    return token


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
    provider = normalize_provider(panel.get("provider"))
    method = method.upper().strip()
    if method not in SUPPORTED_METHODS:
        raise ValueError("method must be GET, POST, PUT, PATCH, or DELETE.")
    if json_body is not None and raw_body is not None:
        raise ValueError("Pass json_body or raw_body, not both.")
    if raw_body is not None and method in {"GET", "DELETE"}:
        raise ValueError("raw_body is only supported for POST, PUT, and PATCH.")

    url, api_kind, accept_header, relative = route_request(panel, api, path)
    if provider == "amp":
        if method != "POST":
            raise ValueError("AMP API operations use POST requests.")
        if raw_body is not None:
            raise ValueError("AMP API calls require JSON so MAP can inject the authenticated SESSIONID.")
        if json_body is None:
            json_body = {}
        if not isinstance(json_body, dict):
            raise ValueError("AMP json_body must be an object.")
        if relative.lower() == "core/login":
            raise ValueError("AMP login is managed automatically by MAP; call the desired native API method.")
        json_body = dict(json_body)
        json_body["SESSIONID"] = _amp_session(panel)
    if query_params is not None and not isinstance(query_params, dict):
        raise ValueError("query_params must be an object.")
    params = dict(query_params or {})
    try:
        query_size = len(json.dumps(params, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError):
        raise ValueError("query_params must be JSON-serializable.") from None
    if query_size > 65536:
        raise ValueError("query_params exceeds the 64 KB input limit.")

    encoded_json: bytes | None = None
    raw_bytes: bytes | None = None
    if json_body is not None:
        try:
            encoded_json = json.dumps(
                json_body, ensure_ascii=False, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
        except (TypeError, ValueError):
            raise ValueError("json_body must be valid JSON data.") from None
        if len(encoded_json) > MAX_REQUEST_BODY_BYTES:
            raise ValueError(f"Request body exceeds MAP_MAX_REQUEST_BODY_BYTES ({MAX_REQUEST_BODY_BYTES} bytes).")
    elif raw_body is not None:
        raw_bytes = raw_body.encode("utf-8")
        if len(raw_bytes) > MAX_REQUEST_BODY_BYTES:
            raise ValueError(f"Request body exceeds MAP_MAX_REQUEST_BODY_BYTES ({MAX_REQUEST_BODY_BYTES} bytes).")

    headers: dict[str, str] = {"Accept": accept_header}
    if provider in PTERODACTYL_COMPATIBLE:
        headers["Content-Type"] = "application/json"
    custom_headers = panel.get("custom_headers", {})
    if isinstance(custom_headers, dict):
        # These hop-by-hop/routing headers are never user-overridable.
        for name, value in custom_headers.items():
            lower = str(name).lower()
            if lower in {"host", "content-length", "connection", "transfer-encoding", "proxy-authorization", "authorization"}:
                continue
            headers[str(name)] = str(value)

    token = _apply_panel_auth(panel, api_kind, headers, params)
    if encoded_json is not None:
        headers["Content-Type"] = "application/json"
    elif raw_bytes is not None:
        headers["Content-Type"] = content_type or "text/plain; charset=utf-8"
    elif content_type:
        headers["Content-Type"] = content_type

    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            params=params,
            data=encoded_json if encoded_json is not None else raw_bytes,
            impersonate=IMPERSONATE,
            timeout=max(1, min(int(timeout_seconds), 120)),
            allow_redirects=False,
            stream=True,
        )
    except Exception as exc:
        raise RuntimeError(
            f"Panel API transport failed ({type(exc).__name__}). Check DNS, TLS, and panel connectivity."
        ) from None

    try:
        if 300 <= response.status_code < 400:
            return {
                "ok": False,
                "status_code": response.status_code,
                "error": "Panel redirected the request; redirect following is disabled to protect credentials.",
            }

        response_type = response.headers.get("content-type", "")
        length = response.headers.get("content-length", "")
        if length.isdigit() and int(length) > MAX_RESPONSE_BYTES:
            return {
                "ok": False,
                "status_code": 413,
                "method": method,
                "api": api_kind,
                "path": "/" + relative,
                "error": f"Panel API response exceeds MAP_MAX_RESPONSE_BYTES ({MAX_RESPONSE_BYTES} bytes).",
            }

        chunks: list[bytes] = []
        total = 0
        try:
            for chunk in response.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    return {
                        "ok": False,
                        "status_code": 413,
                        "method": method,
                        "api": api_kind,
                        "path": "/" + relative,
                        "error": f"Panel API response exceeds MAP_MAX_RESPONSE_BYTES ({MAX_RESPONSE_BYTES} bytes).",
                    }
                chunks.append(chunk)
        except Exception as exc:
            raise RuntimeError(f"Panel API response read failed ({type(exc).__name__}).") from None
    finally:
        response.close()

    body = b"".join(chunks)
    if not body:
        data: Any = None
    elif "json" in response_type.lower():
        try:
            data = _safe_json(json.loads(body))
        except (ValueError, UnicodeDecodeError):
            data = "[Panel returned invalid JSON]"
    elif "text/" in response_type.lower() or "xml" in response_type.lower():
        text_value = _redact_text(body.decode("utf-8", errors="replace"), token=token)
        data = text_value[:MAX_RESPONSE_CHARS] + "…[truncated]" if len(text_value) > MAX_RESPONSE_CHARS else text_value
    else:
        data = {
            "content_type": response_type or "unknown",
            "byte_length": len(body),
            "note": "Binary response omitted. Use a purpose-built file transfer tool for downloads.",
        }

    # MCSManager reports application-level status in JSON, even when HTTP status is 200.
    ok = 200 <= response.status_code < 300
    if provider == "mcsmanager" and isinstance(data, dict) and isinstance(data.get("status"), int):
        ok = ok and data["status"] == 200
    if provider == "amp" and isinstance(data, dict) and "result" in data:
        ok = ok and str(data.get("result", "")).lower() in {"success", "ok"}
    return {
        "ok": ok,
        "status_code": response.status_code,
        "method": method,
        "api": api_kind,
        "provider": provider,
        "path": "/" + relative,
        "data": data,
    }


def _signed_wings_url(panel_id: str, server_id: str, operation: str, query: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    if not SERVER_ID_RE.fullmatch(server_id or ""):
        raise ValueError("server_id contains unsupported characters.")
    panel = _panel(panel_id)
    if normalize_provider(panel.get("provider")) not in PTERODACTYL_COMPATIBLE:
        raise ValueError(
            "The signed Wings upload/download tools require Pterodactyl or Pelican; use the provider's native API for other panels."
        )
    token = _token_for(panel, "client")
    try:
        response = requests.get(
            f"{panel['base_url']}/api/client/servers/{server_id}/files/{operation}",
            headers={"Authorization": f"Bearer {token}", "Accept": "Application/vnd.pterodactyl.v1+json"},
            params=query,
            impersonate=IMPERSONATE,
            timeout=30,
            allow_redirects=False,
            stream=True,
        )
    except Exception as exc:
        raise RuntimeError(f"Panel file-transfer request failed ({type(exc).__name__}).") from None
    if 300 <= response.status_code < 400:
        response.close()
        return None, {"ok": False, "status_code": response.status_code, "error": "Panel redirected the request; redirects are disabled."}
    if response.status_code < 200 or response.status_code >= 300:
        response.close()
        return None, {"ok": False, "status_code": response.status_code, "error": "Panel refused the file-transfer request."}
    try:
        length = response.headers.get("content-length", "")
        if length.isdigit() and int(length) > 65536:
            return None, {"ok": False, "status_code": response.status_code, "error": "Panel file-transfer metadata exceeded 64 KB."}
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            total += len(chunk)
            if total > 65536:
                return None, {"ok": False, "status_code": response.status_code, "error": "Panel file-transfer metadata exceeded 64 KB."}
            chunks.append(chunk)
        payload = json.loads(b"".join(chunks).decode("utf-8"))
        url = payload.get("attributes", {}).get("url")
    except (ValueError, AttributeError, UnicodeDecodeError):
        url = None
    finally:
        response.close()
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
