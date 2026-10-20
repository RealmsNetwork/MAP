"""Model Access Panel (MAP): broad Pterodactyl Client, Application, and Admin API MCP gateway."""
from __future__ import annotations

import base64
import hmac
import ipaddress
import json
import os
import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urlparse, urlunsplit

import uvicorn
from curl_cffi import requests
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

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
SENSITIVE_KEYS = ("authorization", "password", "secret", "api_key", "apikey", "access_token",
                  "refresh_token", "private_key", "client_secret", "bearer", "cookie", "token", "signature")


def _read_panels() -> dict[str, dict[str, str]]:
    """Load panel URLs and API keys from server-side environment only."""
    panels: dict[str, dict[str, str]] = {}
    raw = os.getenv("MAP_PANELS_JSON", "").strip()
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


mcp = FastMCP("Model Access Panel (MAP)", host=HOST, port=PORT)


@mcp.tool()
def list_panels() -> dict[str, Any]:
    """List configured panels and available API-key types without revealing secret values."""
    result = []
    for panel in _panels().values():
        parsed = urlparse(panel["base_url"])
        result.append({
            "id": panel["id"],
            "name": panel["name"],
            "base_url": panel["base_url"],
            "configured": bool(panel["base_url"]),
            "https": parsed.scheme == "https",
            "apis_available": {
                "client": bool(panel.get("client_api_key")),
                "application": bool(panel.get("application_api_key") or panel.get("admin_api_key")),
                "admin": bool(panel.get("admin_api_key")),
            },
        })
    return {"panels": result, "count": len(result)}


@mcp.tool()
def panel_status(panel_id: str, api: str = "application") -> dict[str, Any]:
    """Check panel API connectivity by requesting the selected API namespace root."""
    return _api_request(panel_id, api, "GET", "")


@mcp.tool()
def panel_api_request(
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
    """Request any relative Pterodactyl Client, Application, or Admin API endpoint.

    Supports read and write methods. Use the panel-version API docs to choose namespace,
    endpoint, method, query parameters, and request body. Arbitrary external URLs are rejected.
    """
    return _api_request(panel_id, api, method, path, query_params, json_body, raw_body, content_type, timeout_seconds)


@mcp.tool()
def list_servers(panel_id: str, page: int = 1, api: str = "application") -> dict[str, Any]:
    """List servers using the Application API, or the Client API when api='client'."""
    if page < 1 or page > 1000:
        raise ValueError("page must be between 1 and 1000.")
    return _api_request(panel_id, api, "GET", "servers" if api != "client" else "", {"page": page})


@mcp.tool()
def server_resources(panel_id: str, server_id: str) -> dict[str, Any]:
    """Read live resource usage and running state for a server."""
    if not SERVER_ID_RE.fullmatch(server_id or ""):
        raise ValueError("server_id contains unsupported characters.")
    return _api_request(panel_id, "client", "GET", f"servers/{server_id}/resources")


@mcp.tool()
def server_power(panel_id: str, server_id: str, signal: str) -> dict[str, Any]:
    """Start, stop, restart, or force-kill a server through the Pterodactyl Client API."""
    if not SERVER_ID_RE.fullmatch(server_id or ""):
        raise ValueError("server_id contains unsupported characters.")
    signal = signal.lower().strip()
    if signal not in {"start", "stop", "restart", "kill"}:
        raise ValueError("signal must be start, stop, restart, or kill.")
    return _api_request(panel_id, "client", "POST", f"servers/{server_id}/power", json_body={"signal": signal})


@mcp.tool()
def server_console_command(panel_id: str, server_id: str, command: str) -> dict[str, Any]:
    """Send a console command to a server. Server state and API permissions still apply."""
    if not SERVER_ID_RE.fullmatch(server_id or ""):
        raise ValueError("server_id contains unsupported characters.")
    if not command or len(command) > 10000:
        raise ValueError("command must be between 1 and 10000 characters.")
    return _api_request(panel_id, "client", "POST", f"servers/{server_id}/command", json_body={"command": command})


@mcp.tool()
def server_list_files(panel_id: str, server_id: str, directory: str = "/") -> dict[str, Any]:
    """List files and folders in a server directory."""
    if not SERVER_ID_RE.fullmatch(server_id or ""):
        raise ValueError("server_id contains unsupported characters.")
    return _api_request(panel_id, "client", "GET", f"servers/{server_id}/files/list", {"directory": directory})


@mcp.tool()
def server_read_file(panel_id: str, server_id: str, file: str) -> dict[str, Any]:
    """Read a text file from the server filesystem."""
    if not SERVER_ID_RE.fullmatch(server_id or ""):
        raise ValueError("server_id contains unsupported characters.")
    return _api_request(panel_id, "client", "GET", f"servers/{server_id}/files/contents", {"file": file})


@mcp.tool()
def server_write_file(panel_id: str, server_id: str, file: str, content: str) -> dict[str, Any]:
    """Create or overwrite a text file on a server. Panel permissions apply."""
    if not SERVER_ID_RE.fullmatch(server_id or ""):
        raise ValueError("server_id contains unsupported characters.")
    if len(content.encode("utf-8")) > 2_000_000:
        raise ValueError("Text file content exceeds MAP's 2 MB inline write limit.")
    return _api_request(
        panel_id, "client", "POST", f"servers/{server_id}/files/write",
        {"file": file}, raw_body=content, content_type="text/plain; charset=utf-8",
    )


@mcp.tool()
def server_create_directory(panel_id: str, server_id: str, name: str, root: str = "/") -> dict[str, Any]:
    """Create a directory in the server filesystem."""
    if not SERVER_ID_RE.fullmatch(server_id or ""):
        raise ValueError("server_id contains unsupported characters.")
    return _api_request(panel_id, "client", "POST", f"servers/{server_id}/files/create-folder",
                        json_body={"name": name, "root": root})


@mcp.tool()
def server_delete_files(panel_id: str, server_id: str, files: list[str], root: str = "/") -> dict[str, Any]:
    """Delete selected server files or folders permanently."""
    if not SERVER_ID_RE.fullmatch(server_id or ""):
        raise ValueError("server_id contains unsupported characters.")
    if not files or len(files) > 500:
        raise ValueError("files must contain between 1 and 500 paths.")
    return _api_request(panel_id, "client", "POST", f"servers/{server_id}/files/delete",
                        json_body={"root": root, "files": files})


@mcp.tool()
def server_rename_files(panel_id: str, server_id: str, root: str, files: list[dict[str, str]]) -> dict[str, Any]:
    """Rename or move files using a list of from/to pairs."""
    if not SERVER_ID_RE.fullmatch(server_id or ""):
        raise ValueError("server_id contains unsupported characters.")
    if not files or len(files) > 200:
        raise ValueError("files must contain between 1 and 200 rename pairs.")
    for item in files:
        if not isinstance(item, dict) or not item.get("from") or not item.get("to"):
            raise ValueError("Each rename pair must contain non-empty from and to fields.")
    return _api_request(panel_id, "client", "PUT", f"servers/{server_id}/files/rename",
                        json_body={"root": root, "files": files})


@mcp.tool()
def server_create_backup(panel_id: str, server_id: str, name: str | None = None, ignored: list[str] | None = None) -> dict[str, Any]:
    """Start a backup for a server."""
    if not SERVER_ID_RE.fullmatch(server_id or ""):
        raise ValueError("server_id contains unsupported characters.")
    body: dict[str, Any] = {}
    if name:
        body["name"] = name[:191]
    if ignored:
        body["ignored"] = ignored
    return _api_request(panel_id, "client", "POST", f"servers/{server_id}/backups", json_body=body)


@mcp.tool()
def server_list_backups(panel_id: str, server_id: str) -> dict[str, Any]:
    """List backups registered for a server."""
    if not SERVER_ID_RE.fullmatch(server_id or ""):
        raise ValueError("server_id contains unsupported characters.")
    return _api_request(panel_id, "client", "GET", f"servers/{server_id}/backups")


@mcp.tool()
def server_delete_backup(panel_id: str, server_id: str, backup_id: str) -> dict[str, Any]:
    """Delete a server backup by UUID. This is destructive."""
    if not SERVER_ID_RE.fullmatch(server_id or ""):
        raise ValueError("server_id contains unsupported characters.")
    if not SERVER_ID_RE.fullmatch(backup_id or ""):
        raise ValueError("backup_id contains unsupported characters.")
    return _api_request(panel_id, "client", "DELETE", f"servers/{server_id}/backups/{backup_id}")



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


@mcp.tool()
def server_upload_file_base64(
    panel_id: str,
    server_id: str,
    filename: str,
    content_base64: str,
    directory: str = "/",
) -> dict[str, Any]:
    """Upload a binary or text file to a server using base64 content and a signed Wings upload URL.

    Only the filename, not a local filesystem path, should be supplied. Wings hosts must be listed
    in MAP_TRUSTED_WINGS_HOSTS unless they use the exact same hostname as the panel.
    """
    if not SERVER_ID_RE.fullmatch(server_id or ""):
        raise ValueError("server_id contains unsupported characters.")
    if not filename or filename in {".", ".."} or "/" in filename or "\\" in filename or len(filename) > 255:
        raise ValueError("filename must be a single basename, not a path.")
    try:
        contents = base64.b64decode(content_base64, validate=True)
    except Exception as exc:
        raise ValueError("content_base64 must be valid base64.") from exc
    if not contents:
        raise ValueError("Refusing to upload an empty file.")
    if len(contents) > MAX_INLINE_FILE_BYTES:
        raise ValueError(f"File exceeds MAP_MAX_INLINE_FILE_BYTES ({MAX_INLINE_FILE_BYTES}).")
    url, error = _signed_wings_url(panel_id, server_id, "upload", {"directory": directory})
    if error:
        return error
    try:
        response = requests.post(
            url,
            files={"files": (filename, contents, "application/octet-stream")},
            data={"directory": directory},
            impersonate=IMPERSONATE,
            timeout=90,
            allow_redirects=False,
        )
    except Exception as exc:
        raise RuntimeError(f"Wings upload failed ({type(exc).__name__}). Signed URL and credentials were not logged.") from None
    return {
        "ok": 200 <= response.status_code < 300,
        "status_code": response.status_code,
        "filename": filename,
        "directory": directory,
        "bytes_uploaded": len(contents),
    }


@mcp.tool()
def server_download_file_base64(
    panel_id: str,
    server_id: str,
    file: str,
) -> dict[str, Any]:
    """Download a small file from a server and return its content as base64.

    Inline downloads are capped by MAP_MAX_INLINE_FILE_BYTES. Signed Wings URLs are never returned
    to the MCP caller; MAP follows them only for explicitly trusted Wings hostnames.
    """
    url, error = _signed_wings_url(panel_id, server_id, "download", {"file": file})
    if error:
        return error
    try:
        response = requests.get(
            url,
            impersonate=IMPERSONATE,
            timeout=60,
            allow_redirects=False,
            stream=True,
        )
        if not 200 <= response.status_code < 300:
            response.close()
            return {"ok": False, "status_code": response.status_code, "error": "Wings refused the download."}
        length = response.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_INLINE_FILE_BYTES:
            response.close()
            return {
                "ok": False,
                "status_code": 413,
                "error": f"File exceeds the inline download limit of {MAX_INLINE_FILE_BYTES} bytes.",
            }
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(chunk_size=65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > MAX_INLINE_FILE_BYTES:
                response.close()
                return {
                    "ok": False,
                    "status_code": 413,
                    "error": f"File exceeds the inline download limit of {MAX_INLINE_FILE_BYTES} bytes.",
                }
            chunks.append(chunk)
        response.close()
    except Exception as exc:
        raise RuntimeError(f"Wings download failed ({type(exc).__name__}). Signed URL and credentials were not logged.") from None
    return {
        "ok": True,
        "status_code": response.status_code,
        "file": file,
        "bytes_downloaded": total,
        "content_base64": base64.b64encode(b"".join(chunks)).decode("ascii"),
    }


class BearerGuard:
    """Static bearer-token guard for remote MCP transport."""

    def __init__(self, app: Any, token: str):
        self.app = app
        self.token = token

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http" or not self.token:
            await self.app(scope, receive, send)
            return
        provided = ""
        for key, value in scope.get("headers", []):
            if key.lower() == b"authorization":
                text_value = value.decode("latin1")
                if text_value.lower().startswith("bearer "):
                    provided = text_value[7:].strip()
                break
        if not hmac.compare_digest(provided, self.token):
            body = b'{"error":"Unauthorized"}'
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
            })
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)


if __name__ == "__main__":
    if HOST not in {"127.0.0.1", "::1", "localhost"} and not MCP_BEARER_TOKEN:
        raise SystemExit("MAP_MCP_BEARER_TOKEN is required when MAP_HOST is not localhost.")
    if MCP_BEARER_TOKEN and len(MCP_BEARER_TOKEN) < 32:
        raise SystemExit("MAP_MCP_BEARER_TOKEN must be at least 32 characters.")
    application = BearerGuard(mcp.streamable_http_app(), MCP_BEARER_TOKEN)
    uvicorn.run(application, host=HOST, port=PORT, log_level=os.getenv("MAP_LOG_LEVEL", "info"))
