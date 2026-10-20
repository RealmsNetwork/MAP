"""MCP tool registration and command-line entry point for Model Access Panel."""
from __future__ import annotations

import argparse
import base64
import os
from typing import Any
from urllib.parse import urlparse

import uvicorn
from curl_cffi import requests
from mcp.server.fastmcp import FastMCP

from .client import _api_request, _safe_json, _signed_wings_url
from .config import (
    HOST,
    IMPERSONATE,
    MAX_INLINE_FILE_BYTES,
    MAP_SERVER_NAME,
    MCP_BEARER_TOKEN,
    PORT,
    SERVER_ID_RE,
    SUPPORTED_APIS,
    SUPPORTED_METHODS,
    _panel,
    _panels,
    _token_for,
)
from .security import BearerGuard


mcp = FastMCP(MAP_SERVER_NAME, host=HOST, port=PORT)


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


__all__ = [
    "mcp", "list_panels", "panel_status", "panel_api_request", "list_servers",
    "server_resources", "server_power", "server_console_command", "server_list_files",
    "server_read_file", "server_write_file", "server_create_directory", "server_delete_files",
    "server_rename_files", "server_create_backup", "server_list_backups", "server_delete_backup",
    "server_upload_file_base64", "server_download_file_base64", "BearerGuard",
    "_safe_json", "_panel", "_panels", "_token_for", "SUPPORTED_APIS", "SUPPORTED_METHODS",
]


def main() -> None:
    """Run MAP over HTTP or the local stdio MCP transport."""
    parser = argparse.ArgumentParser(description="Model Access Panel MCP server")
    parser.add_argument(
        "--transport",
        choices=("http", "stdio"),
        default=os.getenv("MAP_TRANSPORT", "http").strip().lower(),
        help="MCP transport (default: MAP_TRANSPORT or http)",
    )
    args = parser.parse_args()
    if args.transport == "stdio":
        mcp.run(transport="stdio")
        return
    if HOST not in {"127.0.0.1", "::1", "localhost"} and len(MCP_BEARER_TOKEN) < 32:
        raise SystemExit("MAP_MCP_BEARER_TOKEN (at least 32 characters) is required for non-loopback HTTP binds.")
    if MCP_BEARER_TOKEN and len(MCP_BEARER_TOKEN) < 32:
        raise SystemExit("MAP_MCP_BEARER_TOKEN must be at least 32 characters.")
    application = BearerGuard(mcp.streamable_http_app(), MCP_BEARER_TOKEN)
    uvicorn.run(application, host=HOST, port=PORT, log_level=os.getenv("MAP_LOG_LEVEL", "info"))


if __name__ == "__main__":
    main()
