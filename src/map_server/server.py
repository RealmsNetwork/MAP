"""MCP tool registration and command-line entry point for Model Access Panel."""
from __future__ import annotations

import argparse
import base64
import os
import re
from typing import Any
from urllib.parse import urlparse

import uvicorn
from curl_cffi import CurlMime, requests
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
from .providers import PTERODACTYL_COMPATIBLE, normalize_provider


mcp = FastMCP(
    MAP_SERVER_NAME,
    host=HOST,
    port=PORT,
    instructions=(
        "You are connected to Model Access Panel (MAP), a multi-provider panel administration MCP. "
        "Before panel-specific work, inspect list_panels, then call panel_api_schema and panel_context "
        "for the selected panel when available. Use the returned provider, version, server identifiers, "
        "feature limits, allocations, and effective per-server permissions as working context. "
        "For Pterodactyl use only configured Client/Application namespaces and Admin only on supported "
        "2.x installations; for Calagopus use native API paths under the configured API base path. "
        "panel_api_request is the general endpoint gateway for every documented endpoint the configured "
        "key can access, including network, databases, schedules, backups, users, startup, infrastructure, "
        "and administration. Never infer permissions from feature names: respect API 401/403 responses "
        "and provider-specific schemas. Calagopus and Pterodactyl are different APIs. Pterodactyl file "
        "deletion is permanent; do not claim a trash/recycle-bin feature."
    ),
)


@mcp.tool()
def list_panels() -> dict[str, Any]:
    """List configured panel providers and auth readiness without revealing credentials."""
    result = []
    for panel in _panels().values():
        provider = normalize_provider(panel.get("provider"))
        ptero_compatible = provider in PTERODACTYL_COMPATIBLE
        if ptero_compatible:
            apis_available = {
                "client": bool(panel.get("client_api_key")),
                "application": bool(panel.get("application_api_key") or panel.get("admin_api_key")),
                "admin": provider == "pterodactyl" and bool(panel.get("admin_api_key")),
            }
            api_mode = "pterodactyl_compatible"
        else:
            apis_available = {"native": bool(
                panel.get("api_key")
                or (panel.get("oauth_client_id") and panel.get("oauth_client_secret"))
                or (panel.get("auth_type") == "basic" and panel.get("auth_username") and panel.get("auth_password"))
                or (provider == "amp" and panel.get("auth_username") and panel.get("auth_password"))
                or panel.get("auth_type") == "none"
            )}
            api_mode = "native"
        result.append({
            "id": panel["id"],
            "name": panel["name"],
            "base_url": panel["base_url"],
            "provider": provider,
            "panel_version": panel.get("panel_version", "auto"),
            "api_base_path": panel.get("api_base_path", ""),
            "api_mode": api_mode,
            "configured": bool(panel["base_url"]),
            "https": urlparse(panel["base_url"]).scheme == "https",
            "auth_type": panel.get("auth_type", "bearer"),
            "apis_available": apis_available,
            "dedicated_server_tools": ptero_compatible or provider in {"mcsmanager", "calagopus"},
        })
    return {"panels": result, "count": len(result)}


def _require_panel_provider(panel_id: str, allowed: set[str], operation: str) -> dict[str, Any]:
    panel = _panel(panel_id)
    provider = normalize_provider(panel.get("provider"))
    if provider not in allowed:
        expected = ", ".join(sorted(allowed))
        raise ValueError(
            f"{operation} is not implemented for provider '{provider}'. "
            f"Supported providers for this tool: {expected}. Use panel_api_request with api='native' for other panels."
        )
    return panel


def _server_api_request(
    panel_id: str,
    server_id: str,
    method: str,
    endpoint: str,
    query_params: dict[str, Any] | None = None,
    json_body: Any = None,
    raw_body: str | None = None,
    content_type: str | None = None,
    response_mode: str = "auto",
) -> dict[str, Any]:
    """Route common server operations through the selected provider's API namespace."""
    panel = _require_panel_provider(
        panel_id, PTERODACTYL_COMPATIBLE | {"calagopus"}, "server operation"
    )
    if not SERVER_ID_RE.fullmatch(server_id or ""):
        raise ValueError("server_id contains unsupported characters.")
    provider = normalize_provider(panel.get("provider"))
    if provider in PTERODACTYL_COMPATIBLE:
        api = "client"
        path = f"servers/{server_id}/{endpoint}"
    else:
        api = "native"
        path = f"client/servers/{server_id}/{endpoint}"
    return _api_request(
        panel_id, api, method, path, query_params, json_body, raw_body,
        content_type, response_mode=response_mode,
    )


@mcp.tool()
def panel_status(panel_id: str, api: str = "auto") -> dict[str, Any]:
    """Check connectivity to the configured panel's API."""
    panel = _panel(panel_id)
    provider = normalize_provider(panel.get("provider"))
    if api == "auto":
        if provider in PTERODACTYL_COMPATIBLE:
            if panel.get("client_api_key"):
                api = "client"
                path = ""
            elif panel.get("application_api_key") or panel.get("admin_api_key"):
                api = "application"
                path = "servers"
            else:
                api = "client"
                path = ""
        else:
            api = "native"
            path = str(panel.get("status_path") or ("Core/GetStatus" if provider == "amp" else ""))
    else:
        path = ""
    if provider == "amp":
        return _api_request(panel_id, api, "POST", path, json_body={})
    return _api_request(panel_id, api, "GET", path)


@mcp.tool()
def panel_api_schema(panel_id: str) -> dict[str, Any]:
    """Inspect the provider API schema and return the version-appropriate API reference.

    Calagopus exposes a live OpenAPI document at /openapi.json when enabled.
    Pterodactyl publishes versioned official API references; panel_api_request
    can call any endpoint permitted by the selected key.
    """
    panel = _panel(panel_id)
    provider = normalize_provider(panel.get("provider"))
    version = str(panel.get("panel_version", "auto")).lower()
    if provider in PTERODACTYL_COMPATIBLE:
        apis = {
            "client": bool(panel.get("client_api_key")),
            "application": bool(panel.get("application_api_key") or panel.get("admin_api_key")),
            "admin": provider == "pterodactyl" and bool(panel.get("admin_api_key")) and version not in {"1", "1.x", "v1"},
        }
        docs_version = "v2" if version in {"2", "2.x", "v2"} else "v1"
        schema_url = (
            "https://pelican.dev/docs/panel/advanced/api-docs/"
            if provider == "pelican"
            else f"https://docs.pterodactyl.io/{docs_version}/api"
        )
        return {
            "provider": provider,
            "configured_version": version,
            "version_assumption": (
                "Configured panel_version is auto; v1 reference selected by default. Set panel_version=2.x for Pterodactyl 2.0."
                if version == "auto" else "Reference matches configured panel_version."
            ),
            "schema_type": "official_versioned_reference",
            "schema_url": schema_url,
            "api_namespaces": apis,
            "notes": [
                "Client API keys are limited to the account and server permissions of their owner.",
                "Application API keys are limited to the permissions assigned when created.",
                "Pterodactyl 2.x Admin API requires a root administrator Client API key; 1.x has no Admin API namespace.",
                "Use panel_context to inspect visible servers and per-server permissions.",
                "Use panel_api_request for any documented endpoint within a configured namespace.",
            ],
        }
    if provider == "calagopus":
        live = _api_request(panel_id, "native", "GET", "openapi.json", timeout_seconds=20)
        if live.get("ok") and isinstance(live.get("data"), dict) and "paths" in live["data"]:
            schema = live["data"]
            return {
                "provider": provider,
                "schema_type": "live_openapi_3",
                "schema_available": True,
                "openapi": schema,
                "path_count": len(schema.get("paths", {})),
                "api_documentation": panel["base_url"].rstrip("/") + "/api",
            }
        return {
            "provider": provider,
            "schema_type": "live_openapi_3",
            "schema_available": False,
            "schema_status": live.get("status_code"),
            "schema_error": live.get("data", live.get("error")),
            "api_documentation": panel["base_url"].rstrip("/") + "/api",
            "schema_endpoint": panel["base_url"].rstrip("/") + "/openapi.json",
            "api_groups": {
                "client": [
                    "account and API-key management", "server groups and server inventory",
                    "per-server resources, logs, websocket, console and power",
                    "files, settings, startup, subusers, backups and backup groups",
                    "allocations, firewall, private connections/tunnels",
                    "classic databases, managed database instances and database hosts",
                    "schedules, mounts, devices, activity and announcements",
                ],
                "admin": [
                    "panel settings, announcements, assets and extensions",
                    "locations, nodes, servers, users, roles and OAuth providers",
                    "nests, eggs, egg configurations and egg repositories",
                    "database hosts, DB Agent hosts and templates",
                    "mounts, devices, backup configurations and system backup policies",
                    "admin activity and statistics",
                ],
                "remote": ["node/Wings communication and node-scoped server operations"],
            },
            "schema_source": "Calagopus panel OpenAPI generated from backend route annotations; source: https://github.com/calagopus/panel",
            "notes": [
                "This panel did not expose its live OpenAPI JSON to the configured API request.",
                "The installed Calagopus API remains independently callable through panel_api_request; this is not a Pterodactyl-compatible API.",
                "Use panel_api_request with api='native' and documented paths. A 401/403 is the panel's permission boundary.",
            ],
        }
    return {
        "provider": provider,
        "schema_type": "provider_native",
        "schema_available": False,
        "api_base_path": panel.get("api_base_path", ""),
        "notes": ["Use panel_api_request with api='native' and the provider's documented API paths."],
    }


def _permission_catalog_names(data: Any, scopes: tuple[str, ...]) -> dict[str, dict[str, list[str]]]:
    if not isinstance(data, dict):
        return {}
    result: dict[str, dict[str, list[str]]] = {}
    for scope in scopes:
        groups = data.get(scope, {})
        if not isinstance(groups, dict):
            continue
        result[scope] = {}
        for group, definition in groups.items():
            if isinstance(definition, dict):
                permissions = definition.get("permissions", definition.get("keys", definition))
                if isinstance(permissions, dict):
                    result[scope][str(group)] = sorted(str(name) for name in permissions)
    return result


@mcp.tool()
def panel_context(panel_id: str, page: int = 1, per_page: int = 50) -> dict[str, Any]:
    """Build an API-aware inventory of visible servers, features, and effective per-server permissions."""
    if page < 1 or page > 1000 or per_page < 1 or per_page > 100:
        raise ValueError("page must be 1–1000 and per_page must be 1–100.")
    panel = _panel(panel_id)
    provider = normalize_provider(panel.get("provider"))
    if provider == "calagopus":
        listed = _api_request(
            panel_id, "native", "GET", "client/servers",
            {"page": page, "per_page": per_page, "other": False},
        )
        if not listed.get("ok"):
            return {"ok": False, "provider": provider, "server_inventory": listed}
        data = listed.get("data", {}).get("servers", {})
        servers = data.get("data", []) if isinstance(data, dict) else []
        catalog_result = _api_request(panel_id, "native", "GET", "client/permissions")
        permission_catalog = _permission_catalog_names(
            catalog_result.get("data", {}) if catalog_result.get("ok") else {},
            ("user_permissions", "admin_permissions", "server_permissions"),
        )
        return {
            "ok": True,
            "provider": provider,
            "server_inventory": {
                "total": data.get("total"),
                "page": data.get("page", page),
                "per_page": data.get("per_page", per_page),
            },
            "servers": [
                {
                    "uuid": item.get("uuid"),
                    "identifier": item.get("uuid_short"),
                    "name": item.get("name"),
                    "node": item.get("node_name"),
                    "status": item.get("status"),
                    "is_owner": item.get("is_owner"),
                    "permissions": item.get("permissions", []),
                    "limits": item.get("limits"),
                    "feature_limits": item.get("feature_limits"),
                    "allocation": item.get("allocation"),
                    "sftp": {"host": item.get("sftp_host"), "port": item.get("sftp_port")},
                }
                for item in servers if isinstance(item, dict)
            ],
            "permission_catalog": permission_catalog,
            "permission_catalog_note": "The catalog lists all defined permissions, not every granted admin permission. The server inventory carries effective per-server permissions.",
            "next": "Use panel_api_schema for the API schema and panel_api_request for additional native endpoints.",
        }
    if provider in PTERODACTYL_COMPATIBLE:
        api = "client" if panel.get("client_api_key") else "application"
        if api == "application":
            listed = _api_request(panel_id, api, "GET", "servers", {"page": page, "per_page": per_page})
        else:
            listed = _api_request(panel_id, api, "GET", "", {"page": page})
        if not listed.get("ok"):
            return {"ok": False, "provider": provider, "api": api, "server_inventory": listed}
        payload = listed.get("data", {})
        rows = payload.get("data", []) if isinstance(payload, dict) else []
        catalog_result = (
            _api_request(panel_id, "client", "GET", "permissions")
            if panel.get("client_api_key") else {}
        )
        ptero_catalog = (
            catalog_result.get("data", {}).get("attributes", {}).get("permissions", {})
            if catalog_result.get("ok") else {}
        )
        permission_catalog = _permission_catalog_names(
            {"server_permissions": ptero_catalog},
            ("server_permissions",),
        )
        output = []
        for row in rows:
            attrs = row.get("attributes", {}) if isinstance(row, dict) else {}
            identifier = attrs.get("identifier") or attrs.get("uuid")
            detail = (
                _api_request(panel_id, "client", "GET", f"servers/{identifier}")
                if identifier and panel.get("client_api_key") else {}
            )
            detail_attrs = detail.get("data", {}).get("attributes", {}) if detail.get("ok") else {}
            meta = detail.get("data", {}).get("meta", {}) if detail.get("ok") else {}
            output.append({
                "uuid": attrs.get("uuid") or detail_attrs.get("uuid"),
                "identifier": identifier,
                "name": attrs.get("name") or detail_attrs.get("name"),
                "node": attrs.get("node") or detail_attrs.get("node"),
                "status": attrs.get("status"),
                "is_owner": meta.get("is_server_owner", attrs.get("server_owner")),
                "permissions": meta.get("user_permissions", []),
                "limits": attrs.get("limits") or detail_attrs.get("limits"),
                "feature_limits": attrs.get("feature_limits") or detail_attrs.get("feature_limits"),
                "allocations": (detail_attrs.get("relationships", {}).get("allocations", {}).get("data", [])
                               if detail_attrs else attrs.get("relationships", {}).get("allocations", {}).get("data", [])),
                "detail_status": detail.get("status_code"),
            })
        return {
            "ok": True,
            "provider": provider,
            "api_used_for_listing": api,
            "server_inventory": {
                "total": payload.get("meta", {}).get("pagination", {}).get("total"),
                "page": payload.get("meta", {}).get("pagination", {}).get("current_page", page),
                "per_page": payload.get("meta", {}).get("pagination", {}).get("per_page"),
            },
            "servers": output,
            "permission_catalog": permission_catalog,
            "notes": [
                "Pterodactyl Client API server details include effective user_permissions; '*' means full permission within that server.",
                "Application API access is determined by the configured key's assigned permissions. MAP does not elevate or bypass those permissions.",
                "Use panel_api_request for every other endpoint allowed by the configured API key.",
            ],
        }
    return {
        "ok": False,
        "provider": provider,
        "note": "Context inventory is not provider-adapted yet. Use panel_api_request with api='native'.",
    }


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
    """Request a relative endpoint from any supported panel API.

    Pterodactyl/Pelican use client/application (and Pterodactyl 2.x admin) namespaces.
    Calagopus, MCSManager, Crafty, PufferPanel, AMP, and generic REST profiles use api='native'.
    The configured key's permissions remain authoritative; arbitrary external URLs are rejected.
    Writes can be destructive.
    """
    return _api_request(panel_id, api, method, path, query_params, json_body, raw_body, content_type, timeout_seconds)


@mcp.tool()
def list_servers(panel_id: str, page: int = 1, api: str = "auto") -> dict[str, Any]:
    """List servers, preferring the Client API and falling back to Application API."""
    if page < 1 or page > 1000:
        raise ValueError("page must be between 1 and 1000.")
    panel = _panel(panel_id)
    provider = normalize_provider(panel.get("provider"))
    if provider == "calagopus":
        if api not in {"auto", "application", "client", "native"}:
            raise ValueError("api must be auto, application, client, or native for Calagopus.")
        return _api_request(
            panel_id, "native", "GET", "client/servers",
            {"page": page, "per_page": 50, "other": False},
        )
    _require_panel_provider(panel_id, PTERODACTYL_COMPATIBLE, "list_servers")
    if api == "auto":
        api = "client" if panel.get("client_api_key") else "application"
    if api == "client":
        return _api_request(panel_id, api, "GET", "", {"page": page})
    if api == "application":
        return _api_request(panel_id, api, "GET", "servers", {"page": page})
    raise ValueError("api must be auto, client, or application for list_servers.")

@mcp.tool()
def mcsmanager_list_instances(
    panel_id: str, daemon_id: str, page: int = 1, page_size: int = 50
) -> dict[str, Any]:
    """List MCSManager instances for a daemon using the native MCSManager API."""
    _require_panel_provider(panel_id, {"mcsmanager"}, "mcsmanager_list_instances")
    if not daemon_id or len(daemon_id) > 256:
        raise ValueError("daemon_id must be between 1 and 256 characters.")
    if page < 1 or page > 1000 or page_size < 1 or page_size > 50:
        raise ValueError("page must be 1–1000 and page_size must be 1–50.")
    panel = _panel(panel_id)
    version = str(panel.get("panel_version", "10.x")).lower()
    daemon_param = "remote_uuid" if version in {"9", "9.x", "v9"} else "daemonId"
    return _api_request(
        panel_id, "native", "GET", "service/remote_service_instances",
        {daemon_param: daemon_id, "page": page, "page_size": page_size},
    )


@mcp.tool()
def mcsmanager_instance_action(
    panel_id: str, daemon_id: str, instance_uuid: str, action: str
) -> dict[str, Any]:
    """Start, stop, restart, or kill an MCSManager instance using its native API."""
    _require_panel_provider(panel_id, {"mcsmanager"}, "mcsmanager_instance_action")
    if not daemon_id or len(daemon_id) > 256:
        raise ValueError("daemon_id must be between 1 and 256 characters.")
    if not SERVER_ID_RE.fullmatch(instance_uuid or ""):
        raise ValueError("instance_uuid contains unsupported characters.")
    action = action.strip().lower()
    routes = {"start": "open", "stop": "stop", "restart": "restart", "kill": "kill"}
    if action not in routes:
        raise ValueError("action must be start, stop, restart, or kill.")
    panel = _panel(panel_id)
    version = str(panel.get("panel_version", "10.x")).lower()
    is_v9 = version in {"9", "9.x", "v9"}
    daemon_param = "remote_uuid" if is_v9 else "daemonId"
    # Use POST for state-changing actions on both generations. MCSManager 10.x
    # accepts multiple verbs on this route, while 9.x documentation specifically
    # shows POST. The daemon selector name remains version-dependent.
    method = "POST"
    return _api_request(
        panel_id, "native", method, f"protected_instance/{routes[action]}",
        {"uuid": instance_uuid, daemon_param: daemon_id},
    )


@mcp.tool()
def mcsmanager_instance_command(
    panel_id: str, daemon_id: str, instance_uuid: str, command: str
) -> dict[str, Any]:
    """Send a command to an MCSManager instance through its native HTTP API."""
    _require_panel_provider(panel_id, {"mcsmanager"}, "mcsmanager_instance_command")
    if not daemon_id or len(daemon_id) > 256:
        raise ValueError("daemon_id must be between 1 and 256 characters.")
    if not SERVER_ID_RE.fullmatch(instance_uuid or ""):
        raise ValueError("instance_uuid contains unsupported characters.")
    if not command or len(command) > 10000:
        raise ValueError("command must be between 1 and 10000 characters.")
    panel = _panel(panel_id)
    version = str(panel.get("panel_version", "10.x")).lower()
    daemon_param = "remote_uuid" if version in {"9", "9.x", "v9"} else "daemonId"
    return _api_request(
        panel_id, "native", "GET", "protected_instance/command",
        {"uuid": instance_uuid, daemon_param: daemon_id, "command": command},
    )


@mcp.tool()
def mcsmanager_instance_output_log(
    panel_id: str, daemon_id: str, instance_uuid: str, size: str = "10KB"
) -> dict[str, Any]:
    """Read the recent output log for an MCSManager instance."""
    _require_panel_provider(panel_id, {"mcsmanager"}, "mcsmanager_instance_output_log")
    if not daemon_id or len(daemon_id) > 256:
        raise ValueError("daemon_id must be between 1 and 256 characters.")
    if not SERVER_ID_RE.fullmatch(instance_uuid or ""):
        raise ValueError("instance_uuid contains unsupported characters.")
    if not re.fullmatch(r"\d+(?:KB)?", size.strip().upper()):
        raise ValueError("size must be a byte count or a value such as 10KB.")
    panel = _panel(panel_id)
    version = str(panel.get("panel_version", "10.x")).lower()
    daemon_param = "remote_uuid" if version in {"9", "9.x", "v9"} else "daemonId"
    return _api_request(
        panel_id, "native", "GET", "protected_instance/outputlog",
        {"uuid": instance_uuid, daemon_param: daemon_id, "size": size.strip().upper()},
    )


@mcp.tool()
def server_resources(panel_id: str, server_id: str) -> dict[str, Any]:
    """Read live resource usage and running state for a server."""
    return _server_api_request(panel_id, server_id, "GET", "resources")

@mcp.tool()
def server_power(panel_id: str, server_id: str, signal: str) -> dict[str, Any]:
    """Start, stop, restart, or force-kill a server through its provider API."""
    action = signal.lower().strip()
    if action not in {"start", "stop", "restart", "kill"}:
        raise ValueError("signal must be start, stop, restart, or kill.")
    provider = normalize_provider(_panel(panel_id).get("provider"))
    body = {"signal": action} if provider in PTERODACTYL_COMPATIBLE else {"action": action}
    return _server_api_request(panel_id, server_id, "POST", "power", json_body=body)

@mcp.tool()
def server_console_command(panel_id: str, server_id: str, command: str) -> dict[str, Any]:
    """Send a console command to a server. Server state and API permissions still apply."""
    if not command or len(command) > 10000:
        raise ValueError("command must be between 1 and 10000 characters.")
    return _server_api_request(
        panel_id, server_id, "POST", "command", json_body={"command": command}
    )

@mcp.tool()
def server_list_files(
    panel_id: str, server_id: str, directory: str = "/", page: int = 1, per_page: int = 100
) -> dict[str, Any]:
    """List files and folders in a server directory, with pagination on Calagopus."""
    if page < 1 or page > 1000 or per_page < 1 or per_page > 1000:
        raise ValueError("page must be 1–1000 and per_page must be 1–1000.")
    provider = normalize_provider(_panel(panel_id).get("provider"))
    params = {"directory": directory}
    if provider == "calagopus":
        params.update({"page": page, "per_page": per_page})
    return _server_api_request(panel_id, server_id, "GET", "files/list", params)

@mcp.tool()
def server_read_file(panel_id: str, server_id: str, file: str) -> dict[str, Any]:
    """Read a UTF-8 text file, including Calagopus files served as octet-stream."""
    if not file or len(file) > 4096:
        raise ValueError("file must be between 1 and 4096 characters.")
    provider = normalize_provider(_panel(panel_id).get("provider"))
    return _server_api_request(
        panel_id, server_id, "GET", "files/contents", {"file": file},
        response_mode="text" if provider == "calagopus" else "auto",
    )

@mcp.tool()
def server_write_file(panel_id: str, server_id: str, file: str, content: str) -> dict[str, Any]:
    """Create or overwrite a UTF-8 text file on a server. Panel permissions apply."""
    if not file or len(file) > 4096:
        raise ValueError("file must be between 1 and 4096 characters.")
    if len(content.encode("utf-8")) > 2_000_000:
        raise ValueError("Text file content exceeds MAP's 2 MB inline write limit.")
    return _server_api_request(
        panel_id, server_id, "POST", "files/write", {"file": file},
        raw_body=content, content_type="text/plain; charset=utf-8",
    )

@mcp.tool()
def server_create_directory(panel_id: str, server_id: str, name: str, root: str = "/") -> dict[str, Any]:
    """Create a directory in the server filesystem."""
    provider = normalize_provider(_panel(panel_id).get("provider"))
    if provider == "calagopus":
        return _server_api_request(
            panel_id, server_id, "POST", "files/create-directory",
            json_body={"name": name, "root": root},
        )
    return _server_api_request(
        panel_id, server_id, "POST", "files/create-folder",
        json_body={"name": name, "root": root},
    )

@mcp.tool()
def server_delete_files(
    panel_id: str, server_id: str, files: list[str], root: str = "/", permanent: bool = False
) -> dict[str, Any]:
    """Delete selected server files or folders; Calagopus uses its trash unless permanent is true."""
    if not files or len(files) > 500:
        raise ValueError("files must contain between 1 and 500 paths.")
    provider = normalize_provider(_panel(panel_id).get("provider"))
    body: dict[str, Any] = {"root": root, "files": files}
    if provider == "calagopus":
        body["permanent"] = bool(permanent)
    return _server_api_request(
        panel_id, server_id, "POST", "files/delete", json_body=body
    )

@mcp.tool()
def server_rename_files(
    panel_id: str, server_id: str, root: str, files: list[dict[str, str]]
) -> dict[str, Any]:
    """Rename or move files using a list of from/to pairs."""
    if not files or len(files) > 200:
        raise ValueError("files must contain between 1 and 200 rename pairs.")
    for item in files:
        if not isinstance(item, dict) or not item.get("from") or not item.get("to"):
            raise ValueError("Each rename pair must contain non-empty from and to fields.")
    return _server_api_request(
        panel_id, server_id, "PUT", "files/rename",
        json_body={"root": root, "files": files},
    )

@mcp.tool()
def server_create_backup(
    panel_id: str, server_id: str, name: str | None = None, ignored: list[str] | None = None
) -> dict[str, Any]:
    """Start a server backup."""
    provider = normalize_provider(_panel(panel_id).get("provider"))
    body: dict[str, Any] = {}
    if provider == "calagopus":
        body["ignored_files"] = ignored or []
    elif ignored:
        body["ignored"] = ignored
    if name:
        body["name"] = name[:191]
    return _server_api_request(panel_id, server_id, "POST", "backups", json_body=body)

@mcp.tool()
def server_list_backups(
    panel_id: str, server_id: str, page: int = 1, per_page: int = 50
) -> dict[str, Any]:
    """List server backups, with pagination on Calagopus."""
    if page < 1 or page > 1000 or per_page < 1 or per_page > 1000:
        raise ValueError("page must be 1–1000 and per_page must be 1–1000.")
    provider = normalize_provider(_panel(panel_id).get("provider"))
    params = {"page": page, "per_page": per_page, "ungrouped": False} if provider == "calagopus" else None
    return _server_api_request(panel_id, server_id, "GET", "backups", params)

@mcp.tool()
def server_delete_backup(panel_id: str, server_id: str, backup_id: str) -> dict[str, Any]:
    """Delete a server backup by ID. This is destructive."""
    if not SERVER_ID_RE.fullmatch(backup_id or ""):
        raise ValueError("backup_id contains unsupported characters.")
    return _server_api_request(
        panel_id, server_id, "DELETE", f"backups/{backup_id}"
    )

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
    if not isinstance(directory, str) or not directory or len(directory) > 4096 or "\\" in directory:
        raise ValueError("directory must be a valid server-relative path.")
    if any(part == ".." for part in directory.split("/")):
        raise ValueError("directory must not contain parent path segments.")
    if not isinstance(content_base64, str):
        raise ValueError("content_base64 must be a base64-encoded string.")
    # Reject oversized encodings before decoding them into an equally large bytes object.
    max_encoded_chars = 4 * ((MAX_INLINE_FILE_BYTES + 2) // 3)
    if len(content_base64) > max_encoded_chars:
        raise ValueError(
            f"Encoded file exceeds the inline upload limit of {MAX_INLINE_FILE_BYTES} bytes."
        )
    try:
        contents = base64.b64decode(content_base64, validate=True)
    except Exception as exc:
        raise ValueError("content_base64 must be valid base64.") from exc
    if not contents:
        raise ValueError("Refusing to upload an empty file.")
    if len(contents) > MAX_INLINE_FILE_BYTES:
        raise ValueError(f"File exceeds MAP_MAX_INLINE_FILE_BYTES ({MAX_INLINE_FILE_BYTES}).")
    provider = normalize_provider(_panel(panel_id).get("provider"))
    if provider == "calagopus":
        url, error = _signed_wings_url(panel_id, server_id, "upload", {})
    else:
        url, error = _signed_wings_url(panel_id, server_id, "upload", {"directory": directory})
    if error:
        return error
    multipart = CurlMime()
    try:
        multipart.addpart(
            name="files", filename=filename,
            content_type="application/octet-stream", data=contents,
        )
        response = requests.post(
            url,
            multipart=multipart,
            params={"directory": directory},
            impersonate=IMPERSONATE,
            timeout=90,
            allow_redirects=False,
            stream=True,
        )
        try:
            status_code = response.status_code
        finally:
            # The upload result body is deliberately unused. Do not buffer an untrusted node response.
            response.close()
    except Exception as exc:
        raise RuntimeError(f"Wings upload failed ({type(exc).__name__}). Signed URL and credentials were not logged.") from None
    finally:
        multipart.close()
    return {
        "ok": 200 <= status_code < 300,
        "status_code": status_code,
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
    if not file or len(file) > 4096 or "\\" in file:
        raise ValueError("file must be a valid server-relative path.")
    provider = normalize_provider(_panel(panel_id).get("provider"))
    if provider == "calagopus":
        normalized = file.lstrip("/")
        parts = normalized.split("/")
        if not normalized or any(part in {"", ".", ".."} for part in parts):
            raise ValueError("file must not contain empty, current, or parent path segments.")
        filename = parts[-1]
        root = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
        transfer_query = {
            "root": root, "files": [filename], "directory": False, "archive_format": "zip"
        }
    else:
        transfer_query = {"file": file}
    url, error = _signed_wings_url(panel_id, server_id, "download", transfer_query)
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
    "mcsmanager_list_instances", "mcsmanager_instance_action", "mcsmanager_instance_command",
    "mcsmanager_instance_output_log", "server_upload_file_base64", "server_download_file_base64", "BearerGuard",
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
