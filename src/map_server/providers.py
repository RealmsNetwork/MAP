"""Panel provider routing and API compatibility rules."""
from __future__ import annotations

from typing import Any

PTERODACTYL_COMPATIBLE = {"pterodactyl", "pelican"}
SUPPORTED_PROVIDERS = {
    "pterodactyl",
    "pelican",
    "mcsmanager",
    "crafty",
    "pufferpanel",
    "calagopus",
    "amp",
    "generic_rest",
}
PROVIDER_ALIASES = {
    "ptero": "pterodactyl",
    "pterodactyl1": "pterodactyl",
    "pterodactyl2": "pterodactyl",
    "pterodactyl-1.x": "pterodactyl",
    "pterodactyl-2.x": "pterodactyl",
    "mcsmanager9": "mcsmanager",
    "mcsmanager10": "mcsmanager",
    "mcs-manager": "mcsmanager",
    "crafty-controller": "crafty",
    "craftycontroller": "crafty",
    "puffer-panel": "pufferpanel",
    "cube-coders-amp": "amp",
    "cubecoders_amp": "amp",
    "cagolqupus": "calagopus",
    "generic": "generic_rest",
    "rest": "generic_rest",
}

DEFAULT_API_BASE_PATH = {
    "pterodactyl": "",
    "pelican": "",
    "mcsmanager": "/api",
    "crafty": "/api/v2",
    "pufferpanel": "/api",
    "calagopus": "/api",
    "amp": "/API",
    "generic_rest": "",
}

PANEL_API_NAMESPACES = {
    "pterodactyl": {"client", "application", "admin"},
    "pelican": {"client", "application"},
}
PTERODACTYL_ACCEPT = "Application/vnd.pterodactyl.v1+json"
JSON_ACCEPT = "application/json"


def normalize_provider(value: Any) -> str:
    provider = str(value or "pterodactyl").strip().lower().replace(" ", "_")
    provider = PROVIDER_ALIASES.get(provider, provider)
    if provider not in SUPPORTED_PROVIDERS:
        supported = ", ".join(sorted(SUPPORTED_PROVIDERS))
        raise RuntimeError(f"Unsupported panel provider '{provider}'. Supported providers: {supported}.")
    return provider


def normalize_api_base_path(panel: dict[str, Any], provider: str) -> str:
    raw = str(panel.get("api_base_path", DEFAULT_API_BASE_PATH[provider]) or "").strip()
    if not raw:
        return ""
    if (
        any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in raw)
        or "?" in raw
        or "#" in raw
        or "%" in raw
        or "://" in raw
        or "\\" in raw
    ):
        raise RuntimeError(
            f"Panel '{panel.get('id', '?')}' api_base_path must be a relative URL path without encoded characters."
        )
    parts = raw.strip("/").split("/")
    if any(part in {".", ".."} for part in parts):
        raise RuntimeError(f"Panel '{panel.get('id', '?')}' api_base_path cannot contain traversal segments.")
    if len(raw) > 256:
        raise RuntimeError(f"Panel '{panel.get('id', '?')}' api_base_path is too long.")
    return "/" + "/".join(part for part in parts if part) if raw.strip("/") else ""


def _validate_relative_path(path: str) -> str:
    if not isinstance(path, str):
        raise ValueError("path must be a relative API path.")
    raw = path.strip()
    if raw.startswith("//"):
        raise ValueError("Absolute network-path URLs are not allowed.")
    relative = raw.lstrip("/")
    if (
        "://" in relative
        or "?" in relative
        or "#" in relative
        or "%" in relative
        or "\\" in relative
        or any(ord(char) < 32 for char in relative)
    ):
        raise ValueError("path must be relative; pass query parameters separately.")
    if any(segment in {".", ".."} for segment in relative.split("/")):
        raise ValueError("path cannot contain traversal segments.")
    if len(relative) > 2048:
        raise ValueError("path is too long.")
    return relative


def route_request(panel: dict[str, Any], api: str, path: str) -> tuple[str, str, str, str]:
    """Resolve provider, API namespace, and relative path into a trusted URL.

    Returns (url, api_kind, accept_header, normalized_relative_path).
    """
    provider = normalize_provider(panel.get("provider"))
    api = str(api or "").strip().lower()
    relative = _validate_relative_path(path)
    base_url = str(panel["base_url"]).rstrip("/")

    if provider in PTERODACTYL_COMPATIBLE:
        if api not in PANEL_API_NAMESPACES[provider]:
            allowed = ", ".join(sorted(PANEL_API_NAMESPACES[provider]))
            raise ValueError(f"Provider '{provider}' supports the API namespaces: {allowed}.")
        version = str(panel.get("panel_version", "auto")).lower()
        if provider == "pterodactyl" and api == "admin" and version in {"1", "1.x", "v1"}:
            raise ValueError("Pterodactyl Admin API is only available in 2.x. Use Client/Application for 1.x.")
        prefix = f"api/{api}"
        if relative == prefix:
            relative = ""
        elif relative.startswith(prefix + "/"):
            relative = relative[len(prefix) + 1:]
        url = f"{base_url}/{prefix}" + (f"/{relative}" if relative else "")
        return url, api, PTERODACTYL_ACCEPT, relative

    if api not in {"native", "custom"}:
        raise ValueError(
            f"Provider '{provider}' uses its native API. Set api='native' and pass a path from that panel's API docs."
        )

    api_base_path = normalize_api_base_path(panel, provider)
    # Accept an already-prefixed path without producing /api/api/... by accident.
    if api_base_path and (relative == api_base_path.strip("/") or relative.startswith(api_base_path.strip("/") + "/")):
        relative = relative[len(api_base_path.strip("/")):].lstrip("/")
    url = base_url + api_base_path + (f"/{relative}" if relative else "")
    return url, "native", JSON_ACCEPT, relative
