import asyncio
import base64
import json

import pytest

from map_server import server


def configured_panel(monkeypatch):
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps(
            [
                {
                    "id": "bp",
                    "name": "ByteProject",
                    "base_url": "https://panel.example.test",
                    "client_api_key": "client-secret-value",
                    "application_api_key": "application-secret-value",
                    "admin_api_key": "admin-secret-value",
                }
            ]
        ),
    )


def test_list_panels_never_returns_api_keys(monkeypatch):
    configured_panel(monkeypatch)
    result = server.list_panels()
    assert result["count"] == 1
    assert result["panels"][0]["apis_available"] == {
        "client": True,
        "application": True,
        "admin": True,
    }
    assert "secret-value" not in json.dumps(result)


def test_base64_environment_panel_config(monkeypatch):
    config = [{"id": "bp", "name": "ByteProject", "base_url": "https://panel.example.test", "client_api_key": "test-key"}]
    encoded = base64.b64encode(json.dumps(config).encode("utf-8")).decode("ascii")
    monkeypatch.setenv("MAP_PANELS_JSON", "")
    monkeypatch.setenv("MAP_PANELS_JSON_B64", encoded)
    result = server.list_panels()
    assert result["count"] == 1
    assert result["panels"][0]["id"] == "bp"


@pytest.mark.parametrize(
    "path",
    [
        "https://attacker.example/api/client/servers",
        "//attacker.example/api/client/servers",
        "../secrets",
        "servers/%2e%2e/secrets",
        "servers?token=secret",
    ],
)
def test_api_request_rejects_non_relative_or_traversal_paths(monkeypatch, path):
    configured_panel(monkeypatch)
    with pytest.raises(ValueError):
        server.panel_api_request("bp", "client", "GET", path)


def test_sensitive_json_fields_redacted():
    result = server._safe_json(
        {
            "name": "safe",
            "token": "very-secret",
            "attributes": {"password": "also-secret"},
            "url": "https://node.example.test/upload?token=signed-value&file=world.zip",
        }
    )
    assert result["name"] == "safe"
    assert result["token"] == "[REDACTED]"
    assert result["attributes"]["password"] == "[REDACTED]"
    assert "signed-value" not in result["url"]
    assert "world.zip" in result["url"]


def test_client_api_requires_client_key(monkeypatch):
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps([{"id": "bp", "base_url": "https://panel.example.test", "application_api_key": "app-secret"}]),
    )
    with pytest.raises(RuntimeError, match="no key configured"):
        server._token_for(server._panel("bp"), "client")


def test_remote_mcp_requires_bearer_token():
    called = {"inner": False}
    messages = []

    async def app(scope, receive, send):
        called["inner"] = True

    async def send(message):
        messages.append(message)

    async def check():
        guard = server.BearerGuard(app, "t" * 40)
        scope = {"type": "http", "headers": []}
        await guard(scope, None, send)

    asyncio.run(check())
    assert not called["inner"]
    assert messages[0]["status"] == 401


def test_admin_methods_and_full_access_tools_are_available():
    assert server.SUPPORTED_METHODS == {"GET", "POST", "PUT", "PATCH", "DELETE"}
    assert server.SUPPORTED_APIS == {"client", "application", "admin"}
    for name in (
        "panel_api_request", "server_power", "server_console_command",
        "server_write_file", "server_upload_file_base64", "server_download_file_base64",
        "server_create_backup", "server_delete_backup",
    ):
        assert hasattr(server, name)
