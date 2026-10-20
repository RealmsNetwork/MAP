import asyncio
import base64
import json

import pytest

from map_server import client, server


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


class FakeResponse:
    def __init__(self, status_code=200, body=b'{"status":"running"}', headers=None, chunk_size=3):
        self.status_code = status_code
        self.body = body
        self.headers = headers or {"content-type": "application/json"}
        self.chunk_size = chunk_size
        self.closed = False

    def iter_content(self, chunk_size=65536):
        for offset in range(0, len(self.body), min(chunk_size, self.chunk_size)):
            yield self.body[offset:offset + min(chunk_size, self.chunk_size)]

    def close(self):
        self.closed = True


def test_api_request_routes_to_selected_panel_and_redacts(monkeypatch):
    configured_panel(monkeypatch)
    calls = []
    response = FakeResponse(body=b'{"status":"running","token":"leaked-secret"}')
    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return response

    monkeypatch.setattr(client.requests, "request", fake_request)
    result = client._api_request("bp", "client", "GET", "servers/abc/resources")

    assert result["ok"] is True
    assert result["data"]["status"] == "running"
    assert result["data"]["token"] == "[REDACTED]"
    assert calls[0][1] == "https://panel.example.test/api/client/servers/abc/resources"
    assert calls[0][2]["headers"]["Authorization"] == "Bearer client-secret-value"
    assert calls[0][2]["allow_redirects"] is False
    assert calls[0][2]["stream"] is True
    assert response.closed is True


def test_api_request_rejects_oversized_json_body(monkeypatch):
    configured_panel(monkeypatch)
    monkeypatch.setattr(client, "MAX_REQUEST_BODY_BYTES", 32)
    with pytest.raises(ValueError, match="MAP_MAX_REQUEST_BODY_BYTES"):
        client._api_request("bp", "client", "POST", "servers/abc/command", json_body={"command": "x" * 200})


def test_api_request_caps_streamed_response(monkeypatch):
    configured_panel(monkeypatch)
    monkeypatch.setattr(client, "MAX_RESPONSE_BYTES", 8)
    response = FakeResponse(body=b'{"message":"this response is too long"}')

    monkeypatch.setattr(client.requests, "request", lambda *args, **kwargs: response)
    result = client._api_request("bp", "client", "GET", "servers")

    assert result["ok"] is False
    assert result["status_code"] == 413
    assert "MAP_MAX_RESPONSE_BYTES" in result["error"]
    assert response.closed is True
