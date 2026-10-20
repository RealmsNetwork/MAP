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


def test_admin_methods_are_available():
    assert server.SUPPORTED_METHODS == {"GET", "POST", "PUT", "PATCH", "DELETE"}
    assert server.SUPPORTED_APIS == {"client", "application", "admin"}
    assert hasattr(server, "server_power")
    assert hasattr(server, "server_console_command")
    assert hasattr(server, "server_write_file")
    assert hasattr(server, "server_upload_file_base64")
    assert hasattr(server, "server_download_file_base64")
