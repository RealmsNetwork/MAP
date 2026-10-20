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
    assert server.SUPPORTED_APIS == {"client", "application", "admin", "native"}
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


def test_list_servers_uses_servers_endpoint_for_client_api(monkeypatch):
    configured_panel(monkeypatch)
    calls = []
    response = FakeResponse(body=b'{"data":[]}')
    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return response

    monkeypatch.setattr(client.requests, "request", fake_request)
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps([{
            "id": "bp",
            "name": "ByteProject",
            "base_url": "https://panel.example.test",
            "panel_version": "1.x",
            "client_api_key": "client-secret-value",
            "application_api_key": "application-secret-value",
        }]),
    )
    result = server.list_servers("bp", api="client")

    assert result["ok"] is True
    assert calls[0][1] == "https://panel.example.test/api/client"
    assert calls[0][2]["params"] == {"page": 1}


def test_text_response_redacts_signed_urls_and_configured_keys(monkeypatch):
    configured_panel(monkeypatch)
    body = (
        "Signed URL: https://node.example.test/upload?token=signed-value&file=world.zip "
        "leaked=client-secret-value"
    ).encode("utf-8")
    response = FakeResponse(
        body=body,
        headers={"content-type": "text/plain; charset=utf-8"},
    )
    monkeypatch.setattr(client.requests, "request", lambda *args, **kwargs: response)

    result = client._api_request("bp", "client", "GET", "servers")

    assert result["ok"] is True
    assert "signed-value" not in result["data"]
    assert "[REDACTED]" in result["data"]
    assert "world.zip" in result["data"]
    assert "client-secret-value" not in result["data"]


@pytest.mark.parametrize(
    "base_url",
    [
        "http://panel.example.test",
        "https://user:password@panel.example.test",
        "https://panel.example.test/path?token=secret",
        "https://127.0.0.1",
        "https://panel.example.test:invalid",
    ],
)
def test_panel_config_rejects_unsafe_origins(monkeypatch, base_url):
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps([
            {
                "id": "bp",
                "base_url": base_url,
                "client_api_key": "client-secret-value",
            }
        ]),
    )
    with pytest.raises(RuntimeError):
        server.list_panels()


def test_panel_config_caps_number_of_panels(monkeypatch):
    panels = [
        {
            "id": f"p{index}",
            "base_url": f"https://panel-{index}.example.test",
            "client_api_key": "dummy-key",
        }
        for index in range(21)
    ]
    monkeypatch.setenv("MAP_PANELS_JSON", json.dumps(panels))
    with pytest.raises(RuntimeError, match="at most 20 panels"):
        server.list_panels()



def configured_mcsmanager(monkeypatch, **extra):
    panel = {
        "id": "mcsm",
        "name": "MCSManager",
        "provider": "mcsmanager",
        "base_url": "https://mcsm.example.test",
        "api_key": "mcsm-secret-key",
    }
    panel.update(extra)
    monkeypatch.setenv("MAP_PANELS_JSON", json.dumps([panel]))
    monkeypatch.delenv("MAP_PANELS_JSON_B64", raising=False)


def test_provider_config_defaults_to_legacy_pterodactyl(monkeypatch):
    configured_panel(monkeypatch)
    panel = server._panel("bp")
    assert panel["provider"] == "pterodactyl"
    assert server.list_panels()["panels"][0]["api_mode"] == "pterodactyl_compatible"


def test_pterodactyl_v1_blocks_admin_namespace(monkeypatch):
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps([{
            "id": "p1",
            "provider": "pterodactyl",
            "panel_version": "1.x",
            "base_url": "https://panel.example.test",
            "client_api_key": "client-key",
            "admin_api_key": "admin-key",
        }]),
    )
    with pytest.raises(ValueError, match="only available in 2.x"):
        client._api_request("p1", "admin", "GET", "eggs")


def test_mcsmanager_native_route_and_query_auth(monkeypatch):
    configured_mcsmanager(monkeypatch)
    calls = []
    response = FakeResponse(body=b'{"status":200,"data":[],"time":123}')
    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return response

    monkeypatch.setattr(client.requests, "request", fake_request)
    result = server.mcsmanager_list_instances("mcsm", "daemon-123", page=2, page_size=20)

    assert result["ok"] is True
    assert result["provider"] == "mcsmanager"
    assert calls[0][1] == "https://mcsm.example.test/api/service/remote_service_instances"
    assert calls[0][2]["params"] == {
        "daemonId": "daemon-123",
        "page": 2,
        "page_size": 20,
        "apikey": "mcsm-secret-key",
    }
    assert calls[0][2]["headers"]["X-Requested-With"] == "XMLHttpRequest"
    assert "mcsm-secret-key" not in json.dumps(result)


def test_mcsmanager_action_uses_native_endpoint(monkeypatch):
    configured_mcsmanager(monkeypatch)
    calls = []
    response = FakeResponse(body=b'{"status":200,"data":true}')
    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return response

    monkeypatch.setattr(client.requests, "request", fake_request)
    result = server.mcsmanager_instance_action("mcsm", "daemon-123", "abc12345", "start")

    assert result["ok"] is True
    assert calls[0][0] == "POST"
    assert calls[0][1] == "https://mcsm.example.test/api/protected_instance/open"
    assert calls[0][2]["params"]["uuid"] == "abc12345"
    assert calls[0][2]["params"]["daemonId"] == "daemon-123"


def test_mcsmanager_application_error_is_not_reported_as_success(monkeypatch):
    configured_mcsmanager(monkeypatch)
    response = FakeResponse(body=b'{"status":403,"data":null,"time":123}')
    monkeypatch.setattr(client.requests, "request", lambda *args, **kwargs: response)
    result = client._api_request("mcsm", "native", "GET", "overview")

    assert result["ok"] is False
    assert result["status_code"] == 200


def test_custom_rest_provider_uses_configured_prefix_and_auth(monkeypatch):
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps([{
            "id": "crafty",
            "provider": "crafty",
            "base_url": "https://crafty.example.test",
            "api_key": "crafty-token",
            "auth_type": "bearer",
        }]),
    )
    calls = []
    response = FakeResponse(body=b'{"servers":[]}')
    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return response

    monkeypatch.setattr(client.requests, "request", fake_request)
    result = client._api_request("crafty", "native", "GET", "servers")

    assert result["ok"] is True
    assert calls[0][1] == "https://crafty.example.test/api/v2/servers"
    assert calls[0][2]["headers"]["Authorization"] == "Bearer crafty-token"


def test_generic_rest_provider_supports_custom_api_path_and_header_auth(monkeypatch):
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps([{
            "id": "custom",
            "provider": "generic_rest",
            "base_url": "https://api.example.test/root",
            "api_base_path": "/v9/control",
            "api_key": "custom-key",
            "auth_type": "header",
            "auth_header": "X-API-Key",
            "auth_scheme": "",
        }]),
    )
    calls = []
    response = FakeResponse(body=b'{"ok":true}')
    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return response

    monkeypatch.setattr(client.requests, "request", fake_request)
    result = client._api_request("custom", "native", "GET", "status")

    assert result["ok"] is True
    assert calls[0][1] == "https://api.example.test/root/v9/control/status"
    assert calls[0][2]["headers"]["X-API-Key"] == "custom-key"


def test_pufferpanel_oauth_token_is_cached_and_used(monkeypatch):
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps([{
            "id": "puffer",
            "provider": "pufferpanel",
            "base_url": "https://puffer.example.test",
            "oauth_client_id": "oauth-client-id",
            "oauth_client_secret": "oauth-client-secret",
        }]),
    )
    token_calls = []
    api_calls = []

    class JsonResponse(FakeResponse):
        def json(self):
            return {"access_token": "cached-access-token", "expires_in": 3600}

    token_response = JsonResponse(body=b'{"access_token":"cached-access-token"}')
    def fake_post(url, **kwargs):
        token_calls.append((url, kwargs))
        return token_response
    def fake_request(method, url, **kwargs):
        api_calls.append((method, url, kwargs))
        return FakeResponse(body=b'{"data":[]}')
    monkeypatch.setattr(client.requests, "post", fake_post)
    monkeypatch.setattr(client.requests, "request", fake_request)
    client._OAUTH_CACHE.clear()

    client._api_request("puffer", "native", "GET", "servers")
    client._api_request("puffer", "native", "GET", "servers")

    assert len(token_calls) == 1
    assert token_calls[0][0] == "https://puffer.example.test/oauth2/token"
    assert token_calls[0][1]["data"]["grant_type"] == "client_credentials"
    assert api_calls[0][1] == "https://puffer.example.test/api/servers"
    assert api_calls[0][2]["headers"]["Authorization"] == "Bearer cached-access-token"
    assert "oauth-client-secret" not in json.dumps(server.list_panels())


def test_pterodactyl_style_tools_reject_unrelated_panel_types(monkeypatch):
    configured_mcsmanager(monkeypatch)
    with pytest.raises(ValueError, match="not implemented for provider"):
        server.server_power("mcsm", "abc12345", "start")


def test_calagopus_alias_uses_native_api_and_non_pterodactyl_auth(monkeypatch):
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps([{
            "id": "cal",
            "name": "Calagopus",
            "provider": "cagolqupus",
            "base_url": "https://calagopus.example.test",
            "api_key": "calagopus-secret-token",
        }]),
    )
    calls = []
    response = FakeResponse(body=b'{"servers":[]}')
    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return response

    monkeypatch.setattr(client.requests, "request", fake_request)
    result = client._api_request("cal", "native", "GET", "client/servers")

    assert result["ok"] is True
    assert result["provider"] == "calagopus"
    assert calls[0][1] == "https://calagopus.example.test/api/client/servers"
    assert calls[0][2]["headers"]["Authorization"] == "Bearer calagopus-secret-token"
    assert "calagopus-secret-token" not in json.dumps(server.list_panels())
    with pytest.raises(ValueError, match="not implemented for provider"):
        server.server_power("cal", "abcd1234", "start")


def test_calagopus_default_path_and_auth_configuration(monkeypatch):
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps([{
            "id": "cal",
            "provider": "calagopus",
            "base_url": "https://calagopus.example.test",
            "api_key": "calagopus-key",
        }]),
    )
    panel = server._panel("cal")
    assert panel["api_base_path"] == "/api"
    assert panel["auth_type"] == "bearer"
    assert server.list_panels()["panels"][0]["dedicated_server_tools"] is False


def test_calagopus_provider_alias_is_available_in_registry():
    from map_server.providers import normalize_provider

    assert normalize_provider("cagolqupus") == "calagopus"



def test_basic_auth_provider_header_and_redaction(monkeypatch):
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps([{
            "id": "basic",
            "provider": "generic_rest",
            "base_url": "https://basic.example.test",
            "api_base_path": "/v1",
            "auth_type": "basic",
            "auth_username": "operator",
            "auth_password": "hidden-basic-password",
        }]),
    )
    calls = []
    response = FakeResponse(
        body=b'{"ok":true,"password":"hidden-basic-password"}',
    )
    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return response

    monkeypatch.setattr(client.requests, "request", fake_request)
    result = client._api_request("basic", "native", "GET", "status")

    assert result["ok"] is True
    assert calls[0][2]["headers"]["Authorization"] == "Basic " + base64.b64encode(
        b"operator:hidden-basic-password"
    ).decode("ascii")
    assert "hidden-basic-password" not in json.dumps(result)
    assert result["data"]["password"] == "[REDACTED]"


def test_amp_session_authenticates_once_and_injects_session_id(monkeypatch):
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps([{
            "id": "amp",
            "provider": "amp",
            "base_url": "https://amp.example.test",
            "auth_type": "amp_session",
            "auth_username": "service-user",
            "auth_password": "hidden-amp-password",
        }]),
    )
    login_calls = []
    api_calls = []

    login_response = FakeResponse(
        body=b'{"sessionID":"amp-session-secret","result":"Success"}',
        headers={"content-type": "application/json"},
    )
    api_response = FakeResponse(
        body=b'{"result":"Success","SESSIONID":"amp-session-secret","state":"running"}',
        headers={"content-type": "application/json"},
    )

    def fake_post(url, **kwargs):
        login_calls.append((url, kwargs))
        return login_response

    def fake_request(method, url, **kwargs):
        api_calls.append((method, url, kwargs))
        return api_response

    monkeypatch.setattr(client.requests, "post", fake_post)
    monkeypatch.setattr(client.requests, "request", fake_request)
    client._AMP_SESSION_CACHE.clear()

    first = client._api_request("amp", "native", "POST", "Core/GetStatus", json_body={"verbose": True})
    second = client._api_request("amp", "native", "POST", "Core/GetStatus", json_body={"verbose": False})

    assert first["ok"] is True
    assert second["ok"] is True
    assert len(login_calls) == 1
    assert login_calls[0][0] == "https://amp.example.test/API/Core/Login"
    assert json.loads(login_calls[0][1]["data"])["username"] == "service-user"
    assert json.loads(login_calls[0][1]["data"].decode())["password"] == "hidden-amp-password"
    assert api_calls[0][0] == "POST"
    assert api_calls[0][1] == "https://amp.example.test/API/Core/GetStatus"
    assert json.loads(api_calls[0][2]["data"])["SESSIONID"] == "amp-session-secret"
    assert first["data"]["SESSIONID"] == "[REDACTED]"
    assert "amp-session-secret" not in json.dumps(first)
    assert "hidden-amp-password" not in json.dumps(server.list_panels())


def test_amp_native_api_requires_post_and_json_object(monkeypatch):
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps([{
            "id": "amp",
            "provider": "amp",
            "base_url": "https://amp.example.test",
            "auth_username": "service-user",
            "auth_password": "hidden-amp-password",
        }]),
    )
    with pytest.raises(ValueError, match="use POST"):
        client._api_request("amp", "native", "GET", "Core/GetStatus")
    monkeypatch.setattr(
        client.requests, "post",
        lambda *args, **kwargs: FakeResponse(body=b'{"sessionID":"amp-session","result":"Success"}'),
    )
    with pytest.raises(ValueError, match="must be an object"):
        client._api_request("amp", "native", "POST", "Core/GetStatus", json_body=["not", "an", "object"])


def test_amp_panel_credentials_are_required_and_never_exposed(monkeypatch):
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps([{
            "id": "amp",
            "provider": "amp",
            "base_url": "https://amp.example.test",
            "auth_username": "operator",
        }]),
    )
    with pytest.raises(RuntimeError, match="require auth_username and auth_password"):
        server.list_panels()


def test_pufferpanel_rejects_partial_oauth_credentials(monkeypatch):
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps([{
            "id": "puffer",
            "provider": "pufferpanel",
            "base_url": "https://puffer.example.test",
            "oauth_client_id": "only-id",
        }]),
    )
    with pytest.raises(RuntimeError, match="both oauth_client_id and oauth_client_secret"):
        server.list_panels()


def test_pufferpanel_rejects_missing_auth_credentials(monkeypatch):
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps([{
            "id": "puffer",
            "provider": "pufferpanel",
            "base_url": "https://puffer.example.test",
        }]),
    )
    with pytest.raises(RuntimeError, match="requires OAuth client credentials or a bearer api_key"):
        server.list_panels()


def test_amp_status_uses_native_post_endpoint(monkeypatch):
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps([{
            "id": "amp",
            "provider": "amp",
            "base_url": "https://amp.example.test",
            "auth_username": "service-user",
            "auth_password": "hidden-amp-password",
        }]),
    )
    calls = []
    login_response = FakeResponse(body=b'{"sessionID":"amp-session-secret","result":"Success"}')
    api_response = FakeResponse(body=b'{"result":"Success","state":"Running"}')
    monkeypatch.setattr(client.requests, "post", lambda url, **kwargs: (calls.append(("login", url, kwargs)) or login_response))
    monkeypatch.setattr(client.requests, "request", lambda method, url, **kwargs: (calls.append((method, url, kwargs)) or api_response))
    client._AMP_SESSION_CACHE.clear()

    result = server.panel_status("amp")

    assert result["ok"] is True
    assert calls[0][0] == "login"
    assert calls[1][0] == "POST"
    assert calls[1][1] == "https://amp.example.test/API/Core/GetStatus"


def test_panel_status_uses_real_application_endpoint_without_client_key(monkeypatch):
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps([{
            "id": "application-only",
            "provider": "pterodactyl",
            "base_url": "https://panel.example.test",
            "application_api_key": "application-secret-value",
        }]),
    )
    calls = []
    response = FakeResponse(body=b'{"data":[]}')
    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return response

    monkeypatch.setattr(client.requests, "request", fake_request)
    result = server.panel_status("application-only")

    assert result["ok"] is True
    assert calls[0][1] == "https://panel.example.test/api/application/servers"
    assert calls[0][2]["headers"]["Authorization"] == "Bearer application-secret-value"


def test_legacy_pterodactyl_version_setting_is_validated(monkeypatch):
    monkeypatch.setenv("PANEL_BASE_URL", "https://legacy.example.test")
    monkeypatch.setenv("PANEL_PROVIDER", "pterodactyl")
    monkeypatch.setenv("PANEL_VERSION", "not-a-version")
    monkeypatch.delenv("MAP_PANELS_JSON", raising=False)
    monkeypatch.delenv("MAP_PANELS_JSON_B64", raising=False)

    with pytest.raises(RuntimeError, match="PANEL_VERSION must be auto, 1.x, or 2.x"):
        server.list_panels()


def test_mcsmanager_9x_uses_legacy_daemon_parameter_and_post_action(monkeypatch):
    configured_mcsmanager(monkeypatch, panel_version="9.x")
    calls = []
    response = FakeResponse(body=b'{"status":200,"data":true}')
    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return response

    monkeypatch.setattr(client.requests, "request", fake_request)
    result = server.mcsmanager_instance_action("mcsm", "daemon-old", "abc12345", "start")

    assert result["ok"] is True
    assert calls[0][0] == "POST"
    assert calls[0][1] == "https://mcsm.example.test/api/protected_instance/open"
    assert calls[0][2]["params"]["remote_uuid"] == "daemon-old"
    assert "daemonId" not in calls[0][2]["params"]


def test_mcsmanager_10x_keeps_documented_get_and_daemon_id(monkeypatch):
    configured_mcsmanager(monkeypatch, panel_version="10.x")
    calls = []
    response = FakeResponse(body=b'{"status":200,"data":true}')
    monkeypatch.setattr(
        client.requests, "request",
        lambda method, url, **kwargs: (calls.append((method, url, kwargs)) or response),
    )
    server.mcsmanager_instance_action("mcsm", "daemon-new", "abc12345", "stop")

    assert calls[0][0] == "POST"
    assert calls[0][2]["params"]["daemonId"] == "daemon-new"
    assert "remote_uuid" not in calls[0][2]["params"]


def test_oauth_token_with_60_second_lifetime_is_cached_until_refresh_window(monkeypatch):
    panel = {
        "id": "short-oauth",
        "base_url": "https://oauth.example.test",
        "oauth_client_id": "client",
        "oauth_client_secret": "secret",
        "oauth_token_path": "/oauth2/token",
    }
    calls = []
    response = FakeResponse(
        body=b'{"access_token":"short-lived-token","expires_in":60}',
        headers={"content-type": "application/json"},
    )
    monkeypatch.setattr(
        client.requests, "post",
        lambda url, **kwargs: (calls.append((url, kwargs)) or response),
    )
    client._OAUTH_CACHE.clear()

    first = client._oauth_access_token(panel)
    second = client._oauth_access_token(panel)

    assert first == "short-lived-token"
    assert second == first
    assert len(calls) == 1


def test_redaction_handles_malformed_url_in_upstream_text(monkeypatch):
    configured_panel(monkeypatch)
    result = client._safe_json({"message": "bad URL https://[broken and access_key=known-secret"})
    assert "bad URL" in result["message"]
    assert "https://[broken" in result["message"]


@pytest.mark.parametrize("api_base_path", ["/api/%2e%2e/internal", "/api/../internal", "/api/\x01bad"])
def test_api_base_path_rejects_encoded_or_control_path_segments(monkeypatch, api_base_path):
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps([{
            "id": "custom",
            "provider": "generic_rest",
            "base_url": "https://api.example.test",
            "api_base_path": api_base_path,
            "auth_type": "none",
        }]),
    )
    with pytest.raises(RuntimeError, match="api_base_path"):
        server.list_panels()


def test_query_auth_token_is_included_in_size_limit(monkeypatch):
    configured_mcsmanager(monkeypatch)
    called = []
    monkeypatch.setattr(client.requests, "request", lambda *args, **kwargs: called.append(args))
    with pytest.raises(ValueError, match="including authentication"):
        client._api_request(
            "mcsm", "native", "GET", "overview",
            query_params={"x": "a" * 65510},
        )
    assert called == []


def test_signed_wings_query_is_bounded(monkeypatch):
    configured_panel(monkeypatch)
    called = []
    monkeypatch.setattr(client.requests, "get", lambda *args, **kwargs: called.append(args))
    with pytest.raises(ValueError, match="64 KB"):
        client._signed_wings_url("bp", "abc12345", "download", {"file": "x" * 65540})
    assert called == []


def test_file_upload_does_not_buffer_node_response(monkeypatch):
    import base64

    configured_panel(monkeypatch)
    monkeypatch.setattr(server, "_signed_wings_url", lambda *args, **kwargs: ("https://node.example.test/upload?token=signed", None))
    response = FakeResponse(status_code=201, body=b"x" * 100000)
    calls = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return response

    monkeypatch.setattr(server.requests, "post", fake_post)
    result = server.server_upload_file_base64("bp", "abc12345", "test.bin", base64.b64encode(b"hello").decode())

    assert result["ok"] is True
    assert result["status_code"] == 201
    assert calls[0][1]["stream"] is True
    assert response.closed is True


def test_custom_access_key_header_and_response_values_are_redacted(monkeypatch):
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps([{
            "id": "custom",
            "provider": "generic_rest",
            "base_url": "https://api.example.test",
            "auth_type": "none",
            "custom_headers": {"X-Access-Key": "custom-access-secret"},
        }]),
    )
    result = client._safe_json({
        "access_key": "custom-access-secret",
        "message": "server echoed custom-access-secret",
        "url": "https://api.example.test/status?access_key=custom-access-secret&ok=1",
    })
    assert result["access_key"] == "[REDACTED]"
    assert "custom-access-secret" not in json.dumps(result)
    assert "ok=1" in result["url"]


def test_auth_scheme_rejects_header_control_characters(monkeypatch):
    monkeypatch.setenv(
        "MAP_PANELS_JSON",
        json.dumps([{
            "id": "custom",
            "provider": "generic_rest",
            "base_url": "https://api.example.test",
            "api_key": "test-key",
            "auth_type": "bearer",
            "auth_scheme": "Bearer\r\nX-Injected: yes",
        }]),
    )
    with pytest.raises(RuntimeError, match="auth_scheme"):
        server.list_panels()
