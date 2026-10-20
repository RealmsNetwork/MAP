"""Authentication middleware for remote HTTP MCP transports."""
from __future__ import annotations

import hmac
from typing import Any


class BearerGuard:
    """ASGI middleware requiring a matching bearer token for HTTP requests."""

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
