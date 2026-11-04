"""Read-only MCP Streamable HTTP discovery client (initialize + tools/list only)."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from agentshield.config.models import ProjectConfig
from agentshield.errors import ConfigurationError, ProviderError, ScopeViolation

_PROTOCOL_VERSION = "2025-11-25"
_MAX_RESPONSE_BYTES = 1_000_000
_MAX_PAGES = 20
_MAX_TOOLS = 500


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _messages(content_type: str, body: bytes) -> list[dict[str, Any]]:
    if len(body) > _MAX_RESPONSE_BYTES:
        raise ProviderError("MCP server response exceeded the configured size limit.")
    try:
        if "text/event-stream" not in content_type.casefold():
            value = json.loads(body)
            return value if isinstance(value, list) else [value] if isinstance(value, dict) else []
        messages: list[dict[str, Any]] = []
        for event in body.decode("utf-8").replace("\r\n", "\n").split("\n\n"):
            data = "\n".join(line[5:].lstrip() for line in event.splitlines() if line.startswith("data:"))
            if data:
                value = json.loads(data)
                if isinstance(value, dict):
                    messages.append(value)
        return messages
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderError("MCP server returned invalid JSON or SSE data.") from exc


class StreamableHTTPMCPClient:
    """Minimal scoped client for MCP metadata; it never calls tools."""

    def __init__(self, config: ProjectConfig) -> None:
        if not config.mcp.server_url:
            raise ConfigurationError("Set mcp.server_url to an explicitly authorized MCP endpoint.")
        config.scope.validate_url(config.mcp.server_url)
        self._url = config.mcp.server_url
        self._timeout = config.mcp.timeout_seconds
        self._token_env = config.mcp.auth_token_env
        self._opener = urllib.request.build_opener(_NoRedirect())
        self._session_id = ""
        self._request_id = 0
        self._token = os.environ.get(self._token_env, "") if self._token_env else ""
        if self._token_env and not self._token:
            raise ConfigurationError(f"Environment variable {self._token_env} is required for the configured MCP server.")

    def _call(self, method: str, params: dict[str, Any] | None = None, *, notification: bool = False, initialize: bool = False) -> dict[str, Any] | None:
        self._request_id += 1
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if not notification:
            message["id"] = self._request_id
        if params is not None:
            message["params"] = params
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        if self._session_id:
            headers["MCP-Session-Id"] = self._session_id
            headers["MCP-Protocol-Version"] = _PROTOCOL_VERSION
        request = urllib.request.Request(self._url, data=json.dumps(message).encode("utf-8"), headers=headers, method="POST")
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                session_id = response.headers.get("MCP-Session-Id", self._session_id)
                if session_id and (len(session_id) > 256 or any(ord(char) < 0x21 or ord(char) > 0x7E for char in session_id)):
                    raise ProviderError("MCP server returned an invalid session identifier.")
                self._session_id = session_id
                payload = response.read(_MAX_RESPONSE_BYTES + 1)
                status = response.status
                content_type = response.headers.get("Content-Type", "application/json")
        except urllib.error.HTTPError as exc:
            # Do not return the response body: an untrusted server may put secrets in errors.
            raise ProviderError(f"MCP {method} request returned HTTP status {exc.code}.") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ProviderError(f"MCP {method} request failed.") from exc
        if notification:
            if status != 202:
                raise ProviderError("MCP server did not accept the initialized notification.")
            return None
        messages = _messages(content_type, payload)
        expected_id = self._request_id
        result = next((item for item in messages if item.get("id") == expected_id), None)
        if not result:
            raise ProviderError(f"MCP {method} response did not contain the matching JSON-RPC response.")
        if "error" in result:
            code = result["error"].get("code") if isinstance(result["error"], dict) else "unknown"
            raise ProviderError(f"MCP {method} failed with JSON-RPC error code {code}.")
        value = result.get("result")
        if not isinstance(value, dict):
            raise ProviderError(f"MCP {method} response has an invalid result object.")
        return value

    def list_tools(self) -> list[dict[str, Any]]:
        """Negotiate Streamable HTTP, then read all bounded tools/list pages."""
        initialized = False
        try:
            init = self._call("initialize", {"protocolVersion": _PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": "AgentShield", "version": "0.1.0"}}, initialize=True)
            if init is None:
                raise ProviderError("MCP initialize returned no result.")
            version = init.get("protocolVersion")
            if version != _PROTOCOL_VERSION:
                raise ProviderError("MCP server selected an unsupported protocol version.")
            initialized = True
            self._call("notifications/initialized", notification=True)
            tools: list[dict[str, Any]] = []
            cursor: str | None = None
            seen_cursors: set[str] = set()
            for _ in range(_MAX_PAGES):
                params = {"cursor": cursor} if cursor else None
                page = self._call("tools/list", params)
                assert page is not None
                entries = page.get("tools")
                if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
                    raise ProviderError("MCP tools/list returned a malformed tools array.")
                tools.extend(entries)
                if len(tools) > _MAX_TOOLS:
                    raise ProviderError("MCP server exposed more tools than the configured discovery limit.")
                next_cursor = page.get("nextCursor")
                if next_cursor is None:
                    return tools
                if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen_cursors:
                    raise ProviderError("MCP server returned an invalid or repeated pagination cursor.")
                seen_cursors.add(next_cursor)
                cursor = next_cursor
            raise ProviderError("MCP tools/list exceeded the configured page limit.")
        finally:
            if initialized and self._session_id:
                self._terminate_session()

    def _terminate_session(self) -> None:
        headers = {"MCP-Session-Id": self._session_id, "MCP-Protocol-Version": _PROTOCOL_VERSION}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        request = urllib.request.Request(self._url, headers=headers, method="DELETE")
        try:
            with self._opener.open(request, timeout=min(self._timeout, 3)):
                pass
        except (urllib.error.URLError, TimeoutError, OSError):
            # Session expiry is server-managed; cleanup failures do not affect discovery results.
            return


def discover_remote_tools(config: ProjectConfig) -> list[dict[str, Any]]:
    """Fetch metadata from the configured authorized MCP server only."""
    return StreamableHTTPMCPClient(config).list_tools()
