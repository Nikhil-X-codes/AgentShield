"""HTTP adapter for an explicitly allowlisted isolated test endpoint."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from agentshield.adapters.base import AgentResponse, ToolCall, ToolDecision
from agentshield.config.models import ProjectConfig
from agentshield.errors import ProviderError, ScopeViolation


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpAgentAdapter:
    """POST {prompt, case_id}; expect {text, tool_calls, decisions} JSON."""

    def __init__(self, config: ProjectConfig) -> None:
        config.scope.validate_target(config.target)
        if config.target.adapter != "http":
            raise ScopeViolation("HTTP adapter can only be used with target.adapter=http.")
        self._url = config.target.base_url
        self._timeout = config.target.timeout_seconds
        self._opener = urllib.request.build_opener(_NoRedirect())
        self._profile = config.target.profile
        self._model = config.target.model
        token = os.environ.get(config.target.auth_token_env, "") if config.target.auth_token_env else ""
        if config.target.auth_token_env and not token:
            raise ScopeViolation(f"Environment variable {config.target.auth_token_env} is required for the configured target.")
        self._auth_header = f"Bearer {token}" if token else ""

    def invoke(self, prompt: str, *, case_id: str) -> AgentResponse:
        body: dict[str, object]
        if self._profile == "openai_chat":
            body = {"model": self._model, "messages": [{"role": "user", "content": prompt}]}
        else:
            body = {"prompt": prompt, "case_id": case_id}
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._profile == "openai_chat":
            headers["X-AgentShield-Case-ID"] = case_id
        if self._auth_header:
            headers["Authorization"] = self._auth_header
        request = urllib.request.Request(self._url, data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                if response.status < 200 or response.status >= 300:
                    raise ProviderError(f"Target returned HTTP status {response.status}.")
                data = json.loads(response.read(1_000_000))
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise ProviderError("Authorized target request failed or returned invalid JSON.") from exc
        if not isinstance(data, dict):
            raise ProviderError("Target response must be a JSON object.")
        trace = data.get("tool_trace", {})
        if not isinstance(trace, dict):
            raise ProviderError("Target tool_trace must be a JSON object.")
        if self._profile == "openai_chat":
            choices = data.get("choices")
            if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict) or not isinstance(choices[0].get("message"), dict):
                raise ProviderError("OpenAI Chat Completions target returned no message choice.")
            message = choices[0]["message"]
            text = message.get("content") or ""
            calls = trace.get("calls", message.get("tool_calls", []))
            decisions = trace.get("decisions", [])
        else:
            text = data.get("text")
            calls = trace.get("calls", data.get("tool_calls", []))
            decisions = trace.get("decisions", data.get("decisions", []))
        if not isinstance(text, str):
            raise ProviderError("Target response text must be a string.")
        if not isinstance(calls, list) or not isinstance(decisions, list):
            raise ProviderError("Target tool_calls and decisions fields must be arrays.")
        parsed_calls = []
        parsed_decisions = []
        for item in calls:
            if not isinstance(item, dict):
                raise ProviderError("Target returned a malformed tool call trace.")
            function = item.get("function", item)
            name = function.get("name") if isinstance(function, dict) else None
            arguments = function.get("arguments", {}) if isinstance(function, dict) else None
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError as exc:
                    raise ProviderError("Target returned malformed JSON tool arguments.") from exc
            if not isinstance(name, str) or not isinstance(arguments, dict):
                raise ProviderError("Target returned a malformed tool call trace.")
            parsed_calls.append(ToolCall(name, arguments))
        for item in decisions:
            if not isinstance(item, dict) or not isinstance(item.get("tool_name"), str) or not isinstance(item.get("authorized"), bool) or not isinstance(item.get("reason", ""), str):
                raise ProviderError("Target returned a malformed authorization decision trace.")
            parsed_decisions.append(ToolDecision(item["tool_name"], item["authorized"], item.get("reason", "")))
        return AgentResponse(text[:8000], tuple(parsed_calls), tuple(parsed_decisions), {"adapter": "http", "profile": self._profile, "status": "success"})
