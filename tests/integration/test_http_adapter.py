from __future__ import annotations

import pytest
from dataclasses import replace

from agentshield.adapters.http import HttpAgentAdapter
from agentshield.errors import AgentShieldError, ProviderError, ScopeViolation
from agentshield.execution.runner import RunBudget, run_cases
from agentshield.generation.corpus import AttackCase
from agentshield.config.models import ProjectConfig, ScopeConfig, TargetConfig
from tests.conftest import make_config


def test_local_http_target_trace_is_evaluated(mock_agent_endpoint):
    url, state = mock_agent_endpoint
    config = make_config(adapter="http", base_url=url, allowed_hosts=("127.0.0.1",))
    result = run_cases([AttackCase("http-regression", "unauthorized_tool_execution", "Try transfer", "deny_tool")], HttpAgentAdapter(config), config, run_id="local")
    assert state["requests"] == 1
    assert result.findings[0].outcome == "confirmed"
    assert result.traces[0]["tool_calls"][0]["name"] == "transfer_funds"


def test_http_adapter_rejects_out_of_scope_host():
    config = ProjectConfig("test-agent", "isolated-test", TargetConfig("http", "https://outside.example/invoke", 1.0), ScopeConfig(("inside.example",)))
    with pytest.raises(ScopeViolation):
        HttpAgentAdapter(config)


def test_http_adapter_does_not_follow_redirects(mock_agent_endpoint):
    url, _state = mock_agent_endpoint
    config = make_config(adapter="http", base_url=url, allowed_hosts=("127.0.0.1",))
    adapter = HttpAgentAdapter(config)
    adapter._url = url + "/redirect-check"
    with pytest.raises(ProviderError):
        adapter.invoke("synthetic prompt", case_id="redirect")


def test_openai_chat_profile_parses_actual_trace_and_env_auth(mock_openai_chat_endpoint, monkeypatch):
    url, state = mock_openai_chat_endpoint
    monkeypatch.setenv("AGENTSHIELD_OPENAI_TEST_TOKEN", "synthetic-test-token")
    config = make_config(adapter="http", base_url=url, allowed_hosts=("127.0.0.1",))
    config = replace(config, target=replace(config.target, profile="openai_chat", model="synthetic-chat-model", auth_token_env="AGENTSHIELD_OPENAI_TEST_TOKEN"))
    config.validate()
    response = HttpAgentAdapter(config).invoke("synthetic prompt", case_id="openai-case")
    assert state["body"]["model"] == "synthetic-chat-model"
    assert state["body"]["messages"] == [{"role": "user", "content": "synthetic prompt"}]
    assert state["authorized_header"] is True
    assert response.tool_calls[0].name == "transfer_funds"
    assert response.decisions[0].authorized is False


def test_http_adapter_timeout_is_actionable(mock_agent_endpoint):
    url, _state = mock_agent_endpoint
    config = make_config(adapter="http", base_url=url, allowed_hosts=("127.0.0.1",))
    config = replace(config, target=replace(config.target, timeout_seconds=0.05))
    with pytest.raises(ProviderError, match="request failed"):
        HttpAgentAdapter(config).invoke("synthetic prompt", case_id="slow")


def test_shared_run_budget_enforces_total_test_count():
    config = make_config(max_total_tests=1)
    budget = RunBudget(config)
    with pytest.raises(AgentShieldError):
        run_cases([AttackCase("one", "prompt_injection", "one", "review_semantics"), AttackCase("two", "prompt_injection", "two", "review_semantics")], object(), config, run_id="limit", budget=budget)
