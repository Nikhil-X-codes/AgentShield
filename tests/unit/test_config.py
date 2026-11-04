from __future__ import annotations

import pytest

from agentshield.config.models import load_config
from agentshield.errors import ConfigurationError, ScopeViolation


def test_loads_example_config():
    config = load_config("configs/finance-agent.example.yaml")
    assert config.target.adapter == "mock"
    assert config.scope.allow_real_side_effects is False
    assert load_config("configs/rag-agent.example.yaml").target.adapter == "mock_rag"
    assert load_config("configs/mcp-agent.example.yaml").target.adapter == "mock_mcp"


def test_rejects_target_host_outside_scope(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text("project: {name: isolated, environment: isolated-test}\ntarget: {adapter: http, base_url: https://outside.example/run}\nscope: {allowed_hosts: [inside.example], allow_real_side_effects: false, use_mock_tools: true}\n", encoding="utf-8")
    with pytest.raises(ScopeViolation):
        load_config(path)


def test_rejects_production_and_real_side_effects(tmp_path):
    path = tmp_path / "unsafe.yaml"
    path.write_text("project: {name: example, environment: production}\ntarget: {adapter: mock}\nscope: {allowed_hosts: [], allow_real_side_effects: true, use_mock_tools: true}\n", encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_config(path)


def test_rejects_unknown_category_and_unbounded_adaptive_retries(tmp_path):
    for field in ("categories: [arbitrary_category]", "adaptive_retries: 3"):
        path = tmp_path / "invalid.yaml"
        path.write_text(f"project: {{name: example, environment: isolated-test}}\ntarget: {{adapter: mock}}\nscope: {{allowed_hosts: [], allow_real_side_effects: false, use_mock_tools: true}}\ntesting: {{{field}}}\n", encoding="utf-8")
        with pytest.raises(ConfigurationError):
            load_config(path)
