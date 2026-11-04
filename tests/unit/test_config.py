from __future__ import annotations

import os

import pytest

from agentshield.config.models import load_config
from agentshield.config.environment import load_local_environment
from agentshield.errors import ConfigurationError, ScopeViolation
from agentshield.cli import main


def test_loads_example_config():
    config = load_config("configs/finance-agent.example.yaml")
    assert config.target.adapter == "mock"
    assert config.scope.allow_real_side_effects is False
    assert load_config("configs/rag-agent.example.yaml").target.adapter == "mock_rag"
    assert load_config("configs/mcp-agent.example.yaml").target.adapter == "mock_mcp"


def test_local_environment_loads_dotenv_without_overriding_process_values(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text('GROQ_API_KEY="local-test-key"\nGROQ_ATTACK_MODEL=openai/gpt-oss-20b\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setenv("GROQ_ATTACK_MODEL", "shell-model")

    assert load_local_environment()
    assert os.environ["GROQ_API_KEY"] == "local-test-key"
    assert os.environ["GROQ_ATTACK_MODEL"] == "shell-model"


def test_cli_loads_dotenv_from_config_directory_when_called_elsewhere(tmp_path, monkeypatch):
    project = tmp_path / "project"
    config_dir = project / "configs"
    config_dir.mkdir(parents=True)
    (project / ".env").write_text("GROQ_ATTACK_MODEL=loaded-for-cli-test\n", encoding="utf-8")
    config = config_dir / "agent.yaml"
    config.write_text("project: {name: env-test, environment: isolated-test}\ntarget: {adapter: mock}\nscope: {allowed_hosts: [], allow_real_side_effects: false, use_mock_tools: true}\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GROQ_ATTACK_MODEL", raising=False)

    assert main(["validate-config", str(config)]) == 0
    assert os.environ["GROQ_ATTACK_MODEL"] == "loaded-for-cli-test"


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
