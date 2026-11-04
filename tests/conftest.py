from __future__ import annotations

from agentshield.config.models import MCPServerConfig, ModelConfig, PolicyConfig, ProjectConfig, ScopeConfig, TargetConfig, TestingConfig, ThresholdConfig


def make_config(*, adapter: str = "mock", base_url: str = "", allowed_hosts: tuple[str, ...] = (), mcp: MCPServerConfig | None = None, categories: tuple[str, ...] = ("prompt_injection",), max_total_tests: int = 40, adaptive_retries: int = 0, max_requests_per_minute: int = 600, max_total_tokens: int = 12000) -> ProjectConfig:
    config = ProjectConfig(
        name="test-agent", environment="isolated-test", target=TargetConfig(adapter, base_url, 1.0, "mock"),
        scope=ScopeConfig(allowed_hosts, (), False, True), mcp=mcp or MCPServerConfig(),
        testing=TestingConfig(categories, 1, adaptive_retries, max_total_tests, max_requests_per_minute, 300, max_total_tokens),
        models=ModelConfig("none", "", "", 512, 1.0),
        policy=PolicyConfig(("transfer_funds",), ("transfer_funds",), "deny"),
        thresholds=ThresholdConfig(True, 0),
    )
    config.validate()
    return config
