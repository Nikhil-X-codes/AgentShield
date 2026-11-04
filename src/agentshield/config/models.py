"""Validated project configuration with deny-by-default scope rules."""

from __future__ import annotations

import os
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from agentshield.errors import ConfigurationError, ScopeViolation
from agentshield.taxonomy import ATTACK_CATEGORIES, DEFAULT_CATEGORIES


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        return os.path.expandvars(value)
    if isinstance(value, list):
        return [_expand(item) for item in value]
    if isinstance(value, dict):
        return {key: _expand(item) for key, item in value.items()}
    return value


@dataclass(frozen=True)
class TargetConfig:
    adapter: str
    base_url: str = ""
    timeout_seconds: float = 10.0
    fixture: str = "mock"
    profile: str = "agentshield"
    model: str = ""
    auth_token_env: str = ""


@dataclass(frozen=True)
class MCPServerConfig:
    server_url: str = ""
    timeout_seconds: float = 10.0
    auth_token_env: str = ""


@dataclass(frozen=True)
class ScopeConfig:
    allowed_hosts: tuple[str, ...]
    allowed_tools: tuple[str, ...] = ()
    allow_real_side_effects: bool = False
    use_mock_tools: bool = True

    def validate_target(self, target: TargetConfig) -> None:
        if target.adapter.startswith("mock"):
            return
        if not target.base_url:
            raise ScopeViolation("A non-mock target requires an explicit base_url.")
        self.validate_url(target.base_url)

    def validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query:
            raise ScopeViolation("Scoped URL must be an absolute HTTP(S) URL without embedded credentials or query parameters.")
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ScopeViolation("Scoped URL contains an invalid port.") from exc
        if parsed.hostname.lower() not in {host.lower() for host in self.allowed_hosts}:
            raise ScopeViolation("URL hostname is not present in scope.allowed_hosts.")

    def permits_tool(self, name: str) -> bool:
        return name in self.allowed_tools


@dataclass(frozen=True)
class TestingConfig:
    categories: tuple[str, ...] = DEFAULT_CATEGORIES
    generated_variants_per_category: int = 0
    adaptive_retries: int = 0
    max_total_tests: int = 40
    max_requests_per_minute: int = 30
    max_wall_clock_seconds: int = 300
    max_total_tokens: int = 12000


@dataclass(frozen=True)
class ModelConfig:
    provider: str = "none"
    attack_model: str = ""
    judge_model: str = ""
    max_tokens: int = 1200
    timeout_seconds: float = 20.0


@dataclass(frozen=True)
class PolicyConfig:
    sensitive_tools: tuple[str, ...] = ()
    require_approval: tuple[str, ...] = ()
    default_tool_policy: str = "deny"


@dataclass(frozen=True)
class ThresholdConfig:
    fail_on_confirmed_critical: bool = True
    max_confirmed_high: int = 0


@dataclass(frozen=True)
class ProjectConfig:
    name: str
    environment: str
    target: TargetConfig
    scope: ScopeConfig
    data_classification: str = "unknown"
    mcp: MCPServerConfig = field(default_factory=MCPServerConfig)
    testing: TestingConfig = field(default_factory=TestingConfig)
    models: ModelConfig = field(default_factory=ModelConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)

    def validate(self) -> None:
        if not self.name.strip():
            raise ConfigurationError("project.name must not be empty.")
        if self.environment.strip().lower() in {"production", "prod"}:
            raise ConfigurationError("Production targets are not supported; use an isolated test environment.")
        if self.data_classification not in {"synthetic", "redacted_synthetic", "unknown"}:
            raise ConfigurationError("project.data_classification must be synthetic, redacted_synthetic, or unknown.")
        self.scope.validate_target(self.target)
        if self.target.adapter not in {"mock", "mock_rag", "mock_mcp", "http"}:
            raise ConfigurationError("target.adapter must be 'mock', 'mock_rag', 'mock_mcp', or 'http'.")
        if self.target.profile not in {"agentshield", "openai_chat"}:
            raise ConfigurationError("target.profile must be 'agentshield' or 'openai_chat'.")
        if self.target.adapter == "http" and self.target.profile == "openai_chat" and not self.target.model:
            raise ConfigurationError("target.model is required for target.profile=openai_chat.")
        if self.target.auth_token_env and not self.target.auth_token_env.replace("_", "").isalnum():
            raise ConfigurationError("target.auth_token_env must be an environment variable name.")
        if not math.isfinite(self.target.timeout_seconds) or self.target.timeout_seconds <= 0 or self.target.timeout_seconds > 120:
            raise ConfigurationError("target.timeout_seconds must be between 0 and 120.")
        if self.mcp.server_url:
            self.scope.validate_url(self.mcp.server_url)
            if not math.isfinite(self.mcp.timeout_seconds) or not 0 < self.mcp.timeout_seconds <= 120:
                raise ConfigurationError("mcp.timeout_seconds must be in 0..120.")
            if self.mcp.auth_token_env and not self.mcp.auth_token_env.replace("_", "").isalnum():
                raise ConfigurationError("mcp.auth_token_env must be an environment variable name.")
        limits = (self.testing.generated_variants_per_category, self.testing.adaptive_retries, self.testing.max_total_tests)
        if any(value < 0 for value in limits) or self.testing.max_total_tests < 1 or self.testing.max_total_tests > 500:
            raise ConfigurationError("Testing budgets are invalid; max_total_tests must be in 1..500.")
        if self.testing.max_requests_per_minute < 1 or self.testing.max_requests_per_minute > 600:
            raise ConfigurationError("testing.max_requests_per_minute must be in 1..600.")
        if self.testing.max_wall_clock_seconds < 1 or self.testing.max_wall_clock_seconds > 3600:
            raise ConfigurationError("testing.max_wall_clock_seconds must be in 1..3600.")
        if not self.testing.categories or len(self.testing.categories) > 10 or any(category not in ATTACK_CATEGORIES for category in self.testing.categories):
            raise ConfigurationError("testing.categories contains an unknown category or exceeds the taxonomy limit.")
        if self.testing.generated_variants_per_category > 20:
            raise ConfigurationError("testing.generated_variants_per_category must not exceed 20.")
        if self.testing.max_total_tokens < 1 or self.testing.max_total_tokens > 100_000:
            raise ConfigurationError("testing.max_total_tokens must be in 1..100000.")
        if self.testing.adaptive_retries > 2:
            raise ConfigurationError("testing.adaptive_retries must not exceed 2.")
        if self.policy.default_tool_policy != "deny":
            raise ConfigurationError("policy.default_tool_policy must be 'deny'.")
        if self.scope.allow_real_side_effects:
            raise ConfigurationError("Real side effects are prohibited; configure mock tools.")
        if not self.scope.use_mock_tools:
            raise ConfigurationError("Only mock tools are supported for consequential actions.")
        if self.models.max_tokens < 1 or self.models.max_tokens > 8192:
            raise ConfigurationError("models.max_tokens must be in 1..8192.")
        if not math.isfinite(self.models.timeout_seconds) or not 0 < self.models.timeout_seconds <= 120:
            raise ConfigurationError("models.timeout_seconds must be in 0..120.")
        if self.thresholds.max_confirmed_high < 0:
            raise ConfigurationError("thresholds.max_confirmed_high must be non-negative.")


def _tuple(data: dict[str, Any], key: str) -> tuple[str, ...]:
    raw = data.get(key, [])
    if not isinstance(raw, list) or any(not isinstance(item, str) or not item for item in raw):
        raise ConfigurationError(f"{key} must be a list of non-empty strings.")
    return tuple(raw)


def _bool(data: dict[str, Any], key: str, default: bool) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise ConfigurationError(f"{key} must be a YAML boolean.")
    return value


def load_config(path: str | Path) -> ProjectConfig:
    """Load YAML, expand environment references, validate schema and scope."""
    config_path = Path(path)
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Could not load configuration file: {config_path}") from exc
    if not isinstance(raw, dict):
        raise ConfigurationError("Configuration root must be a YAML mapping.")
    raw = _expand(raw)
    project = raw.get("project", {})
    target = raw.get("target", {})
    scope = raw.get("scope", {})
    mcp = raw.get("mcp", {})
    testing = raw.get("testing", {})
    models = raw.get("models", {})
    policy = raw.get("policy", {})
    thresholds = raw.get("thresholds", {})
    if not all(isinstance(section, dict) for section in (project, target, scope, mcp, testing, models, policy, thresholds)):
        raise ConfigurationError("All configuration sections must be YAML mappings.")
    cfg = ProjectConfig(
        name=str(project.get("name", "")), environment=str(project.get("environment", "isolated-test")),
        target=TargetConfig(str(target.get("adapter", "mock")), str(target.get("base_url", "")), float(target.get("timeout_seconds", 10)), str(target.get("fixture", "mock")), str(target.get("profile", "agentshield")), str(target.get("model", "")), str(target.get("auth_token_env", ""))),
        scope=ScopeConfig(_tuple(scope, "allowed_hosts"), _tuple(scope, "allowed_tools"), _bool(scope, "allow_real_side_effects", False), _bool(scope, "use_mock_tools", True)),
        data_classification=str(project.get("data_classification", "synthetic" if str(target.get("adapter", "mock")).startswith("mock") else "unknown")),
        mcp=MCPServerConfig(str(mcp.get("server_url", "")), float(mcp.get("timeout_seconds", 10)), str(mcp.get("auth_token_env", ""))),
        testing=TestingConfig(_tuple(testing, "categories") if "categories" in testing else DEFAULT_CATEGORIES, int(testing.get("generated_variants_per_category", 0)), int(testing.get("adaptive_retries", 0)), int(testing.get("max_total_tests", 40)), int(testing.get("max_requests_per_minute", 30)), int(testing.get("max_wall_clock_seconds", 300)), int(testing.get("max_total_tokens", 12000))),
        models=ModelConfig(str(models.get("provider", "none")), str(models.get("attack_model", "")), str(models.get("judge_model", "")), int(models.get("max_tokens", 1200)), float(models.get("timeout_seconds", 20))),
        policy=PolicyConfig(_tuple(policy, "sensitive_tools"), _tuple(policy, "require_approval"), str(policy.get("default_tool_policy", "deny"))),
        thresholds=ThresholdConfig(_bool(thresholds, "fail_on_confirmed_critical", True), int(thresholds.get("max_confirmed_high", 0))),
    )
    cfg.validate()
    return cfg
