"""Sequential, bounded runner with redacted traces."""

from __future__ import annotations

import time
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Callable
from urllib.parse import urlsplit

from agentshield.adapters.base import AgentAdapter
from agentshield.config.models import ProjectConfig
from agentshield.errors import AgentShieldError
from agentshield.evaluation.policy import Finding, evaluate_response
from agentshield.generation.corpus import AttackCase

_SECRET_KEYS = ("authorization", "api_key", "token", "password", "secret", "credential")
_SECRET_TEXT = re.compile(r"(?i)\b(api[_ -]?key|access[_ -]?token|password|secret)\s*[:=]\s*[^\s,;]+|\bBearer\s+[A-Za-z0-9._~+/=-]+|\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{16,})")


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: "[REDACTED]" if any(part in str(key).casefold() for part in _SECRET_KEYS) else redact(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _SECRET_TEXT.sub(lambda match: (match.group(1) + "=[REDACTED]") if match.group(1) else "[REDACTED]", value[:8000])
    return value


def target_host_metadata(config: ProjectConfig) -> dict[str, str]:
    """Report only the validated hostname for an HTTP target, never credentials or URL paths."""
    if config.target.adapter != "http":
        return {}
    host = urlsplit(config.target.base_url).hostname
    return {"target_host": host} if host else {}


@dataclass(frozen=True)
class RunResult:
    run_id: str
    traces: tuple[dict[str, object], ...]
    findings: tuple[Finding, ...]
    metadata: dict[str, object]


@dataclass
class RunBudget:
    """One shared request, test-count, pacing, and wall-clock budget per run."""

    config: ProjectConfig
    started_at: float = field(default_factory=time.monotonic)
    last_request_at: float | None = None
    case_count: int = 0
    request_count: int = 0
    tokens_reserved: int = 0

    @property
    def tokens_remaining(self) -> int:
        return self.config.testing.max_total_tokens - self.tokens_reserved

    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    def before_request(self, timeout_seconds: float = 0.0, token_reservation: int = 0) -> None:
        if token_reservation < 0 or token_reservation > self.tokens_remaining:
            raise AgentShieldError("Model request would exceed testing.max_total_tokens.")
        delay = 60 / self.config.testing.max_requests_per_minute
        if self.last_request_at is not None:
            pause = max(0.0, delay - (time.monotonic() - self.last_request_at))
            if self.elapsed() + pause + timeout_seconds > self.config.testing.max_wall_clock_seconds:
                raise AgentShieldError("Request pacing or timeout would exceed the run wall-clock budget.")
            if pause:
                time.sleep(pause)
        if self.elapsed() + timeout_seconds > self.config.testing.max_wall_clock_seconds:
            raise AgentShieldError("Request timeout would exceed the run wall-clock budget.")
        self.last_request_at = time.monotonic()
        self.request_count += 1
        self.tokens_reserved += token_reservation


def run_cases(cases: list[AttackCase], adapter: AgentAdapter, config: ProjectConfig, *, run_id: str, budget: RunBudget | None = None, progress_callback: Callable[[int, int], None] | None = None) -> RunResult:
    budget = budget or RunBudget(config)
    if budget.case_count + len(cases) > config.testing.max_total_tests:
        raise AgentShieldError("Selected test count exceeds testing.max_total_tests.")
    traces: list[dict[str, object]] = []
    findings: list[Finding] = []
    for case in cases:
        if budget.case_count >= config.testing.max_total_tests:
            raise AgentShieldError("Run exceeded testing.max_total_tests.")
        budget.before_request(config.target.timeout_seconds)
        budget.case_count += 1
        response = adapter.invoke(case.prompt, case_id=case.case_id)
        trace = {"case_id": case.case_id, "category": case.category, "expected_policy": case.expected_policy, "prompt": redact(case.prompt), "response": redact(response.text),
                 "tool_calls": [{"name": call.name, "arguments": redact(call.arguments)} for call in response.tool_calls],
                 "decisions": [redact(asdict(decision)) for decision in response.decisions], "metadata": redact(response.metadata)}
        traces.append(trace)
        case_findings = evaluate_response(case, response, config)
        findings.extend(case_findings)
        if progress_callback is not None:
            progress_callback(len(traces), len(cases))
        if any(finding.outcome == "confirmed" for finding in case_findings):
            break
    return RunResult(run_id, tuple(traces), tuple(findings), {"project": config.name, "environment": config.environment, **target_host_metadata(config), "case_count": len(traces), "total_case_count": budget.case_count, "request_count": budget.request_count, "tokens_reserved": budget.tokens_reserved, "elapsed_seconds": round(budget.elapsed(), 3)})
