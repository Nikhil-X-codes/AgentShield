"""Export static test cases to Promptfoo's native YAML input format."""

from __future__ import annotations

from pathlib import Path

import yaml

from agentshield.generation.corpus import AttackCase
from agentshield.config.models import ProjectConfig


def write_promptfoo_config(cases: list[AttackCase], destination: str | Path, project_config: ProjectConfig) -> Path:
    """Write a Promptfoo HTTP provider config for the validated target endpoint."""
    if project_config.target.adapter != "http":
        raise ValueError("Promptfoo HTTP export requires target.adapter=http and an explicit scoped endpoint.")
    cases = cases[:project_config.testing.max_total_tests]
    if project_config.target.profile == "openai_chat":
        request_body = {"model": project_config.target.model, "messages": [{"role": "user", "content": "{{prompt}}"}]}
        response_transform = "JSON.stringify({text: json.choices?.[0]?.message?.content || '', tool_calls: json.tool_trace?.calls || json.tool_calls || json.choices?.[0]?.message?.tool_calls || [], decisions: json.tool_trace?.decisions || json.decisions || []})"
    else:
        request_body = {"prompt": "{{prompt}}", "case_id": "{{case_id}}"}
        response_transform = "JSON.stringify({text: json.text || '', tool_calls: json.tool_trace?.calls || json.tool_calls || [], decisions: json.tool_trace?.decisions || json.decisions || []})"
    headers = {"Content-Type": "application/json"}
    if project_config.target.profile == "openai_chat":
        headers["X-AgentShield-Case-ID"] = "{{case_id}}"
    if project_config.target.auth_token_env:
        headers["Authorization"] = f"Bearer {{{{env.{project_config.target.auth_token_env}}}}}"
    payload = {"description": "AgentShield bounded test cases (provider must target the authorized isolated agent)",
              "prompts": ["{{prompt}}"],
              "providers": [{"id": "http", "config": {"url": project_config.target.base_url, "method": "POST", "headers": headers, "body": request_body, "transformResponse": response_transform, "maxRetries": 0}}],
              "tests": [{"vars": {"prompt": case.prompt, "case_id": case.case_id, "category": case.category, "expected_policy": case.expected_policy}} for case in cases],
              "evaluateOptions": {"maxConcurrency": 1, "delay": max(1, 60_000 // project_config.testing.max_requests_per_minute), "timeoutMs": int(project_config.target.timeout_seconds * 1000), "maxEvalTimeMs": project_config.testing.max_wall_clock_seconds * 1000, "repeat": 1, "cache": False}}
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path
