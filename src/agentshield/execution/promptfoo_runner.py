"""Run Promptfoo against the validated HTTP target and normalize observed traces."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from agentshield.adapters.base import AgentResponse, ToolCall, ToolDecision
from agentshield.config.models import ProjectConfig
from agentshield.errors import AgentShieldError, ProviderError
from agentshield.evaluation.policy import Finding, evaluate_response
from agentshield.execution.promptfoo import write_promptfoo_config
from agentshield.execution.runner import RunResult, redact
from agentshield.generation.corpus import AttackCase


def _rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        results = payload.get("results", {})
        if isinstance(results, dict):
            for key in ("outputs", "results"):
                if isinstance(results.get(key), list):
                    return results[key]
        if isinstance(results, list):
            return results
    if isinstance(payload, list):
        return payload
    raise ProviderError("Promptfoo JSON export did not contain an outputs array.")


def _agent_response(row: dict[str, Any]) -> AgentResponse:
    response = row.get("response", {})
    if not isinstance(response, dict):
        raise ValueError("response is not an object")
    output = response.get("output", "")
    if isinstance(output, str):
        output = json.loads(output)
    if not isinstance(output, dict) or not isinstance(output.get("text"), str):
        raise ValueError("normalized output must contain a text field")
    calls = output.get("tool_calls", [])
    decisions = output.get("decisions", [])
    if not isinstance(calls, list) or not isinstance(decisions, list):
        raise ValueError("normalized tool traces must be arrays")
    parsed_calls = []
    for call in calls:
        if not isinstance(call, dict):
            raise ValueError("tool call must be an object")
        function = call.get("function", call)
        if not isinstance(function, dict):
            raise ValueError("tool function must be an object")
        name, arguments = function.get("name"), function.get("arguments", {})
        if isinstance(arguments, str):
            arguments = json.loads(arguments)
        if not isinstance(name, str) or not isinstance(arguments, dict):
            raise ValueError("tool call fields are invalid")
        parsed_calls.append(ToolCall(name, arguments))
    parsed_decisions = []
    for decision in decisions:
        if not isinstance(decision, dict) or not isinstance(decision.get("tool_name"), str) or not isinstance(decision.get("authorized"), bool):
            raise ValueError("authorization decision fields are invalid")
        parsed_decisions.append(ToolDecision(decision["tool_name"], decision["authorized"], str(decision.get("reason", ""))))
    return AgentResponse(output["text"][:8000], tuple(parsed_calls), tuple(parsed_decisions), {"adapter": "promptfoo"})


def normalize_promptfoo_export(payload: Any, cases: list[AttackCase], config: ProjectConfig, *, run_id: str, elapsed_seconds: float) -> RunResult:
    """Turn Promptfoo's per-test outputs into AgentShield findings using traces."""
    rows = _rows(payload)
    if len(rows) != len(cases):
        raise ProviderError(f"Promptfoo returned {len(rows)} output rows for {len(cases)} configured cases.")
    ordered: list[dict[str, Any] | None] = [None] * len(cases)
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ProviderError("Promptfoo output row was malformed.")
        test_index = row.get("testIdx", index)
        if not isinstance(test_index, int) or not 0 <= test_index < len(cases) or ordered[test_index] is not None:
            test_index = index
        ordered[test_index] = row
    traces: list[dict[str, object]] = []
    findings: list[Finding] = []
    for index, case in enumerate(cases):
        row = ordered[index]
        if row is None:
            raise ProviderError("Promptfoo output omitted a configured test case.")
        try:
            response = _agent_response(row)
            trace = {"case_id": case.case_id, "category": case.category, "expected_policy": case.expected_policy,
                     "prompt": redact(case.prompt), "response": redact(response.text),
                     "tool_calls": [{"name": call.name, "arguments": redact(call.arguments)} for call in response.tool_calls],
                     "decisions": [redact({"tool_name": decision.tool_name, "authorized": decision.authorized, "reason": decision.reason}) for decision in response.decisions],
                     "metadata": {"adapter": "promptfoo", "provider_success": bool(row.get("success", True))}}
            findings.extend(evaluate_response(case, response, config))
        except (ValueError, TypeError, json.JSONDecodeError):
            trace = {"case_id": case.case_id, "category": case.category, "expected_policy": case.expected_policy,
                     "prompt": redact(case.prompt), "response": "", "tool_calls": [], "decisions": [],
                     "metadata": {"adapter": "promptfoo", "provider_success": False}}
            findings.append(Finding(f"{case.case_id}-promptfoo-error", case.case_id, case.category, "informational", "needs_review", "Promptfoo output could not be interpreted", "The provider returned an error or output outside the configured trace schema; inspect the isolated target adapter.", ("promptfoo.results.outputs",)))
        traces.append(trace)
    return RunResult(run_id, tuple(traces), tuple(findings), {"project": config.name, "environment": config.environment, "execution_backend": "promptfoo", "case_count": len(traces), "total_case_count": len(traces), "elapsed_seconds": round(elapsed_seconds, 3)})


def _command_prefix(resolved_executable: str, *, platform: str | None = None) -> list[str]:
    """Return a native process prefix, bypassing Windows npm .cmd shims."""
    platform = os.name if platform is None else platform
    local_launcher = Path.cwd() / "node_modules" / ".bin" / "promptfoo"
    is_local_launcher = Path(resolved_executable).resolve() == local_launcher.resolve()
    if platform == "nt" and (Path(resolved_executable).suffix.lower() in {".cmd", ".bat"} or is_local_launcher):
        node = shutil.which("node")
        entrypoint = Path.cwd() / "node_modules" / "promptfoo" / "dist" / "src" / "entrypoint.js"
        if not node or not entrypoint.is_file():
            raise ProviderError("On Windows, install the pinned local Promptfoo package and Node.js before execution.")
        return [node, str(entrypoint)]
    return [resolved_executable]


def run_promptfoo(cases: list[AttackCase], config: ProjectConfig, *, run_id: str, executable: str = "promptfoo", runner: Callable[..., Any] = subprocess.run) -> RunResult:
    """Invoke the user's Promptfoo CLI without a shell and keep raw outputs temporary."""
    if config.target.adapter != "http":
        raise AgentShieldError("Promptfoo execution requires the scoped HTTP target adapter.")
    config.scope.validate_target(config.target)
    if len(cases) > config.testing.max_total_tests:
        raise AgentShieldError("Selected test count exceeds testing.max_total_tests.")
    resolved_executable = shutil.which(executable)
    if not resolved_executable and Path(executable).is_file():
        resolved_executable = str(Path(executable).resolve())
    if not resolved_executable:
        local_bin = Path.cwd() / "node_modules" / ".bin"
        candidates = (local_bin / "promptfoo.cmd", local_bin / "promptfoo") if os.name == "nt" else (local_bin / "promptfoo",)
        resolved_executable = next((str(path.resolve()) for path in candidates if path.is_file()), "")
    if not resolved_executable:
        raise ProviderError("Promptfoo CLI was not found. Install the pinned project dependency or pass its executable path.")
    safe_cases = cases[:config.testing.max_total_tests]
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="agentshield-promptfoo-") as temp:
        workdir = Path(temp)
        config_path = write_promptfoo_config(safe_cases, workdir / "promptfooconfig.yaml", config)
        output_path = workdir / "promptfoo-results.json"
        command = [*_command_prefix(resolved_executable), "eval", "-c", str(config_path), "--output", str(output_path), "--no-write", "--no-cache", "--no-progress-bar", "--no-table"]
        environment = os.environ.copy()
        environment["PROMPTFOO_DISABLE_TELEMETRY"] = "1"
        environment["PROMPTFOO_CONFIG_DIR"] = str(workdir / "promptfoo-state")
        try:
            completed = runner(command, cwd=workdir, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, timeout=config.testing.max_wall_clock_seconds, check=False)
        except FileNotFoundError as exc:
            raise ProviderError("Promptfoo executable could not be started.") from exc
        except subprocess.TimeoutExpired as exc:
            raise ProviderError("Promptfoo exceeded testing.max_wall_clock_seconds.") from exc
        if completed.returncode != 0:
            raise ProviderError(f"Promptfoo exited with status {completed.returncode}; raw output was withheld from logs.")
        try:
            payload = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProviderError("Promptfoo did not produce a readable JSON result export.") from exc
        return normalize_promptfoo_export(payload, safe_cases, config, run_id=run_id, elapsed_seconds=time.monotonic() - started)
