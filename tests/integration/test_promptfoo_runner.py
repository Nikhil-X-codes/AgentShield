from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentshield.errors import AgentShieldError
from agentshield.execution.promptfoo_runner import run_promptfoo
from agentshield.generation.corpus import load_baseline
from tests.conftest import make_config


def test_promptfoo_runner_parses_outputs_and_evaluates_actual_tool_trace(tmp_path, monkeypatch):
    config = make_config(adapter="http", base_url="https://test.example/invoke", allowed_hosts=("test.example",))
    case = load_baseline(["unauthorized_tool_execution"])[0]
    command_record = {}

    def fake_run(command, **kwargs):
        command_record.update(command=command, cwd=kwargs["cwd"], environment=kwargs["env"])
        output_path = Path(command[command.index("--output") + 1])
        result = {"results": {"outputs": [{"testIdx": 0, "success": True, "response": {"output": json.dumps({"text": "I refused.", "tool_calls": [{"name": "transfer_funds", "arguments": {"amount": 1}}], "decisions": [{"tool_name": "transfer_funds", "authorized": False, "reason": "synthetic denial"}]})}}]}}
        output_path.write_text(json.dumps(result), encoding="utf-8")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("agentshield.execution.promptfoo_runner.shutil.which", lambda _name: "C:/mock/promptfoo.exe")
    result = run_promptfoo([case], config, run_id="promptfoo-test", runner=fake_run)
    assert result.metadata["execution_backend"] == "promptfoo"
    assert result.findings[0].outcome == "confirmed"
    assert "--no-write" in command_record["command"]
    assert command_record["environment"]["PROMPTFOO_DISABLE_TELEMETRY"] == "1"
    assert not Path(command_record["cwd"]).exists()


def test_promptfoo_runner_refuses_mock_target():
    config = make_config()
    with pytest.raises(AgentShieldError):
        run_promptfoo(load_baseline(["prompt_injection"]), config, run_id="invalid", runner=lambda *_a, **_kw: None)


def _promptfoo_runtime_available() -> bool:
    if not ((Path.cwd() / "node_modules" / ".bin" / "promptfoo").is_file() or (Path.cwd() / "node_modules" / ".bin" / "promptfoo.cmd").is_file() or shutil.which("promptfoo")):
        return False
    node = shutil.which("node")
    if not node:
        return False
    version = subprocess.run([node, "--version"], capture_output=True, text=True, check=False).stdout.strip().lstrip("v").split(".")
    try:
        major, minor = int(version[0]), int(version[1])
    except (ValueError, IndexError):
        return False
    return major > 22 or (major == 22 and minor >= 22)


@pytest.mark.skipif(not _promptfoo_runtime_available(), reason="Pinned Promptfoo CLI requires Node 22.22+; the actual CLI round-trip runs in CI")
def test_pinned_promptfoo_cli_round_trip_to_local_synthetic_target(mock_agent_endpoint):
    url, _state = mock_agent_endpoint
    config = make_config(adapter="http", base_url=url, allowed_hosts=("127.0.0.1",))
    case = load_baseline(["unauthorized_tool_execution"])[0]
    result = run_promptfoo([case], config, run_id="promptfoo-local-e2e")
    assert result.metadata["execution_backend"] == "promptfoo"
    assert result.traces[0]["case_id"] == case.case_id
    assert result.findings[0].outcome == "confirmed"
