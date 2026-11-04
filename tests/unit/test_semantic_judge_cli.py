from __future__ import annotations

import json

from agentshield.cli import main


def _judge_config(path, *, data_classification="synthetic"):
    path.write_text("\n".join([
        "project:", "  name: judge-test", "  environment: isolated-test", f"  data_classification: {data_classification}",
        "target:", "  adapter: mock", "  fixture: mock", "  timeout_seconds: 1",
        "scope:", "  allowed_hosts: []", "  allowed_tools: []", "  allow_real_side_effects: false", "  use_mock_tools: true",
        "testing:", "  categories: [prompt_extraction]", "  max_total_tests: 5", "  max_total_tokens: 1200", "  max_requests_per_minute: 600", "  max_wall_clock_seconds: 30",
        "models:", "  provider: groq", "  attack_model: synthetic-attack-model", "  judge_model: synthetic-judge-model", "  max_tokens: 512", "  timeout_seconds: 1",
    ]) + "\n", encoding="utf-8")


def test_judge_is_explicit_and_labeled_not_confirmed(tmp_path, monkeypatch):
    config = tmp_path / "judge.yaml"
    _judge_config(config)
    calls = []

    def fake_judge(prompt, response, **kwargs):
        calls.append((prompt, response, kwargs["expected_policy"]))
        kwargs["before_request"](kwargs["timeout"], kwargs["max_tokens"])
        return {"outcome": "judge_assessed", "verdict": "violation", "rationale": "Synthetic semantic fixture verdict."}

    monkeypatch.setattr("agentshield.cli.judge_semantics", fake_judge)
    out = tmp_path / "reports"
    code = main(["run", "--config", str(config), "--mode", "baseline", "--judge", "--output-dir", str(out)])
    assert code == 0
    assert len(calls) == 1
    assert calls[0][2] == "review_semantics"
    result = json.loads(next(out.glob("*.json")).read_text(encoding="utf-8"))
    assert any(finding["outcome"] == "judge_assessed" for finding in result["findings"])
    assert result["metadata"]["judge_cases"] == 1


def test_judge_refuses_unknown_data_classification_before_running(tmp_path):
    config = tmp_path / "unknown.yaml"
    _judge_config(config, data_classification="unknown")
    code = main(["run", "--config", str(config), "--judge", "--output-dir", str(tmp_path / "reports")])
    assert code == 2
