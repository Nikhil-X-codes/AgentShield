from __future__ import annotations

import json
from types import SimpleNamespace

from agentshield.evaluation.groq_judge import judge_semantics
from agentshield.generation.groq import generate_variants
from agentshield.groq_client import create_groq_client


class _FakeClient:
    def __init__(self, content: str):
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=lambda **_kwargs: SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])))

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


def test_shared_groq_client_uses_bounded_no_redirect_transport(monkeypatch):
    captured = {}

    def fake_groq(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr("agentshield.groq_client.Groq", fake_groq)
    client = create_groq_client("test-only-key", timeout=3.5)
    assert client is not None
    assert captured["max_retries"] == 0
    assert captured["timeout"] == 3.5
    assert captured["http_client"].follow_redirects is False
    captured["http_client"].close()


def test_generation_uses_groq_sdk_and_validates_synthetic_json(monkeypatch):
    captured = {}
    monkeypatch.setenv("GROQ_API_KEY", "test-only-key")

    def fake_client(_key, *, timeout):
        captured["timeout"] = timeout
        return _FakeClient(json.dumps({"prompts": ["Synthetic prompt injection variant"]}))

    monkeypatch.setattr("agentshield.generation.groq.create_groq_client", fake_client)
    budget = []
    cases = generate_variants("prompt_injection", target_context="Synthetic fixture", count=1, model="test-model", max_tokens=64,
                              timeout=4, before_request=lambda timeout, tokens: budget.append((timeout, tokens)))
    assert len(cases) == 1
    assert cases[0].category == "prompt_injection"
    assert cases[0].prompt == "Synthetic prompt injection variant"
    assert captured["timeout"] == 4
    assert budget == [(4, 64)]


def test_semantic_judge_uses_schema_limited_groq_sdk(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-only-key")
    captured = {}

    def fake_client(_key, *, timeout):
        captured["timeout"] = timeout
        return _FakeClient(json.dumps({"verdict": "no_violation", "rationale": "Synthetic response refused."}))

    monkeypatch.setattr("agentshield.evaluation.groq_judge.create_groq_client", fake_client)
    result = judge_semantics("Synthetic test", "I cannot disclose.", expected_policy="refuse", model="test-model", timeout=5, max_tokens=64)
    assert result["outcome"] == "judge_assessed"
    assert result["verdict"] == "no_violation"
    assert captured["timeout"] == 5
