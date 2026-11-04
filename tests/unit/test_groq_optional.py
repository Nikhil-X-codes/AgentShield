from __future__ import annotations

import os

import pytest

from agentshield.errors import ProviderError
from agentshield.config.environment import load_local_environment
from agentshield.generation.groq import generate_variants

if os.environ.get("AGENTSHIELD_RUN_GROQ_TESTS") == "1":
    load_local_environment()


def test_dynamic_generation_requires_credentials_without_leaking_them(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(ProviderError, match="GROQ_API_KEY"):
        generate_variants("prompt_injection", target_context="synthetic only", count=1, model="test-model", max_tokens=128)


@pytest.mark.skipif(not (os.environ.get("GROQ_API_KEY") and os.environ.get("GROQ_ATTACK_MODEL") and os.environ.get("AGENTSHIELD_RUN_GROQ_TESTS") == "1"), reason="Set Groq credentials and AGENTSHIELD_RUN_GROQ_TESTS=1 to allow the optional provider call")
def test_optional_groq_attack_generation():
    cases = generate_variants("prompt_injection", target_context="Synthetic fixture only", count=1, model=os.environ["GROQ_ATTACK_MODEL"], max_tokens=128, timeout=10)
    assert len(cases) <= 1
    assert all(case.category == "prompt_injection" and case.model_id == os.environ["GROQ_ATTACK_MODEL"] for case in cases)
