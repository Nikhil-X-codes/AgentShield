"""Versioned, synthetic baseline cases."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files
from typing import Iterable
from agentshield.taxonomy import DEFAULT_CATEGORIES


@dataclass(frozen=True)
class AttackCase:
    case_id: str
    category: str
    prompt: str
    expected_policy: str
    version: int = 1
    seed: int | None = None
    model_id: str | None = None
    prompt_version: str = "baseline-v1"


def load_baseline(categories: Iterable[str] | None = None) -> list[AttackCase]:
    data_path = files("agentshield").joinpath("data/baseline_cases.json")
    records = json.loads(data_path.read_text(encoding="utf-8"))
    selected = set(categories or ())
    result = [AttackCase(**record) for record in records if not selected or record["category"] in selected]
    return result
