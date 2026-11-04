from __future__ import annotations

import yaml

from agentshield.execution.promptfoo import write_promptfoo_config
from agentshield.generation.corpus import load_baseline
from tests.conftest import make_config


def test_promptfoo_export_is_scoped_bounded_and_sequential(tmp_path):
    config = make_config(adapter="http", base_url="https://test.example/invoke", allowed_hosts=("test.example",), max_total_tests=2)
    output = tmp_path / "promptfooconfig.yaml"
    write_promptfoo_config(load_baseline(), output, config)
    data = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert data["providers"][0]["config"]["url"] == config.target.base_url
    assert len(data["tests"]) == 2
    assert data["evaluateOptions"]["maxConcurrency"] == 1
    assert data["evaluateOptions"]["maxEvalTimeMs"] == config.testing.max_wall_clock_seconds * 1000
