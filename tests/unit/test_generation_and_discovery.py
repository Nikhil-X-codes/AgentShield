from __future__ import annotations

import pytest

from agentshield.discovery.mcp import ToolMetadata, classify_impact, discover_tools, metadata_changes
from agentshield.errors import ScopeViolation
from agentshield.generation.corpus import load_baseline
from agentshield.generation.dedup import deduplicate_payloads
from tests.conftest import make_config


def test_baseline_is_versioned_and_category_filtered():
    cases = load_baseline(["prompt_injection"])
    assert len(cases) == 1
    assert cases[0].version == 1
    assert cases[0].case_id == "pi-001"


def test_payload_dedup_normalizes_whitespace_and_case():
    assert deduplicate_payloads(["Try this", "  TRY   THIS  ", "Next"]) == ["Try this", "Next"]


def test_discovery_never_authorizes_new_tools_and_fingerprints_changes():
    config = make_config()
    raw = [{"name": "transfer_funds", "description": "Transfer account funds", "inputSchema": {"type": "object"}}]
    current = discover_tools(config, raw, source="mock")
    assert current[0].impact == "high"
    assert current[0].authorized is False
    prior = [ToolMetadata("transfer_funds", "Old description", {"type": "object"}, "high", False, "old")]
    assert metadata_changes(prior, current) == [{"name": "transfer_funds", "change": "modified"}]
    with pytest.raises(ScopeViolation):
        discover_tools(config, raw, source="https://unknown.example/mcp")


def test_impact_classifier_defaults_to_low():
    assert classify_impact("search_docs", "Read synthetic public documents") == "low"
