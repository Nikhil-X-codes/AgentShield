from __future__ import annotations

import json
from threading import Thread

from agentshield.adapters.mock_mcp_server import create_mock_mcp_server
from agentshield.cli import main
from agentshield.config.models import MCPServerConfig, ScopeConfig
from agentshield.discovery.mcp import discover_tools
from agentshield.discovery.streamable_http import discover_remote_tools, invoke_remote_tool
from tests.conftest import make_config


def test_live_mcp_discovery_reads_json_and_sse_pages_without_calling_tools(mock_mcp_endpoint, monkeypatch):
    url, state = mock_mcp_endpoint
    monkeypatch.setenv("AGENTSHIELD_MCP_TEST_TOKEN", "test-only-token")
    config = make_config(allowed_hosts=("127.0.0.1",), mcp=MCPServerConfig(url, 2, "AGENTSHIELD_MCP_TEST_TOKEN"))
    tools = discover_remote_tools(config)
    metadata = discover_tools(config, tools, source=url)
    assert [tool.name for tool in metadata] == ["search_test_documents", "get_test_profile", "simulate_sensitive_action", "transfer_funds"]
    assert metadata[0].authorized is False
    assert metadata[1].impact == "low"
    assert metadata[3].impact == "high"
    assert "tools/call" not in state["methods"]
    assert state["deleted"] is True
    assert state["saw_auth"] is True


def _invocation_config(url, *, enabled=True, allowed_tools=("get_test_profile",)):
    base = make_config(allowed_hosts=("127.0.0.1",), mcp=MCPServerConfig(url, 2, "", False))
    config = __import__("dataclasses").replace(
        base, mcp=MCPServerConfig(url, 2, "", enabled),
        scope=ScopeConfig(("127.0.0.1",), allowed_tools, False, True, (url,)),
    )
    if not enabled or allowed_tools:
        config.validate()
    return config


def test_mcp_tool_invocation_validates_schema_and_records_redacted_untrusted_result(mock_mcp_endpoint):
    url, state = mock_mcp_endpoint
    record = invoke_remote_tool(_invocation_config(url), "get_test_profile", {"profile_id": "synthetic-1"})
    assert record["authorized"] is True
    assert record["result_is_untrusted"] is True
    assert state["calls"] == [{"name": "get_test_profile", "arguments": {"profile_id": "synthetic-1"}}]
    assert state["methods"].count("tools/call") == 1


def test_mcp_tool_invocation_blocks_disabled_and_unallowlisted_without_call(mock_mcp_endpoint):
    url, state = mock_mcp_endpoint
    disabled = invoke_remote_tool(_invocation_config(url, enabled=False), "get_test_profile", {"profile_id": "x"})
    denied = invoke_remote_tool(_invocation_config(url, allowed_tools=()), "get_test_profile", {"profile_id": "x"})
    assert disabled["decision"] == "denied" and "disabled" in disabled["rationale"]
    assert denied["decision"] == "denied" and "scope.allowed_tools" in denied["rationale"]
    assert "tools/call" not in state["methods"]


def test_mcp_tool_invocation_rejects_invalid_arguments_before_call(mock_mcp_endpoint):
    url, state = mock_mcp_endpoint
    record = invoke_remote_tool(_invocation_config(url), "get_test_profile", {"api_key": "synthetic-never-secret", "unexpected": "x"})
    assert record["decision"] == "denied"
    assert "do not match" in record["rationale"]
    assert record["arguments"]["api_key"] == "[REDACTED]"
    assert "synthetic-never-secret" not in str(record)
    assert "tools/call" not in state["methods"]


def test_mcp_tool_invocation_never_calls_sensitive_or_unapproved_tools(mock_mcp_endpoint):
    url, state = mock_mcp_endpoint
    record = invoke_remote_tool(_invocation_config(url), "simulate_sensitive_action", {})
    assert record["decision"] == "denied"
    assert "scope.allowed_tools" in record["rationale"]
    assert "tools/call" not in state["methods"]


def test_mcp_tool_invocation_blocks_high_impact_discovered_metadata(mock_mcp_endpoint):
    url, state = mock_mcp_endpoint
    config = _invocation_config(url, allowed_tools=("simulate_sensitive_action",))
    record = invoke_remote_tool(config, "simulate_sensitive_action", {})
    assert record["decision"] == "denied"
    assert "high impact" in record["rationale"]
    assert "tools/call" not in state["methods"]


def test_mcp_tool_result_injection_is_returned_as_untrusted_evidence(mock_mcp_endpoint):
    url, _state = mock_mcp_endpoint
    record = invoke_remote_tool(_invocation_config(url, allowed_tools=("search_test_documents",)), "search_test_documents", {"query": "synthetic"})
    assert record["result_is_untrusted"] is True
    assert record["tool_metadata_is_untrusted"] is True
    assert record["metadata_injection_suspected"] is True
    assert record["result_injection_suspected"] is True
    assert "Ignore previous instructions" in record["result"]["content"][0]["text"]


def test_standalone_synthetic_mcp_server_cli_flow(tmp_path, capsys):
    server = create_mock_mcp_server(port=0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        url = f"http://127.0.0.1:{port}/mcp"
        config_path = tmp_path / "mcp.yaml"
        config_path.write_text(
            f"""project:\n  name: mcp-cli-test\n  environment: isolated-test\n  data_classification: synthetic\ntarget:\n  adapter: mock_mcp\nscope:\n  allowed_hosts: [127.0.0.1]\n  allowed_mcp_servers: [{url}]\n  allowed_tools: [get_test_profile, search_test_documents]\nmcp:\n  server_url: {url}\n  timeout_seconds: 2\n  enable_tool_invocation: true\npolicy:\n  sensitive_tools: [simulate_sensitive_action]\n  require_approval: [simulate_sensitive_action]\n  default_tool_policy: deny\n""",
            encoding="utf-8",
        )
        output_path = tmp_path / "audit.json"
        assert main(["invoke-mcp-tool", "--config", str(config_path), "--tool", "get_test_profile",
                     "--arguments-json", '{"profile_id":"synthetic-42"}', "--output", str(output_path)]) == 0
        assert "MCP invocation allowed" in capsys.readouterr().out
        record = json.loads(output_path.read_text(encoding="utf-8"))
        assert record["result"]["content"][0]["text"] == "Synthetic profile: synthetic-42"
        assert server.agentshield_state["calls"][0]["name"] == "get_test_profile"
        assert main(["invoke-mcp-tool", "--config", str(config_path), "--tool", "simulate_sensitive_action",
                     "--arguments-json", '{"action":"demo"}', "--output", str(output_path)]) == 1
        denied = json.loads(output_path.read_text(encoding="utf-8"))
        assert denied["decision"] == "denied"
        assert len(server.agentshield_state["calls"]) == 1
        assert server.agentshield_state["sensitive_attempts"] == []
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
