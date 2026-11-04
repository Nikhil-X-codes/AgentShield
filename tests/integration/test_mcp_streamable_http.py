from __future__ import annotations

from agentshield.config.models import MCPServerConfig
from agentshield.discovery.mcp import discover_tools
from agentshield.discovery.streamable_http import discover_remote_tools
from tests.conftest import make_config


def test_live_mcp_discovery_reads_json_and_sse_pages_without_calling_tools(mock_mcp_endpoint, monkeypatch):
    url, state = mock_mcp_endpoint
    monkeypatch.setenv("AGENTSHIELD_MCP_TEST_TOKEN", "test-only-token")
    config = make_config(allowed_hosts=("127.0.0.1",), mcp=MCPServerConfig(url, 2, "AGENTSHIELD_MCP_TEST_TOKEN"))
    tools = discover_remote_tools(config)
    metadata = discover_tools(config, tools, source=url)
    assert [tool.name for tool in metadata] == ["search_docs", "transfer_funds"]
    assert metadata[0].authorized is False
    assert metadata[1].impact == "high"
    assert "tools/call" not in state["methods"]
    assert state["deleted"] is True
    assert state["saw_auth"] is True
