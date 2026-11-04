"""MCP metadata inspection from explicitly configured fixtures only."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable

from agentshield.config.models import ProjectConfig
from agentshield.errors import ScopeViolation


@dataclass(frozen=True)
class ToolMetadata:
    name: str
    description: str
    input_schema: dict[str, object]
    impact: str
    authorized: bool
    fingerprint: str


_HIGH_IMPACT_TERMS = ("transfer", "payment", "delete", "email", "write", "admin", "account", "purchase", "sensitive")


def classify_impact(name: str, description: str) -> str:
    text = f"{name} {description}".casefold()
    return "high" if any(term in text for term in _HIGH_IMPACT_TERMS) else "low"


def discover_tools(config: ProjectConfig, tools: Iterable[dict[str, object]], *, source: str) -> list[ToolMetadata]:
    if source != config.target.fixture and source != config.mcp.server_url:
        raise ScopeViolation("MCP metadata source does not match the configured fixture or target.")
    found: list[ToolMetadata] = []
    for item in tools:
        name, description = item.get("name"), item.get("description", "")
        schema = item.get("inputSchema", {})
        if not isinstance(name, str) or not name or not isinstance(description, str) or not isinstance(schema, dict):
            continue
        impact = classify_impact(name, description)
        digest = hashlib.sha256(json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        found.append(ToolMetadata(name, description, schema, impact, config.scope.permits_tool(name), digest))
    return found


def metadata_changes(previous: Iterable[ToolMetadata], current: Iterable[ToolMetadata]) -> list[dict[str, str]]:
    old = {tool.name: tool.fingerprint for tool in previous}
    new = {tool.name: tool.fingerprint for tool in current}
    changes = [{"name": name, "change": "added"} for name in sorted(new.keys() - old.keys())]
    changes += [{"name": name, "change": "removed"} for name in sorted(old.keys() - new.keys())]
    changes += [{"name": name, "change": "modified"} for name in sorted(old.keys() & new.keys()) if old[name] != new[name]]
    return changes
