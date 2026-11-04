"""Provider-neutral target adapter contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolDecision:
    tool_name: str
    authorized: bool
    reason: str


@dataclass(frozen=True)
class AgentResponse:
    text: str
    tool_calls: tuple[ToolCall, ...] = ()
    decisions: tuple[ToolDecision, ...] = ()
    metadata: dict[str, object] = field(default_factory=dict)


class AgentAdapter(Protocol):
    """A scoped, provider-independent interface to a test agent."""

    def invoke(self, prompt: str, *, case_id: str) -> AgentResponse:
        """Send one test case and return response plus observed execution trace."""
