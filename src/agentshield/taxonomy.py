"""Stable attack objective categories (separate from individual payloads)."""

ATTACK_CATEGORIES = frozenset({"prompt_injection", "jailbreak", "prompt_extraction", "rag_poisoning", "indirect_prompt_injection", "sensitive_output", "mcp_tool_injection", "unauthorized_tool_execution", "parameter_tampering", "sensitive_action_without_approval"})
DEFAULT_CATEGORIES = ("prompt_injection", "rag_poisoning", "unauthorized_tool_execution", "sensitive_output")
