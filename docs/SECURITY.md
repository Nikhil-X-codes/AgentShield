# Security and scope model

AgentShield is for authorized test systems only. Configuration is the authority for scope; attack content, target responses, retrieved text, tool metadata, and model output are untrusted data.

## Enforced boundaries

- A non-mock HTTP target must be an absolute HTTP(S) URL with a hostname exactly present in `scope.allowed_hosts`.
- `production` and `prod` environment names are rejected.
- Real side effects and disabling mock tools are rejected.
- The configured `allowed_tools` list and required-approval list are evaluated independently of a target's final response.
- The runner caps case count, request rate, and wall-clock time. HTTP and Groq requests have timeouts and bounded response reads.
- Dynamic generation returns only schema-validated text payloads; it cannot set destinations, endpoints, configuration, or executable code.
- Reports redact common credential-like fields and credential assignment patterns. Use synthetic data because general-purpose text redaction cannot identify every private value.

## Evidence and verdicts

Observed tool-call traces and authorization decisions are separate from assistant response text. Unauthorized attempted calls produce deterministic `confirmed` findings. A blocked outcome means no violation was observed in a case whose expected policy is to deny a tool; it is not a universal security claim. Text-only sensitive-output heuristics produce `needs_review`. Optional semantic judgments must remain labeled `judge_assessed` and cannot override deterministic tool authorization evidence.

## HTTP adapter contract

The adapter sends `{ "prompt": string, "case_id": string }` and expects `{ "text": string, "tool_calls": [{"name": string, "arguments": object}], "decisions": [{"tool_name": string, "authorized": boolean, "reason": string}] }`. The endpoint must be an isolated harness that returns actual observed tool execution records. Never point it at an unapproved or production service.

## Current limits

Live MCP discovery uses Streamable HTTP initialization and bounded `tools/list` pagination against `mcp.server_url`, which must be explicitly included in the allowed-host scope. The client refuses redirects, optionally reads bearer credentials from the named environment variable, and never invokes tools. Adaptive generation follows only ambiguous cases and shares the run's wall-clock, request-rate, and case-count budgets. Baseline and dynamic coverage remains limited to configured categories and cases actually executed.
